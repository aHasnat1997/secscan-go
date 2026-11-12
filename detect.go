package main

// Behavioural / malware-oriented detections. These go beyond "is the system
// configured well" and look for things that behave like an intrusion:
// disguised persistence, clipboard hijackers, hidden processes, odd outbound
// connections, unowned kernel modules and persistence in less-common places.

import (
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ───────────────────────────── indicators ─────────────────────────────

var (
	// Strings from a known clipboard-hijacker family (fake "gvfs-network" agent).
	knownIOC = regexp.MustCompile(`(?i)gvfs-network|\.wl-swap|\.wl-clip|dockhide|\.user-root|spawn-trace|gtk-clip-daemon|wl-watch-sink`)
	// Generic clipboard-stealer building blocks: needs all three to count.
	clipToolRe = regexp.MustCompile(`(?i)wl-paste|wl-copy|xclip|xsel|Gdk\.Clipboard|Gtk\.Clipboard|clipboard`)
	walletRe   = regexp.MustCompile(`(?i)wallet|bitcoin|monero|\bbc1[a-z0-9]{25,60}\b|\b0x[a-fA-F0-9]{40}\b`)
	swapRe     = regexp.MustCompile(`(?i)swap[-_ ]?(cmd|addr|wallet)|hijack|replace[-_ ]?(addr|wallet)|attacker`)

	brandDescRe  = regexp.MustCompile(`(?i)^Description=.*(GNOME|KDE|systemd|D-Bus|dbus|Virtual File System|PulseAudio|PipeWire|NetworkManager|udev|polkit|Xorg|Wayland|kernel|system update)`)
	brandNameRe  = regexp.MustCompile(`(?i)^(gvfs|dbus|systemd|kde|gnome|pulse|pipewire|network|udev|update|kernel|polkit|xdg|dconf|at-spi)[-_.a-z0-9]*\.(service|timer)$`)
	hiddenExecRe = regexp.MustCompile(`/\.[^/\s'"]+/|/tmp/|/var/tmp/|/dev/shm/`)
	absPathRe    = regexp.MustCompile(`/[^\s'"=]+`)
	scriptRefRe  = regexp.MustCompile(`(/[^\s'"]+\.(?:js|mjs|cjs|py|sh|pl|rb))`)

	interpRe    = regexp.MustCompile(`^(node|nodejs|bun|deno|python[0-9.]*|perl|ruby|php|bash|sh|dash|zsh)$`)
	scriptDirRe = regexp.MustCompile(`^(/home/[^/]+|/root)/(\.config|\.local/share|\.cache)/|^(/tmp|/var/tmp|/dev/shm)/`)
	legitScript = regexp.MustCompile(`/node_modules/|/\.config/(Code|JetBrains|Antigravity)|/\.local/share/(JetBrains|Steam)`)

	unitTmpRe = regexp.MustCompile(`=\s*-?(/tmp|/dev/shm|/var/tmp)/`)
	cronEnvRe = regexp.MustCompile(`^[A-Z_]+=`)
	pidProcRe = regexp.MustCompile(`\("([^"]+)",pid=(\d+)`)
)

type iocHit struct{ known, clip, wallet, swap bool }

func (h iocHit) bad() bool { return h.known || (h.clip && h.wallet && h.swap) }

func (h iocHit) why() string {
	if h.known {
		return "matches known clipboard-hijacker indicators"
	}
	return "clipboard access + wallet strings + swap logic"
}

func iocScan(path string) iocHit {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 4<<20 {
		return iocHit{}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return iocHit{}
	}
	s := string(b)
	return iocHit{knownIOC.MatchString(s), clipToolRe.MatchString(s), walletRe.MatchString(s), swapRe.MatchString(s)}
}

// scanWithRefs scans a script and the scripts it launches (one level deep).
func scanWithRefs(path string) iocHit {
	h := iocScan(path)
	if h.bad() {
		return h
	}
	if b, err := os.ReadFile(path); err == nil && len(b) < 1<<20 {
		for _, m := range scriptRefRe.FindAllStringSubmatch(string(b), 20) {
			if r := iocScan(m[1]); r.bad() {
				return r
			}
		}
	}
	return h
}

func procInfo(pid string) (exe string, args []string) {
	exe, _ = os.Readlink("/proc/" + pid + "/exe")
	cl, _ := os.ReadFile("/proc/" + pid + "/cmdline")
	for _, a := range strings.Split(strings.TrimRight(string(cl), "\x00"), "\x00") {
		if a != "" {
			args = append(args, a)
		}
	}
	return
}

// ───────────────────────────── disguised systemd units ─────────────────────────────

// unitScore rates how much a unit file looks like malware masquerading as a
// system component. >=5 is reported as HIGH.
func unitScore(p string, ls []string) (int, []string) {
	score := 0
	var why []string
	add := func(n int, s string) { score += n; why = append(why, s) }
	if brandNameRe.MatchString(filepath.Base(p)) {
		add(1, "name imitates a system service")
	}
	var desc, hid, quiet, always bool
	var execPaths []string
	for _, l := range ls {
		t := strings.TrimSpace(l)
		switch {
		case !desc && brandDescRe.MatchString(t):
			desc = true
			add(2, "description imitates a system component but the unit is not from a package")
		case strings.HasPrefix(t, "ExecStart"):
			if !hid && hiddenExecRe.MatchString(t) {
				hid = true
				add(2, "runs code from a hidden/temp directory")
			}
			execPaths = append(execPaths, absPathRe.FindAllString(t, -1)...)
		case !quiet && (t == "StandardOutput=null" || t == "StandardError=null" || t == "LogLevelMax=0"):
			quiet = true
			add(2, "logging suppressed (output to null)")
		case !always && t == "Restart=always":
			always = true
			add(1, "restarts itself forever")
		}
	}
	for _, ep := range execPaths {
		if h := scanWithRefs(ep); h.bad() {
			add(4, "script "+ep+" "+h.why())
			break
		}
	}
	return score, why
}

// ───────────────────────────── ioc-scripts: clipboard hijacker / known malware ─────────────────────────────

var iocSkipDirs = map[string]bool{
	"code": true, "code - oss": true, "google-chrome": true, "chromium": true, "bravesoftware": true,
	"discord": true, "slack": true, "jetbrains": true, "antigravity": true, "mozilla": true,
	"cache": true, "service worker": true, "node_modules": true, ".git": true, "steam": true,
	"flatpak": true, "go": true, "pnpm": true, "yarn": true,
}

var iocExts = map[string]bool{".sh": true, ".py": true, ".js": true, ".mjs": true, ".cjs": true,
	".service": true, ".desktop": true, ".pl": true, ".rb": true, "": true}

func checkIOCScripts(e *Env) ([]Finding, error) {
	var roots []string
	for _, h := range e.Homes {
		roots = append(roots, filepath.Join(h, ".config"), filepath.Join(h, ".local/share"), filepath.Join(h, ".local/bin"))
	}
	roots = append(roots, "/tmp", "/var/tmp", "/dev/shm", "/usr/local/bin", "/opt")
	var ev []string
	for _, r := range roots {
		_ = filepath.WalkDir(r, func(p string, d fs.DirEntry, err error) error {
			if e.Ctx.Err() != nil {
				return e.Ctx.Err()
			}
			if err != nil {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if knownIOC.MatchString(p) {
				ev = append(ev, p+"  (path matches known malware indicators)")
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if iocSkipDirs[strings.ToLower(d.Name())] {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || !iocExts[strings.ToLower(filepath.Ext(p))] {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Size() > 4<<20 || info.Size() == 0 {
				return nil
			}
			if filepath.Ext(p) == "" && info.Mode()&0o111 == 0 {
				return nil
			}
			// Generic heuristics are noisy on vendor code; trust package-owned files.
			if h := iocScan(p); h.bad() && (h.known || !pacmanOwns(e, p)) {
				ev = append(ev, p+"  ("+h.why()+")")
			}
			return nil
		})
	}
	if len(ev) == 0 {
		return nil, nil
	}
	sort.Strings(ev)
	return []Finding{finding("MAL-CLIPBOARD-HIJACK", SevHigh, fmt.Sprintf("%d files match clipboard-hijacker / known-malware indicators", len(ev)),
		"Crypto clipboard hijackers watch what you copy and swap wallet addresses for the attacker's. They persist via fake system-named user services.",
		"1) systemctl --user disable --now <unit> and pkill -f <name>; 2) copy the folder aside as evidence (cp -a, chmod -R a-x); 3) delete it and its unit files; 4) find how it arrived; 5) rotate credentials and move funds from a clean device.", ev...)}, nil
}

// ───────────────────────────── proc-scripts: interpreters running hidden scripts ─────────────────────────────

func checkProcScripts(e *Env) ([]Finding, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var hi, med []string
	for _, en := range ents {
		pid := en.Name()
		if n, err := strconv.Atoi(pid); err != nil || n == os.Getpid() {
			continue
		}
		exe, args := procInfo(pid)
		if exe == "" || !interpRe.MatchString(filepath.Base(strings.TrimSuffix(exe, " (deleted)"))) {
			continue
		}
		for _, a := range args[min(1, len(args)):] {
			if !scriptDirRe.MatchString(a) || legitScript.MatchString(a) {
				continue
			}
			line := fmt.Sprintf("pid %s %s %s", pid, filepath.Base(exe), a)
			if h := scanWithRefs(a); h.bad() {
				hi = append(hi, line+"  ("+h.why()+")")
			} else {
				med = append(med, line)
			}
			break
		}
	}
	var out []Finding
	if len(hi) > 0 {
		out = append(out, finding("PROC-MALICIOUS-SCRIPT", SevCritical, "Running script matches malware indicators", "An interpreter is executing a script that looks like a clipboard hijacker / known malware.",
			"Stop it (kill the PID and the unit that respawns it), preserve the script as evidence, then remove its persistence.", hi...))
	}
	if len(med) > 0 {
		out = append(out, finding("PROC-HIDDEN-SCRIPT", SevMedium, fmt.Sprintf("%d interpreter processes run scripts from ~/.config, ~/.local/share, ~/.cache or temp dirs", len(med)),
			"Legitimate apps rarely run loose scripts from these places; malware favours them because they need no root and survive reboots via user services.",
			"For each: ls -l /proc/<pid>/exe, read the script, and find what starts it (systemctl --user status <pid>). Suppress it in the config if it is yours.", med...))
	}
	return out, nil
}

// ───────────────────────────── net-outbound ─────────────────────────────

func checkConnections(e *Env) ([]Finding, error) {
	out, _, _, err := run(e.Ctx, 15*time.Second, "ss", "-H", "-tnp", "state", "established")
	if err != nil {
		return nil, err
	}
	type conn struct {
		name  string
		peers []string
	}
	by := map[string]*conn{}
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		host, port := splitHostPort(f[3])
		host = strings.TrimPrefix(strings.Trim(host, "[]"), "::ffff:")
		ip := net.ParseIP(host)
		if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		g := pidProcRe.FindStringSubmatch(f[4])
		if g == nil {
			continue
		}
		if by[g[2]] == nil {
			by[g[2]] = &conn{name: g[1]}
		}
		by[g[2]].peers = append(by[g[2]].peers, host+":"+port)
	}
	var pids []string
	for p := range by {
		pids = append(pids, p)
	}
	sort.Strings(pids)
	var hi, unpk, stale []string
	for _, pid := range pids {
		c := by[pid]
		exe, args := procInfo(pid)
		peers := c.peers
		if len(peers) > 3 {
			peers = peers[:3]
		}
		label := fmt.Sprintf("pid %s %s -> %s", pid, c.name, strings.Join(peers, ", "))
		deleted := strings.HasSuffix(exe, " (deleted)")
		exe = strings.TrimSuffix(exe, " (deleted)")
		switch {
		case exe == "":
			continue
		case strings.HasPrefix(exe, "/tmp/") || strings.HasPrefix(exe, "/var/tmp/") || strings.HasPrefix(exe, "/dev/shm/"):
			hi = append(hi, label+" [binary in temp dir: "+exe+"]")
			continue
		}
		suspScript := ""
		if interpRe.MatchString(filepath.Base(exe)) {
			for _, a := range args[min(1, len(args)):] {
				if scriptDirRe.MatchString(a) && !legitScript.MatchString(a) {
					suspScript = a
					break
				}
			}
		}
		switch {
		case suspScript != "":
			why := "interpreter running " + suspScript
			if h := scanWithRefs(suspScript); h.bad() {
				why += "; " + h.why()
			}
			hi = append(hi, label+" ["+why+"]")
		case deleted && pacmanOwns(e, exe):
			stale = append(stale, label+" ["+exe+" was updated while running]")
		case deleted:
			hi = append(hi, label+" [binary deleted from disk and not owned by any package]")
		case !pacmanOwns(e, exe):
			unpk = append(unpk, fmt.Sprintf("%s [%s]", label, exe))
		}
	}
	var fs []Finding
	if len(hi) > 0 {
		fs = append(fs, finding("NET-OUTBOUND-SUSPICIOUS", SevHigh, fmt.Sprintf("%d suspicious processes hold connections to the internet", len(hi)),
			"Processes running from temp dirs, hidden script dirs, or deleted binaries that talk to external hosts are typical of command-and-control or exfiltration.",
			"Identify with ls -l /proc/<pid>/exe and sudo ss -tnp. Block the peer in the firewall, kill the process, remove its persistence.", hi...))
	}
	if len(unpk) > 0 {
		fs = append(fs, finding("NET-OUTBOUND-UNPACKAGED", SevLow, fmt.Sprintf("%d programs outside the package manager talk to the internet", len(unpk)),
			"Not malicious by itself (nvm node, AppImages, tools you built), but this is where unknown software shows up. Make sure you recognise each.",
			"Confirm each program is yours. Unknown ones: investigate, then remove.", unpk...))
	}
	if len(stale) > 0 {
		fs = append(fs, finding("NET-OUTBOUND-STALE", SevLow, fmt.Sprintf("%d connected programs run an outdated binary (package updated since launch)", len(stale)),
			"The packaged program was upgraded while still running, so the old, possibly vulnerable version stays in memory.", "Restart those apps or reboot.", stale...))
	}
	if !e.Root {
		fs = append(fs, finding("NET-PARTIAL", SevInfo, "Connection scan limited to your own processes", "", "Run with sudo for full coverage."))
	}
	return fs, nil
}

// ───────────────────────────── hidden PIDs ─────────────────────────────

func checkHiddenPIDs(e *Env) ([]Finding, error) {
	maxPid := 4194304
	if b, err := os.ReadFile("/proc/sys/kernel/pid_max"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 && n < maxPid {
			maxPid = n
		}
	}
	visible := map[int]bool{}
	if ents, err := os.ReadDir("/proc"); err == nil {
		for _, en := range ents {
			if n, err := strconv.Atoi(en.Name()); err == nil {
				visible[n] = true
			}
		}
	}
	var cand []int
	for pid := 1; pid <= maxPid; pid++ {
		if pid&0xffff == 0 && e.Ctx.Err() != nil {
			return nil, e.Ctx.Err()
		}
		if visible[pid] {
			continue
		}
		if err := syscall.Kill(pid, 0); err == nil || err == syscall.EPERM {
			cand = append(cand, pid)
		}
	}
	time.Sleep(300 * time.Millisecond)
	var hidden []string
	for _, pid := range cand {
		if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); err == nil {
			continue // appeared after our snapshot
		}
		if syscall.Kill(pid, 0) == syscall.ESRCH {
			continue // exited
		}
		hidden = append(hidden, "pid "+strconv.Itoa(pid)+" answers kill(0) but is absent from /proc")
	}
	if len(hidden) == 0 {
		return nil, nil
	}
	return []Finding{finding("PROC-HIDDEN-PID", SevCritical, fmt.Sprintf("%d processes are hidden from /proc", len(hidden)),
		"A process that exists but is invisible to ps/top is the signature of a kernel or userland rootkit (or hidepid in unusual setups).",
		"Treat the system as compromised: disconnect, capture memory/disk if needed, back up data only, reinstall from trusted media.", hidden...)}, nil
}

// ───────────────────────────── less-common persistence ─────────────────────────────

func checkPersistMisc(e *Env) ([]Finding, error) {
	globs := []string{
		"/etc/cron.hourly/*", "/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*",
		"/etc/profile.d/*", "/etc/rc.local", "/etc/udev/rules.d/*", "/etc/modules-load.d/*",
		"/etc/ld.so.conf.d/*", "/etc/environment.d/*", "/var/spool/at/*",
	}
	for _, h := range e.Homes {
		for _, g := range []string{".local/bin/*", ".config/autostart-scripts/*", ".config/plasma-workspace/env/*",
			".config/plasma-workspace/shutdown/*", ".config/environment.d/*", ".config/systemd/user/*.wants/*"} {
			globs = append(globs, filepath.Join(h, g))
		}
	}
	var hi, lo []string
	for _, g := range globs {
		m, _ := filepath.Glob(g)
		for _, p := range m {
			st, err := os.Lstat(p)
			if err != nil || st.IsDir() {
				continue
			}
			if strings.HasPrefix(p, "/etc/") && pacmanOwns(e, p) {
				continue
			}
			bad := ""
			if st.Mode().IsRegular() && st.Size() < 1<<20 {
				if b, err := os.ReadFile(p); err == nil {
					s := string(b)
					switch {
					case knownIOC.MatchString(s):
						bad = "known malware indicators"
					case suspicious.MatchString(s):
						bad = "download-and-execute / reverse-shell pattern"
					}
				}
			}
			if bad != "" {
				hi = append(hi, p+"  ("+bad+")")
			} else {
				lo = append(lo, p)
			}
		}
	}
	var out []Finding
	if len(hi) > 0 {
		sort.Strings(hi)
		out = append(out, finding("PERSIST-MISC-SUSPICIOUS", SevHigh, "Suspicious content in a startup/persistence location",
			"These locations run code at boot, login, hotplug or on a schedule.", "Read the file, remove it if it is not yours, and find how it got there.", hi...))
	}
	if len(lo) > 0 {
		sort.Strings(lo)
		out = append(out, finding("PERSIST-MISC", SevInfo, fmt.Sprintf("%d unpackaged files in startup locations", len(lo)),
			"cron.*, profile.d, udev, ~/.local/bin, KDE autostart-scripts... Review that you recognise each.", "", lo...))
	}
	return out, nil
}

// ───────────────────────────── kernel modules ─────────────────────────────

func checkKernelModules(e *Env) ([]Finding, error) {
	if !have("modinfo") {
		return nil, skip("modinfo missing (sudo pacman -S kmod)")
	}
	var odd, dkms []string
	for _, l := range readLines("/proc/modules") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		o, _, _, _ := run(e.Ctx, 5*time.Second, "modinfo", "-n", f[0])
		p := strings.TrimSpace(o)
		if !strings.HasPrefix(p, "/") || pacmanOwns(e, p) {
			continue
		}
		switch {
		case strings.Contains(p, "/dkms/"):
			dkms = append(dkms, f[0]+": "+p)
		default:
			odd = append(odd, f[0]+": "+p)
		}
	}
	var out []Finding
	if len(odd) > 0 {
		sev := SevMedium
		for _, o := range odd {
			if strings.Contains(o, "/home/") || strings.Contains(o, "/tmp/") {
				sev = SevCritical
			}
		}
		out = append(out, finding("KMOD-UNOWNED", sev, fmt.Sprintf("%d loaded kernel modules are not owned by any package", len(odd)),
			"Rootkits often ship as kernel modules. Out-of-tree drivers you installed by hand also appear here.",
			"Verify each: modinfo <name>, and the file's origin. Remove unknown modules (rmmod) and their load config.", odd...))
	}
	if len(dkms) > 0 {
		out = append(out, finding("KMOD-DKMS", SevInfo, fmt.Sprintf("%d DKMS-built kernel modules loaded", len(dkms)),
			"Built locally from source by DKMS packages (e.g. NVIDIA, VirtualBox). Expected if you installed those.", "", dkms...))
	}
	return out, nil
}
