package hostaudit

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Behavioral and malware-oriented indicator regexes for host inspection.
var (
	// knownIOC matches signatures from known clipboard-hijacker malware families (e.g. fake gvfs-network).
	knownIOC = regexp.MustCompile(`(?i)gvfs-network|\.wl-swap|\.wl-clip|dockhide|\.user-root|spawn-trace|gtk-clip-daemon|wl-watch-sink`)

	// Generic clipboard-stealer building blocks (co-occurrence of all three triggers detection).
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

type iocHit struct {
	known, clip, wallet, swap bool
}

func (h iocHit) bad() bool {
	return h.known || (h.clip && h.wallet && h.swap)
}

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
	return iocHit{
		known:  knownIOC.MatchString(s),
		clip:   clipToolRe.MatchString(s),
		wallet: walletRe.MatchString(s),
		swap:   swapRe.MatchString(s),
	}
}

// scanWithRefs scans a script and any referenced sub-scripts it launches (one level deep).
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

// unitScore rates how strongly a systemd unit file resembles malware masquerading as a
// legitimate system component. A score >= 5 is flagged as HIGH severity.
func unitScore(p string, ls []string) (int, []string) {
	score := 0
	var why []string
	add := func(n int, s string) {
		score += n
		why = append(why, s)
	}

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

