// secscan - host security audit CLI for CachyOS / Arch Linux.
//
// Runs a layered set of checks (package integrity, CVEs, persistence,
// network exposure, accounts, processes, hardening) plus optional wrappers
// around ClamAV, rkhunter and Lynis, then prints a prioritised report,
// writes JSON + Markdown copies and diffs against the previous run.
//
// Standard library only. Build: go build -o secscan .   (sources: main.go, detect.go)
// Run:   sudo ./secscan            (root gives full coverage)
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const version = "1.1.0"

// ───────────────────────────── model ─────────────────────────────

type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

var sevNames = []string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

func (s Severity) String() string { return sevNames[s] }
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(strings.ToLower(s.String())), nil
}
func (s *Severity) UnmarshalText(b []byte) error {
	v, ok := parseSeverity(string(b))
	if !ok {
		return fmt.Errorf("bad severity %q", b)
	}
	*s = v
	return nil
}
func parseSeverity(s string) (Severity, bool) {
	for i, n := range sevNames {
		if strings.EqualFold(n, strings.TrimSpace(s)) {
			return Severity(i), true
		}
	}
	return SevInfo, false
}

type Finding struct {
	ID          string   `json:"id"`
	Check       string   `json:"check"`
	Category    string   `json:"category"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Detail      string   `json:"detail,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Fingerprint string   `json:"fingerprint"`
	Status      string   `json:"status,omitempty"` // "new" when absent from previous run
	Suppressed  string   `json:"suppressed,omitempty"`
}

type CheckResult struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Category   string    `json:"category"`
	Status     string    `json:"status"`        // ok | findings | skipped | error
	Gap        bool      `json:"gap,omitempty"` // true when the check could not run for an unintended reason
	Note       string    `json:"note,omitempty"`
	DurationMS int64     `json:"duration_ms"`
	Findings   []Finding `json:"findings,omitempty"`
}

type Report struct {
	Tool       string         `json:"tool"`
	Version    string         `json:"version"`
	Host       string         `json:"host"`
	OS         string         `json:"os"`
	Kernel     string         `json:"kernel"`
	StartedAt  time.Time      `json:"started_at"`
	DurationMS int64          `json:"duration_ms"`
	Root       bool           `json:"root"`
	Score      int            `json:"score"`
	Grade      string         `json:"grade"`
	GradeNote  string         `json:"grade_note,omitempty"`
	Coverage   string         `json:"coverage"`
	Incomplete []string       `json:"incomplete,omitempty"`
	Counts     map[string]int `json:"counts"`
	Suppressed int            `json:"suppressed"`
	Resolved   []string       `json:"resolved_since_last_run,omitempty"`
	Results    []CheckResult  `json:"results"`
}

type Check struct {
	ID       string
	Name     string
	Category string
	Root     bool // needs root to be meaningful
	Slow     bool // skipped by --quick
	Heavy    bool // opt-in only (--clamav / --full)
	Run      func(*Env) ([]Finding, error)
}

type skip string

func (s skip) Error() string { return string(s) }

type Suppression struct {
	ID     string `json:"id"` // exact ID, or prefix ending in *
	Reason string `json:"reason"`
}

type Config struct {
	Suppress        []Suppression `json:"suppress"`
	AllowedPorts    []int         `json:"allowed_ports"`
	ClamPaths       []string      `json:"clamav_paths"`
	IgnoreToolWarns []string      `json:"ignore_tool_warnings_regex"`
}

type Options struct {
	Quick, Full, ClamAV, JSON, NoColor, Verbose, ShowSuppressed, NoSave, List, InitConfig, Version bool
	Only, Skip, OutDir, FailOn, ConfigPath, ClamPaths                                              string
	ClamTimeout                                                                                    time.Duration
	Jobs                                                                                           int
	Config                                                                                         Config
}

type Env struct {
	Ctx   context.Context
	Opts  *Options
	Root  bool
	Homes []string
}

// ───────────────────────────── helpers ─────────────────────────────

func run(ctx context.Context, timeout time.Duration, name string, args ...string) (stdout, stderr string, code int, err error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	err = cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code, err = ee.ExitCode(), nil
		} else {
			code = -1
		}
	}
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("%s timed out after %s", name, timeout)
	}
	return o.String(), e.String(), code, err
}

func have(name string) bool { _, err := exec.LookPath(name); return err == nil }

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimRight(l, "\r \t"); strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func finding(id string, sev Severity, title, detail, fix string, ev ...string) Finding {
	return Finding{ID: id, Severity: sev, Title: title, Detail: detail, Remediation: fix, Evidence: ev}
}

func fingerprint(f Finding) string {
	h := sha256.Sum256([]byte(f.ID + "|" + f.Title + "|" + strings.Join(f.Evidence, "\n")))
	return hex.EncodeToString(h[:])[:12]
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

var ownCache sync.Map

func pacmanOwns(e *Env, path string) bool {
	if v, ok := ownCache.Load(path); ok {
		return v.(bool)
	}
	_, _, code, err := run(e.Ctx, 15*time.Second, "pacman", "-Qqo", path)
	owned := err == nil && code == 0
	ownCache.Store(path, owned)
	return owned
}

var defaultSkipDirs = []string{"/proc", "/sys", "/dev", "/var/lib/docker", "/var/lib/containerd", "/var/lib/containers", "/var/lib/flatpak", "/var/lib/snapd", "/var/lib/machines", "/var/lib/lxc"}

func walk(e *Env, root string, fn func(path string, d fs.DirEntry)) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if e.Ctx.Err() != nil {
			return e.Ctx.Err()
		}
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".cache", ".npm", ".git":
				return filepath.SkipDir
			}
			for _, s := range defaultSkipDirs {
				if p == s {
					return filepath.SkipDir
				}
			}
			return nil
		}
		fn(p, d)
		return nil
	})
}

var suspicious = regexp.MustCompile(`(?i)(curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh|base64\s+(-d|--decode)|/dev/tcp/|\bnc(at)?\s+(-\w*e|.*\s-e\s)|bash\s+-i\s+>&|python[0-9.]*\s+-c\s+.*socket|chmod\s+\+x\s+/(tmp|dev/shm|var/tmp)|LD_PRELOAD=|xmrig|minerd|stratum\+tcp`)
var minerRe = regexp.MustCompile(`(?i)xmrig|minerd|cpuminer|kdevtmpfsi|kinsing|cryptonight`)
var stratumRe = regexp.MustCompile(`(?i)stratum\+tcp`)

func firstArg(cmdline string) string {
	if f := strings.Fields(cmdline); len(f) > 0 {
		return f[0]
	}
	return ""
}

func readLines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(string(b), "\n")
}

// ───────────────────────────── checks: patching ─────────────────────────────

func checkUpdates(e *Env) ([]Finding, error) {
	if !have("checkupdates") {
		return nil, skip("checkupdates missing (sudo pacman -S pacman-contrib)")
	}
	out, _, code, err := run(e.Ctx, 120*time.Second, "checkupdates")
	if err != nil {
		return nil, err
	}
	if code == 2 {
		return nil, nil
	}
	if code != 0 {
		return nil, fmt.Errorf("checkupdates exited %d (network or mirror problem?)", code)
	}
	l := lines(out)
	if len(l) == 0 {
		return nil, nil
	}
	return []Finding{finding("PATCH-PENDING", SevMedium,
		fmt.Sprintf("%d package updates pending", len(l)),
		"Unpatched packages are the most common route to compromise on a desktop.",
		"sudo pacman -Syu", l...)}, nil
}

func checkReboot(e *Env) ([]Finding, error) {
	out, _, _, err := run(e.Ctx, 5*time.Second, "uname", "-r")
	if err != nil {
		return nil, err
	}
	rel := strings.TrimSpace(out)
	if _, err := os.Stat("/usr/lib/modules/" + rel); err != nil {
		return []Finding{finding("PATCH-REBOOT", SevMedium,
			"Running kernel no longer matches installed modules: reboot required",
			"The kernel was updated on disk but the old one is still running. New modules (USB, Wi-Fi, filesystems) will fail to load.",
			"Save your work and reboot.", "running kernel: "+rel)}, nil
	}
	return nil, nil
}

func checkArchAudit(e *Env) ([]Finding, error) {
	if !have("arch-audit") {
		return nil, skip("arch-audit missing (sudo pacman -S arch-audit)")
	}
	fixable, ferr, fcode, err := run(e.Ctx, 120*time.Second, "arch-audit", "--upgradable")
	if err != nil {
		return nil, err
	}
	// arch-audit downloads the advisory list; offline it prints an error and no data.
	// Treating that as "no CVEs" would be a false all-clear.
	if strings.TrimSpace(fixable) == "" && (fcode > 1 || strings.Contains(ferr, "Error")) {
		return nil, fmt.Errorf("arch-audit could not fetch advisories (offline?): %s", trunc(strings.TrimSpace(strings.SplitN(ferr, "\n", 2)[0]), 120))
	}
	all, _, _, _ := run(e.Ctx, 120*time.Second, "arch-audit")
	var out []Finding
	if l := lines(fixable); len(l) > 0 {
		out = append(out, finding("CVE-FIXABLE", SevHigh,
			fmt.Sprintf("%d vulnerable packages have a fix available", len(l)),
			"A patched version is already in your repos.", "sudo pacman -Syu", l...))
	}
	fixSet := map[string]bool{}
	for _, l := range lines(fixable) {
		fixSet[strings.Fields(l)[0]] = true
	}
	var waiting []string
	high := 0
	for _, l := range lines(all) {
		f := strings.Fields(l)
		if len(f) == 0 || fixSet[f[0]] {
			continue
		}
		waiting = append(waiting, l)
		if strings.Contains(l, "High risk") || strings.Contains(l, "Critical risk") {
			high++
		}
	}
	if len(waiting) > 0 {
		sev := SevLow
		if high > 0 {
			sev = SevMedium
		}
		out = append(out, finding("CVE-UNFIXED", sev,
			fmt.Sprintf("%d packages have known CVEs with no fix released yet (%d high risk)", len(waiting), high),
			"Nothing to install yet. Avoid opening untrusted files/archives/images until fixes ship.",
			"Re-run weekly; `arch-audit --upgradable` shows when a fix lands.", waiting...))
	}
	return out, nil
}

// ───────────────────────────── checks: integrity ─────────────────────────────

var benignIntegrity = regexp.MustCompile(`/usr/lib/jvm/|plugins\.dat$|/utempter$|^/var/log/journal|^/usr/share/factory/|plymouth-update-initrd|^/usr/share/code/`)
var criticalDirs = regexp.MustCompile(`^/(usr/(bin|sbin|lib|lib64)|boot|bin|sbin|lib|lib64)/`)

func checkPkgIntegrity(e *Env) ([]Finding, error) {
	if !have("pacman") {
		return nil, skip("pacman not found")
	}
	out, errOut, _, err := run(e.Ctx, 15*time.Minute, "pacman", "-Qkk")
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`^warning: ([^:]+): (.+) \(([^)]+)\)$`)
	type ent struct {
		pkg     string
		reasons []string
	}
	m := map[string]*ent{}
	for _, l := range lines(out + "\n" + errOut) {
		g := re.FindStringSubmatch(l)
		if g == nil {
			continue
		}
		if m[g[2]] == nil {
			m[g[2]] = &ent{pkg: g[1]}
		}
		m[g[2]].reasons = append(m[g[2]].reasons, g[3])
	}
	paths := make([]string, 0, len(m))
	for p := range m {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var high, meta []string
	for _, p := range paths {
		if benignIntegrity.MatchString(p) {
			continue
		}
		en := m[p]
		line := fmt.Sprintf("%s: %s [%s]", en.pkg, p, strings.Join(en.reasons, ", "))
		content := false
		for _, r := range en.reasons {
			if strings.Contains(r, "checksum") || strings.Contains(r, "Size mismatch") {
				content = true
			}
		}
		if content && criticalDirs.MatchString(p) {
			high = append(high, line)
		} else {
			meta = append(meta, line)
		}
	}
	var fs []Finding
	if len(high) > 0 {
		fs = append(fs, finding("INTEG-MODIFIED", SevHigh,
			fmt.Sprintf("%d system files differ from what pacman installed", len(high)),
			"Contents of binaries/libraries changed after install. Could be a manual edit or tampering.",
			"Reinstall the owning package: sudo pacman -S <pkg>. If it changes again or you cannot explain it, treat the host as compromised.",
			high...))
	}
	if len(meta) > 0 {
		fs = append(fs, finding("INTEG-METADATA", SevInfo,
			fmt.Sprintf("%d packaged files differ in permissions/timestamps only", len(meta)),
			"Usually benign (post-install scripts, runtime-generated files).", "", meta...))
	}
	return fs, nil
}

func checkForeignPkgs(e *Env) ([]Finding, error) {
	out, _, _, err := run(e.Ctx, 30*time.Second, "pacman", "-Qm")
	if err != nil {
		return nil, err
	}
	l := lines(out)
	if len(l) == 0 {
		return nil, nil
	}
	return []Finding{finding("PKG-FOREIGN", SevInfo,
		fmt.Sprintf("%d packages not from official repos (AUR / manual)", len(l)),
		"AUR is the most common infection route on Arch. Make sure you recognise each one and reviewed its PKGBUILD.",
		"Remove anything unknown: sudo pacman -Rns <pkg>", l...)}, nil
}

func checkLdPreload(e *Env) ([]Finding, error) {
	var ev []string
	for _, l := range readLines("/etc/ld.so.preload") {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
			ev = append(ev, t)
		}
	}
	if len(ev) == 0 {
		return nil, nil
	}
	return []Finding{finding("INTEG-LDPRELOAD", SevCritical,
		"/etc/ld.so.preload is set",
		"Forces a library into every process. This is the classic userland rootkit hook.",
		"Identify the library (pacman -Qo <file>). If unknown: disconnect, back up data, reinstall.", ev...)}, nil
}

func checkBootSecurity(e *Env) ([]Finding, error) {
	b, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err != nil {
		return nil, skip("not a UEFI system or efivars unreadable")
	}
	if len(b) > 0 && b[len(b)-1] == 1 {
		return nil, nil
	}
	return []Finding{finding("BOOT-SECUREBOOT", SevLow, "Secure Boot is disabled",
		"Without it a bootkit or tampered bootloader would not be detected.",
		"Optional: set up sbctl-based signing for GRUB/kernel, then enable Secure Boot in firmware.")}, nil
}

// ───────────────────────────── checks: network ─────────────────────────────

var procRe = regexp.MustCompile(`\(\("([^"]+)"`)

func splitHostPort(a string) (string, string) {
	i := strings.LastIndex(a, ":")
	if i < 0 {
		return a, ""
	}
	return a[:i], a[i+1:]
}

func isLoopback(h string) bool {
	return strings.HasPrefix(h, "127.") || h == "[::1]" || h == "::1"
}

func checkListening(e *Env) ([]Finding, error) {
	out, _, _, err := run(e.Ctx, 15*time.Second, "ss", "-H", "-tulpn")
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, p := range e.Opts.Config.AllowedPorts {
		allowed[strconv.Itoa(p)] = true
	}
	type agg struct {
		sev Severity
		ev  []string
		pr  string
	}
	m := map[string]*agg{}
	var order []string
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) < 6 {
			continue
		}
		host, port := splitHostPort(f[4])
		if isLoopback(host) || allowed[port] {
			continue
		}
		proc := ""
		if len(f) >= 7 {
			if g := procRe.FindStringSubmatch(f[6]); g != nil {
				proc = g[1]
			}
		}
		id := fmt.Sprintf("NET-LISTEN-%s-%s", f[0], port)
		if m[id] == nil {
			sev := SevMedium
			if f[0] == "udp" {
				sev = SevLow
			}
			m[id] = &agg{sev: sev, pr: proc}
			order = append(order, id)
		}
		m[id].ev = append(m[id].ev, fmt.Sprintf("%s %s  %s", f[0], f[4], proc))
	}
	var fs []Finding
	for _, id := range order {
		a := m[id]
		parts := strings.Split(id, "-")
		fix := "Stop/disable the service, bind it to 127.0.0.1, or block it in the firewall. If expected, add the port to allowed_ports in the config."
		if a.pr == "docker-proxy" {
			fix = "Publish to loopback only: -p 127.0.0.1:PORT:PORT (compose: \"127.0.0.1:PORT:PORT\"). Docker bypasses ufw, so the firewall does NOT protect this port."
		}
		fs = append(fs, finding(id, a.sev,
			fmt.Sprintf("Port %s/%s is reachable from the network (%s)", parts[3], parts[2], valOr(a.pr, "unknown process, run as root to see")),
			"Anything listening on a non-loopback address can be reached by other devices on your LAN.", fix, a.ev...))
	}
	return fs, nil
}

func valOr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func checkDocker(e *Env) ([]Finding, error) {
	if !have("docker") {
		return nil, skip("docker not in use")
	}
	out, _, code, err := run(e.Ctx, 20*time.Second, "docker", "ps", "--format", "{{.Names}}|{{.Image}}|{{.Ports}}")
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, skip("docker daemon not reachable (not running or no permission)")
	}
	var ev []string
	for _, l := range lines(out) {
		if strings.Contains(l, "0.0.0.0:") || strings.Contains(l, ":::") {
			ev = append(ev, l)
		}
	}
	if len(ev) == 0 {
		return nil, nil
	}
	return []Finding{finding("NET-DOCKER-EXPOSED", SevMedium,
		fmt.Sprintf("%d running container(s) publish ports on all interfaces", len(ev)),
		"Docker writes its own iptables rules, so ufw rules do not apply to published ports.",
		"Use 127.0.0.1:HOST:CONTAINER in -p / compose ports, or put a reverse proxy in front.", ev...)}, nil
}

func checkFirewall(e *Env) ([]Finding, error) {
	var active []string
	for _, u := range []string{"ufw", "nftables", "firewalld"} {
		o, _, _, _ := run(e.Ctx, 5*time.Second, "systemctl", "is-active", u)
		if strings.TrimSpace(o) == "active" {
			active = append(active, u)
		}
	}
	if len(active) == 0 {
		return []Finding{finding("NET-FIREWALL", SevHigh, "No host firewall service is active", "",
			"sudo pacman -S ufw && sudo ufw default deny incoming && sudo ufw enable && sudo systemctl enable --now ufw")}, nil
	}
	if e.Root && have("ufw") && contains(active, "ufw") {
		o, _, _, _ := run(e.Ctx, 10*time.Second, "ufw", "status")
		if !strings.Contains(o, "Status: active") {
			return []Finding{finding("NET-FIREWALL", SevHigh, "ufw service runs but the firewall is not enabled",
				"ufw.service is active, yet `ufw status` reports inactive.", "sudo ufw enable", lines(o)...)}, nil
		}
	}
	return nil, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// ───────────────────────────── checks: accounts & access ─────────────────────────────

func checkAccounts(e *Env) ([]Finding, error) {
	var fs []Finding
	var uid0 []string
	for _, l := range readLines("/etc/passwd") {
		f := strings.Split(l, ":")
		if len(f) >= 4 && f[2] == "0" && f[0] != "root" {
			uid0 = append(uid0, l)
		}
	}
	if len(uid0) > 0 {
		fs = append(fs, finding("ACCT-UID0", SevCritical, "Non-root account with UID 0", "Equivalent to a hidden root account.",
			"Investigate immediately: sudo userdel <name>, then audit for compromise.", uid0...))
	}
	if st, err := os.Stat("/etc/shadow"); err == nil && st.Mode().Perm()&0o007 != 0 {
		fs = append(fs, finding("ACCT-SHADOW-PERMS", SevCritical, "/etc/shadow is world-readable", "",
			"sudo chmod 600 /etc/shadow && sudo chown root:root /etc/shadow", st.Mode().String()))
	}
	if e.Root {
		var empty []string
		for _, l := range readLines("/etc/shadow") {
			f := strings.Split(l, ":")
			if len(f) > 1 && f[1] == "" {
				empty = append(empty, f[0])
			}
		}
		if len(empty) > 0 {
			fs = append(fs, finding("ACCT-EMPTY-PW", SevHigh, "Accounts with an empty password", "",
				"sudo passwd <name> or sudo passwd -l <name>", empty...))
		}
		var nopw []string
		files, _ := filepath.Glob("/etc/sudoers.d/*")
		files = append(files, "/etc/sudoers")
		for _, p := range files {
			for _, l := range readLines(p) {
				if t := strings.TrimSpace(l); !strings.HasPrefix(t, "#") && strings.Contains(t, "NOPASSWD") {
					nopw = append(nopw, p+": "+t)
				}
			}
		}
		if len(nopw) > 0 {
			fs = append(fs, finding("ACCT-SUDO-NOPASSWD", SevMedium, "sudo rules that skip the password",
				"Any process running as that user gets root without a prompt.",
				"Remove NOPASSWD unless required (visudo).", nopw...))
		}
	}
	return fs, nil
}

func checkSSH(e *Env) ([]Finding, error) {
	var fs []Finding
	o, _, _, _ := run(e.Ctx, 5*time.Second, "systemctl", "is-active", "sshd")
	if strings.TrimSpace(o) == "active" {
		sev, ev := SevInfo, []string{"sshd is running"}
		if e.Root && have("sshd") {
			t, _, _, _ := run(e.Ctx, 10*time.Second, "sshd", "-T")
			for _, l := range lines(t) {
				if l == "permitrootlogin yes" || l == "passwordauthentication yes" {
					ev = append(ev, l)
					if l == "permitrootlogin yes" {
						sev = SevHigh
					} else if sev < SevMedium {
						sev = SevMedium
					}
				}
			}
		}
		fs = append(fs, finding("SSH-RUNNING", sev, "SSH server is running",
			"Only keep sshd on if you need remote login. Prefer key-only auth and no root login.",
			"Disable: sudo systemctl disable --now sshd. Or set PasswordAuthentication no / PermitRootLogin no in /etc/ssh/sshd_config.d/.", ev...))
	}
	var keys []string
	for _, h := range e.Homes {
		p := filepath.Join(h, ".ssh", "authorized_keys")
		if b, err := os.ReadFile(p); err == nil {
			n := 0
			for _, l := range lines(string(b)) {
				if !strings.HasPrefix(strings.TrimSpace(l), "#") {
					n++
				}
			}
			if n > 0 {
				keys = append(keys, fmt.Sprintf("%s (%d keys)", p, n))
			}
		}
	}
	if len(keys) > 0 {
		fs = append(fs, finding("SSH-AUTHKEYS", SevLow, "authorized_keys present", "These keys can log in to this machine.",
			"Verify every key is yours and remove the rest.", keys...))
	}
	return fs, nil
}

var ipRe = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)

func checkLogins(e *Env) ([]Finding, error) {
	var fs []Finding
	if have("last") {
		o, _, _, _ := run(e.Ctx, 10*time.Second, "last", "-a", "-w", "-n", "200")
		var ev []string
		for _, l := range lines(o) {
			f := strings.Fields(l)
			if len(f) < 3 || f[0] == "reboot" || f[0] == "wtmp" || strings.HasPrefix(l, "wtmp") {
				continue
			}
			h := f[len(f)-1]
			if ipRe.MatchString(h) || (strings.Count(h, ":") >= 2 && !strings.HasPrefix(h, ":")) {
				ev = append(ev, l)
			}
		}
		if len(ev) > 0 {
			fs = append(fs, finding("AUTH-REMOTE-LOGIN", SevMedium, fmt.Sprintf("%d remote logins in login history", len(ev)),
				"Logins from a network address. Expected only if you use SSH.", "Confirm each is you; rotate credentials if not.", ev...))
		}
	}
	if e.Root && have("lastb") {
		o, _, _, _ := run(e.Ctx, 10*time.Second, "lastb", "-a", "-w", "-n", "50")
		var ev []string
		for _, l := range lines(o) {
			if !strings.HasPrefix(l, "btmp") {
				ev = append(ev, l)
			}
		}
		if len(ev) > 0 {
			fs = append(fs, finding("AUTH-FAILED", SevLow, fmt.Sprintf("%d failed login attempts recorded", len(ev)), "",
				"Check whether they were you. Many failures from one address indicates brute-forcing.", ev...))
		}
	}
	return fs, nil
}

// ───────────────────────────── checks: persistence ─────────────────────────────

func checkSystemdUnits(e *Env) ([]Finding, error) {
	dirs := []string{"/etc/systemd/system", "/etc/systemd/user", "/usr/local/lib/systemd/system"}
	for _, h := range e.Homes {
		dirs = append(dirs, filepath.Join(h, ".config/systemd/user"), filepath.Join(h, ".local/share/systemd/user"))
	}
	var hi, lo, disg []string
	for _, d := range dirs {
		walk(e, d, func(p string, de fs.DirEntry) {
			if !de.Type().IsRegular() {
				return
			}
			ok := false
			for _, s := range []string{".service", ".timer", ".path", ".socket"} {
				if strings.HasSuffix(p, s) {
					ok = true
				}
			}
			if !ok || (strings.HasPrefix(p, "/etc/") && pacmanOwns(e, p)) {
				return
			}
			var exec []string
			bad := false
			body := readLines(p)
			if sc, why := unitScore(p, body); sc >= 5 {
				disg = append(disg, fmt.Sprintf("%s (score %d: %s)", p, sc, strings.Join(why, "; ")))
				return
			}
			for _, l := range body {
				t := strings.TrimSpace(l)
				if strings.HasPrefix(t, "ExecStart") {
					exec = append(exec, t)
					if suspicious.MatchString(t) || unitTmpRe.MatchString(t) {
						bad = true
					}
				}
			}
			line := p + " " + strings.Join(exec, " ; ")
			if bad {
				hi = append(hi, line)
			} else {
				lo = append(lo, line)
			}
		})
	}
	var out []Finding
	if len(disg) > 0 {
		out = append(out, finding("PERSIST-UNIT-DISGUISED", SevHigh, fmt.Sprintf("%d systemd units disguised as system components", len(disg)),
			"Not from any package, yet named/described like GNOME/KDE/systemd services, with hidden logging or scripts in hidden directories. This is how user-level malware persists without root.",
			"systemctl --user disable --now <unit>; read the script it runs; copy the folder aside as evidence; delete the unit and folder; find how it arrived.", disg...))
	}
	if len(hi) > 0 {
		out = append(out, finding("PERSIST-UNIT-SUSPICIOUS", SevHigh, "Unpackaged systemd unit with suspicious ExecStart",
			"Runs from a temp dir or uses download-and-execute / reverse-shell patterns.",
			"systemctl disable --now <unit>; delete the file; find out how it got there.", hi...))
	}
	if len(lo) > 0 {
		out = append(out, finding("PERSIST-UNIT-CUSTOM", SevInfo, fmt.Sprintf("%d custom systemd units not owned by any package", len(lo)),
			"Legitimate only if you created them. Real gvfs units ship in /usr/lib/systemd/user, never in your home. Review each command.", "", lo...))
	}
	return out, nil
}

func checkCron(e *Env) ([]Finding, error) {
	files := []string{"/etc/crontab"}
	for _, g := range []string{"/etc/cron.d/*", "/var/spool/cron/*", "/var/spool/cron/crontabs/*"} {
		m, _ := filepath.Glob(g)
		files = append(files, m...)
	}
	var hi, lo []string
	for _, p := range files {
		for i, l := range readLines(p) {
			t := strings.TrimSpace(l)
			if t == "" || strings.HasPrefix(t, "#") || cronEnvRe.MatchString(t) {
				continue
			}
			s := fmt.Sprintf("%s:%d: %s", p, i+1, trunc(t, 160))
			if suspicious.MatchString(t) {
				hi = append(hi, s)
			} else {
				lo = append(lo, s)
			}
		}
	}
	var out []Finding
	if len(hi) > 0 {
		out = append(out, finding("PERSIST-CRON-SUSPICIOUS", SevHigh, "Suspicious cron entries", "",
			"Remove the entry and investigate its origin.", hi...))
	}
	if len(lo) > 0 {
		out = append(out, finding("PERSIST-CRON", SevInfo, fmt.Sprintf("%d cron entries", len(lo)), "Review that you recognise each.", "", lo...))
	}
	return out, nil
}

func checkAutostart(e *Env) ([]Finding, error) {
	dirs := []string{"/etc/xdg/autostart"}
	for _, h := range e.Homes {
		dirs = append(dirs, filepath.Join(h, ".config/autostart"))
	}
	var hi, lo []string
	for _, d := range dirs {
		m, _ := filepath.Glob(filepath.Join(d, "*.desktop"))
		for _, p := range m {
			if strings.HasPrefix(p, "/etc/") && pacmanOwns(e, p) {
				continue
			}
			for _, l := range readLines(p) {
				if strings.HasPrefix(l, "Exec=") {
					s := p + ": " + trunc(l, 160)
					if suspicious.MatchString(l) {
						hi = append(hi, s)
					} else {
						lo = append(lo, s)
					}
				}
			}
		}
	}
	var out []Finding
	if len(hi) > 0 {
		out = append(out, finding("PERSIST-AUTOSTART-SUSPICIOUS", SevHigh, "Suspicious desktop autostart entry", "",
			"Delete the .desktop file and investigate.", hi...))
	}
	if len(lo) > 0 {
		out = append(out, finding("PERSIST-AUTOSTART", SevInfo, fmt.Sprintf("%d user autostart entries", len(lo)), "Apps launched at login.", "", lo...))
	}
	return out, nil
}

func checkShellRC(e *Env) ([]Finding, error) {
	names := []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zshenv", ".zprofile", ".config/fish/config.fish"}
	var ev []string
	for _, h := range e.Homes {
		for _, n := range names {
			p := filepath.Join(h, n)
			for i, l := range readLines(p) {
				t := strings.TrimSpace(l)
				if !strings.HasPrefix(t, "#") && suspicious.MatchString(t) {
					ev = append(ev, fmt.Sprintf("%s:%d: %s", p, i+1, trunc(t, 160)))
				}
			}
		}
	}
	if len(ev) == 0 {
		return nil, nil
	}
	return []Finding{finding("PERSIST-SHELLRC", SevHigh, "Suspicious commands in shell startup files",
		"Runs on every terminal you open. Matches download-and-execute, base64 decode, reverse-shell or LD_PRELOAD patterns.",
		"Review each line. Installers like nvm/sdkman may be legitimate, but unknown curl|sh lines are not.", ev...)}, nil
}

// ───────────────────────────── checks: filesystem & processes ─────────────────────────────

func checkSUID(e *Env) ([]Finding, error) {
	roots := []string{"/usr", "/opt", "/etc", "/srv", "/var", "/tmp"}
	roots = append(roots, e.Homes...)
	var unowned []string
	seen := map[string]bool{}
	for _, r := range roots {
		walk(e, r, func(p string, d fs.DirEntry) {
			if !d.Type().IsRegular() || seen[p] {
				return
			}
			info, err := d.Info()
			if err != nil || info.Mode()&(os.ModeSetuid|os.ModeSetgid) == 0 {
				return
			}
			seen[p] = true
			if !pacmanOwns(e, p) {
				unowned = append(unowned, fmt.Sprintf("%s (%s)", p, info.Mode()))
			}
		})
	}
	if len(unowned) == 0 {
		return nil, nil
	}
	sort.Strings(unowned)
	return []Finding{finding("FS-SUID-UNOWNED", SevHigh, fmt.Sprintf("%d SUID/SGID files not owned by any package", len(unowned)),
		"Privilege-escalation backdoors are usually planted as SUID binaries outside the package database.",
		"Inspect with `ls -l` and `file`. Remove with chmod u-s,g-s if unneeded; delete if unknown.", unowned...)}, nil
}

func checkTempExec(e *Env) ([]Finding, error) {
	var elf, scripts []string
	for _, r := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		walk(e, r, func(p string, d fs.DirEntry) {
			if !d.Type().IsRegular() {
				return
			}
			info, err := d.Info()
			if err != nil {
				return
			}
			if strings.HasPrefix(p, "/tmp/go-build") {
				return
			}
			isElf := false
			if f, err := os.Open(p); err == nil {
				b := make([]byte, 4)
				if n, _ := f.Read(b); n == 4 && string(b) == "\x7fELF" {
					isElf = true
				}
				f.Close()
			}
			switch {
			case isElf:
				elf = append(elf, p)
			case info.Mode()&0o111 != 0:
				scripts = append(scripts, p)
			}
		})
	}
	var out []Finding
	if len(elf) > 0 {
		sort.Strings(elf)
		out = append(out, finding("FS-TMP-ELF", SevMedium, fmt.Sprintf("%d native binaries in temp directories", len(elf)),
			"Malware commonly stages payloads in /tmp, /var/tmp and /dev/shm. Build tools and Electron apps also leave files here.",
			"Inspect: file <path>, sha256sum <path>, then search the hash on virustotal.com. Delete if unknown.", elf...))
	}
	if len(scripts) > 0 {
		sort.Strings(scripts)
		out = append(out, finding("FS-TMP-EXEC", SevLow, fmt.Sprintf("%d executable files in temp directories", len(scripts)), "", "Review and delete what you do not recognise.", scripts...))
	}
	return out, nil
}

func checkProcesses(e *Env) ([]Finding, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var tmp, miners, deleted []string
	for _, en := range ents {
		pid := en.Name()
		if n, err := strconv.Atoi(pid); err != nil || n == os.Getpid() {
			continue
		}
		exe, err := os.Readlink("/proc/" + pid + "/exe")
		if err != nil {
			continue
		}
		cm, _ := os.ReadFile("/proc/" + pid + "/comm")
		comm := strings.TrimSpace(string(cm))
		cl, _ := os.ReadFile("/proc/" + pid + "/cmdline")
		cmdline := strings.ReplaceAll(string(cl), "\x00", " ")
		label := fmt.Sprintf("pid %s %s -> %s", pid, comm, exe)
		switch {
		case minerRe.MatchString(exe) || minerRe.MatchString(comm) || minerRe.MatchString(filepath.Base(firstArg(cmdline))) || stratumRe.MatchString(cmdline):
			miners = append(miners, label+" | "+trunc(cmdline, 120))
		case strings.HasPrefix(exe, "/tmp/") || strings.HasPrefix(exe, "/var/tmp/") || strings.HasPrefix(exe, "/dev/shm/"):
			tmp = append(tmp, label)
		case strings.HasSuffix(exe, " (deleted)"):
			deleted = append(deleted, label)
		}
	}
	var out []Finding
	if len(miners) > 0 {
		out = append(out, finding("PROC-MINER", SevCritical, "Process matches cryptominer indicators", "",
			"Kill it, find the persistence (cron, systemd, shell rc), rotate credentials.", miners...))
	}
	if len(tmp) > 0 {
		out = append(out, finding("PROC-TMP-EXEC", SevHigh, "Processes running from temp directories",
			"Legitimate software rarely runs from /tmp or /dev/shm.", "Inspect with `ls -l /proc/<pid>/exe` and `sudo ss -tupn`. Kill and remove if unknown.", tmp...))
	}
	if len(deleted) > 0 {
		out = append(out, finding("PROC-DELETED-BIN", SevLow, fmt.Sprintf("%d processes run a binary that was replaced on disk", len(deleted)),
			"Normal after updates: the old version is still in memory. Malware also deletes itself after launch, so verify the list.",
			"Restart those services or reboot. If a process is unfamiliar, investigate.", deleted...))
	}
	if !e.Root {
		out = append(out, finding("PROC-PARTIAL", SevInfo, "Process scan limited to your own processes", "", "Run with sudo for full coverage."))
	}
	return out, nil
}

// ───────────────────────────── checks: hardening ─────────────────────────────

func checkSysctl(e *Env) ([]Finding, error) {
	type rule struct {
		key string
		ok  []int
	}
	rules := []rule{
		{"kernel.dmesg_restrict", []int{1}}, {"kernel.kptr_restrict", []int{1, 2}},
		{"kernel.yama.ptrace_scope", []int{1, 2, 3}}, {"kernel.unprivileged_bpf_disabled", []int{1, 2}},
		{"kernel.randomize_va_space", []int{2}}, {"net.core.bpf_jit_harden", []int{1, 2}},
		{"fs.protected_symlinks", []int{1}}, {"fs.protected_hardlinks", []int{1}},
		{"fs.protected_fifos", []int{1, 2}}, {"fs.protected_regular", []int{1, 2}},
		{"fs.suid_dumpable", []int{0}}, {"net.ipv4.tcp_syncookies", []int{1}},
		{"net.ipv4.conf.all.rp_filter", []int{1, 2}}, {"net.ipv4.conf.all.accept_redirects", []int{0}},
		{"net.ipv4.conf.all.send_redirects", []int{0}}, {"net.ipv4.conf.all.accept_source_route", []int{0}},
	}
	var ev, conf []string
	for _, r := range rules {
		v, ok := func() (int, bool) {
			b, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(r.key, ".", "/"))
			if err != nil {
				return 0, false
			}
			n, err := strconv.Atoi(strings.TrimSpace(string(b)))
			return n, err == nil
		}()
		if !ok {
			continue
		}
		good := false
		for _, x := range r.ok {
			if x == v {
				good = true
			}
		}
		if !good {
			ev = append(ev, fmt.Sprintf("%s = %d (want %v)", r.key, v, r.ok))
			conf = append(conf, fmt.Sprintf("%s = %d", r.key, r.ok[len(r.ok)-1]))
		}
	}
	if len(ev) == 0 {
		return nil, nil
	}
	return []Finding{finding("HARD-SYSCTL", SevLow, fmt.Sprintf("%d kernel parameters weaker than recommended", len(ev)),
		"Low-cost kernel hardening. Docker needs ip_forward, so that one is intentionally not checked.",
		"Put these in /etc/sysctl.d/99-hardening.conf and run `sudo sysctl --system`:\n"+strings.Join(conf, "\n"), ev...)}, nil
}

// ───────────────────────────── checks: external scanners ─────────────────────────────

func ignoreRe(e *Env) []*regexp.Regexp {
	var r []*regexp.Regexp
	for _, s := range e.Opts.Config.IgnoreToolWarns {
		if re, err := regexp.Compile(s); err == nil {
			r = append(r, re)
		}
	}
	return r
}

var fpPath = regexp.MustCompile(`(?i)/(heroic|\.wine|wine|proton|steamapps|compatdata|dxvk|vkd3d|lutris|bottles)(/|-)`)
var avRe = regexp.MustCompile(`^(.+): (\S+) FOUND$`)

func checkClamAV(e *Env) ([]Finding, error) {
	if !have("clamscan") {
		return nil, skip("clamav not installed (sudo pacman -S clamav)")
	}
	if e.Root && have("freshclam") {
		_, _, _, _ = run(e.Ctx, 5*time.Minute, "freshclam", "--quiet")
	}
	paths := e.Opts.Config.ClamPaths
	if e.Opts.ClamPaths != "" {
		paths = strings.Split(e.Opts.ClamPaths, ",")
	}
	if len(paths) == 0 {
		paths = append(paths, e.Homes...)
		paths = append(paths, "/tmp", "/var/tmp", "/opt", "/usr/local", "/srv")
	}
	var ok []string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			ok = append(ok, p)
		}
	}
	args := append([]string{"-r", "-i", `--exclude-dir=/\.cache(/|$)`, `--exclude-dir=^/var/lib/docker`}, ok...)
	out, _, code, err := run(e.Ctx, e.Opts.ClamTimeout, "clamscan", args...)
	if err != nil {
		return nil, err
	}
	if code == 2 {
		return nil, fmt.Errorf("clamscan reported an error (exit 2); run it manually for details")
	}
	var real, likely []string
	for _, l := range lines(out) {
		if g := avRe.FindStringSubmatch(l); g != nil {
			s := g[1] + ": " + g[2]
			if fpPath.MatchString(g[1]) && strings.HasPrefix(g[2], "Win.") {
				likely = append(likely, s)
			} else {
				real = append(real, s)
			}
		}
	}
	var fs []Finding
	if len(real) > 0 {
		fs = append(fs, finding("AV-FOUND", SevHigh, fmt.Sprintf("ClamAV detected %d infected file(s)", len(real)),
			"Signature match. Verify before deleting: sha256sum the file and check virustotal.com.",
			"Delete or quarantine confirmed files, then find how they arrived (downloads, AUR, npm).", real...))
	}
	if len(likely) > 0 {
		fs = append(fs, finding("AV-LIKELY-FP", SevLow, fmt.Sprintf("%d probable false positive(s) in Wine/Proton/game tooling", len(likely)),
			"Windows DLLs (DXVK, VKD3D, Wine) often trip generic Win.* signatures. They never execute natively on Linux.",
			"Compare sha256 with the official release, or delete the folder and let Heroic/Lutris re-download it.", likely...))
	}
	return fs, nil
}

func checkRkhunter(e *Env) ([]Finding, error) {
	if !have("rkhunter") {
		return nil, skip("rkhunter not installed (sudo pacman -S rkhunter)")
	}
	_, _, _, _ = run(e.Ctx, 3*time.Minute, "rkhunter", "--update", "--nocolors")
	out, _, _, err := run(e.Ctx, 20*time.Minute, "rkhunter", "--check", "--sk", "--nocolors", "--rwo")
	if err != nil {
		return nil, err
	}
	benign := []*regexp.Regexp{
		regexp.MustCompile(`/usr/bin/(egrep|fgrep|ldd)'? has been replaced by a script`),
		regexp.MustCompile(`Hidden file found: (/etc/\.updated|/usr/share/man/man5/\.k5)`),
		regexp.MustCompile(`SSH configuration option '(PermitRootLogin|Protocol)' has not been set`),
		regexp.MustCompile(`no copy of the (passwd|group) file exists`),
		regexp.MustCompile(`Checking for prerequisites|users responsibility to ensure`),
	}
	benign = append(benign, ignoreRe(e)...)
	var warn, rootkit []string
next:
	for _, l := range lines(out) {
		if !strings.Contains(l, "Warning") {
			continue
		}
		for _, b := range benign {
			if b.MatchString(l) {
				continue next
			}
		}
		if strings.Contains(strings.ToLower(l), "rootkit") {
			rootkit = append(rootkit, l)
		} else {
			warn = append(warn, l)
		}
	}
	var fs []Finding
	if len(rootkit) > 0 {
		fs = append(fs, finding("RKH-ROOTKIT", SevCritical, "rkhunter reports possible rootkit indicators", "",
			"Cross-check with `sudo rkhunter --check` and the log in /var/log/rkhunter.log. If confirmed: disconnect, back up data only, reinstall.", rootkit...))
	}
	if len(warn) > 0 {
		fs = append(fs, finding("RKH-WARN", SevMedium, fmt.Sprintf("%d rkhunter warnings after filtering known Arch false positives", len(warn)), "",
			"Review each in /var/log/rkhunter.log. After verifying the system is clean: sudo rkhunter --propupd", warn...))
	}
	return fs, nil
}

func checkLynis(e *Env) ([]Finding, error) {
	if !have("lynis") {
		return nil, skip("lynis not installed (sudo pacman -S lynis)")
	}
	if _, _, _, err := run(e.Ctx, 15*time.Minute, "lynis", "audit", "system", "--quiet", "--no-colors"); err != nil {
		return nil, err
	}
	var warns, sugg []string
	idx := ""
	for _, l := range readLines("/var/log/lynis-report.dat") {
		switch {
		case strings.HasPrefix(l, "hardening_index="):
			idx = strings.TrimPrefix(l, "hardening_index=")
		case strings.HasPrefix(l, "warning[]="):
			f := strings.Split(strings.TrimPrefix(l, "warning[]="), "|")
			if len(f) >= 2 && f[0] != "KRNL-5830" && f[0] != "PKGS-7322" { // covered by PATCH-* / CVE-* checks
				warns = append(warns, f[0]+": "+f[1])
			}
		case strings.HasPrefix(l, "suggestion[]="):
			f := strings.Split(strings.TrimPrefix(l, "suggestion[]="), "|")
			if len(f) >= 2 {
				sugg = append(sugg, f[0]+": "+f[1])
			}
		}
	}
	var fs []Finding
	if len(warns) > 0 {
		fs = append(fs, finding("LYNIS-WARN", SevMedium, fmt.Sprintf("%d Lynis warnings", len(warns)), "",
			"Details: sudo lynis show details <ID>", warns...))
	}
	if len(sugg) > 0 {
		fs = append(fs, finding("LYNIS-SUGGEST", SevLow, fmt.Sprintf("%d Lynis hardening suggestions (index %s)", len(sugg), valOr(idx, "?")),
			"Many are server-oriented (auditd, separate /var, password aging) and optional on a desktop.",
			"Prioritise: sysctl, USB/firewire modules, umask, core dumps. Look up each with `lynis show details <ID>`.", sugg...))
	}
	return fs, nil
}

// ───────────────────────────── registry ─────────────────────────────

func registry() []Check {
	return []Check{
		{ID: "patch-updates", Name: "Pending package updates", Category: "Patching", Run: checkUpdates},
		{ID: "patch-reboot", Name: "Kernel/reboot state", Category: "Patching", Run: checkReboot},
		{ID: "cve-audit", Name: "Known CVEs (arch-audit)", Category: "Patching", Run: checkArchAudit},
		{ID: "integrity", Name: "Package file integrity (pacman -Qkk)", Category: "Integrity", Slow: true, Run: checkPkgIntegrity},
		{ID: "foreign-pkgs", Name: "AUR / foreign packages", Category: "Integrity", Run: checkForeignPkgs},
		{ID: "ld-preload", Name: "ld.so.preload hook", Category: "Integrity", Run: checkLdPreload},
		{ID: "secureboot", Name: "Secure Boot", Category: "Hardening", Run: checkBootSecurity},
		{ID: "net-listen", Name: "Listening ports", Category: "Network", Run: checkListening},
		{ID: "net-docker", Name: "Docker published ports", Category: "Network", Run: checkDocker},
		{ID: "net-firewall", Name: "Host firewall", Category: "Network", Run: checkFirewall},
		{ID: "accounts", Name: "Accounts & sudo", Category: "Access", Root: true, Run: checkAccounts},
		{ID: "ssh", Name: "SSH exposure & keys", Category: "Access", Run: checkSSH},
		{ID: "logins", Name: "Login history", Category: "Access", Run: checkLogins},
		{ID: "persist-systemd", Name: "systemd units (persistence)", Category: "Persistence", Run: checkSystemdUnits},
		{ID: "persist-cron", Name: "Cron jobs", Category: "Persistence", Run: checkCron},
		{ID: "persist-autostart", Name: "Desktop autostart", Category: "Persistence", Run: checkAutostart},
		{ID: "persist-shellrc", Name: "Shell startup files", Category: "Persistence", Run: checkShellRC},
		{ID: "fs-suid", Name: "Unowned SUID/SGID files", Category: "Filesystem", Slow: true, Run: checkSUID},
		{ID: "fs-tmp", Name: "Executables in temp dirs", Category: "Filesystem", Run: checkTempExec},
		{ID: "procs", Name: "Suspicious processes", Category: "Runtime", Run: checkProcesses},
		{ID: "proc-scripts", Name: "Scripts run from hidden dirs", Category: "Runtime", Run: checkProcScripts},
		{ID: "proc-hidden", Name: "Hidden processes (rootkit)", Category: "Runtime", Root: true, Run: checkHiddenPIDs},
		{ID: "net-outbound", Name: "Outbound connections", Category: "Network", Run: checkConnections},
		{ID: "ioc-scripts", Name: "Clipboard hijacker / malware IOCs", Category: "Malware", Run: checkIOCScripts},
		{ID: "persist-misc", Name: "Other persistence locations", Category: "Persistence", Run: checkPersistMisc},
		{ID: "kmod", Name: "Kernel modules", Category: "Integrity", Slow: true, Run: checkKernelModules},
		{ID: "sysctl", Name: "Kernel hardening (sysctl)", Category: "Hardening", Run: checkSysctl},
		{ID: "rkhunter", Name: "rkhunter rootkit scan", Category: "Malware", Root: true, Slow: true, Run: checkRkhunter},
		{ID: "lynis", Name: "Lynis audit", Category: "Hardening", Root: true, Slow: true, Run: checkLynis},
		{ID: "clamav", Name: "ClamAV malware scan", Category: "Malware", Slow: true, Heavy: true, Run: checkClamAV},
	}
}

// ───────────────────────────── runner ─────────────────────────────

func runCheck(e *Env, c Check) (res CheckResult) {
	res = CheckResult{ID: c.ID, Name: c.Name, Category: c.Category, Status: "ok"}
	start := time.Now()
	defer func() { res.DurationMS = time.Since(start).Milliseconds() }()
	defer func() {
		if r := recover(); r != nil {
			res.Status, res.Note = "error", fmt.Sprint("panic: ", r)
		}
	}()
	fs, err := c.Run(e)
	var sk skip
	switch {
	case errors.As(err, &sk):
		res.Status, res.Note = "skipped", string(sk)
		res.Gap = strings.Contains(res.Note, "missing") || strings.Contains(res.Note, "not installed")
		return
	case err != nil:
		res.Status, res.Note, res.Gap = "error", err.Error(), true
		return
	}
	for i := range fs {
		fs[i].Check, fs[i].Category = c.ID, c.Category
		fs[i].Fingerprint = fingerprint(fs[i])
	}
	res.Findings = fs
	for _, f := range fs {
		if f.Severity > SevInfo {
			res.Status = "findings"
		}
	}
	return
}

func suppressed(cfg *Config, id string) string {
	for _, s := range cfg.Suppress {
		if s.ID == id || (strings.HasSuffix(s.ID, "*") && strings.HasPrefix(id, strings.TrimSuffix(s.ID, "*"))) {
			return valOr(s.Reason, "suppressed")
		}
	}
	return ""
}

// ───────────────────────────── output ─────────────────────────────

type painter struct{ on bool }

func (p painter) c(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p painter) sev(s Severity) string {
	codes := []string{"90", "36", "33", "31", "1;97;41"}
	return p.c(codes[s], fmt.Sprintf("%-8s", s.String()))
}

func score(r *Report) {
	pen := map[Severity]int{SevCritical: 30, SevHigh: 12, SevMedium: 4, SevLow: 1}
	r.Counts = map[string]int{}
	s := 100
	for _, res := range r.Results {
		for _, f := range res.Findings {
			if f.Suppressed != "" {
				r.Suppressed++
				continue
			}
			r.Counts[strings.ToLower(f.Severity.String())]++
			s -= pen[f.Severity]
		}
	}
	if s < 0 {
		s = 0
	}
	ran, errs := 0, 0
	for _, res := range r.Results {
		switch {
		case res.Status == "ok" || res.Status == "findings":
			ran++
		case res.Status == "error":
			errs++
			r.Incomplete = append(r.Incomplete, res.Name+": "+res.Note)
		case res.Gap:
			r.Incomplete = append(r.Incomplete, res.Name+": "+res.Note)
		}
	}
	r.Coverage = fmt.Sprintf("%d/%d checks ran", ran, ran+len(r.Incomplete))
	r.Score = s
	switch {
	case s >= 90:
		r.Grade = "A"
	case s >= 75:
		r.Grade = "B"
	case s >= 60:
		r.Grade = "C"
	case s >= 40:
		r.Grade = "D"
	default:
		r.Grade = "F"
	}
	// A scan that could not look everywhere must not claim a clean bill of health.
	cap := ""
	switch {
	case errs > 0 || len(r.Incomplete) >= 4:
		cap = "C"
	case len(r.Incomplete) > 0:
		cap = "B"
	}
	if cap != "" && r.Grade < cap { // "A" < "B" < "C" lexically
		r.Grade = cap
		r.GradeNote = fmt.Sprintf("capped at %s: %d check(s) could not run, so the score is not trustworthy", cap, len(r.Incomplete))
	} else if cap != "" {
		r.GradeNote = fmt.Sprintf("%d check(s) could not run, coverage is incomplete", len(r.Incomplete))
	}
}

// actionPlan groups open findings into what to do now, this week, and later.
func actionPlan(r *Report) (now, soon, later []string) {
	for _, f := range allFindings(r, false) {
		if f.Severity == SevInfo {
			continue
		}
		fix := strings.SplitN(f.Remediation, "\n", 2)[0]
		if fix == "" {
			fix = f.Title
		}
		line := fmt.Sprintf("[%s] %s: %s", f.Severity, f.ID, fix)
		switch {
		case f.Severity >= SevHigh:
			now = append(now, line)
		case f.Severity == SevMedium:
			soon = append(soon, line)
		default:
			later = append(later, line)
		}
	}
	return
}

func allFindings(r *Report, withSuppressed bool) []Finding {
	var fs []Finding
	for _, res := range r.Results {
		for _, f := range res.Findings {
			if f.Suppressed == "" || withSuppressed {
				fs = append(fs, f)
			}
		}
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		return fs[i].Category < fs[j].Category
	})
	return fs
}

func printReport(r *Report, o *Options) {
	p := painter{on: !o.NoColor}
	w := os.Stdout
	fmt.Fprintf(w, "\n%s\n", p.c("1", fmt.Sprintf("secscan %s  |  %s  |  %s  |  kernel %s", version, r.Host, r.OS, r.Kernel)))
	fmt.Fprintf(w, "Scanned %s in %.1fs%s\n", r.StartedAt.Format("2006-01-02 15:04:05"), float64(r.DurationMS)/1000,
		map[bool]string{true: "", false: p.c("33", "  (not root: reduced coverage, use sudo)")}[r.Root])
	gc := map[string]string{"A": "32", "B": "32", "C": "33", "D": "31", "F": "1;31"}[r.Grade]
	fmt.Fprintf(w, "\nSecurity score: %s  (%d/100)   coverage: %s\n", p.c(gc, "Grade "+r.Grade), r.Score, r.Coverage)
	if r.GradeNote != "" {
		fmt.Fprintf(w, "  %s\n", p.c("33", "! "+r.GradeNote))
		for _, i := range r.Incomplete {
			fmt.Fprintf(w, "    - %s\n", i)
		}
	}
	fmt.Fprintf(w, "  critical %d | high %d | medium %d | low %d | info %d | suppressed %d\n",
		r.Counts["critical"], r.Counts["high"], r.Counts["medium"], r.Counts["low"], r.Counts["info"], r.Suppressed)

	fs := allFindings(r, o.ShowSuppressed)
	fmt.Fprintf(w, "\n%s\n", p.c("1", "FINDINGS (highest severity first)"))
	if len(fs) == 0 {
		fmt.Fprintln(w, "  none")
	}
	limit := 6
	if o.Verbose {
		limit = 1 << 30
	}
	for _, f := range fs {
		tag := ""
		if f.Status == "new" {
			tag = p.c("1;35", "  [NEW]")
		}
		if f.Suppressed != "" {
			tag += p.c("90", "  [suppressed: "+f.Suppressed+"]")
		}
		fmt.Fprintf(w, "\n%s %s  %s%s\n", p.sev(f.Severity), p.c("1", f.ID), f.Title, tag)
		if f.Detail != "" {
			fmt.Fprintf(w, "    why: %s\n", f.Detail)
		}
		lim := limit
		if f.Severity >= SevHigh && lim < 15 {
			lim = 15
		}
		for i, ev := range f.Evidence {
			if i == lim {
				fmt.Fprintf(w, "    ... %d more (use -v or the JSON/Markdown report)\n", len(f.Evidence)-lim)
				break
			}
			fmt.Fprintf(w, "    - %s\n", trunc(ev, 200))
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "    fix: %s\n", strings.ReplaceAll(f.Remediation, "\n", "\n         "))
		}
	}

	fmt.Fprintf(w, "\n%s\n", p.c("1", "CHECKS"))
	for _, res := range r.Results {
		st := map[string]string{"ok": p.c("32", "ok      "), "findings": p.c("33", "findings"), "skipped": p.c("90", "skipped "), "error": p.c("31", "error   ")}[res.Status]
		note := ""
		if res.Note != "" {
			note = "  - " + res.Note
		}
		fmt.Fprintf(w, "  %s %-40s %5.1fs%s\n", st, res.Name, float64(res.DurationMS)/1000, note)
	}

	if len(r.Resolved) > 0 {
		fmt.Fprintf(w, "\n%s\n", p.c("32", fmt.Sprintf("RESOLVED since last run (%d)", len(r.Resolved))))
		for _, t := range r.Resolved {
			fmt.Fprintf(w, "  + %s\n", t)
		}
	}

	now, soon, later := actionPlan(r)
	section := func(title, col string, items []string, max int) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(w, "\n%s\n", p.c(col, title))
		for i, s := range items {
			if i == max {
				fmt.Fprintf(w, "  ... %d more in the report\n", len(items)-max)
				break
			}
			fmt.Fprintf(w, "  %d. %s\n", i+1, trunc(s, 200))
		}
	}
	section("ACTION PLAN: DO NOW (critical/high)", "1;31", now, 20)
	section("ACTION PLAN: THIS WEEK (medium)", "33", soon, 10)
	section("ACTION PLAN: WHEN CONVENIENT (low)", "36", later, 5)
	if len(now) == 0 && len(soon) == 0 && len(later) == 0 && len(r.Incomplete) == 0 {
		fmt.Fprintf(w, "\n%s\n", p.c("32", "Nothing to fix. Re-run after every system change or weekly."))
	}
}

func markdown(r *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Security report: %s\n\n", r.Host)
	fmt.Fprintf(&b, "- Date: %s\n- OS: %s, kernel %s\n- Tool: secscan %s (root: %v)\n- Score: **%s (%d/100)**\n- Counts: critical %d, high %d, medium %d, low %d, info %d, suppressed %d\n\n",
		r.StartedAt.Format(time.RFC1123), r.OS, r.Kernel, r.Version, r.Root, r.Grade, r.Score,
		r.Counts["critical"], r.Counts["high"], r.Counts["medium"], r.Counts["low"], r.Counts["info"], r.Suppressed)
	fmt.Fprintf(&b, "- Coverage: %s\n", r.Coverage)
	if r.GradeNote != "" {
		fmt.Fprintf(&b, "- **Warning:** %s\n", r.GradeNote)
		for _, i := range r.Incomplete {
			fmt.Fprintf(&b, "  - could not run: %s\n", i)
		}
	}
	b.WriteString("\n## Action plan\n\n")
	now, soon, later := actionPlan(r)
	for _, g := range []struct {
		t  string
		it []string
	}{{"Do now (critical/high)", now}, {"This week (medium)", soon}, {"When convenient (low)", later}} {
		if len(g.it) == 0 {
			continue
		}
		fmt.Fprintf(&b, "**%s**\n\n", g.t)
		for _, x := range g.it {
			fmt.Fprintf(&b, "- [ ] %s\n", x)
		}
		b.WriteString("\n")
	}
	if len(now)+len(soon)+len(later) == 0 {
		b.WriteString("Nothing to fix.\n\n")
	}
	b.WriteString("## Findings\n\n")
	for _, f := range allFindings(r, false) {
		st := ""
		if f.Status == "new" {
			st = " **(NEW)**"
		}
		fmt.Fprintf(&b, "### [%s] %s: %s%s\n\n", f.Severity, f.ID, f.Title, st)
		if f.Detail != "" {
			fmt.Fprintf(&b, "%s\n\n", f.Detail)
		}
		if len(f.Evidence) > 0 {
			b.WriteString("Evidence:\n\n```\n")
			b.WriteString(strings.Join(f.Evidence, "\n"))
			b.WriteString("\n```\n\n")
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "**Fix:**\n\n```\n%s\n```\n\n", f.Remediation)
		}
	}
	b.WriteString("## Checks\n\n| Check | Status | Time | Note |\n|---|---|---|---|\n")
	for _, res := range r.Results {
		fmt.Fprintf(&b, "| %s | %s | %.1fs | %s |\n", res.Name, res.Status, float64(res.DurationMS)/1000, res.Note)
	}
	return b.String()
}

// ───────────────────────────── plumbing ─────────────────────────────

func primaryHome() string {
	if su := os.Getenv("SUDO_USER"); su != "" {
		if u, err := user.Lookup(su); err == nil {
			return u.HomeDir
		}
	}
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return os.Getenv("HOME")
}

func detectHomes() []string {
	set := map[string]bool{primaryHome(): true}
	if u, err := user.Current(); err == nil {
		set[u.HomeDir] = true
	}
	if os.Geteuid() == 0 {
		if ents, err := os.ReadDir("/home"); err == nil {
			for _, en := range ents {
				if en.IsDir() {
					set["/home/"+en.Name()] = true
				}
			}
		}
	}
	var out []string
	for h := range set {
		if h != "" {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

func chownToSudoUser(paths ...string) {
	if os.Geteuid() != 0 {
		return
	}
	uid, e1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, e2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if e1 != nil || e2 != nil {
		return
	}
	for _, p := range paths {
		_ = os.Chown(p, uid, gid)
	}
}

func osName() string {
	for _, l := range readLines("/etc/os-release") {
		if strings.HasPrefix(l, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), `"`)
		}
	}
	return "Linux"
}

func splitSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			m[x] = true
		}
	}
	return m
}

const exampleConfig = `{
  "suppress": [
    {"id": "NET-LISTEN-udp-5353", "reason": "mDNS from avahi, intended"},
    {"id": "NET-LISTEN-tcp-1716", "reason": "KDE Connect, paired phone"},
    {"id": "PROC-DELETED-BIN", "reason": "stale after updates, handled by reboot"}
  ],
  "allowed_ports": [],
  "clamav_paths": [],
  "ignore_tool_warnings_regex": []
}
`

func main() { os.Exit(realMain()) }

func realMain() int {
	var o Options
	flag.BoolVar(&o.Quick, "quick", false, "skip slow checks (integrity, SUID walk, rkhunter, lynis)")
	flag.BoolVar(&o.Full, "full", false, "run everything including the ClamAV scan")
	flag.BoolVar(&o.ClamAV, "clamav", false, "also run the ClamAV scan (slow)")
	flag.StringVar(&o.Only, "only", "", "comma-separated check IDs to run")
	flag.StringVar(&o.Skip, "skip", "", "comma-separated check IDs to skip")
	flag.BoolVar(&o.JSON, "json", false, "print the JSON report to stdout (progress goes to stderr)")
	flag.BoolVar(&o.NoColor, "no-color", false, "disable colours")
	flag.BoolVar(&o.Verbose, "v", false, "show all evidence lines")
	flag.BoolVar(&o.ShowSuppressed, "show-suppressed", false, "also list suppressed findings")
	flag.BoolVar(&o.NoSave, "no-save", false, "do not write reports or baseline")
	flag.BoolVar(&o.List, "list", false, "list available checks and exit")
	flag.BoolVar(&o.InitConfig, "init-config", false, "write an example config file and exit")
	flag.BoolVar(&o.Version, "version", false, "print version")
	flag.StringVar(&o.OutDir, "out", "", "report directory (default ~/.local/share/secscan)")
	flag.StringVar(&o.FailOn, "fail-on", "high", "exit 1 if an unsuppressed finding is at/above: info|low|medium|high|critical")
	flag.StringVar(&o.ConfigPath, "config", "", "config file (default ~/.config/secscan/config.json)")
	flag.StringVar(&o.ClamPaths, "clamav-paths", "", "comma-separated paths for ClamAV")
	flag.DurationVar(&o.ClamTimeout, "clamav-timeout", 2*time.Hour, "ClamAV scan timeout")
	flag.IntVar(&o.Jobs, "jobs", 4, "parallel checks")
	flag.Parse()

	if o.Version {
		fmt.Println("secscan", version)
		return 0
	}
	if !o.JSON && !isTTY(os.Stdout) || os.Getenv("NO_COLOR") != "" {
		o.NoColor = true
	}
	checks := registry()
	if o.List {
		for _, c := range checks {
			fmt.Printf("%-18s %-12s %s\n", c.ID, c.Category, c.Name)
		}
		return 0
	}
	home := primaryHome()
	if o.ConfigPath == "" {
		o.ConfigPath = filepath.Join(home, ".config/secscan/config.json")
	}
	if o.OutDir == "" {
		o.OutDir = filepath.Join(home, ".local/share/secscan")
	}
	if o.InitConfig {
		if _, err := os.Stat(o.ConfigPath); err == nil {
			fmt.Println("config already exists:", o.ConfigPath)
			return 0
		}
		_ = os.MkdirAll(filepath.Dir(o.ConfigPath), 0o755)
		if err := os.WriteFile(o.ConfigPath, []byte(exampleConfig), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		chownToSudoUser(filepath.Dir(o.ConfigPath), o.ConfigPath)
		fmt.Println("wrote", o.ConfigPath)
		return 0
	}
	if b, err := os.ReadFile(o.ConfigPath); err == nil {
		if err := json.Unmarshal(b, &o.Config); err != nil {
			fmt.Fprintln(os.Stderr, "bad config:", err)
			return 2
		}
	}
	failOn, ok := parseSeverity(o.FailOn)
	if !ok {
		fmt.Fprintln(os.Stderr, "invalid --fail-on")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	env := &Env{Ctx: ctx, Opts: &o, Root: os.Geteuid() == 0, Homes: detectHomes()}
	if !env.Root {
		fmt.Fprintln(os.Stderr, "note: not running as root; some checks are skipped or partial. Use: sudo ./secscan")
	}

	only, skipSet := splitSet(o.Only), splitSet(o.Skip)
	start := time.Now()
	results := make([]CheckResult, len(checks))
	sem := make(chan struct{}, max1(o.Jobs))
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i, c := range checks {
		reason := ""
		switch {
		case len(only) > 0 && !only[c.ID]:
			reason = "not selected"
		case skipSet[c.ID]:
			reason = "skipped by --skip"
		case c.Heavy && !(o.ClamAV || o.Full):
			reason = "opt-in: use --clamav or --full"
		case c.Slow && o.Quick:
			reason = "skipped by --quick"
		case c.Root && !env.Root:
			reason = "needs root (run with sudo)"
		}
		if reason != "" {
			results[i] = CheckResult{ID: c.ID, Name: c.Name, Category: c.Category, Status: "skipped", Note: reason, Gap: c.Root && !env.Root && reason == "needs root (run with sudo)"}
			continue
		}
		wg.Add(1)
		go func(i int, c Check) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			mu.Lock()
			fmt.Fprintf(os.Stderr, "  running  %s\n", c.Name)
			mu.Unlock()
			r := runCheck(env, c)
			results[i] = r
			mu.Lock()
			fmt.Fprintf(os.Stderr, "  done     %-40s %s (%.1fs)\n", c.Name, r.Status, float64(r.DurationMS)/1000)
			mu.Unlock()
		}(i, c)
	}
	wg.Wait()

	host, _ := os.Hostname()
	kern, _, _, _ := run(ctx, 5*time.Second, "uname", "-r")
	rep := &Report{Tool: "secscan", Version: version, Host: host, OS: osName(), Kernel: strings.TrimSpace(kern),
		StartedAt: start, DurationMS: time.Since(start).Milliseconds(), Root: env.Root, Results: results}

	// suppressions
	for i := range rep.Results {
		for j := range rep.Results[i].Findings {
			f := &rep.Results[i].Findings[j]
			f.Suppressed = suppressed(&o.Config, f.ID)
		}
	}
	// baseline diff
	latest := filepath.Join(o.OutDir, "latest.json")
	if b, err := os.ReadFile(latest); err == nil {
		var prev Report
		if json.Unmarshal(b, &prev) == nil {
			old := map[string]string{}
			ranNow := map[string]bool{}
			for _, r := range rep.Results {
				if r.Status == "ok" || r.Status == "findings" {
					ranNow[r.ID] = true
				}
			}
			for _, r := range prev.Results {
				if !ranNow[r.ID] {
					continue // skipped/errored now: absence of findings proves nothing
				}
				for _, f := range r.Findings {
					if f.Severity > SevInfo && f.Suppressed == "" {
						old[f.Fingerprint] = fmt.Sprintf("[%s] %s", f.Severity, f.Title)
					}
				}
			}
			for i := range rep.Results {
				for j := range rep.Results[i].Findings {
					f := &rep.Results[i].Findings[j]
					if _, seen := old[f.Fingerprint]; seen {
						delete(old, f.Fingerprint)
					} else if f.Severity > SevInfo {
						f.Status = "new"
					}
				}
			}
			for _, t := range old {
				rep.Resolved = append(rep.Resolved, t)
			}
			sort.Strings(rep.Resolved)
		}
	}
	score(rep)

	if o.JSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
	} else {
		printReport(rep, &o)
	}

	if !o.NoSave {
		if err := os.MkdirAll(o.OutDir, 0o755); err == nil {
			stamp := start.Format("20060102-150405")
			jb, _ := json.MarshalIndent(rep, "", "  ")
			files := []string{filepath.Join(o.OutDir, "report-"+stamp+".json"), filepath.Join(o.OutDir, "report-"+stamp+".md"), latest}
			_ = os.WriteFile(files[0], jb, 0o600)
			_ = os.WriteFile(files[1], []byte(markdown(rep)), 0o600)
			_ = os.WriteFile(files[2], jb, 0o600)
			chownToSudoUser(append(files, o.OutDir)...)
			if !o.JSON {
				fmt.Printf("\nReports saved to %s\n", o.OutDir)
			}
		}
	}

	for _, f := range allFindings(rep, false) {
		if f.Severity >= failOn && f.Severity > SevInfo {
			return 1
		}
	}
	for _, r := range rep.Results {
		if r.Status == "error" {
			return 3 // a check failed: do not report success
		}
	}
	return 0
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

func isTTY(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
