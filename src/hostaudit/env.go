package hostaudit

import (
	"context"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"security-go-scanner/src/config"
	"security-go-scanner/src/model"
	"security-go-scanner/src/runner"
)

// SkipError indicates a check was skipped due to an intentional prerequisite gap
// (e.g. missing root privileges or optional third-party binary not installed).
type SkipError string

func (s SkipError) Error() string { return string(s) }

// Options holds runtime flags and configuration for a host security audit.
type Options struct {
	Quick, Full, ClamAV, JSON, NoColor, Verbose, ShowSuppressed, NoSave, List, InitConfig bool
	Only, Skip, OutDir, FailOn, ConfigPath, ClamPaths                                     string
	ClamTimeout                                                                           time.Duration
	Jobs                                                                                  int
	Config                                                                                config.Config
}

// AuditEnv encapsulates shared execution context, user home directories, and system state
// passed to every host audit check.
type AuditEnv struct {
	Ctx   context.Context
	Opts  *Options
	Root  bool
	Homes []string
}

var (
	// suspicious matches common post-exploitation or dropper command patterns in unit files, cron, and shell rc.
	suspicious = regexp.MustCompile(`(?i)(curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh|base64\s+(-d|--decode)|/dev/tcp/|\bnc(at)?\s+(-\w*e|.*\s-e\s)|bash\s+-i\s+>&|python[0-9.]*\s+-c\s+.*socket|chmod\s+\+x\s+/(tmp|dev/shm|var/tmp)|LD_PRELOAD=|xmrig|minerd|stratum\+tcp`)
	minerRe    = regexp.MustCompile(`(?i)xmrig|minerd|cpuminer|kdevtmpfsi|kinsing|cryptonight`)
	stratumRe  = regexp.MustCompile(`(?i)stratum\+tcp`)

	ownCache        sync.Map
	defaultSkipDirs = []string{
		"/proc", "/sys", "/dev",
		"/var/lib/docker", "/var/lib/containerd", "/var/lib/containers",
		"/var/lib/flatpak", "/var/lib/snapd", "/var/lib/machines", "/var/lib/lxc",
	}
)

// finding is a package-local helper constructing a model.Finding.
func finding(id string, sev model.Severity, title, detail, fix string, ev ...string) model.Finding {
	return model.NewFinding(id, sev, title, detail, fix, ev...)
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimRight(l, "\r \t"); strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func readLines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(string(b), "\n")
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func firstArg(cmdline string) string {
	if f := strings.Fields(cmdline); len(f) > 0 {
		return f[0]
	}
	return ""
}

func valOr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func splitSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			m[p] = true
		}
	}
	return m
}

func pacmanOwns(e *AuditEnv, path string) bool {
	if v, ok := ownCache.Load(path); ok {
		return v.(bool)
	}
	_, _, code, err := runner.Run(e.Ctx, 15*time.Second, "pacman", "-Qqo", path)
	owned := err == nil && code == 0
	ownCache.Store(path, owned)
	return owned
}

func walk(e *AuditEnv, root string, fn func(path string, d fs.DirEntry)) {
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

// PrimaryHome resolves the real user's home directory, handling sudo elevation properly.
func PrimaryHome() string {
	if su := os.Getenv("SUDO_USER"); su != "" {
		if u, err := user.Lookup(su); err == nil {
			return u.HomeDir
		}
	}
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "/root"
}

// DetectHomes discovers all interactive user home directories on the system.
func DetectHomes() []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		if h != "" && !seen[h] {
			if st, err := os.Stat(h); err == nil && st.IsDir() {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	add(PrimaryHome())
	for _, l := range readLines("/etc/passwd") {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		if !strings.HasSuffix(f[6], "nologin") && !strings.HasSuffix(f[6], "/false") && f[5] != "/" {
			add(f[5])
		}
	}
	return out
}

// OSName reads PRETTY_NAME from /etc/os-release.
func OSName() string {
	for _, l := range readLines("/etc/os-release") {
		if strings.HasPrefix(l, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), `"`)
		}
	}
	return "Linux"
}

