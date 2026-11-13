package hostaudit

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"security-go-scanner/src/model"
	"security-go-scanner/src/runner"
)

var (
	benignIntegrity = regexp.MustCompile(`/usr/lib/jvm/|plugins\.dat$|/utempter$|^/var/log/journal|^/usr/share/factory/|plymouth-update-initrd|^/usr/share/code/`)
	criticalDirs    = regexp.MustCompile(`^/(usr/(bin|sbin|lib|lib64)|boot|bin|sbin|lib|lib64)/`)
)

// CheckPkgIntegrity validates installed package file checksums and metadata against pacman's database.
func CheckPkgIntegrity(e *AuditEnv) ([]model.Finding, error) {
	if !runner.Have("pacman") {
		return nil, SkipError("pacman not found")
	}
	out, errOut, _, err := runner.Run(e.Ctx, 15*time.Minute, "pacman", "-Qkk")
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

	var fs []model.Finding
	if len(high) > 0 {
		fs = append(fs, finding("INTEG-MODIFIED", model.SevHigh,
			fmt.Sprintf("%d system files differ from what pacman installed", len(high)),
			"Contents of binaries/libraries changed after install. Could be a manual edit or tampering.",
			"Reinstall the owning package: sudo pacman -S <pkg>. If it changes again or you cannot explain it, treat the host as compromised.",
			high...))
	}
	if len(meta) > 0 {
		fs = append(fs, finding("INTEG-METADATA", model.SevInfo,
			fmt.Sprintf("%d packaged files differ in permissions/timestamps only", len(meta)),
			"Usually benign (post-install scripts, runtime-generated files).", "", meta...))
	}
	return fs, nil
}

// CheckLdPreload checks /etc/ld.so.preload for unauthorized shared library injection.
func CheckLdPreload(e *AuditEnv) ([]model.Finding, error) {
	var ev []string
	for _, l := range readLines("/etc/ld.so.preload") {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
			ev = append(ev, t)
		}
	}
	if len(ev) == 0 {
		return nil, nil
	}
	return []model.Finding{finding("INTEG-LDPRELOAD", model.SevCritical,
		"/etc/ld.so.preload is set",
		"Forces a library into every process. This is the classic userland rootkit hook.",
		"Identify the library (pacman -Qo <file>). If unknown: disconnect, back up data, reinstall.", ev...)}, nil
}

// CheckSUID scans critical system paths and user homes for unowned SUID/SGID binaries.
func CheckSUID(e *AuditEnv) ([]model.Finding, error) {
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
	return []model.Finding{finding("FS-SUID-UNOWNED", model.SevHigh,
		fmt.Sprintf("%d SUID/SGID files not owned by any package", len(unowned)),
		"Privilege-escalation backdoors are usually planted as SUID binaries outside the package database.",
		"Inspect with `ls -l` and `file`. Remove with chmod u-s,g-s if unneeded; delete if unknown.", unowned...)}, nil
}

