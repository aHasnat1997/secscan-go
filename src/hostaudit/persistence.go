package hostaudit

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"security-go-scanner/src/model"
)

// CheckSystemdUnits inspects unpackaged user and system systemd units for disguised malware services
// or suspicious ExecStart commands.
func CheckSystemdUnits(e *AuditEnv) ([]model.Finding, error) {
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

	var out []model.Finding
	if len(disg) > 0 {
		out = append(out, finding("PERSIST-UNIT-DISGUISED", model.SevHigh, fmt.Sprintf("%d systemd units disguised as system components", len(disg)),
			"Not from any package, yet named/described like GNOME/KDE/systemd services, with hidden logging or scripts in hidden directories. This is how user-level malware persists without root.",
			"systemctl --user disable --now <unit>; read the script it runs; copy the folder aside as evidence; delete the unit and folder; find how it arrived.", disg...))
	}
	if len(hi) > 0 {
		out = append(out, finding("PERSIST-UNIT-SUSPICIOUS", model.SevHigh, "Unpackaged systemd unit with suspicious ExecStart",
			"Runs from a temp dir or uses download-and-execute / reverse-shell patterns.",
			"systemctl disable --now <unit>; delete the file; find out how it got there.", hi...))
	}
	if len(lo) > 0 {
		out = append(out, finding("PERSIST-UNIT-CUSTOM", model.SevInfo, fmt.Sprintf("%d custom systemd units not owned by any package", len(lo)),
			"Legitimate only if you created them. Real gvfs units ship in /usr/lib/systemd/user, never in your home. Review each command.", "", lo...))
	}
	return out, nil
}

// CheckCron inspects system and user crontabs for suspicious scheduled tasks.
func CheckCron(e *AuditEnv) ([]model.Finding, error) {
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

	var out []model.Finding
	if len(hi) > 0 {
		out = append(out, finding("PERSIST-CRON-SUSPICIOUS", model.SevHigh, "Suspicious cron entries", "",
			"Remove the entry and investigate its origin.", hi...))
	}
	if len(lo) > 0 {
		out = append(out, finding("PERSIST-CRON", model.SevInfo, fmt.Sprintf("%d cron entries", len(lo)), "Review that you recognise each.", "", lo...))
	}
	return out, nil
}

// CheckAutostart audits XDG autostart .desktop entries for malicious login persistence.
func CheckAutostart(e *AuditEnv) ([]model.Finding, error) {
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

	var out []model.Finding
	if len(hi) > 0 {
		out = append(out, finding("PERSIST-AUTOSTART-SUSPICIOUS", model.SevHigh, "Suspicious desktop autostart entry", "",
			"Delete the .desktop file and investigate.", hi...))
	}
	if len(lo) > 0 {
		out = append(out, finding("PERSIST-AUTOSTART", model.SevInfo, fmt.Sprintf("%d user autostart entries", len(lo)), "Apps launched at login.", "", lo...))
	}
	return out, nil
}

// CheckShellRC inspects user shell initialization files for dropper or reverse-shell commands.
func CheckShellRC(e *AuditEnv) ([]model.Finding, error) {
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
	return []model.Finding{finding("PERSIST-SHELLRC", model.SevHigh, "Suspicious commands in shell startup files",
		"Runs on every terminal you open. Matches download-and-execute, base64 decode, reverse-shell or LD_PRELOAD patterns.",
		"Review each line. Installers like nvm/sdkman may be legitimate, but unknown curl|sh lines are not.", ev...)}, nil
}

// CheckPersistMisc scans secondary persistence vectors (udev rules, profile.d, KDE autostart-scripts, systemd generators).
func CheckPersistMisc(e *AuditEnv) ([]model.Finding, error) {
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

	var out []model.Finding
	if len(hi) > 0 {
		sort.Strings(hi)
		out = append(out, finding("PERSIST-MISC-SUSPICIOUS", model.SevHigh, "Suspicious content in a startup/persistence location",
			"These locations run code at boot, login, hotplug or on a schedule.", "Read the file, remove it if it is not yours, and find how it got there.", hi...))
	}
	if len(lo) > 0 {
		sort.Strings(lo)
		out = append(out, finding("PERSIST-MISC", model.SevInfo, fmt.Sprintf("%d unpackaged files in startup locations", len(lo)),
			"cron.*, profile.d, udev, ~/.local/bin, KDE autostart-scripts... Review that you recognise each.", "", lo...))
	}
	return out, nil
}

