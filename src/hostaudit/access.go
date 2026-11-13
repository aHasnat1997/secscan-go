package hostaudit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"security-go-scanner/src/model"
	"security-go-scanner/src/runner"
)

var ipRe = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)

// CheckAccounts verifies privileged account integrity (non-root UID 0, /etc/shadow permissions, empty passwords, NOPASSWD sudo).
func CheckAccounts(e *AuditEnv) ([]model.Finding, error) {
	var fs []model.Finding
	var uid0 []string
	for _, l := range readLines("/etc/passwd") {
		f := strings.Split(l, ":")
		if len(f) >= 4 && f[2] == "0" && f[0] != "root" {
			uid0 = append(uid0, l)
		}
	}
	if len(uid0) > 0 {
		fs = append(fs, finding("ACCT-UID0", model.SevCritical, "Non-root account with UID 0", "Equivalent to a hidden root account.",
			"Investigate immediately: sudo userdel <name>, then audit for compromise.", uid0...))
	}
	if st, err := os.Stat("/etc/shadow"); err == nil && st.Mode().Perm()&0o007 != 0 {
		fs = append(fs, finding("ACCT-SHADOW-PERMS", model.SevCritical, "/etc/shadow is world-readable", "",
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
			fs = append(fs, finding("ACCT-EMPTY-PW", model.SevHigh, "Accounts with an empty password", "",
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
			fs = append(fs, finding("ACCT-SUDO-NOPASSWD", model.SevMedium, "sudo rules that skip the password",
				"Any process running as that user gets root without a prompt.",
				"Remove NOPASSWD unless required (visudo).", nopw...))
		}
	}
	return fs, nil
}

// CheckSSH inspects SSH daemon configuration (PermitRootLogin, PasswordAuthentication) and user authorized_keys.
func CheckSSH(e *AuditEnv) ([]model.Finding, error) {
	var fs []model.Finding
	o, _, _, _ := runner.Run(e.Ctx, 5*time.Second, "systemctl", "is-active", "sshd")
	if strings.TrimSpace(o) == "active" {
		sev, ev := model.SevInfo, []string{"sshd is running"}
		if e.Root && runner.Have("sshd") {
			t, _, _, _ := runner.Run(e.Ctx, 10*time.Second, "sshd", "-T")
			for _, l := range lines(t) {
				if l == "permitrootlogin yes" || l == "passwordauthentication yes" {
					ev = append(ev, l)
					if l == "permitrootlogin yes" {
						sev = model.SevHigh
					} else if sev < model.SevMedium {
						sev = model.SevMedium
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
		fs = append(fs, finding("SSH-AUTHKEYS", model.SevLow, "authorized_keys present", "These keys can log in to this machine.",
			"Verify every key is yours and remove the rest.", keys...))
	}
	return fs, nil
}

// CheckLogins audits recent remote network logins and failed authentication attempts.
func CheckLogins(e *AuditEnv) ([]model.Finding, error) {
	var fs []model.Finding
	if runner.Have("last") {
		o, _, _, _ := runner.Run(e.Ctx, 10*time.Second, "last", "-a", "-w", "-n", "200")
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
			fs = append(fs, finding("AUTH-REMOTE-LOGIN", model.SevMedium, fmt.Sprintf("%d remote logins in login history", len(ev)),
				"Logins from a network address. Expected only if you use SSH.", "Confirm each is you; rotate credentials if not.", ev...))
		}
	}
	if e.Root && runner.Have("lastb") {
		o, _, _, _ := runner.Run(e.Ctx, 10*time.Second, "lastb", "-a", "-w", "-n", "50")
		var ev []string
		for _, l := range lines(o) {
			if !strings.HasPrefix(l, "btmp") {
				ev = append(ev, l)
			}
		}
		if len(ev) > 0 {
			fs = append(fs, finding("AUTH-FAILED", model.SevLow, fmt.Sprintf("%d failed login attempts recorded", len(ev)), "",
				"Check whether they were you. Many failures from one address indicates brute-forcing.", ev...))
		}
	}
	return fs, nil
}

