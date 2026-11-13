package hostaudit

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"security-go-scanner/src/model"
)

// CheckBootSecurity verifies whether UEFI Secure Boot is enabled to detect bootkits or tampered bootloaders.
func CheckBootSecurity(e *AuditEnv) ([]model.Finding, error) {
	b, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err != nil {
		return nil, SkipError("not a UEFI system or efivars unreadable")
	}
	if len(b) > 0 && b[len(b)-1] == 1 {
		return nil, nil
	}
	return []model.Finding{finding("BOOT-SECUREBOOT", model.SevLow, "Secure Boot is disabled",
		"Without it a bootkit or tampered bootloader would not be detected.",
		"Optional: set up sbctl-based signing for GRUB/kernel, then enable Secure Boot in firmware.")}, nil
}

// CheckSysctl audits Linux kernel runtime security parameters in /proc/sys.
func CheckSysctl(e *AuditEnv) ([]model.Finding, error) {
	type rule struct {
		key string
		ok  []int
	}
	rules := []rule{
		{"kernel.dmesg_restrict", []int{1}},
		{"kernel.kptr_restrict", []int{1, 2}},
		{"kernel.yama.ptrace_scope", []int{1, 2, 3}},
		{"kernel.unprivileged_bpf_disabled", []int{1, 2}},
		{"kernel.randomize_va_space", []int{2}},
		{"net.core.bpf_jit_harden", []int{1, 2}},
		{"fs.protected_symlinks", []int{1}},
		{"fs.protected_hardlinks", []int{1}},
		{"fs.protected_fifos", []int{1, 2}},
		{"fs.protected_regular", []int{1, 2}},
		{"fs.suid_dumpable", []int{0}},
		{"net.ipv4.tcp_syncookies", []int{1}},
		{"net.ipv4.conf.all.rp_filter", []int{1, 2}},
		{"net.ipv4.conf.all.accept_redirects", []int{0}},
		{"net.ipv4.conf.all.send_redirects", []int{0}},
		{"net.ipv4.conf.all.accept_source_route", []int{0}},
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
	return []model.Finding{finding("HARD-SYSCTL", model.SevLow, fmt.Sprintf("%d kernel parameters weaker than recommended", len(ev)),
		"Low-cost kernel hardening. Docker needs ip_forward, so that one is intentionally not checked.",
		"Put these in /etc/sysctl.d/99-hardening.conf and run `sudo sysctl --system`:\n"+strings.Join(conf, "\n"), ev...)}, nil
}

