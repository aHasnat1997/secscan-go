package hostaudit

import (
	"fmt"
	"os"
	"strings"
	"time"

	"security-go-scanner/src/model"
	"security-go-scanner/src/runner"
)

// CheckUpdates audits pending system package updates via checkupdates.
func CheckUpdates(e *AuditEnv) ([]model.Finding, error) {
	if !runner.Have("checkupdates") {
		return nil, SkipError("checkupdates missing (sudo pacman -S pacman-contrib)")
	}
	out, _, code, err := runner.Run(e.Ctx, 120*time.Second, "checkupdates")
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
	return []model.Finding{finding("PATCH-PENDING", model.SevMedium,
		fmt.Sprintf("%d package updates pending", len(l)),
		"Unpatched packages are the most common route to compromise on a desktop.",
		"sudo pacman -Syu", l...)}, nil
}

// CheckReboot detects if a newer kernel has been installed on disk but the host has not rebooted.
func CheckReboot(e *AuditEnv) ([]model.Finding, error) {
	out, _, _, err := runner.Run(e.Ctx, 5*time.Second, "uname", "-r")
	if err != nil {
		return nil, err
	}
	rel := strings.TrimSpace(out)
	if _, err := os.Stat("/usr/lib/modules/" + rel); err != nil {
		return []model.Finding{finding("PATCH-REBOOT", model.SevMedium,
			"Running kernel no longer matches installed modules: reboot required",
			"The kernel was updated on disk but the old one is still running. New modules (USB, Wi-Fi, filesystems) will fail to load.",
			"Save your work and reboot.", "running kernel: "+rel)}, nil
	}
	return nil, nil
}

// CheckArchAudit queries Arch Linux Security Advisories (arch-audit) for known CVEs.
func CheckArchAudit(e *AuditEnv) ([]model.Finding, error) {
	if !runner.Have("arch-audit") {
		return nil, SkipError("arch-audit missing (sudo pacman -S arch-audit)")
	}
	fixable, ferr, fcode, err := runner.Run(e.Ctx, 120*time.Second, "arch-audit", "--upgradable")
	if err != nil {
		return nil, err
	}
	// arch-audit downloads advisories; offline it prints an error with empty output.
	// Treating that as "no CVEs" would be a false all-clear.
	if strings.TrimSpace(fixable) == "" && (fcode > 1 || strings.Contains(ferr, "Error")) {
		return nil, fmt.Errorf("arch-audit could not fetch advisories (offline?): %s", trunc(strings.TrimSpace(strings.SplitN(ferr, "\n", 2)[0]), 120))
	}

	all, _, _, _ := runner.Run(e.Ctx, 120*time.Second, "arch-audit")
	var out []model.Finding
	if l := lines(fixable); len(l) > 0 {
		out = append(out, finding("CVE-FIXABLE", model.SevHigh,
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
		sev := model.SevLow
		if high > 0 {
			sev = model.SevMedium
		}
		out = append(out, finding("CVE-UNFIXED", sev,
			fmt.Sprintf("%d packages have known CVEs with no fix released yet (%d high risk)", len(waiting), high),
			"Nothing to install yet. Avoid opening untrusted files/archives/images until fixes ship.",
			"Re-run weekly; `arch-audit --upgradable` shows when a fix lands.", waiting...))
	}
	return out, nil
}

// CheckForeignPkgs lists packages installed outside official repositories (e.g. AUR).
func CheckForeignPkgs(e *AuditEnv) ([]model.Finding, error) {
	if !runner.Have("pacman") {
		return nil, SkipError("pacman not found")
	}
	out, _, _, err := runner.Run(e.Ctx, 30*time.Second, "pacman", "-Qm")
	if err != nil {
		return nil, err
	}
	l := lines(out)
	if len(l) == 0 {
		return nil, nil
	}
	return []model.Finding{finding("PKG-FOREIGN", model.SevInfo,
		fmt.Sprintf("%d packages not from official repos (AUR / manual)", len(l)),
		"AUR is the most common infection route on Arch. Make sure you recognise each one and reviewed its PKGBUILD.",
		"Remove anything unknown: sudo pacman -Rns <pkg>", l...)}, nil
}

