package hostaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"security-go-scanner/src/model"
	"security-go-scanner/src/runner"
)

// Check represents a single registered host audit module.
type Check struct {
	ID       string
	Name     string
	Category string
	Root     bool // requires root privileges for full accuracy
	Slow     bool // bypassed when --quick is passed
	Heavy    bool // opt-in only (--clamav or --full)
	Run      func(*AuditEnv) ([]model.Finding, error)
}

// Registry returns the canonical ordered suite of host security audit checks.
func Registry() []Check {
	return []Check{
		{ID: "patch-updates", Name: "Pending package updates", Category: "Patching", Run: CheckUpdates},
		{ID: "patch-reboot", Name: "Kernel/reboot state", Category: "Patching", Run: CheckReboot},
		{ID: "cve-audit", Name: "Known CVEs (arch-audit)", Category: "Patching", Run: CheckArchAudit},
		{ID: "integrity", Name: "Package file integrity (pacman -Qkk)", Category: "Integrity", Slow: true, Run: CheckPkgIntegrity},
		{ID: "foreign-pkgs", Name: "AUR / foreign packages", Category: "Integrity", Run: CheckForeignPkgs},
		{ID: "ld-preload", Name: "ld.so.preload hook", Category: "Integrity", Run: CheckLdPreload},
		{ID: "secureboot", Name: "Secure Boot", Category: "Hardening", Run: CheckBootSecurity},
		{ID: "net-listen", Name: "Listening ports", Category: "Network", Run: CheckListening},
		{ID: "net-docker", Name: "Docker published ports", Category: "Network", Run: CheckDocker},
		{ID: "net-firewall", Name: "Host firewall", Category: "Network", Run: CheckFirewall},
		{ID: "accounts", Name: "Accounts & sudo", Category: "Access", Root: true, Run: CheckAccounts},
		{ID: "ssh", Name: "SSH exposure & keys", Category: "Access", Run: CheckSSH},
		{ID: "logins", Name: "Login history", Category: "Access", Run: CheckLogins},
		{ID: "persist-systemd", Name: "systemd units (persistence)", Category: "Persistence", Run: CheckSystemdUnits},
		{ID: "persist-cron", Name: "Cron jobs", Category: "Persistence", Run: CheckCron},
		{ID: "persist-autostart", Name: "Desktop autostart", Category: "Persistence", Run: CheckAutostart},
		{ID: "persist-shellrc", Name: "Shell startup files", Category: "Persistence", Run: CheckShellRC},
		{ID: "fs-suid", Name: "Unowned SUID/SGID files", Category: "Filesystem", Slow: true, Run: CheckSUID},
		{ID: "fs-tmp", Name: "Executables in temp dirs", Category: "Filesystem", Run: CheckTempExec},
		{ID: "procs", Name: "Suspicious processes", Category: "Runtime", Run: CheckProcesses},
		{ID: "proc-scripts", Name: "Scripts run from hidden dirs", Category: "Runtime", Run: CheckProcScripts},
		{ID: "proc-hidden", Name: "Hidden processes (rootkit)", Category: "Runtime", Root: true, Run: CheckHiddenPIDs},
		{ID: "net-outbound", Name: "Outbound connections", Category: "Network", Run: CheckConnections},
		{ID: "ioc-scripts", Name: "Clipboard hijacker / malware IOCs", Category: "Malware", Run: CheckIOCScripts},
		{ID: "persist-misc", Name: "Other persistence locations", Category: "Persistence", Run: CheckPersistMisc},
		{ID: "kmod", Name: "Kernel modules", Category: "Integrity", Slow: true, Run: CheckKernelModules},
		{ID: "sysctl", Name: "Kernel hardening (sysctl)", Category: "Hardening", Run: CheckSysctl},
		{ID: "rkhunter", Name: "rkhunter rootkit scan", Category: "Malware", Root: true, Slow: true, Run: CheckRkhunter},
		{ID: "lynis", Name: "Lynis audit", Category: "Hardening", Root: true, Slow: true, Run: CheckLynis},
		{ID: "clamav", Name: "ClamAV malware scan", Category: "Malware", Slow: true, Heavy: true, Run: CheckClamAV},
	}
}

// RunCheck executes an individual audit check with panic isolation and duration tracking.
func RunCheck(e *AuditEnv, c Check) (res model.CheckResult) {
	res = model.CheckResult{ID: c.ID, Name: c.Name, Category: c.Category, Status: "ok"}
	start := time.Now()
	defer func() { res.DurationMS = time.Since(start).Milliseconds() }()
	defer func() {
		if r := recover(); r != nil {
			res.Status, res.Note = "error", fmt.Sprint("panic: ", r)
		}
	}()

	fs, err := c.Run(e)
	var sk SkipError
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
		fs[i].Fingerprint = model.CalculateFingerprint(fs[i])
	}
	res.Findings = fs
	for _, f := range fs {
		if f.Severity > model.SevInfo {
			res.Status = "findings"
			break
		}
	}
	return
}

// RunAudit orchestrates concurrent execution of all selected checks, applies suppressions,
// calculates security posture scoring, and diffs against the previous run.
func RunAudit(ctx context.Context, version string, o *Options, onProgress func(event, name string, res model.CheckResult)) *model.Report {
	checks := Registry()
	env := &AuditEnv{
		Ctx:   ctx,
		Opts:  o,
		Root:  os.Geteuid() == 0,
		Homes: DetectHomes(),
	}

	only, skipSet := splitSet(o.Only), splitSet(o.Skip)
	start := time.Now()

	results := make([]model.CheckResult, len(checks))
	var activeTasks []runner.Task[model.CheckResult]
	var activeIndices []int

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
			results[i] = model.CheckResult{
				ID: c.ID, Name: c.Name, Category: c.Category,
				Status: "skipped", Note: reason,
				Gap: reason == "needs root (run with sudo)",
			}
			continue
		}

		chk := c
		activeIndices = append(activeIndices, i)
		activeTasks = append(activeTasks, runner.Task[model.CheckResult]{
			Name: chk.Name,
			Fn: func(_ context.Context) model.CheckResult {
				return RunCheck(env, chk)
			},
		})
	}

	taskResults := runner.RunConcurrent(ctx, o.Jobs, activeTasks,
		func(name string) {
			if onProgress != nil {
				onProgress("running", name, model.CheckResult{})
			}
		},
		func(name string, res model.CheckResult) {
			if onProgress != nil {
				onProgress("done", name, res)
			}
		},
	)

	for idx, res := range taskResults {
		results[activeIndices[idx]] = res
	}

	// Apply configuration suppressions
	for i := range results {
		for j := range results[i].Findings {
			f := &results[i].Findings[j]
			if reason := o.Config.IsSuppressed(f.ID); reason != "" {
				f.Suppressed = reason
			}
		}
	}

	host, _ := os.Hostname()
	kver, _, _, _ := runner.Run(ctx, 5*time.Second, "uname", "-r")

	rep := &model.Report{
		Tool:       "secscan",
		Version:    version,
		Host:       host,
		OS:         OSName(),
		Kernel:     strings.TrimSpace(kver),
		StartedAt:  start,
		DurationMS: time.Since(start).Milliseconds(),
		Root:       env.Root,
		Results:    results,
	}

	rep.Score()
	DiffWithPrevious(rep, filepath.Join(o.OutDir, "latest.json"))
	return rep
}

// DiffWithPrevious compares findings against the previous report to mark new and resolved items.
func DiffWithPrevious(r *model.Report, prevPath string) {
	b, err := os.ReadFile(prevPath)
	if err != nil {
		return
	}
	var prev model.Report
	if json.Unmarshal(b, &prev) != nil {
		return
	}

	old := map[string]model.Finding{}
	for _, f := range prev.AllFindings(true) {
		old[f.Fingerprint] = f
	}

	cur := map[string]bool{}
	for i := range r.Results {
		for j := range r.Results[i].Findings {
			f := &r.Results[i].Findings[j]
			cur[f.Fingerprint] = true
			if _, ok := old[f.Fingerprint]; !ok {
				f.Status = "new"
			}
		}
	}

	for fp, f := range old {
		if !cur[fp] && f.Severity > model.SevInfo && f.Suppressed == "" {
			r.Resolved = append(r.Resolved, fmt.Sprintf("[%s] %s: %s", f.Severity, f.ID, f.Title))
		}
	}
}

