package report

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"security-go-scanner/src/model"
)

// HostAuditMarkdown generates an executive Markdown summary of the host security audit.
func HostAuditMarkdown(r *model.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Security report: %s\n\n", r.Host)
	fmt.Fprintf(&b, "- Date: %s\n- OS: %s, kernel %s\n- Tool: secscan %s (root: %v)\n- Score: **%s (%d/100)**\n- Counts: critical %d, high %d, medium %d, low %d, info %d, suppressed %d\n\n",
		r.StartedAt.Format(time.RFC1123), r.OS, r.Kernel, r.Version, r.Root, r.Grade, r.ScoreVal,
		r.Counts["critical"], r.Counts["high"], r.Counts["medium"], r.Counts["low"], r.Counts["info"], r.Suppressed)
	fmt.Fprintf(&b, "- Coverage: %s\n", r.Coverage)

	if r.GradeNote != "" {
		fmt.Fprintf(&b, "- **Warning:** %s\n", r.GradeNote)
		for _, i := range r.Incomplete {
			fmt.Fprintf(&b, "  - could not run: %s\n", i)
		}
	}

	b.WriteString("\n## Action plan\n\n")
	now, soon, later := r.ActionPlan()
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
	for _, f := range r.AllFindings(false) {
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

// CodeScanMarkdown generates a Markdown report for a codebase or archive scan.
func CodeScanMarkdown(rep *model.CodeScanReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Malware Scan Report: %s\n\n", filepath.Base(rep.Target))
	fmt.Fprintf(&b, "- **Target:** `%s`\n", rep.Target)
	fmt.Fprintf(&b, "- **Scanner:** %s\n", rep.Scanner)
	fmt.Fprintf(&b, "- **Files Scanned:** %d in %.2fs\n", rep.FilesScanned, rep.Seconds)
	fmt.Fprintf(&b, "- **Verdict:** **%s**\n", strings.ReplaceAll(rep.Verdict, "_", " "))
	fmt.Fprintf(&b, "- **Counts:** critical %d, high %d, medium %d, low %d, info %d\n\n",
		rep.CountsBySeverity["critical"], rep.CountsBySeverity["high"],
		rep.CountsBySeverity["medium"], rep.CountsBySeverity["low"], rep.CountsBySeverity["info"])

	fmt.Fprintf(&b, "## Findings\n\n")
	if len(rep.Findings) == 0 {
		b.WriteString("No indicators found by this scan.\n\n")
	} else {
		for _, f := range rep.Findings {
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			fmt.Fprintf(&b, "### [%s] %s (`%s`)\n\n", f.Severity, f.Rule, loc)
			fmt.Fprintf(&b, "- **Category:** %s\n", f.Category)
			fmt.Fprintf(&b, "- **Why:** %s\n", f.Why)
			if f.Evidence != "" {
				fmt.Fprintf(&b, "- **Match:**\n```\n%s\n```\n", f.Evidence)
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("## Limitations\n\n")
	b.WriteString("Static pattern analysis only. 'no_indicators_found' is NOT proof the code is safe. Heavily obfuscated, encrypted, or runtime-staged payloads may not be detected.\n")
	return b.String()
}
