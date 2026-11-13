package report

import (
	"fmt"
	"io"
	"strings"

	"security-go-scanner/src/model"
	"security-go-scanner/src/terminal"
)

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// PrintHostAudit renders a colorized, prioritized host audit report to the specified writer.
func PrintHostAudit(w io.Writer, r *model.Report, noColor, showSuppressed, verbose bool) {
	p := terminal.NewPainter(!noColor)

	fmt.Fprintf(w, "\n%s\n", p.Bold(fmt.Sprintf("secscan %s  |  %s  |  %s  |  kernel %s", r.Version, r.Host, r.OS, r.Kernel)))
	rootNote := ""
	if !r.Root {
		rootNote = p.Yellow("  (not root: reduced coverage, use sudo)")
	}
	fmt.Fprintf(w, "Scanned %s in %.1fs%s\n", r.StartedAt.Format("2006-01-02 15:04:05"), float64(r.DurationMS)/1000, rootNote)

	gc := map[string]string{"A": "32", "B": "32", "C": "33", "D": "31", "F": "1;31"}[r.Grade]
	fmt.Fprintf(w, "\nSecurity score: %s  (%d/100)   coverage: %s\n", p.Color(gc, "Grade "+r.Grade), r.ScoreVal, r.Coverage)
	if r.GradeNote != "" {
		fmt.Fprintf(w, "  %s\n", p.Yellow("! "+r.GradeNote))
		for _, i := range r.Incomplete {
			fmt.Fprintf(w, "    - %s\n", i)
		}
	}
	fmt.Fprintf(w, "  critical %d | high %d | medium %d | low %d | info %d | suppressed %d\n",
		r.Counts["critical"], r.Counts["high"], r.Counts["medium"], r.Counts["low"], r.Counts["info"], r.Suppressed)

	fs := r.AllFindings(showSuppressed)
	fmt.Fprintf(w, "\n%s\n", p.Bold("FINDINGS (highest severity first)"))
	if len(fs) == 0 {
		fmt.Fprintln(w, "  none")
	}

	limit := 6
	if verbose {
		limit = 1 << 30
	}

	for _, f := range fs {
		tag := ""
		if f.Status == "new" {
			tag = p.Color("1;35", "  [NEW]")
		}
		if f.Suppressed != "" {
			tag += p.Gray("  [suppressed: " + f.Suppressed + "]")
		}
		fmt.Fprintf(w, "\n%s %s  %s%s\n", p.Severity(f.Severity), p.Bold(f.ID), f.Title, tag)
		if f.Detail != "" {
			fmt.Fprintf(w, "    why: %s\n", f.Detail)
		}
		lim := limit
		if f.Severity >= model.SevHigh && lim < 15 {
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

	fmt.Fprintf(w, "\n%s\n", p.Bold("CHECKS"))
	for _, res := range r.Results {
		st := map[string]string{
			"ok":       p.Green("ok      "),
			"findings": p.Yellow("findings"),
			"skipped":  p.Gray("skipped "),
			"error":    p.Red("error   "),
		}[res.Status]
		note := ""
		if res.Note != "" {
			note = "  - " + res.Note
		}
		fmt.Fprintf(w, "  %s %-40s %5.1fs%s\n", st, res.Name, float64(res.DurationMS)/1000, note)
	}

	if len(r.Resolved) > 0 {
		fmt.Fprintf(w, "\n%s\n", p.Green(fmt.Sprintf("RESOLVED since last run (%d)", len(r.Resolved))))
		for _, t := range r.Resolved {
			fmt.Fprintf(w, "  + %s\n", t)
		}
	}

	now, soon, later := r.ActionPlan()
	section := func(title, col string, items []string, maxItems int) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(w, "\n%s\n", p.Color(col, title))
		for i, s := range items {
			if i == maxItems {
				fmt.Fprintf(w, "  ... %d more in the report\n", len(items)-maxItems)
				break
			}
			fmt.Fprintf(w, "  %d. %s\n", i+1, trunc(s, 200))
		}
	}
	section("ACTION PLAN: DO NOW (critical/high)", "1;31", now, 20)
	section("ACTION PLAN: THIS WEEK (medium)", "33", soon, 10)
	section("ACTION PLAN: WHEN CONVENIENT (low)", "36", later, 5)
	if len(now) == 0 && len(soon) == 0 && len(later) == 0 && len(r.Incomplete) == 0 {
		fmt.Fprintf(w, "\n%s\n", p.Green("Nothing to fix. Re-run after every system change or weekly."))
	}
}

// PrintCodeScan renders a colorized codebase/archive scan report to the specified writer.
func PrintCodeScan(w io.Writer, rep *model.CodeScanReport, noColor bool) {
	p := terminal.NewPainter(!noColor)

	fmt.Fprintf(w, "\n%s\n", p.Bold(fmt.Sprintf("secscan code-scan  |  %s", rep.Scanner)))
	fmt.Fprintf(w, "Target: %s\n", p.Bold(rep.Target))
	fmt.Fprintf(w, "Scanned %d files in %.2fs\n", rep.FilesScanned, rep.Seconds)

	verdictColor := "32"
	verdictText := "NO INDICATORS FOUND"
	switch rep.Verdict {
	case "indicators_found_review_required":
		verdictColor = "1;31"
		verdictText = "INDICATORS FOUND - REVIEW REQUIRED"
	case "low_signal_only":
		verdictColor = "33"
		verdictText = "LOW-SIGNAL FINDINGS ONLY"
	}

	fmt.Fprintf(w, "\nVerdict: %s\n", p.Color(verdictColor, verdictText))
	fmt.Fprintf(w, "  critical %d | high %d | medium %d | low %d | info %d\n",
		rep.CountsBySeverity["critical"], rep.CountsBySeverity["high"],
		rep.CountsBySeverity["medium"], rep.CountsBySeverity["low"], rep.CountsBySeverity["info"])

	if len(rep.Findings) == 0 {
		fmt.Fprintf(w, "\n%s\n", p.Green("No malware indicators detected by pattern analysis."))
		fmt.Fprintf(w, "Note: %s\n", rep.VerdictNote)
		return
	}

	fmt.Fprintf(w, "\n%s\n", p.Bold("FINDINGS:"))
	for _, f := range rep.Findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Fprintf(w, "\n%-8s %-20s %s\n", p.Severity(f.Severity), p.Bold(strings.ToUpper(f.Rule)), p.Color("4", loc))
		fmt.Fprintf(w, "    why: %s\n", f.Why)
		if f.Evidence != "" {
			fmt.Fprintf(w, "    match: %s\n", f.Evidence)
		}
	}

	if rep.Verdict == "indicators_found_review_required" {
		fmt.Fprintf(w, "\n%s\n", p.Color("1;31", "RECOMMENDATION:"))
		fmt.Fprintf(w, "  DO NOT run, build, or install dependencies from this project!\n")
		fmt.Fprintf(w, "  High-probability malware or backdoor indicators were detected.\n")
	}

	if len(rep.Skipped) > 0 {
		fmt.Fprintf(w, "\nSkipped files (%d):\n", len(rep.Skipped))
		for i, s := range rep.Skipped {
			if i >= 5 {
				fmt.Fprintf(w, "  ... and %d more\n", len(rep.Skipped)-5)
				break
			}
			fmt.Fprintf(w, "  - %s\n", s)
		}
	}
}
