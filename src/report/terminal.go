package report

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/sys/unix"

	"security-go-scanner/src/model"
)

func termWidth() int {
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err == nil && ws.Col > 40 {
		return int(ws.Col)
	}
	return 100
}

type theme struct {
	enabled bool
	width   int
}

func newTheme(noColor bool) theme {
	w := termWidth()
	if w > 120 {
		w = 120
	}
	return theme{enabled: !noColor, width: w}
}

func (t theme) sevBadge(s model.Severity) string {
	label := fmt.Sprintf(" %-8s ", s.String())
	if !t.enabled {
		return "[" + s.String() + "]"
	}
	var bg, fg string
	switch s {
	case model.SevCritical:
		bg, fg = "#FF0055", "#FFFFFF"
	case model.SevHigh:
		bg, fg = "#FF5F00", "#FFFFFF"
	case model.SevMedium:
		bg, fg = "#FFAF00", "#111111"
	case model.SevLow:
		bg, fg = "#00D7FF", "#111111"
	default:
		bg, fg = "#444444", "#DDDDDD"
	}
	return lipgloss.NewStyle().Bold(true).Background(lipgloss.Color(bg)).Foreground(lipgloss.Color(fg)).Render(label)
}

func (t theme) style(st lipgloss.Style, s string) string {
	if !t.enabled {
		return s
	}
	return st.Render(s)
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// PrintHostAudit renders a full, responsive, Lipgloss-styled host security audit report
// with complete details, evidence, and actionable remediation instructions.
func PrintHostAudit(w io.Writer, r *model.Report, noColor, showSuppressed, verbose bool) {
	th := newTheme(noColor)
	boxWidth := th.width - 2
	if boxWidth < 50 {
		boxWidth = 50
	}

	gradeColor := "#00F5D4"
	switch r.Grade {
	case "C":
		gradeColor = "#FFAF00"
	case "D", "F":
		gradeColor = "#FF0055"
	}

	header := fmt.Sprintf("secscan %s  |  %s  |  %s  |  kernel %s\n", r.Version, r.Host, r.OS, r.Kernel)
	header += fmt.Sprintf("Scanned %s in %.1fs", r.StartedAt.Format("2006-01-02 15:04:05"), float64(r.DurationMS)/1000)
	if !r.Root {
		header += "  (not root: reduced coverage, use sudo)"
	}

	scoreLine := fmt.Sprintf("\nSecurity Score: Grade %s (%d/100)  •  Coverage: %s\n", r.Grade, r.ScoreVal, r.Coverage)
	countsLine := fmt.Sprintf("Critical: %d  |  High: %d  |  Medium: %d  |  Low: %d  |  Info: %d  |  Suppressed: %d",
		r.Counts["critical"], r.Counts["high"], r.Counts["medium"], r.Counts["low"], r.Counts["info"], r.Suppressed)

	bannerStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(gradeColor)).
		Padding(0, 2).
		Width(boxWidth)

	fmt.Fprintln(w)
	fmt.Fprintln(w, th.style(bannerStyle, header+scoreLine+countsLine))

	if r.GradeNote != "" {
		warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FFAF00")).Bold(true)
		fmt.Fprintf(w, "\n%s\n", th.style(warnStyle, "⚠ "+r.GradeNote))
		for _, i := range r.Incomplete {
			fmt.Fprintf(w, "  - %s\n", i)
		}
	}

	fs := r.AllFindings(showSuppressed)
	secTitle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00F5D4"))
	fmt.Fprintf(w, "\n%s\n", th.style(secTitle, "━━━ FINDINGS (highest severity first) ━━━"))

	if len(fs) == 0 {
		okStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00F5D4")).Bold(true)
		fmt.Fprintln(w, th.style(okStyle, "  ✓ No security issues found."))
	}

	limit := 15
	if verbose {
		limit = 1 << 30
	}

	wrapStyle := lipgloss.NewStyle().Width(boxWidth - 4)
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
	fixStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00F5D4"))
	idStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF"))

	for _, f := range fs {
		tag := ""
		if f.Status == "new" {
			tag = th.style(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF55FF")), " [NEW]")
		}
		if f.Suppressed != "" {
			tag += th.style(dimStyle, " [suppressed: "+f.Suppressed+"]")
		}

		fmt.Fprintf(w, "\n%s %s  %s%s\n", th.sevBadge(f.Severity), th.style(idStyle, f.ID), f.Title, tag)
		if f.Detail != "" {
			fmt.Fprintf(w, "  %s %s\n", th.style(dimStyle, "why:"), th.style(wrapStyle, f.Detail))
		}
		lim := limit
		if f.Severity >= model.SevHigh && lim < 25 {
			lim = 25
		}
		for i, ev := range f.Evidence {
			if i == lim {
				fmt.Fprintf(w, "  %s\n", th.style(dimStyle, fmt.Sprintf("... %d more (use -v or --out to save full report)", len(f.Evidence)-lim)))
				break
			}
			fmt.Fprintf(w, "    • %s\n", trunc(ev, boxWidth+40))
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "  %s %s\n", th.style(fixStyle, "fix:"), strings.ReplaceAll(f.Remediation, "\n", "\n       "))
		}
	}

	fmt.Fprintf(w, "\n%s\n", th.style(secTitle, "━━━ CHECKS SUMMARY ━━━"))
	for _, res := range r.Results {
		var badge string
		switch res.Status {
		case "ok":
			badge = th.style(lipgloss.NewStyle().Foreground(lipgloss.Color("#00F5D4")), "✓ ok      ")
		case "findings":
			badge = th.style(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFAF00")), "! findings")
		case "skipped":
			badge = th.style(dimStyle, "- skipped ")
		default:
			badge = th.style(lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0055")), "✗ error   ")
		}
		note := ""
		if res.Note != "" {
			note = "  — " + res.Note
		}
		fmt.Fprintf(w, "  %s %-38s %5.1fs%s\n", badge, res.Name, float64(res.DurationMS)/1000, note)
	}

	if len(r.Resolved) > 0 {
		fmt.Fprintf(w, "\n%s\n", th.style(lipgloss.NewStyle().Foreground(lipgloss.Color("#00F5D4")).Bold(true),
			fmt.Sprintf("RESOLVED since last run (%d)", len(r.Resolved))))
		for _, t := range r.Resolved {
			fmt.Fprintf(w, "  + %s\n", t)
		}
	}

	now, soon, later := r.ActionPlan()
	section := func(title, hexCol string, items []string, maxItems int) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(w, "\n%s\n", th.style(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(hexCol)), title))
		for i, s := range items {
			if i == maxItems {
				fmt.Fprintf(w, "  ... %d more (use --out to save full report)\n", len(items)-maxItems)
				break
			}
			fmt.Fprintf(w, "  %d. %s\n", i+1, trunc(s, boxWidth+40))
		}
	}
	section("ACTION PLAN: DO NOW (critical/high)", "#FF0055", now, 25)
	section("ACTION PLAN: THIS WEEK (medium)", "#FFAF00", soon, 15)
	section("ACTION PLAN: WHEN CONVENIENT (low)", "#00D7FF", later, 10)
	if len(now) == 0 && len(soon) == 0 && len(later) == 0 && len(r.Incomplete) == 0 {
		fmt.Fprintf(w, "\n%s\n", th.style(lipgloss.NewStyle().Foreground(lipgloss.Color("#00F5D4")).Bold(true),
			"✓ Nothing to fix. Re-run after every system change or weekly."))
	}
}

// PrintCodeScan renders a full, responsive, Lipgloss-styled codebase/archive scan report
// with complete details, match snippets, and actionable next steps.
func PrintCodeScan(w io.Writer, rep *model.CodeScanReport, noColor bool) {
	th := newTheme(noColor)
	boxWidth := th.width - 2
	if boxWidth < 50 {
		boxWidth = 50
	}

	verdictColor := "#00F5D4"
	verdictText := "✓ NO INDICATORS FOUND"
	switch rep.Verdict {
	case "indicators_found_review_required":
		verdictColor = "#FF0055"
		verdictText = "⚠ INDICATORS FOUND — REVIEW REQUIRED"
	case "low_signal_only":
		verdictColor = "#FFAF00"
		verdictText = "! LOW-SIGNAL FINDINGS ONLY"
	}

	banner := fmt.Sprintf("secscan code-scan  |  %s\n", rep.Scanner)
	banner += fmt.Sprintf("Target: %s\n", rep.Target)
	banner += fmt.Sprintf("Scanned %d files in %.2fs\n\n", rep.FilesScanned, rep.Seconds)
	banner += fmt.Sprintf("Verdict: %s\n", verdictText)
	banner += fmt.Sprintf("Critical: %d  |  High: %d  |  Medium: %d  |  Low: %d  |  Info: %d",
		rep.CountsBySeverity["critical"], rep.CountsBySeverity["high"],
		rep.CountsBySeverity["medium"], rep.CountsBySeverity["low"], rep.CountsBySeverity["info"])

	bannerStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(verdictColor)).
		Padding(0, 2).
		Width(boxWidth)

	fmt.Fprintln(w)
	fmt.Fprintln(w, th.style(bannerStyle, banner))

	if len(rep.Findings) == 0 {
		fmt.Fprintf(w, "\n%s\n", th.style(lipgloss.NewStyle().Foreground(lipgloss.Color("#00F5D4")),
			"No malware indicators detected by static pattern analysis."))
		fmt.Fprintf(w, "Note: %s\n", rep.VerdictNote)
		return
	}

	secTitle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00F5D4"))
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
	fileStyle := lipgloss.NewStyle().Underline(true).Foreground(lipgloss.Color("#00D7FF"))
	ruleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF"))

	fmt.Fprintf(w, "\n%s\n", th.style(secTitle, "━━━ FINDINGS (highest severity first) ━━━"))
	for _, f := range rep.Findings {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Fprintf(w, "\n%s %s  %s\n", th.sevBadge(f.Severity), th.style(ruleStyle, strings.ToUpper(f.Rule)), th.style(fileStyle, loc))
		fmt.Fprintf(w, "  %s %s\n", th.style(dimStyle, "category:"), f.Category)
		fmt.Fprintf(w, "  %s %s\n", th.style(dimStyle, "why:     "), f.Why)
		if f.Evidence != "" {
			fmt.Fprintf(w, "  %s %s\n", th.style(dimStyle, "match:   "), f.Evidence)
		}
	}

	if rep.Verdict == "indicators_found_review_required" {
		recBox := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#FF0055")).
			Padding(0, 2).
			Width(boxWidth)
		recText := "RECOMMENDATION:\n" +
			"  • DO NOT run, build, or install dependencies (npm/pip/cargo/make) from this project.\n" +
			"  • Inspect each flagged file/line above carefully before trusting the codebase.\n" +
			"  • Use --out <folder> if you want to save a Markdown & JSON copy of this report."
		fmt.Fprintln(w)
		fmt.Fprintln(w, th.style(recBox, recText))
	}

	if len(rep.Skipped) > 0 {
		fmt.Fprintf(w, "\nSkipped files (%d):\n", len(rep.Skipped))
		for i, s := range rep.Skipped {
			if i >= 10 {
				fmt.Fprintf(w, "  ... and %d more\n", len(rep.Skipped)-10)
				break
			}
			fmt.Fprintf(w, "  - %s\n", s)
		}
	}
}
