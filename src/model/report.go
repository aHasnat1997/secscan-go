package model

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// CheckResult records the execution summary, duration, and findings for a single check.
type CheckResult struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Category   string    `json:"category"`
	Status     string    `json:"status"`        // ok | findings | skipped | error
	Gap        bool      `json:"gap,omitempty"` // true when check could not run due to an unintended gap
	Note       string    `json:"note,omitempty"`
	DurationMS int64     `json:"duration_ms"`
	Findings   []Finding `json:"findings,omitempty"`
}

// Report encapsulates the aggregate findings and security posture metrics of a host scan.
type Report struct {
	Tool       string         `json:"tool"`
	Version    string         `json:"version"`
	Host       string         `json:"host"`
	OS         string         `json:"os"`
	Kernel     string         `json:"kernel"`
	StartedAt  time.Time      `json:"started_at"`
	DurationMS int64          `json:"duration_ms"`
	Root       bool           `json:"root"`
	ScoreVal   int            `json:"score"`
	Grade      string         `json:"grade"`
	GradeNote  string         `json:"grade_note,omitempty"`
	Coverage   string         `json:"coverage"`
	Incomplete []string       `json:"incomplete,omitempty"`
	Counts     map[string]int `json:"counts"`
	Suppressed int            `json:"suppressed"`
	Resolved   []string       `json:"resolved_since_last_run,omitempty"`
	Results    []CheckResult  `json:"results"`
}

// AllFindings flattens findings across all check results, optionally including suppressed ones.
func (r *Report) AllFindings(withSuppressed bool) []Finding {
	var fs []Finding
	for _, res := range r.Results {
		for _, f := range res.Findings {
			if f.Suppressed == "" || withSuppressed {
				fs = append(fs, f)
			}
		}
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		return fs[i].Category < fs[j].Category
	})
	return fs
}

// ActionPlan partitions findings into prioritized actions: immediate (now), medium-term (soon), and low-priority (later).
func (r *Report) ActionPlan() (now, soon, later []string) {
	for _, f := range r.AllFindings(false) {
		if f.Severity == SevInfo {
			continue
		}
		fix := strings.SplitN(f.Remediation, "\n", 2)[0]
		if fix == "" {
			fix = f.Title
		}
		line := fmt.Sprintf("[%s] %s: %s", f.Severity, f.ID, fix)
		switch {
		case f.Severity >= SevHigh:
			now = append(now, line)
		case f.Severity == SevMedium:
			soon = append(soon, line)
		default:
			later = append(later, line)
		}
	}
	return
}

// Score computes the weighted security score (0-100), letter grade (A-F), and enforces coverage caps.
func (r *Report) Score() {
	s := 100
	r.Counts = map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	r.Suppressed = 0
	r.Incomplete = nil

	for _, res := range r.Results {
		for _, f := range res.Findings {
			if f.Suppressed != "" {
				r.Suppressed++
				continue
			}
			r.Counts[strings.ToLower(f.Severity.String())]++
			switch f.Severity {
			case SevCritical:
				s -= 30
			case SevHigh:
				s -= 12
			case SevMedium:
				s -= 4
			case SevLow:
				s -= 1
			}
		}
	}
	if s < 0 {
		s = 0
	}

	ran, errs := 0, 0
	for _, res := range r.Results {
		switch {
		case res.Status == "ok" || res.Status == "findings":
			ran++
		case res.Status == "error":
			errs++
			r.Incomplete = append(r.Incomplete, res.Name+": "+res.Note)
		case res.Gap:
			r.Incomplete = append(r.Incomplete, res.Name+": "+res.Note)
		}
	}

	r.Coverage = fmt.Sprintf("%d/%d checks ran", ran, ran+len(r.Incomplete))
	r.ScoreVal = s
	switch {
	case s >= 90:
		r.Grade = "A"
	case s >= 75:
		r.Grade = "B"
	case s >= 60:
		r.Grade = "C"
	case s >= 40:
		r.Grade = "D"
	default:
		r.Grade = "F"
	}

	cap := ""
	switch {
	case errs > 0 || len(r.Incomplete) >= 4:
		cap = "C"
	case len(r.Incomplete) > 0:
		cap = "B"
	}
	if cap != "" && r.Grade < cap {
		r.Grade = cap
		r.GradeNote = fmt.Sprintf("capped at %s: %d check(s) could not run, so the score is not trustworthy", cap, len(r.Incomplete))
	} else if cap != "" {
		r.GradeNote = fmt.Sprintf("%d check(s) could not run, coverage is incomplete", len(r.Incomplete))
	}
}

