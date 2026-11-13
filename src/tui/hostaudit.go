// Package tui provides interactive, responsive, animated Bubble Tea terminal UIs
// for host security auditing and isolated codebase scanning.
package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"security-go-scanner/src/hostaudit"
	"security-go-scanner/src/model"
)

type checkEventMsg struct {
	event string
	name  string
	res   model.CheckResult
}

type auditDoneMsg struct {
	rep *model.Report
}

type tickMsg time.Time

type hostAuditModel struct {
	version   string
	total     int
	completed int
	active    map[string]time.Time
	recent    []model.CheckResult
	counts    map[model.Severity]int
	spinner   spinner.Model
	progress  progress.Model
	width     int
	height    int
	startedAt time.Time
	cancelled bool
	done      bool
	rep       *model.Report
	cancelFn  context.CancelFunc
}

func newHostAuditModel(version string, total int, cancelFn context.CancelFunc) hostAuditModel {
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#00F5D4"))

	prog := progress.New(
		progress.WithGradient("#00F5D4", "#9B5DE5"),
		progress.WithWidth(50),
	)

	return hostAuditModel{
		version:   version,
		total:     total,
		active:    make(map[string]time.Time),
		counts:    make(map[model.Severity]int),
		spinner:   sp,
		progress:  prog,
		width:     80,
		height:    24,
		startedAt: time.Now(),
		cancelFn:  cancelFn,
	}
}

func tickEvery() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m hostAuditModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, tickEvery())
}

func (m hostAuditModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		pw := m.width - 10
		if pw > 76 {
			pw = 76
		}
		if pw < 20 {
			pw = 20
		}
		m.progress.Width = pw
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.cancelled = true
			if m.cancelFn != nil {
				m.cancelFn()
			}
			return m, tea.Quit
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case progress.FrameMsg:
		pm, cmd := m.progress.Update(msg)
		m.progress = pm.(progress.Model)
		return m, cmd

	case tickMsg:
		if m.done {
			return m, nil
		}
		return m, tickEvery()

	case checkEventMsg:
		if msg.event == "running" {
			m.active[msg.name] = time.Now()
			return m, nil
		}
		if msg.event == "done" {
			delete(m.active, msg.name)
			m.completed++
			for _, f := range msg.res.Findings {
				if f.Suppressed == "" {
					m.counts[f.Severity]++
				}
			}
			m.recent = append(m.recent, msg.res)
			if len(m.recent) > 8 {
				m.recent = m.recent[len(m.recent)-8:]
			}
			pct := 0.0
			if m.total > 0 {
				pct = float64(m.completed) / float64(m.total)
			}
			cmd := m.progress.SetPercent(pct)
			return m, cmd
		}

	case auditDoneMsg:
		m.done = true
		m.rep = msg.rep
		return m, tea.Quit
	}

	return m, nil
}

func (m hostAuditModel) View() string {
	boxWidth := m.width - 4
	if boxWidth > 88 {
		boxWidth = 88
	}
	if boxWidth < 40 {
		boxWidth = 40
	}

	elapsed := time.Since(m.startedAt).Seconds()
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00F5D4"))
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#777777"))

	var b strings.Builder
	b.WriteString(titleStyle.Render(fmt.Sprintf("⚡ secscan %s  •  Host Security Audit", m.version)))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render(fmt.Sprintf("Progress: %d / %d checks   •   Elapsed: %.1fs", m.completed, m.total, elapsed)))
	b.WriteString("\n\n")
	b.WriteString(m.progress.View())
	b.WriteString("\n\n")

	// Live finding counters
	crit := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0055")).Bold(true).Render(fmt.Sprintf("CRIT %d", m.counts[model.SevCritical]))
	high := lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5F00")).Bold(true).Render(fmt.Sprintf("HIGH %d", m.counts[model.SevHigh]))
	med := lipgloss.NewStyle().Foreground(lipgloss.Color("#FFAF00")).Render(fmt.Sprintf("MED %d", m.counts[model.SevMedium]))
	low := lipgloss.NewStyle().Foreground(lipgloss.Color("#00D7FF")).Render(fmt.Sprintf("LOW %d", m.counts[model.SevLow]))
	b.WriteString(fmt.Sprintf("Live Detections:  %s   %s   %s   %s\n\n", crit, high, med, low))

	// Active checks
	if len(m.active) > 0 {
		b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Render("Active Modules:"))
		b.WriteString("\n")
		names := make([]string, 0, len(m.active))
		for k := range m.active {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, n := range names {
			dt := time.Since(m.active[n]).Seconds()
			b.WriteString(fmt.Sprintf("  %s %-36s %s\n", m.spinner.View(), n, dimStyle.Render(fmt.Sprintf("(%.1fs)", dt))))
		}
		b.WriteString("\n")
	}

	// Recent completed checks
	if len(m.recent) > 0 {
		b.WriteString(dimStyle.Render("Recent:"))
		b.WriteString("\n")
		for _, res := range m.recent {
			var badge string
			switch res.Status {
			case "ok":
				badge = lipgloss.NewStyle().Foreground(lipgloss.Color("#00F5D4")).Render("✓")
			case "findings":
				badge = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFAF00")).Render("!")
			case "skipped":
				badge = dimStyle.Render("-")
			default:
				badge = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0055")).Render("✗")
			}
			b.WriteString(fmt.Sprintf("  %s %-38s %s\n", badge, res.Name, dimStyle.Render(fmt.Sprintf("%.1fs", float64(res.DurationMS)/1000))))
		}
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("Press q or Ctrl+C to cancel"))

	frame := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#9B5DE5")).
		Padding(1, 2).
		Width(boxWidth)

	return "\n" + frame.Render(b.String()) + "\n"
}

// RunHostAuditTUI executes the host security audit with a live animated Bubble Tea dashboard.
func RunHostAuditTUI(ctx context.Context, version string, o *hostaudit.Options) (*model.Report, bool, error) {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Estimate active checks for accurate progress bar scaling.
	total := len(hostaudit.Registry())
	m := newHostAuditModel(version, total, cancel)
	p := tea.NewProgram(m)

	go func() {
		rep := hostaudit.RunAudit(cctx, version, o, func(event, name string, res model.CheckResult) {
			p.Send(checkEventMsg{event: event, name: name, res: res})
		})
		p.Send(auditDoneMsg{rep: rep})
	}()

	finalModel, err := p.Run()
	if err != nil {
		return nil, false, err
	}
	fm := finalModel.(hostAuditModel)
	return fm.rep, fm.cancelled, nil
}

