package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"security-go-scanner/src/codescan"
	"security-go-scanner/src/model"
)

type codeScanDoneMsg struct {
	rep *model.CodeScanReport
	err error
}

type codeScanModel struct {
	opts      model.CodeScanOptions
	spinner   spinner.Model
	width     int
	height    int
	tick      int
	startedAt time.Time
	cancelled bool
	done      bool
	rep       *model.CodeScanReport
	err       error
	cancelFn  context.CancelFunc
}

func newCodeScanModel(opts model.CodeScanOptions, cancelFn context.CancelFunc) codeScanModel {
	sp := spinner.New()
	sp.Spinner = spinner.Points
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#00F5D4"))

	return codeScanModel{
		opts:      opts,
		spinner:   sp,
		width:     80,
		height:    24,
		startedAt: time.Now(),
		cancelFn:  cancelFn,
	}
}

func (m codeScanModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, tickEvery())
}

func (m codeScanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
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

	case tickMsg:
		if m.done {
			return m, nil
		}
		m.tick++
		return m, tickEvery()

	case codeScanDoneMsg:
		m.done = true
		m.rep = msg.rep
		m.err = msg.err
		return m, tea.Quit
	}

	return m, nil
}

// renderSweepBar renders a smooth, cyber-styled oscillating scanner bar.
func renderSweepBar(width, tick int) string {
	if width < 16 {
		width = 16
	}
	segLen := 8
	span := width - segLen
	if span <= 0 {
		span = 1
	}
	pos := tick % (span * 2)
	if pos >= span {
		pos = (span * 2) - pos
	}

	var b strings.Builder
	trackStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#333344"))
	colors := []string{"#9B5DE5", "#00BBF9", "#00F5D4", "#00F5D4", "#00F5D4", "#00F5D4", "#00BBF9", "#9B5DE5"}

	for i := 0; i < width; i++ {
		if i >= pos && i < pos+segLen {
			c := colors[i-pos]
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(c)).Render("━"))
		} else {
			b.WriteString(trackStyle.Render("─"))
		}
	}
	return b.String()
}

func (m codeScanModel) View() string {
	boxWidth := m.width - 4
	if boxWidth > 84 {
		boxWidth = 84
	}
	if boxWidth < 40 {
		boxWidth = 40
	}

	elapsed := time.Since(m.startedAt).Seconds()
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00F5D4"))
	dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
	modeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#9B5DE5")).Bold(true)

	mode := "Isolated Docker Container (--network none, read-only)"
	if m.opts.NoDocker {
		mode = "Native Safe Scan (read-only, in-memory)"
	}

	phase := "Analyzing files & correlating malware signatures..."
	if !m.opts.NoDocker && elapsed < 2.0 {
		phase = "Spinning up isolated read-only container..."
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render("🛡  secscan code-scan  •  Static Malware Analyzer"))
	b.WriteString("\n\n")
	b.WriteString(fmt.Sprintf("Target:  %s\n", lipgloss.NewStyle().Bold(true).Render(filepath.Base(m.opts.Target))))
	b.WriteString(fmt.Sprintf("Engine:  %s\n", modeStyle.Render(mode)))
	b.WriteString(fmt.Sprintf("Elapsed: %.1fs\n\n", elapsed))
	b.WriteString(fmt.Sprintf("%s %s\n\n", m.spinner.View(), phase))
	b.WriteString(renderSweepBar(boxWidth-8, m.tick))
	b.WriteString("\n\n")
	b.WriteString(dimStyle.Render("Press q or Ctrl+C to cancel"))

	frame := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#00BBF9")).
		Padding(1, 2).
		Width(boxWidth)

	return "\n" + frame.Render(b.String()) + "\n"
}

// RunCodeScanTUI executes the codebase/archive scan with an animated Bubble Tea UI.
func RunCodeScanTUI(ctx context.Context, opts model.CodeScanOptions) (*model.CodeScanReport, bool, error) {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	m := newCodeScanModel(opts, cancel)
	p := tea.NewProgram(m)

	go func() {
		rep, err := codescan.Scan(cctx, opts)
		p.Send(codeScanDoneMsg{rep: rep, err: err})
	}()

	finalModel, err := p.Run()
	if err != nil {
		return nil, false, err
	}
	fm := finalModel.(codeScanModel)
	return fm.rep, fm.cancelled, fm.err
}

