// secscan - Modular Host & Codebase Security Auditing CLI.
//
// Pure Go, zero external runtime dependencies.
// Subcommands:
//   - secscan [host flags]     : 30-point host security audit (CachyOS / Arch Linux)
//   - secscan code-scan <path> : Static malware-indicator scanner for repos and ZIP archives
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"security-go-scanner/src/codescan"
	"security-go-scanner/src/config"
	"security-go-scanner/src/hostaudit"
	"security-go-scanner/src/model"
	"security-go-scanner/src/report"
	"security-go-scanner/src/runner"
	"security-go-scanner/src/terminal"
	"security-go-scanner/src/tui"
)

const version = "1.0.0"

func main() {
	os.Exit(realMain())
}

func realMain() int {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "code-scan":
			return runCodeScanCLI(os.Args[2:])
		case "version", "--version":
			fmt.Printf("secscan %s\n", version)
			return 0
		case "help", "-h", "--help":
			printUsage()
			return 0
		case "host":
			return runHostAuditCLI(os.Args[2:])
		}
	}
	return runHostAuditCLI(os.Args[1:])
}

func printUsage() {
	fmt.Printf(`secscan %s - Host & Codebase Security Auditing CLI

Usage:
  secscan [host flags]             Run comprehensive host security audit
  secscan code-scan [flags] <path> Scan a directory or ZIP archive for malware indicators
  secscan version                  Show version information
  secscan help                     Show this help message

Host Audit Flags:
  --quick            Skip slow checks (pacman -Qkk, SUID walk, rkhunter, lynis)
  --full             Enable opt-in heavy checks (ClamAV)
  --clamav           Run ClamAV scan in addition to default checks
  --only string      Comma-separated list of check IDs to run
  --skip string      Comma-separated list of check IDs to skip
  --list             List all available host audit checks and exit
  --json             Print JSON report to stdout
  --no-color         Disable ANSI color output
  --verbose, -v      Show all evidence lines without truncation
  --show-suppressed  Include suppressed findings in terminal output
  --out string       Save report folder (report.md + report.json) inside specified directory
  --config string    Path to custom config JSON file
  --init-config      Write example config file and exit
  --fail-on string   Exit 1 if any finding >= severity (info|low|medium|high|critical)
  --jobs int         Concurrent check workers (default 4)

Code-Scan Flags:
  --no-docker        Run natively on host instead of isolated Docker container
  --min-severity     Minimum severity to report (info|low|medium|high|critical)
  --format string    Output format: terminal (default), json, or markdown
  --json             Shorthand for --format json
  --no-color         Disable ANSI color output
  --out string       Save report folder (report.md + report.json) inside specified directory
  --password string  Password for encrypted ZIP archives (prompted securely if omitted)
`, version)
}

func runHostAuditCLI(args []string) int {
	fs := flag.NewFlagSet("host", flag.ExitOnError)
	var o hostaudit.Options
	var verFlag bool

	fs.BoolVar(&o.Quick, "quick", false, "skip slow checks")
	fs.BoolVar(&o.Full, "full", false, "include opt-in heavy checks (ClamAV)")
	fs.BoolVar(&o.ClamAV, "clamav", false, "run ClamAV scan")
	fs.BoolVar(&o.JSON, "json", false, "print JSON report to stdout")
	fs.BoolVar(&o.NoColor, "no-color", false, "disable ANSI colors")
	fs.BoolVar(&o.Verbose, "verbose", false, "show all evidence lines")
	fs.BoolVar(&o.Verbose, "v", false, "show all evidence lines")
	fs.BoolVar(&o.ShowSuppressed, "show-suppressed", false, "show suppressed findings")
	fs.BoolVar(&o.NoSave, "no-save", false, "deprecated: reports are not saved unless --out is passed")
	fs.BoolVar(&o.List, "list", false, "list available checks and exit")
	fs.BoolVar(&o.InitConfig, "init-config", false, "write example config file and exit")
	fs.BoolVar(&verFlag, "version", false, "print version and exit")
	fs.StringVar(&o.Only, "only", "", "comma-separated check IDs to run")
	fs.StringVar(&o.Skip, "skip", "", "comma-separated check IDs to skip")
	fs.StringVar(&o.OutDir, "out", "", "save report folder inside this directory")
	fs.StringVar(&o.OutDir, "out-dir", "", "alias for --out")
	fs.StringVar(&o.ConfigPath, "config", "", "config file path")
	fs.StringVar(&o.FailOn, "fail-on", "high", "exit 1 if any unsuppressed finding >= severity")
	fs.StringVar(&o.ClamPaths, "clamav-paths", "", "comma-separated paths for ClamAV")
	fs.DurationVar(&o.ClamTimeout, "clamav-timeout", 30*time.Minute, "ClamAV timeout")
	fs.IntVar(&o.Jobs, "jobs", runner.SmartWorkers(0), "parallel check limit (default ~55% of CPU cores)")
	_ = fs.Parse(args)

	if o.Full && o.ClamTimeout == 30*time.Minute {
		o.ClamTimeout = 45 * time.Minute
	}

	if verFlag {
		fmt.Println("secscan", version)
		return 0
	}

	isTTY := terminal.IsTTY(os.Stdout)
	if (!o.JSON && !isTTY) || os.Getenv("NO_COLOR") != "" {
		o.NoColor = true
	}

	if o.List {
		for _, c := range hostaudit.Registry() {
			fmt.Printf("%-18s %-12s %s\n", c.ID, c.Category, c.Name)
		}
		return 0
	}

	home := hostaudit.PrimaryHome()
	if o.ConfigPath == "" {
		o.ConfigPath = filepath.Join(home, ".config/secscan/config.json")
	}

	if o.InitConfig {
		if _, err := os.Stat(o.ConfigPath); err == nil {
			fmt.Println("config already exists:", o.ConfigPath)
			return 0
		}
		if err := config.WriteExample(o.ConfigPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		report.ChownToSudoUser(filepath.Dir(o.ConfigPath), o.ConfigPath)
		fmt.Println("wrote", o.ConfigPath)
		return 0
	}

	cfg, err := config.Load(o.ConfigPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad config:", err)
		return 2
	}
	o.Config = *cfg

	failOn, ok := model.ParseSeverity(o.FailOn)
	if !ok {
		fmt.Fprintln(os.Stderr, "invalid --fail-on severity")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if os.Geteuid() != 0 && !o.JSON {
		fmt.Fprintln(os.Stderr, "note: not running as root; some checks are skipped or partial. Use: sudo secscan")
	}

	var rep *model.Report
	if isTTY && !o.JSON && !o.NoColor {
		var cancelled bool
		rep, cancelled, err = tui.RunHostAuditTUI(ctx, version, &o)
		if err != nil {
			fmt.Fprintln(os.Stderr, "TUI error:", err)
			return 2
		}
		if cancelled || rep == nil {
			fmt.Fprintln(os.Stderr, "Scan cancelled.")
			return 130
		}
	} else {
		p := terminal.NewPainter(!o.NoColor)
		rep = hostaudit.RunAudit(ctx, version, &o, func(event, name string, res model.CheckResult) {
			if o.JSON {
				return
			}
			if event == "done" {
				st := map[string]string{
					"ok":       p.Green("ok"),
					"findings": p.Yellow("findings"),
					"skipped":  p.Gray("skipped"),
					"error":    p.Red("error"),
				}[res.Status]
				fmt.Fprintf(os.Stderr, "  %-8s %-40s %s (%.1fs)\n", p.Green("done"), name, st, float64(res.DurationMS)/1000)
			}
		})
	}

	if o.JSON {
		jb, _ := report.ToJSON(rep)
		_, _ = os.Stdout.Write(jb)
	} else {
		report.PrintHostAudit(os.Stdout, rep, o.NoColor, o.ShowSuppressed, o.Verbose)
	}

	if o.OutDir != "" {
		folder, jp, mp, err := report.SaveHostAuditToFolder(rep, o.OutDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "failed to save report:", err)
			return 2
		}
		if !o.JSON {
			fmt.Fprintf(os.Stderr, "\nSaved report folder: %s\n  • %s\n  • %s\n", folder, filepath.Base(mp), filepath.Base(jp))
		}
	}

	for _, f := range rep.AllFindings(false) {
		if f.Severity >= failOn {
			return 1
		}
	}
	return 0
}

func runCodeScanCLI(args []string) int {
	fs := flag.NewFlagSet("code-scan", flag.ExitOnError)
	var opts model.CodeScanOptions
	var minSevStr string
	var jsonFlag bool

	fs.BoolVar(&opts.NoDocker, "no-docker", false, "run natively without Docker container isolation")
	fs.StringVar(&minSevStr, "min-severity", "info", "minimum severity (info|low|medium|high|critical)")
	fs.StringVar(&opts.Format, "format", "terminal", "output format: terminal, json, or markdown")
	fs.BoolVar(&jsonFlag, "json", false, "output JSON report")
	fs.BoolVar(&opts.NoColor, "no-color", false, "disable ANSI colors")
	fs.StringVar(&opts.Out, "out", "", "save report folder (report.md + report.json) inside this directory")
	fs.StringVar(&opts.Password, "password", "", "password for encrypted zip archives")
	_ = fs.Parse(args)

	if jsonFlag {
		opts.Format = "json"
	}
	isTTY := terminal.IsTTY(os.Stdout)
	if !isTTY || os.Getenv("NO_COLOR") != "" {
		opts.NoColor = true
	}

	sev, ok := model.ParseSeverity(minSevStr)
	if !ok {
		fmt.Fprintf(os.Stderr, "invalid --min-severity %q\n", minSevStr)
		return 2
	}
	opts.MinSeverity = sev

	rem := fs.Args()
	if len(rem) == 0 {
		fmt.Fprintln(os.Stderr, "usage: secscan code-scan [flags] <target-dir-or-zip>")
		return 2
	}
	opts.Target = rem[0]

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Prompt for encrypted ZIP password before starting TUI so stdin isn't shared.
	codescan.PromptPasswordIfNeeded(&opts)

	var rep *model.CodeScanReport
	var err error
	if isTTY && strings.ToLower(opts.Format) == "terminal" && !opts.NoColor {
		var cancelled bool
		rep, cancelled, err = tui.RunCodeScanTUI(ctx, opts)
		if cancelled {
			fmt.Fprintln(os.Stderr, "Scan cancelled.")
			return 130
		}
	} else {
		rep, err = codescan.Scan(ctx, opts)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	switch strings.ToLower(opts.Format) {
	case "json":
		jb, err := report.ToJSON(rep)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		_, _ = os.Stdout.Write(jb)
	case "markdown", "md":
		fmt.Print(report.CodeScanMarkdown(rep))
	default:
		report.PrintCodeScan(os.Stdout, rep, opts.NoColor)
	}

	if opts.Out != "" {
		folder, jp, mp, err := report.SaveCodeScanToFolder(rep, opts.Out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to save report: %v\n", err)
			return 2
		}
		if strings.ToLower(opts.Format) != "json" {
			fmt.Fprintf(os.Stderr, "\nSaved report folder: %s\n  • %s\n  • %s\n", folder, filepath.Base(mp), filepath.Base(jp))
		}
	}

	if rep.Verdict == "indicators_found_review_required" {
		return 1
	}
	return 0
}
