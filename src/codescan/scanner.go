package codescan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"security-go-scanner/src/model"
	"security-go-scanner/src/runner"
	"security-go-scanner/src/terminal"
)

const (
	maxTextBytes      = 2 * 1024 * 1024
	maxPerRulePerFile = 5
)

// PromptPasswordIfNeeded checks if Target is an encrypted ZIP archive and prompts
// securely on the host TTY before any TUI takes over stdin.
func PromptPasswordIfNeeded(opts *model.CodeScanOptions) {
	if opts.Password != "" {
		return
	}
	if envPw := os.Getenv("SECSCAN_ZIP_PASSWORD"); envPw != "" {
		opts.Password = envPw
		return
	}
	targetAbs, err := filepath.Abs(opts.Target)
	if err != nil {
		return
	}
	st, err := os.Stat(targetAbs)
	if err != nil || st.IsDir() || !strings.EqualFold(filepath.Ext(targetAbs), ".zip") {
		return
	}
	encrypted, err := IsZipFileEncrypted(targetAbs)
	if err == nil && encrypted && terminal.IsTTY(os.Stdin) {
		fmt.Printf("[?] Archive %s contains password-protected files.\n", filepath.Base(targetAbs))
		if pw, err := terminal.ReadPassword("    Enter zip password: "); err == nil {
			opts.Password = pw
		}
	}
}

// Scan executes a static malware-indicator scan on a target directory or ZIP archive.
// By default it isolates the scan inside a read-only, network-disabled Docker container
// using the statically compiled secscan binary itself.
func Scan(ctx context.Context, opts model.CodeScanOptions) (*model.CodeScanReport, error) {
	targetAbs, err := filepath.Abs(opts.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target path: %w", err)
	}

	st, err := os.Stat(targetAbs)
	if err != nil {
		return nil, fmt.Errorf("cannot access target %s: %w", targetAbs, err)
	}

	isZip := !st.IsDir() && strings.EqualFold(filepath.Ext(targetAbs), ".zip")

	PromptPasswordIfNeeded(&opts)
	password := opts.Password

	if !opts.NoDocker {
		return RunInDocker(ctx, targetAbs, isZip, password, opts.MinSeverity)
	}

	if isZip {
		return ScanZipInMemory(targetAbs, password, opts.MinSeverity)
	}

	if !st.IsDir() {
		// Single non-zip file scan
		return scanSingleFileNative(targetAbs, opts.MinSeverity)
	}

	return ScanDirectory(targetAbs, opts.MinSeverity)
}

func scanSingleFileNative(filePath string, minSev model.Severity) (*model.CodeScanReport, error) {
	initRules()
	t0 := time.Now()
	var findings []model.CodeFinding
	var skipped []string

	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	if len(raw) > maxTextBytes {
		skipped = append(skipped, fmt.Sprintf("%s (%d bytes, over text limit)", filepath.Base(filePath), len(raw)))
	} else {
		ScanFileContent(filepath.Base(filePath), filepath.Base(filePath), raw, &findings)
	}

	return BuildReport("secscan code-scan (native safe scan)", filePath, 1, t0, findings, nil, skipped, minSev), nil
}

// ScanDirectory safely walks a directory strictly read-only without following symlinks
// or executing/building any code from the target.
func ScanDirectory(root string, minSev model.Severity) (*model.CodeScanReport, error) {
	initRules()
	t0 := time.Now()

	var findings []model.CodeFinding
	var symlinks []string
	var skipped []string
	filesScanned := 0

	type fileJob struct {
		path string
		rel  string
		name string
	}
	var jobs []fileJob

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		rel, _ := filepath.Rel(root, p)
		if rel == "." {
			return nil
		}

		// Security boundary: Never follow symlinks outside the target tree.
		if d.Type()&fs.ModeSymlink != 0 {
			target, _ := os.Readlink(p)
			symlinks = append(symlinks, fmt.Sprintf("%s -> %s", rel, target))
			return nil
		}

		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == ".cache" {
				return filepath.SkipDir
			}
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		filesScanned++

		if info.Size() > maxTextBytes {
			skipped = append(skipped, fmt.Sprintf("%s (%d bytes, over text limit)", rel, info.Size()))
			return nil
		}

		jobs = append(jobs, fileJob{path: p, rel: rel, name: d.Name()})
		return nil
	})

	if err != nil {
		return nil, err
	}

	if len(jobs) > 0 {
		type jobRes struct {
			findings []model.CodeFinding
			skipped  string
		}
		tasks := make([]runner.Task[jobRes], 0, len(jobs))
		for _, jb := range jobs {
			j := jb
			tasks = append(tasks, runner.Task[jobRes]{
				Name: j.rel,
				Fn: func(_ context.Context) jobRes {
					raw, rerr := os.ReadFile(j.path)
					if rerr != nil {
						return jobRes{skipped: j.rel + " (unreadable)"}
					}
					var localFindings []model.CodeFinding
					ScanFileContent(j.rel, j.name, raw, &localFindings)
					return jobRes{findings: localFindings}
				},
			})
		}

		for _, res := range runner.RunConcurrent(context.Background(), runner.SmartWorkers(0), tasks, nil, nil) {
			if res.skipped != "" {
				skipped = append(skipped, res.skipped)
			}
			findings = append(findings, res.findings...)
		}
	}

	return BuildReport("secscan code-scan (native safe scan)", root, filesScanned, t0, findings, symlinks, skipped, minSev), nil
}

// ScanFileContent evaluates a single file's raw bytes against binary heuristics,
// Trojan Source Unicode attacks, npm lifecycle scripts, regex signatures, and co-occurrence rules.
func ScanFileContent(rel string, name string, raw []byte, findings *[]model.CodeFinding) {
	initRules()
	ext := strings.ToLower(filepath.Ext(name))

	// 1. Double extension masquerading (e.g. invoice.pdf.exe)
	if doubleExtRe.MatchString(name) {
		*findings = append(*findings, model.CodeFinding{
			Rule: "file-double-ext", Category: "obfuscation", Severity: model.SevHigh,
			File: rel, Line: 0, Evidence: name, Why: "double extension disguising an executable",
		})
	}

	// 2. Rootkit file artifacts
	if name == "ld.so.preload" || ext == ".ko" {
		*findings = append(*findings, model.CodeFinding{
			Rule: "file-rootkit-artifact", Category: "rootkit", Severity: model.SevHigh,
			File: rel, Line: 0, Evidence: name, Why: "file type commonly associated with rootkits (kernel module / preload list)",
		})
	}

	// 3. Compiled binary detection via magic bytes or extension
	var head string
	if len(raw) >= 8 {
		head = string(raw[:8])
	}
	kind := ""
	for m, desc := range binaryMagic {
		if strings.HasPrefix(head, m) {
			kind = desc
			break
		}
	}

	if kind != "" || binaryExts[ext] {
		sev := model.SevLow
		if kind != "" && ext != ".node" {
			sev = model.SevMedium
		}
		digest := sha256Bytes(raw)
		ident := kind
		if ident == "" {
			ident = ext
		}
		*findings = append(*findings, model.CodeFinding{
			Rule: "bin-artifact", Category: "binary", Severity: sev,
			File: rel, Line: 0, Evidence: fmt.Sprintf("%s sha256=%s", ident, digest),
			Why: "compiled binary inside source tree; verify it is expected and reproducible",
		})
		return
	}

	// 4. Windows script extensions
	if windowsScriptExts[ext] {
		*findings = append(*findings, model.CodeFinding{
			Rule: "script-windows", Category: "binary", Severity: model.SevLow,
			File: rel, Line: 0, Evidence: name, Why: "Windows script file; review contents",
		})
	}

	// 5. Skip opaque binary blobs (null bytes in first 4KB)
	checkLen := len(raw)
	if checkLen > 4096 {
		checkLen = 4096
	}
	if bytes.ContainsRune(raw[:checkLen], 0) {
		return
	}

	text := string(raw)
	lines := strings.Split(text, "\n")

	// 6. Trojan Source (CVE-2021-42574) Bidirectional Unicode control characters
	if loc := bidiRe.FindStringIndex(text); loc != nil {
		ln := strings.Count(text[:loc[0]], "\n") + 1
		lineText := ""
		if ln-1 < len(lines) {
			lineText = lines[ln-1]
		}
		*findings = append(*findings, model.CodeFinding{
			Rule: "src-bidi", Category: "obfuscation", Severity: model.SevHigh,
			File: rel, Line: ln, Evidence: formatSnippet(lineText),
			Why: "bidirectional-control characters (Trojan Source): code displays differently than it executes",
		})
	}

	// 7. Node.js package.json automatic install-time lifecycle hooks
	if name == "package.json" {
		var pkg struct {
			Scripts map[string]string `json:"scripts"`
		}
		if err := json.Unmarshal(raw, &pkg); err == nil && pkg.Scripts != nil {
			for key, cmd := range pkg.Scripts {
				if npmLifecycleRe[key] && cmd != "" {
					sev := model.SevLow
					if riskyScriptRe.MatchString(cmd) {
						sev = model.SevHigh
					}
					*findings = append(*findings, model.CodeFinding{
						Rule: "npm-lifecycle", Category: "supply_chain", Severity: sev,
						File: rel, Line: 0, Evidence: fmt.Sprintf("%s: %s", key, formatSnippet(cmd)),
						Why: "install-time script runs automatically on npm install",
					})
				}
			}
		}
	}

	// 8. Line-by-line static signature scanning
	ruleHits := make(map[string]int)
	for lnNo, line := range lines {
		if len(line) > 20000 {
			line = line[:20000]
		}
		for _, r := range codeRules {
			if r.Pattern.MatchString(line) {
				if ruleHits[r.ID] < maxPerRulePerFile {
					*findings = append(*findings, model.CodeFinding{
						Rule: r.ID, Category: r.Category, Severity: r.Severity,
						File: rel, Line: lnNo + 1, Evidence: formatSnippet(line), Why: r.Why,
					})
				}
				ruleHits[r.ID]++
			}
		}
	}

	// 9. Whole-file multi-token co-occurrence correlation
	for _, cr := range cooccurRules {
		matchedAll := true
		for _, p := range cr.Patterns {
			if !p.MatchString(text) {
				matchedAll = false
				break
			}
		}
		if matchedAll {
			loc := cr.Patterns[0].FindStringIndex(text)
			ln := 1
			if loc != nil {
				ln = strings.Count(text[:loc[0]], "\n") + 1
			}
			ev := ""
			if ln-1 < len(lines) {
				ev = formatSnippet(lines[ln-1])
			}
			*findings = append(*findings, model.CodeFinding{
				Rule: cr.ID, Category: cr.Category, Severity: cr.Severity,
				File: rel, Line: ln, Evidence: ev, Why: cr.Why,
			})
		}
	}
}

// BuildReport filters, sorts, and aggregates findings into a standardized CodeScanReport.
func BuildReport(scanner, target string, filesScanned int, t0 time.Time, rawFindings []model.CodeFinding, symlinks, skipped []string, minSev model.Severity) *model.CodeScanReport {
	var filtered []model.CodeFinding
	bySev := map[string]int{}
	byCat := map[string]int{}
	maxSev := model.SevInfo

	for _, f := range rawFindings {
		if f.Severity >= minSev {
			filtered = append(filtered, f)
			bySev[strings.ToLower(f.Severity.String())]++
			byCat[f.Category]++
			if f.Severity > maxSev {
				maxSev = f.Severity
			}
		}
	}

	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].Severity != filtered[j].Severity {
			return filtered[i].Severity > filtered[j].Severity
		}
		if filtered[i].File != filtered[j].File {
			return filtered[i].File < filtered[j].File
		}
		return filtered[i].Line < filtered[j].Line
	})

	verdict := "no_indicators_found"
	if maxSev >= model.SevHigh {
		verdict = "indicators_found_review_required"
	} else if len(filtered) > 0 {
		verdict = "low_signal_only"
	}

	return &model.CodeScanReport{
		Scanner:          scanner,
		Target:           target,
		FilesScanned:     filesScanned,
		Seconds:          time.Since(t0).Seconds(),
		Verdict:          verdict,
		VerdictNote:      "Static malware-indicator pattern analysis. 'no_indicators_found' is NOT proof the code is safe.",
		CountsBySeverity: bySev,
		CountsByCategory: byCat,
		Findings:         filtered,
		Symlinks:         symlinks,
		Skipped:          skipped,
	}
}

