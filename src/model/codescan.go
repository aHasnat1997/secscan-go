package model

// CodeFinding represents an individual malware or risk indicator detected inside a codebase or archive.
type CodeFinding struct {
	Rule     string   `json:"rule"`
	Category string   `json:"category"`
	Severity Severity `json:"severity"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Evidence string   `json:"evidence"`
	Why      string   `json:"why"`
}

// CodeScanReport contains aggregate metrics, findings, and analysis verdict for a code scan.
type CodeScanReport struct {
	Scanner          string         `json:"scanner"`
	Target           string         `json:"target"`
	FilesScanned     int            `json:"files_scanned"`
	Seconds          float64        `json:"seconds"`
	Verdict          string         `json:"verdict"`
	VerdictNote      string         `json:"verdict_note"`
	CountsBySeverity map[string]int `json:"counts_by_severity"`
	CountsByCategory map[string]int `json:"counts_by_category"`
	Findings         []CodeFinding  `json:"findings"`
	Symlinks         []string       `json:"symlinks_not_followed,omitempty"`
	Skipped          []string       `json:"skipped,omitempty"`
}

// CodeScanOptions defines parameters for controlling a codebase malware scan.
type CodeScanOptions struct {
	Target      string
	NoDocker    bool
	MinSeverity Severity
	Format      string
	NoColor     bool
	Verbose     bool
	Out         string
	Password    string
}

