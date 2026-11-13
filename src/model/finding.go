package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Finding represents a single security issue, anomaly, or compliance violation.
type Finding struct {
	ID          string   `json:"id"`
	Check       string   `json:"check"`
	Category    string   `json:"category"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Detail      string   `json:"detail,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Fingerprint string   `json:"fingerprint"`
	Status      string   `json:"status,omitempty"`
	Suppressed  string   `json:"suppressed,omitempty"`
}

// NewFinding instantiates a Finding and automatically computes its cryptographic fingerprint.
func NewFinding(id string, sev Severity, title, detail, remediation string, evidence ...string) Finding {
	f := Finding{
		ID:          id,
		Severity:    sev,
		Title:       title,
		Detail:      detail,
		Remediation: remediation,
		Evidence:    evidence,
	}
	f.Fingerprint = CalculateFingerprint(f)
	return f
}

// CalculateFingerprint generates a stable 16-hex-character digest of the finding's identity.
func CalculateFingerprint(f Finding) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%s\n", f.ID, f.Title, strings.Join(f.Evidence, "\n"))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

