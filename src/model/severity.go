package model

import (
	"fmt"
	"strings"
)

// Severity represents the impact classification of a security finding.
type Severity int

const (
	// SevInfo indicates informational observations, diagnostic notices, or baseline configurations.
	SevInfo Severity = iota
	// SevLow indicates minor hardening opportunities or benign anomalies.
	SevLow
	// SevMedium indicates notable security concerns, misconfigurations, or unauthenticated services.
	SevMedium
	// SevHigh indicates urgent exposures, active indicators of compromise, or unpatched CVEs.
	SevHigh
	// SevCritical indicates severe, immediately exploitable vulnerabilities or confirmed malicious payloads.
	SevCritical
)

var sevNames = [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

// String returns the uppercase string representation of the severity level.
func (s Severity) String() string {
	if s >= 0 && int(s) < len(sevNames) {
		return sevNames[s]
	}
	return "UNKNOWN"
}

// MarshalText serializes the severity level to lowercase text for JSON output.
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(strings.ToLower(s.String())), nil
}

// UnmarshalText deserializes a string representation into a Severity level.
func (s *Severity) UnmarshalText(b []byte) error {
	v, ok := ParseSeverity(string(b))
	if !ok {
		return fmt.Errorf("invalid severity level: %q", b)
	}
	*s = v
	return nil
}

// ParseSeverity parses a string (case-insensitive) into a typed Severity.
func ParseSeverity(s string) (Severity, bool) {
	trimmed := strings.TrimSpace(s)
	for i, n := range sevNames {
		if strings.EqualFold(n, trimmed) {
			return Severity(i), true
		}
	}
	return SevInfo, false
}

