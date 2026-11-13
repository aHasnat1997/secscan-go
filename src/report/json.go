package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"

	"security-go-scanner/src/model"
)

// ToJSON serializes any report structure into indented JSON bytes.
func ToJSON(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ChownToSudoUser restores ownership of generated report files when invoked under sudo,
// preventing root-owned files in user-owned ~/.local/share/secscan.
func ChownToSudoUser(paths ...string) {
	if os.Geteuid() != 0 {
		return
	}
	uid, uerr := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, gerr := strconv.Atoi(os.Getenv("SUDO_GID"))
	if uerr != nil || gerr != nil {
		return
	}
	for _, p := range paths {
		_ = os.Chown(p, uid, gid)
	}
}

// SaveHostAuditReports writes timestamped JSON and Markdown reports to outDir and updates latest.json.
func SaveHostAuditReports(r *model.Report, outDir string) (jsonPath, mdPath string, err error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", "", err
	}
	ts := r.StartedAt.Format("20060102-150405")
	jsonPath = filepath.Join(outDir, "report-"+ts+".json")
	mdPath = filepath.Join(outDir, "report-"+ts+".md")
	latestPath := filepath.Join(outDir, "latest.json")

	jb, err := ToJSON(r)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(jsonPath, jb, 0o600); err != nil {
		return "", "", err
	}
	_ = os.WriteFile(latestPath, jb, 0o600)

	md := HostAuditMarkdown(r)
	if err := os.WriteFile(mdPath, []byte(md), 0o600); err != nil {
		return "", "", err
	}

	ChownToSudoUser(outDir, jsonPath, mdPath, latestPath)
	return jsonPath, mdPath, nil
}

