package report

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"security-go-scanner/src/model"
)

var unsafeFilenameRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// ToJSON serializes any report structure into indented JSON bytes.
func ToJSON(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ChownToSudoUser restores ownership of generated report files when invoked under sudo,
// preventing root-owned files in user-owned directories.
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

// ExpandPath expands a leading "~/" to the invoking user's home directory.
func ExpandPath(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home := ""
		if su := os.Getenv("SUDO_USER"); su != "" {
			if u, err := user.Lookup(su); err == nil {
				home = u.HomeDir
			}
		}
		if home == "" {
			home, _ = os.UserHomeDir()
		}
		if home != "" {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

func sanitizeName(s string) string {
	s = strings.TrimSpace(s)
	s = unsafeFilenameRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-.")
	if s == "" {
		return "target"
	}
	return s
}

// SaveHostAuditToFolder creates a descriptive timestamped folder inside baseDir
// and writes report.json and report.md inside it.
func SaveHostAuditToFolder(r *model.Report, baseDir string) (folderPath, jsonPath, mdPath string, err error) {
	baseDir = ExpandPath(baseDir)
	host := sanitizeName(r.Host)
	ts := r.StartedAt.Format("2006-01-02_15-04-05")
	folderName := fmt.Sprintf("secscan-host-%s-%s", host, ts)
	folderPath = filepath.Join(baseDir, folderName)

	if err := os.MkdirAll(folderPath, 0o755); err != nil {
		return "", "", "", err
	}

	jsonPath = filepath.Join(folderPath, "report.json")
	mdPath = filepath.Join(folderPath, "report.md")

	jb, err := ToJSON(r)
	if err != nil {
		return "", "", "", err
	}
	if err := os.WriteFile(jsonPath, jb, 0o644); err != nil {
		return "", "", "", err
	}

	md := HostAuditMarkdown(r)
	if err := os.WriteFile(mdPath, []byte(md), 0o644); err != nil {
		return "", "", "", err
	}

	ChownToSudoUser(baseDir, folderPath, jsonPath, mdPath)
	return folderPath, jsonPath, mdPath, nil
}

// SaveCodeScanToFolder creates a descriptive timestamped folder inside baseDir
// and writes report.json and report.md inside it.
func SaveCodeScanToFolder(rep *model.CodeScanReport, baseDir string) (folderPath, jsonPath, mdPath string, err error) {
	baseDir = ExpandPath(baseDir)
	targetName := sanitizeName(filepath.Base(rep.Target))
	ts := time.Now().Format("2006-01-02_15-04-05")
	folderName := fmt.Sprintf("secscan-codescan-%s-%s", targetName, ts)
	folderPath = filepath.Join(baseDir, folderName)

	if err := os.MkdirAll(folderPath, 0o755); err != nil {
		return "", "", "", err
	}

	jsonPath = filepath.Join(folderPath, "report.json")
	mdPath = filepath.Join(folderPath, "report.md")

	jb, err := ToJSON(rep)
	if err != nil {
		return "", "", "", err
	}
	if err := os.WriteFile(jsonPath, jb, 0o644); err != nil {
		return "", "", "", err
	}

	md := CodeScanMarkdown(rep)
	if err := os.WriteFile(mdPath, []byte(md), 0o644); err != nil {
		return "", "", "", err
	}

	ChownToSudoUser(baseDir, folderPath, jsonPath, mdPath)
	return folderPath, jsonPath, mdPath, nil
}
