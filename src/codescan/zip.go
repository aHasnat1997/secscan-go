package codescan

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"security-go-scanner/src/model"
	"security-go-scanner/src/runner"
)

// IsZipFileEncrypted inspects a ZIP archive's general-purpose bit flags without extracting files
// to determine whether any entry is encrypted.
func IsZipFileEncrypted(zipPath string) (bool, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return false, err
	}
	defer r.Close()

	for _, f := range r.File {
		if f.Flags&1 != 0 {
			return true, nil
		}
	}
	return false, nil
}

// ScanZipInMemory inspects a ZIP archive directly in memory without extracting unencrypted
// artifacts to the host filesystem, mitigating disk-persistence and path-traversal risks.
func ScanZipInMemory(zipPath string, password string, minSev model.Severity) (*model.CodeScanReport, error) {
	initRules()
	t0 := time.Now()

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open zip archive %s: %w", zipPath, err)
	}
	defer r.Close()

	var findings []model.CodeFinding
	var skipped []string
	filesScanned := 0

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if strings.Contains(f.Name, ".git/objects") || strings.Contains(f.Name, ".git/lfs") {
			continue
		}

		filesScanned++
		if f.UncompressedSize64 > maxTextBytes {
			skipped = append(skipped, fmt.Sprintf("%s (%d bytes, over text limit)", f.Name, f.UncompressedSize64))
			continue
		}

		// Bit 0 of Flags indicates standard ZIP encryption or WinZip AES encryption.
		if f.Flags&1 != 0 {
			raw, readErr := readEncryptedEntryToMemory(zipPath, f.Name, password)
			if readErr != nil || len(raw) == 0 {
				findings = append(findings, model.CodeFinding{
					Rule:     "zip-encrypted-payload",
					Category: "obfuscation",
					Severity: model.SevHigh,
					File:     f.Name,
					Line:     0,
					Evidence: fmt.Sprintf("%s is password-protected/encrypted (%v)", f.Name, readErr),
					Why:      "password-protected / encrypted file in archive; requires valid password to scan",
				})
				continue
			}

			ScanFileContent(f.Name, filepath.Base(f.Name), raw, &findings)
			continue
		}

		rc, err := f.Open()
		if err != nil {
			skipped = append(skipped, f.Name+" (unreadable in zip)")
			continue
		}

		raw, err := io.ReadAll(io.LimitReader(rc, maxTextBytes+1))
		rc.Close()
		if err != nil {
			skipped = append(skipped, f.Name+" (read error)")
			continue
		}

		ScanFileContent(f.Name, filepath.Base(f.Name), raw, &findings)
	}

	return BuildReport("secscan code-scan (native in-memory zip scan)", zipPath, filesScanned, t0, findings, nil, skipped, minSev), nil
}

// readEncryptedEntryToMemory streams a decrypted entry directly to stdout in RAM via 7z without writing to disk.
func readEncryptedEntryToMemory(zipPath, entryName, password string) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("password required")
	}
	if !runner.Have("7z") {
		return nil, fmt.Errorf("7z utility required for AES/ZipCrypto stream decryption")
	}

	cmd := exec.Command("7z", "e", "-so", "-p"+password, zipPath, entryName)
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	if err := cmd.Run(); err != nil || outBuf.Len() == 0 {
		return nil, fmt.Errorf("decryption failed (wrong password?)")
	}
	return outBuf.Bytes(), nil
}

