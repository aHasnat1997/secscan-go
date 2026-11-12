package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, p, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func TestDisguisedUnitDetected(t *testing.T) {
	d := t.TempDir()
	script := filepath.Join(d, ".config/gvfs-network/start.sh")
	write(t, script, "#!/bin/sh\nexec node runtime.js\n", 0o755)
	unit := filepath.Join(d, ".config/systemd/user/gvfs-network-agent.service")
	body := "[Unit]\nDescription=GNOME Virtual File System network agent\n[Service]\nExecStart=/bin/sh '" + script + "'\nRestart=always\nStandardOutput=null\nLogLevelMax=0\n"
	write(t, unit, body, 0o644)
	sc, why := unitScore(unit, strings.Split(body, "\n"))
	if sc < 5 {
		t.Fatalf("score %d (%v), want >=5", sc, why)
	}
}

func TestLegitUserUnitNotFlagged(t *testing.T) {
	d := t.TempDir()
	unit := filepath.Join(d, "backup.service")
	body := "[Unit]\nDescription=My nightly backup\n[Service]\nExecStart=/usr/bin/rsync -a /data /mnt/backup\n"
	write(t, unit, body, 0o644)
	if sc, _ := unitScore(unit, strings.Split(body, "\n")); sc >= 5 {
		t.Fatalf("legit unit scored %d", sc)
	}
}

func TestIOCScan(t *testing.T) {
	d := t.TempDir()
	known := filepath.Join(d, "a.js")
	write(t, known, "const f='.wl-swap-cmd'", 0o644)
	if !iocScan(known).bad() {
		t.Fatal("known IOC not detected")
	}
	generic := filepath.Join(d, "b.py")
	write(t, generic, "xclip -o; wallet = 0x"+strings.Repeat("a", 40)+"; swap_addr()", 0o644)
	if !iocScan(generic).bad() {
		t.Fatal("generic hijacker pattern not detected")
	}
	benign := filepath.Join(d, "c.sh")
	write(t, benign, "xclip -o | wc -c # copy to clipboard", 0o644)
	if iocScan(benign).bad() {
		t.Fatal("benign clipboard script flagged")
	}
}

func TestScanFindsHijackerInHome(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, ".config/evil/x.sh"), "wl-paste; wallet; swap_wallet", 0o755)
	e := &Env{Ctx: context.Background(), Opts: &Options{}, Homes: []string{d}}
	fs, err := checkIOCScripts(e)
	if err != nil || len(fs) != 1 || fs[0].Severity != SevHigh {
		t.Fatalf("got %v, %v", fs, err)
	}
}

func TestScoreCapsIncompleteScan(t *testing.T) {
	r := &Report{Results: []CheckResult{
		{Name: "a", Status: "ok"},
		{Name: "b", Status: "skipped", Note: "needs root (run with sudo)", Gap: true},
	}}
	score(r)
	if r.Grade == "A" || r.GradeNote == "" {
		t.Fatalf("incomplete scan graded %s (%q)", r.Grade, r.GradeNote)
	}
	r2 := &Report{Results: []CheckResult{{Name: "a", Status: "ok"}}}
	score(r2)
	if r2.Grade != "A" {
		t.Fatalf("clean full scan graded %s", r2.Grade)
	}
}

func TestMinerNoFalsePositiveOnEditor(t *testing.T) {
	if minerRe.MatchString("vim") || stratumRe.MatchString("vim xmrig.conf") {
		t.Fatal("unexpected miner match")
	}
}
