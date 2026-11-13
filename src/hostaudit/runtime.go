package hostaudit

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"security-go-scanner/src/model"
	"security-go-scanner/src/runner"
)

// CheckTempExec scans volatile temp directories (/tmp, /var/tmp, /dev/shm) for native ELF binaries and executable scripts.
func CheckTempExec(e *AuditEnv) ([]model.Finding, error) {
	var elf, scripts []string
	for _, r := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		walk(e, r, func(p string, d fs.DirEntry) {
			if !d.Type().IsRegular() {
				return
			}
			info, err := d.Info()
			if err != nil {
				return
			}
			if strings.HasPrefix(p, "/tmp/go-build") {
				return
			}
			isElf := false
			if f, err := os.Open(p); err == nil {
				b := make([]byte, 4)
				if n, _ := f.Read(b); n == 4 && string(b) == "\x7fELF" {
					isElf = true
				}
				f.Close()
			}
			switch {
			case isElf:
				elf = append(elf, p)
			case info.Mode()&0o111 != 0:
				scripts = append(scripts, p)
			}
		})
	}
	var out []model.Finding
	if len(elf) > 0 {
		sort.Strings(elf)
		out = append(out, finding("FS-TMP-ELF", model.SevMedium, fmt.Sprintf("%d native binaries in temp directories", len(elf)),
			"Malware commonly stages payloads in /tmp, /var/tmp and /dev/shm. Build tools and Electron apps also leave files here.",
			"Inspect: file <path>, sha256sum <path>, then search the hash on virustotal.com. Delete if unknown.", elf...))
	}
	if len(scripts) > 0 {
		sort.Strings(scripts)
		out = append(out, finding("FS-TMP-EXEC", model.SevLow, fmt.Sprintf("%d executable files in temp directories", len(scripts)), "", "Review and delete what you do not recognise.", scripts...))
	}
	return out, nil
}

// CheckProcesses inspects /proc for cryptominers, binaries running from temp directories, and deleted running binaries.
func CheckProcesses(e *AuditEnv) ([]model.Finding, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var tmp, miners, deleted []string
	for _, en := range ents {
		pid := en.Name()
		if n, err := strconv.Atoi(pid); err != nil || n == os.Getpid() {
			continue
		}
		exe, err := os.Readlink("/proc/" + pid + "/exe")
		if err != nil {
			continue
		}
		cm, _ := os.ReadFile("/proc/" + pid + "/comm")
		comm := strings.TrimSpace(string(cm))
		cl, _ := os.ReadFile("/proc/" + pid + "/cmdline")
		cmdline := strings.ReplaceAll(string(cl), "\x00", " ")
		label := fmt.Sprintf("pid %s %s -> %s", pid, comm, exe)

		switch {
		case minerRe.MatchString(exe) || minerRe.MatchString(comm) || minerRe.MatchString(filepath.Base(firstArg(cmdline))) || stratumRe.MatchString(cmdline):
			miners = append(miners, label+" | "+trunc(cmdline, 120))
		case strings.HasPrefix(exe, "/tmp/") || strings.HasPrefix(exe, "/var/tmp/") || strings.HasPrefix(exe, "/dev/shm/"):
			tmp = append(tmp, label)
		case strings.HasSuffix(exe, " (deleted)"):
			deleted = append(deleted, label)
		}
	}

	var out []model.Finding
	if len(miners) > 0 {
		out = append(out, finding("PROC-MINER", model.SevCritical, "Process matches cryptominer indicators", "",
			"Kill it, find the persistence (cron, systemd, shell rc), rotate credentials.", miners...))
	}
	if len(tmp) > 0 {
		out = append(out, finding("PROC-TMP-EXEC", model.SevHigh, "Processes running from temp directories",
			"Legitimate software rarely runs from /tmp or /dev/shm.", "Inspect with `ls -l /proc/<pid>/exe` and `sudo ss -tupn`. Kill and remove if unknown.", tmp...))
	}
	if len(deleted) > 0 {
		out = append(out, finding("PROC-DELETED-BIN", model.SevLow, fmt.Sprintf("%d processes run a binary that was replaced on disk", len(deleted)),
			"Normal after updates: the old version is still in memory. Malware also deletes itself after launch, so verify the list.",
			"Restart those services or reboot. If a process is unfamiliar, investigate.", deleted...))
	}
	if !e.Root {
		out = append(out, finding("PROC-PARTIAL", model.SevInfo, "Process scan limited to your own processes", "", "Run with sudo for full coverage."))
	}
	return out, nil
}

// CheckHiddenPIDs compares /proc directory entries against kill(pid, 0) responses to uncover kernel/userland rootkits hiding PIDs.
func CheckHiddenPIDs(e *AuditEnv) ([]model.Finding, error) {
	maxPid := 4194304
	if b, err := os.ReadFile("/proc/sys/kernel/pid_max"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 && n < maxPid {
			maxPid = n
		}
	}
	visible := map[int]bool{}
	if ents, err := os.ReadDir("/proc"); err == nil {
		for _, en := range ents {
			if n, err := strconv.Atoi(en.Name()); err == nil {
				visible[n] = true
			}
		}
	}
	var cand []int
	for pid := 1; pid <= maxPid; pid++ {
		if pid&0xffff == 0 && e.Ctx.Err() != nil {
			return nil, e.Ctx.Err()
		}
		if visible[pid] {
			continue
		}
		if err := syscall.Kill(pid, 0); err == nil || err == syscall.EPERM {
			cand = append(cand, pid)
		}
	}
	time.Sleep(300 * time.Millisecond)
	var hidden []string
	for _, pid := range cand {
		if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); err == nil {
			continue
		}
		if syscall.Kill(pid, 0) == syscall.ESRCH {
			continue
		}
		hidden = append(hidden, "pid "+strconv.Itoa(pid)+" answers kill(0) but is absent from /proc")
	}
	if len(hidden) == 0 {
		return nil, nil
	}
	return []model.Finding{finding("PROC-HIDDEN-PID", model.SevCritical, fmt.Sprintf("%d processes are hidden from /proc", len(hidden)),
		"A process that exists but is invisible to ps/top is the signature of a kernel or userland rootkit (or hidepid in unusual setups).",
		"Treat the system as compromised: disconnect, capture memory/disk if needed, back up data only, reinstall from trusted media.", hidden...)}, nil
}

// CheckLynis invokes Lynis system auditing and parses warnings and hardening suggestions.
func CheckLynis(e *AuditEnv) ([]model.Finding, error) {
	if !runner.Have("lynis") {
		return nil, SkipError("lynis not installed (sudo pacman -S lynis)")
	}
	if _, _, _, err := runner.Run(e.Ctx, 15*time.Minute, "lynis", "audit", "system", "--quiet", "--no-colors"); err != nil {
		return nil, err
	}
	var warns, sugg []string
	idx := ""
	for _, l := range readLines("/var/log/lynis-report.dat") {
		switch {
		case strings.HasPrefix(l, "hardening_index="):
			idx = strings.TrimPrefix(l, "hardening_index=")
		case strings.HasPrefix(l, "warning[]="):
			f := strings.Split(strings.TrimPrefix(l, "warning[]="), "|")
			if len(f) >= 2 && f[0] != "KRNL-5830" && f[0] != "PKGS-7322" {
				warns = append(warns, f[0]+": "+f[1])
			}
		case strings.HasPrefix(l, "suggestion[]="):
			f := strings.Split(strings.TrimPrefix(l, "suggestion[]="), "|")
			if len(f) >= 2 {
				sugg = append(sugg, f[0]+": "+f[1])
			}
		}
	}
	var fs []model.Finding
	if len(warns) > 0 {
		fs = append(fs, finding("LYNIS-WARN", model.SevMedium, fmt.Sprintf("%d Lynis warnings", len(warns)), "",
			"Details: sudo lynis show details <ID>", warns...))
	}
	if len(sugg) > 0 {
		fs = append(fs, finding("LYNIS-SUGGEST", model.SevLow, fmt.Sprintf("%d Lynis hardening suggestions (index %s)", len(sugg), valOr(idx, "?")),
			"Many are server-oriented (auditd, separate /var, password aging) and optional on a desktop.",
			"Prioritise: sysctl, USB/firewire modules, umask, core dumps. Look up each with `lynis show details <ID>`.", sugg...))
	}
	return fs, nil
}

