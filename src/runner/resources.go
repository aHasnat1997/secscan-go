package runner

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// SmartWorkers calculates an optimal worker count targeting ~55% CPU utilization
// across all logical cores while respecting available system RAM to prevent OOM
// or starving other running desktop/system processes.
func SmartWorkers(memPerWorkerMB int) int {
	cpus := runtime.NumCPU()
	if cpus < 1 {
		cpus = 1
	}

	// Target ~55% of logical CPU threads (rounded up, minimum 2 on multi-core).
	w := (cpus*55 + 99) / 100
	if cpus > 1 && w < 2 {
		w = 2
	}
	if w > cpus {
		w = cpus
	}

	if memPerWorkerMB > 0 {
		if availMB := availableMemoryMB(); availMB > 0 {
			// Always keep at least 2048 MB free for the OS and interactive apps.
			usableMB := availMB - 2048
			if usableMB < memPerWorkerMB {
				return 1
			}
			byRAM := usableMB / memPerWorkerMB
			if byRAM < w {
				w = byRAM
			}
		}
	}

	if w < 1 {
		return 1
	}
	return w
}

func availableMemoryMB() int {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "MemAvailable:") {
			f := strings.Fields(l)
			if len(f) >= 2 {
				if kb, err := strconv.Atoi(f[1]); err == nil {
					return kb / 1024
				}
			}
		}
	}
	return 0
}

// RunLowPrio executes a CPU/IO-intensive command at lowered scheduling priority (nice -n 10)
// so multi-core scans complete quickly without lagging or disrupting other running processes.
func RunLowPrio(ctx context.Context, timeout time.Duration, name string, args ...string) (stdout, stderr string, code int, err error) {
	if Have("nice") {
		niceArgs := append([]string{"-n", "10", name}, args...)
		return Run(ctx, timeout, "nice", niceArgs...)
	}
	return Run(ctx, timeout, name, args...)
}

