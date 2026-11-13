package codescan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"security-go-scanner/src/model"
	"security-go-scanner/src/runner"
)

// RunInDocker executes the codebase scanner inside a strictly isolated, non-networked,
// read-only container by bind-mounting the static secscan Go binary itself.
// Zero external scripts or interpreters (e.g. Python) are required inside the container.
func RunInDocker(ctx context.Context, targetAbs string, isZip bool, password string, minSev model.Severity) (*model.CodeScanReport, error) {
	if !runner.Have("docker") {
		return nil, fmt.Errorf("docker command not found. Docker is the default isolation engine.\nInstall Docker or run natively without Docker: secscan code-scan --no-docker %s", targetAbs)
	}

	_, _, code, err := runner.Run(ctx, 10*time.Second, "docker", "info")
	if err != nil || code != 0 {
		return nil, fmt.Errorf("docker daemon is not running or accessible.\nStart Docker or run natively without Docker: secscan code-scan --no-docker %s", targetAbs)
	}

	selfExe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to locate secscan binary: %w", err)
	}
	selfAbs, err := filepath.EvalSymlinks(selfExe)
	if err != nil {
		selfAbs = selfExe
	}

	const containerImage = "alpine:latest"
	runID := fmt.Sprintf("%d-%d", time.Now().Unix(), os.Getpid())
	cname := fmt.Sprintf("secscan-box-%s", runID)

	// Ensure container cleanup even if interrupted.
	defer func() {
		_, _, _, _ = runner.Run(context.Background(), 10*time.Second, "docker", "rm", "-f", "-v", cname)
	}()

	uid := os.Getuid()
	gid := os.Getgid()
	if uid == 0 {
		uid = 65534 // nobody
		gid = 65534
	}

	mountArg := fmt.Sprintf("%s:/target:ro", targetAbs)
	targetContainerPath := "/target"
	if isZip {
		mountArg = fmt.Sprintf("%s:/target/%s:ro", targetAbs, filepath.Base(targetAbs))
		targetContainerPath = "/target/" + filepath.Base(targetAbs)
	}

	dockerArgs := []string{
		"run", "--rm", "--name", cname, "--label", "secscan.run=" + runID,
		"--network", "none",
		"--ipc", "none",
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", "128",
		"--memory", "512m",
		"--cpus", "1",
		"--user", fmt.Sprintf("%d:%d", uid, gid),
		"-v", mountArg,
		"-v", fmt.Sprintf("%s:/usr/local/bin/secscan:ro", selfAbs),
	}

	// Pass sensitive zip password via environment variable rather than process CLI arguments.
	if password != "" {
		dockerArgs = append(dockerArgs, "-e", "SECSCAN_ZIP_PASSWORD="+password)
	}

	dockerArgs = append(dockerArgs,
		"--entrypoint", "/usr/local/bin/secscan",
		containerImage,
		"code-scan", "--no-docker", "--format", "json",
		"--min-severity", strings.ToLower(minSev.String()),
		targetContainerPath,
	)

	stdout, stderr, exitCode, err := runner.Run(ctx, 10*time.Minute, "docker", dockerArgs...)
	if err != nil {
		return nil, fmt.Errorf("docker run error: %w (%s)", err, stderr)
	}
	if exitCode != 0 && exitCode != 1 {
		return nil, fmt.Errorf("scanner inside container exited %d: %s", exitCode, stderr)
	}

	var rep model.CodeScanReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		if exitCode != 0 {
			return nil, fmt.Errorf("scanner inside container exited %d: %s", exitCode, stderr)
		}
		return nil, fmt.Errorf("failed to parse scanner JSON: %w (output was: %s)", err, stdout)
	}

	rep.Scanner = "secscan code-scan (isolated docker container: --network none, read-only, pure Go)"
	rep.Target = targetAbs

	return &rep, nil
}

