package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Run executes an external command with a strict timeout without spawning a shell,
// preventing shell injection and enforcing consistent C locale parsing.
func Run(ctx context.Context, timeout time.Duration, name string, args ...string) (stdout, stderr string, code int, err error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, name, args...)
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	cmd.Env = append(os.Environ(), "LC_ALL=C")

	err = cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
			err = nil
		} else {
			code = -1
		}
	}

	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("%s timed out after %s", name, timeout)
	}

	return outb.String(), errb.String(), code, err
}

// Have returns true if the specified executable is discoverable in system PATH.
func Have(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

