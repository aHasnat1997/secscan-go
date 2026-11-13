package terminal

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// ReadPassword securely prompts the user for sensitive input (such as an archive password)
// by disabling terminal ECHO via POSIX termios ioctl, ensuring credentials are never exposed on screen.
func ReadPassword(prompt string) (string, error) {
	fmt.Print(prompt)

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		defer tty.Close()

		var termios syscall.Termios
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, tty.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&termios)))
		if errno == 0 {
			oldLflag := termios.Lflag
			termios.Lflag &^= syscall.ECHO
			_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, tty.Fd(), syscall.TCSETS, uintptr(unsafe.Pointer(&termios)))

			defer func() {
				termios.Lflag = oldLflag
				_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, tty.Fd(), syscall.TCSETS, uintptr(unsafe.Pointer(&termios)))
				fmt.Println()
			}()

			reader := bufio.NewReader(tty)
			line, err := reader.ReadString('\n')
			if err != nil {
				return "", err
			}
			return strings.TrimRight(line, "\r\n"), nil
		}
	}

	cmd := exec.Command("stty", "-echo")
	cmd.Stdin = os.Stdin
	_ = cmd.Run()

	defer func() {
		cmd = exec.Command("stty", "echo")
		cmd.Stdin = os.Stdin
		_ = cmd.Run()
		fmt.Println()
	}()

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

