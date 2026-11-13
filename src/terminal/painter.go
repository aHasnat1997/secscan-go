package terminal

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"security-go-scanner/src/model"
)

// Painter provides methods for styling text with ANSI escape codes when color is enabled.
type Painter struct {
	On bool
}

// NewPainter creates a Painter.
func NewPainter(enabled bool) Painter {
	return Painter{On: enabled}
}

// Color wraps text with an ANSI escape sequence.
func (p Painter) Color(code, s string) string {
	if !p.On {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// Bold returns bolded text.
func (p Painter) Bold(s string) string { return p.Color("1", s) }

// Dim returns faint text.
func (p Painter) Dim(s string) string { return p.Color("2", s) }

// Red returns red text.
func (p Painter) Red(s string) string { return p.Color("31", s) }

// Green returns green text.
func (p Painter) Green(s string) string { return p.Color("32", s) }

// Yellow returns yellow text.
func (p Painter) Yellow(s string) string { return p.Color("33", s) }

// Cyan returns cyan text.
func (p Painter) Cyan(s string) string { return p.Color("36", s) }

// Gray returns gray text.
func (p Painter) Gray(s string) string { return p.Color("90", s) }

// Severity returns a colorized, fixed-width badge for a severity level.
func (p Painter) Severity(s model.Severity) string {
	codes := []string{"90", "36", "33", "31", "1;97;41"}
	idx := int(s)
	code := "90"
	if idx >= 0 && idx < len(codes) {
		code = codes[idx]
	}
	return p.Color(code, fmt.Sprintf("%-8s", s.String()))
}

// IsTTY checks if a given file descriptor points to an interactive terminal device.
func IsTTY(f *os.File) bool {
	if f == nil {
		return false
	}
	var termios syscall.Termios
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&termios)))
	return err == 0
}

