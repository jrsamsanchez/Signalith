//go:build windows

package agentd

import (
	"os"
	"os/exec"
	"syscall"
)

// setProcAttr starts the collector without a console window.
func setProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

// askStop stops the collector. Windows has no polite signal for a
// process without a console; Fluent Bit keeps its buffer on disk, so
// nothing it already read is lost.
func askStop(p *os.Process) error { return p.Kill() }
