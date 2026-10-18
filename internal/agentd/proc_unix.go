//go:build !windows

package agentd

import (
	"os"
	"os/exec"
	"syscall"
)

// setProcAttr starts the collector in a process group of its own, so a
// signal to the agent's terminal does not reach it directly.
func setProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// askStop asks the collector to stop: Fluent Bit flushes what it holds on
// SIGTERM.
func askStop(p *os.Process) error { return p.Signal(syscall.SIGTERM) }
