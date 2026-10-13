//go:build unix

package respond

import (
	"os/exec"
	"syscall"
)

// setProcessGroup starts the program in a process group of its own, and
// stops the whole group when it runs out of time, so programs it started
// stop with it.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
