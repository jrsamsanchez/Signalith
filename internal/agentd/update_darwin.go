package agentd

import (
	"os"
	"os/exec"
	"syscall"
)

// startUpdater starts this program as the updater, in a session of its
// own: it restarts the agent's launchd service, which ends the service's
// processes, so it must not be one of them. On macOS the agent is not
// fenced in, so the updater needs no service of its own.
func (a *Agent) startUpdater() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "install-update")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
