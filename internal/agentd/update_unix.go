//go:build !windows

package agentd

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// openNoFollow opens a file for reading, refusing a symbolic link.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

// startUpdater does nothing here: a path unit starts the updater's
// service when the agent writes the ready file.
func (a *Agent) startUpdater() error { return nil }

// SystemdService controls the agent's systemd service.
type SystemdService struct {
	Unit string
	// Show asks systemd about the unit; nil runs systemctl.
	Show UnitState
}

// Stop does nothing: the program can be replaced while it runs, and the
// restart starts the new one.
func (s SystemdService) Stop(context.Context) error { return nil }

func (s SystemdService) Restart(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", "restart", s.Unit).Run()
}

func (s SystemdService) State(ctx context.Context) (bool, string, error) {
	show := s.Show
	if show == nil {
		show = systemctlShow
	}
	m, err := show(ctx, s.Unit)
	if err != nil {
		return false, "", err
	}
	return m["ActiveState"] == "active", m["NRestarts"], nil
}
