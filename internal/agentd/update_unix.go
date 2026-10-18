//go:build !windows

package agentd

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

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

// LaunchdService controls the agent's launchd service on macOS.
type LaunchdService struct {
	Label string
	// Print asks launchd about the service (launchctl print); nil runs
	// launchctl.
	Print func(ctx context.Context, target string) (string, error)
}

func (s LaunchdService) target() string { return "system/" + s.Label }

// Stop does nothing: the program can be replaced while it runs, and the
// restart starts the new one.
func (s LaunchdService) Stop(context.Context) error { return nil }

func (s LaunchdService) Restart(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return exec.CommandContext(ctx, "/bin/launchctl", "kickstart", "-k", s.target()).Run()
}

func (s LaunchdService) State(ctx context.Context) (bool, string, error) {
	show := s.Print
	if show == nil {
		show = launchctlPrint
	}
	out, err := show(ctx, s.target())
	if err != nil {
		return false, "", err
	}
	state, pid := launchdState(out)
	if state == "" {
		return false, "", errors.New("launchctl print says nothing of the service's state")
	}
	return state == "running", pid, nil
}

func launchctlPrint(ctx context.Context, target string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/launchctl", "print", target).Output()
	return string(out), err
}

// launchdState reads the service's own state and process ID from
// launchctl print, which indents the service's lines by one tab and
// those of what it holds by more.
func launchdState(out string) (state, pid string) {
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "\t\t") {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if !ok {
			continue
		}
		switch k {
		case "state":
			if state == "" {
				state = v
			}
		case "pid":
			if pid == "" {
				pid = v
			}
		}
	}
	return state, pid
}
