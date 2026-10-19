// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package agentd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// openNoFollow opens a file for reading, refusing a symbolic link (the
// update folder is SYSTEM's and the administrators' only, so nothing
// else can leave one there).
func openNoFollow(path string) (*os.File, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a plain file", filepath.Base(path))
	}
	return os.Open(path)
}

// startUpdater starts a copy of this program as the updater, on its own:
// it stops this service, so it must not be part of it.
func (a *Agent) startUpdater() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	updater := filepath.Join(a.Paths.updateDir(), "signalith-agent-updater.exe")
	if err := copyFile(self, updater); err != nil {
		return err
	}
	cmd := exec.Command(updater, "install-update")
	// DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB
	// | CREATE_NO_WINDOW
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000008 | 0x00000200 | 0x01000000 | 0x08000000}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// WindowsService controls the agent's Windows service.
type WindowsService struct{ Name string }

func (s WindowsService) open() (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, err
	}
	sv, err := m.OpenService(s.Name)
	if err != nil {
		m.Disconnect()
		return nil, nil, err
	}
	return m, sv, nil
}

func (s WindowsService) Stop(ctx context.Context) error {
	m, sv, err := s.open()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer sv.Close()
	st, err := sv.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, err := sv.Control(svc.Stop); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		if st, err = sv.Query(); err == nil && st.State == svc.Stopped {
			return nil
		}
		if err := sleepCtx(ctx, 500*time.Millisecond); err != nil {
			return err
		}
	}
	return errors.New("the service did not stop within a minute")
}

func (s WindowsService) Restart(ctx context.Context) error {
	if err := s.Stop(ctx); err != nil {
		return err
	}
	m, sv, err := s.open()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer sv.Close()
	return sv.Start()
}

func (s WindowsService) State(context.Context) (bool, string, error) {
	m, sv, err := s.open()
	if err != nil {
		return false, "", err
	}
	defer m.Disconnect()
	defer sv.Close()
	st, err := sv.Query()
	if err != nil {
		return false, "", err
	}
	return st.State == svc.Running, strconv.FormatUint(uint64(st.ProcessId), 10), nil
}
