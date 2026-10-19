// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package agentd

import (
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// setProcAttr starts the collector without a console window.
func setProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

// askStop stops the collector. Windows has no polite signal for a
// process without a console; Fluent Bit keeps its buffer on disk, so
// nothing it already read is lost.
func askStop(p *os.Process) error { return p.Kill() }

// The job object the collectors run in. Windows ends every process in it
// when its last handle closes, which is when the agent exits, however it
// exits: a collector never outlives the agent, so a restarted agent never
// runs a second copy beside the first.
var (
	jobOnce sync.Once
	job     windows.Handle
	jobErr  error
)

func agentJob() (windows.Handle, error) {
	jobOnce.Do(func() {
		h, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			jobErr = err
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			windows.CloseHandle(h)
			jobErr = err
			return
		}
		job = h
	})
	return job, jobErr
}

// keepWithAgent puts the collector in the agent's job object.
func keepWithAgent(p *os.Process) error {
	j, err := agentJob()
	if err != nil {
		return err
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(p.Pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.AssignProcessToJobObject(j, h)
}
