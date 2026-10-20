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

// collectorMemory is the most memory each collector may commit, as the
// Linux service's MemoryMax.
const collectorMemory = 512 << 20

func agentJob() (windows.Handle, error) {
	jobOnce.Do(func() {
		h, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			jobErr = err
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
		// Each collector may commit at most collectorMemory: a fault
		// then stops it, and the agent starts it again, rather than
		// take the computer's memory.
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
		info.ProcessMemoryLimit = collectorMemory
		if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			windows.CloseHandle(h)
			jobErr = err
			return
		}
		job = h
		watchMemory(h)
	})
	return job, jobErr
}

// memoryHit holds the IDs of the collectors Windows told the agent
// reached collectorMemory, until they exit.
var memoryHit sync.Map

// jobMsgProcessMemoryLimit is JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT.
const jobMsgProcessMemoryLimit = 9

// watchMemory asks Windows to say when a collector in job h reaches
// collectorMemory, so a collector stopped by it does not look like a
// crash. Without it the limit still holds; only the reason is missing.
func watchMemory(h windows.Handle) {
	port, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		return
	}
	assoc := struct {
		CompletionKey  uintptr
		CompletionPort windows.Handle
	}{0, port}
	if _, err := windows.SetInformationJobObject(h, windows.JobObjectAssociateCompletionPortInformation,
		uintptr(unsafe.Pointer(&assoc)), uint32(unsafe.Sizeof(assoc))); err != nil {
		windows.CloseHandle(port)
		return
	}
	go func() {
		for {
			var msg uint32
			var key uintptr
			var ov *windows.Overlapped
			if err := windows.GetQueuedCompletionStatus(port, &msg, &key, &ov, windows.INFINITE); err != nil {
				return
			}
			if msg == jobMsgProcessMemoryLimit {
				// The message's "overlapped" is the process ID.
				memoryHit.Store(uint32(uintptr(unsafe.Pointer(ov))), true)
			}
		}
	}()
}

// memoryHint says why the collector pid stopped when it reached its
// memory limit; "" otherwise.
func memoryHint(pid int) string {
	if _, hit := memoryHit.LoadAndDelete(uint32(pid)); hit {
		return "it reached the 512 MB of memory the agent allows each collector"
	}
	return ""
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
