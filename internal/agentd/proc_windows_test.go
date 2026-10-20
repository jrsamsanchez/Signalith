// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package agentd

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The collectors' job object caps each one's memory (ASI-15), as the
// Linux service's MemoryMax does.
func TestAgentJobCapsCollectorMemory(t *testing.T) {
	j, err := agentJob()
	if err != nil {
		t.Fatal(err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := windows.QueryInformationJobObject(j, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
		t.Fatal(err)
	}
	if info.BasicLimitInformation.LimitFlags&windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY == 0 || info.ProcessMemoryLimit != collectorMemory {
		t.Errorf("limits = %#x, process memory = %d", info.BasicLimitInformation.LimitFlags, info.ProcessMemoryLimit)
	}
	if info.BasicLimitInformation.LimitFlags&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0 {
		t.Error("the job no longer ends the collectors with the agent")
	}
}
