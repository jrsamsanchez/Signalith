// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import "testing"

// A program start whose EXECVE record has no command line takes
// PROCTITLE's; one whose SYSCALL has no program path takes its comm; a
// start that failed is blocked; a user ID without a name stays a number.
func TestProcessStartFallbacks(t *testing.T) {
	execve := &Event{Time: now, Fields: map[string]any{"host": "web1", "auditd_id": "1:2", "auditd_a0": "ls"}}
	sys := map[string]any{"auditd_exe": "(null)", "auditd_comm": "ls", "auditd_pid": "42",
		"auditd_success": "no", "auditd_uid": "1001", "auditd_auid": "1001"}
	title := map[string]any{"auditd_proctitle": "ls -la /tmp"}
	ev := processStart(execve, sys, nil, title)
	expect(t, ev.Fields, map[string]any{
		"process":      "ls -la /tmp",
		"process_name": "ls",
		"process_id":   int64(42),
		"action":       "blocked",
		"user":         "1001",
		"logon_id":     "1001",
	})
	if _, ok := ev.Fields["process_path"]; ok {
		t.Errorf("a relative a0 became a path: %v", ev.Fields["process_path"])
	}
	if processUser(map[string]any{"auditd_uid": "0"}) != "root" {
		t.Error("uid 0 is not root")
	}
}
