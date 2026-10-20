// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sigmacheck

import (
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// auditdProcessFields are the Sysmon for Linux process creation fields
// auditd records too.
var auditdProcessFields = map[string]bool{
	"Image": true, "CommandLine": true, "ParentImage": true, "ParentCommandLine": true,
	"User": true, "LogonId": true, "CurrentDirectory": true, "ProcessId": true, "ParentProcessId": true,
}

// AuditdProcessRecords are a Sysmon for Linux process creation case's
// program start as auditd records it, as the agent sends them (tag
// linux.audit): the SYSCALL, EXECVE and CWD records of the start, after
// those of its parent's own start when the case names the parent. It is
// false when the case has a field auditd does not record (a hash, a
// process GUID).
func (c Case) AuditdProcessRecords(host string, t time.Time) ([]map[string]any, bool) {
	if !strings.EqualFold(c.Channel, LinuxSysmonChannel) || c.EventID != "1" {
		return nil, false
	}
	for k := range c.Data {
		if !auditdProcessFields[k] {
			return nil, false
		}
	}
	var records []map[string]any
	serial := 0
	start := func(pid, ppid int, image, cmd string, own bool) {
		serial++
		sys := map[string]string{"arch": "c000003e", "syscall": "59", "success": "yes", "exit": "0",
			"pid": strconv.Itoa(pid), "ppid": strconv.Itoa(ppid), "auid": "1000", "uid": "1000"}
		// auditd always records the program; a case that does not name
		// it ran another.
		exe := image
		if exe == "" {
			exe = "/opt/test/program"
		}
		sys["exe"], sys["comm"] = exe, baseNameOf(exe)
		if own {
			if u, ok := c.Data["User"]; ok {
				sys["UID"] = u
			}
			if id, ok := c.Data["LogonId"]; ok {
				sys["auid"] = id
			}
		}
		args := map[string]string{}
		if cmd == "" {
			cmd = exe
		}
		parts := []string{}
		if cmd != "" {
			parts = strings.Split(cmd, " ")
		}
		args["argc"] = strconv.Itoa(len(parts))
		for i, a := range parts {
			args["a"+strconv.Itoa(i)] = a
		}
		lines := []string{withSerial(ingest.AuditdLine("SYSCALL", t, sys), serial), withSerial(ingest.AuditdLine("EXECVE", t, args), serial)}
		if d, ok := c.Data["CurrentDirectory"]; ok && own {
			lines = append(lines, withSerial(ingest.AuditdLine("CWD", t, map[string]string{"cwd": d}), serial))
		}
		for _, l := range lines {
			records = append(records, ingest.AuditdRecordFor(l, host))
		}
	}
	pid, ppid := 101, 100
	if n, err := strconv.Atoi(c.Data["ProcessId"]); err == nil {
		pid = n
	}
	if n, err := strconv.Atoi(c.Data["ParentProcessId"]); err == nil {
		ppid = n
	}
	pi, pc := c.Data["ParentImage"], c.Data["ParentCommandLine"]
	if pi != "" || pc != "" {
		start(ppid, 1, pi, pc, false)
	}
	start(pid, ppid, c.Data["Image"], c.Data["CommandLine"], true)
	return records, true
}

// AuditdProcessStart is the Endpoint event the real parser joins from
// the case's AuditdProcessRecords.
func (c Case) AuditdProcessStart(host string, t time.Time) (ingest.Event, bool) {
	records, ok := c.AuditdProcessRecords(host, t)
	if !ok {
		return ingest.Event{}, false
	}
	events := make([]ingest.Event, len(records))
	for i, r := range records {
		events[i] = ingest.Normalize("linux.audit", r, t)
	}
	var tr ingest.ProcessTracker
	starts := tr.Starts(events)
	if len(starts) == 0 {
		return ingest.Event{}, false
	}
	return starts[len(starts)-1], true
}

// withSerial gives an audit record line another serial number.
func withSerial(line string, n int) string {
	return strings.Replace(line, ":4242):", ":"+strconv.Itoa(4242+n)+"):", 1)
}

func baseNameOf(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
