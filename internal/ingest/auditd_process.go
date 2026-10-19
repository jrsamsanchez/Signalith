// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"strings"
	"sync"
)

// A program start on Linux, as auditd records it, is several records that
// share one serial number (auditd_id), written one after another:
//
//	type=SYSCALL ... syscall=59 success=yes ppid=812 pid=9001 auid=1000 uid=0 comm="curl" exe="/usr/bin/curl"
//	type=EXECVE  ... argc=3 a0="curl" a1="-s" a2="http://example.com/x.sh"
//	type=CWD     ... cwd="/tmp"
//	type=PATH    ... name="/usr/bin/curl"
//	type=PROCTITLE ... proctitle=6375726C...
//
// Each record stays one event in Other, as the auditd rules read them. The
// records of each start are also joined into one Endpoint event (a
// process launch), with the fields Splunk's add-on for Linux gives it:
// process (the command line), process_name, process_path, process_id,
// parent_process_id, user, dest and process_current_directory, and the
// parent's path and command line when its own start was recorded.

// ProcessStartModel is the data model of the program starts joined from
// audit records.
const ProcessStartModel = "Endpoint"

// ProcessStartSignatureID is the signature_id of the program starts
// joined from audit records.
const ProcessStartSignatureID = "EXECVE"

// processStartSuffix ends the document ID of the program start joined
// from an EXECVE record whose own event has an ID, so a resent batch
// stores it once.
const processStartSuffix = "-process"

// maxTracked caps each of a ProcessTracker's two tables, per generation.
const maxTracked = 32768

// execSyscalls are the system call numbers of execve and execveat, by
// the arch field of a SYSCALL record (auditd's AUDIT_ARCH_* in hex).
var execSyscalls = map[string][]string{
	"c000003e": {"59", "322"},  // x86_64
	"40000003": {"11", "358"},  // i386
	"c00000b7": {"221", "281"}, // aarch64
	"40000028": {"11", "387"},  // arm
}

// ProcessTracker joins the audit records of each program start into an
// Endpoint event. It remembers, per host, the starts it saw, so a
// process's parent path and command line come from the parent's own
// start, and the SYSCALL record of a start whose other records came in
// the next batch. The zero value is ready to use; it is safe for
// concurrent use.
type ProcessTracker struct {
	mu       sync.Mutex
	syscalls generations[string, map[string]any]
	procs    generations[string, procInfo]
}

// procInfo is what a process's children name as their parent.
type procInfo struct {
	path, command, name, user string
}

// generations is a map that keeps about the last max entries put in it:
// when the current one fills, it becomes the old one, and the one before
// is dropped.
type generations[K comparable, V any] struct {
	cur, old map[K]V
}

func (g *generations[K, V]) get(k K) (V, bool) {
	if v, ok := g.cur[k]; ok {
		return v, true
	}
	v, ok := g.old[k]
	return v, ok
}

func (g *generations[K, V]) put(k K, v V) {
	if g.cur == nil {
		g.cur = map[K]V{}
	}
	if len(g.cur) >= maxTracked {
		g.old, g.cur = g.cur, map[K]V{}
	}
	g.cur[k] = v
}

// auditKey names a record's program start: its host and serial number.
func auditKey(f map[string]any) string {
	return str(f, "host") + "\x00" + str(f, "auditd_id")
}

func isAuditRecord(ev *Event, typ string) bool {
	return ev.Model == "Other" && ev.Fields["sourcetype"] == AuditdSourcetype && ev.Fields["auditd_type"] == typ
}

// isExecSyscall reports whether a SYSCALL record's call starts a program.
func isExecSyscall(f map[string]any) bool {
	call := str(f, "auditd_syscall")
	if n := str(f, "auditd_syscall_name"); n != "" {
		call = n
	}
	if call == "execve" || call == "execveat" {
		return true
	}
	for _, n := range execSyscalls[strings.ToLower(str(f, "auditd_arch"))] {
		if call == n {
			return true
		}
	}
	return false
}

// Starts returns the Endpoint event of each program start among events:
// one for each EXECVE record, joined with the SYSCALL, CWD and PROCTITLE
// records of its start.
func (t *ProcessTracker) Starts(events []Event) []Event {
	var execs []int
	others := map[string]map[string]map[string]any{} // type, key: fields
	for i := range events {
		ev := &events[i]
		if ev.Model != "Other" || ev.Fields["sourcetype"] != AuditdSourcetype {
			continue
		}
		switch typ := str(ev.Fields, "auditd_type"); typ {
		case "EXECVE":
			execs = append(execs, i)
		case "SYSCALL", "CWD", "PROCTITLE":
			if typ == "SYSCALL" && !isExecSyscall(ev.Fields) {
				continue
			}
			if others[typ] == nil {
				others[typ] = map[string]map[string]any{}
			}
			others[typ][auditKey(ev.Fields)] = ev.Fields
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// A start's SYSCALL record may come at the end of one batch and its
	// EXECVE at the start of the next.
	for k, f := range others["SYSCALL"] {
		t.syscalls.put(k, f)
	}
	if len(execs) == 0 {
		return nil
	}
	out := make([]Event, 0, len(execs))
	for _, i := range execs {
		ev := &events[i]
		k := auditKey(ev.Fields)
		sys, ok := others["SYSCALL"][k]
		if !ok {
			sys, _ = t.syscalls.get(k)
		}
		start := processStart(ev, sys, others["CWD"][k], others["PROCTITLE"][k])
		f := start.Fields
		host := str(f, "host")
		if ppid := str(f, "parent_process_id"); ppid != "" {
			if p, ok := t.procs.get(host + "\x00" + ppid); ok {
				setNonEmpty(f, "parent_process_path", p.path)
				setNonEmpty(f, "parent_process", p.command)
				setNonEmpty(f, "parent_process_name", p.name)
				setNonEmpty(f, "parent_user", p.user)
			}
		}
		if pid := str(f, "process_id"); pid != "" {
			t.procs.put(host+"\x00"+pid, procInfo{path: str(f, "process_path"), command: str(f, "process"), name: str(f, "process_name"), user: str(f, "user")})
		}
		out = append(out, start)
	}
	return out
}

func setNonEmpty(f map[string]any, k, v string) {
	if v != "" {
		f[k] = v
	}
}

// processStart is the Endpoint event of the program start whose EXECVE
// record is execve, with its SYSCALL, CWD and PROCTITLE records' fields
// when there are any (nil when not).
func processStart(execve *Event, sys, cwd, title map[string]any) Event {
	e := execve.Fields
	host := str(e, "host")
	f := map[string]any{
		"host":           host,
		"dest":           host,
		"sourcetype":     AuditdSourcetype,
		"vendor_product": AuditdProduct,
		"app":            "auditd",
		"signature":      "Process started",
		"signature_id":   ProcessStartSignatureID,
		"auditd_id":      e["auditd_id"],
		"action":         "allowed",
		"message":        e["message"],
	}
	// The command line: the program's arguments, as auditd recorded
	// them. PROCTITLE has the same, cut to 128 bytes, when EXECVE has
	// none.
	cmd := str(e, "auditd_execve_command")
	if cmd == "" && title != nil {
		cmd = str(title, "auditd_proctitle")
	}
	setNonEmpty(f, "process", cmd)
	a0 := str(e, "auditd_a0")
	if sys != nil {
		if exe := str(sys, "auditd_exe"); exe != "" && exe != "(null)" {
			f["process_path"] = exe
			f["process_name"] = baseName(exe)
		} else {
			setNonEmpty(f, "process_name", str(sys, "auditd_comm"))
		}
		for field, from := range map[string]string{"process_id": "auditd_pid", "parent_process_id": "auditd_ppid"} {
			if n, ok := atoi(str(sys, from)).(int64); ok {
				f[field] = n
			}
		}
		setNonEmpty(f, "user", processUser(sys))
		// The login session's user ID, as Sysmon for Linux gives it.
		if auid := str(sys, "auditd_auid"); atoi(auid) != nil {
			f["logon_id"] = auid
		}
		if str(sys, "auditd_success") == "no" {
			f["action"] = "blocked"
		}
		// The record's own user fields, among them the account logged in
		// (auid), which stays the same through sudo and su.
		for _, k := range []string{"auditd_auid", "auditd_auid_name", "auditd_uid", "auditd_uid_name", "auditd_ses", "auditd_tty", "auditd_key"} {
			if v, ok := sys[k]; ok {
				f[k] = v
			}
		}
	}
	if f["process_path"] == nil && strings.HasPrefix(a0, "/") {
		f["process_path"] = a0
	}
	if f["process_name"] == nil && a0 != "" {
		f["process_name"] = baseName(a0)
	}
	if cwd != nil {
		setNonEmpty(f, "process_current_directory", str(cwd, "auditd_cwd"))
	}
	ev := Event{Time: execve.Time, Model: ProcessStartModel, Fields: f, Origin: execve.Origin}
	if execve.ID != "" {
		ev.ID = execve.ID + processStartSuffix
	}
	return ev
}

// processUser is the account a process runs as: the name of its user ID
// (an ENRICHED record has it, and ausearch -i writes it in place of the
// number), else the number; 0 is always root.
func processUser(sys map[string]any) string {
	if n := str(sys, "auditd_uid_name"); n != "" {
		return n
	}
	uid := str(sys, "auditd_uid")
	if uid == "0" {
		return "root"
	}
	return uid
}
