// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAuditdProcessStarts(t *testing.T) {
	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	at := now.Add(-time.Minute).Unix()
	line := func(serial int, body string) map[string]any {
		typ, rest, _ := strings.Cut(body, " ")
		return map[string]any{"log": fmt.Sprintf("%s msg=audit(%d.100:%d): %s", typ, at, serial, rest), "hostname": "web1"}
	}
	// A shell started by sshd, then curl started by the shell: the
	// records of each start, as auditd writes them.
	shell := []map[string]any{
		line(10, "type=SYSCALL arch=c000003e syscall=59 success=yes exit=0 ppid=800 pid=900 auid=1000 uid=1000 comm=\"bash\" exe=\"/usr/bin/bash\" key=\"exec\"\x1dARCH=x86_64 SYSCALL=execve AUID=\"bob\" UID=\"bob\""),
		line(10, `type=EXECVE argc=1 a0="-bash"`),
		line(10, `type=CWD cwd="/home/bob"`),
		line(10, `type=PROCTITLE proctitle="-bash"`),
	}
	res, err := p.Ingest(context.Background(), "linux.audit", shell)
	if err != nil || res.Indexed != 5 {
		t.Fatalf("res %+v err %v", res, err)
	}
	// The next batch starts with curl's SYSCALL; its other records come in
	// the one after, as a batch cut between them would send them.
	if _, err := p.Ingest(context.Background(), "linux.audit", []map[string]any{
		line(11, "type=SYSCALL arch=c000003e syscall=59 success=yes exit=0 ppid=900 pid=901 auid=1000 uid=0 comm=\"curl\" exe=\"/usr/bin/curl\""),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Ingest(context.Background(), "linux.audit", []map[string]any{
		line(11, `type=EXECVE argc=3 a0="curl" a1="-s" a2=687474703A2F2F6578616D706C652E636F6D2F7820792E7368`),
		line(11, `type=CWD cwd="/tmp"`),
	}); err != nil {
		t.Fatal(err)
	}
	var starts []map[string]any
	for _, d := range fb.docs {
		if d.Doc["datamodel"] == "Endpoint" {
			starts = append(starts, d.Doc)
			if d.Index[:13] != "sig-endpoint-" {
				t.Errorf("index %s", d.Index)
			}
		}
	}
	if len(starts) != 2 || len(fb.docs) != 9 {
		t.Fatalf("%d starts of %d documents", len(starts), len(fb.docs))
	}
	expect(t, starts[0], map[string]any{
		"sourcetype": "linux:audit", "host": "web1", "dest": "web1", "signature_id": "EXECVE", "action": "allowed",
		"process": "-bash", "process_path": "/usr/bin/bash", "process_name": "bash", "process_id": int64(900),
		"parent_process_id": int64(800), "user": "bob", "auditd_auid_name": "bob", "process_current_directory": "/home/bob",
		"auditd_id": "10",
	})
	if _, ok := starts[0]["parent_process_path"]; ok {
		t.Errorf("sshd's start was never seen: %v", starts[0])
	}
	expect(t, starts[1], map[string]any{
		"process": "curl -s http://example.com/x y.sh", "process_path": "/usr/bin/curl", "process_name": "curl",
		"process_id": int64(901), "user": "root", "process_current_directory": "/tmp",
		"parent_process_id": int64(900), "parent_process_path": "/usr/bin/bash", "parent_process": "-bash",
		"parent_process_name": "bash", "parent_user": "bob",
	})
	// The records stay in Other, as auditd rules read them.
	for _, d := range fb.docs {
		if d.Doc["datamodel"] == "Other" && d.Doc["auditd_type"] == nil {
			t.Errorf("record %v", d.Doc)
		}
	}
}

func TestAuditdProcessStartIDs(t *testing.T) {
	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	body := fmt.Sprintf(`{"log": "type=EXECVE msg=audit(%d.000:7): argc=2 a0=\"/bin/sh\" a1=\"-i\"", "hostname": "web1"}`, now.Unix())
	// The same request sent twice stores each document under the same ID.
	for range 2 {
		if _, err := p.IngestBody(context.Background(), "linux.audit", []byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if len(fb.docs) != 4 || fb.docs[0].ID == "" || fb.docs[1].ID != fb.docs[0].ID+processStartSuffix ||
		fb.docs[2].ID != fb.docs[0].ID || fb.docs[3].ID != fb.docs[1].ID {
		t.Fatalf("docs %+v", fb.docs)
	}
	// Without a SYSCALL record, the program is the first argument.
	expect(t, fb.docs[1].Doc, map[string]any{"datamodel": "Endpoint", "process": "/bin/sh -i", "process_path": "/bin/sh", "process_name": "sh"})
	// A SYSCALL that is not a program start makes none.
	tr := &ProcessTracker{}
	ev := Normalize("linux.audit", AuditdRecordFor(fmt.Sprintf(`type=SYSCALL msg=audit(%d.000:8): arch=c000003e syscall=257 success=yes pid=5 exe="/usr/bin/cat"`, now.Unix()), "web1"), now)
	if isExecSyscall(ev.Fields) || len(tr.Starts([]Event{ev})) != 0 {
		t.Errorf("openat taken for a start")
	}
}
