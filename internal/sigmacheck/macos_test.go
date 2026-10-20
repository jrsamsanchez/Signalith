// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sigmacheck

import (
	"testing"
	"time"
)

// A macOS case goes through the real osquery result parser, and its Sigma
// view is the row's columns by Sigma's names.
func TestMacOSCases(t *testing.T) {
	syn := &Synthesis{
		Positive: []map[string]string{{"Image": "/usr/bin/security", "CommandLine": "security dump-keychain -d", "ParentImage": "/bin/bash"}},
		Negative: []map[string]string{{"CommandLine": "security list-keychains"}, {"Hashes": "MD5=00"}},
	}
	cs := MacOSCases("process_creation", syn, nil)
	if len(cs) != 2 {
		t.Fatalf("cases = %+v (a field osquery lacks drops the event)", cs)
	}
	pos, neg := cs[0], cs[1]
	view, ok := pos.SigmaView()
	if !ok || view["Image"] != "/usr/bin/security" || view["ParentCommandLine"] != "/bin/bash" {
		t.Errorf("view = %v", view)
	}
	ev := pos.Stored("mbp", time.Unix(1_800_000_000, 0))
	if ev.Model != "Endpoint" || ev.Fields["process"] != "security dump-keychain -d" || ev.Fields["parent_process_name"] != "bash" ||
		ev.Fields["sourcetype"] != MacOSChannel || ev.Fields["host"] != "mbp" {
		t.Errorf("stored = %s %+v", ev.Model, ev.Fields)
	}
	// A program the event leaves open is a typical one.
	if neg.Data["path"] != MacOSBases["process_creation"]["Image"] || neg.Data["cmdline"] != "security list-keychains" {
		t.Errorf("negative = %v", neg.Data)
	}
	if tag, rec := pos.Record("mbp", time.Unix(1_800_000_000, 0)); tag != OsqueryTag || rec["name"] == nil {
		t.Errorf("record = %s %v", tag, rec)
	}
	if MacOSCases("file_event", syn, nil) != nil {
		t.Error("only program starts")
	}
}
