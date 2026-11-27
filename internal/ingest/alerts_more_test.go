// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"strings"
	"testing"
)

func TestWazuhMalwareBranches(t *testing.T) {
	// A trojaned file rootcheck names only in its log line, at a low
	// level: the file from the line, a signature of its own, and low.
	ev, ok := wazuhMalware(map[string]any{
		"rule":     map[string]any{"level": "2"},
		"full_log": "Trojaned version of file '/bin/ps' detected.",
	}, []string{"rootcheck"})
	if !ok {
		t.Fatal("a trojaned file was not malware")
	}
	expect(t, ev.Fields, map[string]any{"file_path": "/bin/ps", "signature": "Trojaned file", "severity": "low", "category": "trojan"})

	// freshclam's lines that are not a detection are not malware.
	if _, ok := wazuhMalware(map[string]any{"decoder": map[string]any{"name": "freshclam"},
		"full_log": "Oct 13 09:00:00 h freshclam[1]: ClamAV update process started"}, nil); ok {
		t.Error("a freshclam update is malware")
	}
	// Other alerts are not.
	if _, ok := wazuhMalware(map[string]any{"full_log": "x"}, []string{"syslog"}); ok {
		t.Error("a syslog alert is malware")
	}
}

func TestWazuhSCAResults(t *testing.T) {
	comp := map[string]any{}
	for i := 0; i < maxWazuhList+3; i++ {
		comp[strings.Repeat("k", i+1)] = "1.1"
	}
	ev := wazuhSCA(map[string]any{"data": map[string]any{"sca": map[string]any{"policy": "CIS",
		"check": map[string]any{"id": "1", "title": "t", "result": "passed", "compliance": comp}}}})
	if ev.Fields["result"] != "pass" {
		t.Errorf("result = %v", ev.Fields["result"])
	}
	if n := strings.Count(ev.Fields["reference"].(string), "; ") + 1; n != maxWazuhList {
		t.Errorf("kept %d references, want %d", n, maxWazuhList)
	}
}

func TestSuricataIndustrialEvents(t *testing.T) {
	// A Modbus response alone, by name, with an exception reply code.
	f := map[string]any{}
	eveIndustrial("modbus", map[string]any{"modbus": map[string]any{
		"response": map[string]any{"function_code": "ReadCoils", "function_raw": "129", "unit_id": "1"},
	}}, f)
	expect(t, f, map[string]any{"type": "response", "ot_function": "READ_COILS", "reason": "129", "ot_unit": "1"})

	// Error flags explain a failure when no exception does.
	f = map[string]any{}
	eveIndustrial("modbus", map[string]any{"modbus": map[string]any{
		"request": map[string]any{"function_raw": "3"}, "response": map[string]any{"error_flags": "data_value"},
	}}, f)
	expect(t, f, map[string]any{"type": "request", "reason": "data_value", "signature_id": "3"})

	// An EtherNet/IP response, by its command.
	f = map[string]any{}
	eveIndustrial("enip", map[string]any{"enip": map[string]any{
		"response": map[string]any{"command": "ListIdentity", "status": "success"},
	}}, f)
	expect(t, f, map[string]any{"type": "response", "ot_function": "LIST_IDENTITY"})
	if _, ok := f["reason"]; ok {
		t.Errorf("a successful reply has a reason: %v", f["reason"])
	}
}

func TestOTNames(t *testing.T) {
	if got := otFunctionName("profinet", "3"); got != "WRITE" {
		t.Errorf("profinet 3 = %q", got)
	}
	if got := otFunctionName("modbus", "0x83"); got == "" {
		t.Error("a Modbus exception code has no name")
	}
	if got := otFunctionName("other", "1"); got != "" {
		t.Errorf("an unknown protocol = %q", got)
	}
	long := strings.Repeat("Ab ", maxOTValue)
	if got := otName(long); len(got) > maxOTValue+1 {
		t.Errorf("otName kept %d bytes", len(got))
	}
	if !IsZeekIndustrial("modbus") || IsZeekIndustrial("conn") {
		t.Error("IsZeekIndustrial")
	}
}
