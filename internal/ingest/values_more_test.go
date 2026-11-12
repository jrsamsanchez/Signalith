// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestSensorValueHelpers(t *testing.T) {
	for d, want := range map[time.Duration]string{
		30 * time.Minute: "less than an hour", time.Hour: "1 hour", 5 * time.Hour: "5 hours",
		24 * time.Hour: "1 day", 72 * time.Hour: "3 days",
	} {
		if got := age(d); got != want {
			t.Errorf("age(%v) = %q, want %q", d, got, want)
		}
	}
	for s, want := range map[string]bool{"GET": true, "propfind": true, "": false, "G3T": false, strings.Repeat("A", 21): false} {
		if got := isHTTPMethod(s); got != want {
			t.Errorf("isHTTPMethod(%q) = %v", s, got)
		}
	}
	for s, want := range map[string]bool{"example.com": true, "a_b.example": true, "192.0.2.1": false, "nodot": false,
		"bad host.com": false, "": false, strings.Repeat("a.", 130): false} {
		if got := looksLikeHost(s); got != want {
			t.Errorf("looksLikeHost(%q) = %v", s, got)
		}
	}
	f := map[string]any{}
	setNum(f, "n", json.Number("3"))
	setNum(f, "nan", math.NaN())
	setNum(f, "inf", math.Inf(1))
	setNum(f, "text", "x")
	if f["n"] != int64(3) || len(f) != 1 {
		t.Errorf("setNum = %v", f)
	}
	if listFirst([]any{}) != nil || listFirst([]any{"a", "b"}) != "a" || listFirst("s") != "s" {
		t.Error("listFirst")
	}
	if got := sensorList("one"); !reflect.DeepEqual(got, []string{"one"}) {
		t.Errorf("sensorList(string) = %v", got)
	}
	if got := sensorList(""); got != nil {
		t.Errorf("sensorList(\"\") = %v", got)
	}
	if got := encodeRecord(map[string]any{"bad": func() {}}); got != "" {
		t.Errorf("encodeRecord of a func = %q", got)
	}
	f = map[string]any{"direction": "internal", "src": "10.0.0.1", "dest": "10.0.0.1"}
	setLocalHost(f)
	if f["local_host"] != "10.0.0.1" {
		t.Errorf("local_host of a host to itself = %v", f["local_host"])
	}
}

// Values cut to a length never end inside a character.
func TestCuttingKeepsCharacters(t *testing.T) {
	long := strings.Repeat("a", MaxValueLen-1) + "é" + "tail"
	got := CapValue(long)
	if !utf8.ValidString(got) || len(got) > MaxValueLen || !strings.HasSuffix(got, "a") {
		t.Errorf("CapValue cut %q... (%d bytes)", got[len(got)-3:], len(got))
	}
	if got := truncateUTF8("aé", 2); got != "a" {
		t.Errorf("truncateUTF8 = %q", got)
	}
	if got := capLen("aé", 2); got != "a" {
		t.Errorf("capLen = %q", got)
	}
	huge := strings.Repeat("x", MaxValueLen+10)
	if got := MalwareCategory(huge+"trojan", huge); got == "" {
		t.Error("MalwareCategory of long values = \"\"")
	}
	if ValidMalwareAction(MalwareThreat, "not-an-action") {
		t.Error("an unknown action is valid")
	}
}

func TestFieldKinds(t *testing.T) {
	for _, c := range []struct {
		kind byte
		v    any
		want bool
	}{
		{kindNumber, "12.5", true}, {kindNumber, "x", false}, {kindBool, "true", true}, {kindBool, "yes", false},
		{kindBool, int64(1), false}, {kindString, 3, true}, {kindNumber, true, false},
	} {
		if got := fits(c.kind, c.v); got != c.want {
			t.Errorf("fits(%d, %#v) = %v, want %v", c.kind, c.v, got, c.want)
		}
	}
	if typ, ok := FieldType("src"); !ok || typ == "" {
		t.Errorf("FieldType(src) = %q %v", typ, ok)
	}
	if _, ok := FieldType("no_such_field_here"); ok {
		t.Error("FieldType of an unknown field")
	}
}

func TestZeekSMBFileActions(t *testing.T) {
	for _, c := range []struct {
		r    map[string]any
		want map[string]any
	}{
		{map[string]any{"action": "SMB::FILE_OPEN", "path": `\\FS\Share`, "name": `dir\a.txt`},
			map[string]any{"action": "opened", "file_name": "a.txt", "file_path": `\\FS\Share\dir\a.txt`}},
		{map[string]any{"action": "SMB::FILE_ODD", "name": "b.txt"},
			map[string]any{"action": "file_odd", "file_path": "b.txt"}},
		{map[string]any{"action": "SMB::PIPE_OPEN", "path": `\\FS\IPC$`, "name": "samr"},
			map[string]any{"action": "opened", "pipe_name": "samr"}},
	} {
		f := map[string]any{}
		zeekSMBFiles(c.r, f)
		expect(t, f, c.want)
	}
}
