// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"reflect"
	"testing"
)

func TestOTLPSeverityNames(t *testing.T) {
	for n, want := range map[int64]string{0: "", 1: "TRACE", 4: "TRACE", 5: "DEBUG", 9: "INFO", 13: "WARN", 17: "ERROR", 21: "FATAL", 24: "FATAL", 25: "", -1: ""} {
		if got := otlpSeverityName(n); got != want {
			t.Errorf("otlpSeverityName(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestValueBytes(t *testing.T) {
	for _, c := range []struct {
		v    any
		want int
	}{
		{"abc", 3},
		{[]string{"a", "bc"}, 1 + 3 + 2 + 3},
		{[]any{"a", 5}, 1 + 3 + 8 + 3},
		{map[string]any{"k": "vv"}, 1 + 2 + 6},
		{map[string]string{"k": "vv", "kk": "v"}, (1 + 2 + 6) + (2 + 1 + 6)},
		{42, 8},
	} {
		if got := valueBytes(c.v); got != c.want {
			t.Errorf("valueBytes(%#v) = %d, want %d", c.v, got, c.want)
		}
	}
}

func TestHECTags(t *testing.T) {
	for st, want := range map[string]string{
		"aws:cloudtrail": CloudTrailTag, "o365:management:activity": O365Tag, "ms:o365:management": O365Tag,
		"okta": OktaTag, "okta:im2": OktaTag, "google:gcp:pubsub:message": GCPTag, "gcp:audit": GCPTag,
		"azure:monitor:aad": AzureTag, "mscs:azure:eventhub": AzureTag, "github:audit": GitHubTag, "syslog": "hec",
	} {
		if got := hecTag(st); got != want {
			t.Errorf("hecTag(%q) = %q, want %q", st, got, want)
		}
	}
	e := &HECError{Text: "Invalid data format"}
	if e.Error() != "Invalid data format" {
		t.Errorf("HECError = %q", e.Error())
	}
}

func TestAuditdFieldNames(t *testing.T) {
	for _, c := range []struct {
		name, want string
		ok         bool
	}{
		{"exe", "auditd_exe", true}, {"UID", "auditd_uid_name", true}, {"Uid", "", false}, {"bad name", "", false},
	} {
		if got, ok := AuditdField(c.name); got != c.want || ok != c.ok {
			t.Errorf("AuditdField(%q) = %q %v, want %q %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestWazuhHelpers(t *testing.T) {
	for level, want := range map[int64]string{0: "informational", 3: "informational", 5: "low", 6: "low"} {
		if got := wazuhSeverity(level); got != want {
			t.Errorf("wazuhSeverity(%d) = %q, want %q", level, got, want)
		}
	}
	for _, c := range []struct {
		v  any
		n  int64
		ok bool
	}{
		{"12", 12, true}, {"12.0", 12, true}, {"1.5", 0, false}, {"", 0, false}, {"x", 0, false}, {"1e20", 0, false},
	} {
		if n, ok := wint(c.v); n != c.n || ok != c.ok {
			t.Errorf("wint(%#v) = %d %v, want %d %v", c.v, n, ok, c.n, c.ok)
		}
	}
	if got := wlist([]string{"a", "", "b"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("wlist([]string) = %v", got)
	}
	long := make([]string, maxWazuhList+5)
	for i := range long {
		long[i] = "x"
	}
	if got := wlist(long); len(got) != maxWazuhList {
		t.Errorf("wlist kept %d, want %d", len(got), maxWazuhList)
	}
	if got := wlist("one"); !reflect.DeepEqual(got, []string{"one"}) {
		t.Errorf("wlist(string) = %v", got)
	}
}
