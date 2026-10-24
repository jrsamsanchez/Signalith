// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package casefiles

import (
	"strings"
	"testing"
	"time"
)

func TestCleanName(t *testing.T) {
	for in, want := range map[string]string{
		"report.pdf":                       "report.pdf",
		`C:\Users\ana\Desktop\mail.eml`:    "mail.eml",
		"../../etc/passwd":                 "passwd",
		"invoice\u202Efdp.exe":             "invoicefdp.exe",
		"a\x00b\nc\".txt":                  "abc.txt",
		"":                                 "file",
		"..":                               "file",
		"  spaced name.png  ":              "spaced name.png",
		strings.Repeat("é", MaxNameLen+20): strings.Repeat("é", MaxNameLen),
	} {
		if got := CleanName(in); got != want {
			t.Errorf("CleanName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewAndMatches(t *testing.T) {
	data := []byte("<html><script>alert(1)</script></html>")
	f := New("CASE-1", "x.html", data, "ana", time.Now())
	if !ValidID(f.ID) || f.Size != int64(len(data)) || len(f.SHA256) != 64 || !strings.HasPrefix(f.ContentType, "text/html") {
		t.Fatalf("file %+v", f)
	}
	if !f.Matches(data) || f.Matches([]byte("other")) {
		t.Error("Matches")
	}
	if ValidID("ABCDEF0123456789") || ValidID("../x") || ValidID("") {
		t.Error("ValidID took a bad ID")
	}
}

func TestMemory(t *testing.T) {
	m := NewMemory()
	f := New("CASE-1", "a.txt", []byte("hello"), "ana", time.Now())
	if err := m.Put(t.Context(), f, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Get(t.Context(), "CASE-2", f.ID); err != ErrNotFound {
		t.Errorf("another case's file: %v", err)
	}
	got, data, err := m.Get(t.Context(), "CASE-1", f.ID)
	if err != nil || string(data) != "hello" || got.Name != "a.txt" {
		t.Fatalf("get: %+v %q %v", got, data, err)
	}
	m.Delete(t.Context(), "CASE-2", f.ID)
	if _, _, err := m.Get(t.Context(), "CASE-1", f.ID); err != nil {
		t.Error("a delete for another case removed the file")
	}
	m.Delete(t.Context(), "CASE-1", f.ID)
	if _, _, err := m.Get(t.Context(), "CASE-1", f.ID); err != ErrNotFound {
		t.Errorf("after delete: %v", err)
	}
}
