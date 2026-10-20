// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package casereport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/findings"
)

func sampleReport(t *testing.T) *Report {
	t.Helper()
	now := time.Now().UTC()
	c := &cases.Case{ID: "CASE-1", Title: `Phish <script>alert(1)</script>`, Severity: "high", Status: "open", Created: now, Updated: now}
	if _, err := c.AddEntry(cases.Entry{Kind: cases.KindEvent, Event: map[string]any{"host": "web-01", "bytes": int64(9007199254740993), "at": now}}, "ana", now); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddEntry(cases.Entry{Kind: cases.KindNote, Text: "Called the user </pre> back"}, "ana", now); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddTasks([]string{"Reset the password"}, "ana", now); err != nil {
		t.Fatal(err)
	}
	f := &findings.Finding{ID: "f1", Title: "Suspicious sign-in", DetectionID: "d1", Urgency: "high", Status: "open", Created: now}
	r, err := New(c, []*findings.Finding{f}, []string{"gone"}, "ana", "https://siem.example", now)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReportVerifies(t *testing.T) {
	r := sampleReport(t)
	if len(r.SHA256) != 64 || len(r.Evidence) != 1 || !r.Evidence[0].Intact {
		t.Fatalf("report %+v", r)
	}
	js, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(js); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	page, err := r.HTML()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(page); err != nil {
		t.Fatalf("page: %v", err)
	}
	// Saved on Windows with CRLF line ends.
	if _, err := Verify(bytes.ReplaceAll(page, []byte("\n"), []byte("\r\n"))); err != nil {
		t.Fatalf("CRLF page: %v", err)
	}
}

func TestReportCatchesChanges(t *testing.T) {
	r := sampleReport(t)
	js, _ := r.JSON()
	var m map[string]any
	if err := json.Unmarshal(js, &m); err != nil {
		t.Fatal(err)
	}
	m["case"].(map[string]any)["severity"] = "low"
	changed, _ := json.Marshal(m)
	if _, err := Verify(changed); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Errorf("changed case: %v", err)
	}

	// Evidence changed with the report's hash taken again still fails.
	r2 := sampleReport(t)
	r2.Case.Entries[0].Event["host"] = "web-02"
	b, _ := r2.Canonical()
	r2.SHA256 = sha(b)
	js2, _ := r2.JSON()
	if _, err := Verify(js2); err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Errorf("changed evidence: %v", err)
	}

	page, _ := r.HTML()
	edited := bytes.Replace(page, []byte("<dd>High</dd>"), []byte("<dd>Low</dd>"), 1)
	if bytes.Equal(edited, page) {
		t.Fatal("the test's edit did not apply")
	}
	if _, err := Verify(edited); err == nil || !strings.Contains(err.Error(), "page") {
		t.Errorf("edited page: %v", err)
	}

	if _, err := Verify([]byte(`{"format":"other"}`)); err == nil {
		t.Error("another format verified")
	}
}

func TestReportPageIsInert(t *testing.T) {
	page, err := sampleReport(t).HTML()
	if err != nil {
		t.Fatal(err)
	}
	s := string(page)
	for _, bad := range []string{"<script", "</pre> back", "http://", "src="} {
		if strings.Contains(s, bad) {
			t.Errorf("page holds %q", bad)
		}
	}
	if !strings.Contains(s, "&lt;script&gt;") || !strings.Contains(s, "Reset the password") {
		t.Error("page is missing the case")
	}
	// A note cannot end the data block early: Extract still finds JSON.
	if !json.Valid(Extract(page)) {
		t.Error("the page's data is not JSON")
	}
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
