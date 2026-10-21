// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package casereport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/reportkeys"
)

func sampleReport(t *testing.T) *Report {
	t.Helper()
	now := time.Now().UTC()
	c := &cases.Case{ID: "CASE-1", Title: `Phish <script>alert(1)</script>`, Severity: "high", Status: "open", Created: now, Updated: now}
	if _, err := c.AddEntry(cases.Entry{Kind: cases.KindEvent, Event: map[string]any{"host": "web-01", "bytes": int64(9007199254740993), "at": now}}, "ana", now); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddEntry(cases.Entry{Kind: cases.KindNote, Text: "Called the user </pre> <pre id=\"report-data\">{} back\r\nfrom Windows"}, "ana", now); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddTasks([]string{"Reset the password"}, "ana", now); err != nil {
		t.Fatal(err)
	}
	f := &findings.Finding{ID: "f1", Title: "Suspicious sign-in", DetectionID: "d1", Urgency: "high", Status: "open", Created: now}
	r, err := New(c, []*findings.Finding{f}, []string{"gone"}, "ana", "https://siem.example", "signalith", now)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// keyring returns a signing key and the Keys of a list holding it.
func keyring(t *testing.T) (ed25519.PrivateKey, *reportkeys.Memory, Keys) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(nil)
	var m reportkeys.Memory
	if err := m.Use(context.Background(), priv.Public().(ed25519.PublicKey), reportkeys.FromMaster, time.Now()); err != nil {
		t.Fatal(err)
	}
	return priv, &m, func(id string) (*reportkeys.Key, bool) {
		ks, _ := m.List(context.Background())
		for i := range ks {
			if ks[i].ID == id {
				return &ks[i], true
			}
		}
		return nil, false
	}
}

func files(t *testing.T, s *Signed) (js, page []byte) {
	t.Helper()
	js, err := s.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if page, err = s.HTML(); err != nil {
		t.Fatal(err)
	}
	return js, page
}

func TestUnsignedReportIsIntact(t *testing.T) {
	r := sampleReport(t)
	if len(r.SHA256) != 64 || len(r.Evidence) != 1 || !r.Evidence[0].Intact || r.Tenant != "signalith" {
		t.Fatalf("report %+v", r)
	}
	s, _ := r.Sign(nil)
	js, page := files(t, s)
	// As a Windows editor saves it: every line end CR LF.
	crlf := bytes.ReplaceAll(bytes.ReplaceAll(page, []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n"))
	for name, b := range map[string][]byte{"json": js, "page": page, "crlf page": crlf} {
		res, err := Verify(b, nil, false)
		if err != nil || res.Signed {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
	if !strings.Contains(string(page), "Not signed") || !strings.Contains(string(page), "does not prove who made it") {
		t.Error("an unsigned page does not say so")
	}
}

func TestSignedReportVerifies(t *testing.T) {
	priv, m, keys := keyring(t)
	s, err := sampleReport(t).Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	js, page := files(t, s)
	for name, b := range map[string][]byte{"json": js, "page": page} {
		res, err := Verify(b, keys, true)
		if err != nil || !res.Signed || res.KeyStatus != reportkeys.Current || res.Report.Case.ID != "CASE-1" {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
	// A retired key still verifies; a revoked one says so.
	_, newer, _ := ed25519.GenerateKey(nil)
	m.Use(context.Background(), newer.Public().(ed25519.PublicKey), reportkeys.FromMaster, time.Now())
	if res, err := Verify(js, keys, true); err != nil || res.KeyStatus != reportkeys.Retired {
		t.Errorf("retired: %+v %v", res, err)
	}
	m.Revoke(context.Background(), s.KeyID, "admin", "leaked", time.Now())
	if res, err := Verify(js, keys, true); err != nil || res.KeyStatus != reportkeys.Revoked {
		t.Errorf("revoked: %+v %v", res, err)
	}
}

// A CR put inside the page's markup changes how a browser reads it, so
// the page no longer verifies.
func TestPageCatchesCarriageReturns(t *testing.T) {
	priv, _, keys := keyring(t)
	s, _ := sampleReport(t).Sign(priv)
	_, page := files(t, s)
	for _, edit := range [][2]string{{"<style>", "<s\rtyle>"}, {`<span class="hash">`, "<s\rpan class=\"hash\">"}, {"color:", "co\rlor:"}} {
		if !bytes.Contains(page, []byte(edit[0])) {
			t.Fatalf("the page has no %q", edit[0])
		}
		b := bytes.Replace(page, []byte(edit[0]), []byte(edit[1]), 1)
		if _, err := Verify(b, keys, true); !errors.Is(err, ErrChanged) {
			t.Errorf("%q: %v", edit[1], err)
		}
	}
}

func TestSignedReportCatchesChanges(t *testing.T) {
	priv, _, keys := keyring(t)
	s, _ := sampleReport(t).Sign(priv)
	js, page := files(t, s)

	// The payload changed with its hash taken again: the signature fails
	// before anything else is read.
	var env envelope
	json.Unmarshal(js, &env)
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	forged := forge(t, payload, func(r *Report) { r.Case.Severity = "low" })
	env.Payload = base64.StdEncoding.EncodeToString(forged)
	b, _ := json.Marshal(env)
	if _, err := Verify(b, keys, true); !errors.Is(err, ErrChanged) || !strings.Contains(err.Error(), "signature") {
		t.Errorf("forged payload: %v", err)
	}
	// Without a key list, the forgery is only an intact unsigned report.
	if _, err := Verify(forged, nil, false); err != nil {
		t.Errorf("unsigned forgery: %v", err)
	}
	// An unsigned report where a signed one is required.
	if _, err := Verify(forged, keys, true); !errors.Is(err, ErrChanged) {
		t.Errorf("unsigned where required: %v", err)
	}
	// A key this server never used.
	_, other, _ := ed25519.GenerateKey(nil)
	s2, _ := sampleReport(t).Sign(other)
	js2, _ := s2.JSON()
	if _, err := Verify(js2, keys, true); !errors.Is(err, ErrChanged) || !strings.Contains(err.Error(), "never used") {
		t.Errorf("unknown key: %v", err)
	}
	// An edit to what the page shows.
	edited := bytes.Replace(page, []byte("<dd>High</dd>"), []byte("<dd>Low</dd>"), 1)
	if bytes.Equal(edited, page) {
		t.Fatal("the test's edit did not apply")
	}
	if _, err := Verify(edited, keys, true); !errors.Is(err, ErrChanged) || !strings.Contains(err.Error(), "page") {
		t.Errorf("edited page: %v", err)
	}
	// Changed evidence with the report's hash taken again, unsigned.
	r := sampleReport(t)
	r.Case.Entries[0].Event["host"] = "web-02"
	cb, _ := r.Canonical()
	r.SHA256 = sha(cb)
	u, _ := r.Sign(nil)
	if _, err := Verify(u.Payload, nil, false); !errors.Is(err, ErrChanged) || !strings.Contains(err.Error(), "evidence") {
		t.Errorf("changed evidence: %v", err)
	}
	if _, err := Verify(bytes.Repeat([]byte(" "), MaxSize+1), keys, true); err == nil {
		t.Error("an oversized file was read")
	}
	// A key ID that could not be one, or a signature too long to be one,
	// is refused before it is shown anywhere.
	var env2 envelope
	json.Unmarshal(js, &env2)
	for _, bad := range []envelope{
		{PayloadType: PayloadType, Payload: env2.Payload, KeyID: "<script>", Sig: env2.Sig},
		{PayloadType: PayloadType, Payload: env2.Payload, KeyID: env2.KeyID, Sig: strings.Repeat("A", 4096)},
	} {
		b, _ := json.Marshal(bad)
		if res, err := Verify(b, keys, true); !errors.Is(err, ErrChanged) || res != nil {
			t.Errorf("bad signature %.20s: %+v %v", bad.KeyID, res, err)
		}
	}
	if _, err := Verify([]byte(`{"format":"other"}`), nil, false); err == nil {
		t.Error("another format verified")
	}
}

func TestReportPageIsInert(t *testing.T) {
	priv, _, _ := keyring(t)
	s, _ := sampleReport(t).Sign(priv)
	page, err := s.HTML()
	if err != nil {
		t.Fatal(err)
	}
	str := string(page)
	for _, bad := range []string{"<script", "</pre> <pre", "http://", "src="} {
		if strings.Contains(str, bad) {
			t.Errorf("page holds %q", bad)
		}
	}
	if !strings.Contains(str, "&lt;script&gt;") || !strings.Contains(str, "Reset the password") || !strings.Contains(str, s.KeyID) {
		t.Error("page is missing the case or its key")
	}
	if !bytes.Equal(Extract(page), s.Payload) {
		t.Error("the page does not carry the exact bytes signed")
	}
}

// forge rewrites a report's data and takes its hash again, as someone
// editing a report by hand could.
func forge(t *testing.T, payload []byte, edit func(*Report)) []byte {
	t.Helper()
	var r Report
	if err := json.Unmarshal(payload, &r); err != nil {
		t.Fatal(err)
	}
	edit(&r)
	b, _ := r.Canonical()
	r.SHA256 = sha(b)
	out, _ := r.JSON()
	return out
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
