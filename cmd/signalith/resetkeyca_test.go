// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

func TestLostCA(t *testing.T) {
	doc := func(id, body string, deleted bool) shared.StoredDoc {
		return shared.StoredDoc{ID: id, Envelope: shared.Envelope{ID: id, Body: body, Deleted: deleted}}
	}
	sealed := `{"ca_cert_pem":"-----BEGIN CERTIFICATE-----","ca_key":"enc:v1:abcd1234:xyz","ca_sha256":"AB:CD"}`
	if fp := lostCA([]shared.StoredDoc{doc("cluster", "{}", false), doc("tls", sealed, false)}); fp != "AB:CD" {
		t.Errorf("sealed key: %q", fp)
	}
	for name, docs := range map[string][]shared.StoredDoc{
		"no tls document": {doc("cluster", "{}", false)},
		"deleted":         {doc("tls", sealed, true)},
		"key emptied":     {doc("tls", `{"ca_cert_pem":"x","ca_key":"","ca_sha256":"AB:CD"}`, false)},
		"no certificate":  {doc("tls", `{"ca_key":"enc:v1:abcd1234:xyz"}`, false)},
		"unreadable":      {doc("tls", `{`, false)},
	} {
		if fp := lostCA(docs); fp != "" {
			t.Errorf("%s: %q", name, fp)
		}
	}
}

func TestCertExpiries(t *testing.T) {
	now := time.Now().Add(-time.Hour)
	at := func(days int) *time.Time {
		x := now.AddDate(0, 0, days)
		return &x
	}
	hb := func(id, name, fp string, exp *time.Time) cluster.Heartbeat {
		h := cluster.Heartbeat{NodeID: id, Name: name}
		if fp != "" {
			h.TLS = &cluster.TLSStatus{CASHA256: fp, LeafExpires: exp}
		}
		return h
	}
	hbs := []cluster.Heartbeat{
		hb("n_a", "siem-a", "ab:cd", at(10)), // this server: its folder wins
		hb("n_b", "siem-b", "AB:CD", at(300)),
		hb("n_c", "siem-c", "EF:01", at(5)), // another certificate authority
		hb("n_d", "siem-d", "", nil),        // reports no certificate
		hb("n_e", "siem-e", "AB:CD", at(200)),
	}
	own := &certExpiry{Server: "siem-a", Expires: now.AddDate(0, 0, 250).UTC()}
	got := certExpiries("AB:CD", hbs, "n_a", own)
	want := []string{"siem-e", "siem-a", "siem-b"}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i, w := range want {
		if got[i].Server != w {
			t.Errorf("%d: %+v", i, got)
		}
	}
	// Without this server's folder, its heartbeat counts.
	if got := certExpiries("AB:CD", hbs, "n_a", nil); len(got) != 3 || got[0].Server != "siem-a" {
		t.Errorf("without own: %+v", got)
	}

	text := caLossText(got)
	for _, w := range []string{"certificate authority key is lost too", "siem-e, " + shortDay(*at(200)),
		"before " + shortDay(*at(200)), "signalith cluster export-key", "signalith cluster export --to-files"} {
		if !strings.Contains(text, w) {
			t.Errorf("text lacks %q:\n%s", w, text)
		}
	}
	if text := caLossText(nil); !strings.Contains(text, "can't see when") || !strings.Contains(text, "397 days") {
		t.Errorf("text without certificates:\n%s", text)
	}
}
