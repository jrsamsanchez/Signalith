// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package compliancehist

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/compliance"
	"github.com/jrsamsanchez/signalith/internal/reportkeys"
)

func keyring(t *testing.T) (ed25519.PrivateKey, *reportkeys.Memory, func(string) (*reportkeys.Key, bool)) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(nil)
	m := &reportkeys.Memory{}
	if err := m.Use(context.Background(), priv.Public().(ed25519.PublicKey), reportkeys.FromMaster, time.Now()); err != nil {
		t.Fatal(err)
	}
	return priv, m, func(id string) (*reportkeys.Key, bool) {
		ks, _ := m.List(context.Background())
		return reportkeys.Lookup(ks)(id)
	}
}

func record(now time.Time) *Record {
	rep := &compliance.Report{Generated: now, Frameworks: []compliance.FrameworkReport{{
		Framework: compliance.Framework{ID: "pci-dss", Name: "PCI DSS"}, Score: 50,
		Counts:   map[compliance.Status]int{compliance.Met: 1, compliance.Missing: 1},
		Controls: []compliance.ControlReport{{Control: compliance.Control{ID: "10.2"}, Status: compliance.Met}, {Control: compliance.Control{ID: "10.7"}, Status: compliance.External, Attestation: &compliance.Attestation{Note: "SOC tool"}}},
	}}}
	return FromReport(rep, MonthID(now), Monthly, "", "siem-1", "0.3.2", "signalith")
}

func TestSignedRecordChecks(t *testing.T) {
	priv, m, keys := keyring(t)
	now := time.Now()
	s, err := Sign(record(now), priv)
	if err != nil {
		t.Fatal(err)
	}
	c := Check(s, keys)
	if c.Check != Verified || c.Record == nil || c.Record.Frameworks[0].Controls[1].Note != "SOC tool" || c.Record.Tenant != "signalith" {
		t.Fatalf("check: %+v", c)
	}
	unsigned, _ := Sign(record(now), nil)
	if c := Check(unsigned, keys); c.Check != Unsigned || c.Record == nil {
		t.Errorf("unsigned: %+v", c)
	}

	changed := func(name string, edit func(s *Signed)) {
		t.Helper()
		x := *s
		edit(&x)
		if c := Check(&x, keys); c.Check != Changed || c.Record != nil || c.Problem == "" {
			t.Errorf("%s: %+v", name, c)
		}
	}
	other := record(now)
	other.Frameworks[0].Score = 100
	o, _ := Sign(other, nil)
	changed("data with its hash", func(x *Signed) { x.Payload, x.SHA256 = o.Payload, o.SHA256 })
	changed("data alone", func(x *Signed) { x.Payload = o.Payload })
	changed("under another ID", func(x *Signed) { x.ID = "2001-01" })
	changed("unknown key", func(x *Signed) { x.KeyID = "000000000000" })
	changed("odd key ID", func(x *Signed) { x.KeyID = "\x1b[2K" })
	changed("signature dropped", func(x *Signed) { x.Sig = "" })
	// A signature over the bare data, as a case report's is, is not one
	// over a record.
	b, _ := base64.StdEncoding.DecodeString(s.Payload)
	changed("case report signature", func(x *Signed) { x.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b)) })

	m.Revoke(context.Background(), s.KeyID, "admin", "leaked", now)
	if c := Check(s, keys); c.Check != Revoked || c.Record == nil {
		t.Errorf("revoked: %+v", c)
	}
}

func TestIDs(t *testing.T) {
	at := time.Date(2026, 10, 21, 7, 30, 5, 0, time.UTC)
	for _, id := range []string{MonthID(at), ManualID(at)} {
		if !ValidID(id) {
			t.Errorf("%q not valid", id)
		}
	}
	for _, id := range []string{"", "2026-1", "../x", "2026-10-21", "2026-10-21T073005Z\n"} {
		if ValidID(id) {
			t.Errorf("%q valid", id)
		}
	}
}

func TestDueOncePerMonth(t *testing.T) {
	m := NewMemory()
	now := time.Now()
	if due, err := Due(context.Background(), m, now); !due || err != nil {
		t.Fatalf("empty: %v %v", due, err)
	}
	s, _ := Sign(record(now), nil)
	if err := m.Create(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if err := m.Create(context.Background(), s); err == nil {
		t.Error("a second record for the month was stored")
	}
	if due, _ := Due(context.Background(), m, now); due {
		t.Error("due after the month's record")
	}
}
