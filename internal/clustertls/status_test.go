// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clustertls

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

func TestStatusAndHeartbeats(t *testing.T) {
	m, err := tlsauto.New(tlsauto.Options{Dir: filepath.Join(t.TempDir(), "tls"), Names: []string{"siem-a.lan"}})
	if err != nil {
		t.Fatal(err)
	}
	st := StatusOf(m, "siem-a.lan", "")
	if st.Mode != ModeAuto || st.Cluster || st.CASHA256 != m.Fingerprint() || st.CACertPEM != string(m.CAPEM()) ||
		!st.CoversShared || st.ChangePending || st.LeafExpires == nil || !slices.Contains(st.Names, "siem-a.lan") {
		t.Errorf("status %+v", st)
	}
	if StatusOf(m, "siem.example.org", "").CoversShared {
		t.Error("covers a shared name it does not")
	}
	if err := m.Prepare(tlsauto.ScopeStandard); err != nil {
		t.Fatal(err)
	}
	if !StatusOf(m, "", "").ChangePending {
		t.Error("change not reported")
	}
	if st := StatusOf(nil, "", ""); st == nil || st.Mode != ModeOff || !st.CoversShared || st.CASHA256 != "" {
		t.Errorf("no HTTPS: %+v", st)
	}

	now := time.Now()
	servers := FromHeartbeats([]cluster.Heartbeat{
		{NodeID: "n_a", Name: "siem-a", HeartbeatAt: now, TLS: st},
		{NodeID: "n_b", Name: "siem-b", HeartbeatAt: now},
		{NodeID: "n_c", Name: "siem-c", HeartbeatAt: now.Add(-time.Hour)},
		{NodeID: "n_d", Name: "siem-d", HeartbeatAt: now, State: cluster.StateStopped},
	}, "n_a", now)
	if len(servers) != 4 || !servers[0].Up || !servers[1].Up || servers[2].Up || servers[3].Up {
		t.Errorf("up %+v", servers)
	}
	servers = servers[:2]
	if len(servers) != 2 || !servers[0].Founder || servers[1].Founder || servers[0].CACertPEM == "" || servers[1].CACertPEM != "" ||
		!slices.Contains(servers[0].Names, "siem-a.lan") {
		t.Fatalf("servers %+v", servers)
	}
	if cs := Candidates(servers, nil, now); len(cs) != 1 || cs[0].CASHA256 != m.Fingerprint() || cs[0].Servers[0] != "siem-a" {
		t.Errorf("candidates %+v", cs)
	}
}

// KeyLost: after signalith cluster reset-key empties the tls document's
// key, a server that starts with the cluster's certificate authority and
// no ca.key reports it lost; one still holding the key, or one whose tls
// document still holds its key, does not.
func TestKeyLost(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	ca := makeCA(t, "a", time.Now().Add(-time.Hour))
	tl, _ := e.server("siem-a")
	if err := tl.Publish(ctx, "admin", "siem-a", ca.pem, ca.key, []string{"agents.lan"}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "tls")
	m, err := tlsauto.New(tlsauto.Options{Dir: dir, Store: tl.Store()})
	if err != nil {
		t.Fatal(err)
	}
	// A start without the cluster: the CA from ca.pem, without its key.
	d, err := tlsauto.New(tlsauto.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	b, ok := tl.Get()
	if !ok || !d.CAKeyMissing() || KeyLost(d, b) {
		t.Fatalf("before the reset: missing %v, lost %v", d.CAKeyMissing(), KeyLost(d, b))
	}

	// Every copy of the cluster key lost: reset-key signs the documents
	// with a new one and empties the sealed key.
	docs, _, err := shared.ReadAll(ctx, e.cl, prefix)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Format(time.RFC3339Nano)
	dropped, err := shared.Resign(ctx, e.cl, prefix, docs, k2, 1000, "admin", "siem-a", at, "n_a", shared.KeyringMember{Name: "siem-a"})
	if err != nil || !slices.Contains(dropped, DocID+" ca_key") {
		t.Fatalf("resign: %v, dropped %v", err, dropped)
	}
	e.key = k2
	tl2, _ := e.server("siem-a")
	b2, ok := tl2.Get()
	if !ok || !b2.KeyLost() {
		t.Fatalf("the tls document after the reset: %v %+v", ok, b2)
	}
	if !KeyLost(d, b2) {
		t.Error("not lost")
	}
	if KeyLost(m, b2) || KeyLost(nil, b2) || KeyLost(d, nil) {
		t.Error("lost with the key in hand, without a Manager or without a tls document")
	}

	exp := time.Now().Add(-time.Hour).AddDate(1, 0, 0).UTC()
	text := KeyLostText(exp)
	if !strings.HasPrefix(text, "The cluster's certificate authority key was lost; HTTPS certificates expire on "+exp.Format("2 Jan 2006")+" and cannot be renewed.") {
		t.Errorf("text %q", text)
	}
	if !strings.Contains(KeyLostText(time.Time{}), "cannot be renewed and stop working when they expire") {
		t.Errorf("text without a date %q", KeyLostText(time.Time{}))
	}

	// The Servers page warns on the server's row.
	st := StatusOf(d, "", "")
	st.CAKeyLost = true
	r := BuildReport(ReportInput{Heartbeats: []cluster.Heartbeat{{NodeID: "n_a", Name: "siem-a", HeartbeatAt: time.Now(), TLS: st}}, Now: time.Now()})
	if len(r.Servers) != 1 || !slices.Contains(r.Servers[0].Warnings, KeyLostText(*st.LeafExpires)) {
		t.Errorf("servers %+v", r.Servers)
	}
}
