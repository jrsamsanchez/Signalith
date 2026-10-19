// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPlaintextSenders(t *testing.T) {
	now := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	p := &Pipeline{Now: func() time.Time { return now }}
	p.NotePlaintext(netip.MustParseAddr("::ffff:10.0.0.5"), []string{"web-01"})
	now = now.Add(time.Minute)
	p.NotePlaintext(netip.MustParseAddr("10.0.0.7"), nil)
	p.NotePlaintext(netip.MustParseAddr("10.0.0.5"), []string{"web-02", "web-01"})
	p.NotePlaintext(netip.Addr{}, nil)
	got := p.PlaintextSenders(time.Time{})
	if len(got) != 2 || got[0].Address != "10.0.0.5" || got[0].Requests != 2 || got[1].Address != "10.0.0.7" {
		t.Errorf("senders = %+v", got)
	}
	// Host names tell apart agents behind one address, newest last.
	if !slices.Equal(got[0].Hosts, []string{"web-02", "web-01"}) || got[1].Hosts != nil {
		t.Errorf("hosts = %q %q", got[0].Hosts, got[1].Hosts)
	}
	for i := 0; i < maxSenderHosts+3; i++ {
		p.NotePlaintext(netip.MustParseAddr("10.0.0.5"), []string{"pc-" + string(rune('a'+i))})
	}
	if h := p.PlaintextSenders(time.Time{})[0].Hosts; len(h) != maxSenderHosts || h[len(h)-1] != "pc-k" {
		t.Errorf("hosts kept: %q", h)
	}
	if got := p.PlaintextSenders(now.Add(time.Second)); len(got) != 0 {
		t.Errorf("since filter: %+v", got)
	}
	// The table is capped; the one heard from longest ago goes first.
	for i := 0; i < maxSenders+10; i++ {
		now = now.Add(time.Second)
		p.NotePlaintext(netip.AddrFrom4([4]byte{192, 0, 2 + byte(i/250), byte(i % 250)}), nil)
	}
	all := p.PlaintextSenders(time.Time{})
	if len(all) != maxSenders {
		t.Errorf("%d senders kept", len(all))
	}
	for _, s := range all {
		if s.Address == "10.0.0.7" {
			t.Error("the oldest sender was kept")
		}
	}
}

func TestRefusedSenders(t *testing.T) {
	now := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	p := &Pipeline{Now: func() time.Time { return now }}
	a := netip.MustParseAddr("192.168.65.1")
	p.NoteRefused(a, RefusedOldToken)
	p.NoteRefused(a, RefusedOldToken)
	now = now.Add(time.Second)
	p.NoteRefused(a, RefusedToken)
	got := p.RefusedSenders(time.Time{})
	if len(got) != 2 || got[0].Reason != RefusedToken || got[1].Reason != RefusedOldToken || got[1].Requests != 2 {
		t.Errorf("refused = %+v", got)
	}
	if len(p.PlaintextSenders(time.Time{})) != 0 {
		t.Error("a refused agent was listed as sending")
	}
}

// TestResultHosts checks that a batch reports its events' host names,
// a few at most, and only ones that look like names.
func TestResultHosts(t *testing.T) {
	p := &Pipeline{Store: &countingBulk{}}
	body := `{"Computer":"WIN-01","EventID":4624}` + "\n" + `{"Computer":"WIN-01","EventID":4625}` + "\n" +
		`{"Computer":"` + strings.Repeat("x", 100) + `","EventID":4624}` + "\n" + `{"Computer":"has space","EventID":4624}` + "\n" +
		`{"Computer":"WIN-02","EventID":4624}`
	res, err := p.IngestBody(context.Background(), "win.events", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Hosts, []string{"WIN-01", "WIN-02"}) {
		t.Errorf("hosts = %q", res.Hosts)
	}
}
