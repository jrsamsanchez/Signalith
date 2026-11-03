// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func TestMatchingSelectsAndPages(t *testing.T) {
	fake := ostest.New(t)
	c := store.New(store.Config{URL: fake.URL})
	ctx := context.Background()
	if hits, truncated, err := Matching(ctx, c, testPrefix, Match{Messages: []string{"user deleted"}}, 10); err != nil || truncated || len(hits) != 0 {
		t.Fatalf("with no audit index: %v, %v, %v", hits, truncated, err)
	}
	base := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	s := newTestSink(t, SinkOptions{Dir: filepath.Join(t.TempDir(), "spool"), Client: c, Prefix: testPrefix, Server: "a", NodeID: "na"})
	for i, m := range []struct{ msg, action string }{
		{"user deleted", ""}, {"search.run: search run", "search.run"}, {"tenants.add: tenant added", "tenants.add"},
		{"sign-ins from this address are paused after too many", ""}, {"user deleted", ""}, {"settings saved", ""},
	} {
		s.Add(Event{Time: base.Add(time.Duration(i) * time.Minute), Message: m.msg, Action: m.action})
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	m := Match{Messages: []string{"user deleted", "settings saved"}, MessagePrefixes: []string{"sign-ins from this address"}, ActionPrefixes: []string{"tenants."}}
	hits, truncated, err := Matching(ctx, c, testPrefix, m, 10)
	if err != nil || truncated {
		t.Fatal(err, truncated)
	}
	var got []string
	for _, h := range hits {
		got = append(got, h.Message)
		if h.ID == "" {
			t.Errorf("hit without an ID: %+v", h)
		}
	}
	want := []string{"user deleted", "tenants.add: tenant added", "sign-ins from this address are paused after too many", "user deleted", "settings saved"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q (oldest first)", got, want)
		}
	}
	if few, truncated, _ := Matching(ctx, c, testPrefix, m, 2); len(few) != 2 || !truncated {
		t.Errorf("a limit of 2 read %d (truncated %v)", len(few), truncated)
	}
	m.Since = base.Add(4 * time.Minute)
	if late, _, _ := Matching(ctx, c, testPrefix, m, 10); len(late) != 2 {
		t.Errorf("since the fifth minute: %d records, want 2", len(late))
	}
	if none, _, _ := Matching(ctx, c, testPrefix, Match{}, 10); len(none) != 0 {
		t.Errorf("an empty match read %d records", len(none))
	}
}

func TestTapSeesAuditLinesWhileTheSinkIsOff(t *testing.T) {
	sink := newTestSink(t, SinkOptions{})
	sink.SetEnabled(false)
	var got []Event
	sink.SetTap(func(e Event) { got = append(got, e) })
	log := slog.New(Handler(slog.DiscardHandler, sink))
	log.Info("user deleted", "audit", true, "by", "alice", "user", "bob", "client", "203.0.113.7")
	log.Info("not an audit line", "user", "x")
	if len(got) != 1 || got[0].Message != "user deleted" || got[0].User != "alice" || got[0].Target != "bob" || got[0].SourceIP != "203.0.113.7" {
		t.Fatalf("tap got %+v", got)
	}
	if n := len(spooled(t, sink.dir)); n != 0 {
		t.Errorf("a disabled sink spooled %d events", n)
	}
	sink.SetTap(nil)
	log.Info("user deleted", "audit", true)
	if len(got) != 1 {
		t.Errorf("the tap was called after it was removed")
	}
}
