// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// An older part listed after a newer one does not count, and a day moving
// to its next part is logged.
func TestRolloverOlderPartsAndLog(t *testing.T) {
	at := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	c := &catIndices{rows: []map[string]any{
		row("sig-network-2026.10.17-2", 1, 41),
		row("sig-network-2026.10.17", 1, 41),
	}}
	var buf strings.Builder
	r := &Rollover{Client: c, Prefix: "sig", MaxShardBytes: 40 << 30, Now: func() time.Time { return at },
		Log: slog.New(slog.NewTextHandler(&buf, nil))}
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.Index("sig-network-2026.10.17"); got != "sig-network-2026.10.17-3" {
		t.Errorf("Index = %q", got)
	}
	if !strings.Contains(buf.String(), "reached the rollover size") {
		t.Errorf("log = %q", buf.String())
	}
	// The same check again logs nothing new.
	buf.Reset()
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("a second check logged %q", buf.String())
	}
}

// Run checks at once and stops when its context ends.
func TestRolloverRun(t *testing.T) {
	// One day name, read once, so a check near midnight still finds it.
	day := "sig-network-" + dayOf(time.Now())
	c := &catIndices{rows: []map[string]any{row(day, 1, 41)}}
	r := &Rollover{Client: c, Prefix: "sig", MaxShardBytes: 40 << 30}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()
	want := day + "-2"
	deadline := time.Now().Add(5 * time.Second)
	for r.Index(day) != want {
		if time.Now().After(deadline) {
			t.Fatal("Run did not check")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}

	// A context already ended stops Run after its first check.
	r2 := &Rollover{Client: &catIndices{}, Prefix: "sig"}
	r2.Run(ctx)
}
