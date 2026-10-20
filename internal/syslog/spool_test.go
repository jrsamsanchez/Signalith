// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package syslog

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// flaky is a Bulker standing for an OpenSearch that can be down (down),
// too busy for every document (busy), or up. It always refuses a
// document whose message has "unmappable" in it, as a mapping error,
// and refuses a document ID it already stored as a conflict.
type flaky struct {
	mu   sync.Mutex
	down error
	busy bool
	docs []store.IndexedDoc
	ids  map[string]bool
}

func (f *flaky) Bulk(ctx context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down != nil {
		return nil, f.down
	}
	if f.ids == nil {
		f.ids = map[string]bool{}
	}
	var errs []store.BulkItemError
	for i, d := range docs {
		switch {
		case strings.Contains(fmt.Sprint(d.Doc["message"]), "unmappable"):
			errs = append(errs, store.BulkItemError{Index: d.Index, Pos: i, Status: http.StatusBadRequest, Type: "mapper_parsing_exception", Reason: "mapper_parsing_exception: failed to parse"})
		case f.busy:
			errs = append(errs, store.BulkItemError{Index: d.Index, Pos: i, Status: http.StatusTooManyRequests, Type: "es_rejected_execution_exception", Reason: "es_rejected_execution_exception: queue full"})
		case d.ID != "" && f.ids[d.ID]:
			errs = append(errs, store.BulkItemError{Index: d.Index, Pos: i, Status: http.StatusConflict, Type: "version_conflict_engine_exception"})
		default:
			if d.ID != "" {
				f.ids[d.ID] = true
			}
			f.docs = append(f.docs, d)
		}
	}
	return errs, nil
}

func (f *flaky) set(down error, busy bool) {
	f.mu.Lock()
	f.down, f.busy = down, busy
	f.mu.Unlock()
}

func (f *flaky) stored() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, d := range f.docs {
		out = append(out, fmt.Sprint(d.Doc["message"]))
	}
	return out
}

var errDown = errors.New("dial tcp 127.0.0.1:9200: connect: connection refused")

// startSpooled runs a receiver with a spool in dir, writing through a
// pipeline to os, and retrying the spool quickly.
func startSpooled(t *testing.T, dir string, os *flaky, cfg Config) (*Receiver, context.CancelFunc) {
	t.Helper()
	cfg.SpoolDir = dir
	if cfg.UDP == "" {
		cfg.UDP = "127.0.0.1:0"
	}
	return startWith(t, cfg, &ingest.Pipeline{Store: os, Prefix: "sig"}, func(r *Receiver) {
		r.replayMin, r.replayMax = 10*time.Millisecond, 50*time.Millisecond
	})
}

func messages(prefix string, n int) [][]byte {
	at := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	var out [][]byte
	for i := range n {
		out = append(out, fmt.Appendf(nil, "<13>1 %s h app - - - %s %d", at, prefix, i))
	}
	return out
}

func handleAll(r *Receiver, msgs [][]byte) {
	for _, m := range msgs {
		r.handle(context.Background(), m, sender, "udp", true)
	}
}

func spoolFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// TestSpoolKeepsEventsWhileOpenSearchIsDown: batches OpenSearch cannot
// take go to the spool, and are written once it is back, none twice.
func TestSpoolKeepsEventsWhileOpenSearchIsDown(t *testing.T) {
	dir := t.TempDir()
	fo := &flaky{down: errDown}
	r, _ := startSpooled(t, dir, fo, Config{BatchSize: 10})
	handleAll(r, messages("down", 25))
	waitFor(t, "25 spooled", func() bool { return r.Stats().Spooled == 25 })
	s := r.Stats()
	if s.WriteFailed != 0 || s.SpoolEvents != 25 || s.SpoolBytes == 0 || s.SpoolMaxBytes != DefaultSpoolBytes {
		t.Errorf("while down: %+v", s)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("spool folder: %v %v", fi.Mode(), err)
		}
	}
	// Too busy for every document is the same.
	fo.set(nil, true)
	handleAll(r, messages("busy", 5))
	waitFor(t, "30 spooled", func() bool { return r.Stats().Spooled == 30 })

	fo.set(nil, false)
	waitFor(t, "all written", func() bool { return len(fo.stored()) == 30 })
	waitFor(t, "the spool empty", func() bool { s := r.Stats(); return s.SpoolEvents == 0 && s.Replayed == 30 })
	if s := r.Stats(); s.WriteFailed != 0 || s.Dropped != 0 || s.SpoolBytes != 0 {
		t.Errorf("after: %+v", s)
	}
	if n := spoolFiles(t, dir); n != 0 {
		t.Errorf("%d files left in the spool", n)
	}
	// Oldest first.
	if got := fo.stored(); !strings.Contains(got[0], "down 0") || !strings.Contains(got[29], "busy 4") {
		t.Errorf("order: %q ... %q", got[0], got[29])
	}
	// Once it is back, new batches go straight to OpenSearch.
	handleAll(r, messages("up", 3))
	waitFor(t, "33 written", func() bool { return len(fo.stored()) == 33 })
	if s := r.Stats(); s.Spooled != 30 {
		t.Errorf("spooled %d", s.Spooled)
	}
}

// TestSpoolReplaysAfterRestart: what was spooled, also while stopping
// with OpenSearch hanging, is written by the next start.
func TestSpoolReplaysAfterRestart(t *testing.T) {
	dir := t.TempDir()
	sk := &sink{hang: true}
	r, cancel := startWith(t, Config{UDP: "127.0.0.1:0", BatchSize: 100, SpoolDir: dir}, sk, func(r *Receiver) { r.finalFlush = 300 * time.Millisecond })
	handleAll(r, messages("before", 1200))
	time.Sleep(50 * time.Millisecond) // the first write is in progress
	cancel()
	r.Wait()
	if s := r.Stats(); s.Spooled != 1200 || s.Dropped != 0 || s.WriteFailed != 0 {
		t.Fatalf("after stop: %+v", s)
	}

	fo := &flaky{}
	r2, _ := startSpooled(t, dir, fo, Config{})
	if s := r2.Stats(); s.SpoolEvents != 1200 {
		t.Errorf("found %d events in the spool", s.SpoolEvents)
	}
	waitFor(t, "all written", func() bool { return len(fo.stored()) == 1200 })
	waitFor(t, "the spool empty", func() bool { return r2.Stats().SpoolEvents == 0 })
	if s := r2.Stats(); s.Replayed != 1200 || s.WriteFailed != 0 {
		t.Errorf("after replay: %+v", s)
	}
	seen := map[string]bool{}
	for _, m := range fo.stored() {
		if seen[m] {
			t.Fatalf("written twice: %s", m)
		}
		seen[m] = true
	}
}

// TestPermanentRejectionsAreNotSpooled: an event OpenSearch refuses for
// good is counted, not spooled; one refused for now in the same batch is.
func TestPermanentRejectionsAreNotSpooled(t *testing.T) {
	dir := t.TempDir()
	fo := &flaky{}
	r, _ := startSpooled(t, dir, fo, Config{BatchSize: 10})
	handleAll(r, messages("unmappable", 2))
	waitFor(t, "the rejections", func() bool { return r.Stats().WriteFailed == 2 })
	if s := r.Stats(); s.Spooled != 0 || spoolFiles(t, dir) != 0 {
		t.Errorf("spooled a permanent rejection: %+v", s)
	}

	fo.set(nil, true)
	handleAll(r, [][]byte{messages("unmappable", 1)[0], messages("fine", 1)[0]})
	waitFor(t, "the batch", func() bool { s := r.Stats(); return s.WriteFailed == 3 && s.Spooled == 1 })
	fo.set(nil, false)
	waitFor(t, "the spooled one written", func() bool { return len(fo.stored()) == 1 && r.Stats().SpoolEvents == 0 })
	if s := r.Stats(); s.WriteFailed != 3 || s.Replayed != 1 {
		t.Errorf("after: %+v", s)
	}
}

// TestSpoolCap: a full spool drops its oldest batches, counts them, and
// never holds more than its cap.
func TestSpoolCap(t *testing.T) {
	batch := func(tag string, n int) []ingest.Event {
		var evs []ingest.Event
		for i := range n {
			evs = append(evs, ingest.Event{Time: time.Now().Add(-time.Hour), Model: "Other",
				Fields: map[string]any{"message": fmt.Sprintf("%s %d %s", tag, i, strings.Repeat("x", 200))}})
		}
		return evs
	}
	one, _ := encode(batch("a", 10))
	dir := t.TempDir()
	sp, err := openSpool(dir, int64(len(one))*3+100)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		dropped, err := sp.add(batch(fmt.Sprint("b", i), 10))
		if err != nil {
			t.Fatal(err)
		}
		if want := map[bool]int{true: 10, false: 0}[i >= 3]; dropped != want {
			t.Errorf("batch %d dropped %d", i, dropped)
		}
	}
	st := sp.stats()
	if st.spooled != 50 || st.dropped != 20 || st.events != 30 || st.bytes > st.max {
		t.Errorf("stats %+v", st)
	}
	// The oldest left is the third batch.
	f, _ := sp.next()
	evs, bad, err := sp.read(f)
	if err != nil || bad != 0 || len(evs) != 10 || !strings.HasPrefix(evs[0].Fields["message"].(string), "b2 0") {
		t.Fatalf("oldest: %v %d %v", err, bad, evs)
	}
	sp.release()
	// A batch larger than the whole spool is dropped itself.
	if dropped, _ := sp.add(batch("huge", 50)); dropped != 50 || sp.stats().events != 30 {
		t.Errorf("a batch over the cap: dropped %d, %+v", dropped, sp.stats())
	}

	// Through the receiver: the drops are in the stats.
	fo := &flaky{down: errDown}
	r, _ := startSpooled(t, t.TempDir(), fo, Config{BatchSize: 10, SpoolMaxBytes: int64(len(one)) * 2})
	handleAll(r, messages("full", 60))
	// Each batch is kept, or dropped when even the oldest batches cannot
	// make room (the one being retried stays).
	waitFor(t, "drops", func() bool { s := r.Stats(); return s.SpoolEvents+s.SpoolDropped == 60 && s.SpoolDropped > 0 })
	if s := r.Stats(); s.SpoolBytes > s.SpoolMaxBytes || s.WriteFailed != 0 || s.Dropped != 0 {
		t.Errorf("stats %+v", s)
	}
}

// TestSpoolRecords: the fields only Signalith sets are left out, each
// event gets an ID it keeps, and numbers come back as numbers.
func TestSpoolRecords(t *testing.T) {
	at := time.Now().Add(-time.Hour).UTC()
	evs := []ingest.Event{
		{Time: at, Model: "Network_Traffic", Origin: ingest.Origin{Intake: ingest.IntakeSyslog, Sender: "192.0.2.1"},
			Fields: map[string]any{"message": "m", "bytes": int64(42), "ratio": 0.5, "dropped_fields": int64(1), ingest.IntakeField: "syslog", "nested": map[string]any{"n": 7}}},
		{Time: at, Model: "Other", ID: "fixed", Fields: map[string]any{"message": "n"}},
	}
	data, n := encode(evs)
	if n != 2 {
		t.Fatalf("encoded %d", n)
	}
	back, bad := decode(data)
	if bad != 0 || len(back) != 2 {
		t.Fatalf("decoded %d, %d bad", len(back), bad)
	}
	a := back[0]
	if !a.Time.Equal(at) || a.Model != "Network_Traffic" || a.Origin != evs[0].Origin || a.ID == "" {
		t.Errorf("event: %+v", a)
	}
	if a.Fields["bytes"] != int64(42) || a.Fields["ratio"] != 0.5 || a.Fields["message"] != "m" || a.Fields["nested"] == nil {
		t.Errorf("fields: %#v", a.Fields)
	}
	if _, ok := a.Fields["dropped_fields"]; ok {
		t.Error("dropped_fields kept")
	}
	if _, ok := a.Fields[ingest.IntakeField]; ok {
		t.Error("the origin field kept")
	}
	if back[1].ID != "fixed" {
		t.Errorf("id %q", back[1].ID)
	}
	again, _ := encode(back)
	if back2, _ := decode(again); back2[0].ID != a.ID {
		t.Error("the ID changed when spooled again")
	}
	if _, bad := decode([]byte("not json\n{}\n")); bad != 2 {
		t.Errorf("bad lines: %d", bad)
	}
}
