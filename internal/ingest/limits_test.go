// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// countingBulk records each bulk request: how many documents it had and
// the live heap while it was being written.
type countingBulk struct {
	mu       sync.Mutex
	calls    []int
	docs     []store.IndexedDoc
	keep     bool
	measure  bool
	peakHeap uint64
	reject   func(store.IndexedDoc) *store.BulkItemError
}

func (b *countingBulk) Bulk(_ context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, len(docs))
	if b.measure {
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		b.peakHeap = max(b.peakHeap, ms.HeapAlloc)
	}
	var errs []store.BulkItemError
	for i, d := range docs {
		if b.reject != nil {
			if e := b.reject(d); e != nil {
				e.Pos = i
				errs = append(errs, *e)
				continue
			}
		}
		if b.keep {
			b.docs = append(b.docs, d)
		}
	}
	return errs, nil
}

func TestIngestBodyFormats(t *testing.T) {
	for _, body := range []string{
		`[{"a":1},{"a":2}]`,
		" \n[ {\"a\":1} ,\n {\"a\":2} ]\n",
		"{\"a\":1}\n{\"a\":2}\n",
		"{\"a\":1}\r\n\r\n{\"a\":2}",
	} {
		b := &countingBulk{keep: true}
		p := &Pipeline{Store: b, Now: func() time.Time { return now }}
		res, err := p.IngestBody(context.Background(), "app", []byte(body))
		if err != nil || res.Received != 2 || res.Indexed != 2 || len(b.docs) != 2 {
			t.Errorf("%q: res %+v err %v docs %d", body, res, err, len(b.docs))
		}
	}
	// One pretty-printed object, and nothing at all.
	for body, want := range map[string]int{"{\n  \"a\": 1,\n  \"b\": {\"c\": 2}\n}\n": 1, "": 0, "  \n": 0, "[]": 0} {
		p := &Pipeline{Store: &countingBulk{}, Now: func() time.Time { return now }}
		if res, err := p.IngestBody(context.Background(), "app", []byte(body)); err != nil || res.Received != want {
			t.Errorf("%q: res %+v err %v", body, res, err)
		}
	}
}

// TestIngestBodyRefusesOversizedRequests reproduces dos-1: a small body of
// many empty records used to become hundreds of MB of maps. Requests past a
// limit are refused as a whole, with a status and a message saying which
// limit, and nothing is written.
func TestIngestBodyRefusesOversizedRequests(t *testing.T) {
	many := "[" + strings.Repeat("{},", MaxRecords) + "{}]"
	deep := `{"a":` + strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth) + "}"
	big := `[{"a":"` + strings.Repeat("x", MaxRecordBytes) + `"}]`
	cases := []struct {
		name, body string
		status     int
		msg        string
	}{
		{"too many records", many, http.StatusRequestEntityTooLarge, "more than 200000 records"},
		{"record too large", big, http.StatusRequestEntityTooLarge, "per record"},
		{"nested too deep", deep, http.StatusBadRequest, "levels deep"},
		{"not an object", `[{"a":1}, 5]`, http.StatusBadRequest, "record 2 is not a JSON object"},
		{"null record", `[null]`, http.StatusBadRequest, "record 1 is not a JSON object"},
		{"array of arrays", `[[1,2]]`, http.StatusBadRequest, "not a JSON object"},
		{"invalid JSON", `[{"a":1},{"a":]`, http.StatusBadRequest, "invalid JSON in record 2"},
		{"data after the array", `[{"a":1}] {"b":2}`, http.StatusBadRequest, "after the JSON array"},
		{"bad line", "{\"a\":1}\nnot json\n", http.StatusBadRequest, "invalid JSON in record 2"},
		{"not JSON", `hello`, http.StatusBadRequest, "JSON array of records or JSON lines"},
	}
	for _, c := range cases {
		b := &countingBulk{}
		p := &Pipeline{Store: b}
		_, err := p.IngestBody(context.Background(), "app", []byte(c.body))
		var be *BodyError
		if !errors.As(err, &be) || be.Status != c.status || !strings.Contains(be.Msg, c.msg) {
			t.Errorf("%s: err = %v, want %d %q", c.name, err, c.status, c.msg)
		}
		if len(b.calls) != 0 || p.Stats().Received != 0 {
			t.Errorf("%s: wrote %v", c.name, b.calls)
		}
	}
	// At the limits exactly, the request goes through.
	ok := "[" + strings.Repeat("{},", MaxRecords-1) + "{}]"
	p := &Pipeline{Store: &countingBulk{}, Now: func() time.Time { return now }}
	if res, err := p.IngestBody(context.Background(), "app", []byte(ok)); err != nil || res.Indexed != MaxRecords {
		t.Errorf("at the record limit: %+v %v", res, err)
	}
	deepOK := `{"a":` + strings.Repeat("[", MaxDepth-1) + strings.Repeat("]", MaxDepth-1) + "}"
	if _, err := p.IngestBody(context.Background(), "app", []byte(deepOK)); err != nil {
		t.Errorf("at the depth limit: %v", err)
	}
}

// TestIngestBodyMemoryStaysBounded reproduces dos-1's amplification: the
// most records a request may carry are written in bounded batches, so the
// live heap while writing stays small instead of growing with the batch
// (it reached hundreds of MB for this many records before).
func TestIngestBodyMemoryStaysBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	body := []byte("[" + strings.Repeat("{},", MaxRecords-1) + "{}]")
	b := &countingBulk{measure: true}
	p := &Pipeline{Store: b, Now: func() time.Time { return now }}
	res, err := p.IngestBody(context.Background(), "app", body)
	if err != nil || res.Indexed != MaxRecords {
		t.Fatalf("res %+v err %v", res, err)
	}
	for _, n := range b.calls {
		if n > batchEvents {
			t.Fatalf("a bulk request had %d documents", n)
		}
	}
	if len(b.calls) != MaxRecords/batchEvents {
		t.Errorf("%d bulk requests", len(b.calls))
	}
	if b.peakHeap > 64<<20 {
		t.Errorf("live heap reached %d MB while writing", b.peakHeap>>20)
	}
}

// TestFluentBitChunk sends what Fluent Bit sends for one full buffer chunk
// of short log lines: it is accepted and written in batches.
func TestFluentBitChunk(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte('[')
	n := 0
	for buf.Len() < 4<<20 {
		if n > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf, `{"date":%d.%06d,"log":"Oct 11 09:15:%02d web1 cron[%d]: (root) CMD (run-parts)"}`, now.Unix()-60, n%1000000, n%60, n)
		n++
	}
	buf.WriteByte(']')
	b := &countingBulk{}
	p := &Pipeline{Store: b, Now: func() time.Time { return now }}
	res, err := p.IngestBody(context.Background(), "linux.auth", buf.Bytes())
	if err != nil || res.Indexed != n || res.Retimed != 0 {
		t.Fatalf("res %+v err %v (records %d)", res, err, n)
	}
	if len(b.calls) < 2 {
		t.Errorf("written in %d bulk requests", len(b.calls))
	}
}

// TestEventTimesCannotChooseIndices reproduces dos-3 and
// authz-ingest-index-fanout: records dated a year ahead, one day apart, or
// at absurd times, used to create one daily index each. Now an event's own
// time only picks its index inside the window; outside it the event is
// filed under the receive time, keeps its time in device_time, and is
// counted.
func TestEventTimesCannotChooseIndices(t *testing.T) {
	var recs []string
	for i := range 1200 {
		recs = append(recs, fmt.Sprintf(`{"date":%d,"msg":"x"}`, now.AddDate(1, 0, i).Unix()))
	}
	recs = append(recs,
		`{"date":0}`, `{"date":86400.5}`, `{"date":"9999-12-31T00:00:00Z"}`, `{"date":253402300799}`,
		`{"date":-62135596000}`, `{"date":1e18}`,
		`{"Channel":"Security","Computer":"DC1","EventID":4625,"TimeCreated":"2199-01-01 00:00:00 +0000"}`,
	)
	b := &countingBulk{keep: true}
	p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}
	res, err := p.IngestBody(context.Background(), "app", []byte("["+strings.Join(recs, ",")+"]"))
	if err != nil {
		t.Fatal(err)
	}
	indices := map[string]bool{}
	for _, d := range b.docs {
		indices[d.Index] = true
		if d.Doc["@timestamp"] != "2026-10-11T12:00:00Z" || d.Doc["device_time"] == nil {
			t.Fatalf("doc %v", d.Doc)
		}
	}
	if len(indices) != 2 || !indices["sig-other-2026.10.11"] || !indices["sig-authentication-2026.10.11"] {
		t.Errorf("indices: %v", indices)
	}
	if res.Retimed != len(recs) || p.Stats().Retimed != int64(len(recs)) {
		t.Errorf("retimed: result %d, stats %d, want %d", res.Retimed, p.Stats().Retimed, len(recs))
	}
	if got := b.docs[0].Doc["device_time"]; got != now.AddDate(1, 0, 0).Format(time.RFC3339Nano) {
		t.Errorf("device_time = %v", got)
	}
}

func TestEventTimeWindow(t *testing.T) {
	day := 24 * time.Hour
	cases := []struct {
		age    time.Duration // how long before now the event says it happened
		maxAge time.Duration
		kept   bool
	}{
		{time.Minute, 0, true},
		{-30 * time.Minute, 0, true}, // a little ahead: clock skew
		{-time.Hour, 0, true},        // the limit
		{-2 * time.Hour, 0, false},   // too far ahead
		{7 * day, 0, true},           // the default limit
		{7*day + time.Second, 0, false},
		{20 * day, 30 * day, true}, // ingest.max_event_age raised
		{2 * day, day, false},      // or lowered
	}
	for _, c := range cases {
		b := &countingBulk{keep: true}
		p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }, MaxEventAge: c.maxAge}
		at := now.Add(-c.age)
		_, err := p.Ingest(context.Background(), "app", []map[string]any{{"date": float64(at.Unix())}})
		if err != nil {
			t.Fatal(err)
		}
		d := b.docs[0]
		kept := d.Doc["@timestamp"] == at.UTC().Format(time.RFC3339Nano) && d.Doc["device_time"] == nil
		if kept != c.kept || (!kept && d.Index != "sig-other-2026.10.11") {
			t.Errorf("age %v (max %v): kept %v, doc %v in %s", c.age, c.maxAge, kept, d.Doc, d.Index)
		}
	}
}

// TestIngestEventsKeepsSyslogDeviceTime checks that events the syslog
// receiver already refiled are counted, and that the pipeline applies the
// same window to events that arrive with any time.
func TestIngestEventsKeepsSyslogDeviceTime(t *testing.T) {
	b := &countingBulk{keep: true}
	p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}
	refiled := Event{Time: now, DeviceTime: time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC), Fields: map[string]any{"message": "old"}}
	ahead := Event{Time: now.Add(48 * time.Hour), Fields: map[string]any{"message": "ahead"}}
	res, err := p.IngestEvents(context.Background(), []Event{refiled, ahead})
	if err != nil || res.Retimed != 2 || p.Stats().Retimed != 2 {
		t.Fatalf("res %+v err %v", res, err)
	}
	if b.docs[0].Doc["device_time"] != "2001-01-01T00:00:00Z" || b.docs[1].Index != "sig-other-2026.10.11" || b.docs[1].Doc["device_time"] != "2026-10-13T12:00:00Z" {
		t.Errorf("docs %v", b.docs)
	}
}

func TestAdmitLimitsConcurrentRequests(t *testing.T) {
	p := &Pipeline{MaxConcurrent: 2}
	ctx := context.Background()
	r1, err1 := p.Admit(ctx, time.Second, "a")
	r2, err2 := p.Admit(ctx, time.Second, "a")
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	start := time.Now()
	if _, err := p.Admit(ctx, 50*time.Millisecond, "a"); !errors.Is(err, ErrBusy) || time.Since(start) < 50*time.Millisecond {
		t.Fatalf("third request: %v after %v", err, time.Since(start))
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		r1()
	}()
	r3, err := p.Admit(ctx, time.Second, "a")
	if err != nil {
		t.Fatalf("after a slot freed: %v", err)
	}
	r2()
	r3()
}

func TestAdmitDefaultSlots(t *testing.T) {
	p := &Pipeline{}
	ctx := context.Background()
	var release []func()
	for i := 0; i < DefaultMaxConcurrent; i++ {
		r, err := p.Admit(ctx, time.Second, "a")
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		release = append(release, r)
	}
	if _, err := p.Admit(ctx, 10*time.Millisecond, "a"); !errors.Is(err, ErrBusy) {
		t.Fatalf("request past the default: %v", err)
	}
	for _, r := range release {
		r()
	}
}

func TestAdmitSharesSlotsBetweenTokens(t *testing.T) {
	p := &Pipeline{MaxConcurrent: 4} // a share is 1 slot
	ctx := context.Background()
	// Alone, one token gets every slot.
	var busy []func()
	for i := 0; i < 4; i++ {
		r, err := p.Admit(ctx, time.Second, "busy")
		if err != nil {
			t.Fatalf("slot %d: %v", i+1, err)
		}
		busy = append(busy, r)
	}
	// The busy token queues first, then another token: a freed slot goes
	// to the other token, which holds less than its share.
	got := make(chan string, 2)
	// done tells the test this sender's release has finished, so the
	// final look at the slots does not race a release still running.
	done := make(chan struct{}, 2)
	wait := func(sender string) {
		defer func() { done <- struct{}{} }()
		r, err := p.Admit(ctx, 5*time.Second, sender)
		if err != nil {
			got <- "error " + err.Error()
			return
		}
		got <- sender
		r()
	}
	go wait("busy")
	waitFor(t, p, 1)
	go wait("quiet")
	waitFor(t, p, 2)
	busy[0]()
	if first := <-got; first != "quiet" {
		t.Errorf("first freed slot went to %q", first)
	}
	if second := <-got; second != "busy" {
		t.Errorf("then %q", second)
	}
	<-done
	<-done
	for _, r := range busy[1:] {
		r()
	}
	if s := p.limits().slots; s.held != 0 || len(s.per) != 0 || len(s.perTenant) != 0 || len(s.waiting) != 0 || len(s.waitingBy) != 0 {
		t.Errorf("left %+v", p.limits().slots)
	}
}

func TestAdmitTimeoutLeavesNoSlotBehind(t *testing.T) {
	p := &Pipeline{MaxConcurrent: 1}
	ctx, cancel := context.WithCancel(context.Background())
	r, _ := p.Admit(ctx, time.Second, "a")
	done := make(chan error)
	go func() {
		_, err := p.Admit(ctx, 5*time.Second, "b")
		done <- err
	}()
	waitFor(t, p, 1)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled wait: %v", err)
	}
	r()
	if r2, err := p.Admit(context.Background(), time.Second, "c"); err != nil {
		t.Fatalf("after the release: %v", err)
	} else {
		r2()
	}
}

// waitFor waits until n requests are queued for a slot.
func waitFor(t *testing.T, p *Pipeline, n int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		l := p.limits()
		l.slotsMu.Lock()
		got := len(l.slots.waiting)
		l.slotsMu.Unlock()
		if got == n {
			return
		}
	}
	t.Fatalf("never saw %d waiting", n)
}
