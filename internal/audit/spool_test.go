package audit

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const testPrefix = "sgt"

func count(t *testing.T, c *store.Client) int {
	t.Helper()
	var out struct {
		Count int `json:"count"`
	}
	if err := c.Do(context.Background(), http.MethodGet, "/"+Pattern(testPrefix)+"/_count", nil, &out); err != nil {
		t.Fatal(err)
	}
	return out.Count
}

func segments(t *testing.T, dir string) []string {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "seg-*.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	return names
}

func TestSpoolCapDropsOldestAndRecordsTheLoss(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	s := newTestSink(t, SinkOptions{Dir: dir, MaxBytes: 4000})
	s.segMax = 600
	msg := strings.Repeat("m", 100)
	n := 0
	for s.Stats().Lost == 0 {
		n++
		s.Add(Event{Time: time.Now(), Action: "x.y", Message: fmt.Sprintf("%d %s", n, msg)})
		if n > 1000 {
			t.Fatal("the cap never dropped anything")
		}
	}
	n++
	s.Add(Event{Time: time.Now(), Action: "x.y", Message: fmt.Sprintf("%d %s", n, msg)})
	s.Close()

	st := s.Stats()
	if st.SpooledBytes > 4000 {
		t.Errorf("spool holds %d bytes, cap 4000", st.SpooledBytes)
	}
	var size int64
	for _, p := range segments(t, dir) {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		size += fi.Size()
	}
	if size != st.SpooledBytes {
		t.Errorf("files hold %d bytes, stats say %d", size, st.SpooledBytes)
	}
	evs := spooled(t, dir)
	var lost []Event
	for _, ev := range evs {
		if ev.Action == "audit.lost" {
			lost = append(lost, ev)
		}
	}
	if len(lost) != 1 || lost[0].Fields["lost"] != fmt.Sprint(st.Lost) || lost[0].Message != "audit records lost: the spool was full" {
		t.Fatalf("lost events %+v, stats %+v", lost, st)
	}
	if strings.HasPrefix(evs[0].Message, "1 ") {
		t.Error("the oldest event was kept")
	}
	if last := evs[len(evs)-1]; !strings.HasPrefix(last.Message, fmt.Sprintf("%d ", n)) {
		t.Errorf("newest event missing, last is %q", last.Message)
	}
}

func TestFlushWritesMonthlyIndicesAndEmptiesTheSpool(t *testing.T) {
	fake := ostest.New(t)
	c := store.New(store.Config{URL: fake.URL})
	dir := filepath.Join(t.TempDir(), "spool")
	s := newTestSink(t, SinkOptions{Dir: dir, Client: c, Prefix: testPrefix, Server: "a", NodeID: "n1"})
	sep := time.Date(2026, 9, 30, 23, 59, 59, 123456789, time.UTC)
	oct := time.Date(2026, 10, 1, 0, 0, 1, 0, time.FixedZone("x", 3600)) // still September in UTC
	s.Add(Event{Time: sep, Action: "users.create", User: "alice", Message: "users.create: bob", Fields: map[string]string{"k": "v"}})
	s.Add(Event{Time: oct.Add(time.Hour), Action: "users.delete", Message: "users.delete: bob"})
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	evs := []Event{{Time: sep, NodeID: "n1", Seq: 1}, {Time: oct.Add(time.Hour).UTC(), NodeID: "n1", Seq: 2}}
	src := fake.Source(testPrefix+"_audit-2026.09", evs[0].ID())
	if src == nil || src["user"] != "alice" || src["server"] != "a" || src["@timestamp"] != "2026-09-30T23:59:59.123Z" {
		t.Errorf("september event: %v (indices %v)", src, fake.Indices())
	}
	if f, _ := src["fields"].(map[string]any); f["k"] != "v" {
		t.Errorf("fields: %v", src["fields"])
	}
	if fake.Source(testPrefix+"_audit-2026.10", evs[1].ID()) == nil {
		t.Errorf("october event missing (indices %v)", fake.Indices())
	}
	if segs := segments(t, dir); len(segs) != 0 {
		t.Errorf("segments left: %v", segs)
	}
	if st := s.Stats(); st.SpooledBytes != 0 || st.Written != 2 || st.LastError != "" || st.LastFlush.IsZero() {
		t.Errorf("stats %+v", st)
	}
}

func TestReplayAndRestartWriteNoDuplicates(t *testing.T) {
	fake := ostest.New(t)
	c := store.New(store.Config{URL: fake.URL})
	dir := filepath.Join(t.TempDir(), "spool")

	// A server spools while OpenSearch is not configured, then stops.
	first := NewSink(SinkOptions{Dir: dir, NodeID: "n1", Prefix: testPrefix})
	for i := range 3 {
		first.Add(Event{Time: time.Now(), Message: fmt.Sprint("event ", i)})
	}
	first.Close()
	segs := segments(t, dir)
	if len(segs) != 1 {
		t.Fatalf("segments %v", segs)
	}
	saved, err := os.ReadFile(segs[0])
	if err != nil {
		t.Fatal(err)
	}

	// After the restart the spooled events are written.
	second := newTestSink(t, SinkOptions{Dir: dir, NodeID: "n1", Prefix: testPrefix, Client: c})
	if st := second.Stats(); st.SpooledBytes != int64(len(saved)) {
		t.Errorf("restart picked up %d bytes, want %d", st.SpooledBytes, len(saved))
	}
	second.Add(Event{Time: time.Now(), Message: "after restart"})
	second.Close()
	if segs := segments(t, dir); len(segs) != 2 || segs[1] <= segs[0] {
		t.Errorf("new segment does not follow the old ones: %v", segs)
	}
	if err := second.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := count(t, c); n != 4 {
		t.Fatalf("stored %d events, want 4", n)
	}

	// The same segment written again (a crash before it was deleted)
	// stores nothing twice.
	if err := os.WriteFile(segs[0], saved, 0o666); err != nil {
		t.Fatal(err)
	}
	third := newTestSink(t, SinkOptions{Dir: dir, NodeID: "n1", Prefix: testPrefix, Client: c})
	if err := third.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := count(t, c); n != 4 {
		t.Errorf("stored %d events after the replay, want 4", n)
	}
	if st := third.Stats(); st.Written != 3 || st.SpooledBytes != 0 {
		t.Errorf("stats %+v", st)
	}
}

func TestBlockedOpenSearchKeepsTheSpool(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block func(*ostest.Server)
	}{
		{"cluster block", func(f *ostest.Server) { f.Block(true) }},
		{"429 on the request", func(f *ostest.Server) {
			f.SetFault(func(method, path string) *ostest.Fault {
				if strings.Contains(path, "_bulk") {
					return &ostest.Fault{Status: 429, Type: "es_rejected_execution_exception"}
				}
				return nil
			})
		}},
		{"503 on the request", func(f *ostest.Server) { f.FailN(1, http.MethodPost, "_bulk", 503, "unavailable") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := ostest.New(t)
			c := store.New(store.Config{URL: fake.URL})
			dir := filepath.Join(t.TempDir(), "spool")
			s := newTestSink(t, SinkOptions{Dir: dir, Client: c, Prefix: testPrefix})
			s.Add(Event{Time: time.Now(), Message: "one"})
			s.Add(Event{Time: time.Now(), Message: "two"})
			tc.block(fake)
			if err := s.Flush(context.Background()); err == nil {
				t.Fatal("flush succeeded while OpenSearch refused writes")
			}
			if segs := segments(t, dir); len(segs) != 1 {
				t.Errorf("segments %v", segs)
			}
			if st := s.Stats(); st.LastError == "" || st.SpooledBytes == 0 || st.Lost != 0 {
				t.Errorf("stats %+v", st)
			}
			fake.Block(false)
			fake.SetFault(nil)
			if err := s.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			if n := count(t, c); n != 2 {
				t.Errorf("stored %d, want 2", n)
			}
			if segs := segments(t, dir); len(segs) != 0 {
				t.Errorf("segments left %v", segs)
			}
		})
	}
}

func TestConcurrentAddAndRun(t *testing.T) {
	fake := ostest.New(t)
	c := store.New(store.Config{URL: fake.URL})
	dir := filepath.Join(t.TempDir(), "spool")
	s := newTestSink(t, SinkOptions{Dir: dir, Client: c, Prefix: testPrefix, NodeID: "n", Every: 5 * time.Millisecond})
	s.segMax = 2000
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	var wg sync.WaitGroup
	for g := range 20 {
		wg.Go(func() {
			for i := range 50 {
				s.Add(Event{Time: time.Now(), Message: fmt.Sprint(g, " ", i)})
			}
		})
	}
	wg.Wait()
	cancel()
	<-done
	if n := count(t, c); n != 1000 {
		t.Errorf("stored %d, want 1000 (stats %+v)", n, s.Stats())
	}
}

func TestEnsureTemplate(t *testing.T) {
	fake := ostest.New(t)
	c := store.New(store.Config{URL: fake.URL})
	if err := EnsureTemplate(context.Background(), c, testPrefix, ""); err != nil {
		t.Fatal(err)
	}
	raw := string(fake.Template(testPrefix + "_audit"))
	for _, want := range []string{`"index_patterns":["sgt_audit-*"]`, `"priority":500`, `"auto_expand_replicas":"0-1"`,
		`"managed_by":"signalith"`, `"dynamic":"false"`, `"fields":{"enabled":false,"type":"object"}`} {
		if !strings.Contains(raw, want) {
			t.Errorf("template lacks %s: %s", want, raw)
		}
	}
	if err := EnsureTemplate(context.Background(), c, testPrefix, "0-2"); err != nil {
		t.Fatal(err)
	}
	if raw := string(fake.Template(testPrefix + "_audit")); !strings.Contains(raw, `"auto_expand_replicas":"0-2"`) {
		t.Errorf("replicas not used: %s", raw)
	}
	if got := IndexName("p", time.Date(2026, 1, 31, 23, 0, 0, 0, time.FixedZone("w", -3600))); got != "p_audit-2026.02" {
		t.Errorf("IndexName = %s", got)
	}
}
