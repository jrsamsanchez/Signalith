package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// newTestSink returns a sink spooling to a new directory, closed when the
// test ends (Windows removes no directory holding an open file).
func newTestSink(t *testing.T, opts SinkOptions) *Sink {
	t.Helper()
	if opts.Dir == "" {
		opts.Dir = filepath.Join(t.TempDir(), "audit-spool")
	}
	s := NewSink(opts)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// spooled returns the events in the spool directory, oldest first.
func spooled(t *testing.T, dir string) []Event {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "seg-*.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	var out []Event
	for _, n := range names {
		data, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var ev Event
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				t.Fatalf("%s: %v", n, err)
			}
			out = append(out, ev)
		}
	}
	return out
}

func TestHandlerPassesRecordsAndSpoolsAuditOnes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	sink := newTestSink(t, SinkOptions{Dir: dir, Server: "srv-a", NodeID: "node-1", Epoch: func() int64 { return 7 }})
	var buf bytes.Buffer
	log := slog.New(Handler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}), sink))

	log.Info("plain line", "k", 1)
	log.Info("users.create: added bob", "audit", true, "by", "alice", "user", "bob", "client", "10.0.0.1",
		"role", "admin", slog.Group("g", "x", 1))
	log.Debug("hidden", "audit", true)
	sink.Close()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("log has %d lines, want 2:\n%s", len(lines), buf.String())
	}
	if !strings.Contains(lines[0], `"msg":"plain line"`) || !strings.Contains(lines[0], `"k":1`) {
		t.Errorf("plain line changed: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"audit":true`) || !strings.Contains(lines[1], `"g":{"x":1}`) {
		t.Errorf("audit line changed: %s", lines[1])
	}

	evs := spooled(t, dir)
	if len(evs) != 1 {
		t.Fatalf("spooled %d events, want 1: %+v", len(evs), evs)
	}
	ev := evs[0]
	want := Event{Server: "srv-a", NodeID: "node-1", User: "alice", Action: "users.create", Target: "bob",
		Message: "users.create: added bob", SourceIP: "10.0.0.1", Level: "INFO", Epoch: 7}
	got := ev
	got.Time, got.Fields, got.Seq = time.Time{}, nil, 0
	if !reflect.DeepEqual(got, want) {
		t.Errorf("event = %+v\nwant    %+v", got, want)
	}
	if len(ev.Fields) != 2 || ev.Fields["role"] != "admin" || ev.Fields["g.x"] != "1" {
		t.Errorf("fields = %v", ev.Fields)
	}
	if ev.Seq != 1 || ev.Time.IsZero() || ev.Time.Location() != time.UTC {
		t.Errorf("seq %d, time %v", ev.Seq, ev.Time)
	}
	if id := ev.ID(); len(id) != 24 || id != ev.ID() {
		t.Errorf("id %q", id)
	}
}

func TestHandlerKeepsAuditLinesBelowTheLogLevel(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	sink := newTestSink(t, SinkOptions{Dir: dir})
	var buf bytes.Buffer
	log := slog.New(Handler(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}), sink))
	log.Info("feeds.delete: removed", "audit", true, "by", "root", "feed", "f1")
	log.Info("not audit")
	sink.Close()
	if buf.Len() != 0 {
		t.Errorf("log got %q", buf.String())
	}
	evs := spooled(t, dir)
	if len(evs) != 1 || evs[0].Action != "feeds.delete" || evs[0].Target != "f1" || evs[0].User != "root" {
		t.Errorf("spooled %+v", evs)
	}
}

func TestHandlerMapping(t *testing.T) {
	for _, tc := range []struct {
		name  string
		msg   string
		args  []any
		check func(Event) bool
	}{
		{"user without by is the user", "signed in", []any{"user", "bob", "remote", "1.2.3.4"},
			func(e Event) bool {
				return e.User == "bob" && e.Target == "" && e.SourceIP == "1.2.3.4" && e.Action == ""
			}},
		{"action attribute", "sample data loaded", []any{"action", "sample.load", "index", "ix"},
			func(e Event) bool { return e.Action == "sample.load" && e.Target == "ix" }},
		{"message with spaces before colon", "the cluster: founded", []any{"username", "u", "ip", "::1"},
			func(e Event) bool { return e.Action == "" && e.User == "u" && e.SourceIP == "::1" }},
		{"long values are cut", "x: y", []any{"big", strings.Repeat("a", 5000)},
			func(e Event) bool { return len(e.Fields["big"]) < 2100 && strings.HasPrefix(e.Fields["big"], "aaa") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "spool")
			sink := newTestSink(t, SinkOptions{Dir: dir})
			log := slog.New(Handler(slog.DiscardHandler, sink))
			log.Info(tc.msg, append([]any{"audit", true}, tc.args...)...)
			sink.Close()
			evs := spooled(t, dir)
			if len(evs) != 1 || !tc.check(evs[0]) {
				t.Errorf("spooled %+v", evs)
			}
		})
	}
}

func TestHandlerFieldsAreCapped(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	sink := newTestSink(t, SinkOptions{Dir: dir})
	args := []any{"audit", true}
	for i := range 100 {
		args = append(args, "f"+string(rune('A'+i/26))+string(rune('a'+i%26)), i)
	}
	slog.New(Handler(slog.DiscardHandler, sink)).Info("x: y", args...)
	sink.Close()
	if evs := spooled(t, dir); len(evs) != 1 || len(evs[0].Fields) != MaxFields {
		t.Errorf("fields: %d", len(evs[0].Fields))
	}
}

func TestDisabledSinkSpoolsNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	sink := newTestSink(t, SinkOptions{Dir: dir})
	sink.SetEnabled(false)
	var buf bytes.Buffer
	log := slog.New(Handler(slog.NewTextHandler(&buf, nil), sink))
	log.Info("users.create: x", "audit", true, "by", "a")
	sink.Close()
	if evs := spooled(t, dir); len(evs) != 0 {
		t.Errorf("spooled %+v", evs)
	}
	if !strings.Contains(buf.String(), "users.create") {
		t.Errorf("log lost the line: %q", buf.String())
	}
	// With no sink at all, records still pass.
	buf.Reset()
	slog.New(Handler(slog.NewTextHandler(&buf, nil), nil)).Info("x", "audit", true)
	if !strings.Contains(buf.String(), "audit=true") {
		t.Errorf("log: %q", buf.String())
	}
}

func TestWithAttrsAuditLoggerIsCaptured(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	sink := newTestSink(t, SinkOptions{Dir: dir})
	var buf bytes.Buffer
	base := slog.New(Handler(slog.NewJSONHandler(&buf, nil), sink))
	alog := base.With("audit", true, "by", "carol")
	alog.Info("sample data loaded", "id", "s1")
	alog.WithGroup("req").Info("users.delete: removed", "user", "dave")
	base.Info("not audit", "by", "x")
	sink.Close()

	evs := spooled(t, dir)
	if len(evs) != 2 {
		t.Fatalf("spooled %+v", evs)
	}
	if evs[0].User != "carol" || evs[0].Action != "" || evs[0].Fields["id"] != "s1" {
		t.Errorf("first %+v", evs[0])
	}
	// Inside a group, the key is req.user: a field, not the target.
	if evs[1].User != "carol" || evs[1].Action != "users.delete" || evs[1].Fields["req.user"] != "dave" {
		t.Errorf("second %+v", evs[1])
	}
	if !strings.Contains(buf.String(), `"req":{"user":"dave"}`) {
		t.Errorf("groups not passed on: %s", buf.String())
	}
}

func TestHandlerEnabled(t *testing.T) {
	sink := newTestSink(t, SinkOptions{})
	next := slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelError})
	h := Handler(next, sink)
	ctx := context.Background()
	if !h.Enabled(ctx, slog.LevelInfo) || h.Enabled(ctx, slog.LevelDebug) {
		t.Error("enabled sink: want Info on, Debug off")
	}
	sink.SetEnabled(false)
	if h.Enabled(ctx, slog.LevelInfo) || !h.Enabled(ctx, slog.LevelError) {
		t.Error("disabled sink: want next's levels")
	}
}
