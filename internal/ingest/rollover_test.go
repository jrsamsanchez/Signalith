package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// catIndices answers _cat/indices with rows as OpenSearch gives them with
// bytes=b: pri and pri.store.size as text.
type catIndices struct {
	rows  []map[string]any
	paths []string
	err   error
}

func (c *catIndices) Do(_ context.Context, method, path string, _ any, out any) error {
	c.paths = append(c.paths, method+" "+path)
	if c.err != nil {
		return c.err
	}
	b, _ := json.Marshal(c.rows)
	return json.Unmarshal(b, out)
}

func row(index string, pri int, gb float64) map[string]any {
	return map[string]any{"index": index, "pri": strconv.Itoa(pri), "pri.store.size": strconv.FormatInt(int64(gb*(1<<30)), 10)}
}

// A day's index goes on in its next part once its newest part holds
// MaxShardBytes per primary shard; other days and models are not touched.
func TestRolloverMovesFullDays(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	c := &catIndices{rows: []map[string]any{
		row("sig-network-2026.10.17", 2, 90),   // 45 GB a shard: full
		row("sig-endpoint-2026.10.17", 2, 30),  // 15 GB a shard
		row("sig-dns-2026.10.17", 1, 50),       // full,
		row("sig-dns-2026.10.17-2", 1, 41),     // and so is its part 2,
		row("sig-dns-2026.10.17-3", 1, 1),      // so part 3 is written
		row("sig-web-2026.10.16", 1, 39),       // yesterday, not full
		row("sig-auth-2026.10.16-2", 1, 3),     // yesterday's part 2
		row("sig-other-2026.10.17", 1, 0),      // empty
		row("sig-network-2026.10.17-x", 1, 99), // not a part
		row("sig-red-2026.10.17", 1, 0),        // replaced below
	}}
	c.rows[len(c.rows)-1]["pri.store.size"] = nil // a red index: size unknown
	r := &Rollover{Client: c, Prefix: "sig", MaxShardBytes: 40 << 30, Now: func() time.Time { return now }}
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	for day, want := range map[string]string{
		"sig-network-2026.10.17":  "sig-network-2026.10.17-2",
		"sig-endpoint-2026.10.17": "sig-endpoint-2026.10.17",
		"sig-dns-2026.10.17":      "sig-dns-2026.10.17-3",
		"sig-web-2026.10.16":      "sig-web-2026.10.16",
		"sig-auth-2026.10.16":     "sig-auth-2026.10.16-2",
		"sig-other-2026.10.17":    "sig-other-2026.10.17",
		"sig-red-2026.10.17":      "sig-red-2026.10.17",
		"sig-new-2026.10.17":      "sig-new-2026.10.17",
	} {
		if got := r.Index(day); got != want {
			t.Errorf("%s: writes to %s, want %s", day, got, want)
		}
	}
	// It asks for yesterday, today and tomorrow only, sizes in bytes.
	if len(c.paths) != 1 || !strings.Contains(c.paths[0], "sig-%2A-2026.10.16%2A,sig-%2A-2026.10.17%2A,sig-%2A-2026.10.18%2A") ||
		!strings.Contains(c.paths[0], "bytes=b") {
		t.Errorf("asked %v", c.paths)
	}

	// Once the next part fills too, the one after it is written.
	c.rows = append(c.rows, row("sig-network-2026.10.17-2", 2, 81))
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.Index("sig-network-2026.10.17"); got != "sig-network-2026.10.17-3" {
		t.Errorf("after part 2 filled: %s", got)
	}
}

// When OpenSearch cannot be asked, the parts already known are kept, and
// a missing pattern (no index yet today) writes each day's index.
func TestRolloverKeepsPartsOnError(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	c := &catIndices{rows: []map[string]any{row("sig-network-2026.10.17", 1, 41)}}
	r := &Rollover{Client: c, Prefix: "sig", MaxShardBytes: 40 << 30, Now: func() time.Time { return now }}
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.err = &store.Error{Status: http.StatusServiceUnavailable, Body: "busy"}
	if err := r.Check(context.Background()); err == nil {
		t.Error("no error from a refused check")
	}
	if got := r.Index("sig-network-2026.10.17"); got != "sig-network-2026.10.17-2" {
		t.Errorf("after a failed check: %s", got)
	}
	c.err = &store.Error{Status: http.StatusNotFound, Body: "index_not_found_exception"}
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.Index("sig-network-2026.10.17"); got != "sig-network-2026.10.17" {
		t.Errorf("no indices: %s", got)
	}
	var none *Rollover
	if got := none.Index("sig-network-2026.10.17"); got != "sig-network-2026.10.17" {
		t.Errorf("nil rollover: %s", got)
	}
}

// The pipeline writes a full day's events to the part rollover picked,
// and other days to their day's index.
func TestPipelineWritesToRolledPart(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	c := &catIndices{rows: []map[string]any{row("sig-network-2026.10.17", 1, 41)}}
	r := &Rollover{Client: c, Prefix: "sig", MaxShardBytes: 40 << 30, Now: func() time.Time { return now }}
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := &fakeBulk{}
	p := &Pipeline{Store: st, Prefix: "sig", Now: func() time.Time { return now }, Rollover: r}
	_, err := p.write(context.Background(), []Event{
		{Time: now, Model: "Network", Fields: map[string]any{"src_ip": "10.0.0.1"}},
		{Time: now, Model: "Endpoint", Fields: map[string]any{"host": "a"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range st.docs {
		got = append(got, d.Index)
	}
	if strings.Join(got, " ") != "sig-network-2026.10.17-2 sig-endpoint-2026.10.17" {
		t.Errorf("written to %v", got)
	}
}

// Failing checks are logged at debug level, then warned about once after
// RolloverWarnAfter, and the first success after the warning says so.
func TestRolloverWarnsWhenChecksKeepFailing(t *testing.T) {
	var buf strings.Builder
	r := &Rollover{Prefix: "sig", Log: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	var f rolloverFailures
	at := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	fail := errors.New("403 no permission")
	levels := func() string {
		var out []string
		for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			_, rest, _ := strings.Cut(l, "level=")
			lvl, _, _ := strings.Cut(rest, " ")
			out = append(out, lvl)
		}
		buf.Reset()
		return strings.Join(out, " ")
	}
	for i := range 12 {
		f.note(r, fail, at.Add(time.Duration(i)*time.Minute))
	}
	if got := levels(); got != strings.TrimSpace(strings.Repeat("DEBUG ", 10)+"WARN DEBUG") {
		t.Errorf("12 failed checks a minute apart logged %s", got)
	}
	f.note(r, nil, at.Add(12*time.Minute))
	f.note(r, nil, at.Add(13*time.Minute))
	if got := levels(); got != "INFO" {
		t.Errorf("after the warning, two good checks logged %s", got)
	}
	f.note(r, fail, at.Add(14*time.Minute))
	if got := levels(); got != "DEBUG" {
		t.Errorf("a new failure logged %s", got)
	}
}
