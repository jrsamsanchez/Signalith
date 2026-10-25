// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package dashboards

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// fakeExec answers queries from a function and records what it ran.
type fakeExec struct {
	mu      sync.Mutex
	ran     []*query.Query
	active  atomic.Int32
	peak    atomic.Int32
	respond func(q *query.Query) (*search.Result, error)
}

func (f *fakeExec) Execute(ctx context.Context, q *query.Query) (*search.Result, error) {
	n := f.active.Add(1)
	defer f.active.Add(-1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	f.mu.Lock()
	f.ran = append(f.ran, q)
	f.mu.Unlock()
	time.Sleep(5 * time.Millisecond)
	return f.respond(q)
}

func TestPanelsRunInParallelAndFailAlone(t *testing.T) {
	ex := &fakeExec{respond: func(q *query.Query) (*search.Result, error) {
		s := q.String()
		switch {
		case strings.Contains(s, "boom"):
			return nil, errors.New("opensearch said no")
		case strings.Contains(s, "panic"):
			panic("bad row")
		case strings.Contains(s, "stats"):
			n := int64(42)
			if q.Latest != "" { // previous period
				n = 30
			}
			return &search.Result{Kind: "table", Columns: []string{"count"}, Rows: []search.Row{{"count": n}}}, nil
		}
		rows := make([]search.Row, 700)
		for i := range rows {
			rows[i] = search.Row{"user": fmt.Sprint(i)}
		}
		return &search.Result{Kind: "events", Columns: []string{"user"}, Rows: rows, Matched: 700}, nil
	}}
	panels := []Panel{
		{Title: "Count", Query: "datamodel=Authentication | stats count", Viz: VizSingle, Compare: true},
		{Title: "Bad", Query: "boom=1", Viz: VizTable},
		{Title: "Parse", Query: "a=1 | stats avg", Viz: VizTable},
		{Title: "Panics", Query: "panic=1", Viz: VizTable},
		{Title: "Events", Query: "datamodel=Change", Viz: VizTable},
		{Title: "Own range", Query: "datamodel=Change earliest=-7d", Viz: VizSingle, Compare: true},
		{Title: "More", Query: "x=1", Viz: VizTable},
		{Title: "More", Query: "x=2", Viz: VizTable},
	}
	r := &Runner{Engine: ex, Concurrency: 2}
	out := r.Run(context.Background(), panels, "24h")
	if len(out) != len(panels) {
		t.Fatalf("got %d results", len(out))
	}
	for i, res := range out {
		if res.Index != i {
			t.Errorf("result %d has index %d", i, res.Index)
		}
	}
	if out[0].Error != "" || fmt.Sprint(out[0].Value) != "42" || fmt.Sprint(out[0].Previous) != "30" || out[0].Field != "count" || out[0].Earliest != "-24h" {
		t.Errorf("single = %+v", out[0])
	}
	if out[1].Error != "opensearch said no" || out[1].Result != nil {
		t.Errorf("failing panel = %+v", out[1])
	}
	if !strings.Contains(out[2].Error, "at character") {
		t.Errorf("parse error = %+v", out[2])
	}
	if !strings.Contains(out[3].Error, "bad row") {
		t.Errorf("panic = %+v", out[3])
	}
	if out[4].Error != "" || len(out[4].Result.Rows) != 500 || !out[4].Result.Truncated {
		t.Errorf("events = rows %d truncated %v err %q", len(out[4].Result.Rows), out[4].Result.Truncated, out[4].Error)
	}
	if out[5].Earliest != "-7d" || fmt.Sprint(out[5].Value) != "700" || fmt.Sprint(out[5].Previous) != "700" {
		t.Errorf("own range = %+v", out[5])
	}
	if p := ex.peak.Load(); p > 2 {
		t.Errorf("ran %d panels at once, limit 2", p)
	}
	// The comparison searched the previous 24 hours.
	var sawPrev bool
	for _, q := range ex.ran {
		if q.Earliest == "-48h" && q.Latest == "-24h" {
			sawPrev = true
		}
	}
	if !sawPrev {
		t.Error("previous period not searched")
	}
}

func TestCompareNeedsRelativeRange(t *testing.T) {
	ex := &fakeExec{respond: func(q *query.Query) (*search.Result, error) {
		return &search.Result{Kind: "table", Columns: []string{"n"}, Rows: []search.Row{{"n": int64(1)}}}, nil
	}}
	r := &Runner{Engine: ex}
	res := r.RunPanel(context.Background(), Panel{Query: "* | stats count as n", Viz: VizSingle, Compare: true}, "0")
	if res.Previous != nil || !strings.Contains(res.CompareNote, "relative") {
		t.Errorf("all time compare = %+v", res)
	}
	res = r.RunPanel(context.Background(), Panel{Query: "* latest=-1h | stats count as n", Viz: VizSingle, Compare: true}, "24h")
	if res.Previous != nil || !strings.Contains(res.CompareNote, "latest") {
		t.Errorf("latest compare = %+v", res)
	}
}

func TestPreviousPeriodAndSingleValue(t *testing.T) {
	for in, want := range map[string]string{"-24h": "-48h -24h", "-15m": "-30m -15m", "-7d": "-14d -7d"} {
		e, l, ok := PreviousPeriod(in)
		if !ok || e+" "+l != want {
			t.Errorf("%s -> %s %s %v", in, e, l, ok)
		}
	}
	for _, bad := range []string{"0", "-7d@d", "2026-01-01T00:00:00Z", ""} {
		if _, _, ok := PreviousPeriod(bad); ok {
			t.Errorf("%q should not have a previous period", bad)
		}
	}
	res := &search.Result{Kind: "table", Columns: []string{"src", "count", "users"}, Rows: []search.Row{{"src": "a", "count": int64(5), "users": int64(2)}}}
	if f, v := SingleValue(res, ""); f != "count" || v != int64(5) {
		t.Errorf("first number = %s %v", f, v)
	}
	if f, v := SingleValue(res, "users"); f != "users" || v != int64(2) {
		t.Errorf("named = %s %v", f, v)
	}
	if f, v := SingleValue(&search.Result{Kind: "table"}, ""); f != "count" || v != int64(0) {
		t.Errorf("empty = %s %v", f, v)
	}
}

// OB-6: a panel whose search could not reach OpenSearch says so plainly,
// without the address and the connection error.
func TestRunErrOpenSearchDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	_, err = store.New(store.Config{URL: "http://" + addr, Timeout: time.Second}).Health(context.Background())
	if err == nil {
		t.Fatal("no error from a closed port")
	}
	if got := runErr(err); got != store.DownText || strings.Contains(got, addr) {
		t.Errorf("runErr = %q", got)
	}
}
