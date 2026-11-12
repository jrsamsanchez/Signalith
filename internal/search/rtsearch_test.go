// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// slowRex is a pattern Go's regexp runs slowly over long text of a's:
// every position starts up to 900 matches in progress.
const slowRex = `(?<v>a{0,900}Z)`

// TestRexStopsAtTheDeadline reproduces RT-03 (SRCH-02): rex checked the
// search's deadline only every 512 rows, so 500 rows of 2.5 KB ran for
// 14 seconds against a 100 ms deadline. Each regular expression call is
// now charged before it runs, so the search stops soon after its deadline,
// whichever command or function runs the pattern.
func TestRexStopsAtTheDeadline(t *testing.T) {
	text := strings.Repeat("a", 2500)
	for _, c := range []struct{ name, cmd string }{
		{"rex", `rex field=a "` + slowRex + `"`},
		{"rex mode=sed", `rex field=a mode=sed "s/a{0,900}Z/x/g"`},
		{"regex", `regex a="a{0,900}Z"`},
		{"makemv tokenizer", `makemv tokenizer="(a{0,900}Z)" a`},
		{"eval match", `eval m=match(a, "a{0,900}Z")`},
		{"eval replace", `eval m=replace(a, "a{0,900}Z", "x")`},
		{"where =~", `where a=~"a{0,900}Z"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			q := `| makeresults count=2000 | eval a="` + text + `" | ` + c.cmd + ` | stats count`
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, err := (&Engine{}).Run(ctx, q)
			took := time.Since(start)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("err = %v, want the deadline", err)
			}
			// About 20 ms a row; it used to run every row before
			// checking (40 seconds here).
			if took > 3*time.Second {
				t.Errorf("a search with a 100ms deadline ran for %v", took)
			}
		})
	}
}

// TestOneSlowRegexCallIsRefused: a single call over a long value cannot be
// interrupted, so one that would run for seconds is refused before it
// starts, with an error that says what to do.
func TestOneSlowRegexCallIsRefused(t *testing.T) {
	text := strings.Repeat("a", 250_000)
	start := time.Now()
	_, err := (&Engine{}).Run(context.Background(), `| makeresults | eval a="`+text+`" | rex field=a "`+slowRex+`"`)
	var qe *QueryError
	if !errors.As(err, &qe) || !strings.Contains(qe.Msg, "would take too long") {
		t.Errorf("err = %v, want the regular expression refused", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("refusing took %v", took)
	}
}

// TestFillnullValueIsCharged: fillnull put one value on every row without
// counting it, a cheap way to give rex megabytes of text to scan. Each
// copy now counts against the search's budget, as eval's do.
func TestFillnullValueIsCharged(t *testing.T) {
	big := strings.Repeat("b", 100_000)
	_, err := (&Engine{}).Run(context.Background(), `| makeresults count=10000 | fillnull value="`+big+`" a | stats count`)
	var qe *QueryError
	if !errors.As(err, &qe) || !strings.Contains(qe.Msg, "256 MB") {
		t.Errorf("err = %v, want the value budget", err)
	}
	// Ordinary fills are untouched.
	res, err := (&Engine{}).Run(context.Background(), `| makeresults count=10000 | fillnull value=0 a, b, c | stats sum(a) as s`)
	if err != nil || len(res.Rows) != 1 {
		t.Fatalf("fillnull value=0: %v %v", res, err)
	}
}

// TestRealisticRexFits: the charge leaves room for what searches do: rex
// over 10,000 rows of ordinary log lines, several times.
func TestRealisticRexFits(t *testing.T) {
	line := strings.Repeat("x", 1500) + " Failed password for alice from 192.0.2.4 port 22 ssh2"
	q := `| makeresults count=10000 | eval a="` + line + `"` +
		` | rex field=a "(?i)failed password for (?<user>\S+) from (?<ip>\d+\.\d+\.\d+\.\d+)"` +
		` | rex field=a "port (?<port>\d+)"` +
		` | rex field=a mode=sed "s/x+//"` +
		` | where match(a, "ssh\d")` +
		` | stats count by user, ip, port`
	res, err := (&Engine{}).Run(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 || fmt.Sprint(res.Rows[0]["count"]) != "10000" || res.Rows[0]["user"] != "alice" {
		t.Errorf("rows = %v", res.Rows)
	}
}

// TestUserResultIsCapped reproduces RT-02 (SRCH-01): a 25 KB search made a
// 250 MB result out of one shared value, which the API then wrote out
// after the search had freed its slot. A user's search now answers with
// at most MaxResultBytes; detections and other background searches,
// which write nothing out, are not held to it.
func TestUserResultIsCapped(t *testing.T) {
	q := `| makeresults count=10000 | eval a="` + strings.Repeat("a", 25_000) + `"`
	_, err := (&Engine{}).Run(ForUser(context.Background(), "mallory"), q)
	var qe *QueryError
	if !errors.As(err, &qe) || !strings.Contains(qe.Msg, fmt.Sprintf("%d MB a search may return", MaxResultBytes>>20)) {
		t.Errorf("err = %v, want the result cap", err)
	}
	if _, err := (&Engine{}).Run(Background(context.Background()), q); err != nil {
		t.Errorf("background search: %v", err)
	}

	// 10,000 ordinary events of 4 KB each still fit.
	event := strings.Repeat("e", 4000)
	e := &Engine{Store: funcStore(func(context.Context, string, map[string]any) (map[string]any, error) {
		return hits(10000, func(int) string { return event }), nil
	})}
	res, err := e.Run(ForUser(context.Background(), "alice"), `* | head 10000`)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 10000 {
		t.Errorf("%d rows, want 10000", len(res.Rows))
	}
}

// TestUserSharesAreForgotten covers SRCH-03's leak: the engine kept a
// share of the slots for every user that ever searched (for the public
// demo, every visitor's session). It is dropped once nothing of the
// user's holds or waits for a slot.
func TestUserSharesAreForgotten(t *testing.T) {
	e := &Engine{Store: funcStore(func(context.Context, string, map[string]any) (map[string]any, error) {
		return hits(1, func(int) string { return "x" }), nil
	})}
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			if _, err := e.Run(ForUser(context.Background(), fmt.Sprint("user", i%5)), `*`); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	e.slotsMu.Lock()
	n := len(e.perUser)
	e.slotsMu.Unlock()
	if n != 0 {
		t.Errorf("the engine still keeps %d users' shares", n)
	}
}

// TestValuesFromRowsAreNotWildcards reproduces SRCH-04: a value of * from
// a subsearch's rows or a map row became a wildcard term, so a detection
// shaped like "... NOT [search allowlist | fields user]" excluded every
// event once someone got user=* into the allowlist's source.
func TestValuesFromRowsAreNotWildcards(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	e := &Engine{Store: funcStore(func(_ context.Context, _ string, body map[string]any) (map[string]any, error) {
		b, _ := json.Marshal(body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		return hits(0, nil), nil
	})}
	for _, c := range []struct{ name, q string }{
		{"subsearch", `* NOT [| makeresults | eval user="*" | fields user]`},
		{"subsearch prefix", `* [| makeresults | eval user="adm?n*" | fields user]`},
		{"map", `| makeresults | eval user="*" | map search="search user=$user$"`},
		{"map in quotes", `| makeresults | eval user="a*" | map search="search NOT user=\"$user$\""`},
	} {
		t.Run(c.name, func(t *testing.T) {
			bodies = nil
			if _, err := e.Run(context.Background(), c.q); err != nil {
				t.Fatal(err)
			}
			if len(bodies) == 0 {
				t.Fatal("nothing searched")
			}
			body := bodies[len(bodies)-1]
			if strings.Contains(body, `"exists"`) || strings.Contains(body, `"wildcard"`) || !strings.Contains(body, `"term"`) {
				t.Errorf("body = %s, want a plain term", body)
			}
		})
	}
	// A wildcard written in map's own search is still one.
	bodies = nil
	if _, err := e.Run(context.Background(), `| makeresults | eval user="a*" | map search="search user=$user$ host=web*"`); err != nil {
		t.Fatal(err)
	}
	if body := bodies[len(bodies)-1]; !strings.Contains(body, `"wildcard"`) || !strings.Contains(body, `web*`) {
		t.Errorf("body = %s, want host=web* a wildcard", body)
	}

	// In memory too: only the row whose user is * itself matches.
	res, err := (&Engine{}).Run(context.Background(), `| makeresults count=2 | streamstats count as n | eval user=if(n=1, "*", "bob") | search [| makeresults | eval user="*" | fields user]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 || res.Rows[0]["user"] != "*" {
		t.Errorf("rows = %v, want only user=*", res.Rows)
	}
}
