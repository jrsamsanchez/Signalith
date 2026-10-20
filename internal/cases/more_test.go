// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package cases

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// scriptDoer answers requests in turn with the answers given, recording
// each request.
type scriptDoer struct {
	answers []answer
	calls   []string
	bodies  []string
}

type answer struct {
	resp string
	err  error
}

func (d *scriptDoer) Do(_ context.Context, method, path string, body any, out any) error {
	b, _ := json.Marshal(body)
	d.calls = append(d.calls, method+" "+path)
	d.bodies = append(d.bodies, string(b))
	if len(d.answers) == 0 {
		return nil
	}
	a := d.answers[0]
	d.answers = d.answers[1:]
	if a.err != nil {
		return a.err
	}
	if out != nil && a.resp != "" {
		return json.Unmarshal([]byte(a.resp), out)
	}
	return nil
}

func TestOpenSearchMappings(t *testing.T) {
	ctx := context.Background()
	d := &scriptDoer{answers: []answer{{err: &store.Error{Status: 400, Body: "resource_already_exists_exception"}}}}
	s := NewOpenSearch(d, "sig")
	if err := s.EnsureIndex(ctx); err != nil {
		t.Errorf("index exists = %v", err)
	}
	for i, f := range []func(context.Context) error{s.Upgrade, s.EnsureSampleField, s.EnsureTicketsField} {
		if err := f(ctx); err != nil || d.calls[len(d.calls)-1] != "PUT /sig_cases/_mapping" {
			t.Errorf("mapping %d = %v %v", i, err, d.calls)
		}
	}
	if !strings.Contains(d.bodies[len(d.bodies)-1], `"tickets"`) || strings.Contains(d.bodies[len(d.bodies)-1], `"sample"`) {
		t.Errorf("tickets mapping = %s", d.bodies[len(d.bodies)-1])
	}
}

func TestOpenSearchCaseDocs(t *testing.T) {
	ctx := context.Background()
	d := &scriptDoer{}
	s := NewOpenSearch(d, "sig")
	missing := &store.Error{Status: 404}
	boom := errors.New("down")

	d.answers = []answer{{err: missing}, {err: boom}}
	if err := s.Delete(ctx, "c1"); err != nil {
		t.Errorf("delete missing = %v", err)
	}
	if err := s.Delete(ctx, "c1"); !errors.Is(err, boom) {
		t.Errorf("delete failure = %v", err)
	}
	d.answers = []answer{{err: missing}, {err: boom}, {resp: `{"found":false}`}}
	for i, want := range []error{ErrNotFound, boom, ErrNotFound} {
		if _, err := s.Get(ctx, "c1"); !errors.Is(err, want) {
			t.Errorf("get %d = %v", i, err)
		}
	}

	found := answer{resp: `{"found":true,"_source":{"id":"c1","title":"Phish","status":"open"}}`}
	d.answers = []answer{found, {}}
	d.calls = nil
	c, err := s.Modify(ctx, "c1", func(c *Case) (bool, error) { c.Title = "Phishing"; return true, nil })
	if err != nil || c.Title != "Phishing" || len(d.calls) != 2 || !strings.HasPrefix(d.calls[1], "PUT /sig_cases/_doc/c1") {
		t.Errorf("modify = %+v %v %v", c, err, d.calls)
	}
	d.answers = []answer{found}
	d.calls = nil
	if _, err := s.Modify(ctx, "c1", func(*Case) (bool, error) { return false, nil }); err != nil || len(d.calls) != 1 {
		t.Errorf("unchanged = %v %v", err, d.calls)
	}
	nope := errors.New("not allowed")
	d.answers = []answer{found}
	if _, err := s.Modify(ctx, "c1", func(*Case) (bool, error) { return false, nope }); !errors.Is(err, nope) {
		t.Errorf("change failure = %v", err)
	}
	d.answers = []answer{{err: missing}}
	if _, err := s.Modify(ctx, "c1", func(*Case) (bool, error) { return true, nil }); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
	d.answers = []answer{found, {err: boom}}
	if _, err := s.Modify(ctx, "c1", func(*Case) (bool, error) { return true, nil }); !errors.Is(err, boom) {
		t.Errorf("write failure = %v", err)
	}
}

func TestOpenSearchCaseSearch(t *testing.T) {
	ctx := context.Background()
	d := &scriptDoer{answers: []answer{{resp: `{"hits":{"total":{"value":3},"hits":[{"_source":{"id":"c1"}},{"_source":{"id":"c2"}}]}}`}}}
	s := NewOpenSearch(d, "sig")
	since := time.Now().Add(-time.Hour)
	got, total, err := s.Search(ctx, Filter{Status: []string{"open"}, FindingID: "f1", UpdatedSince: since, Ticketed: true, Text: " bob ", Limit: 20000})
	if err != nil || total != 3 || len(got) != 2 || got[1].ID != "c2" {
		t.Fatalf("search = %v %d %v", got, total, err)
	}
	for _, want := range []string{`"terms":{"status":["open"]}`, `"term":{"findings":"f1"}`, `"updated":{"gte":`,
		`"exists":{"field":"tickets.key"}`, `"minimum_should_match":1`, `"size":10000`} {
		if !strings.Contains(d.bodies[0], want) {
			t.Errorf("search lacks %s: %s", want, d.bodies[0])
		}
	}
	d.answers = []answer{{resp: `{"hits":{"hits":[]}}`}}
	s.Search(ctx, Filter{})
	if !strings.Contains(d.bodies[1], `"match_all"`) || !strings.Contains(d.bodies[1], `"size":200`) {
		t.Errorf("empty filter = %s", d.bodies[1])
	}
	boom := errors.New("down")
	d.answers = []answer{{err: boom}}
	if _, _, err := s.Search(ctx, Filter{}); !errors.Is(err, boom) {
		t.Errorf("search failure = %v", err)
	}
}

func TestCaseLimitsAndTickets(t *testing.T) {
	now := time.Now()
	c := &Case{Tickets: []Ticket{{Connection: "jira-1", Key: "SOC-4"}}}
	if tk, ok := c.Ticket("jira-1"); !ok || tk.Key != "SOC-4" {
		t.Errorf("ticket = %+v %v", tk, ok)
	}
	if _, ok := c.Ticket("snow"); ok {
		t.Error("found another connection's ticket")
	}
	bad := "done"
	long := strings.Repeat("x", MaxTextLen+1)
	if err := (Update{Status: &bad}).Validate(); err == nil || !strings.Contains(err.Error(), "status") {
		t.Errorf("status = %v", err)
	}
	if err := (Update{Description: &long}).Validate(); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("long = %v", err)
	}

	full := &Case{}
	for range MaxEntries {
		full.Entries = append(full.Entries, Entry{Kind: KindNote})
	}
	if _, err := full.AddEntry(Entry{Kind: KindNote}, "sam", now); err == nil {
		t.Error("an entry past the limit was added")
	}
	if ok, err := full.AddFinding(&findings.Finding{ID: "f1"}, "sam", now); ok || err == nil {
		t.Errorf("finding with a full timeline = %v %v", ok, err)
	}
	many := &Case{}
	for i := range MaxFindings {
		many.Findings = append(many.Findings, fmt.Sprint(i))
	}
	if ok, err := many.AddFinding(&findings.Finding{ID: "new"}, "sam", now); ok || err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("too many findings = %v %v", ok, err)
	}
	if many.RemoveFinding("absent", "sam", now) {
		t.Error("removed a finding that was not linked")
	}
	if ev, err := TrimEvent(map[string]any{"user": "bob"}); err != nil || ev["user"] != "bob" {
		t.Errorf("small event = %v %v", ev, err)
	}
	if _, err := TrimEvent(map[string]any{"bad": make(chan int)}); err == nil {
		t.Error("an event that is not JSON was taken")
	}
	if got := modifyResult(store.ErrNotFound); !errors.Is(got, ErrNotFound) {
		t.Errorf("modifyResult = %v", got)
	}
	if (changeError{errors.New("x")}).Error() != "x" {
		t.Error("changeError")
	}
}

func TestMemoryCaseEdges(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	if err := m.Save(ctx, &Case{ID: "nope"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("save missing = %v", err)
	}
	now := time.Now()
	for i := range 4 {
		c := &Case{ID: fmt.Sprint(i), Status: "open", Updated: now.Add(-time.Duration(i) * time.Hour)}
		if i == 0 {
			c.Tickets = []Ticket{{Connection: "j", Key: "K-1"}}
		}
		m.Create(ctx, c)
	}
	c, _ := m.Get(ctx, "1")
	c.Title = "saved"
	if err := m.Save(ctx, c); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Get(ctx, "1"); got.Title != "saved" {
		t.Errorf("saved = %+v", got)
	}
	if got, _, _ := m.Search(ctx, Filter{Ticketed: true}); len(got) != 1 || got[0].ID != "0" {
		t.Errorf("ticketed = %v", got)
	}
	if got, _, _ := m.Search(ctx, Filter{UpdatedSince: now.Add(-90 * time.Minute)}); len(got) != 2 {
		t.Errorf("updated since = %d", len(got))
	}
	if got, total, _ := m.Search(ctx, Filter{Limit: 1}); len(got) != 1 || total != 4 {
		t.Errorf("limit = %d of %d", len(got), total)
	}
	if got, err := m.Modify(ctx, "2", func(*Case) (bool, error) { return false, nil }); err != nil || got.ID != "2" {
		t.Errorf("unchanged = %+v %v", got, err)
	}
}
