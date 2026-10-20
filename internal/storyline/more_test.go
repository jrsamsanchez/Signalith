// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package storyline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

func TestCellReaders(t *testing.T) {
	for _, c := range []struct {
		in   any
		want string
	}{
		{nil, ""}, {"a", "a"}, {[]any{"b", "c"}, "b"}, {[]any{}, ""}, {[]string{"d"}, "d"}, {[]string{}, ""},
		{json.Number("12"), "12"}, {1.5, "1.5"}, {true, "true"},
	} {
		if got := str(c.in); got != c.want {
			t.Errorf("str(%#v) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := strs([]string{"x", "y"}); !slices.Equal(got, []string{"x", "y"}) {
		t.Errorf("strs = %v", got)
	}
	if got := strs([]any{"x", "", 3.0}); !slices.Equal(got, []string{"x", "3"}) {
		t.Errorf("strs any = %v", got)
	}
	if strs(nil) != nil || strs("") != nil || !slices.Equal(strs("one"), []string{"one"}) {
		t.Error("strs single")
	}
	for in, want := range map[any]float64{2.5: 2.5, 3: 3, int64(4): 4, json.Number("5.5"): 5.5, "6": 6} {
		if got, ok := num(in); !ok || got != want {
			t.Errorf("num(%#v) = %v %v", in, got, ok)
		}
	}
	for _, in := range []any{json.Number("x"), "seven", true} {
		if _, ok := num(in); ok {
			t.Errorf("num(%#v) worked", in)
		}
	}
}

func TestEntityOf(t *testing.T) {
	for _, c := range []struct {
		field string
		v     any
		row   map[string]any
		want  Entity
		ok    bool
	}{
		{"user", "*", nil, Entity{}, false},
		{"src", "10.0.0.5", nil, Entity{IP, "10.0.0.5"}, true},
		{"src", "laptop-3", nil, Entity{System, "laptop-3"}, true},
		{"risk_object", "203.0.113.4", map[string]any{"risk_object_type": "system"}, Entity{IP, "203.0.113.4"}, true},
		{"risk_object", "web-1", map[string]any{"risk_object_type": "system"}, Entity{System, "web-1"}, true},
		{"risk_object", "ab12", map[string]any{"risk_object_type": "hash"}, Entity{Other, "ab12"}, true},
		{"title", "x", nil, Entity{}, false},
	} {
		got, ok := entityOf(c.field, c.v, c.row)
		if got != c.want || ok != c.ok {
			t.Errorf("entityOf(%s, %v) = %+v %v", c.field, c.v, got, ok)
		}
	}
}

func TestOrderedTactics(t *testing.T) {
	if ordered(nil) != nil {
		t.Error("nil tactics")
	}
	got := ordered([]string{"zzz", "execution", "initial-access", "aaa", "execution"})
	if !slices.Equal(got, []string{"initial-access", "execution", "aaa", "zzz"}) {
		t.Errorf("ordered = %v", got)
	}
}

func TestSeedsAndWindowLimits(t *testing.T) {
	var many []Entity
	for i := range MaxSeeds + 3 {
		many = append(many, Entity{User, fmt.Sprintf("u%d", i)})
	}
	if got := seedsOf(many); len(got) != MaxSeeds {
		t.Errorf("seeds = %d", len(got))
	}
	now := time.Now()
	if e, l := WindowAround(nil, now); !l.Equal(now) || l.Sub(e) != 7*24*time.Hour {
		t.Errorf("no times = %v %v", e, l)
	}
}

type failingFindings struct{ findings.Store }

func (failingFindings) Search(context.Context, findings.Filter) ([]*findings.Finding, int, error) {
	return nil, 0, errors.New("index closed")
}

func TestBuildRequests(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	b := &Builder{}
	var many []Entity
	for i := range MaxSeeds + 2 {
		many = append(many, Entity{User, fmt.Sprintf("u%d", i)})
	}
	st, err := b.Build(ctx, Request{Seeds: many, Earliest: now.Add(-time.Hour), Latest: now})
	if err != nil || len(st.Seeds) != MaxSeeds || len(st.Nodes) != MaxSeeds {
		t.Errorf("many seeds = %d %v", len(st.Seeds), err)
	}
	if _, err := b.Build(ctx, Request{Seeds: many[:1], Earliest: now, Latest: now}); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("empty range = %v", err)
	}
	b.Findings = failingFindings{}
	if _, err := b.Build(ctx, Request{Seeds: many[:1], Earliest: now.Add(-time.Hour), Latest: now}); err == nil || !strings.Contains(err.Error(), "reading findings: index closed") {
		t.Errorf("findings failure = %v", err)
	}
}
