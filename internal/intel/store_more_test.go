// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

// failBackend is a Memory whose calls fail when their error is set.
type failBackend struct {
	*Memory
	put, del, all, ver error
}

func (b *failBackend) Put(ctx context.Context, inds []Indicator) error {
	if b.put != nil {
		return b.put
	}
	return b.Memory.Put(ctx, inds)
}

func (b *failBackend) Delete(ctx context.Context, ids []string) error {
	if b.del != nil {
		return b.del
	}
	return b.Memory.Delete(ctx, ids)
}

func (b *failBackend) All(ctx context.Context) ([]Indicator, error) {
	if b.all != nil {
		return nil, b.all
	}
	return b.Memory.All(ctx)
}

func (b *failBackend) Version(ctx context.Context) (string, error) {
	if b.ver != nil {
		return "", b.ver
	}
	return b.Memory.Version(ctx)
}

func TestStoreBackendFailures(t *testing.T) {
	ctx := context.Background()
	b := &failBackend{Memory: NewMemory()}
	s := NewStore(b)
	boom := errors.New("opensearch down")
	ind := func(v string) Indicator { return Indicator{Type: TypeIP, Value: v, Source: "manual"} }

	b.ver = boom
	if err := s.Load(ctx); !errors.Is(err, boom) {
		t.Errorf("load version = %v", err)
	}
	if _, err := s.Sync(ctx); !errors.Is(err, boom) {
		t.Errorf("sync = %v", err)
	}
	b.ver, b.all = nil, boom
	if err := s.Load(ctx); !errors.Is(err, boom) {
		t.Errorf("load all = %v", err)
	}
	b.all = nil

	if err := s.Add(ctx, nil); err != nil {
		t.Errorf("add nothing = %v", err)
	}
	b.put = boom
	if err := s.Add(ctx, []Indicator{ind("192.0.2.1")}); !errors.Is(err, boom) {
		t.Errorf("add = %v", err)
	}
	if _, _, err := s.ReplaceSource(ctx, "feed", []Indicator{ind("192.0.2.2")}); !errors.Is(err, boom) {
		t.Errorf("replace put = %v", err)
	}
	if _, err := s.MergeSource(ctx, "feed", []Indicator{ind("192.0.2.3")}); !errors.Is(err, boom) {
		t.Errorf("merge = %v", err)
	}
	b.put = nil
	if _, err := s.MergeSource(ctx, "feed", []Indicator{ind("192.0.2.3")}); err != nil {
		t.Fatal(err)
	}
	b.del = boom
	if err := s.Delete(ctx, []string{"x"}); !errors.Is(err, boom) {
		t.Errorf("delete = %v", err)
	}
	if _, _, err := s.ReplaceSource(ctx, "feed", nil); !errors.Is(err, boom) {
		t.Errorf("replace delete = %v", err)
	}
	b.del = nil
	if _, ok := s.Get("nope"); ok {
		t.Error("got a missing indicator")
	}

	// A backend that lists what a source has stored: its failure stops the
	// replacement.
	d := &scriptDoer{answer: func(int, string, string, any) (string, error) { return "", boom }}
	viaOS := NewStore(NewOpenSearch(d, "sig"))
	if _, _, err := viaOS.ReplaceSource(ctx, "feed", []Indicator{ind("192.0.2.4")}); !errors.Is(err, boom) ||
		!strings.Contains(err.Error(), "could not list the indicators stored for feed") {
		t.Errorf("replace list = %v", err)
	}
}

func TestStoreNetworksAndList(t *testing.T) {
	ctx := context.Background()
	s := NewStore(NewMemory())
	now := time.Now().Add(-time.Hour)
	s.Now = func() time.Time { return now }
	add := []Indicator{
		{Type: TypeCIDR, Value: "198.51.100.0/24", Source: "manual", Weight: 1},
		{Type: TypeCIDR, Value: "203.0.113.0/24", Source: "manual", Weight: 3},
		{Type: TypeCIDR, Value: "192.0.2.0/24", Source: "manual", Weight: 1},
		{Type: TypeCIDR, Value: "203.0.113.0/24", Source: "feed", Weight: 2},
		{Type: TypeCIDR, Value: "10.0.0.0/8", Source: "manual", Weight: 5, Expires: now.Add(-time.Minute)},
		{Type: TypeIP, Value: "192.0.2.9", Source: "feed", Description: "Known scanner", Tags: []string{"Scanner"}},
	}
	if err := s.Add(ctx, add); err != nil {
		t.Fatal(err)
	}
	got := s.Networks()
	want := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24")}
	if !slices.Equal(got, want) {
		t.Errorf("networks = %v", got)
	}
	if list, total := s.List(Filter{Source: "feed"}); total != 2 || len(list) != 2 {
		t.Errorf("feed = %d %v", total, list)
	}
	if list, total := s.List(Filter{Text: "scanner"}); total != 1 || list[0].Value != "192.0.2.9" {
		t.Errorf("text = %d %v", total, list)
	}
	if list, total := s.List(Filter{Offset: 5, Limit: 1}); total != 6 || len(list) != 1 {
		t.Errorf("page = %d %v", total, list)
	}
	if list, _ := s.List(Filter{Offset: 50}); len(list) != 0 {
		t.Errorf("past the end = %v", list)
	}
	s.Wake()
	s.Wake() // a second wake while one waits is dropped
	select {
	case <-s.wakeCh():
	default:
		t.Error("no wake waiting")
	}
}
