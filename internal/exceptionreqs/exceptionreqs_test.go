// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package exceptionreqs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func req(by, det, host string, created time.Time) Request {
	return Request{ID: NewID(), DetectionID: det, Match: map[string]string{"host": host}, By: by, Created: created, Status: Pending}
}

func TestAddDecideAndExpire(t *testing.T) {
	now := time.Now()
	m := &Memory{Now: func() time.Time { return now }}
	ctx := context.Background()
	a := req("ann", "d1", "web-01", now)
	if err := m.Modify(ctx, func(rs []Request) ([]Request, error) { return Add(rs, a) }); err != nil {
		t.Fatal(err)
	}
	// The same ask twice is refused while the first waits.
	dup := req("bob", "d1", "web-01", now)
	err := m.Modify(ctx, func(rs []Request) ([]Request, error) { return Add(rs, dup) })
	if err == nil || !strings.Contains(err.Error(), "ann already proposed") {
		t.Fatalf("duplicate: %v", err)
	}
	if !ValidID(a.ID) || ValidID("er-../x") {
		t.Error("ID check")
	}

	var got *Request
	if err := m.Modify(ctx, func(rs []Request) ([]Request, error) {
		out, r, err := Decide(rs, a.ID, Approved, "root", "ok", "ex1", now)
		got = r
		return out, err
	}); err != nil {
		t.Fatal(err)
	}
	if got.Status != Approved || got.DecidedBy != "root" || got.ExceptionID != "ex1" {
		t.Errorf("decided %+v", got)
	}
	// Deciding again is refused, and so is an unknown ID.
	for id, want := range map[string]error{a.ID: ErrDecided, "er-0000000000000000": ErrNotFound} {
		err := m.Modify(ctx, func(rs []Request) ([]Request, error) {
			out, _, err := Decide(rs, id, Declined, "root", "", "", now)
			return out, err
		})
		if !errors.Is(err, want) {
			t.Errorf("decide %s: %v", id, err)
		}
	}
	// Now the same ask can be made again; an old one expires.
	old := req("ann", "d2", "db-01", now.Add(-ExpireAfter-time.Minute))
	if err := m.Modify(ctx, func(rs []Request) ([]Request, error) { return Add(rs, dup) }); err != nil {
		t.Fatal(err)
	}
	if err := m.Modify(ctx, func(rs []Request) ([]Request, error) { return append(rs, old), nil }); err != nil {
		t.Fatal(err)
	}
	rs, _ := m.List(ctx)
	if len(rs) != 3 || rs[0].ID != dup.ID || rs[2].Status != Expired {
		t.Errorf("list %+v", rs)
	}
}

func TestLimits(t *testing.T) {
	now := time.Now()
	var rs []Request
	var err error
	for i := range MaxPendingPerUser {
		if rs, err = Add(rs, req("ann", "d", fmt.Sprint("h", i), now)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Add(rs, req("ann", "d", "more", now)); err == nil || !strings.Contains(err.Error(), "you have 50") {
		t.Errorf("per user: %v", err)
	}
	for i := len(rs); i < MaxPending; i++ {
		if rs, err = Add(rs, req(fmt.Sprint("u", i), "d", fmt.Sprint("h", i), now)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Add(rs, req("zed", "d", "more", now)); err == nil || !strings.Contains(err.Error(), "already wait") {
		t.Errorf("total: %v", err)
	}
	// Decided requests past KeepDecided are dropped, oldest first.
	var done []Request
	for i := range KeepDecided + 5 {
		r := req("ann", "d", fmt.Sprint("x", i), now.Add(time.Duration(i)*time.Second))
		r.Status = Declined
		done = append(done, r)
	}
	kept := Tidy(done, now)
	if len(kept) != KeepDecided || kept[0].Match["host"] != fmt.Sprint("x", KeepDecided+4) {
		t.Errorf("kept %d, first %v", len(kept), kept[0].Match)
	}
}
