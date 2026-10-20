// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sample

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// freshFake records the loads and removals KeepFresh asks for.
type freshFake struct {
	st       *State
	statErr  error
	loadErr  error
	calls    []string
	loadedAt time.Time
}

func (f *freshFake) Status(context.Context) (*State, error) { return f.st, f.statErr }

func (f *freshFake) Load(_ context.Context, size Size, _ ProgressFn) (*State, error) {
	f.calls = append(f.calls, "load "+string(size))
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	f.st = &State{ID: "sample-new", Size: size, LoadedAt: f.loadedAt}
	return f.st, nil
}

func (f *freshFake) Remove(context.Context, ProgressFn) (*State, error) {
	f.calls = append(f.calls, "remove")
	f.st = nil
	return nil, nil
}

// A demo's sample data is loaded when there is none, kept while it is
// younger than a day, and removed and loaded again once it is older or a
// job did not finish.
func TestKeepFreshRounds(t *testing.T) {
	now := time.Now().Add(-time.Hour)
	clock := func() time.Time { return now }
	ctx := context.Background()
	for _, c := range []struct {
		name  string
		st    *State
		calls []string
		wait  time.Duration
	}{
		{"none loaded", nil, []string{"load standard"}, FreshEvery},
		{"recent", &State{ID: "s", LoadedAt: now.Add(-2 * time.Hour)}, nil, FreshEvery - 2*time.Hour},
		{"a day old", &State{ID: "s", LoadedAt: now.Add(-FreshEvery - time.Minute)}, []string{"remove", "load standard"}, FreshEvery},
		{"unfinished", &State{ID: "s", Partial: true, Started: now.Add(-time.Minute)}, []string{"remove", "load standard"}, FreshEvery},
	} {
		f := &freshFake{st: c.st, loadedAt: now}
		wait, err := freshRound(ctx, f, FreshEvery, clock)
		if err != nil || wait != c.wait || !slices.Equal(f.calls, c.calls) {
			t.Errorf("%s: wait %v, calls %v, err %v; want wait %v, calls %v", c.name, wait, f.calls, err, c.wait, c.calls)
		}
	}
	// Another load or removal running elsewhere is waited for briefly;
	// other errors are tried again later.
	f := &freshFake{loadErr: ErrBusy}
	if wait, err := freshRound(ctx, f, FreshEvery, clock); !errors.Is(err, ErrBusy) || wait != freshBusyWait {
		t.Errorf("busy: wait %v, err %v", wait, err)
	}
	f = &freshFake{statErr: errors.New("opensearch down")}
	if wait, err := freshRound(ctx, f, FreshEvery, clock); err == nil || wait != freshErrorWait || len(f.calls) != 0 {
		t.Errorf("status error: wait %v, err %v, calls %v", wait, err, f.calls)
	}
}
