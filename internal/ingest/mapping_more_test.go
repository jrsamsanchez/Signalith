// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// A count being fetched is waited for, unless the writer goes away
// first; counts of indices not asked about for an hour are forgotten.
func TestFieldCounterWaits(t *testing.T) {
	var c fieldCounter
	at := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	started, release := make(chan struct{}), make(chan struct{})
	fetch := func(context.Context, string) (int, error) {
		close(started)
		<-release
		return 7, nil
	}
	first := make(chan int, 1)
	go func() {
		n, _ := c.count(context.Background(), "idx", at, fetch)
		first <- n
	}()
	<-started

	gone, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.count(gone, "idx", at, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("a writer gone while waiting = %v", err)
	}
	second := make(chan int, 1)
	go func() {
		n, _ := c.count(context.Background(), "idx", at, nil)
		second <- n
	}()
	close(release)
	for name, ch := range map[string]chan int{"fetcher": first, "waiter": second} {
		select {
		case n := <-ch:
			if n != 7 {
				t.Errorf("%s got %d", name, n)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not get the count", name)
		}
	}

	// Two hours on, a count of another index forgets this one.
	if _, err := c.count(context.Background(), "other", at.Add(2*time.Hour), func(context.Context, string) (int, error) { return 1, nil }); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	_, kept := c.entries["idx"]
	c.mu.Unlock()
	if kept {
		t.Error("an index not asked about for two hours is still kept")
	}
}

// doerFunc answers Do with a function.
type doerFunc func() error

func (f doerFunc) Do(context.Context, string, string, any, any) error { return f() }

func TestMappingFieldCountErrors(t *testing.T) {
	boom := &store.Error{Status: http.StatusServiceUnavailable, Body: "busy"}
	if _, err := MappingFieldCount(doerFunc(func() error { return boom }))(context.Background(), "idx"); !errors.Is(err, boom) {
		t.Errorf("a failed read = %v", err)
	}
	if n := CountMappingFields([]byte(`[`)); n != 0 {
		t.Errorf("a broken mapping counts %d", n)
	}
}
