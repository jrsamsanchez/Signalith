// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package setupguide

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func TestAsk(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	soon, past := now.Add(time.Hour), now.Add(-time.Second)
	for _, tc := range []struct {
		c    Choice
		want bool
	}{
		{Choice{}, true},
		{Choice{State: Started}, false},
		{Choice{State: Never}, false},
		{Choice{State: Done}, false},
		{Choice{State: Later, Until: &soon}, false},
		{Choice{State: Later, Until: &past}, true},
		{Choice{State: Later}, true},
	} {
		if got := tc.c.Ask(now); got != tc.want {
			t.Errorf("%+v: Ask = %v, want %v", tc.c, got, tc.want)
		}
	}
}

func TestValidate(t *testing.T) {
	c := Choice{State: Started, Skipped: []string{"notify", "notify", "ai"}, Opened: []string{"search"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Skipped, []string{"notify", "ai"}) {
		t.Errorf("Skipped = %v, want duplicates dropped", c.Skipped)
	}
	long := make([]string, MaxSteps+1)
	for i := range long {
		long[i] = "a"
	}
	for _, bad := range []Choice{
		{State: "maybe"},
		{State: Started, Skipped: []string{"Notify"}},
		{State: Started, Skipped: []string{""}},
		{State: Started, Opened: []string{"<script>"}},
		{State: Started, Opened: []string{"a-very-long-step-name-that-goes-on-and-on"}},
		{State: Started, Skipped: long},
	} {
		if err := bad.Validate(); !errors.Is(err, ErrBadChoice) {
			t.Errorf("%+v: Validate = %v, want ErrBadChoice", bad, err)
		}
	}
}

func TestOpenSearch(t *testing.T) {
	fake := ostest.New(t)
	o := &OpenSearch{Docs: store.New(store.Config{URL: fake.URL}), Prefix: "sg"}
	ctx := context.Background()
	got, err := o.Get(ctx, "ana@acme")
	if err != nil || got.State != New {
		t.Fatalf("Get before any choice = %+v, %v", got, err)
	}
	at := time.Date(2026, 10, 18, 1, 0, 0, 0, time.UTC)
	until := at.Add(LaterFor)
	if err := o.Put(ctx, "Ana@Acme", Choice{State: Later, Until: &until, Skipped: []string{"ai"}, At: at}); err != nil {
		t.Fatal(err)
	}
	got, err = o.Get(ctx, "ana@acme")
	if err != nil || got.State != Later || got.Until == nil || !got.Until.Equal(until) || !slices.Equal(got.Skipped, []string{"ai"}) {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if err := o.Put(ctx, "ana@acme", Choice{State: Never, At: at}); err != nil {
		t.Fatal(err)
	}
	if got, _ = o.Get(ctx, "ana@acme"); got.State != Never || got.Until != nil || got.Skipped != nil {
		t.Fatalf("after the second Put, Get = %+v", got)
	}
	src := fake.Source("sg_runtime", "setupguide:ana@acme")
	if src["kind"] != kind || src["user"] != "ana@acme" {
		t.Errorf("stored document = %v", src)
	}
	// Another user's choice is their own.
	if got, _ := o.Get(ctx, "ana"); got.State != New {
		t.Errorf("another user's Get = %+v", got)
	}
}

func TestMemory(t *testing.T) {
	var m Memory
	ctx := context.Background()
	if err := m.Put(ctx, "Bo", Choice{State: Done}); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Get(ctx, "bo"); got.State != Done {
		t.Errorf("Get = %+v", got)
	}
}
