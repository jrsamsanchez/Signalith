// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// A server that has not read an item another wrote creates over its
// tombstone, and is told an item that is still there exists.
func TestCollectionCreateOverUnreadCopies(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	ca := NewCollection[testBody](a, "rule", "rules", 1)
	cb := NewCollection[testBody](b, "rule", "rules", 1)
	for _, name := range []string{"gone", "kept"} {
		if _, err := ca.Create(ctx, "sam", name, &testBody{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	_, etag, ok := ca.Get("gone")
	if !ok {
		t.Fatal("no item gone")
	}
	if _, err := ca.Delete(ctx, "sam", "gone", etag); err != nil {
		t.Fatal(err)
	}
	// b has not read either.
	if _, err := cb.Create(ctx, "kim", "gone", &testBody{Name: "again"}); err != nil {
		t.Errorf("create over an unread tombstone = %v", err)
	}
	if v, _, ok := cb.Get("gone"); !ok || v.Name != "again" {
		t.Errorf("b's item = %+v %v", v, ok)
	}
	if _, err := cb.Create(ctx, "kim", "kept", &testBody{Name: "other"}); !errors.Is(err, store.ErrExists) {
		t.Errorf("create over an unread item = %v", err)
	}
	// Now that b has read it, it is refused at once.
	if _, err := cb.Create(ctx, "kim", "kept", &testBody{Name: "other"}); !errors.Is(err, store.ErrExists) {
		t.Errorf("create over a read item = %v", err)
	}
}

// A server without the cluster key cannot sign a new item.
func TestCollectionCreateWithoutKey(t *testing.T) {
	e := newEnv(t)
	h := NewHub(Options{NodeName: "siem-z", Clock: e.clock})
	h.Use(e.c, testPrefix)
	c := NewCollection[testBody](h, "rule", "rules", 1)
	if _, err := c.Create(context.Background(), "sam", "r1", &testBody{Name: "r1"}); err == nil || !strings.Contains(err.Error(), "no cluster key") {
		t.Errorf("Create without a key = %v", err)
	}
}
