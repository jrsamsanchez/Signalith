// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// A value cut into chunks reads back as written, from another server;
// a chunk changed outside Signalith, gone, or a checksum that does not
// match gives ErrChunkMissing.
func TestChunksRoundTrip(t *testing.T) {
	old := ChunkSize
	ChunkSize = 10
	t.Cleanup(func() { ChunkSize = old })
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	// Not valid UTF-8, and more than 4 chunks so reads take several
	// requests.
	data := append(bytes.Repeat([]byte("0123456789"), 5), 0xff, 0xfe, 0x00, 'x')
	ref, sum, err := a.PutChunks(ctx, "sam", ChunkRef{Kind: "assetlist", Name: "hosts", Gen: 1}, data)
	if err != nil {
		t.Fatal(err)
	}
	if ref.N != 6 || len(sum) != 64 {
		t.Fatalf("ref %+v, sum %q", ref, sum)
	}
	got, err := b.ReadChunks(ctx, ref, sum)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read %q, %v", got, err)
	}
	// The same generation is never written twice.
	if _, _, err := a.PutChunks(ctx, "sam", ChunkRef{Kind: "assetlist", Name: "hosts", Gen: 1}, []byte("other")); err == nil {
		t.Error("a generation was written twice")
	}
	if got, err := b.ReadChunks(ctx, ref, sum); err != nil || !bytes.Equal(got, data) {
		t.Errorf("after the refused write: %q, %v", got, err)
	}
	// A wrong checksum.
	if _, err := b.ReadChunks(ctx, ref, strings.Repeat("0", 64)); !errors.Is(err, ErrChunkMissing) {
		t.Errorf("wrong sum: %v", err)
	}
	// A chunk changed outside Signalith.
	src := e.os.Source(testIndex, ref.id(2))
	src["body"] = `{"data":"AAAA"}`
	e.os.Put(testIndex, ref.id(2), src)
	if _, err := b.ReadChunks(ctx, ref, sum); !errors.Is(err, ErrChunkMissing) {
		t.Errorf("a changed chunk: %v", err)
	}
	// Deleted: missing; deleting again is no error.
	if err := a.DeleteChunks(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ReadChunks(ctx, ref, sum); !errors.Is(err, ErrChunkMissing) {
		t.Errorf("deleted chunks: %v", err)
	}
	if err := a.DeleteChunks(ctx, ref); err != nil {
		t.Errorf("deleting again: %v", err)
	}

	// An empty value is one chunk.
	ref, sum, err = a.PutChunks(ctx, "sam", ChunkRef{Kind: "assetlist", Name: "empty", Gen: 1}, nil)
	if err != nil || ref.N != 1 {
		t.Fatalf("empty: %+v %v", ref, err)
	}
	if got, err := b.ReadChunks(ctx, ref, sum); err != nil || len(got) != 0 {
		t.Errorf("empty read: %q, %v", got, err)
	}
}

// A write that fails part way removes the chunks it wrote.
func TestChunksFailedWriteCleansUp(t *testing.T) {
	old := ChunkSize
	ChunkSize = 4
	t.Cleanup(func() { ChunkSize = old })
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	ref := ChunkRef{Kind: "assetlist", Name: "big", Gen: 7}
	failed := ref.id(2)
	e.os.SetFault(func(method, path string) *ostest.Fault {
		if strings.Contains(path, "/_create/"+failed) {
			return &ostest.Fault{Status: 500, Type: "internal_error"}
		}
		return nil
	})
	_, _, err := a.PutChunks(ctx, "sam", ref, []byte("0123456789ab"))
	if err == nil || !strings.Contains(err.Error(), "could not write part 3 of 3") {
		t.Fatalf("PutChunks = %v", err)
	}
	e.os.SetFault(nil)
	for i := range 3 {
		if e.os.Source(testIndex, ref.id(i)) != nil {
			t.Errorf("chunk %d left behind", i)
		}
	}
	// Deleting chunks when OpenSearch fails reports it.
	e.os.SetFault(func(method, path string) *ostest.Fault {
		if method == "DELETE" {
			return &ostest.Fault{Status: 500, Type: "internal_error"}
		}
		return nil
	})
	if err := a.DeleteChunks(ctx, ChunkRef{Kind: "assetlist", Name: "x", Gen: 1, N: 2}); err == nil {
		t.Error("a failed delete ignored")
	}
}

// MutateMany writes many items with one bump: the other server sees them
// all after one cycle; fn may skip or delete an item, and an error stops
// the batch with the items before it written.
func TestCollectionMutateMany(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	ca := NewCollection[testBody](a, "rule", "rules", 1)
	cb := NewCollection[testBody](b, "rule", "rules", 1)
	if _, err := ca.Create(ctx, "sam", "gone", &testBody{Name: "to delete"}); err != nil {
		t.Fatal(err)
	}
	cycle(t, b)
	n, seq, err := ca.MutateMany(ctx, "sam", []string{"r1", "r2", "skip", "gone", "never"}, func(name string, cur *testBody) (*testBody, bool, error) {
		switch name {
		case "skip":
			return nil, false, nil
		case "gone":
			if cur == nil || cur.Name != "to delete" {
				t.Errorf("gone: cur = %+v", cur)
			}
			return nil, true, nil
		case "never":
			return nil, true, nil // nothing there to delete
		}
		return &testBody{Name: "rule " + name}, true, nil
	})
	if err != nil || n != 3 || seq <= 0 {
		t.Fatalf("MutateMany = %d, %d, %v", n, seq, err)
	}
	cycle(t, b)
	if got := names(cb.List()); len(got) != 2 || got[0] != "r1" || got[1] != "r2" {
		t.Errorf("b's items = %v", got)
	}

	// Nothing written: no bump.
	n, seq, err = ca.MutateMany(ctx, "sam", []string{"r1"}, func(string, *testBody) (*testBody, bool, error) { return nil, false, nil })
	if n != 0 || seq != 0 || err != nil {
		t.Errorf("no writes = %d, %d, %v", n, seq, err)
	}
	// An error part way: the items before it stay written.
	stop := errors.New("stop")
	n, _, err = ca.MutateMany(ctx, "sam", []string{"r3", "r4"}, func(name string, _ *testBody) (*testBody, bool, error) {
		if name == "r4" {
			return nil, false, stop
		}
		return &testBody{Name: name}, true, nil
	})
	if n != 1 || !errors.Is(err, stop) {
		t.Errorf("an error part way = %d, %v", n, err)
	}
	if _, _, ok := ca.Get("r3"); !ok {
		t.Error("r3 was not written")
	}

	// B changes r1 meanwhile: A's batch reads it again and runs fn on the
	// newer copy.
	if _, err := cb.Mutate(ctx, "bob", "r1", func(v *testBody) error { v.Items = []string{"from b"}; return nil }); err != nil {
		t.Fatal(err)
	}
	calls := 0
	n, _, err = ca.MutateMany(ctx, "sam", []string{"r1"}, func(_ string, cur *testBody) (*testBody, bool, error) {
		calls++
		next := *cur
		next.Name = "renamed"
		return &next, true, nil
	})
	if err != nil || n != 1 || calls != 2 {
		t.Fatalf("after a change elsewhere = %d, %v (%d calls)", n, err, calls)
	}
	if v, _, _ := ca.Get("r1"); v.Name != "renamed" || len(v.Items) != 1 {
		t.Errorf("r1 = %+v: B's change was lost", v)
	}
	// A write OpenSearch refuses stops the batch.
	e.os.SetFault(func(method, path string) *ostest.Fault {
		if method == "PUT" && strings.Contains(path, "rule:r2") {
			return &ostest.Fault{Status: 500, Type: "internal_error"}
		}
		return nil
	})
	if _, _, err := ca.MutateMany(ctx, "sam", []string{"r2"}, func(_ string, cur *testBody) (*testBody, bool, error) {
		return &testBody{Name: "x"}, true, nil
	}); err == nil || errors.Is(err, store.ErrConflict) {
		t.Errorf("a refused write: %v", err)
	}
}
