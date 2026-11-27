// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// A chunk signed with the cluster key but of another kind, or whose body
// is not a chunk's, is missing.
func TestChunkDamagedBodies(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h, _ := e.hub("siem-a")
	sum := sha256.Sum256(nil)
	empty := hex.EncodeToString(sum[:])
	for name, c := range map[string]struct{ kind, body string }{
		"another kind":    {"other", `{"data":""}`},
		"body not JSON":   {"assetlist", `not json`},
		"data not base64": {"assetlist", `{"data":"!!"}`},
	} {
		ref := ChunkRef{Kind: "assetlist", Name: name, Gen: 1, N: 1}
		id := ref.id(0)
		env := &Envelope{Kind: c.kind, ID: id, Format: 1, Rev: 1, UpdatedAt: "2026-10-12T09:00:00Z", Body: c.body}
		if err := Sign(e.key, id, env); err != nil {
			t.Fatal(err)
		}
		e.os.Put(testIndex, id, sourceOf(t, env, nil))
		if _, err := h.ReadChunks(ctx, ref, empty); !errors.Is(err, ErrChunkMissing) {
			t.Errorf("%s: ReadChunks = %v", name, err)
		}
	}
}

// A hub not pointed at OpenSearch neither writes, reads nor deletes chunks.
func TestChunksWithoutOpenSearch(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h := NewHub(Options{NodeName: "siem-y", Clock: e.clock})
	ref := ChunkRef{Kind: "assetlist", Name: "hosts", Gen: 1, N: 1}
	if _, _, err := h.PutChunks(ctx, "sam", ref, []byte("x")); err == nil {
		t.Error("PutChunks without OpenSearch")
	}
	if _, err := h.ReadChunks(ctx, ref, ""); err == nil {
		t.Error("ReadChunks without OpenSearch")
	}
	if err := h.DeleteChunks(ctx, ref); err == nil {
		t.Error("DeleteChunks without OpenSearch")
	}
}
