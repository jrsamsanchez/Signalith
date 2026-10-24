// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

func newDocsClient(t *testing.T) (*Client, *ostest.Server) {
	t.Helper()
	os := ostest.New(t)
	return New(Config{URL: os.URL}), os
}

func TestCreateGetPutIfDeleteIf(t *testing.T) {
	c, os := newDocsClient(t)
	ctx := context.Background()
	if _, _, found, err := c.Get(ctx, "s_runtime", "lease:jobs"); err != nil || found {
		t.Fatalf("missing index: found %v err %v", found, err)
	}
	v1, err := c.Create(ctx, "s_runtime", "lease:jobs", map[string]any{"holder": "a", "epoch": 1}, false)
	if err != nil || v1.IsZero() {
		t.Fatalf("create: %v %v", v1, err)
	}
	if _, err := c.Create(ctx, "s_runtime", "lease:jobs", map[string]any{"holder": "b"}, false); !errors.Is(err, ErrExists) {
		t.Fatalf("second create: %v", err)
	}
	src, v, found, err := c.Get(ctx, "s_runtime", "lease:jobs")
	if err != nil || !found || !v.Same(v1) || !strings.Contains(string(src), `"holder":"a"`) {
		t.Fatalf("get: %s %v %v %v", src, v, found, err)
	}
	if !strings.HasPrefix(writeIDOf(src), "w_") {
		t.Errorf("no write_id in %s", src)
	}
	v2, err := c.PutIf(ctx, "s_runtime", "lease:jobs", map[string]any{"holder": "a", "epoch": 1, "renewed": 2}, v1, false)
	if err != nil || v2.Same(v1) || v2.Version != 2 {
		t.Fatalf("put: %v %v", v2, err)
	}
	// A write that names an older version is refused.
	if _, err := c.PutIf(ctx, "s_runtime", "lease:jobs", map[string]any{"holder": "b"}, v1, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale put: %v", err)
	}
	if err := c.DeleteIf(ctx, "s_runtime", "lease:jobs", v1, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	if err := c.DeleteIf(ctx, "s_runtime", "lease:jobs", v2, false); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if os.Source("s_runtime", "lease:jobs") != nil {
		t.Error("not deleted")
	}
	// A conditional write to a document that is gone is a conflict too.
	if _, err := c.PutIf(ctx, "s_runtime", "lease:jobs", map[string]any{"holder": "b"}, v2, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("put over a deleted document: %v", err)
	}
	// A conditional delete of a document that is gone, in an index that is
	// there: OpenSearch answers it as a version conflict, DeleteIf says
	// it is gone.
	if err := c.DeleteIf(ctx, "s_runtime", "lease:jobs", v2, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete of a deleted document: %v", err)
	}
	if err := c.DeleteIf(ctx, "s_nothing", "lease:jobs", v2, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete in a missing index: %v", err)
	}
	if _, err := c.Create(ctx, "s_runtime", "x", []int{1}, false); err == nil {
		t.Error("a document that is not an object was written")
	}
}

func TestUpdateIf(t *testing.T) {
	c, os := newDocsClient(t)
	ctx := context.Background()
	v, err := c.Create(ctx, "s_runtime", "node:n1", map[string]any{"name": "a", "syslog": map[string]any{"udp": "x", "tcp": "y"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	nv, err := c.UpdateIf(ctx, "s_runtime", "node:n1", map[string]any{"syslog": map[string]any{"udp": "z"}}, v, false)
	if err != nil {
		t.Fatal(err)
	}
	src := os.Source("s_runtime", "node:n1")
	if src["name"] != "a" || src["syslog"].(map[string]any)["tcp"] != "y" || src["syslog"].(map[string]any)["udp"] != "z" {
		t.Errorf("merged: %v", src)
	}
	if _, err := c.UpdateIf(ctx, "s_runtime", "node:n1", map[string]any{"name": "b"}, v, false); !errors.Is(err, ErrConflict) {
		t.Errorf("stale update: %v", err)
	}
	if _, err := c.UpdateIf(ctx, "s_runtime", "node:n2", map[string]any{"name": "b"}, nv, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	if _, err := c.Update(ctx, "s_runtime", "node:n1", map[string]any{"last_seen": "now"}, false); err != nil {
		t.Errorf("update: %v", err)
	}
	// Shared configuration documents are only written whole.
	if _, err := c.UpdateIf(ctx, "s_config", "user:a", map[string]any{"x": 1}, nv, false); err == nil || !strings.Contains(err.Error(), "whole") {
		t.Errorf("config partial update: %v", err)
	}
	if _, err := c.Update(ctx, "s_config", "user:a", map[string]any{"x": 1}, false); err == nil {
		t.Error("config update allowed")
	}
}

func TestMGetVersions(t *testing.T) {
	c, _ := newDocsClient(t)
	ctx := context.Background()
	va, _ := c.Create(ctx, "s_runtime", "a", map[string]any{"n": 1}, false)
	vb, _ := c.Create(ctx, "s_other", "b", map[string]any{"n": 2}, false)
	got, err := c.MGetVersions(ctx, []Ref{{"s_runtime", "a"}, {"s_other", "b"}, {"s_runtime", "missing"}, {"s_nope", "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[Ref{"s_runtime", "a"}].Same(va) || !got[Ref{"s_other", "b"}].Same(vb) {
		t.Errorf("versions: %v", got)
	}
	docs, err := c.MGet(ctx, []Ref{{"s_runtime", "a"}, {"s_runtime", "missing"}})
	if err != nil || len(docs) != 2 || !docs[0].Found || docs[1].Found || !strings.Contains(string(docs[0].Source), `"n":1`) {
		t.Errorf("mget: %+v %v", docs, err)
	}
}

func TestSearchVersionsPagesThroughEverything(t *testing.T) {
	c, os := newDocsClient(t)
	ctx := context.Background()
	const n = 2*searchPage + 5
	for i := range n {
		kind := "node"
		if i%2 == 1 {
			kind = "other"
		}
		os.Put("s_runtime", fmt.Sprintf("d%05d", i), map[string]any{"kind": kind})
	}
	docs, err := c.SearchVersions(ctx, "s_runtime", map[string]any{"term": map[string]any{"kind": "node"}})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, d := range docs {
		if seen[d.ID] || d.Version.IsZero() || d.Source != nil {
			t.Fatalf("doc %+v (seen %v)", d, seen[d.ID])
		}
		seen[d.ID] = true
	}
	if len(seen) != (n+1)/2 {
		t.Errorf("%d documents, want %d", len(seen), (n+1)/2)
	}
	few, err := c.SearchDocs(ctx, "s_runtime", map[string]any{"term": map[string]any{"_id": "d00002"}})
	if err != nil || len(few) != 1 || !strings.Contains(string(few[0].Source), "node") {
		t.Errorf("one: %+v %v", few, err)
	}
	none, err := c.SearchVersions(ctx, "s_nothing", nil)
	if err != nil || len(none) != 0 {
		t.Errorf("missing index: %v %v", none, err)
	}
}

// TestLostAnswersAreSettledByWriteID checks what happens when the
// connection breaks after a write was sent: the document is read again,
// and the write's own write_id there means it went through.
func TestLostAnswersAreSettledByWriteID(t *testing.T) {
	c, os := newDocsClient(t)
	ctx := context.Background()
	dropWrites := func(m, p string) *ostest.Fault {
		if m != "GET" {
			return &ostest.Fault{Drop: true}
		}
		return nil
	}
	os.SetFault(dropWrites)
	v1, err := c.Create(ctx, "s_runtime", "lease:jobs", map[string]any{"holder": "a"}, false)
	if err != nil || v1.IsZero() {
		t.Fatalf("create with a lost answer: %v %v", v1, err)
	}
	v2, err := c.PutIf(ctx, "s_runtime", "lease:jobs", map[string]any{"holder": "a", "n": 2}, v1, false)
	if err != nil || v2.Version != 2 {
		t.Fatalf("put with a lost answer: %v %v", v2, err)
	}
	// A write that never arrived keeps its own error, not a conflict.
	os.SetFault(func(m, p string) *ostest.Fault {
		if m != "GET" {
			return &ostest.Fault{Status: 503, Type: "unavailable"}
		}
		return nil
	})
	if _, err := c.PutIf(ctx, "s_runtime", "lease:jobs", map[string]any{"holder": "b"}, v2, false); err == nil || errors.Is(err, ErrConflict) {
		t.Fatalf("lost write: %v", err)
	}
	// Someone else's write in between is a conflict.
	os.SetFault(nil)
	os.Put("s_runtime", "lease:jobs", map[string]any{"holder": "c", "write_id": "w_theirs"})
	os.SetFault(dropWrites)
	if _, err := c.PutIf(ctx, "s_runtime", "lease:jobs", map[string]any{"holder": "b"}, v2, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("their write: %v", err)
	}
	// A delete whose answer is lost succeeded when the document is gone.
	_, cur, _, _ := c.Get(ctx, "s_runtime", "lease:jobs")
	if err := c.DeleteIf(ctx, "s_runtime", "lease:jobs", cur, false); err != nil {
		t.Fatalf("delete with a lost answer: %v", err)
	}
}

func TestClusterBlock(t *testing.T) {
	c, os := newDocsClient(t)
	ctx := context.Background()
	v, _ := c.Create(ctx, "s_runtime", "lease:jobs", map[string]any{"holder": "a"}, false)
	os.Block(true)
	_, err := c.PutIf(ctx, "s_runtime", "lease:jobs", map[string]any{"holder": "a"}, v, false)
	if !IsClusterBlock(err) || errors.Is(err, ErrConflict) {
		t.Fatalf("blocked put: %v", err)
	}
	if _, _, found, err := c.Get(ctx, "s_runtime", "lease:jobs"); err != nil || !found {
		t.Errorf("reads still work: %v %v", found, err)
	}
	if IsClusterBlock(&Error{Status: 429, Body: `{"error":{"type":"es_rejected_execution_exception"}}`}) {
		t.Error("a full write queue is not a disk block")
	}
	if !IsClusterBlock(&Error{Status: 403, Body: `{"error":{"type":"cluster_block_exception"}}`}) {
		t.Error("the older 403 form is a block too")
	}
}

func TestWithWriteID(t *testing.T) {
	type lease struct {
		Holder string `json:"holder"`
		Epoch  int64  `json:"epoch"`
	}
	raw, wid, err := withWriteID(lease{"a", 9007199254740993})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]json.RawMessage
	if err := json.Unmarshal(raw, &back); err != nil || string(back["epoch"]) != "9007199254740993" || writeIDOf(raw) != wid {
		t.Errorf("%s %v", raw, err)
	}
}

// While OpenSearch starts and the index's shards are not assigned yet,
// an mget answers 200 with an error in place of each document. That is
// a read that failed, never a document that is not there.
func TestMGetWhileShardsUnassigned(t *testing.T) {
	c, os := newDocsClient(t)
	ctx := context.Background()
	if _, err := c.Create(ctx, "s_runtime", "a", map[string]any{"n": 1}, false); err != nil {
		t.Fatal(err)
	}
	os.SetFault(func(method, path string) *ostest.Fault {
		if strings.HasPrefix(path, "/_mget") {
			return &ostest.Fault{Unassigned: true}
		}
		return nil
	})
	var oe *Error
	if _, err := c.MGet(ctx, []Ref{{"s_runtime", "a"}}); !errors.As(err, &oe) || oe.Status != 503 || !strings.Contains(err.Error(), "no_shard_available_action_exception") {
		t.Fatalf("mget while unassigned: %v", err)
	}
	if _, err := c.MGetVersions(ctx, []Ref{{"s_runtime", "a"}}); err == nil {
		t.Fatal("mget versions while unassigned: no error")
	}
	os.SetFault(nil)
	docs, err := c.MGet(ctx, []Ref{{"s_runtime", "a"}, {"s_nope", "x"}})
	if err != nil || len(docs) != 2 || !docs[0].Found || docs[1].Found {
		t.Fatalf("mget once assigned: %+v %v", docs, err)
	}
}
