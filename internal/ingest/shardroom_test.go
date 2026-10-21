// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The template check warns when the cluster is near its shard limit on
// any number of data nodes, one included, and for a fixed number of
// shards as well as automatic.
func TestTemplateWarnsNearShardLimit(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		nodes, used int
		shards      any
		warn        bool
	}{
		{1, 799, store.AutoShards, false},
		{1, 800, store.AutoShards, true}, // 1 node allows 1,000
		{1, 950, 1, true},
		{2, 1700, store.AutoShards, true},
		{2, 1700, 2, true},
		{3, 1000, store.AutoShards, false},
	} {
		fullLogged.Store(0)
		os := ostest.New(t)
		os.SetDataNodes(tc.nodes)
		os.SetShardsUsed(tc.used)
		cl := store.New(store.Config{URL: os.URL})
		var buf bytes.Buffer
		log := slog.New(slog.NewTextHandler(&buf, nil))
		set := map[string]any{"auto_expand_replicas": "0-1", "number_of_shards": tc.shards}
		if err := PutIndexTemplate(ctx, cl, "sig", set, log); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(buf.String(), "near its shard limit"); got != tc.warn {
			t.Errorf("%d nodes, %d shards in use, shards %v: warned %v, want %v: %s", tc.nodes, tc.used, tc.shards, got, tc.warn, buf.String())
		}
		if tc.warn && !strings.Contains(buf.String(), "cluster.max_shards_per_node") {
			t.Errorf("the warning does not say how to raise the limit: %s", buf.String())
		}
		// The checks every few minutes do not repeat it.
		buf.Reset()
		if _, err := RestoreIndexTemplate(ctx, cl, "sig", set, log); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(buf.String(), "near its shard limit") {
			t.Errorf("%d nodes: warned again at once", tc.nodes)
		}
	}
}

func TestNearShardLimit(t *testing.T) {
	for _, tc := range []struct {
		used, limit int
		want        bool
	}{{0, 0, false}, {799, 1000, false}, {800, 1000, true}, {1200, 1000, true}} {
		if got := NearShardLimit(tc.used, tc.limit); got != tc.want {
			t.Errorf("%d of %d: %v", tc.used, tc.limit, got)
		}
	}
}

// OpenSearch refuses to create a day's index once the cluster holds the
// most shards it allows. Those events are temporary, so senders send them
// again, never a field rejection, and the log names the shard limit.
func TestShardLimitRefusalIsTemporary(t *testing.T) {
	b := &countingBulk{keep: true}
	b.reject = func(d store.IndexedDoc) *store.BulkItemError {
		if d.Doc["user"] == "full" {
			return &store.BulkItemError{Index: d.Index, Type: "validation_exception", Status: 400,
				Reason: "validation_exception: Validation Failed: 1: this action would add [1] total shards, but this cluster currently has [1000]/[1000] maximum normal shards open;"}
		}
		return nil
	}
	var buf bytes.Buffer
	at := time.Now().Add(-time.Hour)
	p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return at }, Log: slog.New(slog.NewTextHandler(&buf, nil))}
	res, err := p.Ingest(context.Background(), "app", []map[string]any{{"user": "full", "weird": "1"}, {"user": "ok"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Indexed != 1 || res.Rejected != 1 || res.Temporary != 1 || res.FieldsDropped != 0 {
		t.Errorf("res %+v", res)
	}
	if len(b.calls) != 1 {
		t.Errorf("retried as a field rejection: bulk calls %v", b.calls)
	}
	if !strings.Contains(buf.String(), "cluster.max_shards_per_node") || !strings.Contains(buf.String(), "maximum normal shards open") {
		t.Errorf("log: %s", buf.String())
	}
	if shardLimit(store.BulkItemError{Type: "validation_exception", Reason: "Validation Failed: 1: index name is invalid"}) {
		t.Error("another validation_exception taken for the shard limit")
	}
}
