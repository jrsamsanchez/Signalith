// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// writeSharedCache writes this server's copy of the shared settings, as a
// member keeps it, from what OpenSearch holds now; clusterID and prefix
// replace the cluster's when set.
func writeSharedCache(t *testing.T, fc *foundedCluster, clusterID, prefix string) []shared.StoredDoc {
	t.Helper()
	ctx := context.Background()
	cl := store.New(store.Config{URL: fc.fake.URL})
	docs, _, err := shared.ReadAll(ctx, cl, "cc")
	if err != nil || len(docs) == 0 {
		t.Fatalf("shared settings: %v %d", err, len(docs))
	}
	d := shared.CacheData{WrittenAt: time.Now().UTC()}
	id := ""
	for _, sd := range docs {
		src, _ := json.Marshal(sd.Envelope)
		d.Docs = append(d.Docs, shared.CacheDoc{ID: sd.ID, Seq: sd.Version.SeqNo, Term: sd.Version.PrimaryTerm, Source: src})
		d.MaxRev = max(d.MaxRev, sd.Envelope.Rev)
		if sd.ID == shared.ClusterDocID {
			var b shared.ClusterBody
			json.Unmarshal([]byte(sd.Envelope.Body), &b)
			id = b.ClusterID
		}
	}
	if clusterID != "" {
		id = clusterID
	}
	if prefix == "" {
		prefix = "cc"
	}
	c, err := config.Load(fc.path)
	if err != nil {
		t.Fatal(err)
	}
	cache := shared.Cache{Path: shared.CachePath(c.StateDir()), Master: c.Keyring(), ClusterID: id, Prefix: prefix}
	if err := cache.Write(d); err != nil {
		t.Fatal(err)
	}
	return docs
}

// cluster import -from-cache writes this server's copy back, only into
// the same cluster and index prefix.
func TestClusterImportFromCache(t *testing.T) {
	fc := newFoundedCluster(t, nil)
	writeSharedCache(t, fc, "", "zz")
	if _, err := fc.run("", "import", "-from-cache"); err == nil || !strings.Contains(err.Error(), `index prefix "zz"`) {
		t.Errorf("another prefix: %v", err)
	}
	writeSharedCache(t, fc, "c_another", "")
	if _, err := fc.run("", "import", "-from-cache"); err == nil || !strings.Contains(err.Error(), "OpenSearch holds another cluster") {
		t.Errorf("another cluster: %v", err)
	}
	docs := writeSharedCache(t, fc, "", "")
	out, err := fc.run("", "import", "-from-cache")
	if err != nil || !strings.Contains(out, "Wrote back") || !strings.Contains(out, "were there already") {
		t.Errorf("import: %v\n%s", err, out)
	}
	if !strings.Contains(out, "; "+itoa(len(docs))+" were there already") {
		t.Errorf("all %d documents should be there already:\n%s", len(docs), out)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// reset-key leaves documents Signalith did not write, and compares the
// documents with this server's copy.
func TestClusterResetKeyWithCopy(t *testing.T) {
	fc := newFoundedCluster(t, nil)
	for _, f := range shared.ClusterKeyFiles(fc.state) {
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}
	// This server's copy of the settings, then a document that is not
	// Signalith's and one changed outside it.
	docs := writeSharedCache(t, fc, "", "")
	fc.fake.Put("cc_config", "junk", map[string]any{"hello": "world"})
	var changed string
	for _, d := range docs {
		if d.ID != shared.ClusterDocID {
			e := d.Envelope
			e.Body = strings.Replace(e.Body, "}", `,"x":1}`, 1)
			if e.Body == d.Envelope.Body {
				e.Body = `{"x":1}`
			}
			fc.fake.Put("cc_config", d.ID, asMap(t, e))
			changed = d.ID
			break
		}
	}
	if changed == "" {
		t.Fatal("no document to change")
	}
	out, err := fc.run("", "reset-key", "-yes")
	if err != nil {
		t.Fatalf("reset-key: %v\n%s", err, out)
	}
	for _, want := range []string{
		"junk is not a document Signalith wrote",
		changed + " ",
		"differs (revision",
		"the same",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("reset-key output lacks %q:\n%s", want, out)
		}
	}
}
