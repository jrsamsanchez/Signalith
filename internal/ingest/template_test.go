package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

var (
	autoReplicas = map[string]any{"auto_expand_replicas": "0-1"}
	noReplicas   = map[string]any{"number_of_replicas": 0}
)

// templatePuts counts the template writes among the requests made since
// the last call.
func templatePuts(os *ostest.Server) int {
	n := 0
	for _, r := range os.Requests() {
		if strings.HasPrefix(r, "PUT /_index_template/") {
			n++
		}
	}
	return n
}

func withVersion(tmpl map[string]any, v any) map[string]any {
	if v == nil {
		delete(tmpl, "_meta")
	} else {
		tmpl["_meta"] = map[string]any{"signalith": map[string]any{"template_version": v, "managed_by": "signalith"}}
	}
	return tmpl
}

func TestPutIndexTemplateVersions(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		stored   map[string]any // nil: no template yet
		replicas map[string]any
		write    bool
	}{
		{"no template yet", nil, autoReplicas, true},
		{"from before template versions", withVersion(IndexTemplate("sig", noReplicas), nil), noReplicas, true},
		{"older version", withVersion(IndexTemplate("sig", autoReplicas), TemplateVersion-1), autoReplicas, true},
		{"same version and replicas", IndexTemplate("sig", autoReplicas), autoReplicas, false},
		{"same version, other replicas", IndexTemplate("sig", noReplicas), autoReplicas, true},
		{"same version, auto turned off", IndexTemplate("sig", autoReplicas), map[string]any{"number_of_replicas": 2}, true},
		{"newer version", withVersion(IndexTemplate("sig", noReplicas), TemplateVersion+1), autoReplicas, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			os := ostest.New(t)
			cl := store.New(store.Config{URL: os.URL})
			if tc.stored != nil {
				if err := cl.PutIndexTemplate(ctx, "sig", tc.stored); err != nil {
					t.Fatal(err)
				}
			}
			before := os.Template("sig")
			templatePuts(os)
			if err := PutIndexTemplate(ctx, cl, "sig", tc.replicas, nil); err != nil {
				t.Fatal(err)
			}
			if got := templatePuts(os); (got == 1) != tc.write || got > 1 {
				t.Fatalf("%d template writes, want write %v", got, tc.write)
			}
			after := os.Template("sig")
			if !tc.write {
				if !bytes.Equal(before, after) {
					t.Error("the stored template changed")
				}
				return
			}
			var stored map[string]any
			if err := json.Unmarshal(after, &stored); err != nil {
				t.Fatal(err)
			}
			if v := storedVersion(stored); v != TemplateVersion {
				t.Errorf("stored version %d", v)
			}
			if !sameReplicas(stored, tc.replicas) {
				t.Errorf("stored settings %v, want %v", stored["template"].(map[string]any)["settings"], tc.replicas)
			}
		})
	}
}

// An older Signalith started after a newer one leaves the newer template
// alone, and says so once.
func TestPutIndexTemplateNewerLoggedOnce(t *testing.T) {
	ctx := context.Background()
	os := ostest.New(t)
	cl := store.New(store.Config{URL: os.URL})
	if err := cl.PutIndexTemplate(ctx, "sig", withVersion(IndexTemplate("sig", noReplicas), TemplateVersion+1)); err != nil {
		t.Fatal(err)
	}
	newerLogged.Store(false)
	t.Cleanup(func() { newerLogged.Store(false) })
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	for range 2 {
		if err := PutIndexTemplate(ctx, cl, "sig", autoReplicas, log); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(buf.String(), "newer Signalith"); n != 1 {
		t.Errorf("said %d times: %s", n, buf.String())
	}
}

// OpenSearch answers a template with its settings under "index", as text.
func TestSameReplicasOpenSearchShape(t *testing.T) {
	stored := func(settings string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal([]byte(`{"template":{"settings":`+settings+`}}`), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	for _, tc := range []struct {
		settings string
		want     map[string]any
		same     bool
	}{
		{`{"index":{"number_of_shards":"1","auto_expand_replicas":"0-1"}}`, autoReplicas, true},
		{`{"index":{"number_of_shards":"1","number_of_replicas":"0"}}`, autoReplicas, false},
		{`{"index":{"number_of_shards":"1","number_of_replicas":"0"}}`, noReplicas, true},
		{`{"index":{"number_of_replicas":"1"}}`, noReplicas, false},
		{`{"index":{"number_of_replicas":"0","auto_expand_replicas":"false"}}`, noReplicas, true},
		{`{"index.auto_expand_replicas":"0-1"}`, autoReplicas, true},
		{`{}`, noReplicas, false},
		// Shards: one unless asked for, whether or not the template says so.
		{`{"index":{"number_of_shards":"3","auto_expand_replicas":"0-1"}}`, autoReplicas, false},
		{`{"index":{"number_of_shards":"3","auto_expand_replicas":"0-1"}}`, map[string]any{"auto_expand_replicas": "0-1", "number_of_shards": 3}, true},
		{`{"index":{"number_of_shards":"1","auto_expand_replicas":"0-1"}}`, map[string]any{"auto_expand_replicas": "0-1", "number_of_shards": 3}, false},
		{`{"index.auto_expand_replicas":"0-1"}`, map[string]any{"auto_expand_replicas": "0-1", "number_of_shards": 1}, true},
	} {
		if got := sameReplicas(stored(tc.settings), tc.want); got != tc.same {
			t.Errorf("%s with %v: same %v", tc.settings, tc.want, got)
		}
	}
}

// opensearch.shards sets number_of_shards on each new day's indices;
// the default template keeps one.
func TestIndexTemplateShards(t *testing.T) {
	settings := func(tmpl map[string]any) map[string]any {
		return tmpl["template"].(map[string]any)["settings"].(map[string]any)
	}
	if got := settings(IndexTemplate("p", autoReplicas))["number_of_shards"]; got != 1 {
		t.Errorf("default shards %v, want 1", got)
	}
	s := settings(IndexTemplate("p", map[string]any{"auto_expand_replicas": "0-1", "number_of_shards": 4}))
	if s["number_of_shards"] != 4 || s["auto_expand_replicas"] != "0-1" {
		t.Errorf("settings %v, want 4 shards and auto replicas", s)
	}
}

// The keyword fallback for OpenSearch before 2.15 is the same version.
func TestWithoutWildcardKeepsVersion(t *testing.T) {
	tmpl := withoutWildcard(IndexTemplate("sig", autoReplicas))
	if v := storedVersion(roundTrip(t, tmpl)); v != TemplateVersion {
		t.Errorf("version %d", v)
	}
}

func roundTrip(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestTemplateVersionBumped fails when IndexTemplate's output changes
// without a new TemplateVersion: servers of this version would otherwise
// keep the template another server of the same version wrote.
func TestTemplateVersionBumped(t *testing.T) {
	b, err := json.Marshal(IndexTemplate("p", autoReplicas))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != templateHash {
		t.Errorf("IndexTemplate changed: bump TemplateVersion and update this hash (templateHash in template.go) to %s", got)
	}
}

// An older server that wrote its template over this version's, as two
// servers starting together during an upgrade may, has it put back by the
// next check; a template of this version with other replicas is left
// alone, so servers whose Replicas differ do not take turns.
func TestRestoreIndexTemplate(t *testing.T) {
	ctx := context.Background()
	os := ostest.New(t)
	cl := store.New(store.Config{URL: os.URL})
	if err := cl.PutIndexTemplate(ctx, "sig", withVersion(IndexTemplate("sig", autoReplicas), TemplateVersion-1)); err != nil {
		t.Fatal(err)
	}
	if put, err := RestoreIndexTemplate(ctx, cl, "sig", autoReplicas, nil); err != nil || !put {
		t.Fatalf("older template: put %v, %v", put, err)
	}
	var stored map[string]any
	if err := json.Unmarshal(os.Template("sig"), &stored); err != nil || storedVersion(stored) != TemplateVersion {
		t.Fatalf("stored %v %v", stored["_meta"], err)
	}
	if put, err := RestoreIndexTemplate(ctx, cl, "sig", noReplicas, nil); err != nil || put {
		t.Errorf("same version, other replicas: put %v, %v", put, err)
	}
}
