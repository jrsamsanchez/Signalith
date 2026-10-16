package intel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The index keeps a copy on another node once OpenSearch has more than
// one; one made before that gets the setting from Replicate.
func TestIndexReplicas(t *testing.T) {
	ctx := context.Background()
	fake := ostest.New(t)
	s := NewOpenSearch(store.New(store.Config{URL: fake.URL}), "sig")
	// Missing: nothing to change.
	if err := s.Replicate(ctx); err != nil {
		t.Fatalf("replicate a missing index: %v", err)
	}
	if err := s.EnsureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Settings map[string]any `json:"settings"`
	}
	if err := json.Unmarshal(fake.IndexBody(s.Index), &body); err != nil {
		t.Fatal(err)
	}
	if body.Settings["auto_expand_replicas"] != "0-1" || body.Settings["number_of_replicas"] != nil {
		t.Errorf("created with %v", body.Settings)
	}
	// Made with the setting: Replicate leaves it as it is.
	if err := s.Replicate(ctx); err != nil {
		t.Fatal(err)
	}
	if got := fake.Settings(s.Index); len(got) != 0 {
		t.Errorf("an index with copies already was changed: %s", got)
	}
	// Made by an older version with no copy: Replicate gives it the
	// setting, once.
	old := NewOpenSearch(s.Client, "old")
	if err := s.Client.(*store.Client).Do(ctx, "PUT", "/"+old.Index, map[string]any{"settings": map[string]any{"number_of_replicas": 0}}, nil); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := old.Replicate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got := fake.Settings(old.Index)
	if len(got) != 1 || !strings.Contains(string(got[0]), `"auto_expand_replicas":"0-1"`) {
		t.Errorf("settings sent %s", got)
	}
	// opensearch.replicas set to a number: new indices get it, and an
	// index someone gave copies by hand is left alone.
	two := NewOpenSearch(s.Client, "two")
	two.Replicas = map[string]any{"number_of_replicas": 2}
	if err := two.EnsureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fake.IndexBody(two.Index)), `"number_of_replicas":2`) {
		t.Errorf("created with %s", fake.IndexBody(two.Index))
	}
	old.Replicas = two.Replicas
	if err := s.Client.(*store.Client).Do(ctx, "PUT", "/"+old.Index+"/_settings", map[string]any{"index": map[string]any{"number_of_replicas": 3}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := old.Replicate(ctx); err != nil {
		t.Fatal(err)
	}
	if got := fake.Settings(old.Index); len(got) != 2 {
		t.Errorf("copies set by hand were changed: %s", got)
	}
}
