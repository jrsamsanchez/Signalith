package shared

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The config index is copied whole into its retired copy, and only then
// deleted.
func TestRetireConfig(t *testing.T) {
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	const prefix = "rt"
	for i := range 3 {
		fake.Put(ConfigIndex(prefix), fmt.Sprintf("doc:%d", i), map[string]any{"kind": "doc", "rev": i, "body": "{}"})
	}
	n, err := RetireConfig(context.Background(), cl, prefix, "20261015T120000")
	if err != nil || n != 3 {
		t.Fatalf("retired %d documents, %v", n, err)
	}
	retired := RetiredConfigIndex(prefix, "20261015T120000")
	if retired != "rt_config_retired_20261015T120000" {
		t.Fatalf("retired index %s", retired)
	}
	idx := fake.Indices()
	if slices.Contains(idx, ConfigIndex(prefix)) || !slices.Contains(idx, retired) {
		t.Fatalf("indices after: %v", idx)
	}
	for i := range 3 {
		if src := fake.Source(retired, fmt.Sprintf("doc:%d", i)); src == nil || fmt.Sprint(src["rev"]) != fmt.Sprint(i) {
			t.Errorf("doc:%d copied as %v", i, src)
		}
	}
	list, err := cl.ListIndices(context.Background(), RetiredConfigPattern(prefix))
	if err != nil || len(list) != 1 || list[0] != retired {
		t.Errorf("retired copies %v, %v", list, err)
	}
	// With nothing left to retire, it says so and changes nothing.
	if _, err := RetireConfig(context.Background(), cl, prefix, "20261015T130000"); err == nil {
		t.Error("retired a config index that is gone")
	}
	if slices.Contains(fake.Indices(), RetiredConfigIndex(prefix, "20261015T130000")) {
		t.Error("an empty retired copy was made")
	}
}
