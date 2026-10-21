// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// twelveModels are the data models a Windows and Sysmon fleet writes
// every day.
var twelveModels = []string{"authentication", "endpoint", "network_traffic", "change", "filesystem", "registry",
	"network_resolution", "image_load", "script", "alerts", "risk", "other"}

// days returns event indices of models for n days up to now, each with
// copies shard copies.
func days(models []string, n, copies int, now time.Time) []indexCopies {
	var out []indexCopies
	for d := range n {
		day := now.UTC().AddDate(0, 0, -d).Format("2006.01.02")
		for _, m := range models {
			out = append(out, indexCopies{Index: "signalith-" + m + "-" + day, Copies: copies})
		}
	}
	return out
}

func TestProjectShards(t *testing.T) {
	now := time.Now().Add(-time.Hour)
	keep90 := func(string) int { return 90 }

	// One node, twelve models a day, kept 90 days: 12 x 91 = 1,092 shards
	// once retention runs, though only 300 are held after 20 days.
	held := append(days(twelveModels, 20, 1, now), indexCopies{Index: "signalith_config", Copies: 1})
	p := projectShards("signalith", held, 260, 1000, keep90, now)
	if p.PerDay != 12 || p.Projected != 260-240+1092 || p.KeepDays != 91 || p.FullInDays != nil {
		t.Errorf("one node: %+v", p)
	}

	// Just after midnight only one model has written today: yesterday's
	// count stands for the others.
	held = append(days(twelveModels, 5, 2, now.AddDate(0, 0, -1)), indexCopies{Index: "signalith-other-" + now.UTC().Format("2006.01.02"), Copies: 2})
	if p := projectShards("signalith", held, 122, 2000, keep90, now); p.PerDay != 24 {
		t.Errorf("after midnight: %+v", p)
	}

	// Rollover parts of one day add up.
	held = []indexCopies{{Index: "signalith-network_traffic-" + now.UTC().Format("2006.01.02"), Copies: 2},
		{Index: "signalith-network_traffic-" + now.UTC().Format("2006.01.02") + "-2", Copies: 2}}
	if p := projectShards("signalith", held, 4, 1000, func(string) int { return 9 }, now); p.PerDay != 4 || p.Projected != 40 {
		t.Errorf("parts: %+v", p)
	}

	// Kept forever: held as now, and the days until 80% of the limit.
	keep := func(m string) int {
		if m == "other" {
			return 0
		}
		return 7
	}
	held = days([]string{"other", "endpoint"}, 3, 1, now)
	p = projectShards("signalith", held, 106, 1000, keep, now)
	if p.Projected != 106-3+8 || p.FullInDays == nil || *p.FullInDays != (800-111)/1 {
		t.Errorf("forever: %+v %v", p, p.FullInDays)
	}
}

func TestShardWarning(t *testing.T) {
	i := func(n int) *int { return &n }
	for _, tc := range []struct {
		card osCard
		want string
	}{
		{osCard{}, ""},
		{osCard{ShardsUsed: i(500), ShardLimit: i(1000), ShardsPerDay: i(5), ShardsProjected: i(600)}, ""},
		{osCard{ShardsUsed: i(850), ShardLimit: i(1000)}, "OpenSearch holds 850 of the 1000 shards it allows"},
		{osCard{ShardsUsed: i(300), ShardLimit: i(1000), ShardsPerDay: i(12), ShardsProjected: i(1092), keepDays: 91},
			"Each day adds 12 shards (an index per data model written) and retention keeps up to 91 days of them, so OpenSearch will hold about 1092 of the 1000"},
		{osCard{ShardsUsed: i(300), ShardLimit: i(1000), ShardsPerDay: i(5), ShardsProjected: i(300), ShardsFullInDays: i(40)}, "in about 40 days OpenSearch will hold 80% of the 1000 shards"},
		{osCard{ShardsUsed: i(300), ShardLimit: i(1000), ShardsPerDay: i(1), ShardsProjected: i(300), ShardsFullInDays: i(500)}, ""},
	} {
		got := shardWarning(tc.card)
		if tc.want == "" && got != "" || !strings.Contains(got, tc.want) {
			t.Errorf("%+v: %q, want %q", tc.card, got, tc.want)
		}
		if got != "" && (!strings.Contains(got, "raise cluster.max_shards_per_node, which is a soft limit") || !strings.Contains(got, "keep fewer days")) {
			t.Errorf("no advice: %q", got)
		}
	}
}

// A single OpenSearch node holding 850 of its 1,000 shards gets a warning
// on the card, as more nodes would.
func TestClusterOpenSearchShardsNearLimit(t *testing.T) {
	os := ostest.New(t)
	os.SetShardsUsed(850)
	ts, _ := newTestServerWith(t, func(s *Server) { s.Backend = store.New(store.Config{URL: os.URL}) })
	code, out := do(t, ts, "GET", "/api/cluster/opensearch", "", true)
	if code != 200 || out["shards_used"] != float64(850) || out["shard_limit"] != float64(1000) {
		t.Fatalf("%d %v", code, out)
	}
	if w := strings.Join(toStrings(out["warnings"]), "\n"); !strings.Contains(w, "OpenSearch holds 850 of the 1000 shards it allows") {
		t.Errorf("warnings %s", w)
	}
}

// One node writing twelve data models a day, with the default 90 days
// kept: the card projects 1,092 shards against 1,000 long before the
// cluster holds them.
func TestClusterOpenSearchShardsProjected(t *testing.T) {
	now := time.Now().Add(-time.Hour)
	held := days(twelveModels, 10, 1, now)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/_cluster/health":
			fmt.Fprintf(w, `{"status":"green","number_of_nodes":1,"number_of_data_nodes":1,"active_shards":%d}`, len(held)+20)
		case r.URL.Path == "/_cluster/settings":
			io.WriteString(w, `{"persistent":{},"transient":{},"defaults":{"cluster.max_shards_per_node":"1000"}}`)
		case strings.HasPrefix(r.URL.Path, "/_cat/indices/"):
			var rows []string
			for _, ix := range held {
				rows = append(rows, fmt.Sprintf(`{"index":%q,"pri":"1","rep":"0"}`, ix.Index))
			}
			io.WriteString(w, "["+strings.Join(rows, ",")+"]")
		default:
			http.NotFound(w, r)
		}
	}))
	defer fake.Close()
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Backend = store.New(store.Config{URL: fake.URL})
		s.Config.Retention.Days = 90
	})
	code, out := do(t, ts, "GET", "/api/cluster/opensearch", "", true)
	if code != 200 || out["shards_used"] != float64(140) || out["shards_per_day"] != float64(12) || out["shards_projected"] != float64(20+12*91) {
		t.Fatalf("%d %v", code, out)
	}
	if w := strings.Join(toStrings(out["warnings"]), "\n"); !strings.Contains(w, "Each day adds 12 shards") || !strings.Contains(w, "about 1112 of the 1000") {
		t.Errorf("warnings %s", w)
	}
}
