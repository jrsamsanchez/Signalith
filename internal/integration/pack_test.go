//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// TestPackRulesAgainstOpenSearch repeats the content pack check against a
// real OpenSearch: every test event of every shipped rule goes through the
// ingest pipeline into real indices, then every rule's own query runs, and
// it must return exactly its positive events. The unit test
// (detect.TestPackRulesFireOnTheirTests) evaluates the same queries in
// memory; this one proves OpenSearch agrees, including case folding,
// wildcards and escaping.
func TestPackRulesAgainstOpenSearch(t *testing.T) {
	cl, eng, prefix := setup(t)
	ctx := context.Background()
	_, dets, err := detect.Packs()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]*detect.Detection{}
	for _, d := range dets {
		byID[d.ID] = d
	}

	// Each case's event gets its own host name, so a rule's search can be
	// limited to its own events and the hosts it returns compared.
	type ruleCases struct {
		det       *detect.Detection
		hosts     []string
		positives map[string]bool
	}
	var rules []ruleCases
	records := map[string][]map[string]any{}
	at := time.Now().Add(-5 * time.Minute)
	i := 0
	for _, name := range []string{"sigmahq", "splunk"} {
		dir := filepath.Join("..", "detect", "packs", name)
		data, err := os.ReadFile(filepath.Join(dir, "pack.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		var manifest detect.Pack
		if err := yaml.Unmarshal(data, &manifest); err != nil {
			t.Fatal(err)
		}
		for _, r := range manifest.Rules {
			i++
			d := byID[r.ID]
			if d == nil {
				t.Fatalf("%s is in the manifest but not loaded", r.ID)
			}
			raw, err := os.ReadFile(filepath.Join(dir, "tests", strings.TrimSuffix(r.File, ".yml")+".json"))
			if err != nil {
				t.Fatal(err)
			}
			tf, err := sigmacheck.DecodeTestFile(raw)
			if err != nil {
				t.Fatal(err)
			}
			rc := ruleCases{det: d, positives: map[string]bool{}}
			for j, c := range tf.Cases {
				host := fmt.Sprintf("case-%d-%d", i, j)
				rc.hosts = append(rc.hosts, host)
				if c.Expect {
					rc.positives[host] = true
				}
				tag, rec := c.Record(host, at)
				records[tag] = append(records[tag], rec)
			}
			rules = append(rules, rc)
		}
	}
	p := &ingest.Pipeline{Store: cl, Prefix: prefix}
	total := 0
	for tag, recs := range records {
		total += len(recs)
		for start := 0; start < len(recs); start += 500 {
			end := min(start+500, len(recs))
			res, err := p.Ingest(ctx, tag, recs[start:end])
			if err != nil || len(res.Errors) > 0 {
				t.Fatalf("ingest: %v %+v", err, res)
			}
		}
	}
	if err := cl.Do(ctx, http.MethodPost, "/"+prefix+"-*/_refresh", nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d rules, %d test events", len(rules), total)

	failed := 0
	for _, rc := range rules {
		q, err := query.Parse(rc.det.Query)
		if err != nil {
			t.Fatal(err)
		}
		q.Search = &query.And{Children: []query.Expr{q.Search, &query.In{Field: "host", Values: rc.hosts}}}
		q.Earliest = "-1h"
		q.Commands = []query.Command{&query.Stats{Aggs: []query.Agg{{Func: "count"}}, By: []string{"host"}}}
		res, err := eng.Execute(ctx, q)
		if err != nil {
			t.Errorf("%s: %v", rc.det.ID, err)
			failed++
			continue
		}
		got := map[string]bool{}
		for _, row := range res.Rows {
			got[fmt.Sprint(row["host"])] = true
		}
		var wrong []string
		for _, h := range rc.hosts {
			if got[h] != rc.positives[h] {
				wrong = append(wrong, fmt.Sprintf("%s (want %v)", h, rc.positives[h]))
			}
		}
		if len(wrong) > 0 {
			sort.Strings(wrong)
			t.Errorf("%s: OpenSearch disagrees on %s\nquery: %s", rc.det.ID, strings.Join(wrong, ", "), rc.det.Query)
			failed++
		}
		if failed > 25 {
			t.Fatal("too many failures")
		}
	}
}
