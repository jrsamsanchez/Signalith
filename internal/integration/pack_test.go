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
	"github.com/jrsamsanchez/signalith/internal/lookuptables"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
	"github.com/jrsamsanchez/signalith/internal/splcheck"
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
	packs, dets, err := detect.Packs()
	if err != nil {
		t.Fatal(err)
	}
	// The splunk pack's lookup stages read the tables it ships, which
	// every lookup store has.
	var lookups map[string]*splcheck.Lookup
	for _, p := range packs {
		if p.Name == "splunk" {
			lookups = p.Lookups()
		}
	}
	eng.Lookups, _ = lookuptables.Open("")
	// The splunk pack's iplocation rules read the GeoIP database their
	// test events were made with.
	eng.GeoIP = splcheck.TestGeoIP()
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
		// later is set for a Splunk rule whose later stages run after
		// its filter: its whole query runs for each event's host.
		later bool
	}
	var rules []ruleCases
	records := map[string][]map[string]any{}
	var osqueryEvents []ingest.Event
	// On a 10-minute boundary, so a repeated case's events fall in one
	// bucket of any span a rule counts over (bucket span=2m _time).
	at := time.Now().Add(-15 * time.Minute).Truncate(10 * time.Minute)
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
		macros := map[string]*splcheck.Macro{}
		files, _ := filepath.Glob(filepath.Join(dir, "macros", "*.yml"))
		for _, f := range files {
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			m, err := splcheck.ParseMacro(src)
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			macros[m.Name] = m
		}
		for _, r := range manifest.Rules {
			i++
			d := byID[r.ID]
			if d == nil {
				t.Fatalf("%s is in the manifest but not loaded", r.ID)
			}
			later := false
			if name == "splunk" {
				src, err := os.ReadFile(filepath.Join(dir, "rules", r.File))
				if err != nil {
					t.Fatal(err)
				}
				rule, err := splcheck.ParseWith(src, macros, splcheck.ParseOptions{Network: detect.SplunkNetworkRule(r.Path), Lookups: lookups})
				if err != nil {
					t.Fatalf("%s: %v", r.ID, err)
				}
				later = rule.Post != ""
			}
			raw, err := os.ReadFile(filepath.Join(dir, "tests", strings.TrimSuffix(r.File, ".yml")+".json"))
			if err != nil {
				t.Fatal(err)
			}
			tf, err := sigmacheck.DecodeTestFile(raw)
			if err != nil {
				t.Fatal(err)
			}
			rc := ruleCases{det: d, positives: map[string]bool{}, later: later}
			for j, c := range tf.Cases {
				host := fmt.Sprintf("case-%d-%d", i, j)
				rc.hosts = append(rc.hosts, host)
				if c.Expect {
					rc.positives[host] = true
				}
				copies, offsets := c.Copies()
				for k, cp := range copies {
					if cp.Channel == sigmacheck.MacOSChannel {
						// osquery's results come through its remote API,
						// parsed as the API parses them.
						osqueryEvents = append(osqueryEvents, cp.Stored(host, at.Add(offsets[k])))
						continue
					}
					tag, rec := cp.Record(host, at.Add(offsets[k]))
					records[tag] = append(records[tag], rec)
				}
				// The events a join's subsearch reads, on the same host.
				for _, w := range c.With {
					tag, rec := w.Record(host, at)
					records[tag] = append(records[tag], rec)
				}
				// A Linux program start, as auditd records it too.
				// (Not for a case with events a join reads, which are
				// Sysmon's.)
				if recs, ok := c.AuditdProcessRecords(host+"-auditd", at); ok && c.Repeat <= 1 && len(c.With) == 0 {
					rc.hosts = append(rc.hosts, host+"-auditd")
					if c.Expect {
						rc.positives[host+"-auditd"] = true
					}
					records["linux.audit"] = append(records["linux.audit"], recs...)
				}
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
	if len(osqueryEvents) > 0 {
		total += len(osqueryEvents)
		res, err := p.IngestEvents(ctx, osqueryEvents)
		if err != nil || len(res.Errors) > 0 {
			t.Fatalf("ingest osquery events: %v %+v", err, res)
		}
	}
	if err := cl.Do(ctx, http.MethodPost, "/"+prefix+"-*/_refresh", nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d rules, %d test events", len(rules), total)

	failed := 0
	for _, rc := range rules {
		if rc.later {
			var wrong []string
			for _, h := range rc.hosts {
				q, err := query.Parse(rc.det.Query)
				if err != nil {
					t.Fatal(err)
				}
				q.Search = &query.And{Children: []query.Expr{q.Search, &query.Compare{Field: "host", Op: "=", Value: h}}}
				for _, c := range q.Commands {
					// A join's subsearch reads the case's own events, not
					// another case's that share its values.
					if j, ok := c.(*query.Join); ok {
						j.Sub.Search = &query.And{Children: []query.Expr{j.Sub.Search, &query.Compare{Field: "host", Op: "=", Value: h}}}
					}
				}
				q.Earliest = "-1h"
				res, err := eng.Execute(ctx, q)
				if err != nil {
					wrong = append(wrong, fmt.Sprintf("%s (%v)", h, err))
					continue
				}
				if got := len(res.Rows) > 0; got != rc.positives[h] {
					wrong = append(wrong, fmt.Sprintf("%s (want %v)", h, rc.positives[h]))
				}
			}
			if len(wrong) > 0 {
				t.Errorf("%s: OpenSearch disagrees on %s\nquery: %s", rc.det.ID, strings.Join(wrong, ", "), rc.det.Query)
				failed++
			}
			continue
		}
		q, err := query.Parse(rc.det.Query)
		if err != nil {
			t.Fatal(err)
		}
		q.Search = &query.And{Children: []query.Expr{q.Search, &query.In{Field: "host", Values: rc.hosts}}}
		q.Earliest = "-1h"
		// The regex stages a detection runs right after its filter (a
		// Splunk regular expression with word boundaries) stay.
		var cmds []query.Command
		for _, c := range q.Commands {
			if _, ok := c.(*query.Regex); !ok {
				break
			}
			cmds = append(cmds, c)
		}
		q.Commands = append(cmds, &query.Stats{Aggs: []query.Agg{{Func: "count"}}, By: []string{"host"}})
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
