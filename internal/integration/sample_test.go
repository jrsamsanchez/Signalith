//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/risk"
	"github.com/jrsamsanchez/signalith/internal/sample"
)

// TestSampleDataEndToEnd loads the small sample set into a real OpenSearch
// next to real data, backfills the detections, and checks what an
// evaluator sees: every finding-raising detection fired, risk has no
// duplicates, the sample investigation is the phishing story. It checks
// that the real data is left alone throughout: real events inside the
// backfill's windows are not marked, the live scheduler raises nothing from
// the sample, real findings and cases about hosts that share a sample name
// survive removal, the user's list files are never rewritten, and a day
// retention made read-only is still cleaned. Finally a load cancelled part
// way is removable.
//
// The findings and cases indices are made the way a version from before the
// sample data made them, without its marker field, and the background
// jobs' Upgrade never runs: the load maps the field itself. A second
// server sharing the OpenSearch sees the load, refuses to load again and
// takes the sample's asset and identity context up and down with it.
func TestSampleDataEndToEnd(t *testing.T) {
	cl, eng, prefix := setup(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	fstore := findings.NewOpenSearch(cl, prefix)
	cstore := cases.NewOpenSearch(cl, prefix)
	ibackend := intel.NewOpenSearch(cl, prefix)
	indicators := intel.NewStore(ibackend)
	listDir := t.TempDir()
	const userAssets = "host,ip,cidr,owner,priority,category,bunit,location\nreal-dc,10.1.1.1,,IT,high,,Prod,\ndc-01,10.20.0.10,,IT,critical,,Prod,\nodd-box,10.1.1.2,,IT,urgent,,Prod,\n"
	if err := os.WriteFile(filepath.Join(listDir, assets.AssetsFile), []byte(userAssets), 0o640); err != nil {
		t.Fatal(err)
	}
	lists, err := assets.OpenStore(listDir) // the damaged line: empty lists, file left alone
	if err == nil {
		t.Fatal("the damaged list should be reported")
	}
	lib, _, err := detect.NewLibrary(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Findings and cases indices from before the sample data: no "sample"
	// field. The server that runs the background jobs has not upgraded
	// them (it may run an older version).
	kw := map[string]any{"type": "keyword"}
	off := map[string]any{"type": "object", "enabled": false}
	date := map[string]any{"type": "date"}
	title := map[string]any{"type": "text", "fields": map[string]any{"raw": kw}}
	for index, props := range map[string]map[string]any{
		fstore.Index: {"id": kw, "detection_id": kw, "severity": kw, "urgency": kw, "status": kw, "owner": kw,
			"disposition": kw, "mitre": kw, "group_key": kw, "entity_values": kw, "case_id": kw,
			"title": title, "description": map[string]any{"type": "text"}, "created": date, "updated": date,
			"result": off, "entities": off, "comments": off, "history": off, "context": off,
			"query": map[string]any{"type": "keyword", "index": false}},
		cstore.Index: {"id": kw, "status": kw, "severity": kw, "owner": kw, "findings": kw, "entity_values": kw, "created_by": kw,
			"title": title, "description": map[string]any{"type": "text"}, "resolution": map[string]any{"type": "text"},
			"created": date, "updated": date, "entities": off, "entries": off, "history": off},
	} {
		body := map[string]any{"settings": map[string]any{"number_of_shards": 1, "number_of_replicas": 0},
			"mappings": map[string]any{"dynamic": "false", "properties": props}}
		if err := cl.Do(ctx, http.MethodPut, "/"+index, body, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := ibackend.EnsureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	if err := indicators.Load(ctx); err != nil {
		t.Fatal(err)
	}
	eng.Assets = lists
	eng.Intel = indicators
	riskStore := &risk.Store{Client: cl, Prefix: prefix}
	refresh := func() {
		t.Helper()
		if err := cl.Do(ctx, http.MethodPost, "/"+prefix+"-*/_refresh", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	count := func(q string) int64 {
		t.Helper()
		res, err := eng.Execute(ctx, mustParse(t, q))
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if len(res.Rows) == 1 {
			if n, err := strconv.ParseFloat(fmt.Sprint(res.Rows[0]["count"]), 64); err == nil {
				return int64(n)
			}
		}
		return res.Matched
	}

	// Real data that must be left alone.
	now := time.Now()
	loader := &sample.Loader{
		Prefix: prefix, Bulk: cl, OS: cl, Docs: cl, Intel: indicators, Assets: lists,
		Library: lib, Engine: eng, Findings: fstore, Cases: cstore, Risk: riskStore,
		Server: "siem-a", Log: log,
	}
	// Another server sharing the OpenSearch, with lookups of its own.
	listsB, _ := assets.OpenStore(t.TempDir())
	other := &sample.Loader{
		Prefix: prefix, Bulk: cl, OS: cl, Docs: cl, Intel: indicators, Assets: listsB,
		Library: lib, Engine: eng, Findings: fstore, Cases: cstore, Risk: riskStore,
		Server: "siem-b", Log: log,
	}
	runTimes := sample.Generate(sample.Options{Now: now, Size: sample.SizeSmall}).RunTimes
	sshAt := runTimes[len(runTimes)/2] // a time the backfill searches
	real := []ingest.Event{
		{Time: now.Add(-2 * time.Hour), Model: "Authentication",
			Fields: map[string]any{"action": "success", "user": "real.user", "host": "real-host", "app": "sshd"}},
		// An application whose events have a field called "sample".
		{Time: now.Add(-time.Hour), Model: "Other", Fields: map[string]any{"host": "audio-01", "sourcetype": "audio", "sample": "48000"}},
	}
	for i := 0; i < 12; i++ {
		real = append(real, ingest.Event{Time: sshAt.Add(-time.Duration(i) * 20 * time.Second), Model: "Authentication",
			Fields: map[string]any{"action": "failure", "app": "sshd", "src": "172.16.9.9", "dest": "prod-db", "host": "prod-db",
				"user": fmt.Sprintf("user%d", i%4)}})
	}
	pipeline := &ingest.Pipeline{Store: cl, Prefix: prefix, MaxEventAge: 8 * 24 * time.Hour}
	if _, err := pipeline.IngestEvents(ctx, real); err != nil {
		t.Fatal(err)
	}
	refresh()
	realDC := &findings.Finding{ID: "real-dc-01", DetectionID: "risk-threshold-exceeded", Title: "Risk score 140 for system dc-01",
		Severity: "high", Status: findings.StatusInProgress, Owner: "analyst1",
		Created: now.Add(-48 * time.Hour), Updated: now.Add(-48 * time.Hour),
		Entities: map[string]any{"risk_object": "dc-01", "risk_object_type": "system"}}
	if err := fstore.Create(ctx, realDC); err != nil {
		t.Fatal(err)
	}
	realCase := &cases.Case{ID: cases.NewID(now), Title: "Real investigation of dc-01", Status: findings.StatusInProgress,
		CreatedBy: "analyst1", Created: now, Updated: now}
	if _, err := realCase.AddFinding(realDC, "analyst1", now); err != nil {
		t.Fatal(err)
	}
	if err := cstore.Create(ctx, realCase); err != nil {
		t.Fatal(err)
	}
	if err := indicators.Add(ctx, []intel.Indicator{
		{ID: "pre-ind", Source: intel.ManualSource, Type: intel.TypeIP, Value: "203.0.113.200"},
		{ID: "feed-ind", Source: "sample", Type: intel.TypeIP, Value: "203.0.113.201"}, // a user's feed called "sample"
	}); err != nil {
		t.Fatal(err)
	}

	// Load.
	st, err := loader.Load(ctx, sample.SizeSmall, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st.Events == 0 || st.Findings == 0 || st.Skipped != 0 || st.Partial {
		t.Fatalf("state after load: %+v", st)
	}
	refresh()
	mark := datamodel.SampleField + "=" + st.ID

	// The load mapped its marker on the old indices.
	for _, index := range []string{fstore.Index, cstore.Index} {
		var m map[string]struct {
			Mappings struct {
				Properties map[string]any `json:"properties"`
			} `json:"mappings"`
		}
		if err := cl.Do(ctx, http.MethodGet, "/"+index+"/_mapping", nil, &m); err != nil {
			t.Fatal(err)
		}
		if m[index].Mappings.Properties["sample"] == nil {
			t.Errorf("%s has no sample field after the load", index)
		}
	}

	// The other server sees the load and will not load a second one.
	if cur, err := other.Status(ctx); err != nil || cur == nil || cur.ID != st.ID || cur.Partial {
		t.Fatalf("the other server sees %+v, %v", cur, err)
	}
	if _, err := other.Load(ctx, sample.SizeSmall, nil); !errors.Is(err, sample.ErrAlreadyLoaded) {
		t.Fatalf("a second load from the other server: %v", err)
	}
	if err := other.SyncLists(ctx); err != nil {
		t.Fatal(err)
	}
	if a, ok := listsB.Asset("ws-fin-07"); !ok || a.BUnit != sample.SampleBUnit {
		t.Errorf("the other server's ws-fin-07 = %+v", a)
	}

	// Every enabled detection that raises findings raised at least one.
	sampleFindings, _, err := fstore.Search(ctx, findings.Filter{Sample: &st.ID, Limit: 10000})
	if err != nil {
		t.Fatal(err)
	}
	fired := map[string]int{}
	for _, f := range sampleFindings {
		fired[f.DetectionID]++
		if strings.Contains(fmt.Sprint(f.Entities), "172.16.9.9") {
			t.Errorf("real activity was marked as sample: %s %v", f.Title, f.Entities)
		}
	}
	dets, _ := detect.Builtin()
	for _, d := range dets {
		if d.Enabled && (d.Risk == nil || !d.Risk.Only) && fired[d.ID] == 0 {
			t.Errorf("detection %s raised no finding", d.ID)
		}
	}
	// Antivirus findings: only real outbreaks, one finding per ransomware
	// event, and ClamAV's report-only find on app-01 but not its quarantined
	// cryptominer on db-01.
	for _, f := range sampleFindings {
		title := f.Title
		switch {
		case f.DetectionID == "malware-outbreak" && !strings.Contains(title, "Fakepay"):
			t.Errorf("unexpected outbreak finding %q", title)
		case f.DetectionID == "malware-detected" && strings.Contains(title, "Ransom:"):
			t.Errorf("ransomware also raised %q", title)
		case f.DetectionID == "malware-left-clamav" && !strings.Contains(title, "app-01"):
			t.Errorf("unexpected ClamAV finding %q", title)
		}
	}
	if fired["malware-left-clamav"] != 1 {
		t.Errorf("malware-left-clamav raised %d findings, want 1", fired["malware-left-clamav"])
	}
	// The nightly vulnerability scan: one finding per host and CVE, KEV
	// CVEs only as known exploited, and Telnet only on jump-01.
	for id, want := range map[string]int{"vuln-known-exploited": 2, "vuln-critical": 2, "vuln-cleartext-remote-login": 1} {
		if fired[id] != want {
			t.Errorf("%s raised %d findings, want %d", id, fired[id], want)
		}
	}
	for _, f := range sampleFindings {
		switch {
		case f.DetectionID == "vuln-known-exploited" && !strings.Contains(f.Title, "on web-01"),
			f.DetectionID == "vuln-critical" && strings.Contains(f.Title, "CVE-2021-"),
			f.DetectionID == "vuln-cleartext-remote-login" && f.Title != "Telnet open on jump-01":
			t.Errorf("unexpected vulnerability finding %q", f.Title)
		}
	}

	if fired["threat-activity"] == 0 || fired["risk-threshold-exceeded"]+fired["risk-multiple-tactics"] == 0 {
		t.Errorf("threat intel or risk incidents did not fire: %v", fired)
	}
	if n := count("datamodel=Risk src=172.16.9.9 earliest=-8d | stats count"); n != 0 {
		t.Errorf("%d risk events about the real host", n)
	}

	// Risk: written, marked, and never twice for one detection and group.
	res, err := eng.Execute(ctx, mustParse(t, "datamodel=Risk "+mark+" earliest=-8d | stats count by detection_id, group_key, risk_object"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) == 0 {
		t.Error("no sample risk events")
	}
	for _, r := range res.Rows {
		if n, _ := strconv.ParseFloat(fmt.Sprint(r["count"]), 64); n > 1 {
			t.Errorf("risk written %v times for %v / %v on %v", n, r["detection_id"], r["group_key"], r["risk_object"])
		}
	}

	// The built-in Malware dashboard shows the antivirus stories.
	mw, _ := dashboards.GetBuiltin(dashboards.MalwareID)
	for i, pr := range (&dashboards.Runner{Engine: eng}).Run(ctx, mw.Panels, "7d") {
		p := mw.Panels[i]
		if pr.Error != "" {
			t.Errorf("Malware panel %q: %s", p.Title, pr.Error)
			continue
		}
		min := map[string]float64{"Hosts with malware": 6, "Hosts with malware not removed": 2, "Hosts with protection off or tampered with": 1}[p.Title]
		if n, _ := strconv.ParseFloat(fmt.Sprint(pr.Value), 64); min > 0 && n < min {
			t.Errorf("Malware panel %q = %v, want at least %v", p.Title, pr.Value, min)
		}
		if p.Viz != dashboards.VizSingle && (pr.Result == nil || len(pr.Result.Rows) == 0) {
			t.Errorf("Malware panel %q has no rows", p.Title)
		}
	}

	// The investigation is the phishing story on ws-fin-07.
	if len(st.Cases) != 1 {
		t.Fatalf("cases = %v", st.Cases)
	}
	c, err := cstore.Get(ctx, st.Cases[0])
	if err != nil {
		t.Fatal(err)
	}
	if c.Title != sample.CaseTitle || len(c.Findings) < 3 {
		t.Errorf("case %q holds %d findings", c.Title, len(c.Findings))
	}
	ws, ok := lists.Asset("ws-fin-07")
	if !ok || len(ws.IP) == 0 {
		t.Fatal("no sample asset for ws-fin-07")
	}
	for _, fid := range c.Findings {
		f, err := fstore.Get(ctx, fid)
		if err != nil {
			t.Fatal(err)
		}
		ents := fmt.Sprint(f.Entities)
		story := strings.Contains(ents, "ws-fin-07") || strings.Contains(ents, "alice.nguyen") || strings.Contains(ents, ws.IP[0]+" ") || strings.HasSuffix(ents, ws.IP[0]+"]")
		if !story || strings.Contains(ents, "file-01") || strings.Contains(ents, "svc-backup") {
			t.Errorf("case holds %q (%s), which is not the phishing story", f.Title, ents)
		}
	}

	// The lists: the sample's rows answer, the user's file is untouched.
	if a, ok := lists.Asset("ws-fin-07"); !ok || a.BUnit != sample.SampleBUnit {
		t.Errorf("ws-fin-07 = %+v", a)
	}
	checkBytes(t, filepath.Join(listDir, assets.AssetsFile), userAssets)

	// The live scheduler raises nothing from the sample, now or days later
	// when the backfill's throttles have run out.
	before, _, _ := fstore.Search(ctx, findings.Filter{Limit: 10000})
	riskBefore := count("datamodel=Risk earliest=-8d latest=+8d | stats count")
	live := &detect.Scheduler{Library: lib, Engine: eng, Findings: fstore, Risk: riskStore, Assets: lists, Log: log}
	for _, at := range []time.Time{time.Now(), time.Now().Add(5 * 24 * time.Hour), time.Now().Add(7*24*time.Hour + 5*time.Minute)} {
		for _, d := range lib.List() {
			if d.Enabled {
				if _, err := live.RunAt(ctx, d, at); err != nil {
					t.Errorf("live run of %s: %v", d.ID, err)
				}
			}
		}
	}
	refresh()
	after, _, _ := fstore.Search(ctx, findings.Filter{Limit: 10000})
	if len(after) != len(before) {
		for _, f := range after {
			if f.Sample == "" && f.ID != realDC.ID {
				t.Errorf("the live scheduler raised %q from the sample", f.Title)
			}
		}
	}
	if n := count("datamodel=Risk earliest=-8d latest=+8d | stats count"); n != riskBefore {
		t.Errorf("the live scheduler wrote %d risk events from the sample", n-riskBefore)
	}

	// Source health lists the application with a "sample" field.
	if n := count("NOT " + datamodel.SampleField + "=* host=audio-01 | stats count"); n != 1 {
		t.Errorf("source health would not see audio-01 (%d)", n)
	}

	// Retention makes a day read-only: the one with the real SSH events.
	blocked := datamodel.IndexName(prefix, "Authentication", sshAt.UTC().Format("2006.01.02"))
	if err := cl.Do(ctx, http.MethodPut, "/"+blocked+"/_settings", map[string]any{"index.blocks.write": true}, nil); err != nil {
		t.Fatal(err)
	}

	// Remove.
	if _, err := loader.Remove(ctx, nil); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	refresh()
	for _, q := range []string{mark + " earliest=-8d latest=+8d | stats count", "datamodel=Risk " + mark + " earliest=-8d latest=+8d | stats count"} {
		if n := count(q); n != 0 {
			t.Errorf("%q: %d sample docs remain", q, n)
		}
	}
	var out map[string]struct {
		Settings map[string]any `json:"settings"`
	}
	if err := cl.Do(ctx, http.MethodGet, "/"+blocked+"/_settings/index.blocks.write?flat_settings=true", nil, &out); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(out[blocked].Settings["index.blocks.write"]) != "true" {
		t.Errorf("%s is no longer read-only: %v", blocked, out)
	}
	_ = cl.Do(ctx, http.MethodPut, "/"+blocked+"/_settings", map[string]any{"index.blocks.write": nil}, nil)

	if left, _, _ := fstore.Search(ctx, findings.Filter{Sample: &st.ID, Limit: 100}); len(left) != 0 {
		t.Errorf("%d sample findings remain", len(left))
	}
	if f, err := fstore.Get(ctx, realDC.ID); err != nil || f.Owner != "analyst1" {
		t.Errorf("the real dc-01 finding: %+v, %v", f, err)
	}
	if c, err := cstore.Get(ctx, realCase.ID); err != nil || len(c.Findings) != 1 {
		t.Errorf("the real dc-01 case: %+v, %v", c, err)
	}
	if n := count("datamodel=Authentication src=172.16.9.9 earliest=-8d | stats count"); n != 12 {
		t.Errorf("real SSH events left: %d, want 12", n)
	}
	if n := count("user=real.user | stats count"); n != 1 {
		t.Errorf("real event left: %d", n)
	}
	_ = indicators.Load(ctx)
	inds, _ := indicators.List(intel.Filter{})
	sources := map[string]int{}
	for _, ind := range inds {
		sources[ind.Source]++
	}
	if sources[sample.SampleIntelSource] != 0 || sources[intel.ManualSource] != 1 || sources["sample"] != 1 {
		t.Errorf("indicators by source after removal: %v", sources)
	}
	if a, i := lists.Overlay(); len(a)+len(i) != 0 {
		t.Error("sample list rows remain")
	}
	checkBytes(t, filepath.Join(listDir, assets.AssetsFile), userAssets)
	if cur, _ := loader.Status(ctx); cur != nil {
		t.Error("state remained after removal")
	}
	if cur, _ := other.Status(ctx); cur != nil {
		t.Error("the other server still sees the removed load")
	}
	if err := other.SyncLists(ctx); err != nil {
		t.Fatal(err)
	}
	if a, i := listsB.Overlay(); len(a)+len(i) != 0 {
		t.Error("the other server kept the sample's asset and identity context")
	}

	// A load stopped part way (Ctrl-C during the detections) is partial,
	// refuses another load, and Remove takes out everything it wrote.
	cctx, cancel := context.WithCancel(ctx)
	_, err = loader.Load(cctx, sample.SizeSmall, func(p sample.Progress) {
		if p.Phase == "Running detections" && p.Percent >= 60 {
			cancel()
		}
	})
	cancel()
	if err == nil {
		t.Fatal("the cancelled load succeeded")
	}
	cur, _ := loader.Status(ctx)
	if cur == nil || !cur.Partial {
		t.Fatalf("status after a cancelled load: %+v", cur)
	}
	if _, err := loader.Load(ctx, sample.SizeSmall, nil); err == nil {
		t.Error("a load over a partial one should be refused")
	}
	refresh()
	if count(datamodel.SampleField+"="+cur.ID+" earliest=-8d latest=+8d | stats count") == 0 {
		t.Fatal("the cancelled load wrote nothing; the test proves nothing")
	}
	if _, err := loader.Remove(ctx, nil); err != nil {
		t.Fatalf("Remove after a cancelled load: %v", err)
	}
	refresh()
	if n := count(datamodel.SampleField + "=* earliest=-8d latest=+8d | stats count"); n != 0 {
		t.Errorf("%d marked docs remain after removing the partial load", n)
	}
	if left, _, _ := fstore.Search(ctx, findings.Filter{Sample: &cur.ID, Limit: 100}); len(left) != 0 {
		t.Errorf("%d findings of the partial load remain", len(left))
	}
}

func checkBytes(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil || string(b) != want {
		t.Errorf("%s changed (%v):\n%s", filepath.Base(path), err, b)
	}
}

func mustParse(t *testing.T, s string) *query.Query {
	t.Helper()
	q, err := query.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return q
}
