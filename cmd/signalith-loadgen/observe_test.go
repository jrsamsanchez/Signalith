package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseProcStat(t *testing.T) {
	// A name with spaces and a ")" must not shift the fields.
	line := "4242 (sig nal)ith) S 1 4242 4242 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 12 0 9000 812345678 2048 18446744073709551615"
	st, err := parseProcStat(line)
	if err != nil {
		t.Fatal(err)
	}
	if st.cpu != 3*time.Second {
		t.Errorf("cpu %v, want 3s (300 ticks)", st.cpu)
	}
	if st.rss != 2048*int64(os.Getpagesize()) {
		t.Errorf("rss %d", st.rss)
	}
	if _, err := parseProcStat("garbage"); err == nil {
		t.Error("garbage parsed")
	}
}

func TestParsePIDs(t *testing.T) {
	got, err := parsePIDs("a=12, b = 34")
	if err != nil || got["a"] != 12 || got["b"] != 34 {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"a", "a=x", "=3", "a=-1"} {
		if _, err := parsePIDs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestProcSamplerRecordsBusiestServer(t *testing.T) {
	m := newMetrics()
	m.SetPhase("load")
	var calls atomic.Int64
	p := &procSampler{pids: map[string]int{"a": 1, "b": 2}, m: m, read: func(pid int) (procStat, error) {
		n := calls.Add(1)
		// b uses CPU as fast as time passes; a uses none.
		cpu := time.Duration(0)
		if pid == 2 {
			cpu = time.Duration(n) * 100 * time.Millisecond
		}
		return procStat{cpu: cpu, rss: int64(pid) * 100 << 20}, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	p.phase(ctx, "load")
	if v, _ := m.Gauge("load", "server_memory_mb"); v != 200 {
		t.Errorf("server_memory_mb %v, want 200", v)
	}
	if v, ok := m.Gauge("load", "cpu_cores_b"); !ok || v <= 0 {
		t.Errorf("cpu_cores_b %v %v", v, ok)
	}
	if v, _ := m.Gauge("load", "cpu_cores_a"); v != 0 {
		t.Errorf("cpu_cores_a %v", v)
	}
}

// fakeNode answers the OpenSearch health call with status, or with 503.
func fakeNode(t *testing.T, status string, hits *atomic.Int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if status == "" {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/_cluster/health/signalith_") {
			t.Errorf("health asked for %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOSReaderMovesToAnotherNode(t *testing.T) {
	var downHits, upHits atomic.Int64
	down := fakeNode(t, "", &downHits)
	up := fakeNode(t, "yellow", &upHits)
	// A closed address too: a stopped node refuses connections.
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	r, err := newOSReader(OpenSearch{URL: gone.URL, URLs: []string{down.URL, up.URL}})
	if err != nil {
		t.Fatal(err)
	}
	st, err := r.indexHealth(context.Background())
	if err != nil || st != "yellow" {
		t.Fatalf("health %q %v", st, err)
	}
	// The node that answered is used first from now on.
	before := downHits.Load()
	if _, err := r.indexHealth(context.Background()); err != nil {
		t.Fatal(err)
	}
	if downHits.Load() != before {
		t.Error("the reader went back to the node that did not answer")
	}
	// do fails over the same way.
	var out map[string]string
	r.cur.Store(0)
	if err := r.do(context.Background(), http.MethodGet, "/_cluster/health/signalith_*", nil, &out); err != nil || out["status"] != "yellow" {
		t.Fatalf("do: %v %v", out, err)
	}
}

func TestOSReaderAllNodesDown(t *testing.T) {
	var hits atomic.Int64
	down := fakeNode(t, "", &hits)
	r, err := newOSReader(OpenSearch{URL: down.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.indexHealth(context.Background()); err == nil {
		t.Error("no error with every node down")
	}
}

func TestEventsPerSecondAndScaling(t *testing.T) {
	phases := []PhaseReport{
		{Name: "warm", Seconds: 10, Counts: map[string]int64{"agent_events_stored": 1000}},
		{Name: "peak", Seconds: 20, Counts: map[string]int64{"agent_events_stored": 40000}},
		{Name: "drain", Seconds: 30, Counts: map[string]int64{"agent_events_stored": 500}},
	}
	if v, skip := eventsPerSecond(phases, "peak"); skip != "" || v != 2000 {
		t.Errorf("peak %v %q", v, skip)
	}
	if v, _ := eventsPerSecond(phases, ""); v != 41000.0/30 {
		t.Errorf("all %v (drain must not count)", v)
	}
	if _, skip := eventsPerSecond(phases, "nope"); skip == "" {
		t.Error("missing phase not skipped")
	}

	base := &Report{Phases: []PhaseReport{{Name: "peak", Seconds: 20, Counts: map[string]int64{"agent_events_stored": 20000}}}}
	two, three := 1.7, 2.4
	c := Criterion{Name: "ingest_scaling", Phase: "peak", MinByServers: map[int]float64{2: two, 3: three}}
	r := &runner{s: &Scenario{Criteria: []Criterion{c}}, opts: runOptions{Baseline: base}, m: newMetrics(),
		report: &Report{Phases: phases}, fleet: &Fleet{}, servers: []string{"a", "b"}}
	r.evaluate()
	got := r.report.Criteria[0]
	if got.Measured == nil || *got.Measured != 2 || got.Status != statusPass || got.Limit != ">= 1.7" {
		t.Errorf("two servers at twice the baseline: %+v", got)
	}
	r.servers = []string{"a", "b", "c"}
	r.report.Criteria = nil
	r.evaluate()
	if got := r.report.Criteria[0]; got.Status != statusFail || got.Limit != ">= 2.4" {
		t.Errorf("three servers at twice the baseline: %+v", got)
	}
	r.servers = nil
	r.report.Criteria = nil
	r.evaluate()
	if got := r.report.Criteria[0]; got.Status != statusRecord {
		t.Errorf("one server has no limit, so it is recorded: %+v", got)
	}
	r.opts.Baseline = nil
	if _, skip := r.measure(c); !strings.Contains(skip, "-baseline") {
		t.Errorf("no baseline: %q", skip)
	}
}

func TestIngestShareMin(t *testing.T) {
	m := newMetrics()
	f := newFleet("r", "t", []string{"https://a", "https://b"}, nil, m)
	m.SetPhase("warm")
	m.Add(targetCounter(0), 1000)
	m.SetPhase("share")
	m.Add(targetCounter(0), 300)
	m.Add(targetCounter(1), 100)
	r := &runner{s: &Scenario{Targets: f.targets}, m: m, report: &Report{}, fleet: f}
	v, skip := r.measure(Criterion{Name: "ingest_share_min", Phase: "share"})
	if skip != "" || v != 0.5 {
		t.Errorf("share %v %q, want 0.5 (100 of 400, two targets)", v, skip)
	}
	r.s.Targets = r.s.Targets[:1]
	if _, skip := r.measure(Criterion{Name: "ingest_share_min"}); skip == "" {
		t.Error("one target not skipped")
	}
}

func TestClusterViewWindows(t *testing.T) {
	var v clusterView
	if err := json.Unmarshal([]byte(`{"servers":[{"name":"siem-1","state":"ready","os":"linux"},
		{"name":"win-1","state":"ready","os":"windows"},{"name":"win-2","state":"offline","os":"windows"}]}`), &v); err != nil {
		t.Fatal(err)
	}
	if w := v.windows(); len(w) != 1 || w[0] != "win-1" {
		t.Errorf("windows %v", w)
	}
	if !v.isWindows("win-2") || v.isWindows("siem-1") || v.isWindows("nope") {
		t.Error("isWindows")
	}
}

func TestChecksCountFailures(t *testing.T) {
	r := &runner{s: &Scenario{Checks: []Check{{Name: "ok", Cmd: "exit 0"}, {Name: "bad", Cmd: "echo nope; exit 3"}}},
		m: newMetrics(), report: &Report{}}
	if runtime.GOOS == "windows" {
		r.s.Checks = []Check{{Name: "ok", Cmd: "exit 0"}, {Name: "bad", Cmd: "echo nope & exit 3"}}
	}
	r.runChecks(context.Background())
	v, skip := r.measure(Criterion{Name: "check_failures"})
	if skip != "" || v != 1 {
		t.Fatalf("check_failures %v %q", v, skip)
	}
	if r.report.Checks[1].Pass || !strings.Contains(r.report.Checks[1].Output, "nope") {
		t.Errorf("%+v", r.report.Checks[1])
	}
	var b strings.Builder
	r.report.WriteText(&b)
	if !strings.Contains(b.String(), "Check bad: FAILED") {
		t.Errorf("report text:\n%s", b.String())
	}
}

func TestReadReportRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.json")
	rep := &Report{Run: "abc", Scenario: "s", Servers: []string{"a"},
		Phases: []PhaseReport{{Name: "p", Seconds: 5, Counts: map[string]int64{"agent_events_stored": 50}}}}
	if err := rep.WriteJSON(path); err != nil {
		t.Fatal(err)
	}
	got, err := readReport(path)
	if err != nil || got.Run != "abc" || got.Phases[0].Counts["agent_events_stored"] != 50 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestSizingTable(t *testing.T) {
	reports := []*Report{
		{Phases: []PhaseReport{
			{Name: "1k", Seconds: 45, Counts: map[string]int64{"agent_events_stored": 45000},
				Latencies: map[string]LatencySummary{"ingest": {Count: 2000, P99: 41.2}},
				Values:    map[string]float64{"server_cpu_cores": 0.43, "server_memory_mb": 181.6}},
			{Name: "drain", Seconds: 3, Counts: map[string]int64{"agent_events_stored": 10}},
		}},
		{Servers: []string{"a", "b"}, Phases: []PhaseReport{
			{Name: "16k", Seconds: 45, Counts: map[string]int64{"agent_events_stored": 540000},
				Latencies: map[string]LatencySummary{"ingest": {Count: 2000, P99: 1530}}},
		}},
	}
	got := sizingTable(reports)
	for _, want := range []string{"| 1 | 1k | 1000 | 41 ms | 0.4 | 182 MB |", "| 2 | 16k | 12000 | 1.5 s | - | - |"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "drain") {
		t.Errorf("drain listed:\n%s", got)
	}
}

func TestBusiestIndices(t *testing.T) {
	before := map[string]int64{"a": 10, "b": 5, "c": 100}
	after := map[string]int64{"a": 40, "b": 25, "c": 100, "d": 20, "e": 1}
	got := busiestIndices(before, after, 3)
	if len(got) != 3 || got["a"] != 30 || got["b"] != 20 || got["d"] != 20 {
		t.Errorf("%v", got)
	}
}
