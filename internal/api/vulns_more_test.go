package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/vulnscan"
)

// failDocs is a document store that fails the operations fail names,
// by operation (get, create, put, update, delete, search) and document id
// (or, for a search, the query as JSON).
type failDocs struct {
	endpoint.Docs
	mu   sync.Mutex
	fail func(op, id string) error
}

func newFlakyDocs() *failDocs { return &failDocs{Docs: endpoint.NewMemoryDocs()} }

func (f *failDocs) failing(fn func(op, id string) error) {
	f.mu.Lock()
	f.fail = fn
	f.mu.Unlock()
}

func (f *failDocs) check(op, id string) error {
	f.mu.Lock()
	fn := f.fail
	f.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(op, id)
}

func (f *failDocs) Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error) {
	if err := f.check("get", id); err != nil {
		return nil, store.Version{}, false, err
	}
	return f.Docs.Get(ctx, index, id)
}

func (f *failDocs) Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error) {
	if err := f.check("create", id); err != nil {
		return store.Version{}, err
	}
	return f.Docs.Create(ctx, index, id, body, refresh)
}

func (f *failDocs) PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error) {
	if err := f.check("put", id); err != nil {
		return store.Version{}, err
	}
	return f.Docs.PutIf(ctx, index, id, body, v, refresh)
}

func (f *failDocs) Update(ctx context.Context, index, id string, fields map[string]any, refresh bool) (store.Version, error) {
	if err := f.check("update", id); err != nil {
		return store.Version{}, err
	}
	return f.Docs.Update(ctx, index, id, fields, refresh)
}

func (f *failDocs) DeleteIf(ctx context.Context, index, id string, v store.Version, refresh bool) error {
	if err := f.check("delete", id); err != nil {
		return err
	}
	return f.Docs.DeleteIf(ctx, index, id, v, refresh)
}

func (f *failDocs) SearchDocs(ctx context.Context, index string, query map[string]any) ([]store.Doc, error) {
	q, _ := json.Marshal(query)
	if err := f.check("search", string(q)); err != nil {
		return nil, err
	}
	return f.Docs.SearchDocs(ctx, index, query)
}

var errDown = errors.New("OpenSearch is down")

// failOn fails one operation on documents whose id (or query) holds part.
func failOn(op, part string) func(string, string) error {
	return func(o, id string) error {
		if o == op && strings.Contains(id, part) {
			return errDown
		}
		return nil
	}
}

type vulnsFixture struct {
	t    *testing.T
	ts   *httptest.Server
	docs *failDocs
	st   *vulnscan.Store
}

func (f *vulnsFixture) call(method, path, body string) (int, map[string]any) {
	f.t.Helper()
	code, out, _ := call(f.t, f.ts, method, path, body, "admin", "s3cret-pass", nil)
	return code, out
}

func newVulnsFixture(t *testing.T, change func(*Server)) *vulnsFixture {
	t.Helper()
	docs := newFlakyDocs()
	st := vulnscan.NewStore(docs, "signalith")
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Vulns = &Vulns{Store: st}
		if change != nil {
			change(s)
		}
	})
	return &vulnsFixture{t: t, ts: ts, docs: docs, st: st}
}

// seed saves two networks, scans of them and hosts they found.
func (f *vulnsFixture) seed() {
	t := f.t
	ctx := context.Background()
	_, v, err := f.st.Settings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	set := vulnscan.Settings{Targets: []vulnscan.Target{
		{ID: "office", Name: "Office", Networks: []string{"10.0.0.0/24"}, Ports: vulnscan.PortsTop100, Enabled: true, Schedule: vulnscan.Schedule{Every: vulnscan.Daily, Hour: 3}},
		{ID: "lab", Name: "Lab", Networks: []string{"10.9.0.0/24"}, Ports: vulnscan.PortsTop100, Schedule: vulnscan.Schedule{Every: vulnscan.Manual}},
	}}
	if _, err := f.st.SaveSettings(ctx, set, v, "admin"); err != nil {
		t.Fatal(err)
	}
	done, err := f.st.NewScan(ctx, set.Targets[0], vulnscan.TriggerManual, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.UpdateScan(ctx, done.ID, map[string]any{"state": vulnscan.StateDone}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.NewScan(ctx, set.Targets[0], vulnscan.TriggerManual, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.NewScan(ctx, vulnscan.Target{ID: "gone", Name: "Gone"}, vulnscan.TriggerManual, "admin"); err != nil {
		t.Fatal(err)
	}
	seen := time.Now().Add(-time.Hour).UTC()
	hosts := []*vulnscan.Host{
		{ID: vulnscan.HostID("office", "10.0.0.5"), TargetID: "office", TargetName: "Office", Address: "10.0.0.5", Hostname: "files",
			Services: []vulnscan.HostService{
				{Service: vulnscan.Service{Port: 22, Transport: "tcp"}},
				{Service: vulnscan.Service{Port: 445, Transport: "tcp"}, Vulns: []vulnscan.Vuln{{CVE: "CVE-2020-0001"}, {CVE: "CVE-2020-0002"}}},
			},
			Counts: vulnscan.Counts{Services: 2, Critical: 1, High: 1, KEV: 1, Likely: 1}, MaxCVSS: 9.8, FirstSeen: seen, LastSeen: seen},
		{ID: vulnscan.HostID("office", "10.0.0.6"), TargetID: "office", TargetName: "Office", Address: "10.0.0.6",
			Services: []vulnscan.HostService{{Service: vulnscan.Service{Port: 80, Transport: "tcp"}}},
			Counts:   vulnscan.Counts{Services: 1, Medium: 2, Low: 3}, MaxCVSS: 5, FirstSeen: seen, LastSeen: seen},
	}
	if err := f.st.SaveHosts(ctx, "office", hosts); err != nil {
		t.Fatal(err)
	}
	other := []*vulnscan.Host{{ID: vulnscan.HostID("gone", "10.5.0.1"), TargetID: "gone", TargetName: "Gone", Address: "10.5.0.1",
		Counts: vulnscan.Counts{Low: 1}, FirstSeen: seen, LastSeen: seen}}
	if err := f.st.SaveHosts(ctx, "gone", other); err != nil {
		t.Fatal(err)
	}
}

func scanID(t *testing.T, st *vulnscan.Store, state string) string {
	t.Helper()
	scans, err := st.Scans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, sc := range scans {
		if sc.State == state && sc.TargetID == "office" {
			return sc.ID
		}
	}
	t.Fatalf("no %s scan in %v", state, scans)
	return ""
}

// The page lists each network with its next run, the scan running now
// and the last one, its hosts and their counts; the hosts with their
// ports and first CVE; and the totals.
func TestVulnsPage(t *testing.T) {
	f := newVulnsFixture(t, nil)
	f.seed()
	code, out := f.call("GET", "/api/vulns", "")
	if code != http.StatusOK {
		t.Fatalf("vulns %d %v", code, out)
	}
	targets := out["targets"].([]any)
	if len(targets) != 2 {
		t.Fatalf("targets %v", targets)
	}
	office, lab := targets[0].(map[string]any), targets[1].(map[string]any)
	if office["hosts"] != float64(2) || office["next_run"] == nil || office["active"] == nil || office["last_scan"] == nil {
		t.Errorf("office %v", office)
	}
	if c := office["counts"].(map[string]any); c["critical"] != float64(1) || c["medium"] != float64(2) || c["low"] != float64(3) || c["kev"] != float64(1) || c["services"] != float64(3) {
		t.Errorf("office counts %v", c)
	}
	if lab["hosts"] != float64(0) || lab["next_run"] != nil || lab["active"] != nil {
		t.Errorf("lab %v", lab)
	}
	tot := out["totals"].(map[string]any)
	if tot["hosts"] != float64(3) || tot["services"] != float64(3) || tot["low"] != float64(4) || tot["likely"] != float64(1) || tot["high"] != float64(1) {
		t.Errorf("totals %v", tot)
	}
	hosts := out["hosts"].([]any)
	first := hosts[0].(map[string]any)
	if first["address"] != "10.0.0.5" || first["top_cve"] != "CVE-2020-0001" || fmt.Sprint(first["ports"]) != "[22 445]" {
		t.Errorf("first host %v", first)
	}
	if len(out["scans"].([]any)) != 3 || out["scans_here"] != true {
		t.Errorf("scans %v here %v", out["scans"], out["scans_here"])
	}
	if out["exploits"] != nil {
		t.Errorf("exploits without a scanner: %v", out["exploits"])
	}

	// One host, and one that a newer scan no longer found.
	id := first["id"].(string)
	if code, out := f.call("GET", "/api/vulns/hosts/"+id, ""); code != http.StatusOK || out["host"].(map[string]any)["hostname"] != "files" {
		t.Errorf("host %d %v", code, out)
	}
	if code, out := f.call("GET", "/api/vulns/hosts/nope", ""); code != http.StatusNotFound || !strings.Contains(out["error"].(string), "no such host") {
		t.Errorf("missing host %d %v", code, out)
	}
	f.docs.failing(failOn("get", "host:"))
	if code, _ := f.call("GET", "/api/vulns/hosts/"+id, ""); code != http.StatusBadGateway {
		t.Errorf("host while OpenSearch is down: %d", code)
	}
}

// The page shows at most the 30 newest scans, and the exploit feeds'
// state when the scanner has them.
func TestVulnsPageRecentScansAndExploits(t *testing.T) {
	docs := newFlakyDocs()
	st := vulnscan.NewStore(docs, "signalith")
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Vulns = &Vulns{Store: st, Scanner: &vulnscan.Scanner{Store: st, Exploits: vulnscan.NewExploitFeeds(st, "", "")}}
	})
	for i := 0; i < 32; i++ {
		if _, err := st.NewScan(context.Background(), vulnscan.Target{ID: "x", Name: "X"}, vulnscan.TriggerManual, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	code, out, _ := call(t, ts, "GET", "/api/vulns", "", "admin", "s3cret-pass", nil)
	if code != http.StatusOK || len(out["scans"].([]any)) != 30 {
		t.Fatalf("vulns %d scans %d", code, len(out["scans"].([]any)))
	}
	if ex, _ := out["exploits"].(map[string]any); ex == nil || ex["likely_epss"] != vulnscan.LikelyEPSS {
		t.Errorf("exploits %v", out["exploits"])
	}
}

// Without the scanner's store the page says so, and every route does.
func TestVulnsMissing(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, rt := range []struct{ method, path string }{
		{"GET", "/api/vulns"}, {"GET", "/api/vulns/hosts/x"}, {"GET", "/api/vulns/setup"}, {"GET", "/api/vulns/scanners"},
		{"POST", "/api/vulns/networks/x/scan"}, {"POST", "/api/vulns/scans/x/stop"},
	} {
		code, out, _ := call(t, ts, rt.method, rt.path, "{}", "admin", "s3cret-pass", nil)
		if code != http.StatusServiceUnavailable || !strings.Contains(fmt.Sprint(out["error"]), "not running on this server") {
			t.Errorf("%s %s: %d %v", rt.method, rt.path, code, out)
		}
	}
}

// Each read the page needs failing is a 502.
func TestVulnsStoreErrors(t *testing.T) {
	f := newVulnsFixture(t, nil)
	f.seed()
	for _, c := range []struct {
		fail         func(string, string) error
		method, path string
	}{
		{failOn("get", "settings"), "GET", "/api/vulns"},
		{failOn("search", `"scan"`), "GET", "/api/vulns"},
		{failOn("search", `"host"`), "GET", "/api/vulns"},
		{failOn("get", "settings"), "GET", "/api/vulns/scanners"},
		{failOn("search", `"scanner"`), "GET", "/api/vulns/scanners"},
		{failOn("get", "settings"), "POST", "/api/vulns/networks/office/scan"},
		{failOn("search", `"scan"`), "POST", "/api/vulns/networks/lab/scan"},
		{failOn("create", "scan:"), "POST", "/api/vulns/networks/lab/scan"},
		{failOn("get", "scan:"), "POST", "/api/vulns/scans/x/stop"},
		{failOn("get", "settings"), "PUT", "/api/vulns/settings"},
	} {
		f.docs.failing(c.fail)
		if code, out := f.call(c.method, c.path, `{"settings":{"targets":[]},"version":""}`); code != http.StatusBadGateway {
			t.Errorf("%s %s with a failing store: %d %v", c.method, c.path, code, out)
		}
		f.docs.failing(nil)
	}
	// The reports failing leave the scanner summary out of the page.
	f.docs.failing(failOn("search", `"scanner"`))
	if code, out := f.call("GET", "/api/vulns", ""); code != http.StatusOK || out["scanner"] != nil {
		t.Errorf("reports failing: %d %v", code, out["scanner"])
	}
}

// Scan now queues a scan of a network, unless one is queued or running,
// and Stop stops one that has not ended.
func TestVulnScanNowAndStop(t *testing.T) {
	f := newVulnsFixture(t, nil)
	f.seed()
	if code, out := f.call("POST", "/api/vulns/networks/nope/scan", "{}"); code != http.StatusNotFound {
		t.Errorf("an unknown network: %d %v", code, out)
	}
	if code, out := f.call("POST", "/api/vulns/networks/office/scan", "{}"); code != http.StatusConflict || !strings.Contains(out["error"].(string), "already being scanned") {
		t.Errorf("a network already queued: %d %v", code, out)
	}
	code, out := f.call("POST", "/api/vulns/networks/lab/scan", "{}")
	sc, _ := out["scan"].(map[string]any)
	if code != http.StatusAccepted || sc["target_id"] != "lab" || sc["state"] != vulnscan.StateQueued || sc["requested_by"] != "admin" {
		t.Fatalf("scan now: %d %v", code, out)
	}

	queued := scanID(t, f.st, vulnscan.StateQueued)
	f.docs.failing(failOn("update", "scan:"))
	if code, _ := f.call("POST", "/api/vulns/scans/"+queued+"/stop", "{}"); code != http.StatusBadGateway {
		t.Errorf("stop while OpenSearch is down: %d", code)
	}
	f.docs.failing(nil)
	if code, out := f.call("POST", "/api/vulns/scans/"+queued+"/stop", "{}"); code != http.StatusOK || out["stopping"] != queued {
		t.Errorf("stop: %d %v", code, out)
	}
	src, _, _, err := f.docs.Docs.Get(context.Background(), f.st.Index, "scan:"+queued)
	if err != nil || !strings.Contains(string(src), `"stop":true`) || !strings.Contains(string(src), `"stop_by":"admin"`) {
		t.Errorf("the stopped scan: %s %v", src, err)
	}
	done := scanID(t, f.st, vulnscan.StateDone)
	if code, out := f.call("POST", "/api/vulns/scans/"+done+"/stop", "{}"); code != http.StatusConflict || !strings.Contains(out["error"].(string), "already ended") {
		t.Errorf("stop an ended scan: %d %v", code, out)
	}
	if code, out := f.call("POST", "/api/vulns/scans/nope/stop", "{}"); code != http.StatusNotFound {
		t.Errorf("stop a missing scan: %d %v", code, out)
	}
}

// A network whose scanner was removed cannot be scanned until it names
// another; one whose scanner is up can.
func TestVulnScannerOffline(t *testing.T) {
	s := &Server{}
	if why := s.scannerOffline(vulnscan.Target{Scanner: "n_a"}); why != "" {
		t.Errorf("no cluster: %q", why)
	}
	s.Cluster = &fakeCluster{}
	if why := s.scannerOffline(vulnscan.Target{}); why != "" {
		t.Errorf("no scanner: %q", why)
	}
	if why := s.scannerOffline(vulnscan.Target{Scanner: "n_a"}); why != "" {
		t.Errorf("a ready scanner: %q", why)
	}
	if why := s.scannerOffline(vulnscan.Target{Scanner: "n_gone"}); !strings.Contains(why, "was removed") {
		t.Errorf("a removed scanner: %q", why)
	}
	s.Cluster = statusCluster{st: cluster.Status{Servers: []cluster.ServerStatus{{NodeID: "n_a", Name: "siem-a", State: cluster.StateOffline}}}}
	if why := s.scannerOffline(vulnscan.Target{Scanner: "n_a"}); why != "siem-a, the server that scans this network, is offline. Start Signalith there, or edit the network and pick another scanner." {
		t.Errorf("an offline scanner: %q", why)
	}
}

// The setup check runs here when this server scans, and is kept for a
// while; on a server that does not, it is the scanning server's latest.
func TestVulnSetup(t *testing.T) {
	var checks int
	var mu sync.Mutex
	f := newVulnsFixture(t, func(s *Server) {
		s.Vulns.Scanner = &vulnscan.Scanner{Server: "siem-a", Leader: func() bool { return true },
			Checker: &vulnscan.Checker{FindNmap: func() string {
				mu.Lock()
				checks++
				mu.Unlock()
				return ""
			}}}
		s.Vulns.Scanner.Store = s.Vulns.Store
	})
	code, out := f.call("GET", "/api/vulns/setup", "")
	if rep, _ := out["report"].(map[string]any); code != http.StatusOK || out["here"] != true || rep["server"] != "siem-a" || rep["ready"] != false {
		t.Fatalf("setup %d %v", code, out)
	}
	mu.Lock()
	n := checks
	mu.Unlock()
	f.call("GET", "/api/vulns/setup", "")
	mu.Lock()
	if checks != n {
		t.Errorf("checked again within %v", setupFresh)
	}
	mu.Unlock()
	f.call("GET", "/api/vulns/setup?fresh=1", "")
	mu.Lock()
	if checks == n {
		t.Error("fresh=1 did not check again")
	}
	mu.Unlock()
}

func TestVulnSetupElsewhere(t *testing.T) {
	f := newVulnsFixture(t, func(s *Server) { s.Cluster = &fakeCluster{holder: "siem-a"} })
	if code, out := f.call("GET", "/api/vulns/setup", ""); code != http.StatusOK || out["here"] != false || out["scanner_server"] != "siem-a" || out["report"] != nil {
		t.Fatalf("no report yet: %d %v", code, out)
	}
	if err := f.st.PutReport(context.Background(), &vulnscan.Report{Server: "siem-a", NodeID: "n_a", At: time.Now(), Ready: true, Checks: []vulnscan.Check{}}); err != nil {
		t.Fatal(err)
	}
	code, out := f.call("GET", "/api/vulns/setup", "")
	if rep, _ := out["report"].(map[string]any); code != http.StatusOK || rep["server"] != "siem-a" || rep["ready"] != true {
		t.Fatalf("siem-a's report: %d %v", code, out)
	}
	f.docs.failing(failOn("search", `"scanner"`))
	if code, _ := f.call("GET", "/api/vulns/setup", ""); code != http.StatusBadGateway {
		t.Errorf("reports failing: %d", code)
	}
}

// Saving the scan settings is refused for a stale version, a bad network
// and a save that loses a race.
func TestSaveVulnSettingsErrors(t *testing.T) {
	f := newVulnsFixture(t, nil)
	_, out := f.call("GET", "/api/vulns", "")
	version := out["version"].(string)
	body := func(v, nets string) string {
		return `{"version":"` + v + `","settings":{"cve_lookup":true,"targets":[{"id":"o","name":"Office","networks":` + nets +
			`,"ports":"top100","enabled":true,"schedule":{"every":"manual"}}]}}`
	}
	if code, _ := f.call("PUT", "/api/vulns/settings", `{`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	if code, out := f.call("PUT", "/api/vulns/settings", body("stale", `["10.0.0.0/24"]`)); code != http.StatusConflict || !strings.Contains(out["error"].(string), "someone else changed") {
		t.Errorf("stale: %d %v", code, out)
	}
	if code, out := f.call("PUT", "/api/vulns/settings", body(version, `[]`)); code != http.StatusBadRequest {
		t.Errorf("no networks: %d %v", code, out)
	}
	f.docs.failing(func(op, id string) error {
		if (op == "put" || op == "create") && strings.Contains(id, "settings") {
			return store.ErrConflict
		}
		return nil
	})
	if code, out := f.call("PUT", "/api/vulns/settings", body(version, `["10.0.0.0/24"]`)); code != http.StatusConflict {
		t.Errorf("a lost race: %d %v", code, out)
	}
	f.docs.failing(func(op, id string) error {
		if (op == "put" || op == "create") && strings.Contains(id, "settings") {
			return errDown
		}
		return nil
	})
	if code, out := f.call("PUT", "/api/vulns/settings", body(version, `["10.0.0.0/24"]`)); code != http.StatusBadGateway {
		t.Errorf("a failing save: %d %v", code, out)
	}
	f.docs.failing(nil)
	if code, out := f.call("PUT", "/api/vulns/settings", body(version, `["10.0.0.0/24"]`)); code != http.StatusOK {
		t.Errorf("save: %d %v", code, out)
	}
}

// jobsReport picks the check of the server that runs the jobs, an old
// one by name, or the only one when there is a single server.
func TestJobsReport(t *testing.T) {
	a := &vulnscan.Report{Server: "siem-a", NodeID: "n_a"}
	old := &vulnscan.Report{Server: "siem-b"}
	servers := []vulnServer{{ID: "n_a", Name: "siem-a"}, {ID: "n_b", Name: "siem-b", RunsJobs: true}}
	if got := jobsReport(servers, []*vulnscan.Report{a, old}); got != old {
		t.Errorf("by name: %v", got)
	}
	servers[0].RunsJobs, servers[1].RunsJobs = true, false
	if got := jobsReport(servers, []*vulnscan.Report{old, a}); got != a {
		t.Errorf("by node: %v", got)
	}
	servers[0].RunsJobs = false
	if got := jobsReport(servers, []*vulnscan.Report{a}); got != nil {
		t.Errorf("nobody runs the jobs: %v", got)
	}
	if got := jobsReport(servers[:1], []*vulnscan.Report{a}); got != a {
		t.Errorf("one server: %v", got)
	}
}

// The scanners list names a server a network still names once it is
// removed, with its last check when there is one.
func TestVulnServersRemoved(t *testing.T) {
	s := &Server{Cluster: &fakeCluster{holder: "siem-a"}}
	set := vulnscan.Settings{Targets: []vulnscan.Target{{ID: "t1", Name: "One", Scanner: "n_old"}, {ID: "t2", Name: "Two", Scanner: "n_older"}, {ID: "t3", Name: "Three"}}}
	reports := []*vulnscan.Report{{Server: "siem-old", NodeID: "n_old", Ready: true}}
	list := s.vulnServers(set, reports, true)
	if len(list) != 4 {
		t.Fatalf("servers %+v", list)
	}
	old, older := list[2], list[3]
	if old.Name != "siem-old" || old.State != stateRemoved || old.Report == nil || len(old.Networks) != 1 || old.Networks[0].ID != "t1" {
		t.Errorf("removed with a report %+v", old)
	}
	if older.Name != "A removed server" || older.Ready != nil {
		t.Errorf("removed without one %+v", older)
	}
	// On its own, this server is named by its report.
	s.Cluster = nil
	list = s.vulnServers(vulnscan.Settings{}, []*vulnscan.Report{{Server: "siem-x", Ready: true}}, false)
	if len(list) != 1 || list[0].Name != "siem-x" || list[0].Ready == nil || !*list[0].Ready || list[0].Report != nil {
		t.Errorf("alone %+v", list)
	}
}
