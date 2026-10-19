package vulnscan

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// errDocs is a MemoryDocs whose calls fail when a test sets their error.
type errDocs struct {
	*endpoint.MemoryDocs
	mu                                        sync.Mutex
	do, get, create, put, update, del, search error
	doCalls                                   []string
}

func newErrDocs() *errDocs { return &errDocs{MemoryDocs: endpoint.NewMemoryDocs()} }

func (d *errDocs) fail(e *error, v error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	*e = v
}

func (d *errDocs) err(e *error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return *e
}

func (d *errDocs) Do(_ context.Context, method, path string, _, _ any) error {
	d.mu.Lock()
	d.doCalls = append(d.doCalls, method+" "+path)
	d.mu.Unlock()
	return d.err(&d.do)
}

func (d *errDocs) Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error) {
	if err := d.err(&d.get); err != nil {
		return nil, store.Version{}, false, err
	}
	return d.MemoryDocs.Get(ctx, index, id)
}

func (d *errDocs) Create(ctx context.Context, index, id string, body any, r bool) (store.Version, error) {
	if err := d.err(&d.create); err != nil {
		return store.Version{}, err
	}
	return d.MemoryDocs.Create(ctx, index, id, body, r)
}

func (d *errDocs) PutIf(ctx context.Context, index, id string, body any, v store.Version, r bool) (store.Version, error) {
	if err := d.err(&d.put); err != nil {
		return store.Version{}, err
	}
	return d.MemoryDocs.PutIf(ctx, index, id, body, v, r)
}

func (d *errDocs) Update(ctx context.Context, index, id string, f map[string]any, r bool) (store.Version, error) {
	if err := d.err(&d.update); err != nil {
		return store.Version{}, err
	}
	return d.MemoryDocs.Update(ctx, index, id, f, r)
}

func (d *errDocs) DeleteIf(ctx context.Context, index, id string, v store.Version, r bool) error {
	if err := d.err(&d.del); err != nil {
		return err
	}
	return d.MemoryDocs.DeleteIf(ctx, index, id, v, r)
}

func (d *errDocs) SearchDocs(ctx context.Context, index string, q map[string]any) ([]store.Doc, error) {
	if err := d.err(&d.search); err != nil {
		return nil, err
	}
	return d.MemoryDocs.SearchDocs(ctx, index, q)
}

func TestStoreIndexAndFailures(t *testing.T) {
	ctx := context.Background()
	d := newErrDocs()
	st := NewStore(d, "sig")
	st.Now = func() time.Time { return time.Now().Add(-time.Hour) }
	if err := st.EnsureIndex(ctx); err != nil || d.doCalls[0] != "PUT /sig_vulns" {
		t.Fatalf("ensure = %v %v", err, d.doCalls)
	}
	d.fail(&d.do, &store.Error{Status: 400, Body: "resource_already_exists_exception"})
	if err := st.EnsureIndex(ctx); err != nil {
		t.Errorf("existing = %v", err)
	}
	d.fail(&d.do, &store.Error{Status: 500, Body: "x"})
	if err := st.EnsureIndex(ctx); err == nil {
		t.Error("error not returned")
	}

	boom := errors.New("opensearch down")
	tg := target("192.0.2.1")
	set, err := st.SaveSettings(ctx, Settings{Targets: []Target{tg}}, store.Version{}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !set.UpdatedAt.Before(time.Now().Add(-30 * time.Minute)) {
		t.Errorf("the store's clock was not used: %v", set.UpdatedAt)
	}
	sc, err := st.NewScan(ctx, set.Targets[0], TriggerManual, "alice")
	if err != nil {
		t.Fatal(err)
	}
	got, v, err := st.Scan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	got.Error = "x"
	if _, err := st.PutScan(ctx, got, v); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutScan(ctx, got, v); !errors.Is(err, store.ErrConflict) {
		t.Errorf("stale PutScan = %v", err)
	}
	if _, _, err := st.Scan(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing scan = %v", err)
	}
	if _, err := st.Host(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing host = %v", err)
	}
	if err := st.UpdateScan(ctx, "nope", map[string]any{"x": 1}); !errors.Is(err, ErrNotFound) {
		t.Errorf("update missing = %v", err)
	}
	// Broken documents are errors.
	_, _ = d.MemoryDocs.Create(ctx, st.Index, scanDocID("bad"), json.RawMessage(`{"kind":"scan","id":5}`), true)
	_, _ = d.MemoryDocs.Create(ctx, st.Index, hostDocID("bad"), json.RawMessage(`{"kind":"host","id":5}`), true)
	if _, _, err := st.Scan(ctx, "bad"); err == nil {
		t.Error("bad scan read")
	}
	_, _ = d.MemoryDocs.Create(ctx, st.Index, scanDocID("list"), json.RawMessage(`[1]`), true)
	if ok, err := st.ClaimScan(ctx, "list", nil); ok || err == nil {
		t.Errorf("claim bad = %v %v", ok, err)
	}
	if ok, err := st.RequeueScan(ctx, "list", "n"); ok || err == nil {
		t.Errorf("requeue bad = %v %v", ok, err)
	}
	if _, err := st.Host(ctx, "bad"); err == nil {
		t.Error("bad host read")
	}

	// A conflict on claiming or requeueing is "not mine", not an error.
	d.fail(&d.put, store.ErrConflict)
	if ok, err := st.ClaimScan(ctx, sc.ID, map[string]any{"scanner": "a"}); ok || err != nil {
		t.Errorf("claim conflict = %v %v", ok, err)
	}
	d.fail(&d.put, boom)
	if ok, err := st.ClaimScan(ctx, sc.ID, nil); ok || !errors.Is(err, boom) {
		t.Errorf("claim error = %v %v", ok, err)
	}
	d.fail(&d.put, nil)
	if ok, err := st.ClaimScan(ctx, sc.ID, map[string]any{"scanner_id": "n1"}); !ok || err != nil {
		t.Fatalf("claim = %v %v", ok, err)
	}
	d.fail(&d.put, store.ErrConflict)
	if ok, err := st.RequeueScan(ctx, sc.ID, "n1"); ok || err != nil {
		t.Errorf("requeue conflict = %v %v", ok, err)
	}
	d.fail(&d.put, boom)
	if ok, err := st.RequeueScan(ctx, sc.ID, "n1"); ok || !errors.Is(err, boom) {
		t.Errorf("requeue error = %v %v", ok, err)
	}
	d.fail(&d.put, nil)

	// Settings, scans and CVE caching when the store fails.
	d.fail(&d.get, boom)
	for name, err := range map[string]error{
		"settings": func() error { _, _, err := st.Settings(ctx); return err }(),
		"save":     func() error { _, err := st.SaveSettings(ctx, set, store.Version{}, "bob"); return err }(),
		"scan":     func() error { _, _, err := st.Scan(ctx, sc.ID); return err }(),
		"host":     func() error { _, err := st.Host(ctx, "h"); return err }(),
		"putcves":  st.PutCVEs(ctx, "a:x:y", nil),
		"report":   st.PutReport(ctx, &Report{Server: "s"}),
	} {
		if !errors.Is(err, boom) {
			t.Errorf("%s = %v", name, err)
		}
	}
	if ok, err := st.ClaimScan(ctx, sc.ID, nil); ok || !errors.Is(err, boom) {
		t.Errorf("claim get = %v %v", ok, err)
	}
	d.fail(&d.get, nil)
	d.fail(&d.create, boom)
	if _, err := st.NewScan(ctx, set.Targets[0], TriggerManual, "alice"); !errors.Is(err, boom) {
		t.Errorf("new scan = %v", err)
	}
	if err := st.PutCVEs(ctx, "a:x:z", nil); !errors.Is(err, boom) {
		t.Errorf("put cves create = %v", err)
	}
	d.fail(&d.create, store.ErrExists)
	if err := st.PutCVEs(ctx, "a:x:z", nil); err != nil {
		t.Errorf("put cves raced = %v", err)
	}
	d.fail(&d.create, nil)
	if err := st.PutCVEs(ctx, "a:x:z", []CVE{{ID: "CVE-1"}}); err != nil {
		t.Fatal(err)
	}
	d.fail(&d.put, store.ErrConflict)
	if err := st.PutCVEs(ctx, "a:x:z", nil); err != nil {
		t.Errorf("put cves conflict = %v", err)
	}
	d.fail(&d.put, nil)
	if err := st.PutCVEs(ctx, "a:x:z", []CVE{{ID: "CVE-2"}}); err != nil {
		t.Fatal(err)
	}
	if cves, _, ok, _ := st.CachedCVEs(ctx, "a:x:z"); !ok || len(cves) != 1 || cves[0].ID != "CVE-2" {
		t.Errorf("cached = %v %v", cves, ok)
	}

	d.fail(&d.search, boom)
	if _, err := st.Scans(ctx); !errors.Is(err, boom) {
		t.Errorf("scans = %v", err)
	}
	if err := st.PruneScans(ctx, nil); !errors.Is(err, boom) {
		t.Errorf("prune = %v", err)
	}
	if err := st.SaveHosts(ctx, "t", nil); !errors.Is(err, boom) {
		t.Errorf("save hosts = %v", err)
	}
	if err := st.DropHosts(ctx, nil); !errors.Is(err, boom) {
		t.Errorf("drop hosts = %v", err)
	}
	if _, err := st.Reprioritize(ctx, nil); !errors.Is(err, boom) {
		t.Errorf("reprioritize = %v", err)
	}
	if _, err := st.Hosts(ctx); !errors.Is(err, boom) {
		t.Errorf("hosts = %v", err)
	}
	if _, err := st.Reports(ctx); !errors.Is(err, boom) {
		t.Errorf("reports = %v", err)
	}
	d.fail(&d.search, nil)

	// Deleting and writing hosts fail.
	h := &Host{ID: HostID(tg.ID, "192.0.2.1"), TargetID: tg.ID, Address: "192.0.2.1"}
	if err := st.SaveHosts(ctx, tg.ID, []*Host{h}); err != nil {
		t.Fatal(err)
	}
	d.fail(&d.put, boom)
	if err := st.SaveHosts(ctx, tg.ID, []*Host{h}); !errors.Is(err, boom) {
		t.Errorf("save hosts put = %v", err)
	}
	d.fail(&d.put, nil)
	d.fail(&d.create, boom)
	if err := st.SaveHosts(ctx, tg.ID, []*Host{{ID: "new", TargetID: tg.ID}}); !errors.Is(err, boom) {
		t.Errorf("save hosts create = %v", err)
	}
	d.fail(&d.create, nil)
	old, err := st.NewScan(ctx, set.Targets[0], TriggerManual, "alice")
	if err != nil {
		t.Fatal(err)
	}
	old, ov, err := st.Scan(ctx, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	old.State = StateDone
	if _, err := st.PutScan(ctx, old, ov); err != nil {
		t.Fatal(err)
	}
	d.fail(&d.del, boom)
	if err := st.SaveHosts(ctx, tg.ID, nil); !errors.Is(err, boom) {
		t.Errorf("save hosts delete = %v", err)
	}
	if err := st.DropHosts(ctx, map[string]bool{}); !errors.Is(err, boom) {
		t.Errorf("drop hosts delete = %v", err)
	}
	if err := st.PruneScans(ctx, map[string]bool{}); !errors.Is(err, boom) {
		t.Errorf("prune delete = %v", err)
	}
	d.fail(&d.del, store.ErrNotFound)
	if err := st.DropHosts(ctx, map[string]bool{}); err != nil {
		t.Errorf("drop hosts gone = %v", err)
	}
	d.fail(&d.del, nil)
}

func TestNVDClient(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	status, body, gotKey := 200, `{"totalResults":0,"vulnerabilities":[]}`, ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotKey = r.Header.Get("apiKey")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	defer srv.Close()
	n := NewNVD(srv.URL, "  test-key  ")
	n.Gap = time.Millisecond
	if !n.HasKey() {
		t.Error("no key")
	}
	set := func(s int, b string) {
		mu.Lock()
		defer mu.Unlock()
		status, body = s, b
	}
	if err := n.Ping(ctx); err != nil || gotKey != "test-key" {
		t.Errorf("ping = %v, key %q", err, gotKey)
	}
	for _, tc := range []struct {
		status int
		body   string
		want   string
	}{
		{403, "", "refused the NVD API key"},
		{429, "", "slow down"},
		{500, "", "answered 500"},
		{200, "{", "could not read"},
	} {
		set(tc.status, tc.body)
		if err := n.Ping(ctx); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%d: %v", tc.status, err)
		}
	}
	set(404, "")
	if cves, err := n.Product(ctx, "a", "nobody", "nothing"); err != nil || len(cves) != 0 {
		t.Errorf("unknown product = %v %v", cves, err)
	}
	n.Set("", "")
	if n.HasKey() || n.URL != DefaultNVDURL {
		t.Errorf("reset = %+v", n)
	}
	set(403, "")
	n.Set(srv.URL, "")
	if err := n.Ping(ctx); err == nil || !strings.Contains(err.Error(), "slow down") {
		t.Errorf("403 without key = %v", err)
	}
	if u, _ := (&NVD{}).endpoint(); u != DefaultNVDURL {
		t.Errorf("empty endpoint = %q", u)
	}
	if (&NVD{APIKey: "k"}).gap() != 700*time.Millisecond || (&NVD{}).gap() != 6500*time.Millisecond {
		t.Error("gaps")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	slow := &NVD{URL: srv.URL}
	slow.last = time.Now()
	if err := slow.Ping(cctx); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled wait = %v", err)
	}

	for score, want := range map[float64]string{9.8: "critical", 7: "high", 5.5: "medium", 0.1: "low", 0: "none"} {
		if got := SeverityFor(score); got != want {
			t.Errorf("SeverityFor(%v) = %q", score, got)
		}
	}
	if got := truncate("  ééé  ", 3); got != "é…" {
		t.Errorf("truncate = %q", got)
	}
	if got := truncate("ab", 3); got != "ab" {
		t.Errorf("truncate short = %q", got)
	}
	if escapeCPE("a.b_c") != `a\.b_c` {
		t.Errorf("escape = %q", escapeCPE("a.b_c"))
	}
	c := CPE{Part: "a", Vendor: "v", Product: "p"}
	if c.String() != "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*" || (CPE{Version: "*"}).FullVersion() != "" || (CPE{Version: "8.2", Update: "p1"}).FullVersion() != "8.2p1" {
		t.Errorf("cpe = %q", c.String())
	}
}

func TestLocalRoute(t *testing.T) {
	ctx := context.Background()
	if r := LocalRoute(ctx, "127.0.0.1"); !r.Direct || r.Iface != "loopback" {
		t.Errorf("loopback = %+v", r)
	}
	if r := LocalRoute(ctx, "localhost"); r.Err == "" && !r.Direct {
		t.Errorf("localhost = %+v", r)
	}
	// An address on one of this server's own networks is direct.
	var own netip.Addr
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifs {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					own, _ = netip.AddrFromSlice(ipn.IP.To4())
				}
			}
		}
	}
	if own.IsValid() {
		if r := LocalRoute(ctx, own.String()); !r.Direct || r.Iface == "" {
			t.Errorf("own address %s = %+v", own, r)
		}
	}
	// Documentation addresses are on no network here: routed or not
	// reached, never direct.
	if r := LocalRoute(ctx, "198.51.100.77"); r.Direct {
		t.Errorf("TEST-NET-2 = %+v", r)
	}
}

func TestReachCheck(t *testing.T) {
	ctx := context.Background()
	routes := map[string]Route{
		"192.0.2.0/24":    {Direct: true, Iface: "eth0"},
		"198.51.100.1":    {From: netip.MustParseAddr("10.0.0.5")},
		"198.51.100.2":    {},
		"gone.example":    {Err: "the name was not found"},
		"203.0.113.10-20": {From: netip.MustParseAddr("10.0.0.5")},
	}
	c := &Checker{Reach: func(_ context.Context, e string) Route { r := routes[e]; r.Entry = e; return r }}
	tg := target("192.0.2.0/24", "198.51.100.1", "198.51.100.2", "gone.example", "203.0.113.10-20")
	ck := c.reachCheck(ctx, tg)
	for _, want := range []string{"On this server's own network: 192.0.2.0/24 (eth0).", "Through a router, from 10.0.0.5: 198.51.100.1, 203.0.113.10-20.",
		"Through a router, from this server: 198.51.100.2.", "Not reached: gone.example (the name was not found)."} {
		if !strings.Contains(ck.Detail, want) {
			t.Errorf("detail lacks %q: %s", want, ck.Detail)
		}
	}
	if ck.State != CheckWarn || len(ck.Fix) != 3 {
		t.Errorf("check = %+v", ck)
	}
	nets := make([]string, maxReachEntries+3)
	for i := range nets {
		nets[i] = "192.0.2.0/24"
	}
	ck = c.reachCheck(ctx, Target{ID: "x", Name: "Big", Networks: nets})
	if ck.State != CheckOK || !strings.Contains(ck.Detail, "3 more not checked.") || len(ck.Fix) != 0 {
		t.Errorf("many = %+v", ck)
	}
	ck = c.reachCheck(ctx, Target{ID: "y", Name: "Routed", Networks: []string{"198.51.100.1"}})
	if ck.State != CheckInfo || len(ck.Fix) != 2 {
		t.Errorf("routed = %+v", ck)
	}
}
