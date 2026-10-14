package vulnscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func target(nets ...string) Target {
	return Target{ID: "office", Name: "Office LAN", Networks: nets, Enabled: true}
}

func TestValidateTarget(t *testing.T) {
	good := target("192.0.2.0/24", "198.51.100.10-50\n203.0.113.7, files.corp.example", "2001:db8::/120", "192.0.2.0/24")
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if want := []string{"192.0.2.0/24", "198.51.100.10-50", "203.0.113.7", "files.corp.example", "2001:db8::/120"}; !slices.Equal(good.Networks, want) {
		t.Errorf("networks = %q", good.Networks)
	}
	if good.Ports != PortsTop1000 || good.Schedule.Every != Daily {
		t.Errorf("defaults: ports %q, every %q", good.Ports, good.Schedule.Every)
	}
	for _, bad := range []string{
		"-sS", "--script=evil", "10.0.0.0/8", "0.0.0.0", "224.0.0.1", "10.0.0.300", "192.0.2.50-10", "a/b", "host_name!", "::/64", "fe80::1%eth0",
	} {
		tg := target(bad)
		if err := tg.Validate(); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	tg := target("10.0.0.0/16", "10.1.0.1")
	if err := tg.Validate(); err == nil || !strings.Contains(err.Error(), "at most 65536") {
		t.Errorf("a /16 and one more: %v", err)
	}
	for ports, ok := range map[string]bool{"top100": true, "all": true, "22, 80,443,8000-8100": true, "0": false, "70000": false, "22-1": false, "22;rm": false, "-p-": false} {
		tg := target("192.0.2.1")
		tg.Ports = ports
		if err := tg.Validate(); (err == nil) != ok {
			t.Errorf("ports %q: %v", ports, err)
		}
	}
	tg = target("192.0.2.1")
	tg.Exclude = []string{"-oN /tmp/x"}
	if err := tg.Validate(); err == nil {
		t.Error("an option in Exclude was accepted")
	}
	set := Settings{Targets: []Target{target("192.0.2.1"), target("192.0.2.2")}}
	if err := set.Validate(); err == nil {
		t.Error("two networks with one ID")
	}
}

func TestArgs(t *testing.T) {
	tg := target("192.0.2.0/24")
	tg.Exclude = []string{"192.0.2.1", "192.0.2.2"}
	tg.Ports = "22,80"
	a := Args(tg)
	if a[len(a)-1] != "192.0.2.0/24" || !slices.Contains(a, "--unprivileged") || !slices.Contains(a, "-sT") || !slices.Contains(a, "-sV") {
		t.Errorf("args = %q", a)
	}
	if i := slices.Index(a, "-p"); i < 0 || a[i+1] != "22,80" {
		t.Errorf("ports: %q", a)
	}
	if i := slices.Index(a, "--exclude"); i < 0 || a[i+1] != "192.0.2.1,192.0.2.2" {
		t.Errorf("exclude: %q", a)
	}
	if slices.Contains(a, "-T2") {
		t.Error("gentle flags on a normal scan")
	}
	tg.Gentle = true
	tg.Ports = PortsTop100
	a = Args(tg)
	if !slices.Contains(a, "-T2") || !slices.Contains(a, "--version-light") || slices.Contains(a, "-T4") {
		t.Errorf("gentle args = %q", a)
	}
	if i := slices.Index(a, "--top-ports"); i < 0 || a[i+1] != "100" {
		t.Errorf("top ports: %q", a)
	}
}

const nmapXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -oX - 192.0.2.0/24" start="1760400000" version="7.94" xmloutputversion="1.05">
<taskprogress task="Connect Scan" time="1760400010" percent="12.50" remaining="70" etc="1760400080"/>
<host starttime="1760400001" endtime="1760400050"><status state="up" reason="syn-ack"/>
<address addr="192.0.2.10" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="Dell"/>
<hostnames><hostname name="web-01.corp.example" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:8.2p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="http" product="Apache httpd" version="2.4.49" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/a:apache:http_server:2.4.49</cpe></service></port>
<port protocol="tcp" portid="8080"><state state="filtered" reason="no-response"/><service name="http-proxy" method="table" conf="3"/></port>
</ports></host>
<host><status state="down" reason="no-response"/><address addr="192.0.2.11" addrtype="ipv4"/></host>
<host><status state="up" reason="conn-refused"/><address addr="192.0.2.12" addrtype="ipv4"/><hostnames/><ports/></host>
<runstats><finished time="1760400100" timestr="Mon Oct 13 00:01:40 2026" elapsed="100" exit="success"/><hosts up="2" down="254" total="256"/></runstats>
</nmaprun>
`

func TestParseNmap(t *testing.T) {
	var progress []Progress
	hosts, err := parseNmap(strings.NewReader(nmapXML), func(p Progress) { progress = append(progress, p) })
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("hosts = %+v", hosts)
	}
	h := hosts[0]
	if h.Address != "192.0.2.10" || h.Hostname != "web-01.corp.example" || h.MAC != "00:11:22:33:44:55" || h.Vendor != "Dell" {
		t.Errorf("host = %+v", h)
	}
	if len(h.Services) != 2 || h.Services[0].Port != 22 || h.Services[0].Product != "OpenSSH" || h.Services[1].Tunnel != "ssl" ||
		!slices.Equal(h.Services[0].CPEs, []string{"cpe:/a:openbsd:openssh:8.2p1", "cpe:/o:linux:linux_kernel"}) {
		t.Errorf("services = %+v", h.Services)
	}
	if len(hosts[1].Services) != 0 || hosts[1].Services == nil {
		t.Errorf("a host with no open ports: %+v", hosts[1])
	}
	if len(progress) == 0 || progress[0].Percent != 12.5 || progress[0].Task != "Connect Scan" || progress[0].ETA.Unix() != 1760400080 {
		t.Errorf("progress = %+v", progress)
	}
	if _, err := parseNmap(strings.NewReader(strings.Split(nmapXML, "<runstats>")[0]), nil); err == nil {
		t.Error("results cut short were accepted")
	}
}

func TestParseCPE(t *testing.T) {
	c, ok := ParseCPE("cpe:/a:openbsd:openssh:8.2p1")
	if !ok || c.Key() != "a:openbsd:openssh" || c.FullVersion() != "8.2p1" {
		t.Errorf("2.2: %+v", c)
	}
	c, ok = ParseCPE(`cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*`)
	if !ok || c.FullVersion() != "8.2p1" || c.String() != "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*" {
		t.Errorf("2.3: %+v %s", c, c.String())
	}
	c, ok = ParseCPE(`cpe:2.3:a:some\:vendor:prod:1.0:*:*:*:*:*:*:*`)
	if !ok || c.Vendor != "some:vendor" || c.Version != "1.0" {
		t.Errorf("escaped: %+v", c)
	}
	for _, bad := range []string{"", "cpe:/", "cpe:/x:a:b:1", "nope"} {
		if _, ok := ParseCPE(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"7.4", "7.4", 0}, {"7.4", "7.10", -1}, {"2.4.49", "2.4.50", -1}, {"8.2p1", "8.2", 1}, {"8.2", "8.2p1", -1},
		{"8.2p1", "8.3", -1}, {"1.0", "1.0rc1", 1}, {"1.0rc1", "1.0", -1}, {"1.1.1k", "1.1.1l", -1}, {"7.04", "7.4", 0},
		{"10.0", "9.9", 1}, {"7.94SVN", "7.80", 1},
	} {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCriterion(t *testing.T) {
	r := Criterion{Version: "*", StartIncl: "2.4.49", EndExcl: "2.4.51"}
	for v, want := range map[string]bool{"2.4.48": false, "2.4.49": true, "2.4.50": true, "2.4.51": false, "": false} {
		if r.Matches(v) != want {
			t.Errorf("range, %q: %v", v, !want)
		}
	}
	exact := Criterion{Version: "8.2", Update: "p1"}
	if !exact.Matches("8.2p1") || exact.Matches("8.2p2") || exact.Matches("8.2") {
		t.Error("exact with update")
	}
	anyUpdate := Criterion{Version: "8.2", Update: "*"}
	if !anyUpdate.Matches("8.2p1") || !anyUpdate.Matches("8.2") || anyUpdate.Matches("8.21") || anyUpdate.Matches("8.2.1") {
		t.Error("any update")
	}
	if (Criterion{Version: "*"}).Matches("1.0") != true {
		t.Error("every version")
	}
	if (Criterion{Version: "-"}).Matches("1.0") {
		t.Error("no version")
	}
}

// nvdJSON is an answer from the CVE API for Apache httpd.
const nvdJSON = `{"resultsPerPage":3,"startIndex":0,"totalResults":3,"format":"NVD_CVE","version":"2.0","vulnerabilities":[
{"cve":{"id":"CVE-2021-41773","published":"2021-10-05T09:15:07.593","vulnStatus":"Analyzed","cisaExploitAdd":"2021-11-03",
 "descriptions":[{"lang":"en","value":"A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack."}],
 "metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","baseScore":7.5,"baseSeverity":"HIGH"}}],
            "cvssMetricV2":[{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"2.0","baseScore":4.3},"baseSeverity":"MEDIUM"}]},
 "configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
   {"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
   {"vulnerable":true,"criteria":"cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*"}]}]}]}},
{"cve":{"id":"CVE-2021-42013","published":"2021-10-07T16:15:09.270","vulnStatus":"Analyzed","cisaExploitAdd":"2021-11-03",
 "descriptions":[{"lang":"es","value":"x"},{"lang":"en","value":"It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient."}],
 "metrics":{"cvssMetricV31":[{"source":"other","type":"Secondary","cvssData":{"version":"3.1","baseScore":9.0,"baseSeverity":"CRITICAL"}},
                             {"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL"}}]},
 "configurations":[{"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
   {"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*","versionStartIncluding":"2.4.49","versionEndIncluding":"2.4.50"}]}]}]}},
{"cve":{"id":"CVE-2099-0001","published":"2099-01-01T00:00:00.000","vulnStatus":"Rejected","descriptions":[{"lang":"en","value":"** REJECT **"}],"metrics":{},
 "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"}]}]}]}}
]}`

func fakeNVD(t *testing.T, calls *int, mu *sync.Mutex) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*calls++
		mu.Unlock()
		q := r.URL.Query()
		switch {
		case q.Get("cveId") != "":
			io.WriteString(w, `{"totalResults":1,"vulnerabilities":[]}`)
		case q.Get("virtualMatchString") == "cpe:2.3:a:apache:http_server":
			if q.Get("startIndex") != "0" || !strings.Contains(r.URL.RawQuery, "noRejected") {
				t.Errorf("query %s", r.URL.RawQuery)
			}
			io.WriteString(w, nvdJSON)
		default:
			io.WriteString(w, `{"totalResults":0,"vulnerabilities":[]}`)
		}
	}))
}

func TestNVDProduct(t *testing.T) {
	var calls int
	var mu sync.Mutex
	srv := fakeNVD(t, &calls, &mu)
	defer srv.Close()
	n := &NVD{URL: srv.URL, Gap: time.Millisecond}
	cves, err := n.Product(context.Background(), "a", "apache", "http_server")
	if err != nil {
		t.Fatal(err)
	}
	if len(cves) != 2 {
		t.Fatalf("cves = %+v", cves)
	}
	a, b := cves[0], cves[1]
	if a.ID != "CVE-2021-41773" || a.CVSS != 7.5 || a.Severity != "high" || a.KEVAdded != "2021-11-03" || a.Published != "2021-10-05" ||
		len(a.Criteria) != 1 || !a.Applies("2.4.49") || a.Applies("2.4.50") {
		t.Errorf("first = %+v", a)
	}
	if b.CVSS != 9.8 || b.Severity != "critical" || !strings.HasPrefix(b.Description, "It was found") || !b.Applies("2.4.50") || b.Applies("2.4.51") {
		t.Errorf("second = %+v", b)
	}
	if err := n.Ping(context.Background()); err != nil {
		t.Error(err)
	}
	down := &NVD{URL: "http://127.0.0.1:1", Gap: time.Millisecond}
	if err := down.Ping(context.Background()); !errors.Is(err, ErrNVDUnreachable) {
		t.Errorf("unreachable: %v", err)
	}
}

func TestSchedule(t *testing.T) {
	loc := time.UTC
	now := time.Date(2026, 10, 14, 1, 30, 0, 0, loc) // a Wednesday
	d := Schedule{Every: Daily, Hour: 2}
	if got := d.LastSlot(now, loc); !got.Equal(time.Date(2026, 10, 13, 2, 0, 0, 0, loc)) {
		t.Errorf("daily last = %v", got)
	}
	if got := d.NextSlot(now, loc); !got.Equal(time.Date(2026, 10, 14, 2, 0, 0, 0, loc)) {
		t.Errorf("daily next = %v", got)
	}
	w := Schedule{Every: Weekly, Hour: 1, Weekday: 0}
	if got := w.LastSlot(now, loc); !got.Equal(time.Date(2026, 10, 11, 1, 0, 0, 0, loc)) {
		t.Errorf("weekly last = %v", got)
	}
	if got := w.NextSlot(now, loc); !got.Equal(time.Date(2026, 10, 18, 1, 0, 0, 0, loc)) {
		t.Errorf("weekly next = %v", got)
	}
	w.Weekday = 3
	if got := w.LastSlot(now, loc); !got.Equal(time.Date(2026, 10, 14, 1, 0, 0, 0, loc)) {
		t.Errorf("weekly today = %v", got)
	}
	if !(Schedule{Every: Manual}).LastSlot(now, loc).IsZero() {
		t.Error("manual has a slot")
	}
}

type events struct {
	mu  sync.Mutex
	evs []ingest.Event
}

func (e *events) IngestEvents(ctx context.Context, evs []ingest.Event) (*ingest.Result, error) {
	if ingest.OriginFrom(ctx).Intake != ingest.IntakeScanner {
		return nil, errors.New("no scanner origin")
	}
	e.mu.Lock()
	e.evs = append(e.evs, evs...)
	e.mu.Unlock()
	return &ingest.Result{}, nil
}

// fakeNmap returns a Runner that prints out, and records its arguments.
func fakeNmap(out string, args *[]string) *Runner {
	return &Runner{Path: "/usr/bin/nmap", Exec: func(ctx context.Context, path string, a []string) (io.ReadCloser, func() ([]byte, error), error) {
		*args = a
		return io.NopCloser(strings.NewReader(out)), func() ([]byte, error) { return nil, nil }, nil
	}}
}

func newScanner(t *testing.T, nvdURL string, out string, args *[]string) (*Scanner, *events) {
	ev := &events{}
	st := NewStore(endpoint.NewMemoryDocs(), "signalith")
	return &Scanner{Store: st, NVD: &NVD{URL: nvdURL, Gap: time.Millisecond}, Events: ev, Server: "siem-a", Runner: fakeNmap(out, args),
		Checker: &Checker{FindNmap: func() string { return "/usr/bin/nmap" }}}, ev
}

func TestScanNow(t *testing.T) {
	var calls int
	var mu sync.Mutex
	srv := fakeNVD(t, &calls, &mu)
	defer srv.Close()
	var args []string
	s, ev := newScanner(t, srv.URL, nmapXML, &args)
	ctx := context.Background()
	tg := target("192.0.2.0/24")
	tg.Schedule = Schedule{Every: Manual}
	set, err := s.Store.SaveSettings(ctx, Settings{Targets: []Target{tg}, CVELookup: true}, store.Version{}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if set.Targets[0].CreatedBy != "alice" || set.Targets[0].CreatedAt.IsZero() {
		t.Errorf("creator not kept: %+v", set.Targets[0])
	}
	sc, err := s.Store.NewScan(ctx, set.Targets[0], TriggerManual, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if args[len(args)-1] != "192.0.2.0/24" {
		t.Errorf("args = %q", args)
	}
	got, _, err := s.Store.Scan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateDone || got.Scanner != "siem-a" || got.Counts.Hosts != 2 || got.Counts.Services != 2 ||
		got.Counts.Critical != 1 || got.Counts.High != 1 || got.Counts.KEV != 2 || got.CVEError != "" {
		t.Errorf("scan = %+v", got)
	}
	hosts, err := s.Store.Hosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 || hosts[0].Address != "192.0.2.10" || hosts[0].MaxCVSS != 9.8 || hosts[0].Counts.KEV != 2 {
		t.Fatalf("hosts = %+v", hosts)
	}
	web := hosts[0].Services[1]
	// Both 2021 path traversal CVEs apply to 2.4.49; the worse one first.
	if len(web.Vulns) != 2 || web.Vulns[0].CVE != "CVE-2021-42013" || web.Vulns[1].CVE != "CVE-2021-41773" || !web.Vulns[1].KEV ||
		web.Vulns[1].CPE != "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" {
		t.Errorf("web vulns = %+v", web.Vulns)
	}
	// 2 open ports and 2 CVEs.
	if len(ev.evs) != 4 {
		t.Fatalf("events = %d", len(ev.evs))
	}
	var cve map[string]any
	for _, e := range ev.evs {
		if e.Model != Model {
			t.Errorf("model %s", e.Model)
		}
		if e.Fields["cve"] == "CVE-2021-41773" {
			cve = e.Fields
		}
	}
	if cve["cve"] != "CVE-2021-41773" || cve["known_exploited"] != "true" || cve["dest"] != "web-01.corp.example" || cve["dest_ip"] != "192.0.2.10" ||
		cve["dest_port"] != 443 || cve["host"] != "siem-a" || cve["cvss"] != 7.5 || cve["url"] != "https://nvd.nist.gov/vuln/detail/CVE-2021-41773" {
		t.Errorf("cve event = %v", cve)
	}
	// The products were looked up once each and kept: a second scan asks
	// the database nothing (the ssh product has no CVEs here, and is kept
	// too).
	mu.Lock()
	before := calls
	mu.Unlock()
	if _, err := s.Store.NewScan(ctx, set.Targets[0], TriggerManual, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	after := calls
	mu.Unlock()
	if after != before {
		t.Errorf("second scan made %d lookups", after-before)
	}
	hosts2, _ := s.Store.Hosts(ctx)
	if len(hosts2) != 2 || !hosts2[0].FirstSeen.Equal(hosts[0].FirstSeen) {
		t.Errorf("first seen not kept: %v %v", hosts2[0].FirstSeen, hosts[0].FirstSeen)
	}
}

func TestScanWithoutDatabase(t *testing.T) {
	var args []string
	s, _ := newScanner(t, "http://127.0.0.1:1", nmapXML, &args)
	ctx := context.Background()
	set, err := s.Store.SaveSettings(ctx, Settings{Targets: []Target{target("192.0.2.0/24")}, CVELookup: true}, store.Version{}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	sc, _ := s.Store.NewScan(ctx, set.Targets[0], TriggerManual, "alice")
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.Store.Scan(ctx, sc.ID)
	if got.State != StateDone || got.Counts.Services != 2 || got.Counts.Total() != 0 || !strings.Contains(got.CVEError, "could not reach") {
		t.Errorf("scan = %+v", got)
	}
}

func TestScanFails(t *testing.T) {
	var args []string
	s, _ := newScanner(t, "http://127.0.0.1:1", "", &args)
	s.Runner.Exec = func(ctx context.Context, path string, a []string) (io.ReadCloser, func() ([]byte, error), error) {
		return io.NopCloser(strings.NewReader("")), func() ([]byte, error) {
			return []byte("Starting Nmap 7.94\nFailed to resolve \"nope.example\".\n"), errors.New("exit status 1")
		}, nil
	}
	ctx := context.Background()
	set, _ := s.Store.SaveSettings(ctx, Settings{Targets: []Target{target("192.0.2.1")}}, store.Version{}, "alice")
	sc, _ := s.Store.NewScan(ctx, set.Targets[0], TriggerManual, "alice")
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.Store.Scan(ctx, sc.ID)
	if got.State != StateFailed || got.Error != `Nmap stopped with an error: Failed to resolve "nope.example".` {
		t.Errorf("scan = %+v", got)
	}
}

func TestScheduledAndInterrupted(t *testing.T) {
	var args []string
	s, _ := newScanner(t, "http://127.0.0.1:1", nmapXML, &args)
	s.Loc = time.UTC
	ctx := context.Background()
	tg := target("192.0.2.0/24")
	now := time.Now().UTC()
	tg.Schedule = Schedule{Every: Daily, Hour: now.Hour()}
	if _, err := s.Store.SaveSettings(ctx, Settings{Targets: []Target{tg}}, store.Version{}, "alice"); err != nil {
		t.Fatal(err)
	}
	// Created after this hour's slot: nothing is due until tomorrow.
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	scans, _ := s.Store.Scans(ctx)
	if len(scans) != 0 {
		t.Fatalf("a scan ran before its first slot: %+v", scans[0])
	}
	// Made a day ago: today's slot is due, once.
	set, v, _ := s.Store.Settings(ctx)
	set.Targets[0].CreatedAt = now.Add(-25 * time.Hour)
	doc := settingsDoc{Kind: kindSettings, Settings: set}
	if _, err := s.Store.Docs.PutIf(ctx, s.Store.Index, kindSettings, doc, v, true); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	scans, _ = s.Store.Scans(ctx)
	if len(scans) != 1 || scans[0].Trigger != TriggerSchedule || scans[0].State != StateDone {
		t.Fatalf("scans = %+v", scans)
	}
	// A scan whose server stopped is marked so.
	cut := &Scan{ID: "cut", TargetID: tg.ID, TargetName: tg.Name, State: StateRunning, CreatedAt: now, Heartbeat: now.Add(-time.Hour)}
	if _, err := s.Store.Docs.Create(ctx, s.Store.Index, scanDocID(cut.ID), scanDoc{kindScan, cut}, true); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.Store.Scan(ctx, "cut")
	if got.State != StateInterrupted || got.Error == "" {
		t.Errorf("cut scan = %+v", got)
	}
}

func TestStopQueued(t *testing.T) {
	var args []string
	s, _ := newScanner(t, "http://127.0.0.1:1", nmapXML, &args)
	ctx := context.Background()
	set, _ := s.Store.SaveSettings(ctx, Settings{Targets: []Target{target("192.0.2.1")}}, store.Version{}, "alice")
	sc, _ := s.Store.NewScan(ctx, set.Targets[0], TriggerManual, "alice")
	if err := s.Store.UpdateScan(ctx, sc.ID, map[string]any{"stop": true}); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	got, _, _ := s.Store.Scan(ctx, sc.ID)
	if got.State != StateStopped || args != nil {
		t.Errorf("scan = %+v, nmap ran with %q", got, args)
	}
}

func TestSettingsConflict(t *testing.T) {
	st := NewStore(endpoint.NewMemoryDocs(), "signalith")
	ctx := context.Background()
	if _, err := st.SaveSettings(ctx, Settings{Targets: []Target{target("192.0.2.1")}}, store.Version{}, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveSettings(ctx, Settings{}, store.Version{}, "bob"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("a stale save: %v", err)
	}
	var bad *InputError
	_, v, _ := st.Settings(ctx)
	if _, err := st.SaveSettings(ctx, Settings{Targets: []Target{target("10.0.0.0/8")}}, v, "bob"); !errors.As(err, &bad) {
		t.Errorf("a bad network: %v", err)
	}
}

func TestChecks(t *testing.T) {
	ctx := context.Background()
	c := &Checker{FindNmap: func() string { return "" }, GOOS: "windows"}
	checks, path := c.Run(ctx, DefaultSettings())
	if path != "" || Ready(checks) || checks[0].State != CheckFail || !strings.Contains(strings.Join(checks[0].Fix, " "), "nmap.org") {
		t.Errorf("no nmap: %+v", checks)
	}
	c = &Checker{FindNmap: func() string { return "/usr/bin/nmap" }, GOOS: "linux",
		Version:  func(context.Context, string) (string, error) { return "7.94", nil },
		SelfTest: func(context.Context, string) error { return nil }}
	checks, path = c.Run(ctx, Settings{CVELookup: false, Targets: []Target{target("192.0.2.1")}})
	if path != "/usr/bin/nmap" || !Ready(checks) {
		t.Errorf("ready: %+v", checks)
	}
	byID := map[string]Check{}
	for _, ch := range checks {
		byID[ch.ID] = ch
	}
	if byID["nmap"].Detail != "Nmap 7.94 at /usr/bin/nmap." || byID["cve"].State != CheckInfo || byID["networks"].State != CheckOK {
		t.Errorf("checks: %+v", byID)
	}
	c.Version = func(context.Context, string) (string, error) { return "7.60", nil }
	c.SelfTest = func(context.Context, string) error { return fmt.Errorf("dnet: Failed to open device") }
	checks, _ = c.Run(ctx, DefaultSettings())
	if Ready(checks) || checks[0].State != CheckWarn || checks[1].State != CheckFail {
		t.Errorf("old and broken: %+v", checks)
	}
}

func TestVulnSignature(t *testing.T) {
	got := vulnSignature(Vuln{CVE: "CVE-2021-41773", Description: "A flaw was found in Apache HTTP Server 2.4.49. An attacker could use it."})
	if got != "CVE-2021-41773: A flaw was found in Apache HTTP Server 2.4.49" {
		t.Errorf("signature = %q", got)
	}
}
