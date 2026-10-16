package detect

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/search"
)

type memRisk struct{ events []RiskEvent }

func (m *memRisk) Write(_ context.Context, evs []RiskEvent) error {
	m.events = append(m.events, evs...)
	return nil
}

func (m *memRisk) Exists(_ context.Context, id, key string, since time.Time) (bool, error) {
	for _, e := range m.events {
		if e.DetectionID == id && e.GroupKey == key && !e.Time.Before(since) {
			return true, nil
		}
	}
	return false, nil
}

func testAssets(t *testing.T) *assets.Store {
	t.Helper()
	a, _ := assets.NewStore("")
	if _, err := a.SetAssets([]byte("host,owner,priority\nDC01,it-ops,critical\nWS7,desk,low\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SetIdentities([]byte("identity,name,priority,watchlist\nbob,Bob Smith,medium,true\nkiosk,Kiosk,low,\n")); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestRiskOnlyDetectionRecordsRiskAndThrottles(t *testing.T) {
	lib, _, _ := NewLibrary("")
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	rs := &memRisk{}
	fs := findings.NewMemory()
	run := &fakeRunner{rows: []search.Row{
		{"user": "bob", "dest": "DC01", "process": "schtasks /create /tn x"},
		{"user": "kiosk", "dest": "WS7", "process": "schtasks /create /tn y"},
	}}
	s := &Scheduler{Library: lib, Engine: run, Findings: fs, Risk: rs, Assets: testAssets(t), Now: func() time.Time { return now }}
	d, _ := lib.Get("endpoint-scheduled-task")
	if d.Risk == nil || !d.Risk.Only {
		t.Fatalf("expected a risk-only detection: %+v", d.Risk)
	}
	res, err := s.RunManual(context.Background(), d, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.Risk != 4 {
		t.Fatalf("run = %+v", res)
	}
	score := map[string]float64{}
	for _, e := range rs.events {
		score[e.ObjectType+":"+e.Object] = e.Score
		if e.BaseScore != 20 || e.Tactics == nil || e.Message != "Scheduled task created on "+e.Fields["dest"].(string)+" by "+e.Fields["user"].(string) {
			t.Errorf("event = %+v", e)
		}
	}
	// bob is medium priority but watchlisted (x1.5), DC01 critical (x2), WS7 and kiosk low (x0.5).
	want := map[string]float64{"user:bob": 30, "system:DC01": 40, "user:kiosk": 10, "system:WS7": 10}
	for k, v := range want {
		if score[k] != v {
			t.Errorf("%s score = %v, want %v", k, score[k], v)
		}
	}
	// Overlapping run: the same rows are throttled by the risk store.
	now = now.Add(5 * time.Minute)
	res, _ = s.RunManual(context.Background(), d, "")
	if res.Risk != 0 || res.Throttled != 2 {
		t.Errorf("second run = %+v", res)
	}
}

func TestFindingGetsContextAndUrgency(t *testing.T) {
	lib, _, _ := NewLibrary("")
	run := &fakeRunner{rows: []search.Row{{"user": "svc", "dest": "DC01", "process": "vssadmin delete shadows /all"}}}
	rs := &memRisk{}
	s := &Scheduler{Library: lib, Engine: run, Findings: findings.NewMemory(), Risk: rs, Assets: testAssets(t)}
	d, _ := lib.Get("endpoint-encoded-powershell")
	res, err := s.RunManual(context.Background(), d, "")
	if err != nil || len(res.Findings) != 1 {
		t.Fatal(res, err)
	}
	f := res.Findings[0]
	if f.Severity != "high" || f.Urgency != "critical" || f.Context["dest"].Owner != "it-ops" {
		t.Errorf("finding = %+v context=%v", f, f.Context)
	}
	if res.Risk != 2 {
		t.Errorf("risk events = %d", res.Risk)
	}
}

func TestUrgency(t *testing.T) {
	c := func(p string, wl bool) *assets.Context { return &assets.Context{Priority: p, Watchlist: wl} }
	cases := []struct {
		sev  string
		ctx  map[string]*assets.Context
		want string
	}{
		{"medium", nil, "medium"},
		{"medium", map[string]*assets.Context{"dest": c("critical", false)}, "high"},
		{"critical", map[string]*assets.Context{"dest": c("critical", false)}, "critical"},
		{"high", map[string]*assets.Context{"user": c("", true)}, "critical"},
		{"medium", map[string]*assets.Context{"dest": c("low", false), "user": c("low", false)}, "low"},
		{"medium", map[string]*assets.Context{"dest": c("low", false), "user": c("high", false)}, "medium"},
		{"informational", map[string]*assets.Context{"dest": c("low", false)}, "informational"},
	}
	for _, tc := range cases {
		if got := Urgency(tc.sev, tc.ctx); got != tc.want {
			t.Errorf("Urgency(%s, %v) = %s, want %s", tc.sev, tc.ctx, got, tc.want)
		}
	}
}

func TestRiskIncidentContext(t *testing.T) {
	a := testAssets(t)
	ctx := EntityContext(a, map[string]any{"risk_object": "bob", "risk_object_type": "user"})
	if ctx["risk_object"] == nil || ctx["risk_object"].Name != "Bob Smith" {
		t.Errorf("context = %v", ctx)
	}
	ctx = EntityContext(a, map[string]any{"risk_object": "DC01", "risk_object_type": "system"})
	if ctx["risk_object"] == nil || ctx["risk_object"].Owner != "it-ops" {
		t.Errorf("system context = %v", ctx)
	}
}

func TestRiskValidation(t *testing.T) {
	d := &Detection{ID: "r-1", Title: "x", Query: "user=x", Risk: &Risk{Score: 0, Objects: []RiskObject{{Field: "", Type: "host"}}}}
	d.Defaults()
	err := d.Validate()
	if err == nil {
		t.Fatal("invalid risk accepted")
	}
	for _, want := range []string{"risk.score", "field is required", "type must be one of"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
	d = &Detection{ID: "r-2", Title: "x", Query: "user=x", Lookback: "30m", Schedule: "10m", Risk: &Risk{Score: 10, Objects: []RiskObject{{Field: "user", Type: "user"}}, Only: true}}
	d.Defaults()
	if err := d.Validate(); err != nil || d.Throttle.Window != "30m" {
		t.Errorf("risk-only defaults: %v window=%q", err, d.Throttle.Window)
	}
}

func TestRiskEventDoc(t *testing.T) {
	e := RiskEvent{Time: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC), Object: "bob", ObjectType: "user", Score: 30, BaseScore: 20,
		Message: "Thing", DetectionID: "d", MITRE: []string{"T1110"}, Tactics: Tactics([]string{"T1110", "T1078"}), Fields: map[string]any{"user": "bob", "risk_score": "spoof"}}
	doc := e.Doc()
	if doc["risk_score"] != float64(30) || doc["datamodel"] != "Risk" || doc["user"] != "bob" {
		t.Errorf("doc = %v", doc)
	}
	tac := doc["mitre_tactic"].([]string)
	if len(tac) < 3 || tac[0] != "credential-access" {
		t.Errorf("tactics = %v", tac)
	}
}
