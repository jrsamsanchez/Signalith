package storyline

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
)

var t0 = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func finding(id string, at time.Time, sev string, mitre []string, ents map[string]any) *findings.Finding {
	return &findings.Finding{ID: id, Title: "finding " + id, Severity: sev, Urgency: sev, Status: findings.StatusNew,
		DetectionID: "det-" + id, GroupKey: "k-" + id, MITRE: mitre, Entities: ents, Created: at, Updated: at}
}

// fakeRun answers each data model with canned rows and records the
// queries it was asked.
type fakeRun struct {
	rows    map[string][]map[string]any
	fail    map[string]error
	queries []*query.Query
}

func (f *fakeRun) run(_ context.Context, q *query.Query) ([]map[string]any, error) {
	f.queries = append(f.queries, q)
	if err := f.fail[q.Datamodel]; err != nil {
		return nil, err
	}
	return f.rows[q.Datamodel], nil
}

func build(t *testing.T, fs []*findings.Finding, run *fakeRun, seeds ...Entity) *Storyline {
	t.Helper()
	store := findings.NewMemory()
	for _, f := range fs {
		if err := store.Create(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}
	b := &Builder{Findings: store}
	if run != nil {
		b.Run = run.run
	}
	st, err := b.Build(context.Background(), Request{Seeds: seeds, Earliest: t0.Add(-72 * time.Hour), Latest: t0.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func phaseNames(st *Storyline) []string {
	var out []string
	for _, p := range st.Phases {
		out = append(out, p.Name)
	}
	return out
}

func TestStoryOrdersByTacticAndTime(t *testing.T) {
	fs := []*findings.Finding{
		// Out of order on purpose: the story sorts by time, phases by tactic.
		finding("exfil", t0.Add(3*time.Hour), "critical", []string{"T1041"}, map[string]any{"dest": "ws-fin-07", "user": "alice"}),
		finding("phish", t0, "medium", []string{"T1566.001"}, map[string]any{"dest": "ws-fin-07", "user": "alice"}),
		finding("ps", t0.Add(time.Hour), "high", []string{"T1059.001"}, map[string]any{"dest": "ws-fin-07", "process_name": "powershell.exe"}),
		finding("other", t0, "low", nil, map[string]any{"dest": "ws-fin-07"}),
		// Not about the seed: left out.
		finding("elsewhere", t0, "high", []string{"T1059"}, map[string]any{"dest": "web-01"}),
		// Too old for the window: left out.
		finding("old", t0.Add(-10*24*time.Hour), "high", nil, map[string]any{"dest": "ws-fin-07"}),
	}
	st := build(t, fs, nil, Entity{System, "ws-fin-07"})
	var ids []string
	for _, it := range st.Items {
		ids = append(ids, it.ID)
	}
	if strings.Join(ids, ",") != "phish,other,ps,exfil" && strings.Join(ids, ",") != "other,phish,ps,exfil" {
		t.Errorf("items = %v", ids)
	}
	if got := strings.Join(phaseNames(st), ","); got != "Initial Access,Execution,Exfiltration,No ATT&CK tactic" {
		t.Errorf("phases = %s", got)
	}
	if st.Phases[2].Severity != "critical" || st.Phases[2].Items != 1 {
		t.Errorf("exfil phase = %+v", st.Phases[2])
	}
	var seed *Node
	for i, n := range st.Nodes {
		if n.ID == "system:ws-fin-07" {
			seed = &st.Nodes[i]
		}
	}
	if seed == nil || !seed.Seed || seed.Findings != 4 || seed.Severity != "critical" || st.Nodes[0].ID != "system:ws-fin-07" {
		t.Fatalf("seed node = %+v (first %s)", seed, st.Nodes[0].ID)
	}
	hasEdge := func(a, b string) bool {
		return slices.ContainsFunc(st.Edges, func(e Edge) bool {
			return e.Kind == "together" && (e.From == a && e.To == b || e.From == b && e.To == a)
		})
	}
	if !hasEdge("system:ws-fin-07", "user:alice") || !hasEdge("system:ws-fin-07", "process:powershell.exe") {
		t.Errorf("edges = %+v", st.Edges)
	}
}

func TestRiskJoinsItsFindingOrStandsAlone(t *testing.T) {
	fs := []*findings.Finding{finding("brute", t0, "high", []string{"T1110"}, map[string]any{"user": "bob", "src": "203.0.113.9"})}
	run := &fakeRun{rows: map[string][]map[string]any{
		"Risk": {
			// Written with the finding: adds to it.
			{"_time": t0.Format(time.RFC3339Nano), "risk_object": "bob", "risk_object_type": "user", "risk_score": 40.0,
				"detection_id": "det-brute", "group_key": "k-brute", "risk_message": "Brute force"},
			// A risk-only detection: its own item, with its tactic.
			{"_time": t0.Add(2 * time.Hour).Format(time.RFC3339Nano), "risk_object": "bob", "risk_object_type": "user", "risk_score": 25.0,
				"detection_id": "rare-login", "group_key": "x", "risk_message": "Rare sign-in country", "mitre_tactic": []any{"initial-access"},
				"src": "198.51.100.4"},
			// The same detection's risk event for the system: the same item.
			{"_time": t0.Add(2 * time.Hour).Format(time.RFC3339Nano), "risk_object": "ws-1", "risk_object_type": "system", "risk_score": 10.0,
				"detection_id": "rare-login", "group_key": "x", "risk_message": "Rare sign-in country", "mitre_tactic": []any{"initial-access"},
				"user": "bob"},
		},
	}}
	st := build(t, fs, run, Entity{User, "bob"})
	if len(st.Items) != 2 || st.Items[0].Risk != 40 || st.Items[1].Kind != "risk" || st.Items[1].Title != "Rare sign-in country" || st.Items[1].Risk != 35 {
		t.Fatalf("items = %+v", st.Items)
	}
	if st.Risk != 75 {
		t.Errorf("risk = %v", st.Risk)
	}
	if got := strings.Join(phaseNames(st), ","); got != "Initial Access,Credential Access" {
		t.Errorf("phases = %s", got)
	}
	// The risk search looks for the seed in every entity field, in the
	// window, and is bounded.
	q := run.queries[0]
	if q.Datamodel != "Risk" || !strings.Contains(q.String(), "risk_object IN (bob)") || q.Earliest == "" || q.Latest == "" {
		t.Errorf("risk query = %s", q)
	}
	if h, ok := q.Commands[len(q.Commands)-1].(*query.Head); !ok || h.N != MaxRisk+1 {
		t.Errorf("risk query not bounded: %s", q)
	}
}

func TestActivityLinksEntities(t *testing.T) {
	fs := []*findings.Finding{
		finding("ps", t0, "high", []string{"T1059.001"}, map[string]any{"dest": "ws-fin-07", "process_name": "powershell.exe", "user": "alice"}),
		finding("c2", t0, "high", []string{"T1071"}, map[string]any{"host": "ws-fin-07", "src": "10.0.0.7", "dest": "203.0.113.50"}),
	}
	run := &fakeRun{rows: map[string][]map[string]any{
		"Authentication": {
			{"user": "alice", "src": "10.0.0.9", "dest": "ws-fin-07", "action": "success", "count": 3.0, "first": float64(t0.UnixMilli()), "last": float64(t0.UnixMilli())},
			// Touches nothing in the story: does not add nodes.
			{"user": "carol", "src": "10.0.0.20", "dest": "file-01", "action": "success", "count": 9.0},
		},
		"Endpoint": {
			{"dest": "ws-fin-07", "parent_process_name": "winword.exe", "process_name": "powershell.exe", "count": 1.0},
		},
		"Network_Traffic": {
			{"src": "10.0.0.7", "dest": "203.0.113.50", "dest_port": "443", "action": "allowed", "count": 120.0},
		},
	}}
	st := build(t, fs, run, Entity{System, "ws-fin-07"})
	has := func(from, to, kind string) bool {
		return slices.ContainsFunc(st.Edges, func(e Edge) bool { return e.From == from && e.To == to && e.Kind == kind })
	}
	if !has("user:alice", "system:ws-fin-07", "login") || !has("ip:10.0.0.9", "system:ws-fin-07", "login") {
		t.Errorf("login edges missing: %+v", st.Edges)
	}
	if !has("process:winword.exe", "process:powershell.exe", "started") {
		t.Errorf("process edge missing: %+v", st.Edges)
	}
	if !has("ip:10.0.0.7", "ip:203.0.113.50", "connected") {
		t.Errorf("connection edge missing: %+v", st.Edges)
	}
	if slices.ContainsFunc(st.Nodes, func(n Node) bool { return n.Value == "carol" || n.Value == "file-01" }) {
		t.Errorf("unrelated sign-in joined the graph: %+v", st.Nodes)
	}
	if len(st.Activity) != 3 || st.Activity[0].Kind != "login" || st.Activity[0].Count != 3 || !st.Activity[0].First.Equal(t0) {
		t.Errorf("activity = %+v", st.Activity)
	}
	for _, k := range []string{"risk", "login", "process", "connection"} {
		if st.Searches[k] == "" {
			t.Errorf("no search for %s", k)
		}
	}
	// The process search is only about processes in the story, on its
	// systems.
	for _, q := range run.queries {
		if q.Datamodel == "Endpoint" && (!strings.Contains(q.String(), "powershell.exe") || !strings.Contains(q.String(), "ws-fin-07")) {
			t.Errorf("process query = %s", q)
		}
	}
}

func TestActivityFailureIsAWarning(t *testing.T) {
	fs := []*findings.Finding{finding("a", t0, "high", nil, map[string]any{"dest": "ws-fin-07", "user": "alice"})}
	run := &fakeRun{fail: map[string]error{"Authentication": errors.New("index missing")}}
	st := build(t, fs, run, Entity{System, "ws-fin-07"})
	if len(st.Items) != 1 || len(st.Warnings) != 1 || !strings.Contains(st.Warnings[0], "sign-ins") {
		t.Errorf("items %d warnings %v", len(st.Items), st.Warnings)
	}
	// Risk is part of the story itself: its failure fails the request.
	store := findings.NewMemory()
	b := &Builder{Findings: store, Run: (&fakeRun{fail: map[string]error{"Risk": errors.New("down")}}).run}
	if _, err := b.Build(context.Background(), Request{Seeds: []Entity{{System, "x"}}, Earliest: t0, Latest: t0.Add(time.Hour)}); err == nil {
		t.Error("risk failure ignored")
	}
}

func TestLimits(t *testing.T) {
	var fs []*findings.Finding
	for i := range MaxFindings + 5 {
		ents := map[string]any{"dest": "ws-fin-07"}
		for j := range 8 {
			ents[[]string{"user", "src", "src_user", "host", "dest_host", "src_host", "member", "process_name"}[j]] = "e" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + string(rune('0'+j))
		}
		fs = append(fs, finding("f"+string(rune('a'+i%26))+string(rune('a'+i/26)), t0.Add(time.Duration(i)*time.Minute), "low", nil, ents))
	}
	st := build(t, fs, nil, Entity{System, "ws-fin-07"})
	if len(st.Items) != MaxFindings || !slices.Contains(st.Truncated, "findings") {
		t.Errorf("items %d truncated %v", len(st.Items), st.Truncated)
	}
	if len(st.Nodes) != MaxNodes || len(st.Edges) > MaxEdges || !slices.Contains(st.Truncated, "nodes") {
		t.Errorf("nodes %d edges %d", len(st.Nodes), len(st.Edges))
	}
	for _, it := range st.Items {
		if len(it.Entities) > maxPerItem {
			t.Fatalf("item has %d entities", len(it.Entities))
		}
	}
	// A window longer than the limit is cut to it.
	b := &Builder{Findings: findings.NewMemory()}
	out, err := b.Build(context.Background(), Request{Seeds: []Entity{{User, "x"}}, Earliest: t0.Add(-365 * 24 * time.Hour), Latest: t0})
	if err != nil || out.Latest.Sub(out.Earliest) != MaxWindow {
		t.Errorf("window = %v..%v %v", out.Earliest, out.Latest, err)
	}
	if _, err := b.Build(context.Background(), Request{Earliest: t0, Latest: t0.Add(time.Hour)}); !errors.Is(err, ErrNoSeeds) {
		t.Errorf("no seeds = %v", err)
	}
}

func TestParseSeed(t *testing.T) {
	for _, c := range []struct{ typ, value, want string }{
		{"system", "ws-fin-07", "system:ws-fin-07"},
		{"system", " 10.0.0.7 ", "ip:10.0.0.7"},
		{"user", `CORP\bob`, `user:CORP\bob`},
		{"user", "*", ""},
		{"user", "bo?", ""},
		{"user", "", ""},
		{"user", "a\nb", ""},
		{"process", "cmd.exe", ""},
		{"user", strings.Repeat("a", 257), ""},
	} {
		e, err := ParseSeed(c.typ, c.value)
		if (err == nil) != (c.want != "") || (err == nil && e.Key() != c.want) {
			t.Errorf("ParseSeed(%q, %q) = %v, %v; want %q", c.typ, c.value, e, err, c.want)
		}
	}
}

func TestSeedsFromFindingAndCase(t *testing.T) {
	f := finding("a", t0, "high", nil, map[string]any{"user": "alice", "dest": "10.0.0.7", "process_name": "cmd.exe", "risk_object": "alice", "risk_object_type": "user", "object": "x"})
	got := SeedsFromFinding(f)
	if len(got) != 2 || got[0] != (Entity{User, "alice"}) || got[1] != (Entity{IP, "10.0.0.7"}) {
		t.Errorf("finding seeds = %v", got)
	}
	g := finding("b", t0, "high", nil, map[string]any{"dest": "web-01"})
	h := finding("c", t0, "high", nil, map[string]any{"dest": "web-01", "user": "svc"})
	c := &cases.Case{Entities: []cases.Entity{{Field: "user", Value: "mallory"}, {Field: "ip", Value: "198.51.100.1"}}}
	got = SeedsFromCase(c, []*findings.Finding{g, h})
	want := []Entity{{User, "mallory"}, {IP, "198.51.100.1"}, {System, "web-01"}, {User, "svc"}}
	if !slices.Equal(got, want) {
		t.Errorf("case seeds = %v", got)
	}
}

func TestWindowAround(t *testing.T) {
	now := t0.Add(5 * time.Hour)
	e, l := WindowAround([]time.Time{t0, t0.Add(time.Hour)}, now)
	if !e.Equal(t0.Add(-72*time.Hour)) || !l.Equal(now) {
		t.Errorf("window = %v..%v", e, l)
	}
	e, l = WindowAround([]time.Time{t0.Add(-60 * 24 * time.Hour), t0}, now)
	if l.Sub(e) != MaxWindow {
		t.Errorf("long window = %v..%v", e, l)
	}
}
