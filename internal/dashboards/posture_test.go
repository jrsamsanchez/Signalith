package dashboards

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

var now = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

func mkFinding(id, det, urgency, status string, created time.Time, mitre []string, history ...findings.Change) *findings.Finding {
	f := &findings.Finding{ID: id, DetectionID: det, Title: id + " title", Severity: urgency, Urgency: urgency, Status: status,
		MITRE: mitre, Created: created, Updated: created, History: history}
	for _, h := range history {
		if h.Time.After(f.Updated) {
			f.Updated = h.Time
		}
	}
	return f
}

func change(field, from, to string, at time.Time) findings.Change {
	return findings.Change{Author: "sam", Field: field, From: from, To: to, Time: at}
}

func seedFindings(t *testing.T) *findings.Memory {
	t.Helper()
	m := findings.NewMemory()
	h := func(n float64) time.Time { return now.Add(time.Duration(-n * float64(time.Hour))) }
	for _, f := range []*findings.Finding{
		// Raised in the last 24h.
		mkFinding("a", "auth-brute-force", "high", "new", h(1), []string{"T1110"}),
		mkFinding("b", "auth-brute-force", "critical", "in_progress", h(3), []string{"T1110"},
			change("owner", "", "sam", h(2.5)), change("status", "new", "in_progress", h(2))), // triaged after 30m
		mkFinding("c", "endpoint-encoded-powershell", "medium", "closed", h(10), []string{"T1059.001"},
			change("status", "new", "in_progress", h(9)), change("status", "in_progress", "closed", h(6))), // triage 1h, resolve 4h
		// Raised the day before; one closed today.
		mkFinding("d", "auth-brute-force", "high", "resolved", h(30), nil,
			change("status", "new", "resolved", h(5))), // triage and resolve in the current period: 25h
		mkFinding("e", "change-account-created", "low", "new", h(40), []string{"T1136"}),
		// Old, open, outside both periods.
		mkFinding("f", "auth-sudo-failures", "medium", "pending", h(24*20), nil, change("status", "new", "pending", h(24*20-1))),
	} {
		if err := m.Create(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func postureExec(t *testing.T, fail string) *fakeExec {
	return &fakeExec{respond: func(q *query.Query) (*search.Result, error) {
		s := q.String()
		if fail != "" && strings.Contains(s, fail) {
			return nil, errors.New("index missing")
		}
		table := func(cols []string, rows ...search.Row) (*search.Result, error) {
			return &search.Result{Kind: "table", Columns: cols, Rows: rows}, nil
		}
		switch {
		case strings.Contains(s, "max(_time)"):
			return table([]string{"host", "sourcetype", "last_seen", "count"},
				search.Row{"host": "web1", "sourcetype": "linux:auth", "last_seen": now.Add(-5 * time.Minute).UnixMilli(), "count": int64(900)},
				search.Row{"host": "DC01", "sourcetype": "WinEventLog:Security", "last_seen": float64(now.Add(-26 * time.Hour).UnixMilli()), "count": int64(40)})
		case strings.Contains(s, "by risk_object"):
			return table([]string{"risk_object", "risk_object_type", "risk_score"}, search.Row{"risk_object": "bob", "risk_object_type": "user", "risk_score": int64(160)})
		case strings.Contains(s, "by detection_id"):
			if q.Earliest == "-30d" {
				return table([]string{"detection_id", "count"}, search.Row{"detection_id": "endpoint-discovery-burst", "count": int64(3)})
			}
			return table([]string{"detection_id", "count"},
				search.Row{"detection_id": "endpoint-scheduled-task", "count": int64(9)},
				search.Row{"detection_id": "auth-brute-force", "count": int64(1)})
		case strings.Contains(s, "by mitre_tactic"):
			return table([]string{"mitre_tactic", "count"}, search.Row{"mitre_tactic": "persistence", "count": int64(9)}, search.Row{"mitre_tactic": "execution", "count": int64(2)})
		case strings.Contains(s, "timechart"):
			return &search.Result{Kind: "timechart", Columns: []string{"_time", "Authentication"}, Rows: []search.Row{{"_time": "2026-10-12T11:00:00Z", "Authentication": int64(5)}}}, nil
		case strings.Contains(s, "stats count"):
			if q.Latest == "-24h" {
				return table([]string{"count"}, search.Row{"count": int64(800)})
			}
			return table([]string{"count"}, search.Row{"count": int64(1000)})
		}
		t.Errorf("unexpected query %s", s)
		return nil, errors.New("unexpected")
	}}
}

func TestPostureMetrics(t *testing.T) {
	lib, _, err := detect.NewLibrary("")
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]detect.RunState{
		"auth-password-spray": {LastRun: now.Add(-time.Minute), LastError: "unknown field"},
		"auth-brute-force":    {LastRun: now.Add(-time.Minute), LastResults: 1},
	}
	p := &Posture{Engine: postureExec(t, ""), Findings: seedFindings(t), Detections: lib, Status: func() map[string]detect.RunState { return status },
		SchedulerOn: true, StaleAfter: 2 * time.Hour, Now: func() time.Time { return now }}
	rep := p.Report(context.Background(), 24*time.Hour, "24h")
	if rep.Errors != nil {
		t.Fatalf("errors = %v", rep.Errors)
	}
	ind := map[string]Indicator{}
	for _, i := range rep.Indicators {
		ind[i.ID] = i
	}
	val := func(id string) string {
		i := ind[id]
		v, p := "nil", "nil"
		if i.Value != nil {
			v = fmt.Sprint(*i.Value)
		}
		if i.Previous != nil {
			p = fmt.Sprint(*i.Previous)
		}
		return v + "/" + p
	}
	for id, want := range map[string]string{
		"open_findings":        "4/nil",     // a, b, e, f
		"new_findings":         "3/2",       // a, b, c now; d, e the day before
		"closed_findings":      "2/0",       // c and d closed today
		"mean_time_to_triage":  "31800/nil", // b 30m, c 1h, d 25h -> 8h50m; nothing triaged the day before
		"mean_time_to_resolve": "52200/nil", // c 4h, d 25h -> 14.5h
		"events_ingested":      "1000/800",
	} {
		if got := val(id); got != want {
			t.Errorf("%s = %s, want %s", id, got, want)
		}
	}
	if rep.OpenByUrgency["high"] != 1 || rep.OpenByUrgency["critical"] != 1 || rep.OpenByUrgency["low"] != 1 || rep.OpenByUrgency["medium"] != 1 {
		t.Errorf("open by urgency = %v", rep.OpenByUrgency)
	}

	// Findings over time: hourly buckets with a column per urgency seen.
	ot := rep.FindingsOverTime
	if strings.Join(ot.Columns, ",") != "_time,critical,high,medium" || len(ot.Rows) != 25 {
		t.Errorf("over time columns %v rows %d", ot.Columns, len(ot.Rows))
	}
	var total int64
	for _, r := range ot.Rows {
		for _, c := range ot.Columns[1:] {
			total += r[c].(int64)
		}
	}
	if total != 3 {
		t.Errorf("findings over time total %d", total)
	}

	// Top detections merge findings and risk events.
	if len(rep.TopDetections) != 3 {
		t.Fatalf("top detections = %+v", rep.TopDetections)
	}
	if d := rep.TopDetections[0]; d.ID != "endpoint-scheduled-task" || d.RiskEvents != 9 || d.Findings != 0 {
		t.Errorf("top = %+v", d)
	}
	// Counted across hosts, a detection is named without its $field$
	// placeholders, not "Brute force against dest from src".
	if d := rep.TopDetections[1]; d.ID != "auth-brute-force" || d.Findings != 2 || d.RiskEvents != 1 || d.Title != "Brute force" {
		t.Errorf("second = %+v", d)
	}
	for _, d := range rep.TopDetections {
		if d.ID == "endpoint-encoded-powershell" && d.Title != "Encoded PowerShell command" {
			t.Errorf("encoded PowerShell title = %q", d.Title)
		}
	}

	// Tactics in matrix order with names.
	var tac []string
	for _, x := range rep.Tactics {
		tac = append(tac, fmt.Sprintf("%s:%d+%d", x.Tactic, x.Findings, x.RiskEvents))
	}
	if strings.Join(tac, " ") != "execution:1+2 persistence:0+9 credential-access:2+0" {
		t.Errorf("tactics = %v", tac)
	}
	if rep.Tactics[0].Name != "Execution" {
		t.Errorf("tactic name = %q", rep.Tactics[0].Name)
	}

	h := rep.Health
	if h.Total != len(lib.List()) || h.Enabled == 0 || h.Enabled >= h.Total || !h.SchedulerOn {
		t.Errorf("health counts = %+v", h)
	}
	if len(h.Erroring) != 1 || h.Erroring[0].ID != "auth-password-spray" || h.Erroring[0].Error != "unknown field" || h.Erroring[0].Title != "Password spray" {
		t.Errorf("erroring = %+v", h.Erroring)
	}
	silent := map[string]bool{}
	for _, s := range h.Silent {
		silent[s.ID] = true
	}
	// Brute force raised findings and the discovery burst added risk this
	// month; encoded PowerShell is enabled and raised one.
	if silent["auth-brute-force"] || silent["endpoint-encoded-powershell"] || silent["endpoint-discovery-burst"] || !silent["endpoint-shadow-copy-delete"] {
		t.Errorf("silent = %v", silent)
	}
	if h.NotRun != h.Enabled-2 {
		t.Errorf("not run = %d of %d enabled", h.NotRun, h.Enabled)
	}
	if h.Sources != 2 || len(h.StaleSources) != 1 || h.StaleSources[0].Host != "DC01" || h.StaleAfter != "2h" {
		t.Errorf("sources = %+v", h)
	}
}

func TestPostureSectionsFailAlone(t *testing.T) {
	p := &Posture{Engine: postureExec(t, "datamodel=Risk"), Findings: nil, Now: func() time.Time { return now }}
	rep := p.Report(context.Background(), 7*24*time.Hour, "7d")
	for _, sec := range []string{"findings", "risk_objects", "top_detections", "tactics", "health"} {
		if rep.Errors[sec] == "" {
			t.Errorf("no error for %s: %v", sec, rep.Errors)
		}
	}
	if rep.Errors["events"] != "" || rep.EventsByDatamodel == nil || rep.Health == nil || rep.Health.Sources != 2 {
		t.Errorf("working sections broke: %v", rep.Errors)
	}
	for _, i := range rep.Indicators {
		if i.ID == "events_ingested" && (i.Value == nil || *i.Value != 1000) {
			t.Errorf("events = %+v", i)
		}
		if i.ID == "new_findings" && i.Error == "" {
			t.Errorf("new findings without a store = %+v", i)
		}
	}
	if len(rep.Health.Silent) != 0 {
		t.Errorf("silent judged without data: %v", rep.Health.Silent)
	}
}

func TestTriageAndResolveTimes(t *testing.T) {
	c := now.Add(-time.Hour)
	f := mkFinding("x", "d", "low", "closed", c, nil,
		change("owner", "", "", c.Add(time.Minute)), // clearing the owner is not triage
		change("status", "new", "resolved", c.Add(10*time.Minute)),
		change("status", "resolved", "new", c.Add(20*time.Minute)),
		change("status", "new", "closed", c.Add(30*time.Minute)))
	if at, ok := TriagedAt(f); !ok || !at.Equal(c.Add(10*time.Minute)) {
		t.Errorf("triaged %v %v", at, ok)
	}
	if at, ok := ResolvedAt(f); !ok || !at.Equal(c.Add(30*time.Minute)) {
		t.Errorf("resolved %v %v", at, ok)
	}
	f.Status = "new"
	if _, ok := ResolvedAt(f); ok {
		t.Error("open finding has a resolve time")
	}
}

// A detection no longer in the library is named by its findings' title
// only when every finding has the same one: a title filled in for one host
// must not name a count across several.
func TestPostureTopDetectionsRemovedDetection(t *testing.T) {
	m := findings.NewMemory()
	for i, x := range []struct{ det, title string }{
		{"gone-same", "Odd thing seen"}, {"gone-same", "Odd thing seen"},
		{"gone-mixed", "Odd login on ws-1"}, {"gone-mixed", "Odd login on ws-2"},
	} {
		f := mkFinding(fmt.Sprint("f", i), x.det, "low", "new", now.Add(-time.Hour), nil)
		f.Title = x.title
		if err := m.Create(context.Background(), f); err != nil {
			t.Fatal(err)
		}
	}
	p := &Posture{Engine: postureExec(t, ""), Findings: m, Now: func() time.Time { return now }}
	rep := p.Report(context.Background(), 24*time.Hour, "24h")
	got := map[string]string{}
	for _, d := range rep.TopDetections {
		got[d.ID] = d.Title
	}
	if got["gone-same"] != "Odd thing seen" || got["gone-mixed"] != "gone-mixed" {
		t.Errorf("titles = %v", got)
	}
}

// Health comes from the run state every server shares: a server that
// does not run the detections still counts the ones that never ran or
// fail, lists the ones behind, and merges the runs that were skipped.
func TestPostureHealthOnAnotherServer(t *testing.T) {
	lib, _, err := detect.NewLibrary("")
	if err != nil {
		t.Fatal(err)
	}
	gapFrom, gapTo := now.Add(-10*time.Hour), now.Add(-6*time.Hour)
	status := map[string]detect.RunState{
		"auth-password-spray": {LastRun: now.Add(-time.Minute), LastError: "unknown field", ErrorKind: detect.ErrorQuery},
		"auth-brute-force": {LastRun: now.Add(-time.Minute), NextRun: now.Add(time.Minute),
			Skipped: &detect.Skipped{From: gapFrom, To: gapTo.Add(-time.Hour), At: now.Add(-time.Hour), Count: 48}},
		"endpoint-encoded-powershell": {LastRun: now.Add(-time.Minute), NextRun: now.Add(-3 * time.Hour),
			Skipped: &detect.Skipped{From: gapFrom.Add(time.Hour), To: gapTo, At: now.Add(-2 * time.Hour), Count: 12}},
		// Skipped long ago: not shown.
		"endpoint-shadow-copy-delete": {LastRun: now.Add(-time.Minute),
			Skipped: &detect.Skipped{From: now.Add(-80 * time.Hour), To: now.Add(-79 * time.Hour), At: now.Add(-72 * time.Hour), Count: 5}},
	}
	p := &Posture{Engine: postureExec(t, ""), Findings: seedFindings(t), Detections: lib, Status: func() map[string]detect.RunState { return status },
		SchedulerOn: true, Elsewhere: true, RunsOn: "siem-a", StaleAfter: 2 * time.Hour, Now: func() time.Time { return now }}
	h := p.Report(context.Background(), 24*time.Hour, "24h").Health
	if !h.RunsElsewhere || h.RunsOn != "siem-a" || h.SchedulerOn {
		t.Errorf("label = %+v", h)
	}
	if h.NotRun != h.Enabled-len(status) {
		t.Errorf("not run = %d of %d enabled", h.NotRun, h.Enabled)
	}
	if len(h.Erroring) != 1 || h.Erroring[0].ID != "auth-password-spray" {
		t.Errorf("erroring = %+v", h.Erroring)
	}
	behind := false
	for _, b := range h.Behind {
		behind = behind || b.ID == "endpoint-encoded-powershell"
		if b.ID == "auth-brute-force" {
			t.Errorf("brute force is not behind: %+v", h.Behind)
		}
	}
	if !behind {
		t.Errorf("behind = %+v", h.Behind)
	}
	g := h.Skipped
	if g == nil || g.Runs != 60 || g.Detections != 2 || g.Title != "" || !g.From.Equal(gapFrom) || !g.To.Equal(gapTo) {
		t.Errorf("skipped = %+v", g)
	}

	// One rule: the gap names it.
	status = map[string]detect.RunState{"auth-brute-force": status["auth-brute-force"]}
	g = p.Report(context.Background(), 24*time.Hour, "24h").Health.Skipped
	if g == nil || g.Runs != 48 || g.Detections != 1 || g.Title == "" {
		t.Errorf("one skipped = %+v", g)
	}
}
