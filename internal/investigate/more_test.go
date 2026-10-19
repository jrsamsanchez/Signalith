// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package investigate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// scripted answers with its replies in turn, or err.
type scripted struct {
	replies []string
	err     error
	got     [][]assistant.Message
}

func (m *scripted) Name() string { return "scripted" }
func (m *scripted) Chat(_ context.Context, _ string, msgs []assistant.Message, _ int) (string, error) {
	m.got = append(m.got, msgs)
	if m.err != nil {
		return "", m.err
	}
	if len(m.replies) == 0 {
		return "{}", nil
	}
	r := m.replies[0]
	m.replies = m.replies[1:]
	return r, nil
}

// manyRows answers every search with more rows than are sent and long
// values; a query with "boom" in it fails.
type manyRows struct {
	mu  sync.Mutex
	ran []string
}

func (s *manyRows) Execute(_ context.Context, q *query.Query) (*search.Result, error) {
	s.mu.Lock()
	s.ran = append(s.ran, q.String()+" @"+q.Earliest+".."+q.Latest)
	s.mu.Unlock()
	if strings.Contains(q.String(), "boom") {
		return nil, errors.New("index missing")
	}
	var rows []search.Row
	for i := range RowsSent + 2 {
		rows = append(rows, search.Row{"user": "alice", "src": "10.1.2.3", "n": i,
			"note": strings.Repeat("é", MaxValueLen), "_raw": strings.Repeat("x", MaxRawLen+5)})
	}
	return &search.Result{Kind: "events", Columns: []string{"user", "src", "n"}, Matched: 50, Rows: rows}, nil
}

func richFinding() *findings.Finding {
	return &findings.Finding{ID: "f1", Title: "Odd logons", DetectionID: "auth_odd", Severity: "high", Urgency: "critical",
		Description: "Logons from a new place.", MITRE: []string{"T1078"},
		Entities: map[string]any{"user": []any{"alice", "bob"}, "src": "10.1.2.3", "risk_object": "web-01", "risk_object_type": "system",
			"dvc": []string{"fw1"}, "custom": "thing", "extra": "more"},
		Context: map[string]*assets.Context{"user": {Kind: "identity", Priority: "high", BUnit: "sales", Category: []string{"vip"}, Watchlist: true}, "gone": nil,
			"src": {Kind: "asset"}},
		Result:   map[string]any{"user": "alice", "src": "10.1.2.3", "_time": "x", "_raw": "raw"},
		Query:    "datamodel=Authentication user=alice",
		Comments: []findings.Comment{{Author: "kim", Text: "Looked at it."}}}
}

func TestRunGathersEverything(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	is := intel.NewStore(intel.NewMemory())
	var inds []intel.Indicator
	for i := range RowsSent + 1 {
		inds = append(inds, intel.Indicator{Type: intel.TypeIP, Value: "10.1.2.3", Source: fmt.Sprintf("feed-%d", i), Description: "scanner", Weight: 1})
	}
	if err := is.Add(ctx, inds); err != nil {
		t.Fatal(err)
	}

	fs := findings.NewMemory()
	for i := range maxRelated + 2 {
		f := &findings.Finding{ID: fmt.Sprintf("r%02d", i), Title: "Related", Severity: "low", Status: "new", Created: now.Add(-time.Hour),
			Entities: map[string]any{"user": "alice", "risk_object_type": "user"}}
		if err := fs.Create(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []*findings.Finding{
		{ID: "f1", Title: "Itself", Created: now.Add(-10 * time.Minute), Entities: map[string]any{"user": "alice"}},
		{ID: "later", Title: "Later", Created: now.Add(48 * time.Hour), Entities: map[string]any{"user": "alice"}},
	} {
		if err := fs.Create(ctx, f); err != nil {
			t.Fatal(err)
		}
	}

	var timeline, evidence []string
	for i := range maxTimelineRows + 1 {
		timeline = append(timeline, fmt.Sprintf(`{"time":"2026-10-13T10:%02d:00Z","text":"event %d"}`, 59-i, i))
	}
	timeline = append(timeline, `{"time":"x","text":" "}`)
	for i := range 13 {
		evidence = append(evidence, fmt.Sprintf(`{"text":"fact %d","steps":[1,1,2]}`, i))
	}
	evidence = append(evidence, `{"text":""}`)
	verdict := `{"verdict":"Malicious","confidence":"very","summary":"masked-user-1 logged on oddly",` +
		`"timeline":[` + strings.Join(timeline, ",") + `],"evidence":[` + strings.Join(evidence, ",") + `],` +
		`"actions":[{"action":"block_ip","target":"not-an-ip"},{"action":"block_ip","target":"10.1.2.3"},{"action":"block_ip","target":"10.9.9.9"},` +
		`{"action":"disable_user","target":"\"masked-user-1\"","reason":"stop masked-user-1"},{"action":"isolate","target":"WEB-01"},` +
		`{"action":"disable_user","target":"masked-user-2"},{"action":"disable_user","target":"alice"}],` +
		`"next_steps":["Call masked-user-1", " "]}`
	model := &scripted{replies: []string{
		"I think it is fine.",
		`{"searches":[{"why":"","query":" "},{"why":"fails","query":"boom"},` +
			`{"why":"by stand-in","query":"user IN (masked-user-1) OR NOT src=10.1.2.3 | where user=\"masked-user-1\" OR src=10.1.2.3","earliest":"2026-10-20T00:00:00Z","latest":"2026-10-01T00:00:00Z"}]}`,
		`{"searches":[{"why":"a long one","query":"masked-user-1","earliest":"2000-01-01T00:00:00Z","latest":"2026-10-01T00:00:00Z"}]}`,
		`{}`,
		verdict,
	}}
	sr := &manyRows{}
	inv := &Investigator{Model: model, Search: sr, Findings: fs, Intel: is, Mask: []string{"user"},
		Actions: []respond.Info{
			{Name: "block_ip", Label: "Block", Target: respond.TargetIP, Disruptive: true, What: "Block {target}"},
			{Name: "disable_user", Label: "Disable", Target: respond.TargetUser, Disruptive: true, What: "Disable {target}"},
			{Name: "isolate", Label: "Isolate", Target: respond.TargetHost, Disruptive: true, What: "Isolate {target}"},
		}}
	res, err := inv.Run(ctx, richFinding(), nil)
	if err != nil {
		t.Fatal(err)
	}

	first := model.got[0][0].Content
	for _, want := range []string{"Description: Logons from a new place.", "Urgency (severity adjusted", "MITRE ATT&CK: T1078",
		"Context for user: priority high; business unit sales; category vip; on the watchlist", "Analyst notes so far:", "matched; the first 10 rows"} {
		if !strings.Contains(first, want) {
			t.Errorf("first message lacks %q", want)
		}
	}
	if strings.Contains(first, "alice") {
		t.Error("a masked value was sent")
	}
	if !strings.Contains(model.got[1][len(model.got[1])-1].Content, "not one JSON object") {
		t.Errorf("no retry: %s", model.got[1][len(model.got[1])-1].Content)
	}

	byKind := map[string][]Step{}
	for _, st := range res.Steps {
		byKind[st.Kind] = append(byKind[st.Kind], st)
	}
	if in := byKind["intel"]; len(in) != 1 || in[0].Matched != int64(RowsSent+1) || !in[0].More || len(in[0].Rows) != RowsSent {
		t.Errorf("intel = %+v", in)
	}
	// The newest are asked for: one is the finding itself, one is from
	// after the period.
	if rel := byKind["findings"]; len(rel) != 1 || rel[0].Matched != int64(maxRelated-1) || rel[0].More || len(rel[0].Rows) != maxRelated-1 {
		t.Errorf("related = %+v", rel)
	} else if ents := rel[0].Rows[0]["entities"].(map[string]any); ents["user"] != "masked-user-1" || ents["risk_object_type"] != nil {
		t.Errorf("related entities = %v", ents)
	}
	var ai []Step
	for _, st := range byKind["search"] {
		if st.By == "ai" {
			ai = append(ai, st)
		}
		if st.Error == "" && st.By == "signalith" && st.Title == "Events behind the finding" {
			row := st.Rows[0]
			if !strings.HasSuffix(row["_raw"].(string), "…") || len(row["_raw"].(string)) > MaxRawLen+4 || !strings.HasSuffix(row["note"].(string), "…") {
				t.Errorf("not trimmed: %v", row)
			}
		}
	}
	if len(ai) != 4 || ai[0].Error != "no query was given" || ai[0].Title != "A search the AI model asked for" ||
		ai[1].Error != "index missing" || ai[2].Error != "" {
		t.Fatalf("ai steps = %+v", ai)
	}
	// Times that end before they start are the default range; a range
	// longer than the most is cut.
	if e, err := time.Parse(time.RFC3339, ai[2].Earliest); err != nil || e.Sub(now.Add(-historyBefore)).Abs() > time.Minute {
		t.Errorf("reversed range = %s..%s", ai[2].Earliest, ai[2].Latest)
	}
	if !strings.Contains(ai[2].Query, "alice") || strings.Contains(ai[2].Query, "masked") {
		t.Errorf("stand-ins not revealed: %s", ai[2].Query)
	}
	if ai[3].Latest != "2026-10-01T00:00:00Z" || ai[3].Earliest != stamp(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Add(-MaxSpan)) {
		t.Errorf("long range = %s..%s", ai[3].Earliest, ai[3].Latest)
	}

	if res.Verdict != VerdictReal || res.Confidence != "low" || res.Summary != "alice logged on oddly" {
		t.Errorf("verdict = %s %s %q", res.Verdict, res.Confidence, res.Summary)
	}
	if len(res.Timeline) != maxTimelineRows || res.Timeline[0].Time > res.Timeline[1].Time {
		t.Errorf("timeline = %d %+v", len(res.Timeline), res.Timeline[:2])
	}
	if len(res.Evidence) != 12 || len(res.Evidence[0].Steps) != 2 {
		t.Errorf("evidence = %d %+v", len(res.Evidence), res.Evidence[0])
	}
	var acts []string
	for _, a := range res.Actions {
		acts = append(acts, a.Action+":"+a.Target)
	}
	if strings.Join(acts, ",") != "block_ip:10.1.2.3,disable_user:alice,isolate:web-01,disable_user:bob,disable_user:alice" {
		t.Errorf("actions = %v", acts)
	}
	if len(res.NextSteps) != 1 || res.NextSteps[0] != "Call alice" {
		t.Errorf("next steps = %v", res.NextSteps)
	}
}

func TestRunFailures(t *testing.T) {
	ctx := context.Background()
	f := testFinding()
	boom := errors.New("model down")
	if _, err := (&Investigator{Model: &scripted{err: boom}, Search: &fakeSearch{}}).Run(ctx, f, nil); !errors.Is(err, boom) {
		t.Errorf("model error = %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := (&Investigator{Model: &scripted{}, Search: &fakeSearch{}}).Run(cctx, f, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled = %v", err)
	}
	words := &scripted{replies: []string{"a", "b", "c", "d", "e", "f"}}
	if _, err := (&Investigator{Model: words, Search: &fakeSearch{}}).Run(ctx, f, nil); err == nil || !strings.Contains(err.Error(), "expected form") {
		t.Errorf("never JSON = %v", err)
	}
	if _, err := (&Investigator{Model: &scripted{}, Search: &fakeSearch{}}).Run(ctx, f, nil); err == nil || !strings.Contains(err.Error(), "no verdict") {
		t.Errorf("no verdict = %v", err)
	}
	for in, want := range map[string]string{"false_positive": VerdictBenign, "likely_real": VerdictReal, "perhaps": VerdictUnsure, "BENIGN": VerdictBenign} {
		res, err := (&Investigator{Model: &scripted{replies: []string{`{"verdict":"` + in + `","confidence":"High"}`}}, Search: &fakeSearch{}}).Run(ctx, f, nil)
		if err != nil || res.Verdict != want || res.Confidence != "high" {
			t.Errorf("%s = %+v %v", in, res, err)
		}
	}
}

func TestRelatedFindingsFail(t *testing.T) {
	inv := &Investigator{Model: &scripted{}, Search: &fakeSearch{}, Findings: failingFindings{findings.NewMemory()}}
	p, err := inv.Preview(context.Background(), testFinding())
	if err != nil {
		t.Fatal(err)
	}
	last := p.Steps[len(p.Steps)-1]
	if last.Kind != "findings" || last.Error != "store down" {
		t.Errorf("last step = %+v", last)
	}
	// No entities: no related findings are looked for.
	f := testFinding()
	f.Entities = map[string]any{"risk_object_type": "user"}
	p, _ = inv.Preview(context.Background(), f)
	for _, st := range p.Steps {
		if st.Kind == "findings" {
			t.Errorf("looked for related findings: %+v", st)
		}
	}
}

func TestRelatedFindingsMore(t *testing.T) {
	ctx := context.Background()
	fs := findings.NewMemory()
	for i := range maxRelated + 1 {
		if err := fs.Create(ctx, &findings.Finding{ID: fmt.Sprintf("r%02d", i), Created: testFinding().Created.Add(-time.Hour), Entities: map[string]any{"user": "alice"}}); err != nil {
			t.Fatal(err)
		}
	}
	p, err := (&Investigator{Model: &scripted{}, Search: &fakeSearch{}, Findings: fs}).Preview(ctx, testFinding())
	if err != nil {
		t.Fatal(err)
	}
	last := p.Steps[len(p.Steps)-1]
	if last.Kind != "findings" || !last.More || last.Matched != int64(maxRelated+1) || len(last.Rows) != maxRelated {
		t.Errorf("related = %+v", last)
	}
}

type failingFindings struct{ *findings.Memory }

func (failingFindings) Search(context.Context, findings.Filter) ([]*findings.Finding, int, error) {
	return nil, 0, errors.New("store down")
}

func TestMaskerMore(t *testing.T) {
	m := NewMasker([]string{" ", "_raw", "user", "!!"})
	if !m.DropsRaw() || m.Fields()[len(m.Fields())-1] != "_raw" {
		t.Errorf("fields = %v", m.Fields())
	}
	if got := m.Value("user", []string{"a1", ""}); fmt.Sprint(got) != "[masked-user-1 ]" {
		t.Errorf("list = %v", got)
	}
	if got := m.Value("!!", "x"); got != "masked-value-1" {
		t.Errorf("odd field = %v", got)
	}
	if kindOf("!!") != "value" || quote(`a"b`) != `"a\"b"` {
		t.Error("kindOf / quote")
	}
	// Text with only short values masked stays as it is.
	short := NewMasker([]string{"user"})
	short.Value("user", "a")
	if short.Text("a b c") != "a b c" {
		t.Error("a short value was masked in text")
	}
	if got := cut("aé", 2); got != "a" {
		t.Errorf("cut = %q", got)
	}
	if compact(map[string]any{"c": make(chan int)}) == "" {
		t.Error("compact")
	}
	if err := decode("no braces", &reply{}); err == nil {
		t.Error("decode")
	}
}

func TestGuardMore(t *testing.T) {
	m := NewMasker([]string{"user"})
	m.Value("user", "alice")
	for src, ok := range map[string]bool{
		`user=masked-user-1 OR src=1.2.3.4`:          true,
		`user=adm* OR src=1.2.3.4`:                   false,
		`NOT (src=1 OR user=bob)`:                    false,
		`* | where -len(user) < 3`:                   false,
		`* | where len(src) > 3`:                     true,
		`masked-user-1 | where user="masked-user-1"`: true,
		`* | eval x=1`:                               false,
	} {
		q, err := query.Parse(src)
		if err != nil {
			t.Errorf("%s: %v", src, err)
			continue
		}
		if err := guardQuery(q, m); (err == nil) != ok {
			t.Errorf("%s: %v, want ok %v", src, err, ok)
		}
	}
	q, _ := query.Parse(`masked-user-1 NOT user=masked-user-1 | where user IN (masked-user-1)`)
	m.revealQuery(q)
	if s := q.String(); strings.Contains(s, "masked") {
		t.Errorf("revealed = %s", s)
	}
	if !asciiEqualFold("ABC", "abc") || asciiEqualFold("ab", "abc") {
		t.Error("asciiEqualFold")
	}
	r := &run{f: &findings.Finding{Entities: map[string]any{"src": []any{"10.0.0.1", 3}}}, mask: m}
	if s, ok := r.evidenceValue(respond.TargetIP, "10.0.0.01"); ok {
		t.Errorf("a bad address matched %q", s)
	}
	if s, ok := r.evidenceValue(respond.TargetIP, "::ffff:10.0.0.1"); ok {
		t.Errorf("a mapped address matched %q", s)
	}
	if _, ok := r.evidenceValue(respond.TargetIP, " "); ok {
		t.Error("an empty target matched")
	}
	r.f.Entities["src"] = []string{"10.0.0.2"}
	if s, ok := r.evidenceValue(respond.TargetIP, "10.0.0.2"); !ok || s != "10.0.0.2" {
		t.Errorf("a list of strings = %q %v", s, ok)
	}
}
