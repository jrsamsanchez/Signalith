package investigate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/search"
)

type fakeSearch struct{ ran []*query.Query }

func (f *fakeSearch) Execute(_ context.Context, q *query.Query) (*search.Result, error) {
	f.ran = append(f.ran, q)
	return &search.Result{Kind: "events", Columns: []string{"user", "src", "_raw"}, Matched: 2, Rows: []search.Row{
		{"user": "alice", "src": "10.1.2.3", "password": "hunter22", "_raw": "logon by alice from 10.1.2.3 password=hunter22"},
		{"user": "bob", "src": "10.1.2.3", "_raw": "logon by bob"},
	}}, nil
}

type fakeModel struct {
	replies []string
	got     [][]assistant.Message
}

func (m *fakeModel) Name() string { return "test-model" }
func (m *fakeModel) Chat(_ context.Context, system string, msgs []assistant.Message, _ int) (string, error) {
	m.got = append(m.got, append([]assistant.Message{{Role: "system", Content: system}}, msgs...))
	r := m.replies[0]
	m.replies = m.replies[1:]
	return r, nil
}

func testFinding() *findings.Finding {
	return &findings.Finding{ID: "f1", Title: "Brute force then success", DetectionID: "auth_bruteforce", Severity: "high",
		Entities: map[string]any{"user": "alice", "src": "10.1.2.3"},
		Result:   map[string]any{"user": "alice", "src": "10.1.2.3", "count": 40},
		Query:    "datamodel=Authentication user=alice", Earliest: "2026-10-13T10:00:00Z", Latest: "2026-10-13T11:00:00Z",
		Created: time.Date(2026, 10, 13, 11, 0, 0, 0, time.UTC)}
}

func TestMaskerStandIns(t *testing.T) {
	m := NewMasker([]string{"user", "_raw"})
	row := m.Row(map[string]any{"user": "Alice", "src": "10.1.2.3", "_raw": "secret text", "api_token": "abc123", "count": 3})
	if row["user"] != "masked-user-1" || row["api_token"] != "masked-api-token-1" || row["src"] != "10.1.2.3" || row["count"] != 3 {
		t.Fatalf("row %v", row)
	}
	if _, ok := row["_raw"]; ok {
		t.Error("_raw was kept although it is masked")
	}
	if got := m.Value("user", "alice"); got != "masked-user-1" {
		t.Errorf("the same value in another case got %v", got)
	}
	if got := m.Text("ALICE logged on; masked-user-1 stays"); got != "masked-user-1 logged on; masked-user-1 stays" {
		t.Errorf("text %q", got)
	}
	if got := m.Query(`user=masked-user-1 OR src_user="masked-user-1"`); got != `user="Alice" OR src_user="Alice"` {
		t.Errorf("query %q", got)
	}
	if got := m.Reveal("masked-user-1 and masked-host-9"); got != "Alice and masked-host-9" {
		t.Errorf("reveal %q", got)
	}
}

func TestMaskerShortValueInsideStandIn(t *testing.T) {
	m := NewMasker([]string{"user"})
	m.Value("user", "user")
	if got := m.Text("user masked-user-1"); got != "masked-user-1 masked-user-1" {
		t.Errorf("text %q", got)
	}
}

func TestRunMasksAndFollowsUp(t *testing.T) {
	s := &fakeSearch{}
	m := &fakeModel{replies: []string{
		"```json\n{\"searches\":[{\"why\":\"other logons by this user\",\"query\":\"datamodel=Authentication user=masked-user-1 earliest=-1y\"}]}\n```",
		`{"verdict":"real","confidence":"high","summary":"masked-user-1 was brute forced.","timeline":[{"time":"2026-10-13T10:30:00Z","text":"40 failures"}],` +
			`"evidence":[{"text":"40 failures then a success","steps":[1,99]}],` +
			`"actions":[{"action":"disable_user","target":"masked-user-1","reason":"stop the attacker"},{"action":"made_up","target":"x"}],"next_steps":["Ask masked-user-1"]}`,
	}}
	inv := &Investigator{Model: m, Search: s, Mask: []string{"user"},
		Actions: []respond.Info{{Name: "disable_user", Label: "Disable AD user", Target: "user", What: "Disable {target}"}},
		Now:     func() time.Time { return time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC) }}
	var events []Event
	res, err := inv.Run(context.Background(), testFinding(), func(e Event) { events = append(events, e) })
	if err != nil {
		t.Fatal(err)
	}
	for _, conv := range m.got {
		for _, msg := range conv {
			if msg.Role != "user" { // the system prompt is fixed text
				continue
			}
			for _, secret := range []string{"alice", "Alice", "hunter22"} {
				if strings.Contains(msg.Content, secret) {
					t.Errorf("%q was sent:\n%s", secret, msg.Content)
				}
			}
		}
	}
	last := s.ran[len(s.ran)-1]
	if !strings.Contains(last.String(), `user=alice`) || strings.Contains(last.String(), "masked") {
		t.Errorf("the follow-up search ran as %q", last.String())
	}
	if last.Earliest != "2026-10-06T11:00:00Z" || last.Latest != "2026-10-14T00:00:00Z" {
		t.Errorf("the follow-up search covered %s to %s", last.Earliest, last.Latest)
	}
	if res.Verdict != VerdictReal || res.Summary != "alice was brute forced." || len(res.Actions) != 1 ||
		res.Actions[0].Target != "alice" || res.Actions[0].Label != "Disable AD user" || res.NextSteps[0] != "Ask alice" {
		t.Errorf("result %+v", res)
	}
	if len(res.Evidence) != 1 || len(res.Evidence[0].Steps) != 1 {
		t.Errorf("evidence %+v", res.Evidence)
	}
	ai := res.Steps[len(res.Steps)-1]
	if ai.By != "ai" || ai.Why != "other logons by this user" {
		t.Errorf("last step %+v", ai)
	}
	steps := 0
	for _, e := range events {
		if e.Type == "step" {
			steps++
		}
	}
	if steps != len(res.Steps) {
		t.Errorf("%d step events for %d steps", steps, len(res.Steps))
	}
}

func TestRunStopsAskingForSearches(t *testing.T) {
	ask := `{"searches":[{"query":"user=x"},{"query":"user=y"},{"query":"user=z"},{"query":"user=w"}]}`
	m := &fakeModel{replies: []string{ask, ask, ask, ask, `{"verdict":"maybe"}`}}
	inv := &Investigator{Model: m, Search: &fakeSearch{}}
	res, err := inv.Run(context.Background(), testFinding(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ai := 0
	for _, st := range res.Steps {
		if st.By == "ai" {
			ai++
		}
	}
	if ai != MaxSearches || res.Verdict != VerdictUnsure {
		t.Errorf("%d searches by the model, verdict %q", ai, res.Verdict)
	}
	if last := m.got[len(m.got)-1]; !strings.Contains(last[len(last)-1].Content, "give your verdict now") {
		t.Errorf("last message %q", last[len(last)-1].Content)
	}
}

func TestPreviewIsTheFirstMessage(t *testing.T) {
	m := &fakeModel{replies: []string{`{"verdict":"benign","summary":"ok"}`}}
	inv := &Investigator{Model: m, Search: &fakeSearch{}, Mask: []string{"src"}}
	p, err := inv.Preview(context.Background(), testFinding())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inv.Run(context.Background(), testFinding(), nil); err != nil {
		t.Fatal(err)
	}
	if p.Message != m.got[0][1].Content || p.System != m.got[0][0].Content {
		t.Error("the preview differs from what was sent")
	}
	if strings.Contains(p.Message, "10.1.2.3") || !strings.Contains(p.Message, "masked-src-1") {
		t.Errorf("preview:\n%s", p.Message)
	}
}
