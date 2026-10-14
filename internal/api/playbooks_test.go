package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/playbooks"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// countingSender counts the messages sent through it.
type countingSender struct{ n atomic.Int32 }

func (c *countingSender) Send(context.Context, notify.Channel, notify.Message) error {
	c.n.Add(1)
	return nil
}

func TestPlaybooksFlow(t *testing.T) {
	var blocks atomic.Int32
	fw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		blocks.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(fw.Close)
	sender := &countingSender{}
	runs := playbooks.NewMemory()
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		srv = s
		s.Users = users.NewMemory()
		for name, role := range map[string]users.Role{"vera": users.Viewer, "andy": users.Analyst, "bea": users.Analyst} {
			if _, err := s.Users.Create(context.Background(), users.NewUser{Username: name, Role: role, Password: "role-password"}); err != nil {
				t.Fatal(err)
			}
		}
		actions := &respond.Actions{}
		if err := actions.Save([]respond.Connector{{Name: "block", Label: "Block IP", Kind: respond.KindHTTP, Target: respond.TargetIP,
			Method: "POST", AllowLoopback: true, URL: fw.URL + "/block/{{.ip}}"}}); err != nil {
			t.Fatal(err)
		}
		s.Respond = &respond.Runner{Actions: actions, Store: &respond.Memory{}, Log: s.Log}
		notes := &notify.Manager{}
		if _, err := notes.Save(notify.Input{Channels: []notify.ChannelInput{{ID: "soc", Name: "#soc", Type: "slack", URL: "https://hooks.slack.com/services/T/B/x"}}}); err != nil {
			t.Fatal(err)
		}
		s.Notify = &Notify{Settings: notes, Sender: sender}
		s.Playbooks = &Playbooks{Manager: &playbooks.Manager{File: filepath.Join(t.TempDir(), "playbooks.yaml")}, Runs: runs}
	})
	ctx := t.Context()

	// Only admins see and change playbooks.
	save := `{"playbooks":[{"id":"bf","name":"Brute force response","enabled":true,"approval_channel":"soc",
		"trigger":{"detections":["brute-force"],"min_urgency":"high"},
		"steps":[{"kind":"notify","channel":"soc"},{"kind":"action","action":"block","target":"src"},
		         {"kind":"open_case","title":"Brute force from {src}"}]}]}`
	if code, _ := doAs(t, ts, "andy", "role-password", "PUT", "/api/playbooks", save); code != 403 {
		t.Errorf("analyst PUT = %d", code)
	}
	if code, _ := doAs(t, ts, "andy", "role-password", "GET", "/api/playbooks", ""); code != 403 {
		t.Errorf("analyst GET = %d", code)
	}
	code, body := do(t, ts, "PUT", "/api/playbooks", save, true)
	if code != 200 {
		t.Fatalf("save = %d %v", code, body)
	}
	pb := body["playbooks"].([]any)[0].(map[string]any)
	if pb["summary"] != "When brute-force fires at high or above: notify Slack #soc, then block IP for the source IP after approval, then open a case." ||
		pb["steps"].([]any)[1].(map[string]any)["needs_approval"] != true || body["manage"] != true || len(body["actions"].([]any)) != 1 {
		t.Errorf("view %v", body)
	}
	code, body = do(t, ts, "PUT", "/api/playbooks", `{"playbooks":[{"name":"x","enabled":true,"steps":[{"kind":"notify","channel":"nope"}]}]}`, true)
	if code != 400 || body["problems"].([]any)[0].(map[string]any)["field"] != "steps[0].channel" {
		t.Errorf("bad save = %d %v", code, body)
	}

	// A finding starts it on the server that runs the jobs.
	runner := &playbooks.Runner{Playbooks: srv.Playbooks.Manager, Findings: srv.Findings, Runs: runs, Desk: srv.PlaybookDesk(),
		Respond: srv.Respond, Notify: srv.Notify.Settings, Sender: sender, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, id := range []string{"F-1", "F-2"} {
		f := &findings.Finding{ID: id, DetectionID: "brute-force", Title: "Brute force", Severity: "high", Status: findings.StatusNew,
			Created: time.Now().UTC().Add(time.Second), Entities: map[string]any{"src": "203.0.113.7"}}
		if err := srv.Findings.Create(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	runner.Pass(ctx)
	if blocks.Load() != 0 || sender.n.Load() != 4 {
		t.Fatalf("blocks %d sent %d", blocks.Load(), sender.n.Load())
	}

	// Analysts see what waits; viewers do not.
	if code, _ := doAs(t, ts, "vera", "role-password", "GET", "/api/playbooks/runs?status=waiting_approval", ""); code != 403 {
		t.Errorf("viewer runs = %d", code)
	}
	code, body = doAs(t, ts, "andy", "role-password", "GET", "/api/playbooks/runs?status=waiting_approval", "")
	if code != 200 || body["waiting"] != float64(2) || len(body["runs"].([]any)) != 2 {
		t.Fatalf("runs = %d %v", code, body)
	}
	what := body["runs"].([]any)[0].(map[string]any)["approval"].(map[string]any)["what"].(string)
	if !strings.HasPrefix(what, "Send POST to 127.0.0.1:") || !strings.HasSuffix(what, " for 203.0.113.7.") {
		t.Errorf("what %q", what)
	}
	if code, _ := doAs(t, ts, "andy", "role-password", "GET", "/api/playbooks/runs?status=nope", ""); code != 400 {
		t.Errorf("bad status = %d", code)
	}
	if code, _ := doAs(t, ts, "vera", "role-password", "POST", "/api/playbooks/runs/x/approve", ""); code != 403 {
		t.Errorf("viewer approve = %d", code)
	}
	id1, id2 := playbooks.RunID("F-1", "bf"), playbooks.RunID("F-2", "bf")
	if code, body := doAs(t, ts, "andy", "role-password", "POST", "/api/playbooks/runs/"+id1+"/approve", `{"note":"confirmed with the user"}`); code != 200 || body["status"] != "approved" {
		t.Fatalf("approve = %d %v", code, body)
	}
	code, body = doAs(t, ts, "bea", "role-password", "POST", "/api/playbooks/runs/"+id1+"/approve", "")
	if code != 409 || body["error"] != "It was already approved by andy." || body["code"] != "decided" {
		t.Errorf("second approve = %d %v", code, body)
	}
	if code, body := doAs(t, ts, "bea", "role-password", "POST", "/api/playbooks/runs/"+id2+"/reject", `{"note":"pentest"}`); code != 200 || body["status"] != "rejected" {
		t.Fatalf("reject = %d %v", code, body)
	}
	if code, _ := doAs(t, ts, "bea", "role-password", "POST", "/api/playbooks/runs/nope/approve", ""); code != 404 {
		t.Errorf("missing run = %d", code)
	}

	// The jobs server goes on with the approved run only.
	runner.Pass(ctx)
	if blocks.Load() != 1 {
		t.Fatalf("blocks %d", blocks.Load())
	}
	st, _ := runs.Get(ctx, id1)
	if st.Status != playbooks.StatusSucceeded || st.CaseID == "" {
		t.Fatalf("run %+v", st.Run)
	}
	c, err := srv.Cases.Get(ctx, st.CaseID)
	if err != nil || c.Title != "Brute force from 203.0.113.7" || len(c.Findings) != 1 || c.CreatedBy != "playbook Brute force response" {
		t.Fatalf("case %+v %v", c, err)
	}
	f1, _ := srv.Findings.Get(ctx, "F-1")
	f2, _ := srv.Findings.Get(ctx, "F-2")
	all := func(f *findings.Finding) string {
		var b strings.Builder
		for _, c := range f.Comments {
			b.WriteString(c.Author + ": " + c.Text + "\n")
		}
		return b.String()
	}
	if s := all(f1); !strings.Contains(s, "Approved by andy") || !strings.Contains(s, "playbook Brute force response: Opened case") {
		t.Errorf("F-1 comments:\n%s", s)
	}
	if s := all(f2); !strings.Contains(s, "bea: bea rejected: Send POST") || !strings.Contains(s, "Note: pentest") {
		t.Errorf("F-2 comments:\n%s", s)
	}
}

func TestPlaybooksOff(t *testing.T) {
	ts, _ := newTestServerWith(t, nil)
	if code, _ := do(t, ts, "GET", "/api/playbooks", "", true); code != 503 {
		t.Errorf("GET = %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/playbooks/runs", "", true); code != 503 {
		t.Errorf("runs = %d", code)
	}
}
