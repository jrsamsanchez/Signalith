package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/ticketing"
)

// dueStore is a link store whose reads the test decides.
type dueStore struct {
	ticketing.Store
	due []ticketing.Stored
	err error
}

func (d *dueStore) Due(context.Context) ([]ticketing.Stored, error) { return d.due, d.err }

func (d *dueStore) ForCases(context.Context, []string) ([]ticketing.Stored, error) {
	return nil, d.err
}

// Without ticketing every route says so; bad bodies are 400s.
func TestTicketingRefusals(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, rt := range []struct{ method, path string }{
		{"GET", "/api/ticketing"}, {"PUT", "/api/ticketing"}, {"POST", "/api/ticketing/test"},
	} {
		if code, out := doAs(t, ts, "admin", "s3cret-pass", rt.method, rt.path, "{}"); code != http.StatusServiceUnavailable || out["error"] != errTicketingOff.Error() {
			t.Errorf("%s %s: %d %v", rt.method, rt.path, code, out)
		}
	}

	ts, srv, _ := newTicketingServer(t, nil)
	now := time.Now().UTC()
	if err := srv.Cases.Create(context.Background(), &cases.Case{ID: "case-1", Title: "x", Severity: "high", Status: "new", Created: now, Updated: now}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ method, path, body string }{
		{"PUT", "/api/ticketing", `{`},
		{"POST", "/api/ticketing/test", `{`},
		{"POST", "/api/cases/case-1/tickets", `{`},
		{"POST", "/api/cases/case-1/tickets", `{"connection":"  "}`},
	} {
		if code, _ := doAs(t, ts, "admin", "s3cret-pass", c.method, c.path, c.body); code != http.StatusBadRequest {
			t.Errorf("%s %s %s: %d", c.method, c.path, c.body, code)
		}
	}
	code, out := doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/ticketing/test", `{"connection":{"name":"x","type":"jira","url":"http://example.com"}}`)
	if code != http.StatusBadRequest || out["problems"] == nil {
		t.Errorf("bad connection: %d %v", code, out)
	}
}

// The page counts each connection's tickets and lists the failing ones,
// newest first; a store that cannot be read says so.
func TestTicketingViewLinks(t *testing.T) {
	links := &dueStore{Store: ticketing.NewMemory()}
	ts, _, svc := newTicketingServer(t, nil)
	save := `{"connections":[{"id":"desk","name":"Desk","type":"servicenow","url":"https://example.service-now.com","auth":"basic","username":"svc","password":"pw-123456"}]}`
	if code, body := doAs(t, ts, "admin", "s3cret-pass", "PUT", "/api/ticketing", save); code != http.StatusOK {
		t.Fatalf("save: %d %v", code, body)
	}
	svc.Links = links
	now := time.Now().Add(-time.Hour)
	links.due = []ticketing.Stored{
		{Link: ticketing.Link{CaseID: "c1", Connection: "desk", State: ticketing.StateLinked}},
		{Link: ticketing.Link{CaseID: "c2", Connection: "desk", State: ticketing.StateLinked, Error: "old", ErrorAt: now.Add(-time.Minute)}},
		{Link: ticketing.Link{CaseID: "c3", Connection: "desk", State: "failed", Error: "new", ErrorAt: now}},
	}
	code, body := doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/ticketing", "")
	if code != http.StatusOK {
		t.Fatalf("view: %d %v", code, body)
	}
	c := body["connections"].([]any)[0].(map[string]any)
	if c["tickets"] != float64(2) || c["failing"] != float64(2) {
		t.Errorf("counts %v", c)
	}
	probs := body["problems"].([]any)
	if len(probs) != 2 || probs[0].(map[string]any)["case_id"] != "c3" {
		t.Errorf("problems %v", probs)
	}
	links.due, links.err = nil, errDown
	code, body = doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/ticketing", "")
	if code != http.StatusOK || !strings.Contains(body["links_error"].(string), errDown.Error()) {
		t.Errorf("store down: %d %v", code, body)
	}
}

// Without ticketing a case still lists the tickets it holds; with it, a
// store that cannot be read says so and the case's own tickets show, and
// another server syncing them is named.
func TestCaseTicketsMore(t *testing.T) {
	now := time.Now().UTC()
	kase := &cases.Case{ID: "case-1", Title: "x", Severity: "high", Status: "new", Created: now, Updated: now,
		Tickets: []cases.Ticket{{Connection: "desk", System: "servicenow", Key: "INC0000001", URL: "javascript:alert(1)", Created: now}}}

	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) { srv = s })
	if err := srv.Cases.Create(context.Background(), kase); err != nil {
		t.Fatal(err)
	}
	code, body := doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/cases/case-1/tickets", "")
	tk, _ := body["tickets"].([]any)
	if code != http.StatusOK || body["available"] != false || len(tk) != 1 || tk[0].(map[string]any)["key"] != "INC0000001" {
		t.Fatalf("without ticketing: %d %v", code, body)
	}
	if _, ok := tk[0].(map[string]any)["url"]; ok {
		t.Errorf("a link that is not a web address is shown: %v", tk[0])
	}
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/cases/nope/tickets", ""); code != http.StatusNotFound {
		t.Errorf("unknown case: %d", code)
	}

	cl := &fakeCluster{}
	cl.set(false, "siem-b")
	ts, srv, svc := newTicketingServer(t, func(s *Server) { s.Cluster = cl })
	svc.Links = &dueStore{Store: ticketing.NewMemory(), err: errDown}
	if err := srv.Cases.Create(context.Background(), kase); err != nil {
		t.Fatal(err)
	}
	code, body = doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/cases/case-1/tickets", "")
	tk, _ = body["tickets"].([]any)
	if code != http.StatusOK || body["available"] != true || len(tk) != 1 || body["runs_on"] != "siem-b" ||
		!strings.Contains(body["links_error"].(string), errDown.Error()) || body["public_url_set"] != true {
		t.Errorf("store down: %d %v", code, body)
	}
}

// With the scheduler off the page says connections are set elsewhere,
// without naming a server.
func TestTicketingSchedulerOff(t *testing.T) {
	ts, _, _ := newTicketingServer(t, func(s *Server) { s.Config.Detections.Scheduler = false })
	code, body := doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/ticketing", "")
	if code != http.StatusOK || body["manage"] != false || body["runs_on"] != nil || !strings.Contains(body["manage_why"].(string), "detections.scheduler is off") {
		t.Errorf("view: %d %v", code, body)
	}
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/ticketing/test", `{"id":"desk"}`); code != http.StatusConflict {
		t.Errorf("test: %d", code)
	}
}
