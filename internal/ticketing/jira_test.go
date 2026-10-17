package ticketing

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cases"
)

func jiraCloudConn(f *fakeJira) Connection {
	return Connection{ID: "jc", Name: "SOC", Type: TypeJira, URL: f.URL(), Auth: AuthCloud,
		Email: "bot@example.com", Token: "jira-api-token-123456", Project: "SEC", IssueType: "Task",
		SetPriority: true, SyncNotes: true, SyncStatus: true, AllowLoopback: true, CAPEM: f.caPEM()}
}

func jiraDCConn(f *fakeJira) Connection {
	return Connection{ID: "dc", Name: "Jira DC", Type: TypeJira, URL: f.URL(), Auth: AuthBearer,
		Token: "dc-personal-access-token", Project: "SEC", IssueType: "Task",
		SetPriority: true, SyncNotes: true, SyncStatus: true, AllowLoopback: true, CAPEM: f.caPEM(),
		Statuses: map[string]string{"pending": "Waiting for customer"}}
}

// commentTexts returns an issue's comments as "author: text".
func commentTexts(i fakeIssue) []string {
	var out []string
	for _, c := range i.comments {
		raw, _ := json.Marshal(c.body)
		out = append(out, c.author+": "+bodyText(raw))
	}
	return out
}

func TestJiraCloudSyncBothWays(t *testing.T) {
	f := newFakeJira(t, true, basic("bot@example.com", "jira-api-token-123456"))
	e := newEnv(t, jiraCloudConn(f))
	ctx := context.Background()
	e.newCase("case-1", "Brute force on host-7", "high")
	e.note("case-1", "Written before the ticket")

	l, err := e.svc.Create(ctx, "case-1", "jc", "ann")
	if err != nil {
		t.Fatal(err)
	}
	if l.Key != "SEC-1" || l.URL != f.URL()+"/browse/SEC-1" || l.RemoteStatus.Name != "To Do" {
		t.Fatalf("link %+v", l)
	}
	is := f.issue("SEC-1")
	desc, _ := json.Marshal(is.description)
	if is.summary != "Brute force on host-7" || is.priority != "High" || is.issueType != "Task" {
		t.Errorf("issue %+v", is)
	}
	if !strings.Contains(string(desc), `"type":"doc"`) || !strings.Contains(string(desc), "https://siem.example.com/#cases?id=case-1") || !strings.Contains(bodyText(desc), "Suspicious logons on host-7.") {
		t.Errorf("description %s", desc)
	}
	c := e.getCase("case-1")
	if tk, ok := c.Ticket("jc"); !ok || tk.Key != "SEC-1" || tk.CreatedBy != "ann" {
		t.Errorf("case tickets %+v", c.Tickets)
	}
	if h := c.History[len(c.History)-1]; h.Field != "ticket" || h.To != "Jira SEC-1" {
		t.Errorf("history %+v", h)
	}
	if _, err := e.svc.Create(ctx, "case-1", "jc", "ann"); err == nil {
		t.Error("a second ticket opens for the same case and connection")
	}

	// The first pass sees the ticket agrees with the new case: nothing
	// moves, and the note written before the ticket is not sent.
	e.pass()
	if f.count("POST /rest/api/3/issue/SEC-1/transitions") != 0 || len(f.issue("SEC-1").comments) != 0 {
		t.Fatalf("first pass changed the ticket: %v", f.requests())
	}

	// From Jira: a comment and a new status.
	f.humanComment("SEC-1", "Dana Scully", "Found the host\nIt is patched")
	f.humanStatus("SEC-1", "In Progress")
	e.pass()
	c = e.getCase("case-1")
	if c.Status != "in_progress" {
		t.Errorf("case status %s", c.Status)
	}
	if n := notesOf(c); !slices.Contains(n, "jira:Dana Scully: Found the host\nIt is patched") {
		t.Errorf("case notes %q", n)
	}
	if len(f.issue("SEC-1").comments) != 1 || f.count("POST /rest/api/3/issue/SEC-1/transitions") != 0 {
		t.Errorf("the imported comment or status echoed back: %q", commentTexts(f.issue("SEC-1")))
	}

	// From the case: a note, and resolved with a resolution.
	e.note("case-1", "Isolated the host")
	e.change("case-1", cases.Update{Status: ptr("resolved"), Resolution: ptr("Reimaged host-7")})
	e.pass()
	is = f.issue("SEC-1")
	if is.status != "Done" {
		t.Errorf("issue status %s", is.status)
	}
	want := []string{"Dana Scully: Found the host\nIt is patched", "Signalith Bot: [Signalith] The case was resolved: Reimaged host-7", "Signalith Bot: [Signalith] ann: Isolated the host"}
	if got := commentTexts(is); !slices.Equal(got, want) {
		t.Errorf("comments\n%q\nwant\n%q", got, want)
	}
	for _, cm := range is.comments[1:] {
		if d, ok := cm.body.(map[string]any); !ok || d["type"] != "doc" {
			t.Errorf("comment body is not ADF: %#v", cm.body)
		}
	}

	// The next pass takes none of Signalith's own comments back.
	before := len(e.getCase("case-1").Entries)
	e.pass()
	e.pass()
	if after := len(e.getCase("case-1").Entries); after != before || len(f.issue("SEC-1").comments) != 3 {
		t.Errorf("echo: entries %d to %d, comments %q", before, after, commentTexts(f.issue("SEC-1")))
	}
	if st := e.link("jc", "case-1"); st.Error != "" || st.CaseStatus != "resolved" || st.RemoteStatus.Name != "Done" {
		t.Errorf("link %+v", st.Link)
	}

	// Title and severity go to the summary and priority.
	e.change("case-1", cases.Update{Title: ptr("Brute force, confirmed"), Severity: ptr("critical")})
	e.pass()
	if is := f.issue("SEC-1"); is.summary != "Brute force, confirmed" || is.priority != "Highest" {
		t.Errorf("issue after the case's title changed: %+v", is)
	}

	// Both change in one pass: the case wins and the ticket moves back.
	f.humanStatus("SEC-1", "In Progress")
	e.change("case-1", cases.Update{Status: ptr("closed")})
	e.pass()
	if c, is := e.getCase("case-1"), f.issue("SEC-1"); c.Status != "closed" || jiraStatuses[is.status] != "done" {
		t.Errorf("conflict: case %s, issue %s", c.Status, is.status)
	}

	for _, r := range f.requests() {
		if !strings.Contains(r, "/rest/api/3/") {
			t.Errorf("cloud request not on API version 3: %s", r)
		}
	}
}

func TestJiraDataCenter(t *testing.T) {
	f := newFakeJira(t, false, "Bearer dc-personal-access-token")
	f.pageSize = 1
	f.noPriority = true
	e := newEnv(t, jiraDCConn(f))
	ctx := context.Background()
	e.newCase("case-1", "First", "medium")
	e.newCase("case-2", "Second", "low")
	if _, err := e.svc.Create(ctx, "case-1", "dc", "ann"); err != nil {
		t.Fatal(err)
	}
	// The priority field is not on the screen: the issue is made without
	// it, and the next one does not try.
	if _, err := e.svc.Create(ctx, "case-2", "dc", "ann"); err != nil {
		t.Fatal(err)
	}
	if n := f.count("POST /rest/api/2/issue"); n != 3 {
		t.Errorf("%d creates, want 3 (one refused for its priority): %v", n, f.requests())
	}
	is := f.issue("SEC-1")
	if d, ok := is.description.(string); !ok || !strings.Contains(d, "Opened from Signalith case case-1.") || !strings.Contains(d, "#cases?id=case-1") {
		t.Errorf("description %#v", is.description)
	}

	e.pass() // full: pages through the search one issue at a time
	if n := f.count("POST /rest/api/2/search"); n != 2 {
		t.Errorf("%d searches, want 2 pages", n)
	}

	// A status mapped by name.
	f.humanStatus("SEC-2", "Waiting for customer")
	f.humanComment("SEC-2", "jdoe", "Asked the user")
	e.pass()
	if c := e.getCase("case-2"); c.Status != "pending" || !slices.Contains(notesOf(c), "jira:jdoe: Asked the user") {
		t.Errorf("case-2 %s %q", c.Status, notesOf(c))
	}
	e.change("case-1", cases.Update{Status: ptr("pending")})
	e.note("case-1", "Waiting on the owner")
	e.pass()
	if is := f.issue("SEC-1"); is.status != "Waiting for customer" || len(is.comments) != 1 || is.comments[0].body != "[Signalith] ann: Waiting on the owner" {
		t.Errorf("issue %+v", is)
	}
	// Incremental polls ask by a relative time, which needs no time zone.
	if j := f.lastJQL[len(f.lastJQL)-1]; !strings.Contains(j, `updated >= "-`) {
		t.Errorf("JQL %s", j)
	}

	// A deleted issue: the search fails, each is read, the link is gone,
	// and a new ticket may be opened.
	f.delete("SEC-1")
	e.clk.add(fullEvery)
	e.pass()
	if st := e.link("dc", "case-1"); st.State != StateGone || st.Active || !strings.Contains(st.Error, "deleted") {
		t.Fatalf("link of a deleted issue %+v", st.Link)
	}
	l, err := e.svc.Create(ctx, "case-1", "dc", "ann")
	if err != nil || l.Key != "SEC-3" {
		t.Fatalf("new ticket after delete: %+v %v", l, err)
	}
	if c := e.getCase("case-1"); len(c.Tickets) != 1 || c.Tickets[0].Key != "SEC-3" {
		t.Errorf("case tickets %+v", c.Tickets)
	}
	for _, r := range f.requests() {
		if strings.Contains(r, "/rest/api/3/") {
			t.Errorf("data center request on API version 3: %s", r)
		}
	}
}

func TestJiraWorkflowWithoutTransition(t *testing.T) {
	f := newFakeJira(t, true, basic("bot@example.com", "jira-api-token-123456"))
	conn := jiraCloudConn(f)
	conn.Statuses = map[string]string{"pending": "Blocked"}
	e := newEnv(t, conn)
	e.newCase("case-1", "x", "high")
	if _, err := e.svc.Create(context.Background(), "case-1", "jc", "ann"); err != nil {
		t.Fatal(err)
	}
	e.pass()
	e.change("case-1", cases.Update{Status: ptr("pending")})
	e.pass()
	st := e.link("jc", "case-1")
	if !strings.Contains(st.Error, "no transition") || st.CaseStatus != "pending" {
		t.Errorf("link %+v", st.Link)
	}
	// It is not tried again until the case changes.
	n := f.count("GET /rest/api/3/issue/SEC-1/transitions")
	e.pass()
	if f.count("GET /rest/api/3/issue/SEC-1/transitions") != n {
		t.Error("a transition the workflow lacks is tried on every pass")
	}
}

func TestJiraTest(t *testing.T) {
	f := newFakeJira(t, true, basic("bot@example.com", "jira-api-token-123456"))
	e := newEnv(t)
	conn := jiraCloudConn(f)
	msg, err := e.svc.Test(context.Background(), conn)
	if err != nil || !strings.Contains(msg, "Signed in as Signalith Bot") || !strings.Contains(msg, "Task can be created") {
		t.Errorf("test: %q %v", msg, err)
	}
	conn.Project = "NOPE"
	if _, err := e.svc.Test(context.Background(), conn); err == nil || !strings.Contains(err.Error(), "no project NOPE") {
		t.Errorf("missing project: %v", err)
	}
	conn.Project, conn.IssueType = "SEC", "Bug"
	if _, err := e.svc.Test(context.Background(), conn); err == nil || !strings.Contains(err.Error(), "no issue type Bug") {
		t.Errorf("missing issue type: %v", err)
	}
}
