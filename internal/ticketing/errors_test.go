// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/secrets"
)

func TestUnauthorizedIsScrubbed(t *testing.T) {
	f := newFakeJira(t, true, basic("bot@example.com", "jira-api-token-123456"))
	e := newEnv(t)
	conn := jiraCloudConn(f)
	conn.Token = "wrong-token-abcdef"
	_, err := e.svc.Test(context.Background(), conn)
	if err == nil {
		t.Fatal("a wrong token signs in")
	}
	wire := base64.StdEncoding.EncodeToString([]byte("bot@example.com:wrong-token-abcdef"))
	if msg := err.Error(); strings.Contains(msg, "wrong-token-abcdef") || strings.Contains(msg, wire) || !strings.Contains(msg, "401") || !strings.Contains(msg, "API token") {
		t.Errorf("401: %s", msg)
	}
	if e := errorOf(err); e == nil || e.Retry {
		t.Errorf("a 401 is tried again: %+v", e)
	}
}

func TestScrub(t *testing.T) {
	c := Connection{Auth: AuthBasic, Username: "u", Password: "hunter2-password", Token: "abc"}
	wire := base64.StdEncoding.EncodeToString([]byte("u:hunter2-password"))
	got := Scrub("sent hunter2-password as "+wire+" and abc", c)
	if strings.Contains(got, "hunter2-password") || strings.Contains(got, wire) {
		t.Errorf("scrub: %s", got)
	}
	// Values too short to be secrets are left, so words are not masked.
	if !strings.Contains(got, "abc") {
		t.Errorf("scrub masked a 3-character value: %s", got)
	}
}

// A secret an answer echoes is hidden before the message is quoted and
// cut: one holding quotes or backslashes, and one the cut falls inside.
func TestEchoedSecretIsScrubbedBeforeCut(t *testing.T) {
	secret := `pa"ss\word-9876`
	f := newFakeSN(t, basic("svc.signalith", secret))
	conn := snConn(f)
	conn.Password = secret
	e := newEnv(t)
	for _, said := range []string{
		"bad credentials " + secret,
		strings.Repeat("x", 290) + secret,
	} {
		body, _ := json.Marshal(map[string]any{"error": map[string]any{"message": said}})
		f.inject(fault{match: "GET /api/now/table/incident", status: 403, body: string(body)})
		_, err := e.svc.Test(context.Background(), conn)
		if err == nil {
			t.Fatal("a 403 passed the test")
		}
		msg := err.Error()
		for _, part := range []string{`pa"ss`, `pa\"ss`, `ss\wor`, `ss\\wor`, "word-9876"} {
			if strings.Contains(msg, part) {
				t.Errorf("the message shows part of the secret (%s): %s", part, msg)
			}
		}
	}
	// Scrub hides the quoted and JSON-escaped forms too.
	quoted, _ := json.Marshal(secret)
	for _, in := range []string{secret, strconv.Quote(secret), string(quoted)} {
		if got := Scrub("said "+in, conn); strings.Contains(got, "word-9876") {
			t.Errorf("scrub of %s: %s", in, got)
		}
	}
}

func TestNotFoundAndServerErrors(t *testing.T) {
	f := newFakeJira(t, true, basic("bot@example.com", "jira-api-token-123456"))
	e := newEnv(t, jiraCloudConn(f))
	ctx := context.Background()
	e.newCase("case-1", "x", "high")

	f.inject(fault{match: "POST /rest/api/3/issue", status: 502, body: "<html>Bad gateway</html>"})
	_, err := e.svc.Create(ctx, "case-1", "jc", "ann")
	if err == nil || !strings.Contains(err.Error(), "502") || !retryable(err) {
		t.Fatalf("502: %v", err)
	}
	if st := e.link("jc", "case-1"); st.State != StateFailed || st.Attempts != 1 || st.Error == "" {
		t.Errorf("link after a failed create %+v", st.Link)
	}
	if strings.Contains(err.Error(), "<html>") {
		t.Errorf("an HTML error page is shown: %v", err)
	}
	// The analyst tries again.
	if l, err := e.svc.Create(ctx, "case-1", "jc", "ann"); err != nil || l.Key != "SEC-1" || l.Attempts != 2 {
		t.Fatalf("second try: %+v %v", l, err)
	}

	// A 5xx while syncing is shown on the link and tried again.
	e.pass()
	e.note("case-1", "hello")
	f.inject(fault{match: "POST /rest/api/3/issue/SEC-1/comment", status: 500, body: `{"errorMessages":["Internal server error"]}`})
	e.pass()
	if st := e.link("jc", "case-1"); !strings.Contains(st.Error, "500") {
		t.Errorf("link after a 500 %+v", st.Link)
	}
	e.clk.add(retryEvery)
	e.pass()
	if st := e.link("jc", "case-1"); st.Error != "" || len(f.issue("SEC-1").comments) != 1 {
		t.Errorf("not tried again: %+v", st.Link)
	}

	// 404 for a missing project when testing is covered in TestJiraTest;
	// a ticket deleted while open is 404 on its comments, shown as such.
	_, err = (&jira{client: mustClient(t, e.svc, jiraCloudConn(f))}).comments(ctx, ref{Key: "SEC-99"})
	if er := errorOf(err); er == nil || er.Code != 404 || !strings.Contains(er.Msg, "still exists") {
		t.Errorf("404: %v", err)
	}
}

func mustClient(t *testing.T, s *Service, c Connection) *client {
	t.Helper()
	cl, err := s.newClient(c)
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

func TestRateLimit(t *testing.T) {
	f := newFakeJira(t, true, basic("bot@example.com", "jira-api-token-123456"))
	e := newEnv(t, jiraCloudConn(f))
	ctx := context.Background()
	e.newCase("case-1", "x", "high")

	// A short Retry-After is waited out.
	f.inject(fault{match: "POST /rest/api/3/issue", status: 429, retryAfter: "2", body: `{"errorMessages":["Rate limit exceeded"]}`})
	if _, err := e.svc.Create(ctx, "case-1", "jc", "ann"); err != nil {
		t.Fatal(err)
	}
	if len(e.slept) != 1 || e.slept[0] != 2*time.Second {
		t.Errorf("slept %v, want [2s]", e.slept)
	}

	// A long one pauses the connection until then.
	e.pass()
	f.inject(fault{match: "POST /rest/api/3/search/jql", status: 429, retryAfter: "180"})
	e.pass()
	n := f.count("POST /rest/api/3/search/jql")
	e.pass()
	e.pass()
	if f.count("POST /rest/api/3/search/jql") != n {
		t.Error("a paused connection is polled")
	}
	if len(e.slept) != 1 {
		t.Errorf("waited for a long Retry-After: %v", e.slept)
	}
	e.pass()
	e.pass()
	if f.count("POST /rest/api/3/search/jql") == n {
		t.Error("the connection is not polled again after the Retry-After")
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 16, 10, 0, 0, 0, time.UTC)
	for v, want := range map[string]time.Duration{
		"3": 3 * time.Second, "0": time.Second, "": time.Minute, "soon": time.Minute, "999999": maxPause,
		now.Add(90 * time.Second).Format(http.TimeFormat): 90 * time.Second,
	} {
		if got := retryAfter(v, now); got != want {
			t.Errorf("Retry-After %q: %v, want %v", v, got, want)
		}
	}
}

func TestRedirectIsRefused(t *testing.T) {
	hit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	t.Cleanup(target.Close)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(redir.Close)
	e := newEnv(t)
	conn := Connection{ID: "x", Type: TypeServiceNow, URL: redir.URL, Auth: AuthBasic, Username: "u", Password: "secret-pass", Table: "incident", AllowLoopback: true}
	_, err := e.svc.Test(context.Background(), conn)
	if err == nil || !strings.Contains(err.Error(), "redirect") || hit {
		t.Errorf("redirect: %v (followed: %v)", err, hit)
	}
}

func TestAddressesRefused(t *testing.T) {
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	e := newEnv(t)
	u, _ := url.Parse(f.URL())
	e.svc.Protected = notify.Protected{u.Host}
	if _, err := e.svc.Test(context.Background(), snConn(f)); err == nil || !strings.Contains(err.Error(), "OpenSearch") {
		t.Errorf("protected address: %v", err)
	}
	e.svc.Protected = nil
	conn := snConn(f)
	conn.AllowLoopback = false
	if _, err := e.svc.Test(context.Background(), conn); err == nil || !strings.Contains(err.Error(), "does not connect") {
		t.Errorf("loopback without allow: %v", err)
	}
	if n := len(f.requests()); n != 0 {
		t.Errorf("a refused address was reached %d times", n)
	}

	for _, c := range []struct {
		url   string
		allow bool
		ok    bool
	}{
		{"https://example.atlassian.net", false, true},
		{"https://jira.example.com/jira", false, true},
		{"https://10.1.2.3", false, true},
		{"http://example.atlassian.net", false, false},
		{"http://example.atlassian.net", true, false},
		{"http://127.0.0.1:8080", false, false},
		{"http://127.0.0.1:8080", true, true},
		{"http://localhost:8080", true, true},
		{"https://localhost", false, false},
		{"https://localhost.", false, false},
		{"https://LocalHost..:8443", false, false},
		{"https://jira.localhost.", false, false},
		{"http://localhost.:8080", true, true},
		{"https://169.254.169.254", false, false},
		{"https://169.254.169.254", true, false},
		{"https://[::1]", false, false},
		{"https://0.0.0.0", false, false},
		{"https://user:pw@example.com", false, false},
		{"https://example.com/?a=1", false, false},
		{"https://example.com/#x", false, false},
		{"ftp://example.com", false, false},
		{"example.com", false, false},
		{"https://example.com:99999", false, false},
	} {
		if got := CheckURL(c.url, c.allow) == ""; got != c.ok {
			t.Errorf("CheckURL(%q, %v) ok=%v, want %v (%s)", c.url, c.allow, got, c.ok, CheckURL(c.url, c.allow))
		}
	}
}

func TestBadCertificate(t *testing.T) {
	f := newFakeJira(t, true, basic("bot@example.com", "jira-api-token-123456"))
	e := newEnv(t)
	conn := jiraCloudConn(f)
	conn.CAPEM = ""
	_, err := e.svc.Test(context.Background(), conn)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("untrusted certificate: %v", err)
	}
}

func TestLargeAnswerRefused(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":[{"sys_id":"`))
		chunk := strings.Repeat("a", 64<<10)
		for i := 0; i < (maxAnswer/len(chunk))+2; i++ {
			w.Write([]byte(chunk))
		}
		w.Write([]byte(`"}]}`))
	}))
	t.Cleanup(big.Close)
	e := newEnv(t)
	conn := Connection{ID: "x", Type: TypeServiceNow, URL: big.URL, Auth: AuthBasic, Username: "u", Password: "secret-pass", Table: "incident", AllowLoopback: true}
	if _, err := e.svc.Test(context.Background(), conn); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("large answer: %v", err)
	}
}

func TestAutoCreate(t *testing.T) {
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	conn := snConn(f)
	conn.AutoCreate, conn.AutoMinSeverity = true, "high"
	clk := newClock()
	conn.AutoSince = clk.Now().Add(-time.Hour)
	e := newEnv(t, conn)
	e.clk = clk
	e.svc.Now = clk.Now

	e.clk.add(-2 * time.Hour)
	e.newCase("old", "opened before auto-create", "critical")
	e.clk.add(2 * time.Hour)
	e.change("old", cases.Update{Title: ptr("still open")})
	e.newCase("high", "high", "high")
	e.newCase("low", "low", "low")
	e.newCase("sample", "sample", "critical")
	_, _ = e.cases.Modify(context.Background(), "sample", func(c *cases.Case) (bool, error) { c.Sample = "load-1"; return true, nil })

	e.pass()
	e.pass()
	if n := f.count("POST /api/now/table/incident"); n != 1 {
		t.Errorf("%d tickets opened, want 1: %v", n, f.requests())
	}
	if c := e.getCase("high"); len(c.Tickets) != 1 || c.Tickets[0].CreatedBy != "Signalith" {
		t.Errorf("high case tickets %+v", c.Tickets)
	}
	if st := e.link("sn", "high"); !st.Auto {
		t.Errorf("link %+v", st.Link)
	}
	for _, id := range []string{"old", "low", "sample"} {
		if c := e.getCase(id); len(c.Tickets) != 0 {
			t.Errorf("case %s got a ticket", id)
		}
	}

	// A failed auto-create is tried again by itself, a few times.
	e.newCase("high-2", "second", "critical")
	f.inject(fault{match: "POST /api/now/table/incident", status: 503, count: 1})
	e.pass()
	if st := e.link("sn", "high-2"); st.State != StateFailed {
		t.Fatalf("link %+v", st.Link)
	}
	e.clk.add(retryEvery)
	e.pass()
	if st := e.link("sn", "high-2"); st.State != StateLinked {
		t.Errorf("not tried again: %+v", st.Link)
	}
}

func TestRequestFromAnotherServer(t *testing.T) {
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	e := newEnv(t, snConn(f))
	e.newCase("case-1", "x", "medium")
	l, err := e.svc.Request(context.Background(), "case-1", "sn", "bob")
	if err != nil || l.State != StatePending {
		t.Fatalf("request: %+v %v", l, err)
	}
	if len(f.requests()) != 0 {
		t.Error("a request called the system")
	}
	if _, err := e.svc.Request(context.Background(), "case-1", "sn", "bob"); err != ErrInProgress {
		t.Errorf("second request: %v", err)
	}
	// Not the job server: nothing happens.
	e.svc.Allowed = func() bool { return false }
	e.pass()
	if len(f.requests()) != 0 {
		t.Error("a server that does not run the jobs synced")
	}
	e.svc.Allowed = nil
	e.pass()
	st := e.link("sn", "case-1")
	if st.State != StateLinked || st.CreatedBy != "bob" || st.Key != "INC0010001" {
		t.Errorf("link %+v", st.Link)
	}
	if c := e.getCase("case-1"); len(c.Tickets) != 1 {
		t.Errorf("case tickets %+v", c.Tickets)
	}
	if _, err := e.svc.Create(context.Background(), "case-1", "nope", "bob"); err != ErrNoConnection {
		t.Errorf("unknown connection: %v", err)
	}
}

func TestUndecryptableSecret(t *testing.T) {
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	e := newEnv(t, snConn(f))
	conn, _ := e.svc.Settings.Settings()
	c := conn.Connections[0]
	sealed, err := secrets.NewKeyring(t.TempDir()).Seal(FileField(c.ID, "password"), "sn-password-123")
	if err != nil {
		t.Fatal(err)
	}
	c.Password = sealed
	if bad := c.Undecrypted(); len(bad) != 1 || bad[0] != "password" {
		t.Errorf("undecrypted %v", bad)
	}
	if _, err := e.svc.Test(context.Background(), c); err == nil || !strings.Contains(err.Error(), "cannot be decrypted") {
		t.Errorf("test with an undecryptable password: %v", err)
	}
}
