// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/notify"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClientFailDescribesErrors(t *testing.T) {
	cl := &client{conn: Connection{ID: "jc", Type: TypeJira, Token: "jira-api-token-123456"}}
	wrap := func(err error) error {
		return &url.Error{Op: "Post", URL: "https://jira.example.com/rest?x=1", Err: err}
	}
	for _, c := range []struct {
		name  string
		err   error
		want  string
		retry bool
	}{
		{"blocked", &notify.BlockedError{Addr: "127.0.0.1:443", Why: "this server's own address", Loopback: true}, "tick \"Allow this server's own addresses\"", false},
		{"deadline", wrap(context.DeadlineExceeded), "did not answer within", true},
		{"dns not found", wrap(&net.DNSError{Name: "jira.invalid", IsNotFound: true}), "Could not find the server jira.invalid", true},
		{"dns failed", wrap(&net.DNSError{Name: "jira.example.com"}), "Could not look up the server jira.example.com (DNS)", true},
		{"timeout", wrap(timeoutErr{}), "did not answer in time", true},
		{"refused", wrap(&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}), "refused the connection", true},
		{"unknown authority", wrap(x509.UnknownAuthorityError{}), "not from a trusted authority", false},
		{"hostname", wrap(x509.HostnameError{Certificate: &x509.Certificate{}, Host: "x"}), "certificate is for another name", false},
		{"invalid", wrap(x509.CertificateInvalidError{Cert: &x509.Certificate{}, Reason: x509.Expired}), "certificate is not valid (", false},
		{"not tls", wrap(tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}), "did not answer with TLS", false},
		{"other, scrubbed", wrap(fmt.Errorf("reset by peer near jira-api-token-123456")), "Could not reach Jira: reset by peer near", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := cl.fail(c.err)
			var e *Error
			if !errors.As(err, &e) || !strings.Contains(e.Msg, c.want) || e.Retry != c.retry {
				t.Fatalf("%v (%+v)", err, e)
			}
			if strings.Contains(e.Msg, "jira-api-token-123456") || strings.Contains(e.Msg, "rest?x=1") {
				t.Errorf("message shows a secret or the URL: %s", e.Msg)
			}
		})
	}
	if err := cl.fail(wrap(context.Canceled)); !errors.Is(err, context.Canceled) {
		t.Errorf("cancel: %v", err)
	}
	if describeTLS(errors.New("plain"), "Jira") != "" {
		t.Error("describeTLS described a plain error")
	}
}

func TestNewClientRefusesBadConnections(t *testing.T) {
	s := &Service{}
	for _, c := range []struct {
		name string
		conn Connection
		want string
	}{
		{"bad ca", Connection{ID: "x", Type: TypeJira, URL: "https://jira.example.com", CAPEM: "not a certificate"}, "not a PEM certificate"},
		{"bad url", Connection{ID: "x", Type: TypeJira, URL: "ftp://jira.example.com"}, ""},
	} {
		_, err := s.newClient(c.conn)
		var e *Error
		if !errors.As(err, &e) || !strings.Contains(e.Msg, c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if _, err := s.newClient(Connection{ID: "x", Type: TypeJira, URL: "https://jira.example.com"}); err != nil {
		t.Errorf("good connection: %v", err)
	}
}

func TestServiceNowPollAndPatchProblems(t *testing.T) {
	ctx := context.Background()
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	e := newEnv(t, snConn(f))
	rem, err := e.svc.remote(snConn(f))
	if err != nil {
		t.Fatal(err)
	}
	gone := ref{Key: "INC0000099", ID: strings.Repeat("a", 32)}
	bad := ref{Key: "INC0000098", ID: "not-a-sys-id"}
	// A ticket the list leaves out and that reads as not found is gone;
	// one without a valid sys_id is not asked about.
	states, err := rem.poll(ctx, []ref{gone, bad}, time.Time{})
	if err != nil || len(states) != 1 || !states[0].Gone || states[0].Key != gone.Key {
		t.Fatalf("poll %+v %v", states, err)
	}
	if states, err := rem.poll(ctx, []ref{bad}, time.Time{}); err != nil || len(states) != 0 {
		t.Errorf("only bad ids: %+v %v", states, err)
	}
	// The list failing, or the read of one ticket failing otherwise.
	f.inject(fault{match: "GET /api/now/table/incident", status: 500, body: `{"error":{"message":"boom"}}`})
	if _, err := rem.poll(ctx, []ref{gone}, time.Time{}); err == nil {
		t.Error("a failed list was not returned")
	}
	f.inject(fault{match: "GET /api/now/table/incident/" + gone.ID, status: 403, body: `{"error":{"message":"denied"}}`})
	if _, err := rem.poll(ctx, []ref{gone}, time.Time{}); err == nil {
		t.Error("a failed read was not returned")
	}
	if err := rem.update(ctx, bad, "title", "high"); err == nil || !strings.Contains(err.Error(), "has no valid sys_id") {
		t.Errorf("patch without sys_id: %v", err)
	}
}

func TestJiraFindWithoutKnowingItself(t *testing.T) {
	ctx := context.Background()
	f := newFakeJira(t, true, basic("bot@example.com", "jira-api-token-123456"))
	conn := jiraCloudConn(f)
	e := newEnv(t, conn)
	since := e.clk.Now().Add(-time.Hour)
	find := func(c Connection) (*created, error) {
		t.Helper()
		rem, err := e.svc.remote(c)
		if err != nil {
			t.Fatal(err)
		}
		return rem.(*jira).find(ctx, "case-1", since)
	}
	// A project key Jira would not take is never searched.
	odd := conn
	odd.ID, odd.Project = "odd", "not a key"
	before := len(f.requests())
	if got, err := find(odd); got != nil || err != nil || len(f.requests()) != before {
		t.Errorf("odd project: %v %v", got, err)
	}
	// Jira refusing to say who Signalith is: it takes no issue.
	f.inject(fault{match: "GET /rest/api/3/myself", status: 403, body: `{"errorMessages":["no"]}`})
	if got, err := find(conn); got != nil || err != nil {
		t.Errorf("refused: %v %v", got, err)
	}
	// Jira busy: tried again later.
	f.inject(fault{match: "GET /rest/api/3/myself", status: 503, body: `{}`, count: 5})
	if _, err := find(conn); err == nil {
		t.Error("a busy Jira was not reported")
	}
	f.mu.Lock()
	f.faults = nil
	f.mu.Unlock()
	// An answer that names no account.
	f.inject(fault{match: "GET /rest/api/3/myself", status: 200, body: `{}`})
	rem, _ := e.svc.remote(conn)
	if _, err := rem.(*jira).self(ctx); err == nil || !strings.Contains(err.Error(), "did not say which account") {
		t.Errorf("no account: %v", err)
	}
}

func TestSentenceAndLabels(t *testing.T) {
	for in, want := range map[string]string{"": "", "  bad thing ": "Bad thing.", "Done.": "Done."} {
		if got := sentence(in); got != want {
			t.Errorf("sentence(%q) = %q", in, got)
		}
	}
	if TypeLabel(TypeJira) != "Jira" || TypeLabel("other") == "" {
		t.Errorf("TypeLabel %q %q", TypeLabel(TypeJira), TypeLabel("other"))
	}
	for _, c := range []struct {
		r      RemoteStatus
		system string
		want   string
	}{
		{RemoteStatus{Name: "6"}, TypeServiceNow, stateLabels["6"]},
		{RemoteStatus{Name: "42"}, TypeServiceNow, "State 42"},
		{RemoteStatus{}, TypeServiceNow, ""},
		{RemoteStatus{Name: "In Progress"}, TypeJira, "In Progress"},
	} {
		if got := c.r.Label(c.system); got != c.want {
			t.Errorf("Label(%+v, %s) = %q, want %q", c.r, c.system, got, c.want)
		}
	}
	for st, want := range map[string]string{"new": "new", "resolved": "done", "closed": "done", "in_progress": "indeterminate"} {
		if got := jiraCategory(st); got != want {
			t.Errorf("jiraCategory(%s) = %q", st, got)
		}
	}
	jira := Connection{Type: TypeJira, Priorities: map[string]string{"high": " Highest "}}
	if jira.priority("high") != "Highest" || jira.priority("low") != DefaultPriorities["low"] {
		t.Errorf("priority %q %q", jira.priority("high"), jira.priority("low"))
	}
	if jira.agrees("new", RemoteStatus{}) {
		t.Error("an empty status agrees")
	}
	if !jira.agrees("resolved", RemoteStatus{Name: "Done", Category: "done"}) || jira.agrees("new", RemoteStatus{Name: "Done", Category: "done"}) {
		t.Error("jira agrees by category")
	}
	sn := Connection{Type: TypeServiceNow}
	if !sn.agrees("closed", RemoteStatus{Name: canceledState}) {
		t.Error("a canceled ticket does not agree with a closed case")
	}
	if got := sn.caseStatusFor(RemoteStatus{Name: canceledState}); got != "closed" {
		t.Errorf("canceled = %q", got)
	}
	if got := sn.caseStatusFor(RemoteStatus{Name: "99"}); got != "" {
		t.Errorf("unknown state = %q", got)
	}
	if got := jira.caseStatusFor(RemoteStatus{}); got != "" {
		t.Errorf("empty = %q", got)
	}
	if got := jira.caseStatusFor(RemoteStatus{Name: "Odd", Category: "weird"}); got != "" {
		t.Errorf("odd category = %q", got)
	}
	for sev, want := range map[string][2]string{"critical": {"1", "1"}, "high": {"1", "2"}, "medium": {"2", "2"}, "low": {"2", "3"}, "informational": {"3", "3"}} {
		if i, u := impactUrgency(sev); i != want[0] || u != want[1] {
			t.Errorf("impactUrgency(%s) = %s %s", sev, i, u)
		}
	}
	if len(newID()) != 12 || newID() == newID() {
		t.Error("newID")
	}
}
