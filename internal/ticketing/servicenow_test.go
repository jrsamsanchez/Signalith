package ticketing

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
)

func snConn(f *fakeSN) Connection {
	return Connection{ID: "sn", Name: "Service desk", Type: TypeServiceNow, URL: f.URL(), Auth: AuthBasic,
		Username: "svc.signalith", Password: "sn-password-123", Table: "incident", CommentField: "work_notes",
		CloseCode: DefaultCloseCode, CallerID: "6816f79cc0a8016401c5a33be04be441", Statuses: DefaultStates,
		SyncNotes: true, SyncStatus: true, AllowLoopback: true}
}

func TestServiceNowSyncBothWays(t *testing.T) {
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	e := newEnv(t, snConn(f))
	ctx := context.Background()
	e.newCase("case-1", "Malware on host-7", "high")

	l, err := e.svc.Create(ctx, "case-1", "sn", "ann")
	if err != nil {
		t.Fatal(err)
	}
	r := f.record("INC0010001")
	if l.Key != "INC0010001" || l.RemoteID != r.sysID || !strings.Contains(l.URL, "/nav_to.do?uri=") {
		t.Fatalf("link %+v", l)
	}
	if r.shortDesc != "Malware on host-7" || r.impact != "1" || r.urgency != "2" || r.caller != "6816f79cc0a8016401c5a33be04be441" ||
		!strings.Contains(r.description, "https://siem.example.com/#cases?id=case-1") {
		t.Errorf("record %+v", r)
	}
	e.pass()

	// From ServiceNow: a comment and a new state.
	f.humanNote("INC0010001", "comments", "beth.anglin", "Rebooted the host")
	f.humanState("INC0010001", "2")
	e.pass()
	c := e.getCase("case-1")
	if c.Status != "in_progress" || !slices.Contains(notesOf(c), "servicenow:beth.anglin: Rebooted the host") {
		t.Errorf("case %s %q", c.Status, notesOf(c))
	}
	if len(f.notes("INC0010001")) != 1 {
		t.Errorf("the imported comment echoed back: %+v", f.notes("INC0010001"))
	}

	// From the case: a note, then resolved; ServiceNow needs a close code
	// and notes for that.
	e.note("case-1", "Removed the implant")
	e.change("case-1", cases.Update{Status: ptr("resolved"), Resolution: ptr("Reimaged")})
	e.pass()
	r = f.record("INC0010001")
	if r.state != "6" || r.closeCode != DefaultCloseCode || r.closeNotes != "Reimaged" {
		t.Errorf("record %+v", r)
	}
	n := f.notes("INC0010001")
	if len(n) != 2 || n[1].element != "work_notes" || n[1].value != "[Signalith] ann: Removed the implant" {
		t.Errorf("journal %+v", n)
	}
	before := len(e.getCase("case-1").Entries)
	e.pass()
	if after := len(e.getCase("case-1").Entries); after != before {
		t.Errorf("Signalith's own work note came back: %q", notesOf(e.getCase("case-1")))
	}
	if st := e.link("sn", "case-1"); st.Error != "" || st.RemoteStatus.Name != "6" {
		t.Errorf("link %+v", st.Link)
	}

	// Canceled closes the case.
	f.humanState("INC0010001", "8")
	e.pass()
	if c := e.getCase("case-1"); c.Status != "closed" {
		t.Errorf("canceled incident: case %s", c.Status)
	}
	if r := f.record("INC0010001"); r.state != "8" {
		t.Errorf("the canceled incident was moved to %s", r.state)
	}

	// Severity sets impact and urgency.
	e.change("case-1", cases.Update{Severity: ptr("low")})
	e.pass()
	if r := f.record("INC0010001"); r.impact != "2" || r.urgency != "3" {
		t.Errorf("record after severity change %+v", r)
	}
}

func TestServiceNowStateRefused(t *testing.T) {
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	conn := snConn(f)
	conn.CloseCode = ""
	e := newEnv(t, conn)
	e.newCase("case-1", "x", "medium")
	if _, err := e.svc.Create(context.Background(), "case-1", "sn", "ann"); err != nil {
		t.Fatal(err)
	}
	e.pass()
	e.change("case-1", cases.Update{Status: ptr("resolved")})
	e.pass()
	if st := e.link("sn", "case-1"); !strings.Contains(st.Error, "Resolution code and notes are mandatory") {
		t.Errorf("link %+v", st.Link)
	}
}

func TestServiceNowOAuth(t *testing.T) {
	f := newFakeSN(t, "Bearer none-yet")
	f.clientID, f.clientSecret = "signalith-client", "oauth-client-secret-1"
	conn := snConn(f)
	conn.Auth, conn.Username, conn.Password = AuthOAuth, "", ""
	conn.ClientID, conn.ClientSecret = "signalith-client", "oauth-client-secret-1"
	e := newEnv(t, conn)
	e.newCase("case-1", "x", "critical")
	if _, err := e.svc.Create(context.Background(), "case-1", "sn", "ann"); err != nil {
		t.Fatal(err)
	}
	e.pass()
	e.pass()
	if n := f.count("POST /oauth_token.do"); n != 1 {
		t.Errorf("%d token requests, want 1 (kept until it expires)", n)
	}
	// A revoked token: a new one is asked for, once.
	f.mu.Lock()
	f.auth = "Bearer revoked"
	f.mu.Unlock()
	e.note("case-1", "after revoke")
	e.pass()
	if n := f.count("POST /oauth_token.do"); n != 2 {
		t.Errorf("%d token requests after a revoke, want 2", n)
	}
	if st := e.link("sn", "case-1"); st.Error != "" {
		t.Errorf("link %+v", st.Link)
	}

	// A wrong secret is reported without it.
	conn.ClientSecret = "wrong-secret-value"
	_, err := e.svc.Test(context.Background(), conn)
	if err == nil || strings.Contains(err.Error(), "wrong-secret-value") || !strings.Contains(err.Error(), "client ID and secret") {
		t.Errorf("wrong secret: %v", err)
	}
}

func TestServiceNowTest(t *testing.T) {
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	e := newEnv(t)
	conn := snConn(f)
	msg, err := e.svc.Test(context.Background(), conn)
	if err != nil || !strings.Contains(msg, "Comments can be read back") {
		t.Errorf("test: %q %v", msg, err)
	}
	f.journalForbidden = true
	if _, err := e.svc.Test(context.Background(), conn); err == nil || !strings.Contains(err.Error(), "sys_journal_field") {
		t.Errorf("journal forbidden: %v", err)
	}
	conn.Table = "no_such_table"
	if _, err := e.svc.Test(context.Background(), conn); err == nil || !strings.Contains(err.Error(), "no table no_such_table") {
		t.Errorf("missing table: %v", err)
	}
}

// A cached token is only used with the credentials it was issued for.
func TestTokenCacheChecksCredentials(t *testing.T) {
	var c tokenCache
	now := time.Now()
	c.put("sn:", "url\x00id\x00secret-1", "token-1", now.Add(time.Hour))
	if got := c.get("sn:", "url\x00id\x00secret-1", now); got != "token-1" {
		t.Errorf("same credentials: %q", got)
	}
	if got := c.get("sn:", "url\x00id\x00secret-2", now); got != "" {
		t.Errorf("new secret got the old token %q", got)
	}
	if got := c.get("sn:", "url\x00id\x00secret-1", now.Add(2*time.Hour)); got != "" {
		t.Errorf("expired token %q", got)
	}
}
