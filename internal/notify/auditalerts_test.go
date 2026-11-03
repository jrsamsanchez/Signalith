// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/audit"
)

func TestAuditAlertsCatalog(t *testing.T) {
	ids := map[string]bool{}
	for _, a := range AuditAlerts {
		if ids[a.ID] {
			t.Errorf("two audit alerts have the ID %s", a.ID)
		}
		ids[a.ID] = true
		if !idForm.MatchString(a.ID) || a.Name == "" || a.Description == "" {
			t.Errorf("audit alert %+v needs an ID, a name and a description", a)
		}
		if !slices.Contains(Urgencies, a.Urgency) {
			t.Errorf("%s: urgency %q is not one of %v", a.ID, a.Urgency, Urgencies)
		}
		if len(a.messages)+len(a.prefixes)+len(a.actions)+len(a.actionPrefixes) == 0 {
			t.Errorf("%s matches no audit record", a.ID)
		}
	}
}

// TestAuditAlertsMatchLoggedRecords keeps the alerts in step with the
// audit records Signalith logs: each message, prefix and action an alert
// looks for must be written somewhere in the code, so renaming an audit
// line cannot silently turn an alert off.
func TestAuditAlertsMatchLoggedRecords(t *testing.T) {
	root := filepath.Join("..", "..")
	var src strings.Builder
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "site", "web", "docs":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || strings.HasSuffix(p, "auditalerts.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		src.Write(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	code := src.String()
	for _, a := range AuditAlerts {
		for _, m := range a.messages {
			if !strings.Contains(code, `"`+m+`"`) && !strings.Contains(code, `"`+m+`:`) {
				t.Errorf("%s looks for the audit message %q, which no code logs", a.ID, m)
			}
		}
		for _, p := range a.prefixes {
			if !strings.Contains(code, `"`+p) {
				t.Errorf("%s looks for audit messages starting %q, which no code logs", a.ID, p)
			}
		}
		for _, act := range append(slices.Clone(a.actions), a.actionPrefixes...) {
			if !strings.Contains(code, `"`+act) {
				t.Errorf("%s looks for the audit action %q, which no code logs", a.ID, act)
			}
		}
	}
}

func ev(msg string, fields map[string]string) audit.Event {
	return audit.Event{Time: t0.Add(time.Minute), Message: msg, User: "alice", SourceIP: "203.0.113.7", Fields: fields}
}

// first returns the ID of the first audit alert that matches e, or "".
func first(e audit.Event) string {
	for _, a := range AuditAlerts {
		if a.Matches(e) {
			return a.ID
		}
	}
	return ""
}

func TestAuditAlertsMatch(t *testing.T) {
	for _, c := range []struct {
		name string
		ev   audit.Event
		want string
	}{
		{"built-in admin", ev("signed in", map[string]string{"source": "builtin", "role": "admin"}), "builtin_signin"},
		{"local admin", ev("signed in", map[string]string{"source": "local", "role": "admin"}), "admin_signin"},
		{"analyst", ev("signed in", map[string]string{"source": "local", "role": "analyst"}), ""},
		{"wrong password", ev("sign-in failed", map[string]string{"reason": "wrong password", "locked_out": "false"}), "signin_failed"},
		{"locked out", ev("sign-in failed", map[string]string{"locked_out": "true"}), "lockout"},
		{"address paused", ev(addressPaused+" after too many wrong passwords. If many people", nil), "lockout"},
		{"user deleted", ev("user deleted", nil), "access_change"},
		{"tenant added", audit.Event{Message: "tenants.add: tenant added", Action: "tenants.add"}, "tenant_change"},
		{"tenant switch", audit.Event{Message: "tenants.switch: switched tenant", Action: "tenants.switch"}, ""},
		{"api token", audit.Event{Message: "api_token.create: API token created", Action: "api_token.create"}, "token_change"},
		{"settings", ev("settings saved", nil), "settings_change"},
		{"detection deleted", audit.Event{Message: "detection.delete: detection deleted", Action: "detection.delete"}, "deletions"},
		{"audit lost", audit.Event{Message: "audit records lost: the spool was full", Action: audit.ActionLost}, "audit_integrity"},
		{"tamper", audit.Event{Message: "config.tamper: a shared setting was changed", Action: "config.tamper"}, "audit_integrity"},
		{"search", audit.Event{Message: "search.run: search run", Action: "search.run"}, ""},
	} {
		if got := first(c.ev); got != c.want {
			t.Errorf("%s: matched %q, want %q", c.name, got, c.want)
		}
	}
}

func TestAuditTapKeepsOnlyAlertRecords(t *testing.T) {
	var tap AuditTap
	tap.Add(audit.Event{Time: t0, Message: "search.run: search run", Action: "search.run"})
	tap.Add(ev("user deleted", nil))
	got, truncated, err := tap.AuditRecords(context.Background(), audit.Match{Since: t0}, 10)
	if err != nil || truncated || len(got) != 1 || got[0].Event.Message != "user deleted" || !strings.HasPrefix(got[0].ID, "tap-") {
		t.Fatalf("got %+v, %v, %v", got, truncated, err)
	}
	if again, _, _ := tap.AuditRecords(context.Background(), audit.Match{Since: t0.Add(time.Hour)}, 10); len(again) != 0 {
		t.Errorf("records before since were read: %+v", again)
	}
	for i := range TapSize + 5 {
		e := ev("user deleted", nil)
		e.Time = t0.Add(time.Duration(i+120) * time.Second)
		tap.Add(e)
	}
	all, truncated, _ := tap.AuditRecords(context.Background(), audit.Match{}, TapSize+10)
	if len(all) != TapSize || truncated || tap.Dropped() != 6 {
		t.Errorf("kept %d (truncated %v), dropped %d; want %d kept, 6 dropped", len(all), truncated, tap.Dropped(), TapSize)
	}
	if few, truncated, _ := tap.AuditRecords(context.Background(), audit.Match{}, 3); len(few) != 3 || !truncated {
		t.Errorf("a limit of 3 read %d (truncated %v)", len(few), truncated)
	}
}

// auditRig is a dispatcher with the audit alerts given on, reading the
// records added to its tap.
func auditRig(t *testing.T, alerts ...AuditRuleInput) (*rig, *AuditTap) {
	t.Helper()
	r := newRig(t)
	if _, err := r.set.Save(Input{Channels: []ChannelInput{
		slackInput("aaa", "https://hooks.example.com/a"),
		{ID: "bbb", Name: "SOAR", Type: TypeWebhook, URL: "https://soar.example.com/hook"},
	}, AuditAlerts: &alerts}); err != nil {
		t.Fatal(err)
	}
	tap := &AuditTap{}
	r.d.Audit = func() AuditSource { return tap }
	return r, tap
}

func TestDispatcherSendsAuditAlertsOnce(t *testing.T) {
	r, tap := auditRig(t,
		AuditRuleInput{ID: "access_change", Enabled: true, Channels: []string{"aaa", "bbb"}},
		AuditRuleInput{ID: "deletions", Enabled: true, Channels: []string{"aaa"}},
		AuditRuleInput{ID: "settings_change", Enabled: false, Channels: []string{"aaa"}},
	)
	before := ev("user created", nil)
	before.Time = t0.Add(-time.Minute) // logged before the alert was turned on
	tap.Add(before)
	// Matches access_change and deletions: one message per channel.
	tap.Add(ev("user deleted", map[string]string{"password_hash": "not sent", "tenant": "acme"}))
	tap.Add(ev("settings saved", nil)) // its alert is off
	r.clock.add(2 * time.Minute)
	r.pass()
	if r.sender.count("aaa") != 1 || r.sender.count("bbb") != 1 {
		t.Fatalf("sent %+v", r.sender.sent)
	}
	m := r.sender.sent[0].msg
	if m.Kind != KindAudit || m.Urgency != "high" || m.AuditAlert != "Users, roles and two-step sign-in change" ||
		m.Entities["user"] != "alice" || m.Entities["src"] != "203.0.113.7" || m.AuditTenant != "acme" || m.Link != "https://siem.example.com/#audit" {
		t.Errorf("message %+v", m)
	}
	b, _ := json.Marshal(m)
	if strings.Contains(string(b), "not sent") {
		t.Errorf("a field of the audit record was sent: %s", b)
	}
	list, _ := r.store.Recent(context.Background(), 10)
	if len(list) != 2 || list[0].Kind != KindAudit || !strings.HasPrefix(list[0].Rule, "audit:") {
		t.Errorf("deliveries %+v", list)
	}
	r.clock.add(time.Minute)
	r.pass()
	if r.sender.count("") != 2 {
		t.Errorf("sent again: %+v", r.sender.sent)
	}
}

func TestDispatcherAuditAlertsSummarizeFloods(t *testing.T) {
	r, tap := auditRig(t, AuditRuleInput{ID: "signin_failed", Enabled: true, Channels: []string{"aaa"}})
	for i := range FloodLimit + 5 {
		e := ev("sign-in failed", map[string]string{"locked_out": "false"})
		e.Time = t0.Add(time.Duration(i+1) * time.Second)
		tap.Add(e)
	}
	r.clock.add(time.Minute)
	r.pass()
	if n := r.sender.count("aaa"); n != FloodLimit {
		t.Fatalf("sent %d messages, want %d", n, FloodLimit)
	}
	last := r.sender.sent[len(r.sender.sent)-1].msg
	if last.Kind != KindAuditSummary || last.Count != 6 || last.Link != "https://siem.example.com/#audit" ||
		!strings.Contains(last.text("x"), "Open the Audit page") {
		t.Errorf("summary %+v", last)
	}
}

func TestDispatcherAuditAlertsRetry(t *testing.T) {
	r, tap := auditRig(t, AuditRuleInput{ID: "builtin_signin", Enabled: true, Channels: []string{"aaa"}})
	r.sender.fail = errors.New("down")
	tap.Add(ev("signed in", map[string]string{"source": "builtin"}))
	r.clock.add(time.Minute)
	r.pass()
	r.sender.fail = nil
	r.clock.add(Backoff[0] + time.Second)
	r.pass()
	if r.sender.count("aaa") != 2 {
		t.Fatalf("sent %d times, want a failure and a retry", r.sender.count("aaa"))
	}
	list, _ := r.store.Recent(context.Background(), 10)
	if len(list) != 1 || list[0].Status != StatusSent || list[0].Kind != KindAudit {
		t.Errorf("deliveries %+v", list)
	}
}

func TestDispatcherWithoutAuditSourceSendsNoAuditAlerts(t *testing.T) {
	r, tap := auditRig(t, AuditRuleInput{ID: "builtin_signin", Enabled: true, Channels: []string{"aaa"}})
	r.d.Audit = nil
	tap.Add(ev("signed in", map[string]string{"source": "builtin"}))
	r.clock.add(time.Minute)
	r.pass()
	if r.sender.count("") != 0 {
		t.Errorf("sent %+v", r.sender.sent)
	}
}

func TestAuditAlertsInput(t *testing.T) {
	cl := &clock{now: t0}
	m := &Manager{File: filepath.Join(t.TempDir(), "n.yaml"), Now: cl.Now}
	chans := []ChannelInput{slackInput("aaa", "https://hooks.example.com/a")}
	bad := []AuditRuleInput{{ID: "nope", Enabled: true}, {ID: "lockout", Enabled: true}, {ID: "deletions", Enabled: true, Channels: []string{"zzz"}}}
	_, err := m.Save(Input{Channels: chans, AuditAlerts: &bad})
	var ie *InputError
	if !errors.As(err, &ie) || len(ie.Problems) != 3 {
		t.Fatalf("want three problems, got %v", err)
	}
	good := []AuditRuleInput{{ID: "lockout", Enabled: true, Channels: []string{"aaa"}}, {ID: "deletions"}}
	s, err := m.Save(Input{Channels: chans, AuditAlerts: &good})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.AuditAlerts) != 1 || !s.AuditRule("lockout").Enabled || !s.AuditRule("lockout").Since.Equal(t0) || s.AuditRule("deletions").Enabled {
		t.Fatalf("saved %+v", s.AuditAlerts)
	}
	// Left out, they are kept; the time they were turned on too.
	cl.add(time.Hour)
	s, err = m.Save(Input{Channels: chans})
	if err != nil || !s.AuditRule("lockout").Enabled || !s.AuditRule("lockout").Since.Equal(t0) {
		t.Fatalf("kept %+v, %v", s.AuditAlerts, err)
	}
	// Read back from the file.
	again := &Manager{File: m.File}
	if s, err := again.Settings(); err != nil || !s.AuditRule("lockout").Enabled {
		t.Fatalf("read %+v, %v", s.AuditAlerts, err)
	}
	// Removing their only channel turns them off.
	s, err = m.Save(Input{})
	if err != nil || s.AuditRule("lockout").Enabled || len(s.AuditRule("lockout").Channels) != 0 {
		t.Fatalf("after removing the channel %+v, %v", s.AuditAlerts, err)
	}
	if m.Fingerprint() == "" {
		t.Error("settings with an audit alert have no fingerprint")
	}
}

func TestAuditMessageBodies(t *testing.T) {
	a, _ := FindAuditAlert("builtin_signin")
	m := AuditMessage(a, AuditRecord{ID: "abc", Event: audit.Event{Time: t0, Message: "signed in", User: "admin", SourceIP: "203.0.113.7",
		Server: "siem-1", Fields: map[string]string{"source": "builtin"}}}, "https://siem.example.com/#audit")
	if m.headline() != "High: Built-in admin signs in: signed in" {
		t.Errorf("headline %q", m.headline())
	}
	text := m.text("Slack #soc")
	for _, want := range []string{"Audit alert: Built-in admin signs in", "User:", "admin", "From:", "203.0.113.7", "Server:", "siem-1"} {
		if !strings.Contains(text, want) {
			t.Errorf("email text lacks %q:\n%s", want, text)
		}
	}
	b := m.webhookBody(t0)
	if b.Type != KindAudit || b.Audit == nil || b.Finding != nil || b.Audit.ID != "abc" || b.Audit.User != "admin" || b.Audit.Server != "siem-1" {
		t.Errorf("webhook body %+v", b)
	}
	if len(m.buttons(Channel{Type: TypeSlack, SigningSecret: "s"})) != 0 {
		t.Error("an audit message carries buttons")
	}
	slack, _ := json.Marshal(m.slackBody(Channel{Type: TypeSlack, Name: "#soc"}))
	teams, _ := json.Marshal(m.teamsCard(Channel{Type: TypeTeams, Name: "SOC"}))
	for _, body := range []string{string(slack), string(teams)} {
		if !strings.Contains(body, "Built-in admin signs in") || !strings.Contains(body, "203.0.113.7") {
			t.Errorf("chat body lacks the alert: %s", body)
		}
	}
}

func TestAuditAlertsHideTypedNamesThatAreNoAccount(t *testing.T) {
	r, tap := auditRig(t, AuditRuleInput{ID: "signin_failed", Enabled: true, Channels: []string{"aaa"}})
	r.d.KnownUser = func(name string) bool { return name == "alice" }
	known := ev("sign-in failed", map[string]string{"locked_out": "false"})
	typo := ev("sign-in failed", map[string]string{"locked_out": "false"})
	typo.User, typo.Time = "Hunter2!password", typo.Time.Add(time.Second)
	tap.Add(known)
	tap.Add(typo)
	r.clock.add(time.Minute)
	r.pass()
	if r.sender.count("aaa") != 2 {
		t.Fatalf("sent %+v", r.sender.sent)
	}
	got := map[string]bool{}
	for _, s := range r.sender.sent {
		got[s.msg.Entities["user"]] = true
		if b, _ := json.Marshal(s.msg); strings.Contains(string(b), "Hunter2") {
			t.Errorf("a typed name that is no account was sent: %s", b)
		}
	}
	if !got["alice"] || !got[UnknownName] {
		t.Errorf("users sent %v, want alice and %q", got, UnknownName)
	}
}
