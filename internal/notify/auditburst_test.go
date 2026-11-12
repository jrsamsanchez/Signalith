// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/audit"
)

// ssoFlood is the audit record anyone could once write without limit.
func ssoFlood(at time.Time) audit.Event {
	return audit.Event{Time: at, Message: "single sign-on failed", SourceIP: "198.51.100.9",
		Fields: map[string]string{"code": "denied", "reason": "the identity provider answered x: sign in again at https://evil.example/login"}}
}

// A burst of records of little weight used to push the oldest out of the
// tap, whatever they were about, without a word.
func TestAuditTapLetsGoOfTheLeastUrgentFirst(t *testing.T) {
	var logged bytes.Buffer
	r, tap := auditRig(t, AuditRuleInput{ID: "builtin_signin", Enabled: true, Channels: []string{"aaa"}},
		AuditRuleInput{ID: "audit_integrity", Enabled: true, Channels: []string{"aaa"}})
	r.d.Log = slog.New(slog.NewTextHandler(&logged, nil))
	if w := r.d.AuditWarning(); w != "" {
		t.Fatalf("a warning before anything happened: %s", w)
	}
	tap.Add(audit.Event{Time: t0.Add(time.Second), Action: "config.tamper", Message: "config.tamper: shared settings changed outside Signalith"})
	tap.Add(audit.Event{Time: t0.Add(2 * time.Second), Message: "signed in", User: "admin", Fields: map[string]string{"source": "builtin", "role": "admin"}})
	for i := range TapSize + 200 {
		tap.Add(ssoFlood(t0.Add(3*time.Second + time.Duration(i)*time.Millisecond)))
	}
	if got := tap.Dropped(); got != 202 {
		t.Errorf("dropped %d records, want the 202 over TapSize", got)
	}
	r.clock.add(15 * time.Second)
	r.pass()
	var titles []string
	for _, s := range r.sender.sent {
		titles = append(titles, s.msg.Title)
	}
	if len(titles) != 2 || !strings.HasPrefix(titles[0], "Audit records lost or settings tampered with") || !strings.HasPrefix(titles[1], "Built-in admin signs in") {
		t.Fatalf("after the burst the urgent alerts sent were %q", titles)
	}
	// The loss is logged and shown, once.
	if !strings.Contains(logged.String(), "audit records were let go") || !strings.Contains(logged.String(), "dropped=202") {
		t.Errorf("the dropped records were not logged: %s", logged.String())
	}
	if w := r.d.AuditWarning(); !strings.Contains(w, "202") || !strings.Contains(w, "may be missing") {
		t.Errorf("warning %q", w)
	}
	logged.Reset()
	r.clock.add(15 * time.Second)
	r.pass()
	if strings.Contains(logged.String(), "let go") {
		t.Errorf("logged again with nothing new dropped: %s", logged.String())
	}
	r.clock.add(2 * time.Hour)
	if w := r.d.AuditWarning(); w != "" {
		t.Errorf("still warning two hours later: %s", w)
	}
}

// A record less urgent than everything a full tap keeps is the one let go.
func TestAuditTapKeepsTheMoreUrgentWhenFull(t *testing.T) {
	var tap AuditTap
	for i := range TapSize {
		tap.Add(audit.Event{Time: t0.Add(time.Duration(i) * time.Millisecond), Message: "signed in", Fields: map[string]string{"source": "builtin"}})
	}
	tap.Add(ssoFlood(t0.Add(time.Minute)))
	all, _, _ := tap.AuditRecords(context.Background(), auditMatch(AuditAlerts, time.Time{}), TapSize+10)
	if len(all) != TapSize || tap.Dropped() != 1 || all[len(all)-1].Event.Message != "signed in" {
		t.Errorf("kept %d, dropped %d, newest %q", len(all), tap.Dropped(), all[len(all)-1].Event.Message)
	}
	// Reading for one alert is not held up by the records of another.
	a, _ := FindAuditAlert("signin_failed")
	if got, truncated, _ := tap.AuditRecords(context.Background(), auditMatch([]AuditAlert{a}, time.Time{}), 10); len(got) != 0 || truncated {
		t.Errorf("read %d records of an alert the tap holds none of (truncated %v)", len(got), truncated)
	}
}

// fakeAuditIndex answers audit.Matching's searches like OpenSearch does:
// the message filter, the range on @timestamp, oldest first, size and
// search_after. Its events are kept oldest first.
type fakeAuditIndex struct {
	evs []audit.Event
}

func (f *fakeAuditIndex) Search(_ context.Context, _ string, body map[string]any) (map[string]any, error) {
	filter := body["query"].(map[string]any)["bool"].(map[string]any)["filter"].([]any)
	var m audit.Match
	for _, sh := range filter[0].(map[string]any)["bool"].(map[string]any)["should"].([]any) {
		for kind, v := range sh.(map[string]any) {
			for fld, val := range v.(map[string]any) {
				switch {
				case kind == "terms" && fld == "message.keyword":
					m.Messages = val.([]string)
				case kind == "terms":
					m.Actions = val.([]string)
				case fld == "message.keyword":
					m.MessagePrefixes = append(m.MessagePrefixes, val.(string))
				default:
					m.ActionPrefixes = append(m.ActionPrefixes, val.(string))
				}
			}
		}
	}
	start := 0
	if len(filter) > 1 {
		gte := filter[1].(map[string]any)["range"].(map[string]any)["@timestamp"].(map[string]any)["gte"].(string)
		since, _ := time.Parse(time.RFC3339Nano, gte)
		start = sort.Search(len(f.evs), func(i int) bool { return !f.evs[i].Time.Before(since) })
	}
	if after, ok := body["search_after"].([]any); ok {
		n, _ := strconv.Atoi(fmt.Sprint(after[0]))
		start = n + 1
	}
	hits := []any{}
	for i := start; i < len(f.evs) && len(hits) < body["size"].(int); i++ {
		if m.Selects(f.evs[i]) {
			hits = append(hits, map[string]any{"_index": "x_audit-2026.10", "_id": fmt.Sprint("d", i), "_source": f.evs[i], "sort": []any{i}})
		}
	}
	return map[string]any{"hits": map[string]any{"hits": hits}}, nil
}

// In a cluster a steady trickle of failed sign-ons, more than one pass
// reads, used to keep every other audit alert from being read at all.
func TestAuditAlertsAreReadMostUrgentFirstFromTheIndex(t *testing.T) {
	var logged bytes.Buffer
	r, _ := auditRig(t,
		AuditRuleInput{ID: "audit_integrity", Enabled: true, Channels: []string{"aaa"}},
		AuditRuleInput{ID: "builtin_signin", Enabled: true, Channels: []string{"aaa"}},
		AuditRuleInput{ID: "lockout", Enabled: true, Channels: []string{"aaa"}},
		AuditRuleInput{ID: "signin_failed", Enabled: true, Channels: []string{"bbb"}})
	r.d.Log = slog.New(slog.NewTextHandler(&logged, nil))
	idx := &fakeAuditIndex{}
	r.d.Audit = func() AuditSource { return AuditIndex{Client: idx, Prefix: "x"} }
	// More failed sign-ons than two passes read, and only then the
	// records that matter.
	const flood = 2*MaxAudit + 500
	at := t0.Add(time.Second)
	for i := range flood {
		idx.evs = append(idx.evs, ssoFlood(at.Add(time.Duration(i)*time.Millisecond)))
	}
	late := at.Add(flood * time.Millisecond)
	idx.evs = append(idx.evs,
		audit.Event{Time: late, Action: "config.tamper", Message: "config.tamper: shared settings were changed in OpenSearch outside Signalith"},
		audit.Event{Time: late.Add(time.Millisecond), Message: "signed in", User: "admin", Fields: map[string]string{"source": "builtin"}},
		audit.Event{Time: late.Add(2 * time.Millisecond), Message: "sign-in failed", User: "alice", Fields: map[string]string{"locked_out": "true"}})
	r.clock.add(time.Minute)
	r.pass()
	var titles []string
	for _, s := range r.sender.sent {
		if s.channel == "aaa" {
			titles = append(titles, s.msg.Title)
		}
	}
	if len(titles) != 2 || !strings.HasPrefix(titles[0], "Audit records lost or settings tampered with") || !strings.HasPrefix(titles[1], "Built-in admin signs in") {
		t.Fatalf("the first pass sent the security channel %q, want the tampering and the built-in admin's sign-in", titles)
	}
	// The noisy alerts are behind, which is logged and shown, and catch
	// up over the next passes without losing the lockout.
	if w := r.d.AuditWarning(); !strings.Contains(w, "Sign-ins locked out") || !strings.Contains(w, "Failed sign-ins and refused tokens") || strings.Contains(w, "Built-in admin") {
		t.Errorf("warning %q", w)
	}
	if n := strings.Count(logged.String(), "more audit records matched an audit alert"); n != 2 {
		t.Errorf("logged %d alerts as behind, want 2: %s", n, logged.String())
	}
	for range 3 {
		r.clock.add(Interval)
		r.pass()
	}
	lockouts := 0
	for _, s := range r.sender.sent {
		if s.channel == "aaa" && strings.HasPrefix(s.msg.Title, "Sign-ins locked out") {
			lockouts++
		}
	}
	if lockouts != 1 {
		t.Errorf("the lockout behind the flood was sent %d times, want once", lockouts)
	}
	if w := r.d.AuditWarning(); w != "" {
		t.Errorf("still warning once everything was read: %s", w)
	}
}

// A server that could not reach OpenSearch writes its audit records
// later, with the time they were logged at: more than Window late, they
// used never to be sent.
func TestAuditAlertForARecordThatArrivesLate(t *testing.T) {
	r, tap := auditRig(t, AuditRuleInput{ID: "builtin_signin", Enabled: true, Channels: []string{"aaa"}})
	r.clock.add(time.Minute)
	r.pass()
	r.clock.add(45 * time.Minute)
	r.pass()
	tap.Add(audit.Event{Time: t0.Add(10 * time.Minute), Message: "signed in", User: "admin", Fields: map[string]string{"source": "builtin"}})
	for range 4 {
		r.clock.add(AuditSweepEvery / 3)
		r.pass()
	}
	if n := r.sender.count("aaa"); n != 1 {
		t.Fatalf("the late sign-in of the built-in admin was sent %d times, want once", n)
	}
	// And not again by the looks that follow.
	for range 6 {
		r.clock.add(AuditSweepEvery / 2)
		r.pass()
	}
	if n := r.sender.count("aaa"); n != 1 {
		t.Errorf("sent %d times after more passes", n)
	}
}

// Ten lockouts in one pass used to leave an admin's sign-in and a new
// token to "And 3 more audit alerts".
func TestAuditAlertFloodKeepsOneOfEachAlert(t *testing.T) {
	var all []AuditRuleInput
	for _, a := range AuditAlerts {
		all = append(all, AuditRuleInput{ID: a.ID, Enabled: true, Channels: []string{"aaa"}})
	}
	r, tap := auditRig(t, all...)
	for i := range 12 {
		e := ev("sign-in failed", map[string]string{"locked_out": "true"})
		e.Time = t0.Add(time.Minute + time.Duration(i)*time.Millisecond)
		tap.Add(e)
	}
	a := ev("signed in", map[string]string{"role": "admin", "source": "local"})
	a.Time = t0.Add(time.Minute + time.Second)
	tap.Add(a)
	for i := range 2 {
		tap.Add(audit.Event{Time: t0.Add(time.Minute + time.Duration(2+i)*time.Second), Message: "api_token.create: API token made", Action: "api_token.create", User: "alice"})
	}
	r.clock.add(2 * time.Minute)
	r.pass()
	if n := r.sender.count("aaa"); n != FloodLimit {
		t.Fatalf("sent %d messages, want %d", n, FloodLimit)
	}
	var titles []string
	for _, s := range r.sender.sent {
		titles = append(titles, s.msg.Title)
	}
	own := strings.Join(titles[:FloodLimit-1], "\n")
	if !strings.Contains(own, "An admin signs in: signed in") || !strings.Contains(own, "Tokens made or revoked: api_token.create") {
		t.Errorf("an alert was left to the summary alone:\n%s", strings.Join(titles, "\n"))
	}
	if !strings.HasPrefix(titles[0], "Sign-ins locked out") {
		t.Errorf("the most urgent did not go first: %q", titles[0])
	}
	last := r.sender.sent[FloodLimit-1].msg
	if last.Kind != KindAuditSummary || last.Count != 6 || last.Title != "And 6 more audit alerts: Sign-ins locked out (5), Tokens made or revoked (1)" {
		t.Errorf("summary %+v", last)
	}
}

// The reason of a failed single sign-on can quote what an anonymous
// sender put in the callback, so a message never carries it.
func TestAuditMessageOfAFailedSingleSignOnCarriesOnlyTheCode(t *testing.T) {
	a, _ := FindAuditAlert("signin_failed")
	m := AuditMessage(a, AuditRecord{ID: "r1", Event: ssoFlood(t0)}, "")
	if m.AuditReason != "code denied (the audit log says more)" {
		t.Errorf("reason %q", m.AuditReason)
	}
	for _, c := range []Channel{{Type: TypeSlack}, {Type: TypeWebhook}, {Type: TypeEmail}} {
		if b := fmt.Sprint(m.webhookBody(t0), m.text(c.Label())); strings.Contains(b, "evil.example") {
			t.Errorf("the sender's text is in the message: %s", b)
		}
	}
	// Other records keep their reason.
	other := AuditMessage(a, AuditRecord{ID: "r2", Event: ev("sign-in failed", map[string]string{"reason": "wrong password"})}, "")
	if other.AuditReason != "wrong password" {
		t.Errorf("reason of a failed password sign-in: %q", other.AuditReason)
	}
}

func TestAuditLosses(t *testing.T) {
	r, _ := auditRig(t,
		AuditRuleInput{ID: "builtin_signin", Enabled: true, Channels: []string{"aaa", "bbb"}},
		AuditRuleInput{ID: "lockout", Enabled: true, Channels: []string{"aaa"}})
	old, _ := r.set.Settings()
	chans := []ChannelInput{{ID: "aaa", Name: "#soc", Type: TypeSlack}, {ID: "bbb", Name: "SOAR", Type: TypeWebhook}}
	save := func(in Input) (cur, next Settings) {
		t.Helper()
		calls := 0
		if _, err := r.set.SaveAfter(in, func(c, n Settings) { cur, next, calls = c, n, calls+1 }); err != nil || calls != 1 {
			t.Fatalf("save: %v (asked %d times)", err, calls)
		}
		// Back to how it was, for the next case.
		rules := []AuditRuleInput{{ID: "builtin_signin", Enabled: true, Channels: []string{"aaa", "bbb"}}, {ID: "lockout", Enabled: true, Channels: []string{"aaa"}}}
		if _, err := r.set.Save(Input{Channels: []ChannelInput{slackInput("aaa", "https://hooks.example.com/a"),
			{ID: "bbb", Name: "SOAR", Type: TypeWebhook, URL: "https://soar.example.com/hook"}}, AuditAlerts: &rules}); err != nil {
			t.Fatal(err)
		}
		return cur, next
	}
	if l := AuditLosses(old, old); len(l) != 0 {
		t.Fatalf("no change, yet %+v", l)
	}
	// A save that changes something else takes nothing away.
	renamed := []ChannelInput{{ID: "aaa", Name: "#soc-2", Type: TypeSlack}, chans[1]}
	if l := AuditLosses(save(Input{Channels: renamed})); len(l) != 0 {
		t.Errorf("a renamed channel: %+v", l)
	}
	// Every alert off.
	off := []AuditRuleInput{}
	l := AuditLosses(save(Input{Channels: chans, AuditAlerts: &off}))
	if len(l) != 2 || l[0].Channel.ID != "aaa" || l[0].Channel.URL != "https://hooks.example.com/a" || len(l[0].Alerts) != 2 || l[0].Removed || l[0].Moved ||
		len(l[1].Alerts) != 1 || l[1].What() != "No longer sent here: Built-in admin signs in." {
		t.Errorf("all turned off: %+v", l)
	}
	// One channel taken off one alert.
	fewer := []AuditRuleInput{{ID: "builtin_signin", Enabled: true, Channels: []string{"aaa"}}, {ID: "lockout", Enabled: true, Channels: []string{"aaa"}}}
	if l := AuditLosses(save(Input{Channels: chans, AuditAlerts: &fewer})); len(l) != 1 || l[0].Channel.ID != "bbb" {
		t.Errorf("a channel taken off an alert: %+v", l)
	}
	// The channel removed: its alerts go with it.
	l = AuditLosses(save(Input{Channels: chans[:1]}))
	if len(l) != 1 || l[0].Channel.ID != "bbb" || !l[0].Removed || !strings.Contains(l[0].What(), "removed") {
		t.Errorf("a channel removed: %+v", l)
	}
	// The channel sent elsewhere, with every alert still on.
	moved := []ChannelInput{chans[0], {ID: "bbb", Name: "SOAR", Type: TypeWebhook, URL: "https://elsewhere.example.net/hook"}}
	l = AuditLosses(save(Input{Channels: moved}))
	if len(l) != 1 || l[0].Channel.ID != "bbb" || !l[0].Moved || l[0].Channel.URL != "https://soar.example.com/hook" || len(l[0].Alerts) != 0 {
		t.Errorf("a channel's address changed: %+v", l)
	}
	// A save that is refused asks nothing.
	bad := []AuditRuleInput{{ID: "nope", Enabled: true}}
	if _, err := r.set.SaveAfter(Input{Channels: chans, AuditAlerts: &bad}, func(Settings, Settings) { t.Error("asked for a save that was refused") }); err == nil {
		t.Error("a bad save was taken")
	}
}

func TestSendAuditLosses(t *testing.T) {
	r, _ := auditRig(t, AuditRuleInput{ID: "builtin_signin", Enabled: true, Channels: []string{"aaa", "bbb"}})
	old, _ := r.set.Settings()
	losses := AuditLosses(old, Settings{Channels: old.Channels[:1]})
	if len(losses) != 2 {
		t.Fatalf("losses %+v", losses)
	}
	if failed := SendAuditLosses(context.Background(), r.sender, r.store, losses, "mallory", "198.51.100.9", "siem-a", "https://siem.example.com/#audit", r.clock.Now); failed != 0 {
		t.Fatalf("%d failed", failed)
	}
	if r.sender.count("aaa") != 1 || r.sender.count("bbb") != 1 {
		t.Fatalf("sent %+v", r.sender.sent)
	}
	for _, s := range r.sender.sent {
		m := s.msg
		if m.Kind != KindAudit || m.Urgency != "critical" || m.Entities["user"] != "mallory" || m.Entities["src"] != "198.51.100.9" ||
			m.AuditServer != "siem-a" || !strings.Contains(m.AuditReason, "Built-in admin signs in") {
			t.Errorf("message %+v", m)
		}
		if s.channel == "bbb" && (m.Title != "This channel was removed and gets no more audit alerts" || !strings.Contains(m.text("x"), "mallory")) {
			t.Errorf("to the removed channel: %+v", m)
		}
	}
	list, _ := r.store.Recent(context.Background(), 10)
	if len(list) != 2 || list[0].Kind != KindAudit || list[0].Status != StatusSent {
		t.Errorf("deliveries %+v", list)
	}
	// One that fails is recorded as failed for good: the dispatcher must
	// not send it again, to wherever the channel points now.
	r.sender.fail = fmt.Errorf("down")
	if failed := SendAuditLosses(context.Background(), r.sender, r.store, losses[:1], "mallory", "", "siem-a", "", r.clock.Now); failed != 1 {
		t.Errorf("%d failed, want 1", failed)
	}
	r.sender.fail = nil
	r.clock.add(2 * time.Hour)
	before := r.sender.count("")
	r.pass()
	if r.sender.count("") != before {
		t.Errorf("a failed last message was sent again")
	}
}
