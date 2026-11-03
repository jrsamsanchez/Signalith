// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/audit"
)

// Audit alerts tell admins about Signalith's own audit records: sign-ins
// to admin accounts, failed sign-ins and lockouts, changes to users,
// tenants, tokens and settings, deletions, and audit records that were
// lost or settings changed outside Signalith. They are built in: each is
// off until an admin turns it on and picks the channels it goes to, on
// the Notifications page (Settings.AuditAlerts).
//
// They never become findings, so the audit records they are about stay
// out of the Findings page, of search and of everyone but admins. Only
// the server that runs the background jobs sends them, like findings,
// and each audit record goes to a channel at most once.

// AuditAlert is one built-in audit alert: which audit records it is
// about, and how urgent a message about one is.
type AuditAlert struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Urgency     string `json:"urgency"`
	// Noisy is set on an alert that can send many messages on a server
	// reachable from the internet, so the page can say so.
	Noisy bool `json:"noisy,omitempty"`

	// The records it is about: a message that is one of messages or
	// starts with one of prefixes, or an action that is one of actions or
	// starts with one of actionPrefixes, and that check, when set, takes.
	messages       []string
	prefixes       []string
	actions        []string
	actionPrefixes []string
	check          func(audit.Event) bool
}

// Matches reports whether an audit record is one the alert is about.
func (a AuditAlert) Matches(ev audit.Event) bool {
	hit := slices.Contains(a.messages, ev.Message) || slices.Contains(a.actions, ev.Action)
	for _, p := range a.prefixes {
		hit = hit || strings.HasPrefix(ev.Message, p)
	}
	for _, p := range a.actionPrefixes {
		hit = hit || strings.HasPrefix(ev.Action, p)
	}
	return hit && (a.check == nil || a.check(ev))
}

// field returns an audit record's field.
func field(ev audit.Event, k string) string { return ev.Fields[k] }

// The failed sign-in messages of the sign-in page, single sign-on, the
// two-step code, passkeys and password changes.
var failedSignIns = []string{"sign-in failed", "single sign-on failed", "two-step code refused", "passkey refused", "password change refused"}

// typedName reports whether an audit record's user is a name someone
// typed to sign in, which may be anything, a password typed in the wrong
// box among them, rather than an account Signalith knows.
func typedName(ev audit.Event) bool { return slices.Contains(failedSignIns, ev.Message) }

// UnknownName stands for a typed sign-in name that is no known account,
// in place of the name itself.
const UnknownName = "(not a known account)"

// addressPaused starts the record logged when sign-ins from one address
// are paused after too many wrong passwords.
const addressPaused = "sign-ins from this address are paused"

// AuditAlerts are the built-in audit alerts, in the order the page lists
// them. A record that more than one matches goes to a channel once, as
// the first of them.
var AuditAlerts = []AuditAlert{
	{
		ID: "audit_integrity", Name: "Audit records lost or settings tampered with", Urgency: "critical",
		Description: "Audit records could not be kept, or shared settings, the cluster document or a sign-in session were changed in OpenSearch outside Signalith.",
		actions:     []string{audit.ActionLost, "config.tamper", "session.tamper"},
		messages: []string{
			"a response action was not run: its audit record could not be written",
			"a response action ran but its result could not be written to the audit log",
		},
	},
	{
		ID: "builtin_signin", Name: "Built-in admin signs in", Urgency: "high",
		Description: "Someone signs in as the built-in admin. Most teams keep it for emergencies, or turn it off once they have admins of their own.",
		messages:    []string{"signed in"},
		check:       func(ev audit.Event) bool { return field(ev, "source") == "builtin" },
	},
	{
		ID: "lockout", Name: "Sign-ins locked out", Urgency: "high",
		Description: "Too many wrong passwords or codes lock an account, or pause sign-ins from one address.",
		messages:    failedSignIns,
		prefixes:    []string{addressPaused},
		check: func(ev audit.Event) bool {
			return strings.HasPrefix(ev.Message, addressPaused) || field(ev, "locked_out") == "true"
		},
	},
	{
		ID: "access_change", Name: "Users, roles and two-step sign-in change", Urgency: "high",
		Description: "A user is added, changed, turned off or deleted, gets another role or a new password, or loses two-step sign-in; or the directory settings change.",
		messages: []string{
			"user created", "user changed", "user deleted", "user disabled", "user enabled", "user role changed",
			"password reset", "two-step sign-in turned off", "two-step sign-in reset", "authenticator app turned off",
			"passkeys removed", "directory user's role changed", "directory user lost access", "directory settings changed",
		},
		actions: []string{"users.create"},
	},
	{
		ID: "tenant_change", Name: "Tenants change", Urgency: "high",
		Description:    "A tenant is added, renamed, turned off or on.",
		actionPrefixes: []string{"tenants."},
		check:          func(ev audit.Event) bool { return ev.Action != "tenants.switch" },
	},
	{
		ID: "token_change", Name: "Tokens made or revoked", Urgency: "medium",
		Description: "An API, agent, SCIM, metrics or cluster join token is made or revoked.",
		messages: []string{
			"agent token created", "agent token revoked", "SCIM token created", "metrics scrape token created",
			"join token made", "join token revoked", "shared agent token accepted again",
		},
		actions: []string{"api_token.create", "api_token.revoke"},
	},
	{
		ID: "settings_change", Name: "Settings change", Urgency: "medium",
		Description: "Settings, notifications, retention, ticketing, agent collection or the cluster's keys and certificate authority change.",
		messages: []string{
			"settings saved", "notification settings changed", "retention settings changed", "ticketing connections changed",
			"agent collection settings changed", "endpoint settings saved", "vulnerability scan settings saved",
			"accepted the shared settings restored in OpenSearch", "cluster key rotation asked for",
			"certificate authority chosen for the cluster", "asked to replace the cluster's certificate authority",
		},
	},
	{
		ID: "deletions", Name: "Deletions", Urgency: "medium",
		Description: "Detections, lookup tables, threat intel, parsers, content updates, endpoints, servers, sample data or a retention run started by hand delete what they hold.",
		messages: []string{
			"lookup table deleted", "custom parser deleted", "content update removed", "endpoint removed",
			"sample data remove started", "hunting notebook deleted", "case file removed", "retention run started by hand",
		},
		actions: []string{"detection.delete", "intel.feed_delete", "intel.indicator_delete", "cluster.remove"},
	},
	{
		ID: "admin_signin", Name: "An admin signs in", Urgency: "medium",
		Description: "Someone with the admin role signs in, other than the built-in admin.",
		messages:    []string{"signed in"},
		check: func(ev audit.Event) bool {
			return field(ev, "role") == "admin" && field(ev, "source") != "builtin"
		},
	},
	{
		ID: "signin_failed", Name: "Failed sign-ins and refused tokens", Urgency: "low", Noisy: true,
		Description: "Every wrong password or code, failed single sign-on, and refused API, SCIM or agent token. On a server the internet can reach this can send many messages; Sign-ins locked out sends far fewer.",
		messages:    append(slices.Clone(failedSignIns), "SCIM token refused", "shared agent token refused"),
		actions:     []string{"api_token.refused"},
	},
}

// FindAuditAlert returns the built-in audit alert with an ID.
func FindAuditAlert(id string) (AuditAlert, bool) {
	for _, a := range AuditAlerts {
		if a.ID == id {
			return a, true
		}
	}
	return AuditAlert{}, false
}

// AuditRule turns one built-in audit alert on and says where it goes.
type AuditRule struct {
	// ID is the alert's (AuditAlert.ID).
	ID       string   `yaml:"id" json:"id"`
	Enabled  bool     `yaml:"enabled" json:"enabled"`
	Channels []string `yaml:"channels" json:"channels"`
	// Since is when the alert was last turned on: only records logged
	// from then on are sent.
	Since time.Time `yaml:"since" json:"since"`
}

// AuditRule returns the rule of an audit alert, off when there is none.
func (s Settings) AuditRule(id string) AuditRule {
	for _, r := range s.AuditAlerts {
		if r.ID == id {
			return r
		}
	}
	return AuditRule{ID: id, Channels: []string{}}
}

// auditMatch is what a source reads for the alerts in rules: every
// record any of them may be about.
func auditMatch(alerts []AuditAlert, since time.Time) audit.Match {
	m := audit.Match{Since: since}
	add := func(dst *[]string, list []string) {
		for _, v := range list {
			if !slices.Contains(*dst, v) {
				*dst = append(*dst, v)
			}
		}
	}
	for _, a := range alerts {
		add(&m.Messages, a.messages)
		add(&m.MessagePrefixes, a.prefixes)
		add(&m.Actions, a.actions)
		add(&m.ActionPrefixes, a.actionPrefixes)
	}
	return m
}

// AuditRecord is an audit record a source read, with its ID.
type AuditRecord struct {
	ID    string
	Event audit.Event
}

// AuditSource reads the audit records the alerts may be about.
type AuditSource interface {
	// AuditRecords returns the records m selects, oldest first, at most
	// limit of them; truncated is true when there were more.
	AuditRecords(ctx context.Context, m audit.Match, limit int) (list []AuditRecord, truncated bool, err error)
}

// AuditIndex reads the audit records of every server from the audit
// indices in OpenSearch, where they are kept once servers share one
// OpenSearch as a cluster.
type AuditIndex struct {
	Client audit.Searcher
	Prefix string
}

// AuditRecords implements AuditSource.
func (a AuditIndex) AuditRecords(ctx context.Context, m audit.Match, limit int) ([]AuditRecord, bool, error) {
	hits, truncated, err := audit.Matching(ctx, a.Client, a.Prefix, m, limit)
	if err != nil {
		return nil, false, err
	}
	out := make([]AuditRecord, len(hits))
	for i, h := range hits {
		out[i] = AuditRecord{ID: h.ID, Event: h.Event}
	}
	return out, truncated, nil
}

// AuditTap keeps, in memory, the audit records this server logs that an
// audit alert may be about, for a server whose audit records are kept
// only in its log (audit.Sink.SetTap hands them over). It keeps at most
// TapSize of them, for at most CatchUp.
type AuditTap struct {
	mu   sync.Mutex
	list []AuditRecord
	// dropped counts records let go because there were too many.
	dropped int64
}

// TapSize is the most records an AuditTap keeps.
const TapSize = 5000

// Add keeps ev when an audit alert may be about it. It returns at once.
func (t *AuditTap) Add(ev audit.Event) {
	if !slices.ContainsFunc(AuditAlerts, func(a AuditAlert) bool { return a.Matches(ev) }) {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	rec := AuditRecord{ID: tapID(ev), Event: ev}
	t.mu.Lock()
	defer t.mu.Unlock()
	cut := 0
	old := ev.Time.Add(-CatchUp)
	for cut < len(t.list) && t.list[cut].Event.Time.Before(old) {
		cut++
	}
	if len(t.list)-cut >= TapSize {
		t.dropped += int64(len(t.list) - cut - TapSize + 1)
		cut = len(t.list) - TapSize + 1
	}
	if cut > 0 {
		t.list = slices.Delete(t.list, 0, cut)
	}
	t.list = append(t.list, rec)
}

// Dropped returns how many records were let go because there were more
// than TapSize.
func (t *AuditTap) Dropped() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dropped
}

// AuditRecords implements AuditSource.
func (t *AuditTap) AuditRecords(_ context.Context, m audit.Match, limit int) ([]AuditRecord, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []AuditRecord
	for _, r := range t.list {
		if r.Event.Time.Before(m.Since) {
			continue
		}
		if len(out) == limit {
			return out, true, nil
		}
		out = append(out, r)
	}
	return out, false, nil
}

// tapID is the ID of a record a tap keeps: a hash of what it says, as it
// has no document ID.
func tapID(ev audit.Event) string {
	h := sha256.New()
	for _, v := range []string{ev.Time.UTC().Format(time.RFC3339Nano), ev.Message, ev.User, ev.Target, ev.SourceIP, ev.Action} {
		h.Write([]byte(v))
		h.Write([]byte{0})
	}
	keys := make([]string, 0, len(ev.Fields))
	for k := range ev.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		h.Write([]byte(k + "=" + ev.Fields[k]))
		h.Write([]byte{0})
	}
	return "tap-" + hex.EncodeToString(h.Sum(nil))[:24]
}

// AuditDeliveryID is the delivery of an audit record to a channel.
func AuditDeliveryID(recordID, channelID string) string {
	return DeliveryID("audit:"+recordID, channelID)
}

// AuditLink returns the link to the Audit page of the Signalith at
// publicURL, or "" when it is not known.
func AuditLink(publicURL string) string {
	publicURL = strings.TrimRight(strings.TrimSpace(publicURL), "/")
	if publicURL == "" {
		return ""
	}
	return publicURL + "/#audit"
}

// AuditMessage returns the message about an audit record that alert a
// matched. Like a finding's, it never holds the whole record: only what
// happened, who did it, from where, to what, on which server and tenant,
// and why a sign-in failed.
func AuditMessage(a AuditAlert, rec AuditRecord, link string) Message {
	ev := rec.Event
	what := clean(ev.Message, 200)
	if what == "" {
		what = clean(ev.Action, 100)
	}
	m := Message{
		Kind: KindAudit, AuditID: clean(rec.ID, 100), Title: clean(a.Name+": "+what, maxTitle), Urgency: a.Urgency,
		AuditAlert: clean(a.Name, 100), AuditAction: clean(ev.Action, 100), Created: ev.Time.UTC(), Link: link,
		AuditTarget: clean(ev.Target, maxEntity), AuditServer: clean(ev.Server, 200),
		AuditTenant: clean(field(ev, "tenant"), 100), AuditReason: clean(field(ev, "reason"), maxEntity),
	}
	if u := clean(ev.User, maxEntity); u != "" {
		m.Entities = map[string]string{"user": u}
	}
	if ip := clean(ev.SourceIP, maxEntity); ip != "" {
		if m.Entities == nil {
			m.Entities = map[string]string{}
		}
		m.Entities["src"] = ip
	}
	return m
}

// auditSummaryMessage stands for count audit alerts sent in one message.
func auditSummaryMessage(count int, link string, now time.Time) Message {
	return Message{Kind: KindAuditSummary, Title: fmt.Sprintf("And %d more %s", count, plural(count, "audit alert", "audit alerts")),
		Count: count, Link: link, Created: now.UTC()}
}
