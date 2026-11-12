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
	"strconv"
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
var failedSignIns = []string{"sign-in failed", ssoFailed, "two-step code refused", "passkey refused", "password change refused"}

// ssoFailed is the record of a failed single sign-on.
const ssoFailed = "single sign-on failed"

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
		Description: "Audit records could not be kept; shared settings, the cluster document or a sign-in session were changed in OpenSearch outside Signalith; the cluster key was exported or imported; or a passkey that may have been copied was used.",
		actions:     []string{audit.ActionLost, "config.tamper", "session.tamper"},
		messages: []string{
			"a response action was not run: its audit record could not be written",
			"a response action ran but its result could not be written to the audit log",
			"exported the cluster key", "imported a cluster key",
			"refused to run a request: it may have been forged or replayed by someone who can write to OpenSearch",
			"shared documents that no cluster key signed were not signed with the new key",
			"the rule tuning stored in OpenSearch fails the checks of a save: no sensor gets it until an admin saves it again",
			"passkey refused: its counter went backwards, so it may have been copied",
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
		Description: "A user is added, changed, turned off or deleted, gets another role or a new password, adds or removes a passkey, makes or uses a recovery code, links a chat account or loses two-step sign-in; the built-in admin is turned on again, renamed or gets a new password; or the directory settings change.",
		messages: []string{
			"user created", "user changed", "user deleted", "user disabled", "user enabled", "user role changed",
			"password reset", "password changed", "two-step sign-in turned off", "two-step sign-in reset", "authenticator app turned off",
			"passkey added", "passkey removed", "passkeys removed", "new recovery codes made", "recovery code used",
			"chat account linked",
			"turned the built-in admin on again", "changed the built-in admin's password for every server of the cluster",
			"renamed the built-in admin for every server of the cluster",
			"directory user's role changed", "directory user lost access", "directory settings changed",
		},
		actions: []string{"users.create"},
	},
	{
		ID: "detection_change", Name: "Detections, exceptions and responses change", Urgency: "high",
		Description: "Detections are saved or turned off; a content update is uploaded or a lookup table saved; an exception is added or approved for one detection, many or from a finding; sensor rule tuning or behavior baselines change; response actions or playbooks change; or an endpoint is unblocked.",
		actions: []string{
			"detection.enable", "detection.save", "detection.exception_add", "detection.scoped_exception_add",
			"finding.suppress", "respond.change", "playbook.change",
		},
		messages: []string{
			"detection exception approved", "sensor rule tuning saved", "behavior baseline settings saved",
			"behavior baseline reset", "endpoint unblocked", "content update uploaded", "lookup table saved",
		},
		// Turning detections on is no way to hide anything.
		check: func(ev audit.Event) bool { return ev.Action != "detection.enable" || field(ev, "enabled") != "true" },
	},
	{
		ID: "tenant_change", Name: "Tenants change", Urgency: "high",
		Description:    "A tenant is added, renamed, turned off or on.",
		actionPrefixes: []string{"tenants."},
		check:          func(ev audit.Event) bool { return ev.Action != "tenants.switch" },
	},
	{
		ID: "token_change", Name: "Tokens made or revoked", Urgency: "medium",
		Description: "An API, agent, SCIM, metrics or cluster join token is made or revoked, or a server is approved to join the cluster, joins it, or is refused because it is not the one expected.",
		messages: []string{
			"agent token created", "agent token revoked", "SCIM token created", "metrics scrape token created",
			"join token made", "join token revoked", "shared agent token accepted again",
			"server approved to join the cluster",
			"cluster.approve refused: the fingerprint does not match",
			"cluster.approve refused: the server would take another member's place",
		},
		actions: []string{"api_token.create", "api_token.revoke", "cluster.approve", "cluster.join"},
	},
	{
		ID: "settings_change", Name: "Settings change", Urgency: "medium",
		Description: "Settings, notifications, retention, ticketing, agent collection or the cluster's keys and certificate authority change, or the shared settings are exported to files.",
		messages: []string{
			"settings saved", "notification settings changed", "retention settings changed", "ticketing connections changed",
			"agent collection settings changed", "endpoint settings saved", "vulnerability scan settings saved",
			"accepted the shared settings restored in OpenSearch", "cluster key rotation asked for",
			"certificate authority chosen for the cluster", "asked to replace the cluster's certificate authority",
			"exported the shared settings to files", "asked for a rotation of the cluster key",
			"made a new cluster key and signed the shared settings with it",
			"asked a server to publish its certificate authority as the cluster's",
			"published this server's certificate authority as the cluster's, as an admin chose",
			"gave the cluster its certificate authority's key again", "founded the cluster from the command line",
			"reset a shared setting to its default for every server of the cluster", "reset one of this server's own settings",
			"restored the shared settings from this server's copy", "retired the shared settings for a downgrade",
			"new web address confirmed", "vulnerability scan login saved",
		},
		actions: []string{"retention.confirm"},
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
		ID: "live_query", Name: "Live queries run on endpoints", Urgency: "medium",
		Description: "Someone sends a live query to endpoints, which can read their files and registry.",
		messages:    []string{"live query sent"},
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
// TapSize of them, for at most CatchUp. When there are more it lets go
// of the least urgent first, so a burst of records of little weight
// (failed sign-ins, say) never pushes out one an urgent alert is about.
type AuditTap struct {
	mu   sync.Mutex
	list []AuditRecord
	// rank is, for each record of list, the urgency of the most urgent
	// alert that matches it.
	rank []int
	// dropped counts records let go because there were too many.
	dropped int64
}

// TapSize is the most records an AuditTap keeps.
const TapSize = 5000

// Add keeps ev when an audit alert may be about it. It returns at once.
func (t *AuditTap) Add(ev audit.Event) {
	rank := -1
	for _, a := range AuditAlerts {
		if a.Matches(ev) {
			rank = max(rank, urgencyRank(a.Urgency))
		}
	}
	if rank < 0 {
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
	if cut > 0 {
		t.list, t.rank = slices.Delete(t.list, 0, cut), slices.Delete(t.rank, 0, cut)
	}
	if len(t.list) >= TapSize {
		// Full: the oldest of the least urgent goes, or this record when
		// everything kept is more urgent than it.
		t.dropped++
		least := slices.Min(t.rank)
		if rank < least {
			return
		}
		i := slices.Index(t.rank, least)
		t.list, t.rank = slices.Delete(t.list, i, i+1), slices.Delete(t.rank, i, i+1)
	}
	t.list, t.rank = append(t.list, rec), append(t.rank, rank)
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
		if !m.Selects(r.Event) {
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
	if ev.Message == ssoFailed {
		// The reason of a failed single sign-on may quote text the sender
		// or the identity provider chose, so the message carries only the
		// sign-in page's code for it; the audit log has the rest.
		m.AuditReason = ""
		if code := clean(field(ev, "code"), 40); code != "" {
			m.AuditReason = "code " + code + " (the audit log says more)"
		}
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

// auditSummaryMessage stands for the audit alerts in names (an alert's
// name once for each record) sent in one message. It says how many of
// each alert there are, so none is hidden behind a count.
func auditSummaryMessage(names []string, link string, now time.Time) Message {
	count := len(names)
	title := fmt.Sprintf("And %d more %s", count, plural(count, "audit alert", "audit alerts"))
	var order []string
	per := map[string]int{}
	for _, n := range names {
		if n == "" {
			continue
		}
		if per[n] == 0 {
			order = append(order, n)
		}
		per[n]++
	}
	for i, n := range order {
		sep := ", "
		if i == 0 {
			sep = ": "
		}
		title += fmt.Sprintf("%s%s (%d)", sep, n, per[n])
	}
	return Message{Kind: KindAuditSummary, Title: clean(title, maxTitle), Count: count, Link: link, Created: now.UTC()}
}

// AuditLoss is what a change to the notification settings takes from a
// channel that audit alerts went to.
type AuditLoss struct {
	// Channel is the channel as it was before the change.
	Channel Channel
	// Alerts names the audit alerts that no longer go to it: they were
	// turned off, or the channel was taken off them.
	Alerts []string
	// Removed says the channel was deleted, and Moved that it stays but
	// sends to another address.
	Removed, Moved bool
}

// What says what was lost, as a sentence or more.
func (l AuditLoss) What() string {
	var out []string
	switch {
	case l.Removed:
		out = append(out, "This channel was removed from Signalith.")
	case l.Moved:
		out = append(out, "The address this channel sends to was changed, so later audit alerts go elsewhere.")
	}
	if len(l.Alerts) > 0 {
		out = append(out, "No longer sent here: "+strings.Join(l.Alerts, ", ")+".")
	}
	return strings.Join(out, " ")
}

// address is where a channel sends to, to tell whether it was moved.
func (c Channel) address() string {
	return strings.Join([]string{c.Type, c.URL, c.Host, strconv.Itoa(c.Port), strings.Join(c.To, ","), c.AppID, c.TenantID}, "\x00")
}

// AuditLosses returns what a change of the settings from old to next
// takes from each channel that audit alerts were going to under old: an
// alert turned off or no longer sent to it, the channel removed, or its
// address changed. Whoever watched that channel would otherwise hear
// nothing more and not know why, which is what someone hiding their
// tracks wants.
func AuditLosses(old, next Settings) []AuditLoss {
	var out []AuditLoss
	for _, c := range old.Channels {
		l := AuditLoss{Channel: c}
		watching := false
		for _, a := range AuditAlerts {
			was := old.AuditRule(a.ID)
			if !was.Enabled || !slices.Contains(was.Channels, c.ID) {
				continue
			}
			watching = true
			if now := next.AuditRule(a.ID); !now.Enabled || !slices.Contains(now.Channels, c.ID) {
				l.Alerts = append(l.Alerts, a.Name)
			}
		}
		if !watching {
			continue
		}
		if nc, ok := next.Channel(c.ID); !ok {
			l.Removed = true
		} else if nc.address() != c.address() {
			l.Moved = true
		}
		if l.Removed || l.Moved || len(l.Alerts) > 0 {
			out = append(out, l)
		}
	}
	return out
}

// AuditLossMessage is the last message to a channel about what it loses:
// who made the change, from where and on which server.
func AuditLossMessage(l AuditLoss, user, from, server, link string, now time.Time) Message {
	title := "Audit alerts were turned off for this channel"
	switch {
	case l.Removed:
		title = "This channel was removed and gets no more audit alerts"
	case l.Moved:
		title = "This channel's address was changed"
	}
	m := Message{
		Kind: KindAudit, AuditID: "change-" + newID() + newID(), Title: title, Urgency: "critical",
		AuditAlert: "Audit alerts turned off or sent elsewhere", AuditAction: "notify.audit_alerts",
		Created: now.UTC(), Link: link, AuditServer: clean(server, 200), AuditReason: clean(l.What(), 1000),
		Entities: map[string]string{},
	}
	if u := clean(user, maxEntity); u != "" {
		m.Entities["user"] = u
	}
	if ip := clean(from, maxEntity); ip != "" {
		m.Entities["src"] = ip
	}
	return m
}

// AuditLossTimeout is how long the last messages of one save may take
// in all; the save goes on whether they arrived or not, so that a dead
// channel can still be removed.
const AuditLossTimeout = 10 * time.Second

// SendAuditLosses sends each channel of losses its last message, as the
// channel was before the change, all at once and within
// AuditLossTimeout, and records each in deliveries (when not nil) so the
// page shows how it went. A message that fails is not sent again: the
// channel may be gone. It returns how many could not be sent.
func SendAuditLosses(ctx context.Context, sender Sender, deliveries Deliveries, losses []AuditLoss, user, from, server, link string, now func() time.Time) (failed int) {
	if now == nil {
		now = time.Now
	}
	ctx, cancel := context.WithTimeout(ctx, AuditLossTimeout)
	defer cancel()
	errs := make([]error, len(losses))
	dels := make([]Delivery, len(losses))
	var wg sync.WaitGroup
	for i, l := range losses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, start := l.Channel, now()
			m := AuditLossMessage(l, user, from, server, link, start)
			errs[i] = sender.Send(ctx, c, m)
			end := now()
			dels[i] = Delivery{
				ID: AuditDeliveryID(m.AuditID, c.ID), Kind: KindAudit, Channel: c.ID, ChannelName: c.Name, ChannelType: c.Type,
				Rule: "audit:change", RuleName: m.AuditAlert, Status: StatusSent, Attempts: 1, DurationMS: end.Sub(start).Milliseconds(),
				Message: m, Server: server, Created: start, Updated: end, Claimed: start,
			}
			if errs[i] != nil {
				dels[i].Status, dels[i].Error, dels[i].Final = StatusFailed, errs[i].Error(), true
			}
		}()
	}
	wg.Wait()
	for i := range dels {
		if errs[i] != nil {
			failed++
		}
		if deliveries != nil {
			wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			_, _ = deliveries.Claim(wctx, &dels[i])
			cancel()
		}
	}
	return failed
}
