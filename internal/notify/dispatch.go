// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The dispatcher is the background job "notifications". Every Interval it
// reads the findings raised since its last pass (see Reader), matches them against the
// rules, and sends each new one to its channels. Only the server that
// runs the background jobs does, and it asks Allowed before each message,
// so a server that lost the jobs stops at once.
//
// Each message is claimed before it is sent, by creating its delivery
// document with the ID DeliveryID(finding, channel): when that document
// is already there, the message was sent, or is being sent, by this
// server or another, and it is skipped. Claim then send means a message
// goes out at most once, even across a takeover. A delivery left
// "sending" by a server that stopped is marked failed ("the server
// stopped while sending; it may not have arrived") and never sent again.
//
// A failed message is tried again after Backoff[0], then Backoff[1] and
// so on, and given up after len(Backoff) more tries. When one pass would
// send a channel more than FloodLimit messages, the first FloodLimit-1
// go out on their own and one more says how many others there are, with
// a link to the Findings page.

// Timing and limits of the dispatcher.
const (
	Interval = 15 * time.Second
	// FloodLimit is the most messages one pass sends a channel.
	FloodLimit = 10
	// KeepFor is how long deliveries are kept.
	KeepFor = 30 * 24 * time.Hour
	// StuckAfter is how long a delivery may stay "sending" before it is
	// taken for one a stopped server left.
	StuckAfter = 5 * time.Minute
	// purgeEvery is how often old deliveries are deleted.
	purgeEvery = time.Hour
)

// Backoff is how long a failed message waits before each new try.
var Backoff = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour}

// MaxAttempts is how many times a message is tried in all.
var MaxAttempts = len(Backoff) + 1

// StoppedWhileSending is the error of a delivery a stopped server left.
const StoppedWhileSending = "The Signalith server stopped while sending this message, so it may not have arrived. It is not sent again."

// Dispatcher sends the findings that match the rules.
type Dispatcher struct {
	Settings   *Manager
	Findings   findings.Store
	Deliveries Deliveries
	Sender     Sender
	// PublicURL returns server.public_url, for the link in messages.
	PublicURL func() string
	// Server names this server in the deliveries it sends.
	Server string
	// Allowed reports whether this server may send now: it runs the
	// background jobs. nil always may.
	Allowed func() bool
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	Log *slog.Logger
	// SLA returns the due-time targets for rules that escalate late
	// findings; nil escalates none.
	SLA func() findings.SLA
	// Audit returns where the audit alerts read audit records from now:
	// the audit indices when servers share them, else this server's own
	// (AuditTap). nil, or a nil source, sends no audit alerts.
	Audit func() AuditSource
	// KnownUser reports whether a name is an account Signalith knows. The
	// name of a failed sign-in is whatever was typed, perhaps a password
	// typed in the wrong box, so an audit alert sends it only when it is
	// a known account, and UnknownName otherwise. nil knows none.
	KnownUser func(name string) bool

	reader Reader
	// For each audit alert, by ID: when the last pass that read all of
	// its records started, whether the last pass read the most it may
	// (logged once), and how far the look for records that arrived late
	// has come and when the last one finished.
	auditDone   map[string]time.Time
	auditBehind map[string]bool
	auditSweep  map[string]time.Time
	auditSwept  map[string]time.Time
	// How many records the source had let go of (AuditTap.Dropped) at
	// the last pass, and when that last rose.
	auditDropped   int64
	auditDroppedAt time.Time
	mu             sync.Mutex
	inFlight       map[string]bool // deliveries this server is sending
	warned         bool            // a pass read the most findings it may; logged once
	lastPurge      time.Time
	lastLate       time.Time
	lastErr        string // the last pass's problem, logged once
}

func (d *Dispatcher) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Dispatcher) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

func (d *Dispatcher) allowed() bool { return d.Allowed == nil || d.Allowed() }

func (d *Dispatcher) link() string {
	if d.PublicURL == nil {
		return ""
	}
	return FindingsLink(d.PublicURL())
}

// Run sends every Interval until ctx ends.
func (d *Dispatcher) Run(ctx context.Context) {
	t := time.NewTicker(Interval)
	defer t.Stop()
	for {
		d.Pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// item is one message to send to a channel: about a new finding, or a
// failed delivery to try again.
type item struct {
	msg     Message
	rule    Rule
	stored  *Stored // set for a retry
	urgency int
	late    bool // an escalation of a finding still unassigned
}

// Pass sends what is due once.
func (d *Dispatcher) Pass(ctx context.Context) {
	if !d.allowed() || ctx.Err() != nil {
		return
	}
	s, err := d.Settings.Settings()
	if err != nil {
		// A file that cannot be read sends nothing, so a bad hand edit
		// never sends to the wrong place; the page says why.
		d.problem("notifications are not sent until the notifications file is fixed", err)
		return
	}
	now := d.now()
	d.purge(ctx, now)
	retry, stuck, err := d.Deliveries.Due(ctx, now, now.Add(-StuckAfter))
	if err != nil {
		d.problem("could not read the notifications to send again", err)
		return
	}
	for _, st := range stuck {
		d.giveUp(ctx, st, now)
	}
	perChannel, perAudit := map[string][]item{}, map[string][]item{}
	for _, st := range retry {
		c, ok := s.Channel(st.Channel)
		if !ok {
			st.Status, st.Final, st.Error, st.Updated, st.NextTry = StatusFailed, true, "The channel was deleted, so this message is not sent again.", now, nil
			_, _ = d.Deliveries.Update(ctx, &st.Delivery, st.Version)
			continue
		}
		st := st
		to := perChannel
		if st.Kind == KindAudit {
			to = perAudit
		}
		to[c.ID] = append(to[c.ID], item{msg: st.Message, stored: &st, urgency: urgencyRank(st.Message.Urgency),
			rule: Rule{ID: st.Rule, Name: st.RuleName}})
	}
	if err := d.collect(ctx, s, now, perChannel); err != nil {
		d.problem("could not read new findings to send", err)
	} else if err := d.collectLate(ctx, s, now, perChannel); err != nil {
		d.problem("could not read late findings to send", err)
	} else if err := d.collectAudit(ctx, s, now, perAudit); err != nil {
		d.problem("could not read the audit records to send", err)
	} else {
		d.problem("", nil)
	}
	d.sendAll(ctx, s, perChannel, now, false, func(list []claimed) Message { return summaryMessage(len(list), d.link(), d.now()) })
	d.sendAll(ctx, s, perAudit, now, true, func(list []claimed) Message {
		names := make([]string, len(list))
		for i, cl := range list {
			names[i] = cl.d.RuleName
		}
		return auditSummaryMessage(names, d.auditLink(), d.now())
	})
}

// sendAll sends each channel its items, in the order of the channel IDs.
func (d *Dispatcher) sendAll(ctx context.Context, s Settings, perChannel map[string][]item, now time.Time, eachRule bool, summary func([]claimed) Message) {
	ids := make([]string, 0, len(perChannel))
	for id := range perChannel {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		c, _ := s.Channel(id)
		d.sendChannel(ctx, c, perChannel[id], now, eachRule, summary)
	}
}

func (d *Dispatcher) auditLink() string {
	if d.PublicURL == nil {
		return ""
	}
	return AuditLink(d.PublicURL())
}

// MaxAudit is the most audit records one pass reads for one audit alert.
const MaxAudit = 2000

// AuditSweepEvery is how often the audit records of the last CatchUp are
// read again for each alert, for those that arrived late: a server that
// could not reach OpenSearch writes its audit records when it can again,
// with the time they were logged at.
const AuditSweepEvery = 10 * time.Minute

// collectAudit adds the new audit records an audit alert that is on
// matches to perChannel: each record at most once per channel, as the
// first alert that matches it, and not when it was claimed before.
//
// Each alert's records are read on their own, the most urgent alert
// first, so many records of one alert (failed sign-ins, say) never keep
// another alert's from being read.
func (d *Dispatcher) collectAudit(ctx context.Context, s Settings, now time.Time, perChannel map[string][]item) error {
	var src AuditSource
	if d.Audit != nil {
		src = d.Audit()
	}
	type on struct {
		alert AuditAlert
		rule  AuditRule
	}
	var rules []on
	for _, a := range AuditAlerts {
		r := s.AuditRule(a.ID)
		if src != nil && r.Enabled && len(r.Channels) > 0 {
			rules = append(rules, on{a, r})
		} else {
			d.auditRead(a, now, now, time.Time{}, false, false)
		}
	}
	d.auditLost(src, now)
	if len(rules) == 0 {
		return nil
	}
	link := d.auditLink()
	var wants []item
	var ids, channels []string
	seen := map[string]bool{}
	gather := func(o on, list []AuditRecord) {
		for _, rec := range list {
			if rec.Event.Time.Before(o.rule.Since) || !o.alert.Matches(rec.Event) {
				continue
			}
			for _, cid := range o.rule.Channels {
				id := AuditDeliveryID(rec.ID, cid)
				if _, ok := s.Channel(cid); !ok || seen[id] {
					continue
				}
				seen[id] = true
				m := AuditMessage(o.alert, rec, link)
				if u := m.Entities["user"]; u != "" && typedName(rec.Event) && (d.KnownUser == nil || !d.KnownUser(rec.Event.User)) {
					m.Entities["user"] = UnknownName
				}
				wants = append(wants, item{msg: m, rule: Rule{ID: "audit:" + o.alert.ID, Name: o.alert.Name}, urgency: urgencyRank(m.Urgency)})
				ids = append(ids, id)
				channels = append(channels, cid)
			}
		}
	}
	// A read that fails stops the reading, but what the more urgent
	// alerts already read is still sent.
	var failed error
	oldest := now.Add(-CatchUp)
	for _, o := range rules {
		one := []AuditAlert{o.alert}
		d.mu.Lock()
		since, sweep, sweeping := oldest, d.auditSweep[o.alert.ID], false
		if t := d.auditDone[o.alert.ID].Add(-Window); t.After(since) {
			since = t
			// Records that arrived late are older than since: every
			// AuditSweepEvery the whole of CatchUp is read again, over as
			// many passes as it takes.
			_, sweeping = d.auditSweep[o.alert.ID]
			if !sweeping && now.Sub(d.auditSwept[o.alert.ID]) >= AuditSweepEvery {
				sweep, sweeping = oldest, true
			}
			if sweep.Before(oldest) {
				sweep = oldest
			}
		}
		d.mu.Unlock()
		list, truncated, err := src.AuditRecords(ctx, auditMatch(one, since), MaxAudit)
		if err != nil {
			failed = err
			break
		}
		gather(o, list)
		done := now
		if truncated && len(list) > 0 {
			// The next pass reads on from the newest record read.
			done = list[len(list)-1].Event.Time.Add(Window)
		}
		if !sweeping {
			d.auditRead(o.alert, now, done, time.Time{}, !since.After(oldest), truncated)
			continue
		}
		late, more, err := src.AuditRecords(ctx, auditMatch(one, sweep), MaxAudit)
		if err != nil {
			d.auditRead(o.alert, now, done, sweep, false, truncated)
			failed = err
			break
		}
		gather(o, late)
		next := time.Time{}
		if more && len(late) > 0 && late[len(late)-1].Event.Time.After(sweep) {
			next = late[len(late)-1].Event.Time
		}
		d.auditRead(o.alert, now, done, next, next.IsZero(), truncated)
	}
	if len(wants) > 0 {
		have, err := d.Deliveries.Existing(ctx, ids)
		if err != nil {
			return err
		}
		for i, w := range wants {
			if !have[ids[i]] {
				perChannel[channels[i]] = append(perChannel[channels[i]], w)
			}
		}
	}
	return failed
}

// auditRead records how a pass's reading for an audit alert went: its
// records up to done, less Window, were all looked at (the zero time
// leaves that as it was); sweep is where the look for late records goes
// on in the next pass, or the zero time when none is under way any more;
// whole says the whole of CatchUp has now been read; behind says the
// pass read the most records it may, which is logged once.
func (d *Dispatcher) auditRead(a AuditAlert, now, done, sweep time.Time, whole, behind bool) {
	d.mu.Lock()
	if d.auditDone == nil {
		d.auditDone, d.auditBehind = map[string]time.Time{}, map[string]bool{}
		d.auditSweep, d.auditSwept = map[string]time.Time{}, map[string]time.Time{}
	}
	if done.After(d.auditDone[a.ID]) {
		d.auditDone[a.ID] = done
	}
	if sweep.IsZero() {
		delete(d.auditSweep, a.ID)
	} else {
		d.auditSweep[a.ID] = sweep
	}
	if whole {
		d.auditSwept[a.ID] = now
	}
	warn := behind && !d.auditBehind[a.ID]
	d.auditBehind[a.ID] = behind
	d.mu.Unlock()
	if warn {
		d.log().Warn("more audit records matched an audit alert than one notifications pass reads; the newest wait for the next pass",
			"alert", a.Name, "read", MaxAudit)
	}
}

// auditLost logs when the source of the audit records let go of some
// before they were read (see AuditTap), so the loss is never silent.
func (d *Dispatcher) auditLost(src AuditSource, now time.Time) {
	t, ok := src.(interface{ Dropped() int64 })
	if !ok {
		return
	}
	n := t.Dropped()
	d.mu.Lock()
	more := n - d.auditDropped
	d.auditDropped = n
	if more > 0 {
		d.auditDroppedAt = now
	}
	d.mu.Unlock()
	if more > 0 {
		d.log().Warn("audit records were let go before the audit alerts could look at them, the least urgent first, because more than this server keeps arrived at once; they are still in the audit log",
			"dropped", more, "dropped_in_all", n, "kept", TapSize)
	}
}

// AuditWarning says, in words for the Health and Notifications pages,
// that audit alerts may be missing or late: the source let go of audit
// records in the last hour, or more records match an alert than a pass
// reads. It is "" when all is well.
func (d *Dispatcher) AuditWarning() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	if !d.auditDroppedAt.IsZero() && d.now().Sub(d.auditDroppedAt) < time.Hour {
		out = append(out, fmt.Sprintf("Audit alerts may be missing: so many audit records arrived at once that %d in all were let go before the alerts could look at them, the least urgent first. The audit log still has them.", d.auditDropped))
	}
	var behind []string
	for _, a := range AuditAlerts {
		if d.auditBehind[a.ID] {
			behind = append(behind, a.Name)
		}
	}
	if len(behind) > 0 {
		out = append(out, "Audit alerts are late: more audit records match "+strings.Join(behind, ", ")+" than one pass reads, so the newest wait.")
	}
	return strings.Join(out, " ")
}

// collect adds the new findings that match a rule to perChannel: each
// finding at most once per channel, and not when it was claimed before.
func (d *Dispatcher) collect(ctx context.Context, s Settings, now time.Time, perChannel map[string][]item) error {
	var rules []Rule
	for _, r := range s.Rules {
		if r.Enabled && len(r.Channels) > 0 {
			rules = append(rules, r)
		}
	}
	if len(rules) == 0 {
		d.reader.Done(now)
		return nil
	}
	list, truncated, err := d.reader.Read(ctx, d.Findings, now)
	if err != nil {
		return err
	}
	d.tooMany(truncated, len(list))
	link := d.link()
	type want struct {
		f       *findings.Finding
		channel string
		rule    Rule
	}
	var wants []want
	seen := map[string]bool{}
	for _, f := range list {
		for _, r := range rules {
			if !r.Matches(f) {
				continue
			}
			for _, cid := range r.Channels {
				if _, ok := s.Channel(cid); !ok {
					continue
				}
				id := DeliveryID(f.ID, cid)
				if seen[id] {
					continue
				}
				seen[id] = true
				wants = append(wants, want{f, cid, r})
			}
		}
	}
	if len(wants) == 0 {
		d.reader.Done(now)
		return nil
	}
	ids := make([]string, len(wants))
	for i, w := range wants {
		ids[i] = DeliveryID(w.f.ID, w.channel)
	}
	have, err := d.Deliveries.Existing(ctx, ids)
	if err != nil {
		return err
	}
	for i, w := range wants {
		if have[ids[i]] {
			continue
		}
		m := NewMessage(w.f, link)
		perChannel[w.channel] = append(perChannel[w.channel], item{msg: m, rule: w.rule, urgency: urgencyRank(m.Urgency)})
	}
	d.reader.Done(now)
	return nil
}

// LateEvery is how often the dispatcher looks for findings still
// unassigned past their due time, and MaxLate the most it reads at once.
const (
	LateEvery = time.Minute
	MaxLate   = 200
)

// LateDeliveryID is the delivery of a finding's escalation to a channel:
// apart from the first message, so each goes out once.
func LateDeliveryID(findingID, channelID string) string {
	return DeliveryID(findingID+"~late", channelID)
}

// collectLate adds, for rules that escalate, the open findings nobody
// owns that are past their due time, each once per channel.
func (d *Dispatcher) collectLate(ctx context.Context, s Settings, now time.Time, perChannel map[string][]item) error {
	if d.SLA == nil || now.Sub(d.lastLate) < LateEvery {
		return nil
	}
	var rules []Rule
	for _, r := range s.Rules {
		if r.Enabled && r.Late && len(r.Channels) > 0 {
			rules = append(rules, r)
		}
	}
	sla := d.SLA()
	if len(rules) == 0 || sla.Off() {
		d.lastLate = now
		return nil
	}
	list, _, err := d.Findings.Search(ctx, findings.Filter{
		Status: []string{findings.StatusNew, findings.StatusInProgress, findings.StatusPending}, Unowned: true, Due: &findings.DueWithin{SLA: sla, Now: now},
		Limit: MaxLate, Order: findings.OrderUrgency,
	})
	if err != nil {
		return err
	}
	link := d.link()
	seen := map[string]bool{}
	type want struct {
		f       *findings.Finding
		channel string
		rule    Rule
	}
	var wants []want
	var ids []string
	for _, f := range list {
		for _, r := range rules {
			if !r.Matches(f) {
				continue
			}
			for _, cid := range r.Channels {
				id := LateDeliveryID(f.ID, cid)
				if _, ok := s.Channel(cid); !ok || seen[id] {
					continue
				}
				seen[id] = true
				wants = append(wants, want{f, cid, r})
				ids = append(ids, id)
			}
		}
	}
	if len(wants) > 0 {
		have, err := d.Deliveries.Existing(ctx, ids)
		if err != nil {
			return err
		}
		for i, w := range wants {
			if have[ids[i]] {
				continue
			}
			m := NewMessage(w.f, link)
			m.Late = true
			m.Title = clean("Unassigned and late: "+m.Title, maxTitle)
			perChannel[w.channel] = append(perChannel[w.channel], item{msg: m, rule: w.rule, urgency: urgencyRank(m.Urgency), late: true})
		}
	}
	d.lastLate = now
	return nil
}

// tooMany logs, once, that a pass read the most findings it may.
func (d *Dispatcher) tooMany(truncated bool, n int) {
	d.mu.Lock()
	warn := truncated && !d.warned
	d.warned = truncated
	d.mu.Unlock()
	if warn {
		d.log().Warn("more findings were raised than one notifications pass reads; the oldest are not sent", "read", n)
	}
}

// sendChannel sends a channel its messages: the most urgent first, and
// when there are more than FloodLimit, the rest in one summary. With
// eachRule (the audit alerts), the first message of each rule is sent
// on its own before a second of any, so many records of one alert never
// leave another alert to the summary alone.
func (d *Dispatcher) sendChannel(ctx context.Context, c Channel, items []item, now time.Time, eachRule bool, summary func([]claimed) Message) {
	byUrgency := func(items []item) {
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].urgency != items[j].urgency {
				return items[i].urgency > items[j].urgency
			}
			return items[i].msg.Created.Before(items[j].msg.Created)
		})
	}
	byUrgency(items)
	single, rest := items, []item(nil)
	if len(items) > FloodLimit {
		if eachRule {
			var first, more []item
			seen := map[string]bool{}
			for _, it := range items {
				if seen[it.rule.ID] {
					more = append(more, it)
				} else {
					seen[it.rule.ID] = true
					first = append(first, it)
				}
			}
			items = append(first, more...)
			byUrgency(items[:FloodLimit-1])
		}
		single, rest = items[:FloodLimit-1], items[FloodLimit-1:]
	}
	for _, it := range single {
		if ctx.Err() != nil || !d.allowed() {
			return
		}
		cl, ok := d.claim(ctx, c, it, 0)
		if !ok {
			continue
		}
		d.send(ctx, c, it.msg, []claimed{cl})
	}
	if len(rest) == 0 || ctx.Err() != nil || !d.allowed() {
		return
	}
	var claims []claimed
	for _, it := range rest {
		if cl, ok := d.claim(ctx, c, it, len(rest)); ok {
			claims = append(claims, cl)
		}
	}
	switch len(claims) {
	case 0:
		return
	case 1:
		// Only one left to send after all: it goes out on its own.
		claims[0].d.Summary = 0
		d.send(ctx, c, claims[0].d.Message, claims)
		return
	}
	for i := range claims {
		claims[i].d.Summary = len(claims)
	}
	if !d.allowed() {
		// Claimed but not sent: they wait in "sending" and are given up
		// as left by a stopped server, which is what this one is now.
		d.release(claims)
		return
	}
	d.send(ctx, c, summary(claims), claims)
}

// claimed is a delivery this server claimed and is about to send.
type claimed struct {
	d *Delivery
	v store.Version
}

// claim claims a message: a new delivery for a new finding, or the
// failed delivery being tried again. ok is false when someone else
// claimed it first.
func (d *Dispatcher) claim(ctx context.Context, c Channel, it item, summary int) (claimed, bool) {
	now := d.now()
	if it.stored != nil {
		del := it.stored.Delivery
		del.Status, del.Attempts, del.Claimed, del.Updated, del.NextTry = StatusSending, del.Attempts+1, now, now, nil
		del.ChannelName, del.ChannelType, del.Server, del.Summary = c.Name, c.Type, d.Server, summary
		d.mark(del.ID, true)
		v, err := d.Deliveries.Update(ctx, &del, it.stored.Version)
		if err != nil {
			d.mark(del.ID, false)
			if !store.IsConflict(err) {
				d.log().Warn("could not claim a notification to send again", "channel", c.Name, "err", err)
			}
			return claimed{}, false
		}
		return claimed{&del, v}, true
	}
	id, kind := DeliveryID(it.msg.FindingID, c.ID), KindFinding
	switch {
	case it.msg.Kind == KindAudit:
		id, kind = AuditDeliveryID(it.msg.AuditID, c.ID), KindAudit
	case it.late:
		id = LateDeliveryID(it.msg.FindingID, c.ID)
	}
	del := &Delivery{
		ID: id, Kind: kind, FindingID: it.msg.FindingID,
		Channel: c.ID, ChannelName: c.Name, ChannelType: c.Type, Rule: it.rule.ID, RuleName: it.rule.Name,
		Status: StatusSending, Attempts: 1, Summary: summary, Message: it.msg, Server: d.Server,
		Created: now, Updated: now, Claimed: now,
	}
	d.mark(del.ID, true)
	v, err := d.Deliveries.Claim(ctx, del)
	if err != nil {
		d.mark(del.ID, false)
		if !errors.Is(err, store.ErrExists) {
			d.log().Warn("could not claim a notification", "channel", c.Name, "finding", it.msg.FindingID, "err", err)
		}
		return claimed{}, false
	}
	return claimed{del, v}, true
}

func (d *Dispatcher) mark(id string, on bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.inFlight == nil {
		d.inFlight = map[string]bool{}
	}
	if on {
		d.inFlight[id] = true
	} else {
		delete(d.inFlight, id)
	}
}

func (d *Dispatcher) sending(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.inFlight[id]
}

func (d *Dispatcher) release(list []claimed) {
	for _, cl := range list {
		d.mark(cl.d.ID, false)
	}
}

// send sends m and records the outcome in each of the claimed
// deliveries it stands for.
func (d *Dispatcher) send(ctx context.Context, c Channel, m Message, list []claimed) {
	defer d.release(list)
	start := d.now()
	err := d.Sender.Send(ctx, c, m)
	end := d.now()
	took := end.Sub(start).Milliseconds()
	for _, cl := range list {
		del := cl.d
		del.DurationMS = took
		settle(del, err, end)
		// Written whatever happens to ctx: the message went out or not.
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		_, werr := d.Deliveries.Update(wctx, del, cl.v)
		cancel()
		if werr != nil {
			d.log().Warn("could not record a notification's outcome", "channel", c.Name, "status", del.Status, "err", werr)
		}
	}
	if err != nil {
		d.log().Warn("a notification could not be sent", "channel", c.Name, "type", c.Type, "findings", len(list), "err", err.Error())
	} else {
		d.log().Info("notification sent", "channel", c.Name, "type", c.Type, "findings", len(list), "kind", m.Kind)
	}
}

// settle records how sending a delivery went at end: sent, or failed and
// due to be tried again after the next Backoff, or failed for good.
func settle(del *Delivery, err error, end time.Time) {
	del.Updated, del.NextTry = end, nil
	if err == nil {
		del.Status, del.Error, del.Final = StatusSent, "", false
		return
	}
	del.Status, del.Error = StatusFailed, err.Error()
	var se *SendError
	retry := !errors.As(err, &se) || se.Retry
	if retry && del.Attempts < MaxAttempts {
		next := end.Add(Backoff[min(del.Attempts-1, len(Backoff)-1)])
		del.NextTry = &next
	} else {
		del.Final = true
	}
}

// giveUp marks a delivery a stopped server left "sending" as failed, for
// good: it may have arrived.
func (d *Dispatcher) giveUp(ctx context.Context, st Stored, now time.Time) {
	if d.sending(st.ID) {
		return
	}
	st.Status, st.Final, st.Error, st.Updated, st.NextTry = StatusFailed, true, StoppedWhileSending, now, nil
	if _, err := d.Deliveries.Update(ctx, &st.Delivery, st.Version); err != nil && !store.IsConflict(err) {
		d.log().Warn("could not mark a notification left sending as failed", "channel", st.ChannelName, "err", err)
	}
}

// purge deletes deliveries older than KeepFor, once in a while.
func (d *Dispatcher) purge(ctx context.Context, now time.Time) {
	d.mu.Lock()
	due := now.Sub(d.lastPurge) >= purgeEvery
	if due {
		d.lastPurge = now
	}
	d.mu.Unlock()
	if !due {
		return
	}
	if err := d.Deliveries.Purge(ctx, now.Add(-KeepFor)); err != nil && ctx.Err() == nil {
		d.log().Warn("could not delete old notification deliveries", "err", err)
	}
}

// problem logs a pass's problem once, until it changes or goes away.
func (d *Dispatcher) problem(what string, err error) {
	msg := ""
	if err != nil {
		msg = what + ": " + err.Error()
	}
	d.mu.Lock()
	changed := msg != d.lastErr
	d.lastErr = msg
	d.mu.Unlock()
	if changed && err != nil {
		d.log().Error(what, "err", err)
	}
}

// ChannelStatus is how the last message to a channel went.
type ChannelStatus struct {
	Status string    `json:"status"`
	Time   time.Time `json:"time"`
	Error  string    `json:"error,omitempty"`
	Kind   string    `json:"kind"`
}

// LastStatus returns, for each channel, how its latest finished delivery
// in list (newest first, as Recent returns them) went.
func LastStatus(list []Delivery) map[string]ChannelStatus {
	out := map[string]ChannelStatus{}
	for _, d := range list {
		if d.Status == StatusSending {
			continue
		}
		if _, ok := out[d.Channel]; ok {
			continue
		}
		out[d.Channel] = ChannelStatus{Status: d.Status, Time: d.Updated, Error: d.Error, Kind: d.Kind}
	}
	return out
}

// Failing lists the channels of s whose latest delivery in list failed
// since since, in the order of s.
func Failing(s Settings, list []Delivery, since time.Time) []Channel {
	last := LastStatus(list)
	var out []Channel
	for _, c := range s.Channels {
		if st, ok := last[c.ID]; ok && st.Status == StatusFailed && !st.Time.Before(since) {
			out = append(out, c)
		}
	}
	return slices.Clip(out)
}

// SendTest sends a test message through c, from any server, and records
// it in deliveries (when not nil) so the page shows how it went. Its
// error is the SendError, in words for people.
func SendTest(ctx context.Context, sender Sender, deliveries Deliveries, c Channel, link, server string, now func() time.Time) (Delivery, error) {
	if now == nil {
		now = time.Now
	}
	start := now()
	err := sender.Send(ctx, c, TestMessage(link, start))
	end := now()
	del := Delivery{
		ID: "test-" + newID() + newID(), Kind: KindTest, Channel: c.ID, ChannelName: c.Name, ChannelType: c.Type,
		Status: StatusSent, Attempts: 1, DurationMS: end.Sub(start).Milliseconds(), Message: TestMessage(link, start),
		Server: server, Created: start, Updated: end, Claimed: start,
	}
	if err != nil {
		del.Status, del.Error, del.Final = StatusFailed, err.Error(), true
	}
	if deliveries != nil && c.ID != "test" {
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		_, _ = deliveries.Claim(wctx, &del)
		cancel()
	}
	return del, err
}
