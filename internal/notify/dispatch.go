package notify

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The dispatcher is the background job "notifications". Every Interval it
// reads the findings raised in the last Window, matches them against the
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
	// Window is how far back each pass reads findings.
	Window = 30 * time.Minute
	// FloodLimit is the most messages one pass sends a channel.
	FloodLimit = 10
	// KeepFor is how long deliveries are kept.
	KeepFor = 30 * 24 * time.Hour
	// StuckAfter is how long a delivery may stay "sending" before it is
	// taken for one a stopped server left.
	StuckAfter = 5 * time.Minute
	// maxFindings is the most findings one pass reads.
	maxFindings = 2000
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

	mu        sync.Mutex
	inFlight  map[string]bool // deliveries this server is sending
	lastPurge time.Time
	lastErr   string // the last pass's problem, logged once
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
	perChannel := map[string][]item{}
	for _, st := range retry {
		c, ok := s.Channel(st.Channel)
		if !ok {
			st.Status, st.Final, st.Error, st.Updated, st.NextTry = StatusFailed, true, "The channel was deleted, so this message is not sent again.", now, nil
			_, _ = d.Deliveries.Update(ctx, &st.Delivery, st.Version)
			continue
		}
		st := st
		perChannel[c.ID] = append(perChannel[c.ID], item{msg: st.Message, stored: &st, urgency: urgencyRank(st.Message.Urgency),
			rule: Rule{ID: st.Rule, Name: st.RuleName}})
	}
	if err := d.collect(ctx, s, now, perChannel); err != nil {
		d.problem("could not read new findings to send", err)
	} else {
		d.problem("", nil)
	}
	ids := make([]string, 0, len(perChannel))
	for id := range perChannel {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		c, _ := s.Channel(id)
		d.sendChannel(ctx, c, perChannel[id], now)
	}
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
		return nil
	}
	list, err := RecentFindings(ctx, d.Findings, now)
	if err != nil {
		return err
	}
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
	return nil
}

// sendChannel sends a channel its messages: the most urgent first, and
// when there are more than FloodLimit, the rest in one summary.
func (d *Dispatcher) sendChannel(ctx context.Context, c Channel, items []item, now time.Time) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].urgency != items[j].urgency {
			return items[i].urgency > items[j].urgency
		}
		return items[i].msg.Created.Before(items[j].msg.Created)
	})
	single, rest := items, []item(nil)
	if len(items) > FloodLimit {
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
	d.send(ctx, c, summaryMessage(len(claims), d.link(), d.now()), claims)
}

// RecentFindings reads the findings raised in the Window before now, as
// each pass of the dispatcher does; playbooks read new findings the same
// way. A matching rule or playbook still skips those raised before it
// was turned on.
func RecentFindings(ctx context.Context, fs findings.Store, now time.Time) ([]*findings.Finding, error) {
	list, _, err := fs.Search(ctx, findings.Filter{Since: now.Add(-Window), Limit: maxFindings})
	return list, err
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
	del := &Delivery{
		ID: DeliveryID(it.msg.FindingID, c.ID), Kind: KindFinding, FindingID: it.msg.FindingID,
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
		del.DurationMS, del.Updated = took, end
		if err == nil {
			del.Status, del.Error, del.Final = StatusSent, "", false
		} else {
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
