package notify

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// fakeSender records what it is asked to send, and fails while fail is
// set.
type fakeSender struct {
	mu   sync.Mutex
	sent []sentMsg
	fail error
	// during runs while a message is being sent.
	during func()
}

type sentMsg struct {
	channel string
	msg     Message
}

func (f *fakeSender) Send(_ context.Context, c Channel, m Message) error {
	if f.during != nil {
		f.during()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sentMsg{c.ID, m})
	return f.fail
}

func (f *fakeSender) count(channel string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.sent {
		if channel == "" || s.channel == channel {
			n++
		}
	}
	return n
}

// clock is a fake clock that can be moved forward.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type rig struct {
	t      *testing.T
	clock  *clock
	fs     *findings.Memory
	store  *Memory
	sender *fakeSender
	d      *Dispatcher
	set    *Manager
}

// newRig sets up a dispatcher with channels slack (aaa) and webhook (bbb)
// and the rules given.
func newRig(t *testing.T, rules ...RuleInput) *rig {
	t.Helper()
	cl := &clock{now: t0}
	set := &Manager{File: filepath.Join(t.TempDir(), "n.yaml"), Now: cl.Now}
	if _, err := set.Save(Input{Channels: []ChannelInput{
		slackInput("aaa", "https://hooks.example.com/a"),
		{ID: "bbb", Name: "SOAR", Type: TypeWebhook, URL: "https://soar.example.com/hook"},
	}, Rules: rules}); err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, clock: cl, fs: findings.NewMemory(), store: NewMemory(), sender: &fakeSender{}, set: set}
	r.d = &Dispatcher{Settings: set, Findings: r.fs, Deliveries: r.store, Sender: r.sender, Now: cl.Now, Server: "s1",
		PublicURL: func() string { return "https://siem.example.com/" }}
	return r
}

func on() *bool { b := true; return &b }

func (r *rig) raise(id, urgency, detection string) *findings.Finding {
	r.t.Helper()
	f := finding(id, urgency, detection, r.clock.Now())
	f.Entities = map[string]any{"user": "bob", "src": "10.0.0.5", "process": "not sent"}
	f.Result = map[string]any{"risk_score": 90.0, "raw": "secret event payload"}
	if err := r.fs.Create(context.Background(), f); err != nil {
		r.t.Fatal(err)
	}
	return f
}

func (r *rig) pass() { r.d.Pass(context.Background()) }

func TestDispatcherSendsEachFindingOncePerChannel(t *testing.T) {
	// Two rules send the same finding to the Slack channel: it goes once.
	r := newRig(t,
		RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa"}},
		RuleInput{ID: "r2", Name: "all to both", Enabled: on(), Channels: []string{"aaa", "bbb"}, MinUrgency: "low"})
	r.clock.add(time.Second)
	r.raise("f1", "high", "brute")
	r.raise("f2", "low", "scan")
	r.raise("f3", "informational", "scan")
	r.pass()
	if r.sender.count("aaa") != 2 || r.sender.count("bbb") != 2 {
		t.Fatalf("sent %+v", r.sender.sent)
	}
	r.pass()
	r.clock.add(time.Minute)
	r.pass()
	if r.sender.count("") != 4 {
		t.Errorf("sent again: %d", r.sender.count(""))
	}
	d, ok := r.store.Get(DeliveryID("f1", "aaa"))
	if !ok || d.Status != StatusSent || d.Attempts != 1 || d.Rule != "r1" || d.RuleName != "urgent" || d.Server != "s1" || d.ChannelName != "#soc" {
		t.Errorf("delivery %+v", d)
	}
	m := d.Message
	if m.Link != "https://siem.example.com/#findings" || m.Entities["user"] != "bob" || m.Entities["src"] != "10.0.0.5" ||
		m.Entities["process"] != "" || m.RiskScore == nil || *m.RiskScore != 90 || m.Urgency != "high" {
		t.Errorf("message %+v", m)
	}
}

func TestDispatcherSkipsWhatItMayNotSend(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa"}})
	// Raised before the rule: not sent, so a new rule does not replay
	// history.
	old := finding("old", "critical", "d", t0.Add(-time.Minute))
	r.fs.Create(context.Background(), old)
	r.clock.add(time.Second)
	s := r.raise("sample", "critical", "d")
	s.Sample = "load-1"
	r.fs.Save(context.Background(), s)
	allowed := false
	r.d.Allowed = func() bool { return allowed }
	r.raise("f1", "critical", "d")
	r.pass()
	if r.sender.count("") != 0 {
		t.Fatalf("sent while not allowed: %+v", r.sender.sent)
	}
	allowed = true
	r.pass()
	if r.sender.count("") != 1 || r.sender.sent[0].msg.FindingID != "f1" {
		t.Errorf("sent %+v", r.sender.sent)
	}
}

func TestDispatcherIncludesSampleDataWhenAsked(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "try", Enabled: on(), Channels: []string{"aaa"}, IncludeSample: true})
	r.clock.add(time.Second)
	f := r.raise("s1", "high", "d")
	f.Sample = "load-1"
	r.fs.Save(context.Background(), f)
	r.pass()
	if r.sender.count("") != 1 || !r.sender.sent[0].msg.Sample {
		t.Errorf("sent %+v", r.sender.sent)
	}
}

func TestDispatcherRetriesWithBackoff(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa"}})
	r.clock.add(time.Second)
	r.raise("f1", "high", "d")
	r.sender.fail = &SendError{Msg: "The receiver answered 503 Service Unavailable.", Retry: true}
	r.pass()
	id := DeliveryID("f1", "aaa")
	d, _ := r.store.Get(id)
	if d.Status != StatusFailed || d.Final || d.Attempts != 1 || d.NextTry == nil || !d.NextTry.Equal(r.clock.Now().Add(time.Minute)) {
		t.Fatalf("after one failure %+v", d)
	}
	// Not before the wait is over.
	r.clock.add(30 * time.Second)
	r.pass()
	if r.sender.count("") != 1 {
		t.Fatalf("retried early: %d", r.sender.count(""))
	}
	waits := []time.Duration{30 * time.Second, 5 * time.Minute, 15 * time.Minute, time.Hour}
	for i, w := range waits {
		r.clock.add(w)
		r.pass()
		d, _ = r.store.Get(id)
		if r.sender.count("") != i+2 || d.Attempts != i+2 {
			t.Fatalf("try %d: sent %d, %+v", i+2, r.sender.count(""), d)
		}
	}
	if !d.Final || d.NextTry != nil || d.Attempts != MaxAttempts {
		t.Errorf("given up %+v", d)
	}
	// Given up, even well after the finding left the window.
	r.clock.add(48 * time.Hour)
	r.pass()
	if r.sender.count("") != MaxAttempts {
		t.Errorf("sent after giving up: %d", r.sender.count(""))
	}
}

func TestDispatcherRetrySucceeds(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa"}})
	r.clock.add(time.Second)
	r.raise("f1", "high", "d")
	r.sender.fail = errors.New("connection reset")
	r.pass()
	r.sender.fail = nil
	r.clock.add(time.Minute)
	r.pass()
	d, _ := r.store.Get(DeliveryID("f1", "aaa"))
	if d.Status != StatusSent || d.Attempts != 2 || d.Error != "" || d.NextTry != nil {
		t.Errorf("%+v", d)
	}
	// A blocked address is not tried again.
	r.raise("f2", "high", "d")
	r.sender.fail = &SendError{Msg: "blocked", Retry: false}
	r.pass()
	if d, _ := r.store.Get(DeliveryID("f2", "aaa")); !d.Final || d.NextTry != nil {
		t.Errorf("final failure %+v", d)
	}
}

func TestDispatcherFloodGuard(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "all", Enabled: on(), Channels: []string{"aaa"}, MinUrgency: "low"})
	r.clock.add(time.Second)
	for i := range 32 {
		u := "low"
		if i == 31 {
			u = "critical" // raised last, sent first
		}
		r.raise(fmt.Sprintf("f%02d", i), u, "d")
		r.clock.add(time.Millisecond)
	}
	r.pass()
	sent := r.sender.sent
	if len(sent) != FloodLimit {
		t.Fatalf("sent %d messages", len(sent))
	}
	if sent[0].msg.FindingID != "f31" || sent[1].msg.FindingID != "f00" {
		t.Errorf("order: %s, %s", sent[0].msg.FindingID, sent[1].msg.FindingID)
	}
	last := sent[FloodLimit-1].msg
	if last.Kind != KindSummary || last.Count != 23 || last.Title != "And 23 more new findings" || last.Link != "https://siem.example.com/#findings" {
		t.Errorf("summary %+v", last)
	}
	d, _ := r.store.Get(DeliveryID("f20", "aaa"))
	if d.Status != StatusSent || d.Summary != 23 {
		t.Errorf("summarized delivery %+v", d)
	}
	// Each finding counts as delivered: nothing more next time.
	r.clock.add(time.Minute)
	r.pass()
	if len(r.sender.sent) != FloodLimit {
		t.Errorf("sent again %d", len(r.sender.sent))
	}
}

func TestDispatcherGivesUpOnAStoppedServersClaim(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa"}})
	r.clock.add(time.Second)
	f := r.raise("f1", "high", "d")
	// Another server claimed it and stopped before saying how it went.
	id := DeliveryID(f.ID, "aaa")
	now := r.clock.Now()
	if _, err := r.store.Claim(context.Background(), &Delivery{ID: id, Kind: KindFinding, FindingID: f.ID, Channel: "aaa",
		Status: StatusSending, Attempts: 1, Created: now, Updated: now, Claimed: now, Server: "s0"}); err != nil {
		t.Fatal(err)
	}
	r.pass()
	if r.sender.count("") != 0 {
		t.Fatal("sent a message another server claimed")
	}
	if d, _ := r.store.Get(id); d.Status != StatusSending {
		t.Fatalf("a fresh claim was given up: %+v", d)
	}
	r.clock.add(StuckAfter + time.Second)
	r.pass()
	d, _ := r.store.Get(id)
	if d.Status != StatusFailed || !d.Final || d.Error != StoppedWhileSending {
		t.Errorf("%+v", d)
	}
	r.clock.add(time.Hour)
	r.pass()
	if r.sender.count("") != 0 {
		t.Error("a message that may have arrived was sent again")
	}
}

func TestDispatcherStopsWhenItLosesTheJobs(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa"}})
	r.clock.add(time.Second)
	r.raise("f1", "high", "d")
	r.raise("f2", "high", "d")
	allowed := true
	r.d.Allowed = func() bool { return allowed }
	r.sender.during = func() { allowed = false }
	r.pass()
	if r.sender.count("") != 1 {
		t.Errorf("sent %d after losing the jobs", r.sender.count(""))
	}
}

// TestTwoServersSendOnce: two dispatchers that share the deliveries (a
// takeover, or a split moment with both running) send each message once.
func TestTwoServersSendOnce(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa", "bbb"}})
	other := &Dispatcher{Settings: r.set, Findings: r.fs, Deliveries: r.store, Sender: r.sender, Now: r.clock.Now, Server: "s2"}
	r.clock.add(time.Second)
	for i := range 5 {
		r.raise(fmt.Sprintf("f%d", i), "critical", "d")
	}
	var wg sync.WaitGroup
	wg.Go(r.pass)
	wg.Go(func() { other.Pass(context.Background()) })
	wg.Wait()
	if r.sender.count("") != 10 {
		t.Errorf("sent %d messages for 5 findings to 2 channels", r.sender.count(""))
	}
}

// claimLoser is a Deliveries whose every claim finds someone else's.
type claimLoser struct{ *Memory }

func (c claimLoser) Claim(context.Context, *Delivery) (store.Version, error) {
	return store.Version{}, store.ErrExists
}

func TestDispatcherSkipsMessagesClaimedElsewhere(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa"}})
	r.d.Deliveries = claimLoser{r.store}
	r.clock.add(time.Second)
	r.raise("f1", "high", "d")
	r.pass()
	if r.sender.count("") != 0 {
		t.Error("sent a message claimed elsewhere")
	}
}

func TestDispatcherPurgesOldDeliveries(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa"}})
	r.clock.add(time.Second)
	r.raise("f1", "high", "d")
	r.pass()
	r.clock.add(KeepFor + 2*time.Hour)
	r.pass()
	if _, ok := r.store.Get(DeliveryID("f1", "aaa")); ok {
		t.Error("old delivery kept")
	}
}

func TestDeletedChannelStopsRetries(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa", "bbb"}})
	r.clock.add(time.Second)
	r.raise("f1", "high", "d")
	r.sender.fail = errors.New("down")
	r.pass()
	if _, err := r.set.Save(Input{Channels: []ChannelInput{{ID: "bbb", Name: "SOAR", Type: TypeWebhook}},
		Rules: []RuleInput{{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"bbb"}}}}); err != nil {
		t.Fatal(err)
	}
	r.sender.fail = nil
	r.clock.add(2 * time.Minute)
	r.pass()
	d, _ := r.store.Get(DeliveryID("f1", "aaa"))
	if !d.Final || !strings.Contains(d.Error, "deleted") {
		t.Errorf("%+v", d)
	}
	if r.sender.count("bbb") != 2 || r.sender.count("aaa") != 1 {
		t.Errorf("sent %+v", r.sender.sent)
	}
}

func TestLastStatusAndFailing(t *testing.T) {
	s := Settings{Channels: []Channel{{ID: "a", Name: "a", Type: TypeSlack}, {ID: "b", Name: "b", Type: TypeSlack}, {ID: "c", Name: "c", Type: TypeSlack}}}
	list := []Delivery{ // newest first
		{Channel: "a", Status: StatusSending, Updated: t0.Add(3 * time.Minute)},
		{Channel: "a", Status: StatusFailed, Error: "down", Updated: t0.Add(2 * time.Minute)},
		{Channel: "b", Status: StatusSent, Updated: t0.Add(2 * time.Minute)},
		{Channel: "b", Status: StatusFailed, Updated: t0.Add(time.Minute)},
		{Channel: "c", Status: StatusFailed, Updated: t0.Add(-48 * time.Hour)},
	}
	last := LastStatus(list)
	if last["a"].Status != StatusFailed || last["b"].Status != StatusSent {
		t.Errorf("last %+v", last)
	}
	failing := Failing(s, list, t0.Add(-24*time.Hour))
	if len(failing) != 1 || failing[0].ID != "a" {
		t.Errorf("failing %+v", failing)
	}
}

func TestSendTestRecordsADelivery(t *testing.T) {
	store := NewMemory()
	sender := &fakeSender{}
	c := Channel{ID: "aaa", Name: "#soc", Type: TypeSlack}
	d, err := SendTest(context.Background(), sender, store, c, "https://x/#findings", "s1", func() time.Time { return t0 })
	if err != nil || d.Status != StatusSent || sender.sent[0].msg.Kind != KindTest {
		t.Fatalf("%v %+v", err, d)
	}
	list, _ := store.Recent(context.Background(), 10)
	if len(list) != 1 || list[0].Kind != KindTest || list[0].Channel != "aaa" {
		t.Errorf("recorded %+v", list)
	}
	sender.fail = &SendError{Msg: "nope"}
	if d, err := SendTest(context.Background(), sender, store, c, "", "s1", nil); err == nil || d.Status != StatusFailed || !d.Final {
		t.Errorf("failed test %v %+v", err, d)
	}
}

// Findings raised while no pass ran, for longer than Window, are still
// sent, up to CatchUp back.
func TestDispatcherCatchesUpAfterAnOutage(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa"}})
	r.clock.add(time.Second)
	r.raise("f-old", "high", "d")
	r.clock.add(CatchUp + time.Minute)
	r.raise("f-mid", "high", "d")
	r.clock.add(3 * time.Hour)
	r.pass()
	if r.sender.count("") != 1 || r.sender.sent[0].msg.FindingID != "f-mid" {
		t.Fatalf("sent %+v", r.sender.sent)
	}
	// A pass that finished reads back only Window from it.
	r.clock.add(time.Minute)
	r.raise("f-new", "high", "d")
	r.clock.add(Window - 2*time.Minute)
	r.pass()
	if r.sender.count("") != 2 {
		t.Errorf("sent %d", r.sender.count(""))
	}
}

// A playbook's notify step and a rule share one delivery per finding and
// channel, so the channel gets the finding once, whichever comes first.
func TestSendOnceSharesTheRulesDelivery(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa"}})
	s, _ := r.set.Settings()
	c, _ := s.Channel("aaa")
	r.clock.add(time.Second)
	f1 := r.raise("f1", "high", "d")
	again, err := SendOnce(context.Background(), r.sender, r.store, c, NewMessage(f1, "x"), "Brute force response", "s1", r.clock.Now)
	if err != nil || again {
		t.Fatal(again, err)
	}
	r.pass()
	if r.sender.count("aaa") != 1 {
		t.Fatalf("sent %d", r.sender.count("aaa"))
	}
	if d, _ := r.store.Get(DeliveryID("f1", "aaa")); d.Playbook != "Brute force response" || d.Status != StatusSent || d.Rule != "" {
		t.Errorf("delivery %+v", d)
	}
	// The rule first, then the playbook.
	f2 := r.raise("f2", "high", "d")
	r.pass()
	if _, err := SendOnce(context.Background(), r.sender, r.store, c, NewMessage(f2, "x"), "p", "s1", r.clock.Now); !errors.Is(err, ErrAlreadySent) {
		t.Fatal(err)
	}
	if r.sender.count("aaa") != 2 {
		t.Fatalf("sent %d", r.sender.count("aaa"))
	}
	// A failed playbook message is tried again by the dispatcher.
	f3 := r.raise("f3", "high", "d")
	r.sender.fail = errors.New("connection reset")
	again, err = SendOnce(context.Background(), r.sender, r.store, c, NewMessage(f3, "x"), "p", "s1", r.clock.Now)
	if err == nil || !again {
		t.Fatal(again, err)
	}
	r.sender.fail = nil
	r.pass()
	if r.sender.count("aaa") != 3 {
		t.Fatalf("retried early: %d", r.sender.count("aaa"))
	}
	r.clock.add(time.Minute)
	r.pass()
	if d, _ := r.store.Get(DeliveryID("f3", "aaa")); r.sender.count("aaa") != 4 || d.Status != StatusSent || d.Attempts != 2 {
		t.Errorf("sent %d, %+v", r.sender.count("aaa"), d)
	}
}
