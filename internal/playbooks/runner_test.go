package playbooks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/respond"
)

// fakeSender records what it sends; fail makes it fail.
type fakeSender struct {
	mu   sync.Mutex
	sent []string // channel id + " " + kind + " " + title
	fail error
}

func (s *fakeSender) Send(_ context.Context, c notify.Channel, m notify.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	s.sent = append(s.sent, c.ID+" "+m.Kind+" "+m.Title)
	return nil
}

func (s *fakeSender) list() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.sent...)
}

// fakeDesk keeps cases in a map and records every note.
type fakeDesk struct {
	mu       sync.Mutex
	f        findings.Store
	cases    map[string][]string // case -> findings
	closed   map[string]bool
	notes    []string // "finding <id>: text" or "case <id>: text"
	nextCase int
}

func newDesk(f findings.Store) *fakeDesk {
	return &fakeDesk{f: f, cases: map[string][]string{}, closed: map[string]bool{}}
}

func (d *fakeDesk) OpenCase(_ context.Context, f *findings.Finding, title, owner, author string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nextCase++
	id := "CASE-" + string(rune('0'+d.nextCase))
	d.cases[id] = []string{f.ID}
	d.notes = append(d.notes, "opened "+id+" "+title+" for "+owner+" by "+author)
	return id, nil
}

func (d *fakeDesk) AddToCase(_ context.Context, caseID string, f *findings.Finding, _ string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cases[caseID] = append(d.cases[caseID], f.ID)
	return nil
}

func (d *fakeDesk) CaseOpen(_ context.Context, caseID string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.cases[caseID]
	return ok && !d.closed[caseID], nil
}

func (d *fakeDesk) NoteOnCase(_ context.Context, caseID, text, _ string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.notes = append(d.notes, "case "+caseID+": "+text)
	return nil
}

func (d *fakeDesk) UpdateFinding(ctx context.Context, id string, u findings.Update, author string) error {
	d.mu.Lock()
	d.notes = append(d.notes, "finding "+id+": "+u.Comment)
	d.mu.Unlock()
	f, err := d.f.Get(ctx, id)
	if err != nil {
		return err
	}
	f.Apply(u, author, time.Now())
	return d.f.Save(ctx, f)
}

func (d *fakeDesk) all() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return strings.Join(d.notes, "\n")
}

// rig is a server's runner with everything it needs, in memory, and a
// fake firewall that counts the blocks it gets.
type rig struct {
	t       *testing.T
	runner  *Runner
	runs    *Memory
	fs      *findings.Memory
	desk    *fakeDesk
	sender  *fakeSender
	audit   *respond.Memory
	blocks  atomic.Int32
	clock   time.Time
	clockMu sync.Mutex
}

func (g *rig) now() time.Time {
	g.clockMu.Lock()
	defer g.clockMu.Unlock()
	return g.clock
}

func (g *rig) advance(d time.Duration) {
	g.clockMu.Lock()
	g.clock = g.clock.Add(d)
	g.clockMu.Unlock()
}

func newRig(t *testing.T) *rig {
	t.Helper()
	g := &rig{t: t, runs: NewMemory(), fs: findings.NewMemory(), sender: &fakeSender{}, audit: &respond.Memory{},
		clock: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	g.desk = newDesk(g.fs)
	fw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.blocks.Add(1)
		_, _ = io.WriteString(w, "blocked")
	}))
	t.Cleanup(fw.Close)
	actions := &respond.Actions{}
	no := false
	err := actions.Save([]respond.Connector{
		{Name: "block", Label: "Block IP", Kind: respond.KindHTTP, Target: respond.TargetIP, Method: "POST", AllowLoopback: true,
			URL: fw.URL + "/block/{{.ip}}"},
		{Name: "tag", Label: "Tag host", Kind: respond.KindHTTP, Target: respond.TargetAny, Method: "POST", AllowLoopback: true,
			URL: fw.URL + "/tag/{{.target}}", Disruptive: &no},
	})
	if err != nil {
		t.Fatal(err)
	}
	notes := &notify.Manager{}
	if _, err := notes.Save(notify.Input{Channels: []notify.ChannelInput{
		{ID: "soc", Name: "#soc", Type: "slack", URL: "https://hooks.slack.com/services/T0/B0/x"},
		{ID: "leads", Name: "#leads", Type: "slack", URL: "https://hooks.slack.com/services/T0/B0/y"},
	}}); err != nil {
		t.Fatal(err)
	}
	g.runner = g.server("siem-a", notes, &respond.Runner{Actions: actions, Store: g.audit, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	return g
}

// server returns another runner sharing the rig's stores, as a second
// Signalith server would.
func (g *rig) server(name string, notes *notify.Manager, rr *respond.Runner) *Runner {
	if notes == nil {
		notes, rr = g.runner.Notify, g.runner.Respond
	}
	pm := &Manager{Now: g.now}
	if g.runner != nil {
		pm = g.runner.Playbooks
	}
	return &Runner{Playbooks: pm, Findings: g.fs, Runs: g.runs, Desk: g.desk, Respond: rr, Notify: notes, Sender: g.sender,
		PublicURL: func() string { return "https://siem.example.com" }, Server: name, Now: g.now,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func (g *rig) save(list ...Playbook) {
	g.t.Helper()
	if _, err := g.runner.Playbooks.Save(Input{Playbooks: list}, BuildRefs(g.runner.Notify, g.runner.Respond)); err != nil {
		g.t.Fatal(err)
	}
}

func (g *rig) finding(id, detection, urgency, src string, sample bool) *findings.Finding {
	g.t.Helper()
	f := &findings.Finding{ID: id, DetectionID: detection, Title: "Brute force from " + src, Severity: urgency, Status: findings.StatusNew,
		Entities: map[string]any{"src": src, "user": "jdoe"}, Created: g.now().Add(time.Second)}
	if sample {
		f.Sample = "load-1"
	}
	if err := g.fs.Create(context.Background(), f); err != nil {
		g.t.Fatal(err)
	}
	return f
}

func (g *rig) run(f *findings.Finding, p Playbook) Run {
	g.t.Helper()
	st, err := g.runs.Get(context.Background(), RunID(f.ID, p.ID))
	if err != nil {
		g.t.Fatalf("run of %s for %s: %v", p.ID, f.ID, err)
	}
	return st.Run
}

func bruteForce(steps ...Step) Playbook {
	return Playbook{ID: "bf", Name: "Brute force response", Enabled: true,
		Trigger: Trigger{Detections: []string{"brute-force"}, MinUrgency: "high"}, Steps: steps, ApprovalChannel: "leads"}
}

func TestTriggerMatching(t *testing.T) {
	since := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	p := Playbook{Enabled: true, Since: since, Trigger: Trigger{Detections: []string{"brute-force"}, MinUrgency: "high"},
		Steps: []Step{{Kind: StepNotify, Channel: "soc"}}}
	f := func(mut func(*findings.Finding)) *findings.Finding {
		x := &findings.Finding{DetectionID: "brute-force", Severity: "high", Created: since.Add(time.Minute)}
		if mut != nil {
			mut(x)
		}
		return x
	}
	cases := []struct {
		name string
		p    func(Playbook) Playbook
		f    *findings.Finding
		want bool
	}{
		{"match", nil, f(nil), true},
		{"urgency raised above severity", nil, f(func(x *findings.Finding) { x.Severity, x.Urgency = "medium", "critical" }), true},
		{"too low", nil, f(func(x *findings.Finding) { x.Severity = "medium" }), false},
		{"other detection", nil, f(func(x *findings.Finding) { x.DetectionID = "dns-tunnel" }), false},
		{"any detection", func(p Playbook) Playbook { p.Trigger.Detections = nil; return p }, f(func(x *findings.Finding) { x.DetectionID = "dns-tunnel" }), true},
		{"before it was turned on", nil, f(func(x *findings.Finding) { x.Created = since.Add(-time.Second) }), false},
		{"sample data", nil, f(func(x *findings.Finding) { x.Sample = "s1" }), false},
		{"sample data opted in", func(p Playbook) Playbook { p.Trigger.IncludeSample = true; return p }, f(func(x *findings.Finding) { x.Sample = "s1" }), true},
		{"off", func(p Playbook) Playbook { p.Enabled = false; return p }, f(nil), false},
		{"no steps", func(p Playbook) Playbook { p.Steps = nil; return p }, f(nil), false},
		{"default least urgency is high", func(p Playbook) Playbook { p.Trigger.MinUrgency = ""; return p }, f(func(x *findings.Finding) { x.Severity = "medium" }), false},
	}
	for _, c := range cases {
		pp := p
		if c.p != nil {
			pp = c.p(p.clone())
		}
		if got := pp.Matches(c.f); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// Two servers that both think they run the jobs claim each run once: a
// playbook runs once per finding, and never for old or sample findings.
func TestClaimRunsOnce(t *testing.T) {
	g := newRig(t)
	g.save(bruteForce(Step{Kind: StepNotify, Channel: "soc"}, Step{Kind: StepSetFinding, Status: "in_progress", Owner: "ann"}))
	old := g.finding("F-old", "brute-force", "high", "203.0.113.1", false)
	old.Created = g.now().Add(-time.Hour)
	_ = g.fs.Save(context.Background(), old)
	f := g.finding("F-1", "brute-force", "high", "203.0.113.7", false)
	g.finding("F-sample", "brute-force", "high", "203.0.113.8", true)
	g.finding("F-low", "brute-force", "low", "203.0.113.9", false)
	other := g.server("siem-b", nil, nil)
	var wg sync.WaitGroup
	for _, r := range []*Runner{g.runner, other, g.runner, other} {
		wg.Add(1)
		go func() { defer wg.Done(); r.Pass(context.Background()) }()
	}
	wg.Wait()
	if got := g.sender.list(); len(got) != 1 || got[0] != "soc finding Brute force from 203.0.113.7" {
		t.Fatalf("sent %v", got)
	}
	run := g.run(f, bruteForce())
	if run.Status != StatusSucceeded || len(run.Steps) != 2 || run.Steps[1].Text != "Set the status to In progress and the owner to ann." {
		t.Fatalf("run %+v", run)
	}
	got, _ := g.fs.Get(context.Background(), "F-1")
	if got.Status != findings.StatusInProgress || got.Owner != "ann" || len(got.Comments) != 2 || got.Comments[0].Author != "playbook Brute force response" {
		t.Errorf("finding %+v", got)
	}
	if _, total, _ := g.runs.List(context.Background(), Filter{}); total != 1 {
		t.Errorf("%d runs", total)
	}
	// Passes later do not run it again.
	g.runner.Pass(context.Background())
	if len(g.sender.list()) != 1 {
		t.Errorf("sent again: %v", g.sender.list())
	}
}

func approvalPlaybook() Playbook {
	return bruteForce(
		Step{Kind: StepNotify, Channel: "soc"},
		Step{Kind: StepAction, Action: "block", Target: TargetSrc},
		Step{Kind: StepOpenCase, Title: "Brute force from {src}", Owner: "ann"},
	)
}

func TestApproveThenRun(t *testing.T) {
	g := newRig(t)
	g.save(approvalPlaybook())
	f := g.finding("F-1", "brute-force", "critical", "203.0.113.7", false)
	g.runner.Pass(context.Background())
	run := g.run(f, approvalPlaybook())
	if run.Status != StatusWaiting || run.Approval == nil || run.Approval.Target != "203.0.113.7" || g.blocks.Load() != 0 {
		t.Fatalf("not waiting: %+v (blocks %d)", run, g.blocks.Load())
	}
	// The same sentence the Respond dialog shows.
	if !strings.HasPrefix(run.Approval.What, "Send POST to 127.0.0.1:") || !strings.HasSuffix(run.Approval.What, " for 203.0.113.7.") ||
		run.Approval.Expires.Sub(run.Approval.Requested) != ApprovalWindow {
		t.Errorf("approval %+v", run.Approval)
	}
	if sent := g.sender.list(); len(sent) != 2 || sent[1] != "leads approval Brute force from 203.0.113.7" {
		t.Errorf("sent %v", sent)
	}
	// Waiting runs are not run again by later passes.
	g.runner.Pass(context.Background())
	if g.blocks.Load() != 0 {
		t.Fatal("ran without approval")
	}
	// Two analysts approve at once: one wins.
	var wins, lost atomic.Int32
	var wg sync.WaitGroup
	for _, who := range []string{"ann", "bob"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := Decide(context.Background(), g.runs, g.desk, run.ID, who, "looks bad", true, g.now())
			var de *DecidedError
			switch {
			case err == nil:
				wins.Add(1)
			case errors.As(err, &de):
				lost.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 || lost.Load() != 1 {
		t.Fatalf("wins %d lost %d", wins.Load(), lost.Load())
	}
	run = g.run(f, approvalPlaybook())
	approver := run.Approval.DecidedBy
	if _, err := Decide(context.Background(), g.runs, g.desk, run.ID, "carl", "", false, g.now()); err == nil ||
		err.Error() != "it was already approved by "+approver {
		t.Errorf("late reject: %v", err)
	}
	// The server that runs the jobs goes on, once.
	g.runner.Pass(context.Background())
	g.server("siem-b", nil, nil).Pass(context.Background())
	run = g.run(f, approvalPlaybook())
	if run.Status != StatusSucceeded || g.blocks.Load() != 1 || run.CaseID != "CASE-1" {
		t.Fatalf("after approval %+v (blocks %d)", run, g.blocks.Load())
	}
	audit, _ := g.audit.List(context.Background(), respond.Filter{})
	if len(audit) != 1 || audit[0].ApprovedBy != approver || !audit[0].Automatic || audit[0].Actor != "Brute force response" ||
		!strings.Contains(audit[0].Reason, "Approval note: looks bad") {
		t.Errorf("audit %+v", audit)
	}
	want := []string{StepSucceeded, StepApproved, StepSucceeded, StepSucceeded}
	for i, s := range run.Steps {
		if i >= len(want) || s.Status != want[i] {
			t.Errorf("steps %+v", run.Steps)
			break
		}
	}
	notes := g.desk.all()
	for _, w := range []string{"Waiting for an analyst to approve: Send POST", "Approved by " + approver, "opened CASE-1 Brute force from 203.0.113.7 for ann",
		"case CASE-1: Opened case CASE-1"} {
		if !strings.Contains(notes, w) {
			t.Errorf("notes lack %q:\n%s", w, notes)
		}
	}
}

func TestRejectAndExpire(t *testing.T) {
	g := newRig(t)
	g.save(approvalPlaybook())
	f1 := g.finding("F-1", "brute-force", "high", "203.0.113.7", false)
	f2 := g.finding("F-2", "brute-force", "high", "203.0.113.8", false)
	g.runner.Pass(context.Background())
	r1, r2 := g.run(f1, approvalPlaybook()), g.run(f2, approvalPlaybook())
	if _, err := Decide(context.Background(), g.runs, g.desk, r1.ID, "ann", strings.Repeat("x", MaxNote+1), false, g.now()); !errors.Is(err, ErrNoteTooLong) {
		t.Errorf("long note: %v", err)
	}
	if _, err := Decide(context.Background(), g.runs, g.desk, "nope", "ann", "", true, g.now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	got, err := Decide(context.Background(), g.runs, g.desk, r1.ID, "ann", "a pentest", false, g.now())
	if err != nil || got.Status != StatusRejected {
		t.Fatalf("reject: %+v %v", got, err)
	}
	if !strings.Contains(g.desk.all(), "finding F-1: ann rejected: Send POST") || !strings.Contains(g.desk.all(), "Note: a pentest The playbook stopped.") {
		t.Errorf("notes %s", g.desk.all())
	}
	// Nobody approves the other one for a day.
	g.advance(ApprovalWindow + time.Minute)
	if _, err := Decide(context.Background(), g.runs, g.desk, r2.ID, "ann", "", true, g.now()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("late approval: %v", err)
	}
	g.runner.Pass(context.Background())
	r1, r2 = g.run(f1, approvalPlaybook()), g.run(f2, approvalPlaybook())
	if r1.Status != StatusRejected || r2.Status != StatusExpired || g.blocks.Load() != 0 || r1.CaseID != "" || r2.CaseID != "" {
		t.Fatalf("r1 %+v r2 %+v blocks %d", r1, r2, g.blocks.Load())
	}
	if r2.Steps[1].Status != StepExpired || !strings.Contains(g.desk.all(), "finding F-2: Nobody approved this within 24 hours") {
		t.Errorf("expired steps %+v notes %s", r2.Steps, g.desk.all())
	}
}

// A step that fails stops the run: later steps do not run.
func TestFailedStepStops(t *testing.T) {
	g := newRig(t)
	p := bruteForce(Step{Kind: StepNotify, Channel: "soc"}, Step{Kind: StepAction, Action: "tag", Target: TargetHost},
		Step{Kind: StepSetFinding, Status: "closed"})
	g.save(p)
	g.sender.fail = &notify.SendError{Msg: "Slack answered 404 Not Found."}
	f := g.finding("F-1", "brute-force", "high", "203.0.113.7", false)
	g.runner.Pass(context.Background())
	run := g.run(f, p)
	if run.Status != StatusFailed || len(run.Steps) != 1 || run.Error != "Could not send this finding to Slack #soc: Slack answered 404 Not Found." {
		t.Fatalf("run %+v", run)
	}
	if !strings.Contains(g.desk.all(), "Slack answered 404 Not Found. The playbook stopped.") {
		t.Errorf("notes %s", g.desk.all())
	}
	// A finding without the entity the action needs.
	g.sender.fail = nil
	f2 := g.finding("F-2", "brute-force", "high", "203.0.113.8", false)
	g.runner.Pass(context.Background())
	run = g.run(f2, p)
	if run.Status != StatusFailed || len(run.Steps) != 2 || run.Steps[1].Error != "Could not run Tag host: The finding has no host value." || g.blocks.Load() != 0 {
		t.Fatalf("run %+v", run)
	}
	got, _ := g.fs.Get(context.Background(), "F-2")
	if got.Status == findings.StatusClosed {
		t.Error("a later step ran")
	}
}

// A server that may not run the jobs runs nothing; one that loses them
// between steps leaves the run queued, and the server that has them goes
// on from the next step without doing the first again.
func TestAllowedGating(t *testing.T) {
	g := newRig(t)
	p := bruteForce(Step{Kind: StepNotify, Channel: "soc"}, Step{Kind: StepAction, Action: "tag", Target: TargetSrc})
	g.save(p)
	f := g.finding("F-1", "brute-force", "high", "203.0.113.7", false)
	g.runner.Allowed = func() bool { return false }
	g.runner.Pass(context.Background())
	if _, total, _ := g.runs.List(context.Background(), Filter{}); total != 0 || len(g.sender.list()) != 0 {
		t.Fatalf("a server without the jobs ran %d runs", total)
	}
	var asked atomic.Int32
	g.runner.Allowed = func() bool { return asked.Add(1) <= 3 } // pass, start, first step
	g.runner.Pass(context.Background())
	run := g.run(f, p)
	if run.Status != StatusQueued || run.Next != 1 || len(g.sender.list()) != 1 || g.blocks.Load() != 0 {
		t.Fatalf("handed over %+v", run)
	}
	g.server("siem-b", nil, nil).Pass(context.Background())
	run = g.run(f, p)
	if run.Status != StatusSucceeded || len(g.sender.list()) != 1 || g.blocks.Load() != 1 || run.Server != "siem-b" {
		t.Fatalf("taken over %+v sent %v blocks %d", run, g.sender.list(), g.blocks.Load())
	}
}

// A run a stopped server left running is marked interrupted, never run
// again.
func TestInterrupted(t *testing.T) {
	g := newRig(t)
	p := bruteForce(Step{Kind: StepNotify, Channel: "soc"})
	g.save(p)
	f := g.finding("F-1", "brute-force", "high", "203.0.113.7", false)
	run := &Run{ID: RunID(f.ID, p.ID), PlaybookID: p.ID, PlaybookName: p.Name, Playbook: p, FindingID: f.ID, Status: StatusRunning,
		Created: g.now(), Updated: g.now()}
	if _, err := g.runs.Claim(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	g.runner.Pass(context.Background())
	if got := g.run(f, p); got.Status != StatusRunning || len(g.sender.list()) != 0 {
		t.Fatalf("too soon: %+v", got)
	}
	g.advance(StuckAfter + time.Second)
	g.runner.Pass(context.Background())
	got := g.run(f, p)
	if got.Status != StatusInterrupted || got.Error != StoppedWhileRunning || got.Steps[0].Status != StepInterrupted || len(g.sender.list()) != 0 {
		t.Fatalf("not interrupted: %+v sent %v", got, g.sender.list())
	}
}

// Reuse adds later findings to the case an earlier run opened, while it
// is open.
func TestReuseCase(t *testing.T) {
	g := newRig(t)
	p := bruteForce(Step{Kind: StepOpenCase, Reuse: true})
	g.save(p)
	f1 := g.finding("F-1", "brute-force", "high", "203.0.113.7", false)
	g.runner.Pass(context.Background())
	g.advance(time.Second)
	f2 := g.finding("F-2", "brute-force", "high", "203.0.113.8", false)
	g.runner.Pass(context.Background())
	if a, b := g.run(f1, p), g.run(f2, p); a.CaseID != "CASE-1" || b.CaseID != "CASE-1" || len(g.desk.cases["CASE-1"]) != 2 {
		t.Fatalf("runs %+v %+v", a, b)
	}
	g.desk.closed["CASE-1"] = true
	g.advance(time.Second)
	f3 := g.finding("F-3", "brute-force", "high", "203.0.113.9", false)
	g.runner.Pass(context.Background())
	if c := g.run(f3, p); c.CaseID != "CASE-2" {
		t.Errorf("closed case reused: %+v", c)
	}
}

func TestResolveTarget(t *testing.T) {
	f := &findings.Finding{Entities: map[string]any{"src": "10.0.0.5", "dest": "Files.Example.com", "user": []any{"CORP\\jdoe"}, "process": "cmd.exe"}}
	cases := []struct {
		step        Step
		kind        string
		want, wkind string
		err         string
	}{
		{Step{Target: TargetSrc}, "ip", "10.0.0.5", "ip", ""},
		{Step{Target: TargetEntity}, "ip", "10.0.0.5", "ip", ""},
		{Step{Target: TargetEntity}, "domain", "files.example.com", "domain", ""},
		{Step{Target: TargetUser}, "any", "CORP\\jdoe", "user", ""},
		{Step{Target: TargetEntity}, "user", "CORP\\jdoe", "user", ""},
		{Step{Target: TargetFixed, Value: "198.51.100.1"}, "any", "198.51.100.1", "ip", ""},
		{Step{Target: TargetHost}, "host", "", "", "the finding has no host value"},
		{Step{Target: TargetDest}, "ip", "", "", "is not"},
	}
	for _, c := range cases {
		got, kind, err := ResolveTarget(c.step, c.kind, f)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%+v: %q %v, want error %q", c.step, got, err, c.err)
			}
			continue
		}
		if err != nil || got != c.want || kind != c.wkind {
			t.Errorf("%+v on %s: %q %q %v", c.step, c.kind, got, kind, err)
		}
	}
}

// A finding raised while no server ran the jobs, for longer than
// notify.Window, still starts its playbook.
func TestCatchUpAfterAnOutage(t *testing.T) {
	g := newRig(t)
	g.save(bruteForce(Step{Kind: StepNotify, Channel: "soc"}))
	f := g.finding("F-1", "brute-force", "high", "203.0.113.7", false)
	g.advance(5 * time.Hour)
	g.runner.Pass(context.Background())
	if run := g.run(f, bruteForce()); run.Status != StatusSucceeded {
		t.Fatalf("run %+v", run)
	}
}

// More matches than one pass starts are started on the next passes, even
// once they are older than notify.Window.
func TestManyMatchesStartOverPasses(t *testing.T) {
	g := newRig(t)
	g.save(bruteForce(Step{Kind: StepSetFinding, Owner: "ann"}))
	n := MaxStartsPerPass + 5
	for i := range n {
		g.finding(fmt.Sprintf("F-%03d", i), "brute-force", "high", "203.0.113.7", false)
	}
	g.advance(time.Hour)
	g.runner.Pass(context.Background())
	g.advance(time.Hour)
	g.runner.Pass(context.Background())
	if _, total, _ := g.runs.List(context.Background(), Filter{}); total != n {
		t.Errorf("%d runs, want %d", total, n)
	}
}

// A notify step and a notification rule that send the same finding to the
// same channel send it once.
func TestNotifyStepAndRuleSendOnce(t *testing.T) {
	g := newRig(t)
	deliveries := notify.NewMemory()
	g.runner.Deliveries = deliveries
	g.runner.Notify.Now = g.now
	if _, err := g.runner.Notify.Save(notify.Input{Channels: []notify.ChannelInput{
		{ID: "soc", Name: "#soc", Type: "slack", URL: "https://hooks.slack.com/services/T0/B0/x"},
		{ID: "leads", Name: "#leads", Type: "slack", URL: "https://hooks.slack.com/services/T0/B0/y"},
	}, Rules: []notify.RuleInput{{ID: "r1", Name: "urgent", Enabled: ptr(true), Channels: []string{"soc"}}}}); err != nil {
		t.Fatal(err)
	}
	g.save(bruteForce(Step{Kind: StepNotify, Channel: "soc"}))
	f := g.finding("F-1", "brute-force", "high", "203.0.113.7", false)
	d := &notify.Dispatcher{Settings: g.runner.Notify, Findings: g.fs, Deliveries: deliveries, Sender: g.sender, Now: g.now,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	g.runner.Pass(context.Background())
	d.Pass(context.Background())
	if got := g.sender.list(); len(got) != 1 {
		t.Fatalf("sent %v", got)
	}
	if run := g.run(f, bruteForce()); run.Status != StatusSucceeded || run.Steps[0].Text != "Sent this finding to Slack #soc." {
		t.Fatalf("run %+v", run)
	}
	// The rule first: the step says the finding already went there.
	f2 := g.finding("F-2", "brute-force", "high", "203.0.113.8", false)
	d.Pass(context.Background())
	g.runner.Pass(context.Background())
	if got := g.sender.list(); len(got) != 2 {
		t.Fatalf("sent %v", got)
	}
	if run := g.run(f2, bruteForce()); run.Status != StatusSucceeded || run.Steps[0].Text != "This finding was already sent to Slack #soc, so it was not sent again." {
		t.Fatalf("run %+v", run)
	}
}

func ptr[T any](v T) *T { return &v }
