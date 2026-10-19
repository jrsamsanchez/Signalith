package playbooks

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// failRuns is a Memory whose calls fail when a test sets their error.
type failRuns struct {
	*Memory
	due, claim, update, purge, list error
	// updateAfter lets that many updates through before update fails.
	updateAfter int
}

func (f *failRuns) Due(ctx context.Context, now, stale time.Time) ([]Stored, []Stored, []Stored, error) {
	if f.due != nil {
		return nil, nil, nil, f.due
	}
	return f.Memory.Due(ctx, now, stale)
}

func (f *failRuns) Claim(ctx context.Context, r *Run) (store.Version, error) {
	if f.claim != nil {
		return store.Version{}, f.claim
	}
	return f.Memory.Claim(ctx, r)
}

func (f *failRuns) Update(ctx context.Context, r *Run, v store.Version) (store.Version, error) {
	if f.update != nil {
		if f.updateAfter == 0 {
			return store.Version{}, f.update
		}
		f.updateAfter--
	}
	return f.Memory.Update(ctx, r, v)
}

func (f *failRuns) Purge(ctx context.Context, before time.Time) error {
	if f.purge != nil {
		return f.purge
	}
	return f.Memory.Purge(ctx, before)
}

func (f *failRuns) List(ctx context.Context, flt Filter) ([]Run, int, error) {
	if f.list != nil {
		return nil, 0, f.list
	}
	return f.Memory.List(ctx, flt)
}

// errDesk is a fakeDesk whose calls fail when a test sets their error.
type errDesk struct {
	*fakeDesk
	open, add, note, update error
}

func (d *errDesk) OpenCase(ctx context.Context, f *findings.Finding, title, owner, author string) (string, error) {
	if d.open != nil {
		return "", d.open
	}
	return d.fakeDesk.OpenCase(ctx, f, title, owner, author)
}

func (d *errDesk) AddToCase(ctx context.Context, caseID string, f *findings.Finding, author string) error {
	if d.add != nil {
		return d.add
	}
	return d.fakeDesk.AddToCase(ctx, caseID, f, author)
}

func (d *errDesk) NoteOnCase(ctx context.Context, caseID, text, author string) error {
	if d.note != nil {
		return d.note
	}
	return d.fakeDesk.NoteOnCase(ctx, caseID, text, author)
}

func (d *errDesk) UpdateFinding(ctx context.Context, id string, u findings.Update, author string) error {
	if d.update != nil {
		return d.update
	}
	return d.fakeDesk.UpdateFinding(ctx, id, u, author)
}

// logs collects a runner's log safely.
type logs struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (g *rig) logTo() *logs {
	l := &logs{}
	g.runner.Log = slog.New(slog.NewTextHandler(l, nil))
	return l
}

// queue puts a run of p for f in the store, queued at step next, as a
// server that lost the jobs leaves it.
func (g *rig) queue(f *findings.Finding, p Playbook, next int, approval *Approval) Run {
	g.t.Helper()
	run := &Run{ID: RunID(f.ID, p.ID), PlaybookID: p.ID, PlaybookName: p.Name, Playbook: p, FindingID: f.ID, FindingTitle: f.Title,
		Status: StatusQueued, Next: next, Steps: []StepResult{}, Created: g.now(), Updated: g.now()}
	if approval != nil {
		run.Status, run.Approval = StatusApproved, approval
	}
	if _, err := g.runs.Claim(context.Background(), run); err != nil {
		g.t.Fatal(err)
	}
	return *run
}

func TestRunStopsWithContext(t *testing.T) {
	g := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { g.runner.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
}

func TestStepsWithoutServices(t *testing.T) {
	g := newRig(t)
	f := g.finding("F-1", "brute-force", "high", "203.0.113.7", false)
	cases := []struct {
		step  Step
		setup func(r *Runner)
		want  string
	}{
		{Step{Kind: StepNotify, Channel: "soc"}, func(r *Runner) { r.Notify = nil }, "Could not send this finding: notifications are not available on this server."},
		{Step{Kind: StepNotify, Channel: "gone"}, nil, "Could not send this finding: the notification channel was deleted."},
		{Step{Kind: StepAction, Action: "block", Target: TargetSrc}, func(r *Runner) { r.Respond = nil }, "Could not run block: response actions are not available on this server."},
		{Step{Kind: StepAction, Action: "gone", Target: TargetSrc}, nil, "Could not run gone: the response action was deleted."},
		{Step{Kind: StepOpenCase}, func(r *Runner) { r.Desk = nil }, "Could not open a case: cases are not available on this server."},
		{Step{Kind: StepSetFinding, Owner: "ann"}, func(r *Runner) { r.Desk = nil }, "Could not change the finding: findings are not available on this server."},
		{Step{Kind: "email"}, nil, `Step 1 is of an unknown kind "email".`},
	}
	for i, c := range cases {
		r := g.server("siem-a", nil, nil)
		if c.setup != nil {
			c.setup(r)
		}
		p := Playbook{ID: "p" + string(rune('a'+i)), Name: "P", Enabled: true, Steps: []Step{c.step}}
		g.queue(f, p, 0, nil)
		r.Pass(context.Background())
		run := g.run(f, p)
		if run.Status != StatusFailed || run.Error != c.want {
			t.Errorf("%+v: %s %q", c.step, run.Status, run.Error)
		}
	}
}

func TestDeskFailures(t *testing.T) {
	g := newRig(t)
	boom := errors.New("the case store is down")
	desk := &errDesk{fakeDesk: g.desk}
	g.runner.Desk = desk
	l := g.logTo()
	f := g.finding("F-1", "brute-force", "high", "203.0.113.7", false)

	desk.open = boom
	p := Playbook{ID: "open", Name: "Open", Steps: []Step{{Kind: StepOpenCase, Title: "x"}}}
	g.queue(f, p, 0, nil)
	g.runner.Pass(context.Background())
	if run := g.run(f, p); run.Error != "Could not open a case: The case store is down." {
		t.Errorf("open = %+v", run)
	}
	desk.open = nil

	desk.update = boom
	p = Playbook{ID: "set", Name: "Set", Steps: []Step{{Kind: StepSetFinding, Status: findings.StatusClosed}}}
	g.queue(f, p, 0, nil)
	g.runner.Pass(context.Background())
	if run := g.run(f, p); run.Error != "Could not change the finding: The case store is down." {
		t.Errorf("set = %+v", run)
	}
	if !strings.Contains(l.String(), "could not note a playbook step on the finding") {
		t.Errorf("note failure not logged: %s", l)
	}
	desk.update = nil

	// Reuse: the earlier runs cannot be listed, or the finding cannot be
	// added to the case they opened.
	runs := &failRuns{Memory: g.runs, list: boom}
	g.runner.Runs = runs
	p = Playbook{ID: "reuse", Name: "Reuse", Steps: []Step{{Kind: StepOpenCase, Reuse: true}}}
	g.queue(f, p, 0, nil)
	g.runner.Pass(context.Background())
	if run := g.run(f, p); !strings.HasPrefix(run.Error, "Could not look for the case this playbook opened earlier") {
		t.Errorf("reuse list = %+v", run)
	}
	runs.list = nil
	f2 := g.finding("F-2", "brute-force", "high", "203.0.113.8", false)
	prev := &Run{ID: "earlier", PlaybookID: "reuse2", Status: StatusSucceeded, CaseID: "CASE-9", Created: g.now()}
	_, _ = g.runs.Claim(context.Background(), prev)
	desk.cases["CASE-9"] = []string{"F-0"}
	desk.add = boom
	p = Playbook{ID: "reuse2", Name: "Reuse", Steps: []Step{{Kind: StepOpenCase, Reuse: true}}}
	g.queue(f2, p, 0, nil)
	g.runner.Pass(context.Background())
	if run := g.run(f2, p); run.Error != "Could not add this finding to case CASE-9: The case store is down." {
		t.Errorf("reuse add = %+v", run)
	}
	desk.add = nil

	// A run already in an open case opens no other; a note on the case
	// that fails is logged.
	f3 := g.finding("F-3", "brute-force", "high", "203.0.113.9", false)
	desk.note = boom
	p = Playbook{ID: "incase", Name: "In case", Steps: []Step{{Kind: StepOpenCase}}}
	run := &Run{ID: RunID(f3.ID, p.ID), PlaybookID: p.ID, PlaybookName: p.Name, Playbook: p, FindingID: f3.ID, Status: StatusQueued,
		CaseID: "CASE-9", Created: g.now(), Updated: g.now()}
	_, _ = g.runs.Claim(context.Background(), run)
	g.runner.Pass(context.Background())
	if got := g.run(f3, p); got.Status != StatusSucceeded || !strings.Contains(got.Steps[0].Text, "already in case CASE-9") {
		t.Errorf("in case = %+v", got)
	}
	if !strings.Contains(l.String(), "could not note a playbook step on the case") {
		t.Errorf("case note failure not logged: %s", l)
	}
}

func TestResumeProblems(t *testing.T) {
	g := newRig(t)
	l := g.logTo()
	f := g.finding("F-1", "brute-force", "high", "203.0.113.7", false)

	// The finding was deleted, or cannot be read.
	p := Playbook{ID: "p", Name: "P", Steps: []Step{{Kind: StepSetFinding, Owner: "ann"}}}
	ghost := &findings.Finding{ID: "F-gone", Title: "gone"}
	g.queue(ghost, p, 0, nil)
	g.runner.Pass(context.Background())
	if run := g.run(ghost, p); run.Status != StatusFailed || run.Error != "The finding was deleted, so the playbook stopped." {
		t.Errorf("deleted finding = %+v", run)
	}

	// An approved action runs with the approver; without response actions,
	// or when the action cannot run, the step fails.
	block := Playbook{ID: "b", Name: "Block", Steps: []Step{{Kind: StepAction, Action: "block", Target: TargetSrc}}}
	appr := &Approval{Step: 0, Action: "block", ActionLabel: "Block IP", Target: "203.0.113.7", TargetKind: "ip", DecidedBy: "ann"}
	r := g.server("siem-a", nil, nil)
	r.Respond = nil
	g.queue(f, block, 0, appr)
	r.Pass(context.Background())
	if run := g.run(f, block); run.Status != StatusFailed || run.Error != "Could not run Block IP: response actions are not available on this server." {
		t.Errorf("no respond = %+v", run)
	}
	f2 := g.finding("F-2", "brute-force", "high", "203.0.113.8", false)
	r = g.server("siem-a", nil, nil)
	r.Respond = &respond.Runner{Actions: g.runner.Respond.Actions} // no audit log: nothing runs
	appr2 := *appr
	appr2.ActionLabel = ""
	g.queue(f2, block, 0, &appr2)
	r.Pass(context.Background())
	if run := g.run(f2, block); run.Status != StatusFailed || !strings.HasPrefix(run.Error, "Could not run block on 203.0.113.7: ") || g.blocks.Load() != 0 {
		t.Errorf("no audit = %+v", run)
	}

	// Someone else took it first: nothing happens.
	f3 := g.finding("F-3", "brute-force", "high", "203.0.113.9", false)
	runs := &failRuns{Memory: g.runs, update: store.ErrConflict}
	g.runner.Runs = runs
	g.queue(f3, p, 0, nil)
	g.runner.Pass(context.Background())
	if run := g.run(f3, p); run.Status != StatusQueued {
		t.Errorf("conflict = %+v", run)
	}
	// A store error is logged.
	runs.update = errors.New("down")
	g.runner.Pass(context.Background())
	if !strings.Contains(l.String(), "could not claim a playbook run to go on with") {
		t.Errorf("not logged: %s", l)
	}
	// A run that cannot be recorded after its step stops there.
	runs.updateAfter = 1
	g.runner.Pass(context.Background())
	if !strings.Contains(l.String(), "could not record a playbook run; it stops here") {
		t.Errorf("write failure not logged: %s", l)
	}
}

func TestFailingAction(t *testing.T) {
	g := newRig(t)
	fw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer fw.Close()
	no := false
	actions := &respond.Actions{}
	if err := actions.Save([]respond.Connector{{Name: "tag", Label: "Tag host", Kind: respond.KindHTTP, Target: respond.TargetAny, Method: "POST",
		AllowLoopback: true, URL: fw.URL + "/tag/{{.target}}", Disruptive: &no}}); err != nil {
		t.Fatal(err)
	}
	g.runner.Respond = &respond.Runner{Actions: actions, Store: g.audit, Log: slog.New(slog.DiscardHandler)}
	f := g.finding("F-1", "brute-force", "high", "203.0.113.7", false)
	p := Playbook{ID: "t", Name: "Tag", Steps: []Step{{Kind: StepAction, Action: "tag", Target: TargetSrc}, {Kind: StepSetFinding, Owner: "ann"}}}
	g.queue(f, p, 0, nil)
	g.runner.Pass(context.Background())
	run := g.run(f, p)
	if run.Status != StatusFailed || run.Steps[0].Status != StepFailed || run.Error == "" || len(run.Steps) != 1 {
		t.Errorf("failed action = %+v", run)
	}
	if !strings.Contains(g.desk.all(), "The playbook stopped.") {
		t.Errorf("notes = %s", g.desk.all())
	}
}

func TestApprovalRequestProblems(t *testing.T) {
	g := newRig(t)
	l := g.logTo()
	// The approval channel was deleted after the run started.
	p := Playbook{ID: "p", Name: "P", ApprovalChannel: "gone", Steps: []Step{{Kind: StepAction, Action: "block", Target: TargetSrc}}}
	f := g.finding("F-1", "brute-force", "high", "203.0.113.7", false)
	g.queue(f, p, 0, nil)
	g.runner.Pass(context.Background())
	if run := g.run(f, p); run.Status != StatusWaiting {
		t.Fatalf("run = %+v", run)
	}
	if !strings.Contains(l.String(), "could not ask for a playbook approval") {
		t.Errorf("deleted channel not logged: %s", l)
	}

	g2 := newRig(t)
	l2 := g2.logTo()
	g2.save(approvalPlaybook())
	f2 := g2.finding("F-1", "brute-force", "high", "203.0.113.7", false)
	g2.sender.fail = errors.New("slack is down")
	g2.runner.Pass(context.Background())
	if run := g2.run(f2, approvalPlaybook()); run.Status != StatusFailed {
		// The first step, notify, fails first: the run stops there.
		t.Fatalf("run = %+v", run)
	}
	g2.sender.fail = nil
	p2 := approvalPlaybook()
	p2.ID, p2.Steps = "bf2", p2.Steps[1:]
	g2.save(p2)
	f3 := g2.finding("F-2", "brute-force", "high", "203.0.113.8", false)
	g2.sender.mu.Lock()
	g2.sender.fail = errors.New("slack is down")
	g2.sender.mu.Unlock()
	g2.runner.Pass(context.Background())
	if run := g2.run(f3, p2); run.Status != StatusWaiting {
		t.Fatalf("run = %+v", run)
	}
	if !strings.Contains(l2.String(), "could not ask for a playbook approval") || !strings.Contains(l2.String(), "slack is down") {
		t.Errorf("send failure not logged: %s", l2)
	}
}

func TestPassProblems(t *testing.T) {
	g := newRig(t)
	l := g.logTo()
	boom := errors.New("opensearch down")
	runs := &failRuns{Memory: g.runs, due: boom, purge: boom}
	g.runner.Runs = runs
	g.runner.Pass(context.Background())
	g.runner.Pass(context.Background())
	out := l.String()
	if strings.Count(out, "could not read the playbook runs to go on with") != 1 {
		t.Errorf("due problem logged %d times: %s", strings.Count(out, "could not read the playbook runs"), out)
	}
	if !strings.Contains(out, "could not delete old playbook runs") {
		t.Errorf("purge not logged: %s", out)
	}
	runs.due = nil

	// A playbooks file that cannot be read starts nothing.
	path := filepath.Join(t.TempDir(), "playbooks.yaml")
	if err := os.WriteFile(path, []byte("playbooks: [:"), 0o600); err != nil {
		t.Fatal(err)
	}
	g.runner.Playbooks = &Manager{File: path}
	g.runner.Pass(context.Background())
	if !strings.Contains(l.String(), "playbooks do not start until the playbooks file is fixed") {
		t.Errorf("file problem not logged: %s", l)
	}

	// A claim that fails for another reason than an existing run is
	// logged, and the playbook does not run.
	g.runner.Playbooks = &Manager{Now: g.now}
	if _, err := g.runner.Playbooks.Save(Input{Playbooks: []Playbook{bruteForce(Step{Kind: StepSetFinding, Owner: "ann"})}}, BuildRefs(g.runner.Notify, g.runner.Respond)); err != nil {
		t.Fatal(err)
	}
	f := g.finding("F-1", "brute-force", "high", "203.0.113.7", false)
	runs.claim = boom
	g.runner.Pass(context.Background())
	if !strings.Contains(l.String(), "could not claim a playbook run") {
		t.Errorf("claim failure not logged: %s", l)
	}
	if got, _ := g.fs.Get(context.Background(), f.ID); got.Owner != "" {
		t.Errorf("ran without a claim: %+v", got)
	}
}

func TestInterruptAndExpireConflicts(t *testing.T) {
	g := newRig(t)
	l := g.logTo()
	f := g.finding("F-1", "brute-force", "high", "203.0.113.7", false)
	p := Playbook{ID: "p", Name: "P", Steps: []Step{{Kind: StepSetFinding, Owner: "ann"}}}
	stuck := &Run{ID: RunID(f.ID, p.ID), PlaybookID: p.ID, PlaybookName: p.Name, Playbook: p, FindingID: f.ID, Status: StatusRunning,
		Next: 1, Created: g.now(), Updated: g.now()}
	_, _ = g.runs.Claim(context.Background(), stuck)
	f2 := g.finding("F-2", "brute-force", "high", "203.0.113.8", false)
	waiting := &Run{ID: RunID(f2.ID, p.ID), PlaybookID: p.ID, PlaybookName: p.Name, Playbook: p, FindingID: f2.ID, Status: StatusWaiting,
		Created: g.now(), Updated: g.now(), Approval: &Approval{Expires: g.now(), What: "Block 203.0.113.8."}}
	_, _ = g.runs.Claim(context.Background(), waiting)
	g.advance(StuckAfter + time.Minute)
	runs := &failRuns{Memory: g.runs, update: errors.New("down")}
	g.runner.Runs = runs
	g.runner.Pass(context.Background())
	out := l.String()
	if !strings.Contains(out, "could not mark a playbook run left running as interrupted") || !strings.Contains(out, "could not expire a playbook run") {
		t.Errorf("not logged: %s", out)
	}
	if g.run(f, p).Status != StatusRunning || g.run(f2, p).Status != StatusWaiting {
		t.Error("runs changed despite the failed writes")
	}
	// A conflict is someone else's change: nothing is logged.
	runs.update = store.ErrConflict
	before := strings.Count(l.String(), "could not")
	g.runner.Pass(context.Background())
	if strings.Count(l.String(), "could not") != before {
		t.Errorf("conflict logged: %s", l)
	}
	// With the step done, an interrupted run adds no step result.
	g.runner.Runs = g.runs
	g.runner.Pass(context.Background())
	if run := g.run(f, p); run.Status != StatusInterrupted || len(run.Steps) != 0 {
		t.Errorf("interrupted = %+v", run)
	}
	if run := g.run(f2, p); run.Status != StatusExpired || !strings.Contains(g.desk.all(), "so it was not done: Block 203.0.113.8. The playbook stopped.") {
		t.Errorf("expired = %+v %s", run, g.desk.all())
	}
}

func TestResolveTargetNouns(t *testing.T) {
	f := &findings.Finding{Entities: map[string]any{"process": "cmd.exe!"}}
	for kind, noun := range map[string]string{"ip": "an IP address", "domain": "a domain", "user": "a user name", "host": "a host", "hash": "a value"} {
		_, _, err := ResolveTarget(Step{Target: TargetEntity}, kind, f)
		if err == nil || !strings.Contains(err.Error(), "is "+noun+" it can act on") {
			t.Errorf("%s: %v", kind, err)
		}
	}
}

func TestDefaults(t *testing.T) {
	r := &Runner{}
	if r.log() != slog.Default() || r.publicURL() != "" || !r.allowed() {
		t.Error("runner defaults")
	}
	if Author("X") != "playbook X" {
		t.Error("author")
	}
}
