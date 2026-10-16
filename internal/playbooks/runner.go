package playbooks

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The runner is the background job "playbooks". Every Interval it reads
// the findings raised since its last pass, as the notifications
// dispatcher does (see notify.Reader), and starts each playbook whose
// trigger a new finding matches. Only the server that runs the background jobs does, and it
// asks Allowed before each step, so a server that lost the jobs stops at
// once.
//
// Each run is claimed before its first step, by creating its document
// with the ID RunID(finding, playbook): when that document is already
// there, the playbook ran, or is running, for that finding, here or on
// another server, and it is not started again. Steps then run in order,
// and the run is written again after each one. A run left "running" by a
// server that stopped is marked interrupted and never run again: its last
// step may or may not have happened. A server that loses the jobs between
// two steps leaves its run "queued", and the server that takes them over
// goes on from the next step.
//
// An action step that needs approval pauses the run as "waiting for
// approval" for ApprovalWindow. An analyst approves or rejects it on the
// Approvals page (Decide); the runner picks approved runs up on its next
// pass and goes on with the approver recorded, so an approved action runs
// once, on the server that runs the jobs. A rejected or expired step, or
// one that fails, stops the run.

// Timing and limits of the runner.
const (
	Interval = 15 * time.Second
	// ApprovalWindow is how long a step waits for approval.
	ApprovalWindow = 24 * time.Hour
	// StuckAfter is how long a run may go without a change while running
	// before it is taken for one a stopped server left. It is longer than
	// the longest script action may run.
	StuckAfter = time.Duration(respond.MaxScriptTimeout)*time.Second + 5*time.Minute
	// KeepFor is how long finished runs are kept.
	KeepFor = 90 * 24 * time.Hour
	// MaxStartsPerPass is the most runs one pass starts; the rest start
	// on the next passes.
	MaxStartsPerPass = 50
	// MaxNote is the longest approval note.
	MaxNote = 1000
	// purgeEvery is how often old runs are deleted.
	purgeEvery = time.Hour
)

// StoppedWhileRunning is the error of a run a stopped server left.
const StoppedWhileRunning = "The Signalith server stopped while this playbook ran, so its last step may or may not have happened. It is not run again; check the finding."

// Desk is what a run changes besides running response actions: findings
// and cases. The API server provides it, so its changes are made one at a
// time with the analysts' own.
type Desk interface {
	// OpenCase opens a case about a finding, adds the finding to it and
	// returns its ID.
	OpenCase(ctx context.Context, f *findings.Finding, title, owner, author string) (string, error)
	// AddToCase adds a finding to a case.
	AddToCase(ctx context.Context, caseID string, f *findings.Finding, author string) error
	// CaseOpen reports whether a case exists and is still open.
	CaseOpen(ctx context.Context, caseID string) (bool, error)
	// NoteOnCase adds a note to a case's timeline.
	NoteOnCase(ctx context.Context, caseID, text, author string) error
	// UpdateFinding changes a finding's status or owner, and adds the
	// update's comment.
	UpdateFinding(ctx context.Context, findingID string, u findings.Update, author string) error
}

// Runner runs the playbooks.
type Runner struct {
	Playbooks *Manager
	Findings  findings.Store
	Runs      Runs
	// Desk changes findings and cases; nil skips the notes and fails
	// open_case and set_finding steps.
	Desk Desk
	// Respond runs action steps; nil fails them.
	Respond *respond.Runner
	// Notify and Sender send notify steps and approval messages; nil
	// fails notify steps.
	Notify *notify.Manager
	Sender notify.Sender
	// Deliveries records notify steps with the notifications' own
	// deliveries, so a finding a rule already sent to a channel is not
	// sent there again, and the other way round. nil sends every step.
	Deliveries notify.Deliveries
	// PublicURL returns server.public_url, for the links in messages.
	PublicURL func() string
	// Server names this server in the runs it makes.
	Server string
	// Allowed reports whether this server may run steps now: it runs the
	// background jobs. nil always may.
	Allowed func() bool
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	Log *slog.Logger

	reader    notify.Reader
	mu        sync.Mutex
	inFlight  map[string]bool // runs this server is running
	warned    bool            // a pass read the most findings it may; logged once
	lastPurge time.Time
	lastErr   string
	last      time.Time
}

// now returns the time, never the same twice: Windows clocks can repeat,
// and runs and steps stay in order.
func (r *Runner) now() time.Time {
	t := time.Now()
	if r.Now != nil {
		t = r.Now()
	}
	t = t.UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !t.After(r.last) {
		t = r.last.Add(time.Microsecond)
	}
	r.last = t
	return t
}

func (r *Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func (r *Runner) allowed() bool { return r.Allowed == nil || r.Allowed() }

func (r *Runner) publicURL() string {
	if r.PublicURL == nil {
		return ""
	}
	return r.PublicURL()
}

// Author is who a playbook's notes are written as: "playbook <name>", as
// response actions it runs are.
func Author(name string) string { return "playbook " + name }

// Run runs a pass every Interval until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	t := time.NewTicker(Interval)
	defer t.Stop()
	for {
		r.Pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Pass does what is due once: it marks runs a stopped server left as
// interrupted, expires approvals nobody gave, goes on with approved and
// queued runs, and starts the playbooks new findings match.
func (r *Runner) Pass(ctx context.Context) {
	if !r.allowed() || ctx.Err() != nil {
		return
	}
	now := r.now()
	r.purge(ctx, now)
	resume, expired, stuck, err := r.Runs.Due(ctx, now, now.Add(-StuckAfter))
	if err != nil {
		r.problem("could not read the playbook runs to go on with", err)
		return
	}
	for _, st := range stuck {
		r.interrupt(ctx, st)
	}
	for _, st := range expired {
		r.expire(ctx, st)
	}
	for _, st := range resume {
		if ctx.Err() != nil || !r.allowed() {
			return
		}
		r.resume(ctx, st)
	}
	list, err := r.Playbooks.List()
	if err != nil {
		// A file that cannot be read starts nothing, so a bad hand edit
		// never runs the wrong steps; the page says why.
		r.problem("playbooks do not start until the playbooks file is fixed", err)
		return
	}
	if err := r.start(ctx, list, now); err != nil {
		r.problem("could not read new findings for playbooks", err)
	} else {
		r.problem("", nil)
	}
}

// start starts the playbooks that new findings match, oldest finding
// first, each playbook at most once per finding.
func (r *Runner) start(ctx context.Context, list []Playbook, now time.Time) error {
	var active []Playbook
	for _, p := range list {
		if p.Enabled && len(p.Steps) > 0 {
			active = append(active, p)
		}
	}
	if len(active) == 0 {
		r.reader.Done(now)
		return nil
	}
	fs, truncated, err := r.reader.Read(ctx, r.Findings, now)
	if err != nil {
		return err
	}
	r.mu.Lock()
	warn := truncated && !r.warned
	r.warned = truncated
	r.mu.Unlock()
	if warn {
		r.log().Warn("more findings were raised than one playbooks pass reads; the oldest do not start playbooks", "read", len(fs))
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if !fs[i].Created.Equal(fs[j].Created) {
			return fs[i].Created.Before(fs[j].Created)
		}
		return fs[i].ID < fs[j].ID
	})
	type want struct {
		f *findings.Finding
		p Playbook
	}
	var wants []want
	var ids []string
	for _, f := range fs {
		for _, p := range active {
			if p.Matches(f) {
				wants = append(wants, want{f, p})
				ids = append(ids, RunID(f.ID, p.ID))
			}
		}
	}
	if len(wants) == 0 {
		r.reader.Done(now)
		return nil
	}
	have, err := r.Runs.Existing(ctx, ids)
	if err != nil {
		return err
	}
	started := 0
	for i, w := range wants {
		if have[ids[i]] {
			continue
		}
		if ctx.Err() != nil || !r.allowed() {
			return nil
		}
		if started == MaxStartsPerPass {
			r.log().Warn("many findings matched playbooks at once; the rest start on the next passes", "started", started)
			return nil
		}
		started++
		r.begin(ctx, w.p, w.f)
	}
	// Every match started, or had: the next pass need not read these
	// findings again. A pass cut short above leaves them for the next.
	r.reader.Done(now)
	return nil
}

// begin claims and runs a playbook for a finding.
func (r *Runner) begin(ctx context.Context, p Playbook, f *findings.Finding) {
	now := r.now()
	run := &Run{
		ID: RunID(f.ID, p.ID), PlaybookID: p.ID, PlaybookName: p.Name, Playbook: p.clone(), FindingID: f.ID,
		FindingTitle: cut(f.Title, 300), DetectionID: f.DetectionID, Urgency: f.EffectiveUrgency(), Sample: f.Sample != "",
		Status: StatusRunning, Steps: []StepResult{}, CaseID: f.CaseID, Server: r.Server, Created: now, Updated: now,
	}
	r.mark(run.ID, true)
	defer r.mark(run.ID, false)
	v, err := r.Runs.Claim(ctx, run)
	if err != nil {
		if !errors.Is(err, store.ErrExists) {
			r.log().Warn("could not claim a playbook run", "playbook", p.Name, "finding", f.ID, "err", err)
		}
		return
	}
	r.log().Info("playbook started", "playbook", p.Name, "finding", f.ID, "run", run.ID)
	r.advance(ctx, run, v, f, nil)
}

// resume goes on with an approved or queued run, from its next step.
func (r *Runner) resume(ctx context.Context, st Stored) {
	if r.sending(st.ID) {
		return
	}
	run := st.Run
	var approved *Approval
	if run.Status == StatusApproved && run.Approval != nil {
		a := *run.Approval
		approved = &a
	}
	run.Status, run.Server, run.Updated = StatusRunning, r.Server, r.now()
	r.mark(run.ID, true)
	defer r.mark(run.ID, false)
	v, err := r.Runs.Update(ctx, &run, st.Version)
	if err != nil {
		if !store.IsConflict(err) {
			r.log().Warn("could not claim a playbook run to go on with", "playbook", run.PlaybookName, "run", run.ID, "err", err)
		}
		return
	}
	f, err := r.Findings.Get(ctx, run.FindingID)
	if err != nil {
		msg := "The finding could not be read, so the playbook stopped: " + err.Error()
		if errors.Is(err, findings.ErrNotFound) {
			msg = "The finding was deleted, so the playbook stopped."
		}
		run.Status, run.Error, run.Finished = StatusFailed, msg, r.now()
		r.write(ctx, &run, v)
		return
	}
	if approved != nil {
		r.log().Info("playbook goes on after approval", "playbook", run.PlaybookName, "run", run.ID, "approved_by", approved.DecidedBy)
	}
	r.advance(ctx, &run, v, f, approved)
}

// outcome is what doing a step gave.
type outcome struct {
	res StepResult
	// wait pauses the run for approval; run.Approval says what waits.
	wait bool
	// onFinding and onCase are true when the step already noted itself
	// there (a response action, a finding update).
	onFinding, onCase bool
}

// advance runs a run's steps from run.Next, writing it after each one,
// until it ends, waits for approval, or this server may no longer run
// steps. approved is the approval of the step at run.Next, if any.
func (r *Runner) advance(ctx context.Context, run *Run, v store.Version, f *findings.Finding, approved *Approval) {
	steps := run.Playbook.Steps
	for run.Next < len(steps) {
		if ctx.Err() != nil || !r.allowed() {
			// Stopped between two steps: the server that runs the jobs
			// goes on from the next one.
			run.Status = StatusQueued
			r.write(ctx, run, v)
			r.log().Info("playbook run handed over to the server that runs the background jobs", "playbook", run.PlaybookName, "run", run.ID)
			return
		}
		i := run.Next
		var o outcome
		if approved != nil && approved.Step == i {
			o = r.runAction(ctx, run, approved)
			approved = nil
		} else {
			o = r.do(ctx, run, f, steps[i], i)
		}
		o.res.Step, o.res.Kind, o.res.Time = i, steps[i].Kind, r.now()
		run.Steps = append(run.Steps, o.res)
		switch {
		case o.wait:
			run.Status = StatusWaiting
		case o.res.Status == StepFailed:
			run.Next = i + 1
			run.Status, run.Error, run.Finished = StatusFailed, o.res.Error, r.now()
		default:
			run.Next = i + 1
		}
		nv, ok := r.write(ctx, run, v)
		text := o.res.Text
		if o.res.Status == StepFailed {
			text = strings.TrimSpace(text + " The playbook stopped.")
		}
		if o.onFinding && o.onCase {
			if o.res.Status == StepFailed {
				r.note(ctx, run, "The playbook stopped because this step failed.", true)
			}
		} else {
			r.note(ctx, run, text, !o.onFinding)
		}
		if !ok {
			return
		}
		v = nv
		if o.wait {
			r.askApproval(ctx, run, f)
			return
		}
		if run.Status == StatusFailed {
			r.log().Warn("playbook stopped: a step failed", "playbook", run.PlaybookName, "run", run.ID, "step", i+1, "error", o.res.Error)
			return
		}
	}
	run.Status, run.Finished = StatusSucceeded, r.now()
	r.write(ctx, run, v)
	r.log().Info("playbook finished", "playbook", run.PlaybookName, "run", run.ID, "steps", len(steps))
}

// write records a run; it reports false when it could not, and the run
// then stops here.
func (r *Runner) write(ctx context.Context, run *Run, v store.Version) (store.Version, bool) {
	run.Updated, run.Server = r.now(), r.Server
	// Written whatever happens to ctx: the step happened or not.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	nv, err := r.Runs.Update(wctx, run, v)
	if err != nil {
		r.log().Warn("could not record a playbook run; it stops here", "playbook", run.PlaybookName, "run", run.ID, "status", run.Status, "err", err)
		return v, false
	}
	return nv, true
}

// note writes text on the finding (when onFinding) and on the run's case,
// as the playbook.
func (r *Runner) note(ctx context.Context, run *Run, text string, onFinding bool) {
	if r.Desk == nil || text == "" {
		return
	}
	nctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	author := Author(run.PlaybookName)
	if onFinding {
		if err := r.Desk.UpdateFinding(nctx, run.FindingID, findings.Update{Comment: text}, author); err != nil {
			r.log().Warn("could not note a playbook step on the finding", "run", run.ID, "err", err)
		}
	}
	if run.CaseID != "" {
		if err := r.Desk.NoteOnCase(nctx, run.CaseID, text, author); err != nil {
			r.log().Warn("could not note a playbook step on the case", "run", run.ID, "case", run.CaseID, "err", err)
		}
	}
}

func failed(format string, args ...any) outcome {
	msg := fmt.Sprintf(format, args...)
	return outcome{res: StepResult{Status: StepFailed, Text: msg, Error: msg}}
}

// do does one step.
func (r *Runner) do(ctx context.Context, run *Run, f *findings.Finding, s Step, i int) outcome {
	switch s.Kind {
	case StepNotify:
		return r.doNotify(ctx, run, f, s)
	case StepAction:
		return r.doAction(ctx, run, f, s, i)
	case StepOpenCase:
		return r.doOpenCase(ctx, run, f, s)
	case StepSetFinding:
		return r.doSetFinding(ctx, run, s)
	}
	return failed("Step %d is of an unknown kind %q.", i+1, s.Kind)
}

func (r *Runner) channel(id string) (notify.Channel, error) {
	if r.Notify == nil || r.Sender == nil {
		return notify.Channel{}, errors.New("notifications are not available on this server")
	}
	set, err := r.Notify.Settings()
	if err != nil {
		return notify.Channel{}, err
	}
	c, ok := set.Channel(id)
	if !ok {
		return notify.Channel{}, errors.New("the notification channel was deleted")
	}
	return c, nil
}

func (r *Runner) doNotify(ctx context.Context, run *Run, f *findings.Finding, s Step) outcome {
	c, err := r.channel(s.Channel)
	if err != nil {
		return failed("Could not send this finding: %s.", strings.TrimSuffix(err.Error(), "."))
	}
	m := notify.NewMessage(f, notify.FindingsLink(r.publicURL()))
	again := false
	if r.Deliveries == nil {
		err = r.Sender.Send(ctx, c, m)
	} else {
		again, err = notify.SendOnce(ctx, r.Sender, r.Deliveries, c, m, run.PlaybookName, r.Server, r.Now)
	}
	switch {
	case errors.Is(err, notify.ErrAlreadySent):
		return outcome{res: StepResult{Status: StepSucceeded, Text: "This finding was already sent to " + c.Label() + ", so it was not sent again."}}
	case err != nil:
		text := "Could not send this finding to " + c.Label() + ": " + sentence(err.Error())
		if again {
			text += " It is tried again later, as the Notifications page shows."
		}
		return failed("%s", text)
	}
	return outcome{res: StepResult{Status: StepSucceeded, Text: "Sent this finding to " + c.Label() + "."}}
}

func (r *Runner) doAction(ctx context.Context, run *Run, f *findings.Finding, s Step, i int) outcome {
	if r.Respond == nil || r.Respond.Actions == nil {
		return failed("Could not run %s: response actions are not available on this server.", s.Action)
	}
	c, ok, err := r.Respond.Actions.Get(s.Action)
	if err != nil {
		return failed("Could not run %s: %s", s.Action, sentence(err.Error()))
	}
	if !ok {
		return failed("Could not run %s: the response action was deleted.", s.Action)
	}
	target, kind, err := ResolveTarget(s, c.Target, f)
	if err != nil {
		return failed("Could not run %s: %s", c.Label, sentence(err.Error()))
	}
	a := &Approval{Step: i, Action: c.Name, ActionLabel: c.Label, Target: target, TargetKind: kind}
	if !s.NeedsApproval && !c.IsDisruptive() {
		return r.runAction(ctx, run, a)
	}
	now := r.now()
	a.What, a.Requested, a.Expires = r.Respond.Describe(c, target), now, now.Add(ApprovalWindow)
	run.Approval = a
	return outcome{wait: true, res: StepResult{Status: StepWaiting,
		Text: "Waiting for an analyst to approve: " + a.What + " It is not done unless someone approves it within 24 hours."}}
}

// runAction runs the action an action step names on its target, as the
// playbook, with the approver when it was approved.
func (r *Runner) runAction(ctx context.Context, run *Run, a *Approval) outcome {
	if r.Respond == nil {
		return failed("Could not run %s: response actions are not available on this server.", a.ActionLabel)
	}
	reason := fmt.Sprintf("Playbook %s, for finding %s (%s).", run.PlaybookName, cut(run.FindingTitle, 200), run.FindingID)
	if a.Note != "" {
		reason += " Approval note: " + a.Note
	}
	rr, err := r.Respond.Run(ctx, respond.Request{
		Action: a.Action, Target: a.Target, TargetKind: a.TargetKind, FindingID: run.FindingID, CaseID: run.CaseID,
		Reason: cut(reason, respond.MaxReason), Actor: respond.Actor{Name: run.PlaybookName, Automatic: true, ApprovedBy: a.DecidedBy},
	})
	if err != nil {
		label := a.ActionLabel
		if label == "" {
			label = a.Action
		}
		return failed("Could not run %s on %s: %s", label, a.Target, sentence(err.Error()))
	}
	recorded := r.Respond.Record != nil
	o := outcome{res: StepResult{Status: StepSucceeded, Text: rr.Text(), ActionRun: rr.ID}, onFinding: recorded, onCase: recorded}
	if rr.Status != respond.StatusSucceeded {
		o.res.Status, o.res.Error = StepFailed, rr.Error
		if o.res.Error == "" {
			o.res.Error = "The action " + rr.Status + "."
		}
	}
	return o
}

func (r *Runner) doOpenCase(ctx context.Context, run *Run, f *findings.Finding, s Step) outcome {
	if r.Desk == nil {
		return failed("Could not open a case: cases are not available on this server.")
	}
	author := Author(run.PlaybookName)
	if run.CaseID != "" {
		if open, err := r.Desk.CaseOpen(ctx, run.CaseID); err == nil && open {
			return outcome{res: StepResult{Status: StepSucceeded, Text: "This finding is already in case " + run.CaseID + ", so no case was opened."}}
		}
	}
	if s.Reuse {
		prev, _, err := r.Runs.List(ctx, Filter{PlaybookID: run.PlaybookID, Limit: 50})
		if err != nil {
			return failed("Could not look for the case this playbook opened earlier: %s", sentence(err.Error()))
		}
		seen := map[string]bool{}
		for _, p := range prev {
			if p.ID == run.ID || p.CaseID == "" || seen[p.CaseID] {
				continue
			}
			seen[p.CaseID] = true
			open, err := r.Desk.CaseOpen(ctx, p.CaseID)
			if err != nil || !open {
				continue
			}
			if err := r.Desk.AddToCase(ctx, p.CaseID, f, author); err != nil {
				return failed("Could not add this finding to case %s: %s", p.CaseID, sentence(err.Error()))
			}
			run.CaseID = p.CaseID
			return outcome{res: StepResult{Status: StepSucceeded, Text: "Added this finding to case " + p.CaseID + ", which this playbook opened earlier."}}
		}
	}
	title := Expand(s.Title, f)
	id, err := r.Desk.OpenCase(ctx, f, title, s.Owner, author)
	if err != nil {
		return failed("Could not open a case: %s", sentence(err.Error()))
	}
	run.CaseID = id
	text := "Opened case " + id + ": " + title + "."
	if s.Owner != "" {
		text += " Assigned to " + s.Owner + "."
	}
	return outcome{res: StepResult{Status: StepSucceeded, Text: text}}
}

func (r *Runner) doSetFinding(ctx context.Context, run *Run, s Step) outcome {
	if r.Desk == nil {
		return failed("Could not change the finding: findings are not available on this server.")
	}
	var u findings.Update
	var bits []string
	if s.Status != "" {
		st := s.Status
		u.Status = &st
		bits = append(bits, "the status to "+StatusLabels[st])
	}
	if s.Owner != "" {
		o := s.Owner
		u.Owner = &o
		bits = append(bits, "the owner to "+o)
	}
	text := "Set " + joinAnd(bits) + "."
	u.Comment = text
	if err := r.Desk.UpdateFinding(ctx, run.FindingID, u, Author(run.PlaybookName)); err != nil {
		return failed("Could not change the finding: %s", sentence(err.Error()))
	}
	return outcome{res: StepResult{Status: StepSucceeded, Text: text}, onFinding: true}
}

// askApproval tells the playbook's approval channel, if it has one, that
// a run waits.
func (r *Runner) askApproval(ctx context.Context, run *Run, f *findings.Finding) {
	id := run.Playbook.ApprovalChannel
	if id == "" || run.Approval == nil {
		return
	}
	c, err := r.channel(id)
	if err != nil {
		r.log().Warn("could not ask for a playbook approval", "playbook", run.PlaybookName, "err", err)
		return
	}
	ask := fmt.Sprintf("Playbook %s waits for approval to: %s", run.PlaybookName, run.Approval.What)
	if err := r.Sender.Send(ctx, c, notify.ApprovalMessage(f, ask, notify.ApprovalsLink(r.publicURL()))); err != nil {
		r.log().Warn("could not ask for a playbook approval", "playbook", run.PlaybookName, "channel", c.Label(), "err", err)
	}
}

// interrupt marks a run a stopped server left running as interrupted, for
// good.
func (r *Runner) interrupt(ctx context.Context, st Stored) {
	if r.sending(st.ID) {
		return
	}
	run := st.Run
	now := r.now()
	if run.Next < len(run.Playbook.Steps) {
		run.Steps = append(run.Steps, StepResult{Step: run.Next, Kind: run.Playbook.Steps[run.Next].Kind, Status: StepInterrupted,
			Text: "The server stopped during this step.", Time: now})
	}
	run.Status, run.Error, run.Finished = StatusInterrupted, StoppedWhileRunning, now
	if _, err := r.Runs.Update(ctx, &run, st.Version); err != nil {
		if !store.IsConflict(err) {
			r.log().Warn("could not mark a playbook run left running as interrupted", "run", run.ID, "err", err)
		}
		return
	}
	r.log().Warn("a playbook run was left running by a server that stopped; it is not run again", "playbook", run.PlaybookName, "run", run.ID)
	r.note(ctx, &run, StoppedWhileRunning, true)
}

// expire stops a run nobody approved in time.
func (r *Runner) expire(ctx context.Context, st Stored) {
	run := st.Run
	what := "the step"
	if run.Approval != nil {
		what = strings.TrimSuffix(run.Approval.What, ".")
	}
	text := "Nobody approved this within 24 hours, so it was not done: " + what + ". The playbook stopped."
	markDecision(&run, StepExpired, text)
	run.Status, run.Error, run.Finished = StatusExpired, "Nobody approved it within 24 hours.", r.now()
	if _, err := r.Runs.Update(ctx, &run, st.Version); err != nil {
		if !store.IsConflict(err) {
			r.log().Warn("could not expire a playbook run", "run", run.ID, "err", err)
		}
		return
	}
	r.log().Info("playbook approval expired", "playbook", run.PlaybookName, "run", run.ID)
	r.note(ctx, &run, text, true)
}

// markDecision sets the waiting step's result to status, with text.
func markDecision(run *Run, status, text string) {
	for i := len(run.Steps) - 1; i >= 0; i-- {
		if run.Steps[i].Status == StepWaiting {
			run.Steps[i].Status, run.Steps[i].Text = status, text
			return
		}
	}
}

func (r *Runner) mark(id string, on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inFlight == nil {
		r.inFlight = map[string]bool{}
	}
	if on {
		r.inFlight[id] = true
	} else {
		delete(r.inFlight, id)
	}
}

func (r *Runner) sending(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inFlight[id]
}

// purge deletes finished runs older than KeepFor, once in a while.
func (r *Runner) purge(ctx context.Context, now time.Time) {
	r.mu.Lock()
	due := now.Sub(r.lastPurge) >= purgeEvery
	if due {
		r.lastPurge = now
	}
	r.mu.Unlock()
	if !due {
		return
	}
	if err := r.Runs.Purge(ctx, now.Add(-KeepFor)); err != nil && ctx.Err() == nil {
		r.log().Warn("could not delete old playbook runs", "err", err)
	}
}

// problem logs a pass's problem once, until it changes or goes away.
func (r *Runner) problem(what string, err error) {
	msg := ""
	if err != nil {
		msg = what + ": " + err.Error()
	}
	r.mu.Lock()
	changed := msg != r.lastErr
	r.lastErr = msg
	r.mu.Unlock()
	if changed && err != nil {
		r.log().Error(what, "err", err)
	}
}

// ResolveTarget picks an action step's target from a finding, for an
// action that acts on kind (ip, domain, user, host or any), and returns
// it checked and in its usual form, with its kind.
func ResolveTarget(s Step, kind string, f *findings.Finding) (string, string, error) {
	pick := func(v string) string {
		if kind == "" || kind == respond.TargetAny {
			return respond.GuessKind(v)
		}
		return kind
	}
	var v, k string
	switch s.Target {
	case TargetFixed:
		v = s.Value
		k = pick(v)
	case TargetSrc, TargetDest, TargetUser, TargetHost:
		v = entityValue(f, s.Target)
		if v == "" {
			return "", "", fmt.Errorf("the finding has no %s value", s.Target)
		}
		k = pick(v)
		if fk := fieldKind(s.Target); fk != "" && (kind == "" || kind == respond.TargetAny) {
			k = fk
		}
	default:
		for _, field := range entityOrder(f) {
			val := entityValue(f, field)
			// A user name is only taken from a field that holds one, and
			// only for an action on users (or on anything).
			if val == "" || (kind == respond.TargetUser) != userish(field) && kind != "" && kind != respond.TargetAny {
				continue
			}
			kk := pick(val)
			if userish(field) {
				kk = respond.TargetUser
			} else if fk := fieldKind(field); fk != "" && (kind == "" || kind == respond.TargetAny) {
				kk = fk
			}
			if _, err := respond.ValidateTarget(kk, val); err == nil {
				v, k = val, kk
				break
			}
		}
		if v == "" {
			return "", "", fmt.Errorf("none of the finding's entities is %s it can act on", nounOf(kind))
		}
	}
	t, err := respond.ValidateTarget(k, v)
	if err != nil {
		return "", "", err
	}
	return t, k, nil
}

// entityOrder lists a finding's entity fields: src, dest, user and host
// first, then the others by name.
func entityOrder(f *findings.Finding) []string {
	out := []string{TargetSrc, TargetDest, TargetUser, TargetHost}
	var rest []string
	for k := range f.Entities {
		switch k {
		case TargetSrc, TargetDest, TargetUser, TargetHost, "risk_object_type":
			continue
		}
		rest = append(rest, k)
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// userish reports whether an entity field holds a user name.
func userish(field string) bool {
	f := strings.ToLower(field)
	return f == TargetUser || strings.Contains(f, "user") || strings.Contains(f, "account") || f == "member" || f == "identity"
}

func nounOf(kind string) string {
	switch kind {
	case respond.TargetIP:
		return "an IP address"
	case respond.TargetDomain:
		return "a domain"
	case respond.TargetUser:
		return "a user name"
	case respond.TargetHost:
		return "a host"
	}
	return "a value"
}

// sentence makes an error read as a sentence: capital first, full stop
// last.
func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	s = string(r)
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}
