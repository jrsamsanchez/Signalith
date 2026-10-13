// Package respond runs response actions: an analyst, or later a playbook,
// disables a directory account, blocks an IP or domain through a
// firewall's API or a SOAR webhook, or runs a script such as one that
// isolates a host. Admins set the actions up on the Response actions page;
// each one has a kind (disable_user, http or script) and the kind of
// target it acts on.
//
// Every run is checked before anything happens (the action exists and is
// on, the target is valid for it, a disruptive action has a reason, the
// actor has not run too many in the last minute), written to the audit
// log (the <prefix>_actions index) before it starts and again when it
// ends, logged, and recorded on the case timeline and the finding it was
// run from. A run that cannot be written to the audit log does not run.
package respond

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// Run statuses.
const (
	StatusRunning   = "running"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	// StatusInterrupted is a run left running by a server that stopped:
	// it may or may not have finished.
	StatusInterrupted = "interrupted"
)

// Limits.
const (
	// MaxOutput is how much of a run's output is kept.
	MaxOutput = 16 << 10
	// MaxReason is the longest reason.
	MaxReason = 2000
	// RunsPerMinute is how many actions one actor may run in a minute,
	// so a stuck button or a loop cannot fire hundreds.
	RunsPerMinute = 30
)

// Actor is who runs an action: a signed-in user, or a playbook.
type Actor struct {
	// Name is the user name, or the playbook's name.
	Name string
	// Automatic marks a run a playbook started rather than a person.
	Automatic bool
	// ApprovedBy is the user who approved an automatic run, if any.
	ApprovedBy string
}

// Label is how the actor is shown: "jdoe", or "playbook phishing".
func (a Actor) Label() string {
	if a.Automatic {
		return "playbook " + a.Name
	}
	return a.Name
}

// Request is one run to make.
type Request struct {
	// Action is the action's name.
	Action string `json:"action"`
	Target string `json:"target"`
	// TargetKind is the kind of Target for an action that takes any; when
	// empty it is guessed (see GuessKind). For other actions it must be
	// empty or the action's own kind.
	TargetKind string `json:"target_kind,omitempty"`
	FindingID  string `json:"finding_id,omitempty"`
	CaseID     string `json:"case_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Actor      Actor  `json:"-"`
}

// Run is one run of an action: the audit log's record.
type Run struct {
	ID          string `json:"id"`
	Action      string `json:"action"`
	ActionLabel string `json:"action_label"`
	Kind        string `json:"kind"`
	Target      string `json:"target"`
	TargetKind  string `json:"target_kind"`
	Actor       string `json:"actor"`
	Automatic   bool   `json:"automatic,omitempty"`
	ApprovedBy  string `json:"approved_by,omitempty"`
	Reason      string `json:"reason,omitempty"`
	FindingID   string `json:"finding_id,omitempty"`
	CaseID      string `json:"case_id,omitempty"`
	Status      string `json:"status"`
	// Summary says what happened in one sentence.
	Summary string `json:"summary,omitempty"`
	// Output is what the program or server answered, with secrets hidden,
	// cut to MaxOutput.
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
	// Server is the Signalith server that ran it.
	Server     string    `json:"server,omitempty"`
	Started    time.Time `json:"started"`
	Finished   time.Time `json:"finished,omitzero"`
	DurationMS int64     `json:"duration_ms,omitempty"`
	// RecordErrors says where the run could not be noted: the case, the
	// finding, or the audit log's final record.
	RecordErrors []string `json:"record_errors,omitempty"`
}

// RequestError is a run refused before anything happened, because of the
// request: the caller's fault (HTTP 400).
type RequestError struct {
	Field string
	Msg   string
}

func (e *RequestError) Error() string { return e.Msg }

func badRequest(field, format string, args ...any) error {
	return &RequestError{Field: field, Msg: fmt.Sprintf(format, args...)}
}

var (
	// ErrNotFound is an action that does not exist.
	ErrNotFound = errors.New("there is no response action with this name")
	// ErrRateLimited refuses an actor who ran RunsPerMinute actions in the
	// last minute.
	ErrRateLimited = fmt.Errorf("you ran %d response actions in the last minute; wait a moment before running more", RunsPerMinute)
)

// AuditError means the audit log could not be written, so the action did
// not run.
type AuditError struct{ Err error }

func (e *AuditError) Error() string {
	return "The run could not be written to the audit log, so the action did not run: " + e.Err.Error()
}

func (e *AuditError) Unwrap() error { return e.Err }

// Recorder notes runs where analysts look: the case timeline and the
// finding's activity. The API server provides it, so changes to a case
// are made one at a time with its other changes.
type Recorder interface {
	// Check reports an error when a finding or case named by a run does
	// not exist; "" IDs are not checked.
	Check(ctx context.Context, findingID, caseID string) error
	// OnCase adds the run to a case's timeline.
	OnCase(ctx context.Context, caseID string, run *Run) error
	// OnFinding adds the run to a finding's activity.
	OnFinding(ctx context.Context, findingID string, run *Run) error
}

// Runner runs response actions.
type Runner struct {
	Actions *Actions
	// Directory returns the directory settings of the Users page, for
	// disable_user actions; nil means there is no directory.
	Directory func() users.LDAPSettings
	// ScriptsDir is the only folder script actions may run programs from
	// (response.scripts_dir).
	ScriptsDir string
	// Store is the audit log. Required: runs that cannot be logged do not
	// happen.
	Store Store
	// Record notes runs on cases and findings; nil skips that.
	Record Recorder
	// Protected are host:port addresses HTTP actions never reach, such as
	// Signalith's own OpenSearch.
	Protected []string
	// Server is this server's name, kept with each run.
	Server string
	Log    *slog.Logger

	limiter limiter
	now     func() time.Time
	// tick makes run IDs from the same nanosecond differ.
	tickMu sync.Mutex
	last   time.Time
}

func (r *Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func (r *Runner) clock() time.Time {
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	r.tickMu.Lock()
	defer r.tickMu.Unlock()
	t := now().UTC()
	// Windows clocks can return the same time twice; runs stay in order.
	if !t.After(r.last) {
		t = r.last.Add(time.Microsecond)
	}
	r.last = t
	return t
}

// NewRunID returns a run ID such as "RUN-20261013-1a2b3c4d5e6f7a8b".
func NewRunID(now time.Time) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "RUN-" + now.UTC().Format("20060102") + "-" + hex.EncodeToString(b)
}

// prepare checks a request and returns the action and the clean target.
func (r *Runner) prepare(req *Request) (Connector, error) {
	req.Action = strings.TrimSpace(req.Action)
	req.Reason = strings.TrimSpace(req.Reason)
	req.FindingID = strings.TrimSpace(req.FindingID)
	req.CaseID = strings.TrimSpace(req.CaseID)
	if req.Action == "" {
		return Connector{}, badRequest("action", "choose an action")
	}
	if strings.TrimSpace(req.Actor.Name) == "" {
		return Connector{}, badRequest("actor", "a run needs an actor")
	}
	c, ok, err := r.Actions.Get(req.Action)
	if err != nil {
		return Connector{}, err
	}
	if !ok {
		return Connector{}, ErrNotFound
	}
	if !c.IsEnabled() {
		return Connector{}, badRequest("action", "%s is turned off on the Response actions page", c.Label)
	}
	if locked := r.Actions.Locked(c.Name); len(locked) > 0 {
		return Connector{}, badRequest("action", "%s cannot run until an admin enters its %s again on the Response actions page (it could not be decrypted)", c.Label, strings.Join(locked, " and "))
	}
	kind := c.Target
	switch {
	case c.Target == TargetAny && req.TargetKind == "":
		kind = GuessKind(req.Target)
	case c.Target == TargetAny:
		kind = req.TargetKind
		found := false
		for _, k := range TargetKinds {
			found = found || k == kind
		}
		if !found {
			return Connector{}, badRequest("target_kind", "target_kind must be ip, domain, user or host")
		}
	case req.TargetKind != "" && req.TargetKind != c.Target:
		return Connector{}, badRequest("target", "%s acts on a %s, not a %s", c.Label, kindNoun(c.Target), kindNoun(req.TargetKind))
	}
	t, err := ValidateTarget(kind, req.Target)
	if err != nil {
		return Connector{}, badRequest("target", "%v", err)
	}
	req.Target, req.TargetKind = t, kind
	if len(req.Reason) > MaxReason {
		return Connector{}, badRequest("reason", "the reason must be at most %d characters", MaxReason)
	}
	if c.IsDisruptive() && req.Reason == "" {
		return Connector{}, badRequest("reason", "say why: %s is disruptive, so it needs a reason", c.Label)
	}
	for _, id := range []struct{ field, v string }{{"finding_id", req.FindingID}, {"case_id", req.CaseID}} {
		if len(id.v) > 200 || strings.ContainsFunc(id.v, unicode.IsControl) {
			return Connector{}, badRequest(id.field, "%s is not valid", id.field)
		}
	}
	return c, nil
}

// Run checks a request, runs the action and returns its record. The
// action runs on after ctx ends (a browser that goes away does not stop a
// half-done change), within its own time limit. A request refused before
// anything ran returns a *RequestError, ErrNotFound, ErrRateLimited or an
// *AuditError; a run that failed returns its record with status failed and
// no error.
func (r *Runner) Run(ctx context.Context, req Request) (*Run, error) {
	if r.Store == nil {
		return nil, &AuditError{Err: errors.New("there is no audit log")}
	}
	c, err := r.prepare(&req)
	if err != nil {
		return nil, err
	}
	if r.Record != nil && (req.FindingID != "" || req.CaseID != "") {
		if err := r.Record.Check(ctx, req.FindingID, req.CaseID); err != nil {
			return nil, err
		}
	}
	key := "user:" + strings.ToLower(req.Actor.Name)
	if req.Actor.Automatic {
		key = "auto:" + req.Actor.Name
	}
	if !r.limiter.allow(key, r.clock()) {
		return nil, ErrRateLimited
	}
	start := r.clock()
	run := &Run{
		ID: NewRunID(start), Action: c.Name, ActionLabel: c.Label, Kind: c.Kind,
		Target: req.Target, TargetKind: req.TargetKind, Actor: req.Actor.Name, Automatic: req.Actor.Automatic,
		ApprovedBy: req.Actor.ApprovedBy, Reason: req.Reason, FindingID: req.FindingID, CaseID: req.CaseID,
		Status: StatusRunning, Server: r.Server, Started: start,
	}
	// The run is detached from the request, so the audit record and the
	// change itself are finished even if the caller goes away.
	ctx = context.WithoutCancel(ctx)
	if err := r.Store.Put(ctx, run, false); err != nil {
		r.log().Error("a response action was not run: its audit record could not be written", "audit", true,
			"action", c.Name, "target", run.Target, "actor", req.Actor.Label(), "err", err)
		return nil, &AuditError{Err: err}
	}
	r.log().Info("response action started", "audit", true, "run", run.ID, "action", c.Name, "kind", c.Kind,
		"target", run.Target, "target_kind", run.TargetKind, "actor", req.Actor.Label(), "finding", run.FindingID, "case", run.CaseID)
	r.finish(run, c, r.execute(ctx, c, run))
	level := slog.LevelInfo
	if run.Status == StatusFailed {
		level = slog.LevelWarn
	}
	r.log().Log(ctx, level, "response action "+run.Status, "audit", true, "run", run.ID, "action", c.Name,
		"target", run.Target, "actor", req.Actor.Label(), "duration_ms", run.DurationMS, "summary", run.Summary, "error", run.Error)
	if r.Record != nil {
		if run.CaseID != "" {
			if err := r.Record.OnCase(ctx, run.CaseID, run); err != nil {
				run.RecordErrors = append(run.RecordErrors, "It could not be added to the case timeline: "+err.Error())
			}
		}
		if run.FindingID != "" {
			if err := r.Record.OnFinding(ctx, run.FindingID, run); err != nil {
				run.RecordErrors = append(run.RecordErrors, "It could not be noted on the finding: "+err.Error())
			}
		}
		for _, e := range run.RecordErrors {
			r.log().Warn("response action not recorded", "run", run.ID, "problem", e)
		}
	}
	if err := r.Store.Put(ctx, run, true); err != nil {
		// The action ran; say so, and that the audit log still says
		// running.
		r.log().Error("a response action ran but its result could not be written to the audit log", "audit", true,
			"run", run.ID, "status", run.Status, "err", err)
		run.RecordErrors = append(run.RecordErrors, "Its result could not be written to the audit log: "+err.Error())
	}
	return run, nil
}

// result is what executing an action gave.
type result struct {
	summary string
	output  string
	err     error
}

// execute runs the action of its kind.
func (r *Runner) execute(ctx context.Context, c Connector, run *Run) result {
	v := valuesFor(run.TargetKind, run.Target, run.FindingID, run.CaseID, run.Actor, run.Reason)
	switch c.Kind {
	case KindHTTP:
		return r.runHTTP(ctx, c, v)
	case KindScript:
		return r.runScript(ctx, c, run)
	case KindDisableUser:
		return r.runDisableUser(ctx, c, run.Target)
	}
	return result{err: fmt.Errorf("unknown kind %q", c.Kind)}
}

// Describe says in one sentence what running c on target will do, for
// the confirm step, such as "Disable the AD account of jdoe in
// corp.example.com." Target may be "{target}" to make a template.
func (r *Runner) Describe(c Connector, target string) string {
	switch c.Kind {
	case KindDisableUser:
		where, what := "", "directory account"
		if r.Directory != nil {
			s := r.Directory()
			if d := users.Domain(s.UserBaseDN); d != "" {
				where = " in " + d
			}
			if s.Type == "" || s.Type == users.TypeActiveDirectory {
				what = "AD account"
			}
		}
		verb := "Disable"
		if c.Operation == OpEnable {
			verb = "Enable"
		}
		return fmt.Sprintf("%s the %s of %s%s.", verb, what, target, where)
	case KindHTTP:
		host := ""
		if o, _, err := splitURLTemplate(c.URL); err == nil {
			host = strings.SplitN(o, "://", 2)[1]
		}
		return fmt.Sprintf("Send %s to %s for %s.", c.Method, host, target)
	case KindScript:
		return fmt.Sprintf("Run %s on this Signalith server with %s.", c.Program, target)
	}
	return c.Label + " for " + target + "."
}

// cleanOutput keeps output readable and safe to show: valid UTF-8,
// without control characters other than new lines and tabs, with secrets
// hidden, at most MaxOutput bytes.
func cleanOutput(s string, secretVals []string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r == '\r' {
			return -1
		}
		if unicode.IsControl(r) {
			return '�'
		}
		return r
	}, s)
	s = scrub(s, secretVals)
	if len(s) > MaxOutput {
		cut := MaxOutput
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "\n[… output cut at 16 KB]"
	}
	return s
}

// scrub hides secret values in text.
func scrub(s string, secretVals []string) string {
	for _, v := range secretVals {
		if len(v) >= 4 {
			s = strings.ReplaceAll(s, v, "[hidden]")
		}
	}
	return s
}

// limiter counts runs per actor in a sliding minute.
type limiter struct {
	mu   sync.Mutex
	runs map[string][]time.Time
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.runs == nil {
		l.runs = map[string][]time.Time{}
	}
	cut := now.Add(-time.Minute)
	kept := l.runs[key][:0]
	for _, t := range l.runs[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= RunsPerMinute {
		l.runs[key] = kept
		return false
	}
	l.runs[key] = append(kept, now)
	// Forget actors who stopped, so the map does not grow.
	if len(l.runs) > 1000 {
		for k, ts := range l.runs {
			if len(ts) == 0 || !ts[len(ts)-1].After(cut) {
				delete(l.runs, k)
			}
		}
	}
	return true
}

// Author is who a run is noted as on a case or finding: the user, or
// "playbook <name>".
func (run *Run) Author() string {
	if run.Automatic {
		return "playbook " + run.Actor
	}
	return run.Actor
}

// Text says in plain words what ran, on what and how it went, for a case
// timeline or a finding's activity, such as "Ran Block IP on the
// firewall on IP address 203.0.113.7: succeeded. POST … answered 200
// OK. Reason: brute force."
func (run *Run) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Ran %s on %s %s: %s.", run.ActionLabel, kindNoun(run.TargetKind), run.Target, run.Status)
	if run.Summary != "" {
		b.WriteString(" " + run.Summary)
	}
	if run.Error != "" {
		b.WriteString(" " + strings.TrimSuffix(run.Error, ".") + ".")
	}
	if run.ApprovedBy != "" {
		b.WriteString(" Approved by " + run.ApprovedBy + ".")
	}
	if run.Reason != "" {
		b.WriteString(" Reason: " + run.Reason)
	}
	return cut(b.String(), 4000)
}

// cut shortens s to at most n bytes, at a character boundary.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
