package playbooks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Analysts approve or reject a waiting step from any server: the decision
// is written to the run with the version it was read at, so of two
// analysts deciding at once, one wins and the other is told who did. An
// approved run is picked up by the server that runs the background jobs,
// which runs the step with the approver recorded.

// DecidedError refuses a decision on a run that no longer waits for one.
type DecidedError struct{ Run Run }

func (e *DecidedError) Error() string {
	a := e.Run.Approval
	by := "someone"
	if a != nil && a.DecidedBy != "" {
		by = a.DecidedBy
	}
	switch e.Run.Status {
	case StatusApproved:
		return "it was already approved by " + by
	case StatusRejected:
		return "it was already rejected by " + by
	case StatusExpired, StatusWaiting:
		return "it expired: nobody approved it within 24 hours"
	}
	return "it no longer waits for approval (it is " + strings.ReplaceAll(e.Run.Status, "_", " ") + ")"
}

// ErrNoteTooLong refuses an approval note that is too long.
var ErrNoteTooLong = fmt.Errorf("the note must be at most %d characters", MaxNote)

// Decide approves or rejects the step a run waits on, as user, with an
// optional note. It returns ErrNotFound, ErrNoteTooLong, or *DecidedError
// when the run does not wait any more (someone decided first, or it
// expired). A rejection stops the run and is noted on the finding and its
// case through desk (when not nil); an approval is noted when the step
// runs.
func Decide(ctx context.Context, runs Runs, desk Desk, id, user, note string, approve bool, now time.Time) (Run, error) {
	note = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, note)), " ")
	if len([]rune(note)) > MaxNote {
		return Run{}, ErrNoteTooLong
	}
	st, err := runs.Get(ctx, id)
	if err != nil {
		return Run{}, err
	}
	run := st.Run
	if run.Status != StatusWaiting || run.Approval == nil || !now.Before(run.Approval.Expires) {
		return Run{}, &DecidedError{Run: run}
	}
	now = now.UTC()
	run.Approval.DecidedBy, run.Approval.Decided, run.Approval.Note = user, now, note
	what := strings.TrimSuffix(run.Approval.What, ".")
	var text string
	if approve {
		text = user + " approved: " + what + "."
		run.Status = StatusApproved
		markDecision(&run, StepApproved, text)
	} else {
		text = user + " rejected: " + what + "."
		if note != "" {
			text += " Note: " + note
		}
		text = strings.TrimSpace(text + " The playbook stopped.")
		run.Status, run.Error, run.Finished = StatusRejected, "Rejected by "+user+".", now
		markDecision(&run, StepRejected, text)
	}
	run.Updated = now
	if _, err := runs.Update(ctx, &run, st.Version); err != nil {
		if errors.Is(err, store.ErrConflict) {
			// Someone else decided, or the run expired, meanwhile.
			if again, gerr := runs.Get(ctx, id); gerr == nil {
				return Run{}, &DecidedError{Run: again.Run}
			}
		}
		return Run{}, err
	}
	if !approve && desk != nil {
		nctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_ = desk.UpdateFinding(nctx, run.FindingID, findings.Update{Comment: text}, user)
		if run.CaseID != "" {
			_ = desk.NoteOnCase(nctx, run.CaseID, text, user)
		}
	}
	return run, nil
}
