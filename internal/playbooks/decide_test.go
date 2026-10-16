package playbooks

import (
	"errors"
	"testing"
	"time"
)

func TestDecideStepOnlyDecidesThatStep(t *testing.T) {
	runs := NewMemory()
	now := time.Now().UTC()
	run := &Run{ID: "r", PlaybookName: "p", Status: StatusWaiting, Created: now, Updated: now,
		Steps:    []StepResult{{Step: 2, Kind: StepAction, Status: StepWaiting}},
		Approval: &Approval{Step: 2, What: "Block it.", Requested: now, Expires: now.Add(time.Hour)}}
	if _, err := runs.Claim(t.Context(), run); err != nil {
		t.Fatal(err)
	}
	if _, err := DecideStep(t.Context(), runs, nil, "r", 1, "andy", "", true, now); !errors.Is(err, ErrOtherStep) {
		t.Fatalf("other step = %v", err)
	}
	got, err := DecideStep(t.Context(), runs, nil, "r", 2, "andy", "In Slack.", true, now)
	if err != nil || got.Status != StatusApproved || got.Approval.DecidedBy != "andy" || got.Approval.Note != "In Slack." {
		t.Fatalf("decide = %+v %v", got, err)
	}
	var de *DecidedError
	if _, err := DecideStep(t.Context(), runs, nil, "r", 2, "bea", "", false, now); !errors.As(err, &de) {
		t.Fatalf("second decision = %v", err)
	}
}
