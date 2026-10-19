package playbooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

func TestSummary(t *testing.T) {
	refs := testRefs()
	for _, tc := range []struct {
		p    Playbook
		want string
	}{
		{Playbook{}, "When any detection fires at high or above: nothing yet. Add a step."},
		{Playbook{Trigger: Trigger{Detections: []string{"a", "b"}, MinUrgency: "critical", IncludeSample: true}, Steps: []Step{{Kind: StepNotify, Channel: "soc"}}},
			"When a and b fires at critical (sample data too): notify Slack #soc."},
		{Playbook{Trigger: Trigger{Detections: []string{"a", "b", "c", "d"}, MinUrgency: "informational"}, Steps: []Step{{Kind: StepNotify, Channel: "gone"}}},
			"When any of 4 detections fires: notify a deleted channel."},
		{Playbook{Trigger: Trigger{Detections: []string{"x"}, MinUrgency: "medium"}, Steps: []Step{
			{Kind: StepAction, Action: "block", Target: TargetSrc, NeedsApproval: true},
			{Kind: StepAction, Action: "block", Target: TargetDest},
			{Kind: StepAction, Action: "tag", Target: TargetSrc},
			{Kind: StepAction, Action: "tag", Target: TargetDest},
			{Kind: StepAction, Action: "disable", Target: TargetUser},
			{Kind: StepAction, Action: "tag", Target: TargetHost},
			{Kind: StepAction, Action: "gone", Target: TargetFixed, Value: "10.0.0.1"},
			{Kind: StepAction, Action: "block", Target: TargetEntity},
			{Kind: StepAction, Action: "tag", Target: TargetEntity},
		}}, "When x fires at medium or above: block IP on the edge firewall for the source IP after approval, " +
			"then block IP on the edge firewall for the destination IP, then tag host for the source, then tag host for the destination, " +
			"then disable AD account for the user, then tag host for the host, then run gone for 10.0.0.1, " +
			"then block IP on the edge firewall for the finding's IP, then tag host for the finding's first entity."},
		{Playbook{Steps: []Step{
			{Kind: StepOpenCase},
			{Kind: StepOpenCase, Reuse: true, Owner: "ana"},
			{Kind: StepSetFinding, Status: findings.StatusInProgress, Owner: "ana"},
			{Kind: StepSetFinding, Owner: "bo"},
			{Kind: "email"},
		}}, "When any detection fires at high or above: open a case, then open a case (or add to the one it opened) for ana, " +
			"then set the finding to In progress and assign it to ana, then assign the finding to bo, then email."},
	} {
		if got := tc.p.Summary(refs); got != tc.want {
			t.Errorf("Summary\n got %q\nwant %q", got, tc.want)
		}
	}
	for in, want := range map[string]string{"": "", "Block IP": "block IP", "AD sync": "AD sync", "É": "é", "x": "x"} {
		if got := lowerFirst(in); got != want {
			t.Errorf("lowerFirst(%q) = %q", in, got)
		}
	}
}

func TestErrorsRead(t *testing.T) {
	inner := errors.New("permission denied")
	fe := &FileError{Path: "/etc/signalith/playbooks.yaml", Err: inner}
	if !errors.Is(fe, inner) || !strings.Contains(fe.Error(), "/etc/signalith/playbooks.yaml could not be read (permission denied)") {
		t.Errorf("FileError = %q", fe.Error())
	}
	ie := &InputError{Problems: []Problem{{Msg: "name is required"}, {Msg: "add a step"}}}
	if ie.Error() != "Please fix these settings: name is required; add a step" {
		t.Errorf("InputError = %q", ie.Error())
	}
}

func TestLoad(t *testing.T) {
	if err := (&Manager{}).Load(); err != nil {
		t.Errorf("in memory = %v", err)
	}
	dir := t.TempDir()
	if err := (&Manager{File: filepath.Join(dir, "missing.yaml")}).Load(); err != nil {
		t.Errorf("missing file = %v", err)
	}
	// A directory where the file should be cannot be read.
	var fe *FileError
	if err := (&Manager{File: dir}).Load(); !errors.As(err, &fe) {
		t.Errorf("directory = %v", err)
	}
	path := filepath.Join(dir, "playbooks.yaml")
	if err := os.WriteFile(path, []byte("playbooks:\n  - id: a\n    name: A\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{File: path}
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	list, err := m.List()
	if err != nil || len(list) != 1 || list[0].Name != "A" {
		t.Errorf("list = %+v %v", list, err)
	}
}
