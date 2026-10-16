// Package playbooks runs simple response playbooks when a detection
// raises a finding: tell a channel, run a response action (a firewall
// block, disabling an account), open a case, set the finding's status or
// owner, in the order an admin set on the Playbooks page. A step that
// changes something elsewhere can wait for an analyst's approval first;
// disruptive actions always do.
//
// Playbooks are kept in a YAML file in the lookups folder
// (playbooks.file). They hold no secrets: they name notification
// channels and response actions by ID, and those keep their own secrets.
//
// Only the server that runs the background jobs runs playbooks (see
// Runner). Each run is claimed first with a document in OpenSearch whose
// ID says which finding and playbook it is for, so a playbook runs at
// most once per finding, even when another server takes the jobs over
// part way. Everything a run does is noted on the finding and, once it
// has one, on the case.
package playbooks

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/notify"
)

// Step kinds.
const (
	// StepNotify sends the finding to a notification channel.
	StepNotify = "notify"
	// StepAction runs a response action on a target from the finding.
	StepAction = "action"
	// StepOpenCase opens a case for the finding, or adds it to the open
	// case an earlier run of the playbook opened.
	StepOpenCase = "open_case"
	// StepSetFinding sets the finding's status or owner.
	StepSetFinding = "set_finding"
)

// StepKinds lists the step kinds, in the order the page offers them.
var StepKinds = []string{StepNotify, StepAction, StepOpenCase, StepSetFinding}

// Where an action step takes its target from: an entity field of the
// finding, the first entity that suits the action, or a fixed value.
const (
	TargetSrc    = "src"
	TargetDest   = "dest"
	TargetUser   = "user"
	TargetHost   = "host"
	TargetEntity = "entity"
	TargetFixed  = "fixed"
)

// TargetSources lists where an action step can take its target from.
var TargetSources = []string{TargetSrc, TargetDest, TargetUser, TargetHost, TargetEntity, TargetFixed}

// Limits on what the page can save.
const (
	MaxPlaybooks = 100
	MaxSteps     = 20
	maxName      = 80
	maxText      = 200
)

// Playbook is what to do, step by step, when a finding matches its
// trigger.
type Playbook struct {
	// ID never changes, so runs keep pointing at the playbook when it is
	// renamed.
	ID      string  `yaml:"id" json:"id"`
	Name    string  `yaml:"name" json:"name"`
	Enabled bool    `yaml:"enabled" json:"enabled"`
	Trigger Trigger `yaml:"trigger" json:"trigger"`
	Steps   []Step  `yaml:"steps" json:"steps"`
	// ApprovalChannel, when set, is the notification channel told when a
	// run waits for approval.
	ApprovalChannel string `yaml:"approval_channel,omitempty" json:"approval_channel"`
	// Since is when the playbook was added or last turned on: only
	// findings raised from then on start it, so a new playbook does not
	// act on old ones.
	Since time.Time `yaml:"since" json:"since"`
}

// Trigger says which findings start a playbook.
type Trigger struct {
	// Detections limits it to findings of these detections; empty means
	// every detection.
	Detections []string `yaml:"detections,omitempty" json:"detections"`
	// MinUrgency is the least urgency a finding needs; default high.
	MinUrgency string `yaml:"min_urgency" json:"min_urgency"`
	// IncludeSample starts it for findings raised from the one-click
	// sample data too, to try it out. Off by default.
	IncludeSample bool `yaml:"include_sample,omitempty" json:"include_sample"`
}

// Step is one thing a playbook does. Its kind decides which settings it
// uses.
type Step struct {
	Kind string `yaml:"kind" json:"kind"`

	// notify: the channel's ID.
	Channel string `yaml:"channel,omitempty" json:"channel,omitempty"`

	// action: the response action's name, where its target comes from
	// (one of TargetSources) and, for TargetFixed, the value.
	Action string `yaml:"action,omitempty" json:"action,omitempty"`
	Target string `yaml:"target,omitempty" json:"target,omitempty"`
	Value  string `yaml:"value,omitempty" json:"value,omitempty"`
	// NeedsApproval makes the run wait for an analyst to approve the
	// action. Always on for disruptive actions.
	NeedsApproval bool `yaml:"needs_approval,omitempty" json:"needs_approval"`

	// open_case: the case's title, with placeholders (see Expand), and
	// whether to add the finding to the case an earlier run of this
	// playbook opened while that case is still open.
	Title string `yaml:"title,omitempty" json:"title,omitempty"`
	Reuse bool   `yaml:"reuse,omitempty" json:"reuse,omitempty"`

	// open_case and set_finding: the owner to assign; set_finding: the
	// status to set. Empty leaves it as it is.
	Owner  string `yaml:"owner,omitempty" json:"owner,omitempty"`
	Status string `yaml:"status,omitempty" json:"status,omitempty"`
}

// DefaultCaseTitle is an open_case step's title when none is set.
const DefaultCaseTitle = "{title}"

// Matches reports whether a finding starts the playbook: the playbook is
// on and has steps, the finding is at least as urgent as its trigger
// asks, from one of its detections, raised since the playbook was turned
// on, and not sample data unless the trigger asks for it.
func (p Playbook) Matches(f *findings.Finding) bool {
	if !p.Enabled || f == nil || len(p.Steps) == 0 {
		return false
	}
	if f.Sample != "" && !p.Trigger.IncludeSample {
		return false
	}
	if f.Created.Before(p.Since) {
		return false
	}
	if !notify.AtLeast(f.EffectiveUrgency(), p.Trigger.MinUrgency) {
		return false
	}
	return len(p.Trigger.Detections) == 0 || slices.Contains(p.Trigger.Detections, f.DetectionID)
}

// clone returns a deep copy, so a caller may change it.
func (p Playbook) clone() Playbook {
	p.Trigger.Detections = slices.Clone(p.Trigger.Detections)
	p.Steps = slices.Clone(p.Steps)
	return p
}

// RunID is the ID of the run of a playbook for a finding, so a playbook
// runs once per finding.
func RunID(findingID, playbookID string) string {
	sum := sha256.Sum256([]byte(findingID + "|" + playbookID))
	return hex.EncodeToString(sum[:])
}

// newID returns a short random ID for a playbook.
func newID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// entityValue returns a finding's value of an entity field, the first
// one when it holds several, or "".
func entityValue(f *findings.Finding, field string) string {
	v, ok := f.Entities[field]
	if !ok || v == nil {
		return ""
	}
	if list, ok := v.([]any); ok {
		if len(list) == 0 || list[0] == nil {
			return ""
		}
		v = list[0]
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

// Placeholders are what a case title may hold, filled from the finding.
var Placeholders = []string{"{title}", "{detection}", "{urgency}", "{src}", "{dest}", "{user}", "{host}", "{finding_id}"}

// Expand fills a case title's placeholders from a finding. Values from
// the finding lose their control characters, and the title is cut to 200
// characters.
func Expand(tmpl string, f *findings.Finding) string {
	if strings.TrimSpace(tmpl) == "" {
		tmpl = DefaultCaseTitle
	}
	r := strings.NewReplacer("{title}", f.Title, "{detection}", f.DetectionID, "{urgency}", f.EffectiveUrgency(),
		"{src}", entityValue(f, "src"), "{dest}", entityValue(f, "dest"), "{user}", entityValue(f, "user"),
		"{host}", entityValue(f, "host"), "{finding_id}", f.ID)
	s := strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, r.Replace(tmpl))), " ")
	if s == "" {
		s = f.Title
	}
	return cut(s, maxText)
}

// cut shortens s to at most n runes.
func cut(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// joinAnd lists words as people do: "a, b and c".
func joinAnd(list []string) string {
	switch len(list) {
	case 0:
		return ""
	case 1:
		return list[0]
	}
	return strings.Join(list[:len(list)-1], ", ") + " and " + list[len(list)-1]
}
