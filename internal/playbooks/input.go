package playbooks

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/respond"
)

// Refs are what steps name: the notification channels and the response
// actions, for checking a save and saying what a playbook does.
type Refs struct {
	// Channels names each notification channel by ID, as in "Slack
	// #soc"; nil when notifications are not available.
	Channels map[string]string
	// Actions are the response actions by name; nil when response actions
	// are not available.
	Actions map[string]ActionRef
}

// ActionRef is a response action as playbooks see it.
type ActionRef struct {
	Label string `json:"label"`
	// Target is the kind of value it acts on: ip, domain, user, host or
	// any.
	Target     string `json:"target"`
	Disruptive bool   `json:"disruptive"`
	Enabled    bool   `json:"enabled"`
	// What says what a run does, with {target} for the target, in the
	// words of respond's Runner.Describe.
	What string `json:"what"`
}

// BuildRefs reads the channels and actions; either may be nil.
func BuildRefs(n *notify.Manager, r *respond.Runner) Refs {
	var refs Refs
	if n != nil {
		refs.Channels = map[string]string{}
		if s, err := n.Settings(); err == nil {
			for _, c := range s.Channels {
				refs.Channels[c.ID] = c.Label()
			}
		}
	}
	if r != nil && r.Actions != nil {
		refs.Actions = map[string]ActionRef{}
		list, _ := r.Actions.List()
		for _, c := range list {
			refs.Actions[c.Name] = ActionRef{Label: c.Label, Target: c.Target, Disruptive: c.IsDisruptive(), Enabled: c.IsEnabled(),
				What: r.Describe(c, "{target}")}
		}
	}
	return refs
}

// Input is the whole list of playbooks as the Playbooks page sends it.
type Input struct {
	// Revision is the Revision the page started from; a save over newer
	// playbooks is refused with ErrChanged. Empty skips the check.
	Revision  string     `json:"revision"`
	Playbooks []Playbook `json:"playbooks"`
}

// Problem is one setting to fix. Where is "playbook:<id>" (or
// "playbook:#2" for one sent without an ID); Field is the setting, such
// as name or steps[1].channel, for the form to mark.
type Problem struct {
	Where string `json:"where"`
	Field string `json:"field,omitempty"`
	Msg   string `json:"message"`
}

// InputError lists the settings to fix.
type InputError struct{ Problems []Problem }

func (e *InputError) Error() string {
	msgs := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		msgs[i] = p.Msg
	}
	return "Please fix these settings: " + strings.Join(msgs, "; ")
}

var (
	idForm    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)
	ownerForm = regexp.MustCompile(`^[^\s"'<>\\]{1,100}$`)
)

// merge checks the new list against the saved one (whose references
// stay accepted while unchanged, so a deleted channel or action never
// blocks saving other playbooks) and the channels and actions there are.
func merge(cur []Playbook, in []Playbook, refs Refs, now time.Time) ([]Playbook, []Problem) {
	if len(in) > MaxPlaybooks {
		return nil, []Problem{{Where: "playbooks", Msg: fmt.Sprintf("at most %d playbooks can be set up", MaxPlaybooks)}}
	}
	var out []Playbook
	var probs []Problem
	ids, names := map[string]bool{}, map[string]bool{}
	for i, p := range in {
		w := "playbook:" + where(p.ID, i)
		var old *Playbook
		for _, c := range cur {
			if c.ID == strings.TrimSpace(p.ID) {
				old = &c
				break
			}
		}
		np, pp := check(p, old, w, refs, now)
		probs = append(probs, pp...)
		if np.ID == "" {
			np.ID = newID()
		}
		if ids[np.ID] {
			probs = append(probs, Problem{Where: w, Field: "id", Msg: fmt.Sprintf("two playbooks have the ID %s", np.ID)})
		}
		ids[np.ID] = true
		if key := strings.ToLower(np.Name); key != "" {
			if names[key] {
				probs = append(probs, Problem{Where: w, Field: "name", Msg: fmt.Sprintf("another playbook is already named %s; choose another name", np.Name)})
			}
			names[key] = true
		}
		out = append(out, np)
	}
	return out, probs
}

func where(id string, i int) string {
	if id = strings.TrimSpace(id); id != "" {
		return id
	}
	return "#" + strconv.Itoa(i+1)
}

// cleanText trims a value and reports whether it is short enough and
// free of control characters.
func cleanText(s string, max int) (string, bool) {
	s = strings.TrimSpace(s)
	return s, utf8.RuneCountInString(s) <= max && strings.IndexFunc(s, unicode.IsControl) < 0
}

// fieldKind is the kind of target an entity field holds, or "" when it
// can hold several (the source and destination may be addresses or
// names).
func fieldKind(source string) string {
	switch source {
	case TargetUser:
		return respond.TargetUser
	case TargetHost:
		return respond.TargetHost
	}
	return ""
}

// check checks one playbook and returns it cleaned up.
func check(in Playbook, old *Playbook, w string, refs Refs, now time.Time) (Playbook, []Problem) {
	var probs []Problem
	label := strings.TrimSpace(in.Name)
	if label == "" {
		label = "a playbook"
	}
	add := func(field, msg string) {
		probs = append(probs, Problem{Where: w, Field: field, Msg: label + ": " + msg})
	}
	p := Playbook{ID: strings.TrimSpace(in.ID), Enabled: in.Enabled, Trigger: Trigger{IncludeSample: in.Trigger.IncludeSample,
		MinUrgency: strings.ToLower(strings.TrimSpace(in.Trigger.MinUrgency))}}
	if p.ID != "" && old == nil && !idForm.MatchString(p.ID) {
		add("id", "a new playbook's ID may only hold lowercase letters, digits, - and _ (at most 40 characters)")
	}
	var ok bool
	p.Name, ok = cleanText(in.Name, maxName)
	switch {
	case p.Name == "":
		add("name", "give it a name")
	case !ok:
		add("name", fmt.Sprintf("the name must be at most %d characters, on one line", maxName))
	}
	if p.Trigger.MinUrgency == "" {
		p.Trigger.MinUrgency = notify.DefaultMinUrgency
	}
	if !slices.Contains(notify.Urgencies, p.Trigger.MinUrgency) {
		add("trigger.min_urgency", "pick the least urgency: "+strings.Join(notify.Urgencies, ", "))
	}
	for _, d := range in.Trigger.Detections {
		d, ok := cleanText(d, 200)
		switch {
		case d == "" || slices.Contains(p.Trigger.Detections, d):
		case !ok:
			add("trigger.detections", fmt.Sprintf("%q is not a detection ID", d))
		default:
			p.Trigger.Detections = append(p.Trigger.Detections, d)
		}
	}
	if len(p.Trigger.Detections) > 500 {
		add("trigger.detections", "at most 500 detections")
	}
	// A reference the saved playbook already had stays accepted, so a
	// channel or action deleted since never blocks a save; the run says
	// it is gone.
	hadChannel := func(id string) bool {
		if old == nil {
			return false
		}
		if old.ApprovalChannel == id {
			return true
		}
		return slices.ContainsFunc(old.Steps, func(s Step) bool { return s.Kind == StepNotify && s.Channel == id })
	}
	hadAction := func(name string) bool {
		return old != nil && slices.ContainsFunc(old.Steps, func(s Step) bool { return s.Kind == StepAction && s.Action == name })
	}
	if c := strings.TrimSpace(in.ApprovalChannel); c != "" {
		if _, ok := refs.Channels[c]; !ok && !hadChannel(c) {
			add("approval_channel", "there is no notification channel with the ID "+c)
		}
		p.ApprovalChannel = c
	}
	if len(in.Steps) > MaxSteps {
		add("steps", fmt.Sprintf("at most %d steps", MaxSteps))
	}
	if len(in.Steps) == 0 && p.Enabled {
		add("steps", "add at least one step")
	}
	for i, s := range in.Steps {
		if i == MaxSteps {
			break
		}
		f := fmt.Sprintf("steps[%d].", i)
		st := Step{Kind: strings.TrimSpace(s.Kind)}
		switch st.Kind {
		case StepNotify:
			st.Channel = strings.TrimSpace(s.Channel)
			switch {
			case st.Channel == "":
				add(f+"channel", fmt.Sprintf("step %d: pick a channel to notify", i+1))
			case refs.Channels == nil && !hadChannel(st.Channel):
				add(f+"channel", fmt.Sprintf("step %d: notifications are not available on this server", i+1))
			default:
				if _, ok := refs.Channels[st.Channel]; !ok && !hadChannel(st.Channel) {
					add(f+"channel", fmt.Sprintf("step %d: there is no notification channel with the ID %s", i+1, st.Channel))
				}
			}
		case StepAction:
			st.Action, st.Target, st.NeedsApproval = strings.TrimSpace(s.Action), strings.TrimSpace(s.Target), s.NeedsApproval
			if st.Target == "" {
				st.Target = TargetEntity
			}
			a, known := refs.Actions[st.Action]
			switch {
			case st.Action == "":
				add(f+"action", fmt.Sprintf("step %d: pick a response action", i+1))
			case !known && !hadAction(st.Action):
				add(f+"action", fmt.Sprintf("step %d: there is no response action named %s", i+1, st.Action))
			}
			if known && a.Disruptive {
				// Disruptive actions never run without a person's say.
				st.NeedsApproval = true
			}
			if !slices.Contains(TargetSources, st.Target) {
				add(f+"target", fmt.Sprintf("step %d: the target comes from one of %s", i+1, strings.Join(TargetSources, ", ")))
				break
			}
			if st.Target == TargetFixed {
				kind := a.Target
				if kind == "" || kind == respond.TargetAny {
					kind = respond.GuessKind(s.Value)
				}
				v, err := respond.ValidateTarget(kind, s.Value)
				if err != nil {
					add(f+"value", fmt.Sprintf("step %d: %v", i+1, err))
				}
				st.Value = v
				break
			}
			if !known {
				break
			}
			fk := fieldKind(st.Target)
			switch {
			case st.Target == TargetEntity || a.Target == respond.TargetAny:
			case a.Target == respond.TargetUser && st.Target != TargetUser:
				add(f+"target", fmt.Sprintf("step %d: %s acts on a user name; take the target from the user field", i+1, a.Label))
			case a.Target != respond.TargetUser && fk == respond.TargetUser:
				add(f+"target", fmt.Sprintf("step %d: %s does not act on a user name; take the target from another field", i+1, a.Label))
			}
		case StepOpenCase:
			st.Reuse = s.Reuse
			var ok1, ok2 bool
			st.Title, ok1 = cleanText(s.Title, maxText)
			st.Owner, ok2 = cleanText(s.Owner, 100)
			if !ok1 {
				add(f+"title", fmt.Sprintf("step %d: the case title must be at most %d characters, on one line", i+1, maxText))
			}
			if !ok2 || (st.Owner != "" && !ownerForm.MatchString(st.Owner)) {
				add(f+"owner", fmt.Sprintf("step %d: the owner must be a user name", i+1))
			}
		case StepSetFinding:
			st.Status = strings.TrimSpace(s.Status)
			var ok2 bool
			st.Owner, ok2 = cleanText(s.Owner, 100)
			if st.Status != "" && !slices.Contains(findings.Statuses, st.Status) {
				add(f+"status", fmt.Sprintf("step %d: the status must be one of %s", i+1, strings.Join(findings.Statuses, ", ")))
			}
			if !ok2 || (st.Owner != "" && !ownerForm.MatchString(st.Owner)) {
				add(f+"owner", fmt.Sprintf("step %d: the owner must be a user name", i+1))
			}
			if st.Status == "" && st.Owner == "" {
				add(f+"status", fmt.Sprintf("step %d: set a status, an owner or both", i+1))
			}
		default:
			add(f+"kind", fmt.Sprintf("step %d: a step is one of %s", i+1, strings.Join(StepKinds, ", ")))
		}
		p.Steps = append(p.Steps, st)
	}
	// Only findings raised from when a playbook is turned on start it.
	switch {
	case !p.Enabled:
		if old != nil {
			p.Since = old.Since
		}
	case old == nil || !old.Enabled:
		p.Since = now.UTC()
	default:
		p.Since = old.Since
	}
	return p, probs
}

// StatusLabels names finding statuses for people.
var StatusLabels = map[string]string{findings.StatusNew: "New", findings.StatusInProgress: "In progress",
	findings.StatusPending: "Pending", findings.StatusResolved: "Resolved", findings.StatusClosed: "Closed"}

// Summary says in plain English what a playbook does, as in "When
// brute-force fires at high or above: notify Slack #soc, then block IP
// on the edge firewall for the source after approval, then open a case."
func (p Playbook) Summary(refs Refs) string {
	when := "any detection"
	switch d := p.Trigger.Detections; {
	case len(d) == 1:
		when = d[0]
	case len(d) == 2 || len(d) == 3:
		when = joinAnd(d)
	case len(d) > 3:
		when = fmt.Sprintf("any of %d detections", len(d))
	}
	head := "When " + when + " fires"
	switch u := p.Trigger.MinUrgency; u {
	case "informational":
	case "critical":
		head += " at critical"
	case "":
		head += " at " + notify.DefaultMinUrgency + " or above"
	default:
		head += " at " + u + " or above"
	}
	if p.Trigger.IncludeSample {
		head += " (sample data too)"
	}
	if len(p.Steps) == 0 {
		return head + ": nothing yet. Add a step."
	}
	parts := make([]string, len(p.Steps))
	for i, s := range p.Steps {
		parts[i] = s.phrase(refs)
	}
	return head + ": " + strings.Join(parts, ", then ") + "."
}

// phrase says what a step does, in a few words.
func (s Step) phrase(refs Refs) string {
	switch s.Kind {
	case StepNotify:
		if l, ok := refs.Channels[s.Channel]; ok {
			return "notify " + l
		}
		return "notify a deleted channel"
	case StepAction:
		a, ok := refs.Actions[s.Action]
		what := "run " + s.Action
		if ok {
			what = lowerFirst(a.Label)
		}
		out := what + " for " + targetPhrase(s, a.Target)
		if s.NeedsApproval {
			out += " after approval"
		}
		return out
	case StepOpenCase:
		out := "open a case"
		if s.Reuse {
			out = "open a case (or add to the one it opened)"
		}
		if s.Owner != "" {
			out += " for " + s.Owner
		}
		return out
	case StepSetFinding:
		var bits []string
		if s.Status != "" {
			bits = append(bits, "set the finding to "+StatusLabels[s.Status])
		}
		if s.Owner != "" {
			if len(bits) == 0 {
				bits = append(bits, "assign the finding to "+s.Owner)
			} else {
				bits = append(bits, "assign it to "+s.Owner)
			}
		}
		return strings.Join(bits, " and ")
	}
	return s.Kind
}

// targetPhrase says where an action step's target comes from.
func targetPhrase(s Step, kind string) string {
	noun := map[string]string{respond.TargetIP: "IP", respond.TargetDomain: "domain", respond.TargetUser: "user", respond.TargetHost: "host"}[kind]
	switch s.Target {
	case TargetSrc:
		if noun == "IP" {
			return "the source IP"
		}
		return "the source"
	case TargetDest:
		if noun == "IP" {
			return "the destination IP"
		}
		return "the destination"
	case TargetUser:
		return "the user"
	case TargetHost:
		return "the host"
	case TargetFixed:
		return s.Value
	}
	if noun == "" {
		return "the finding's first entity"
	}
	return "the finding's " + noun
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	r, n := utf8.DecodeRuneInString(s)
	// Keep acronyms and names: "AD", "IP", "Slack".
	if n < len(s) {
		if r2, _ := utf8.DecodeRuneInString(s[n:]); unicode.IsUpper(r2) {
			return s
		}
	}
	return string(unicode.ToLower(r)) + s[n:]
}
