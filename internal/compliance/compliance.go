// Package compliance maps what Signalith collects, detects and checks to
// the controls of common security frameworks (NIST SP 800-53, CIS Controls,
// PCI DSS, ISO/IEC 27001, the HIPAA Security Rule and SOC 2), and reports
// which controls it has evidence for.
//
// The mapping has two layers. Capabilities are things Signalith can show
// on its own, each with a status worked out from the live system:
// "authentication logs arrive", "a vulnerability scan ran in the last 30
// days", "logs are kept a year". Controls name the capabilities that
// support them, and the NIST SP 800-53 controls they line up with, which
// pick the configuration checks that count as their evidence. Both layers
// are Signalith's own work (frameworks.yaml); for frameworks whose text is
// copyrighted only the control numbers are used.
package compliance

import (
	_ "embed"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed frameworks.yaml
var frameworksYAML []byte

// Status is how well a capability or control is supported.
type Status string

// Statuses. External and NotApplicable come only from an admin's note on a
// control (see Attestation).
const (
	Met           Status = "met"
	Partial       Status = "partial"
	Missing       Status = "missing"
	External      Status = "external"
	NotApplicable Status = "na"
)

// Framework is a compliance framework and the controls Signalith maps.
type Framework struct {
	ID        string    `yaml:"id" json:"id"`
	Name      string    `yaml:"name" json:"name"`
	Version   string    `yaml:"version" json:"version"`
	Publisher string    `yaml:"publisher" json:"publisher"`
	URL       string    `yaml:"url" json:"url"`
	Notice    string    `yaml:"notice" json:"notice"`
	Controls  []Control `yaml:"controls" json:"-"`
}

// Control is one control or requirement of a framework.
type Control struct {
	ID    string `yaml:"id" json:"id"`
	Group string `yaml:"group" json:"group"`
	// Title is the official title for public-domain frameworks, else
	// Signalith's own summary.
	Title string `yaml:"title" json:"title"`
	// Caps are the capabilities that support the control.
	Caps []string `yaml:"caps" json:"caps"`
	// NIST are the NIST SP 800-53 controls this control lines up with.
	// Configuration checks that reference one of them are evidence for it.
	NIST []string `yaml:"nist" json:"nist"`
}

type catalog struct {
	Frameworks []Framework `yaml:"frameworks"`
}

var (
	loadOnce   sync.Once
	frameworks []Framework
	loadErr    error
)

// Frameworks returns every framework, in display order.
func Frameworks() []Framework {
	loadOnce.Do(func() { frameworks, loadErr = parseFrameworks(frameworksYAML) })
	if loadErr != nil {
		panic("compliance: bad embedded frameworks.yaml: " + loadErr.Error())
	}
	return frameworks
}

// FrameworkByID finds a framework.
func FrameworkByID(id string) (Framework, bool) {
	for _, f := range Frameworks() {
		if f.ID == id {
			return f, true
		}
	}
	return Framework{}, false
}

var (
	frameworkID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,31}$`)
	nistID      = regexp.MustCompile(`^[A-Z]{2}-\d{1,2}(\(\d{1,2}\))?$`)
)

func parseFrameworks(b []byte) ([]Framework, error) {
	var c catalog
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	var p []string
	seen := map[string]bool{}
	for _, f := range c.Frameworks {
		if !frameworkID.MatchString(f.ID) || seen[f.ID] {
			p = append(p, fmt.Sprintf("framework id %q is not valid or not unique", f.ID))
		}
		seen[f.ID] = true
		if f.Name == "" || f.Notice == "" || !strings.HasPrefix(f.URL, "https://") {
			p = append(p, f.ID+": name, notice and an https url are required")
		}
		ctl := map[string]bool{}
		for _, c := range f.Controls {
			if c.ID == "" || ctl[c.ID] {
				p = append(p, fmt.Sprintf("%s: control id %q is empty or repeated", f.ID, c.ID))
			}
			ctl[c.ID] = true
			if c.Title == "" || c.Group == "" || len(c.Caps) == 0 {
				p = append(p, fmt.Sprintf("%s %s: title, group and caps are required", f.ID, c.ID))
			}
			for _, cp := range c.Caps {
				if _, ok := capabilityByID[cp]; !ok {
					p = append(p, fmt.Sprintf("%s %s: unknown capability %q", f.ID, c.ID, cp))
				}
			}
			for _, n := range c.NIST {
				if !nistID.MatchString(n) {
					p = append(p, fmt.Sprintf("%s %s: %q is not a NIST SP 800-53 control ID", f.ID, c.ID, n))
				}
			}
		}
		if len(f.Controls) == 0 {
			p = append(p, f.ID+": no controls")
		}
	}
	if len(p) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(p, "; "))
	}
	return c.Frameworks, nil
}

// refMatches reports whether a check's NIST reference, such as "CM-6a" or
// "AC-6(2)", supports the NIST control ctl. A base control ("AC-6") is
// supported by its enhancements; an enhancement only by itself.
func refMatches(ctl, ref string) bool {
	ref = strings.TrimRightFunc(strings.TrimSpace(ref), func(r rune) bool { return r >= 'a' && r <= 'z' })
	return ref == ctl || strings.HasPrefix(ref, ctl+"(")
}

// ---- the system as it is now ----

// Snapshot is what the evaluation needs to know about the system. A nil
// pointer field means that part of Signalith is turned off or could not be
// read.
type Snapshot struct {
	Now time.Time
	// Data is the events of each data model in the last DataWindow, not
	// counting sample data. DataErr says why it is unknown.
	Data    map[string]DataSeen
	DataErr string
	// Detections is nil when detections are off.
	Detections  []Detection
	SchedulerOn bool
	// Checks is nil when endpoints are off; Hosts is how many hosts run
	// osquery.
	Checks []CheckStat
	Hosts  int

	Vulns     *Vulns
	Findings  *Findings
	Cases     *Cases
	Notify    *Notify
	Response  *Response
	Intel     *Intel
	Retention *Retention
	Users     *Users
	// Assets is how many assets and identities are listed; -1 when unknown.
	Assets int
	// HTTPS is whether the web UI and API are served over HTTPS.
	HTTPS bool
}

// DataWindow is how far back event data counts as arriving.
const DataWindow = 7 * 24 * time.Hour

// DataSeen is the events of one data model.
type DataSeen struct {
	Count int64     `json:"count"`
	Last  time.Time `json:"last"`
}

// Detection is what the evaluation needs of a detection.
type Detection struct {
	ID      string
	Name    string
	Enabled bool
	// Models are the data models the query reads; empty means any.
	Models []string
	// Tactics are the ATT&CK tactics (short names) of its techniques.
	Tactics []string
	// Tags may map the detection to a control: "<framework>:<control>",
	// such as "pci-dss:10.2.1.4".
	Tags []string
}

// CheckStat is one configuration check and its results across hosts.
type CheckStat struct {
	ID, Title, Platform            string
	Refs                           []string
	Pass, Fail, NA, Error, Pending int
}

// Vulns is the state of vulnerability scanning.
type Vulns struct {
	Networks int
	LastScan time.Time // the last scan that finished; zero when none
}

// Findings counts the findings queue.
type Findings struct {
	Open int // not resolved or closed
	New  int // nobody has looked at yet
	// Stale are new findings older than TriageWindow.
	Stale int
}

// TriageWindow is how long a new finding may wait before triage counts as
// behind.
const TriageWindow = 7 * 24 * time.Hour

// Cases counts investigations.
type Cases struct{ Total, Open int }

// Notify counts the notification setup.
type Notify struct {
	Channels int
	Rules    int // enabled rules that send to at least one channel
}

// Response counts response actions and playbooks.
type Response struct {
	Actions   int // set up without problems
	Playbooks int
}

// Intel counts threat intel feeds.
type Intel struct {
	Feeds int // enabled
	Fresh int // downloaded in the last 7 days
}

// Retention is the event data retention policy.
type Retention struct {
	KeepDays  int // 0 keeps data forever
	Archive   bool
	MaxSizeGB float64
	Guard     bool
	// Shorter names the data categories with their own, shorter policy.
	Shorter []string
}

// Users counts who can sign in to Signalith.
type Users struct {
	Named     int // users other than the built-in admin
	Directory bool
}

// HasData reports whether a data model had events in the window.
func (s *Snapshot) HasData(model string) bool {
	if model == "" {
		for m, d := range s.Data {
			if d.Count > 0 && m != "Risk" {
				return true
			}
		}
		return false
	}
	return s.Data[model].Count > 0
}

// ---- results ----

// Report is the compliance view.
type Report struct {
	Generated    time.Time          `json:"generated"`
	Frameworks   []FrameworkReport  `json:"frameworks"`
	Capabilities []CapabilityResult `json:"capabilities"`
	// Notes are things that limit the report, such as event counts that
	// could not be read.
	Notes []string `json:"notes,omitempty"`
}

// FrameworkReport is one framework with every control's status.
type FrameworkReport struct {
	Framework
	// Score is the share of applicable controls with evidence, 0-100;
	// partly supported controls count half.
	Score    int             `json:"score"`
	Counts   map[Status]int  `json:"counts"`
	Controls []ControlReport `json:"controls"`
}

// ControlReport is one control's status and its evidence.
type ControlReport struct {
	Control
	Status Status `json:"status"`
	// Computed is the status from evidence alone, before an admin's note.
	Computed    Status         `json:"computed"`
	Evidence    []Evidence     `json:"evidence"`
	Checks      *CheckEvidence `json:"checks,omitempty"`
	Detections  []DetectionRef `json:"detections"`
	Attestation *Attestation   `json:"attestation,omitempty"`
}

// Evidence is one capability's part in a control.
type Evidence struct {
	Capability string `json:"capability"`
	Name       string `json:"name"`
	Status     Status `json:"status"`
	Detail     string `json:"detail"`
	Fix        string `json:"fix,omitempty"`
	Page       string `json:"page,omitempty"`
}

// CheckEvidence sums up the configuration checks behind a control.
type CheckEvidence struct {
	Checks  int        `json:"checks"`
	Pass    int        `json:"pass"`
	Fail    int        `json:"fail"`
	NA      int        `json:"na"`
	Pending int        `json:"pending"`
	Error   int        `json:"error"`
	Failing []CheckRef `json:"failing"`
}

// CheckRef names a check that failed on some hosts.
type CheckRef struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Platform string `json:"platform"`
	Hosts    int    `json:"hosts"`
}

// DetectionRef names an enabled detection that supports a control.
type DetectionRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Data is whether the data it reads arrives.
	Data bool `json:"data"`
	// Tagged is whether a tag maps it to this control by name.
	Tagged bool `json:"tagged,omitempty"`
}

// CapabilityResult is a capability's status on its own, for the list of
// capabilities.
type CapabilityResult struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      Status `json:"status"`
	Detail      string `json:"detail"`
	Fix         string `json:"fix,omitempty"`
	Page        string `json:"page,omitempty"`
}

// maxDetectionRefs caps the detections listed per control.
const maxDetectionRefs = 100

// Evaluate works out every framework's controls from a snapshot. notes
// holds the admins' notes on controls, keyed by Key.
func Evaluate(s *Snapshot, notes map[string]Attestation) *Report {
	rep := &Report{Generated: s.Now.UTC(), Frameworks: []FrameworkReport{}, Capabilities: []CapabilityResult{}}
	if s.DataErr != "" {
		rep.Notes = append(rep.Notes, "Event counts could not be read, so data sources show as missing: "+s.DataErr)
	}
	for _, c := range capabilities {
		st, detail := c.eval(s, nil)
		rep.Capabilities = append(rep.Capabilities, CapabilityResult{ID: c.ID, Name: c.Name, Description: c.Description, Status: st, Detail: detail, Fix: fixFor(c, st), Page: c.Page})
	}
	for _, f := range Frameworks() {
		fr := FrameworkReport{Framework: f, Counts: map[Status]int{Met: 0, Partial: 0, Missing: 0, External: 0, NotApplicable: 0}, Controls: []ControlReport{}}
		var points, applicable float64
		for _, c := range f.Controls {
			cr := evalControl(s, f.ID, c)
			if a, ok := notes[Key(f.ID, c.ID)]; ok {
				a := a
				cr.Attestation = &a
				cr.Status = a.Status
			}
			fr.Counts[cr.Status]++
			switch cr.Status {
			case Met, External:
				points++
				applicable++
			case Partial:
				points += 0.5
				applicable++
			case Missing:
				applicable++
			}
			fr.Controls = append(fr.Controls, cr)
		}
		if applicable > 0 {
			fr.Score = int(points/applicable*100 + 0.5)
		}
		rep.Frameworks = append(rep.Frameworks, fr)
	}
	return rep
}

func evalControl(s *Snapshot, fw string, c Control) ControlReport {
	cr := ControlReport{Control: c, Evidence: []Evidence{}, Detections: []DetectionRef{}}
	ctx := &controlCtx{framework: fw, control: c}
	var met, partial, total int
	for _, id := range c.Caps {
		cp := capabilityByID[id]
		st, detail := cp.eval(s, ctx)
		cr.Evidence = append(cr.Evidence, Evidence{Capability: cp.ID, Name: cp.Name, Status: st, Detail: detail, Fix: fixFor(cp, st), Page: cp.Page})
		total++
		switch st {
		case Met:
			met++
		case Partial:
			partial++
		}
	}
	// Detections tagged with this control count too, as their own line
	// when no capability of the control is about detections.
	tagged := taggedDetections(s, fw, c.ID)
	if len(tagged) > 0 && !ctx.detections {
		st, detail := detectionStatus(s, tagged, nil)
		cr.Evidence = append(cr.Evidence, Evidence{Capability: "tagged", Name: "Detections tagged for this control", Status: st, Detail: detail, Fix: fixFor(capabilityByID["detect-any"], st), Page: "detections"})
		total++
		switch st {
		case Met:
			met++
		case Partial:
			partial++
		}
	}
	cr.Checks = ctx.checks
	seen := map[string]bool{}
	for _, d := range append(tagged, ctx.dets...) {
		if !d.Enabled || seen[d.ID] || len(cr.Detections) >= maxDetectionRefs {
			continue
		}
		seen[d.ID] = true
		cr.Detections = append(cr.Detections, DetectionRef{ID: d.ID, Name: d.Name, Data: detectionHasData(s, d), Tagged: slices.ContainsFunc(tagged, func(t Detection) bool { return t.ID == d.ID })})
	}
	switch {
	case total > 0 && met == total:
		cr.Computed = Met
	case met > 0 || partial > 0:
		cr.Computed = Partial
	default:
		cr.Computed = Missing
	}
	cr.Status = cr.Computed
	return cr
}

func taggedDetections(s *Snapshot, fw, control string) []Detection {
	want := strings.ToLower(fw + ":" + control)
	var out []Detection
	for _, d := range s.Detections {
		for _, t := range d.Tags {
			if strings.ToLower(strings.TrimSpace(t)) == want {
				out = append(out, d)
				break
			}
		}
	}
	return out
}
