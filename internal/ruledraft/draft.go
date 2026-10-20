// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package ruledraft drafts a detection from a plain-English description,
// such as "more than 10 failed logins from the same source in 5 minutes".
// The draft is a whole rule: the search, how often it runs and how far
// back it looks, severity, ATT&CK techniques, risk and how repeats are
// grouped. It works offline with the Ask box's translator (package nlq),
// a table of attack cues and the detections already in the library; an AI
// model, when one is set up, can write the draft instead (see AI).
//
// A draft is never turned on: the person reviews it, backtests it and
// saves it.
package ruledraft

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/nlq"
	"github.com/jrsamsanchez/signalith/internal/query"
)

// MaxDescription is the longest description accepted, in bytes.
const MaxDescription = 1000

// Draft is a drafted detection and how it was made.
type Draft struct {
	Detection *detect.Detection `json:"detection"`
	// Source is "rules" (the offline translator), "library" (a copy of a
	// detection already in the library) or "ai".
	Source string `json:"source"`
	// BasedOn is the library detection a "library" draft copies.
	BasedOn string `json:"based_on,omitempty"`
	// Steps explain each choice, phrase by phrase.
	Steps []nlq.Step `json:"steps"`
	// Unknown lists the words the translator did not understand.
	Unknown    []string `json:"unknown,omitempty"`
	Confidence float64  `json:"confidence"`
	// Warnings are things to check before turning the detection on.
	Warnings []string `json:"warnings,omitempty"`
	// Similar lists detections already in the library that look like
	// what was described, best first.
	Similar []Similar `json:"similar,omitempty"`
}

// Similar is a library detection that matches the description.
type Similar struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	MITRE    []string `json:"mitre,omitempty"`
	Enabled  bool     `json:"enabled"`
	Source   string   `json:"source"`
	// Score is how much of the description it matches, from 0 to 1.
	Score float64 `json:"score"`
}

// libraryScore is the similarity at which a weak translation gives way to
// a copy of the library detection.
const libraryScore = 0.6

// closeScore is the similarity at which a draft warns that the library
// already has the detection.
const closeScore = 0.7

// vagueScore is the similarity at which a translation that understood
// almost nothing gives way to a copy of the library detection.
const vagueScore = 0.4

// Offline drafts a detection without an AI model. library is every
// detection the server has, for similar ones; it may be nil.
func Offline(description string, hints nlq.Hints, library []*detect.Detection) (*Draft, error) {
	description = strings.TrimSpace(description)
	if description == "" {
		return nil, fmt.Errorf("describe what to detect, for example: more than 10 failed logins from the same source in 5 minutes")
	}
	if len(description) > MaxDescription {
		return nil, fmt.Errorf("keep the description under %d characters", MaxDescription)
	}
	low := strings.ToLower(description)
	cs := matchCues(low)
	var techniques []string
	for _, c := range cs {
		for _, m := range c.mitre {
			if !slices.Contains(techniques, m) {
				techniques = append(techniques, m)
			}
		}
	}
	similar := FindSimilar(description, techniques, library, 5)
	text, window, windowPhrase := cutWindow(stripLead(description))
	text = strings.TrimSpace(statedPattern.ReplaceAllString(text, ""))
	if strings.Trim(text, " ,.;:-") == "" {
		// Only a window or a severity: search for the words as they are.
		text = description
	}
	res, err := nlq.Translate(text, hints)
	if err != nil {
		return nil, err
	}
	dr := &Draft{Source: "rules", Steps: res.Steps, Unknown: res.Unknown, Confidence: res.Confidence, Similar: similar}
	// A library detection that matches well beats a weak translation.
	if len(similar) > 0 && (similar[0].Score >= libraryScore && res.Confidence < libraryScore || similar[0].Score >= vagueScore && vague(res.Query)) {
		if base := find(library, similar[0].ID); base != nil {
			return fromLibrary(dr, description, base)
		}
	}
	q, err := query.Parse(res.Query)
	if err != nil {
		return nil, err
	}
	d := &detect.Detection{Description: description, Tags: []string{"plain-english"}}
	// The time range becomes the lookback; a detection's query sets none.
	lookback := window
	if lookback == "" && q.Earliest != "" && q.Latest == "" {
		if lb, ok := relative(q.Earliest); ok {
			lookback = lb
			windowPhrase = q.Earliest
		}
	}
	q.Earliest, q.Latest = "", ""
	d.Query = q.String()
	by := byFields(q)
	summary := !q.Drilldown().Events
	if lookback == "" {
		lookback = "10m"
		if summary {
			lookback = "15m"
		}
		dr.step("", "search back %s each run (the default; say \"in 5 minutes\" or \"in an hour\" to change it)", lookback)
	} else {
		dr.step(windowPhrase, "search back %s each run", lookback)
	}
	d.Lookback, d.Schedule = lookback, scheduleFor(lookback)
	dr.step("", "run every %s", d.Schedule)

	d.MITRE = techniques
	d.Severity = "medium"
	why := "the default"
	for _, c := range cs {
		if sevRank(c.severity) > sevRank(d.Severity) {
			d.Severity, why = c.severity, "it looks like "+c.label
		}
	}
	if s, phrase := statedSeverity(low); s != "" {
		d.Severity, why = s, "you said "+strconv.Quote(phrase)
	}
	dr.step("", "severity %s, because %s", d.Severity, why)
	for _, c := range cs {
		dr.step(c.phrase, "%s: ATT&CK %s", c.label, strings.Join(c.mitre, ", "))
	}
	if len(d.MITRE) == 0 {
		dr.warn("No ATT&CK technique was recognized. Add one so the detection counts on the coverage page.")
	}

	model := q.Datamodel
	objs := riskObjects(by, summary, model)
	if len(objs) > 0 {
		d.Risk = &detect.Risk{Score: riskScores[d.Severity], Objects: objs}
		var names []string
		for _, o := range objs {
			names = append(names, o.Field+" ("+o.Type+")")
		}
		dr.step("", "add %d risk to %s for each result", d.Risk.Score, strings.Join(names, " and "))
	} else {
		dr.warn("The results name no user or system, so the detection adds no risk. Group by user, src or dest to add risk.")
	}
	d.Throttle.Fields = by
	if len(by) == 0 {
		for _, o := range objs {
			d.Throttle.Fields = append(d.Throttle.Fields, o.Field)
		}
	}
	d.Throttle.Window = "1h"
	if lb, _ := detect.ParseDuration(d.Lookback); lb > time.Hour {
		d.Throttle.Window = d.Lookback
	}
	if len(d.Throttle.Fields) > 0 {
		dr.step("", "one finding per %s every %s", strings.Join(d.Throttle.Fields, ", "), d.Throttle.Window)
	}

	d.Title = title(text, cs, by, objs)
	d.ID = Slug(d.Title)
	d.Guidance = "Drafted from a plain-English description. Check the backtest and the triage steps for your environment before relying on it."
	if vague(res.Query) {
		dr.warn("Few words were understood, so the search is broad. Edit the query, or try naming the data, such as failed logins, processes or connections.")
	}
	if len(similar) > 0 && similar[0].Score >= closeScore {
		dr.warn(fmt.Sprintf("The library already has %q, which looks similar. Turning it on may be simpler than adding this one.", similar[0].Title))
	}
	d.Defaults()
	dr.Detection = d
	return dr, d.Validate()
}

func (dr *Draft) step(phrase, meaning string, args ...any) {
	dr.Steps = append(dr.Steps, nlq.Step{Phrase: phrase, Meaning: fmt.Sprintf(meaning, args...)})
}

func (dr *Draft) warn(w string) { dr.Warnings = append(dr.Warnings, w) }

func find(ds []*detect.Detection, id string) *detect.Detection {
	for _, d := range ds {
		if d.ID == id {
			return d
		}
	}
	return nil
}

// fromLibrary drafts a copy of a library detection, turned off, for the
// person to adjust.
func fromLibrary(dr *Draft, description string, base *detect.Detection) (*Draft, error) {
	data, err := detect.Encode(base)
	if err != nil {
		return nil, err
	}
	d, err := detect.Decode(data)
	if err != nil {
		return nil, err
	}
	d.ID = Slug(detect.BaseTitle(d.Title)) + "-custom"
	if len(d.ID) > 64 {
		d.ID = strings.TrimRight(d.ID[:64], "-_")
	}
	d.Enabled = false
	d.Exceptions = nil
	d.Source = ""
	if d.Description == "" {
		d.Description = description
	}
	dr.Source, dr.BasedOn, dr.Detection = "library", base.ID, d
	dr.Steps = append(dr.Steps, nlq.Step{Meaning: fmt.Sprintf("copied %q from the library, which matches the description best", base.BaseTitle())})
	state := "off"
	if base.Enabled {
		state = "on"
	}
	dr.warn(fmt.Sprintf("This copies %q, which is already in the library and %s. If both are on, each result raises two findings, so consider turning that one on instead.", base.BaseTitle(), state))
	d.Defaults()
	return dr, d.Validate()
}

// vague says a translated query names no data model and no field, so it
// is a text search at best.
func vague(q string) bool {
	return !strings.Contains(q, "datamodel=") && !strings.Contains(q, "=")
}

// leadPattern is what a description starts with that only says "write a
// detection": "alert me when", "detect", "notify me if" and so on.
var leadPattern = regexp.MustCompile(`(?i)^\s*(?:please\s+)?(?:(?:alert|notify|warn|tell|page)(?:\s+(?:me|us|the\s+soc))?(?:\s+(?:when|if|on|about|for|whenever))?|(?:detect|find|flag|catch|look\s+for|watch\s+for|spot)(?:\s+(?:when|if|whenever))?|(?:raise|create|make|write)\s+(?:a|an)\s+(?:finding|alert|detection|rule)\s+(?:when|if|for|on)|(?:a\s+)?(?:detection|rule|alert)\s+(?:for|when|that\s+fires\s+when))\s+`)

func stripLead(s string) string {
	if out := leadPattern.ReplaceAllString(s, ""); strings.TrimSpace(out) != "" {
		return out
	}
	return s
}

// windowPattern is a time window such as "in 5 minutes", "within an hour"
// or "over 2 days", which becomes the lookback.
var windowPattern = regexp.MustCompile(`(?i)\b(?:in|within|over|during|inside)\s+(?:(?:a|an|one)\s+|(\d+)\s*)(s|sec|secs|seconds?|m|min|mins|minutes?|h|hr|hrs|hours?|d|days?)\b(?:\s+window)?`)

// cutWindow takes a time window out of the text and returns it as a
// lookback.
func cutWindow(s string) (text, lookback, phrase string) {
	m := windowPattern.FindStringSubmatchIndex(s)
	if m == nil {
		return s, "", ""
	}
	n := 1
	if m[2] >= 0 {
		n, _ = strconv.Atoi(s[m[2]:m[3]])
	}
	unit := strings.ToLower(s[m[4]:m[5]])
	u := map[byte]string{'s': "s", 'm': "m", 'h': "h", 'd': "d"}[unit[0]]
	if n < 1 || n > 100000 {
		return s, "", ""
	}
	if u == "s" {
		// Detections search at least a minute back.
		n, u = max(1, (n+59)/60), "m"
	}
	lb := strconv.Itoa(n) + u
	if d, err := detect.ParseDuration(lb); err != nil || d > 90*24*time.Hour {
		return s, "", ""
	}
	phrase = s[m[0]:m[1]]
	return strings.Join(strings.Fields(s[:m[0]]+" "+s[m[1]:]), " "), lb, phrase
}

// relative turns a query's earliest=-24h into a lookback of 24h. Snapped
// times (@d) are not a fixed window and are left out.
func relative(earliest string) (string, bool) {
	m := regexp.MustCompile(`^-(\d+)(s|m|h|d|w)$`).FindStringSubmatch(earliest)
	if m == nil {
		return "", false
	}
	lb := m[1] + m[2]
	if d, err := detect.ParseDuration(lb); err != nil || d < time.Minute || d > 90*24*time.Hour {
		return "", false
	}
	return lb, true
}

// scheduleFor picks how often a detection runs for its lookback: often
// enough that a finding comes soon, never less often than the lookback.
func scheduleFor(lookback string) string {
	lb, err := detect.ParseDuration(lookback)
	if err != nil {
		return "5m"
	}
	switch {
	case lb <= 5*time.Minute:
		return lookback
	case lb <= 30*time.Minute:
		return "5m"
	case lb <= 2*time.Hour:
		return "15m"
	default:
		return "1h"
	}
}

// byFields returns the fields the query's first summary groups by.
func byFields(q *query.Query) []string {
	for _, c := range q.Commands {
		switch c := c.(type) {
		case *query.Stats:
			return slices.Clone(c.By)
		case *query.Top:
			return append(slices.Clone(c.Fields), c.By...)
		}
	}
	return nil
}

var (
	userFields   = []string{"user", "src_user", "member", "dest_user"}
	systemFields = []string{"dest", "src", "host", "dest_host", "src_host", "dest_ip", "src_ip", "dvc"}
)

// riskObjects picks the users and systems a result names. A summary names
// only its by fields; events carry the data model's usual fields.
func riskObjects(by []string, summary bool, model string) []detect.RiskObject {
	var out []detect.RiskObject
	if summary {
		for _, f := range by {
			switch {
			case slices.Contains(userFields, f):
				out = append(out, detect.RiskObject{Field: f, Type: "user"})
			case slices.Contains(systemFields, f):
				out = append(out, detect.RiskObject{Field: f, Type: "system"})
			}
		}
		return out
	}
	switch model {
	case "Network_Traffic", "Network_Resolution", "Web", "Intrusion_Detection":
		return []detect.RiskObject{{Field: "src", Type: "system"}}
	case "Vulnerabilities":
		return []detect.RiskObject{{Field: "dest", Type: "system"}}
	}
	return []detect.RiskObject{{Field: "user", Type: "user"}, {Field: "dest", Type: "system"}}
}

// riskScores is the risk each result adds, by severity, in line with the
// built-in detections.
var riskScores = map[string]int{"informational": 5, "low": 15, "medium": 30, "high": 50, "critical": 80}

func sevRank(s string) int {
	return map[string]int{"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}[s]
}

var statedPattern = regexp.MustCompile(`(?i)\b(critical|high|medium|low|informational|info)(?:\s+|-)(?:severity|priority|sev|urgency)\b|\b(?:severity|priority)\s*(?:of|=|:|is)?\s*(critical|high|medium|low|informational|info)\b`)

// statedSeverity reads a severity the description gives, such as "high
// severity" or "priority: low".
func statedSeverity(low string) (string, string) {
	m := statedPattern.FindStringSubmatch(low)
	if m == nil {
		return "", ""
	}
	s := m[1] + m[2]
	if s == "info" {
		s = "informational"
	}
	return s, m[0]
}

// title makes a finding title from the description: the first sentence,
// capitalized, with the result's user or system as a $field$ token.
func title(text string, cs []matched, by []string, objs []detect.RiskObject) string {
	t := strings.TrimSpace(statedPattern.ReplaceAllString(text, ""))
	if len(cs) > 0 {
		// The behaviour reads better than the description: "Password
		// guessing from $src$".
		t = strings.TrimPrefix(strings.TrimPrefix(cs[0].label, "a "), "an ")
	}
	if i := strings.IndexAny(t, ".!?\n"); i > 0 {
		t = t[:i]
	}
	t = strings.Join(strings.Fields(t), " ")
	t = strings.TrimRight(t, " ,;:-")
	if words := strings.Fields(t); len(t) > 80 {
		t = ""
		for _, w := range words {
			if len(t)+len(w)+1 > 80 {
				break
			}
			t = strings.TrimSpace(t + " " + w)
		}
	}
	// $ in the description would read as a token.
	t = strings.ReplaceAll(t, "$", "")
	if t == "" {
		t = "Custom detection"
	}
	r := []rune(t)
	r[0] = unicode.ToUpper(r[0])
	t = string(r)
	fields := by
	if len(fields) == 0 {
		for _, o := range objs {
			fields = append(fields, o.Field)
		}
	}
	// The system first: "on $dest$" says where to look.
	for _, f := range []string{"dest", "host", "dest_host", "src", "src_ip", "user", "src_user"} {
		if !slices.Contains(fields, f) {
			continue
		}
		switch f {
		case "dest", "host", "dest_host":
			return t + " on $" + f + "$"
		case "src", "src_ip":
			return t + " from $" + f + "$"
		default:
			return t + " by $" + f + "$"
		}
	}
	return t
}

var slugStrip = regexp.MustCompile(`[^a-z0-9]+`)

// Slug makes a detection ID from a title: lowercase words joined by
// dashes, without $field$ tokens, at most 48 characters.
func Slug(t string) string {
	s := strings.ToLower(detect.BaseTitle(t))
	s = strings.Trim(slugStrip.ReplaceAllString(s, "-"), "-")
	if len(s) > 48 {
		s = s[:48]
		if i := strings.LastIndexByte(s, '-'); i > 16 {
			s = s[:i]
		}
		s = strings.Trim(s, "-")
	}
	if len(s) < 3 {
		return "custom-detection"
	}
	return s
}
