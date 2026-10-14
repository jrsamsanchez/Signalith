// Package detect runs scheduled detections, like Splunk ES correlation
// searches. A detection is a query, a schedule and a lookback window; each
// result row it returns becomes a finding, unless the throttle says an
// identical finding was raised recently.
//
// Detections are YAML files. Built-in content ships inside the binary;
// detections an admin creates or edits are written to the detections
// directory, where a file with a built-in's id overrides that built-in.
package detect

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
	"github.com/jrsamsanchez/signalith/internal/query"
)

// Detection is one scheduled rule.
type Detection struct {
	ID    string `yaml:"id" json:"id"`
	Title string `yaml:"title" json:"title"` // may use $field$ tokens from the result row
	// Name is the detection's name without $field$ tokens, for views that
	// count it across hosts and users, such as the posture dashboard.
	// Optional: BaseTitle derives one from Title when it is empty.
	Name        string `yaml:"name,omitempty" json:"name,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// Query is a Signalith query. It must not set earliest= or latest=;
	// the lookback window decides the time range.
	Query    string   `yaml:"query" json:"query"`
	Schedule string   `yaml:"schedule" json:"schedule"` // how often it runs: 5m, 1h, 1d
	Lookback string   `yaml:"lookback" json:"lookback"` // how far back each run searches
	Severity string   `yaml:"severity" json:"severity"`
	MITRE    []string `yaml:"mitre,omitempty" json:"mitre,omitempty"` // ATT&CK technique IDs, such as T1110.001
	Throttle Throttle `yaml:"throttle,omitempty" json:"throttle"`
	// Risk adds risk to the users and systems in each result.
	Risk    *Risk `yaml:"risk,omitempty" json:"risk,omitempty"`
	Enabled bool  `yaml:"enabled" json:"enabled"`
	// Tags are free-form labels for filtering.
	Tags []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	// Notes for the analyst: how to triage, known false positives.
	Guidance string `yaml:"guidance,omitempty" json:"guidance,omitempty"`
	// Origin is set on detections from a content pack: where the rule
	// came from and whom to credit.
	Origin *Origin `yaml:"origin,omitempty" json:"origin,omitempty"`
	// Exceptions are results that raise nothing (see Exception).
	Exceptions []Exception `yaml:"exceptions,omitempty" json:"exceptions,omitempty"`

	// Source is "builtin", "pack", "custom" or "override"; set when loaded.
	Source string `yaml:"-" json:"source"`
}

// Throttle suppresses repeat findings. Two results with the same values
// for Fields within Window raise one finding. With no fields, the whole
// result row is the key.
type Throttle struct {
	Fields []string `yaml:"fields,omitempty" json:"fields,omitempty"`
	Window string   `yaml:"window,omitempty" json:"window,omitempty"`
}

var (
	idPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,63}$`)
	mitrePattern = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	durPattern   = regexp.MustCompile(`^(\d+)\s*(s|m|h|d|w)$`)
	tokenPattern = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_.()]*)\$`)
)

// ParseDuration parses 30s, 5m, 1h, 1d or 2w.
func ParseDuration(s string) (time.Duration, error) {
	m := durPattern.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return 0, fmt.Errorf("%q is not a duration; use a number and a unit, like 5m, 1h or 1d", s)
	}
	n, _ := strconv.Atoi(m[1])
	unit := map[string]time.Duration{
		"s": time.Second, "m": time.Minute, "h": time.Hour,
		"d": 24 * time.Hour, "w": 7 * 24 * time.Hour,
	}[m[2]]
	return time.Duration(n) * unit, nil
}

// Defaults fills empty optional fields.
func (d *Detection) Defaults() {
	if d.Schedule == "" {
		d.Schedule = "5m"
	}
	if d.Lookback == "" {
		d.Lookback = d.Schedule
	}
	if d.Severity == "" {
		d.Severity = "medium"
	}
	if d.Throttle.Window == "" && len(d.Throttle.Fields) > 0 {
		d.Throttle.Window = "1h"
	}
	if d.Risk != nil && d.Risk.Only && d.Throttle.Window == "" {
		// Overlapping runs would otherwise count the same risk twice.
		d.Throttle.Window = d.Lookback
	}
	for i, t := range d.MITRE {
		d.MITRE[i] = strings.ToUpper(strings.TrimSpace(t))
	}
}

// Validate checks every field and returns all problems at once.
func (d *Detection) Validate() error {
	var p []string
	if !idPattern.MatchString(d.ID) {
		p = append(p, "id must be 3-64 lowercase letters, digits, - or _")
	}
	if strings.TrimSpace(d.Title) == "" {
		p = append(p, "title is required")
	}
	if tokenPattern.MatchString(d.Name) {
		p = append(p, "name must not use $field$ tokens; it names the detection across all its findings")
	}
	if q, err := query.Parse(d.Query); err != nil {
		p = append(p, "query: "+err.Error())
	} else if q.Earliest != "" || q.Latest != "" {
		p = append(p, "query must not set earliest= or latest=; use lookback instead")
	}
	sched, err := ParseDuration(d.Schedule)
	if err != nil {
		p = append(p, "schedule: "+err.Error())
	} else if sched < time.Minute {
		p = append(p, "schedule must be at least 1m")
	}
	if lb, err := ParseDuration(d.Lookback); err != nil {
		p = append(p, "lookback: "+err.Error())
	} else if lb > 90*24*time.Hour {
		p = append(p, "lookback cannot be more than 90d")
	} else if err == nil && sched > 0 && lb < sched {
		p = append(p, "lookback should be at least as long as schedule, or events between runs are missed")
	}
	if !slices.Contains(findings.Severities, d.Severity) {
		p = append(p, "severity must be one of "+strings.Join(findings.Severities, ", "))
	}
	for _, t := range d.MITRE {
		if !mitrePattern.MatchString(t) {
			p = append(p, fmt.Sprintf("mitre %q must be a technique ID like T1110 or T1110.001", t))
		}
	}
	if d.Risk != nil {
		p = append(p, d.Risk.problems()...)
	}
	if d.Throttle.Window != "" {
		if _, err := ParseDuration(d.Throttle.Window); err != nil {
			p = append(p, "throttle.window: "+err.Error())
		}
	}
	p = append(p, exceptionProblems(d.Exceptions)...)
	if len(p) > 0 {
		return &ValidationError{ID: d.ID, Problems: p}
	}
	return nil
}

// ValidationError lists every problem with a detection.
type ValidationError struct {
	ID       string   `json:"id"`
	Problems []string `json:"problems"`
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("detection %q: %s", e.ID, strings.Join(e.Problems, "; "))
}

var (
	// tokenGroup is a parenthesised part of a title that holds a token,
	// as in "Malware found on $dest$ ($signature$)".
	tokenGroup = regexp.MustCompile(`\s*\([^()]*\$[A-Za-z_][A-Za-z0-9_.()]*\$[^()]*\)`)
	// tokenPhrase is a token with the preposition that leads to it, as in
	// "on $dest$", "from $src$" or "on port $dest_port$".
	tokenPhrase  = regexp.MustCompile(`(?i)\s+(?:on|from|by|against|to|for|of|at|via|in)\s+(?:(?:remote admin )?port\s+)?\$[A-Za-z_][A-Za-z0-9_.()]*\$`)
	trailingWord = regexp.MustCompile(`(?i)\s+(?:on|from|by|against|to|for|of|at|via|in|with|and)$`)
)

// BaseTitle is the detection's name for views that count it across many
// results, where no one result's values apply: Name when set, else Title
// with each $field$ token and the words that lead to it left out, so
// "Encoded PowerShell command on $dest$" reads "Encoded PowerShell
// command" rather than naming a host or the placeholder.
func (d *Detection) BaseTitle() string {
	if n := strings.TrimSpace(d.Name); n != "" {
		return n
	}
	return BaseTitle(d.Title)
}

// BaseTitle derives a name without tokens from a title; see
// Detection.BaseTitle.
func BaseTitle(title string) string {
	t := tokenGroup.ReplaceAllString(title, "")
	t = tokenPhrase.ReplaceAllString(t, "")
	t = tokenPattern.ReplaceAllString(t, "")
	t = strings.Join(strings.Fields(t), " ")
	// A word left leading to a token that is gone, as in "logged on with".
	t = trailingWord.ReplaceAllString(t, "")
	if t == "" {
		// Nothing but tokens: name the fields, as before.
		return strings.Join(strings.Fields(tokenPattern.ReplaceAllString(title, "$1")), " ")
	}
	r, n := utf8.DecodeRuneInString(t)
	return string(unicode.ToUpper(r)) + t[n:]
}

// RenderTitle replaces $field$ tokens with values from a result row.
// Characters in the result that hide or disguise text are written as
// visible markers (see ShowHidden), since the values come from events.
func RenderTitle(title string, row map[string]any) string {
	return ShowHidden(tokenPattern.ReplaceAllStringFunc(title, func(tok string) string {
		v, ok := row[tok[1:len(tok)-1]]
		if !ok || v == nil {
			return "unknown"
		}
		return fmt.Sprint(v)
	}))
}
