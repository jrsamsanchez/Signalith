package detect

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Exception tunes a detection: results that match it raise no finding and
// add no risk, like a Splunk ES suppression. Match lists result fields and
// the values they must have (with * and ? wildcards, ignoring case); every
// one must match. An exception with no Match suppresses every result, which
// with From and Until silences a detection for a maintenance window.
type Exception struct {
	ID      string            `yaml:"id" json:"id"`
	Match   map[string]string `yaml:"match,omitempty" json:"match,omitempty"`
	From    *time.Time        `yaml:"from,omitempty" json:"from,omitempty"`
	Until   *time.Time        `yaml:"until,omitempty" json:"until,omitempty"`
	Comment string            `yaml:"comment,omitempty" json:"comment,omitempty"`
	By      string            `yaml:"by,omitempty" json:"by,omitempty"`
	Added   time.Time         `yaml:"added" json:"added"`
	// Finding is the finding the exception was made from, if any.
	Finding string `yaml:"finding,omitempty" json:"finding,omitempty"`
}

// Limits on a detection's exceptions.
const (
	MaxExceptions     = 500
	maxExceptionField = 128
	maxExceptionValue = 1024
	maxExceptionMatch = 8
	maxCommentLen     = 1000
)

var exceptionField = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.:@-]*$`)

// NewExceptionID returns a random ID for an exception.
func NewExceptionID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return "ex-" + hex.EncodeToString(b)
}

// Active reports whether the exception applies at t.
func (e *Exception) Active(t time.Time) bool {
	if e.From != nil && t.Before(*e.From) {
		return false
	}
	if e.Until != nil && !t.Before(*e.Until) {
		return false
	}
	return true
}

// Expired reports whether the exception has ended for good by t.
func (e *Exception) Expired(t time.Time) bool { return e.Until != nil && !t.Before(*e.Until) }

// Matches reports whether a result row matches every field of the
// exception. A multi-valued field matches when any of its values does.
func (e *Exception) Matches(row map[string]any) bool {
	for field, want := range e.Match {
		if !valueMatches(row[field], want) {
			return false
		}
	}
	return true
}

func valueMatches(v any, pattern string) bool {
	switch x := v.(type) {
	case nil:
		return false
	case []any:
		for _, item := range x {
			if valueMatches(item, pattern) {
				return true
			}
		}
		return false
	case []string:
		for _, item := range x {
			if wildcard(pattern, item) {
				return true
			}
		}
		return false
	}
	return wildcard(pattern, fmt.Sprint(v))
}

// wildcard matches * (any run) and ? (any one character), ignoring case.
func wildcard(pattern, s string) bool {
	p := []rune(strings.ToLower(pattern))
	t := []rune(strings.ToLower(s))
	pi, ti, star, mark := 0, 0, -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && p[pi] != '*' && (p[pi] == '?' || p[pi] == t[ti]):
			pi++
			ti++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ti
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ti = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

func (e *Exception) problems() []string {
	var p []string
	if e.ID == "" {
		p = append(p, "exception id is required")
	}
	if len(e.Match) > maxExceptionMatch {
		p = append(p, fmt.Sprintf("exception %s: at most %d fields", e.ID, maxExceptionMatch))
	}
	for f, v := range e.Match {
		if len(f) > maxExceptionField || !exceptionField.MatchString(f) {
			p = append(p, fmt.Sprintf("exception %s: %q is not a field name", e.ID, f))
		}
		if strings.TrimSpace(v) == "" {
			p = append(p, fmt.Sprintf("exception %s: %s needs a value", e.ID, f))
		} else if len(v) > maxExceptionValue {
			p = append(p, fmt.Sprintf("exception %s: the value of %s is longer than %d characters", e.ID, f, maxExceptionValue))
		}
	}
	if len(e.Match) == 0 && e.Until == nil {
		p = append(p, fmt.Sprintf("exception %s: an exception for every result needs an end time; turn the detection off instead", e.ID))
	}
	if e.From != nil && e.Until != nil && !e.Until.After(*e.From) {
		p = append(p, fmt.Sprintf("exception %s: until must be after from", e.ID))
	}
	if len(e.Comment) > maxCommentLen {
		p = append(p, fmt.Sprintf("exception %s: the comment is longer than %d characters", e.ID, maxCommentLen))
	}
	return p
}

func exceptionProblems(es []Exception) []string {
	var p []string
	if len(es) > MaxExceptions {
		p = append(p, fmt.Sprintf("at most %d exceptions", MaxExceptions))
	}
	ids := map[string]bool{}
	for i := range es {
		p = append(p, es[i].problems()...)
		if ids[es[i].ID] {
			p = append(p, fmt.Sprintf("exception id %s is used twice", es[i].ID))
		}
		ids[es[i].ID] = true
	}
	return p
}

// Suppressing returns the first active exception that matches a result
// row at t, or nil.
func (d *Detection) Suppressing(row map[string]any, t time.Time) *Exception {
	for i := range d.Exceptions {
		if e := &d.Exceptions[i]; e.Active(t) && e.Matches(row) {
			return e
		}
	}
	return nil
}

// Describe is a short human description of what an exception matches.
func (e *Exception) Describe() string {
	if len(e.Match) == 0 {
		return "every result"
	}
	keys := make([]string, 0, len(e.Match))
	for k := range e.Match {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + e.Match[k]
	}
	return strings.Join(parts, " and ")
}
