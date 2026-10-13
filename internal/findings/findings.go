// Package findings stores the alerts detections raise and the triage work
// analysts do on them, like Splunk ES notable events and Incident Review.
package findings

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
)

// Statuses a finding moves through.
const (
	StatusNew        = "new"
	StatusInProgress = "in_progress"
	StatusPending    = "pending"
	StatusResolved   = "resolved"
	StatusClosed     = "closed"
)

// Statuses lists valid statuses in workflow order.
var Statuses = []string{StatusNew, StatusInProgress, StatusPending, StatusResolved, StatusClosed}

// Severities lists valid severities, lowest first.
var Severities = []string{"informational", "low", "medium", "high", "critical"}

// Dispositions record what a closed finding turned out to be.
var Dispositions = []string{"", "true_positive", "benign_true_positive", "false_positive", "undetermined"}

// Finding is one alert.
type Finding struct {
	ID          string `json:"id"`
	DetectionID string `json:"detection_id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	// Credit names the rule's author and licence, for detections from a
	// content pack whose licence asks for it.
	Credit   string `json:"credit,omitempty"`
	Severity string `json:"severity"`
	// Urgency is severity adjusted by the priority of the assets and
	// identities involved; the queue sorts and filters on it.
	Urgency     string         `json:"urgency,omitempty"`
	Status      string         `json:"status"`
	Owner       string         `json:"owner,omitempty"`
	Disposition string         `json:"disposition,omitempty"`
	MITRE       []string       `json:"mitre,omitempty"`
	Entities    map[string]any `json:"entities,omitempty"` // user, src, dest, host values from the result
	// Context is what the asset and identity lists say about each entity.
	Context  map[string]*assets.Context `json:"context,omitempty"`
	Result   map[string]any             `json:"result"`             // the result row that fired
	Query    string                     `json:"query"`              // drilldown search
	Earliest string                     `json:"earliest,omitempty"` // drilldown window, absolute
	Latest   string                     `json:"latest,omitempty"`
	GroupKey string                     `json:"group_key,omitempty"` // throttle key
	// CaseID is the investigation this finding belongs to, if any.
	CaseID string `json:"case_id,omitempty"`
	// Sample marks a finding the sample-data feature raised, holding the
	// load's ID, so Remove can delete exactly those; empty for real ones.
	Sample   string    `json:"sample,omitempty"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
	Comments []Comment `json:"comments,omitempty"`
	History  []Change  `json:"history,omitempty"`
}

// Comment is an analyst note.
type Comment struct {
	Author string    `json:"author"`
	Text   string    `json:"text"`
	Time   time.Time `json:"time"`
}

// Change records one field change for the audit trail.
type Change struct {
	Author string    `json:"author"`
	Field  string    `json:"field"`
	From   string    `json:"from"`
	To     string    `json:"to"`
	Time   time.Time `json:"time"`
}

// Filter selects findings.
type Filter struct {
	Status      []string `json:"status,omitempty"`
	Severity    []string `json:"severity,omitempty"`
	Urgency     []string `json:"urgency,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	DetectionID string   `json:"detection_id,omitempty"`
	Text        string   `json:"text,omitempty"`
	// Sample, when set, keeps only findings with this sample-load marker.
	// A marker is never empty, so a set but empty one matches no finding:
	// it never means "every finding".
	Sample *string `json:"sample,omitempty"`
	// EntityValues keeps findings whose entity values include any of these,
	// used to find findings raised from sample entities (hosts, IPs, users).
	EntityValues []string `json:"entity_values,omitempty"`
	Since        time.Time
	// UpdatedSince keeps findings changed at or after this time, so
	// dashboards see old findings closed recently.
	UpdatedSince time.Time
	Limit        int
}

// Update is a triage change. Nil fields stay as they are.
type Update struct {
	Status      *string `json:"status,omitempty"`
	Owner       *string `json:"owner,omitempty"`
	Severity    *string `json:"severity,omitempty"`
	Disposition *string `json:"disposition,omitempty"`
	Comment     string  `json:"comment,omitempty"`
}

// Validate checks an update's values.
func (u Update) Validate() error {
	if u.Status != nil && !slices.Contains(Statuses, *u.Status) {
		return fmt.Errorf("status must be one of %s", strings.Join(Statuses, ", "))
	}
	if u.Severity != nil && !slices.Contains(Severities, *u.Severity) {
		return fmt.Errorf("severity must be one of %s", strings.Join(Severities, ", "))
	}
	if u.Disposition != nil && !slices.Contains(Dispositions, *u.Disposition) {
		return fmt.Errorf("disposition must be one of %s", strings.Join(Dispositions[1:], ", "))
	}
	if len(u.Comment) > 10000 {
		return errors.New("comment is too long")
	}
	return nil
}

// Apply applies an update to a finding, recording history. It reports
// whether anything changed.
func (f *Finding) Apply(u Update, author string, now time.Time) bool {
	changed := false
	set := func(field string, cur *string, v *string) {
		if v == nil || *v == *cur {
			return
		}
		f.History = append(f.History, Change{Author: author, Field: field, From: *cur, To: *v, Time: now})
		*cur = *v
		changed = true
	}
	set("status", &f.Status, u.Status)
	set("owner", &f.Owner, u.Owner)
	if u.Severity != nil && *u.Severity != f.Severity && f.Urgency != "" {
		// An analyst's severity call replaces the computed urgency.
		urg := *u.Severity
		set("urgency", &f.Urgency, &urg)
	}
	set("severity", &f.Severity, u.Severity)
	set("disposition", &f.Disposition, u.Disposition)
	if c := strings.TrimSpace(u.Comment); c != "" {
		f.Comments = append(f.Comments, Comment{Author: author, Text: c, Time: now})
		changed = true
	}
	if changed {
		f.Updated = now
	}
	return changed
}

// Summary counts open findings for the dashboard.
type Summary struct {
	Open       int            `json:"open"`
	ByStatus   map[string]int `json:"by_status"`
	BySeverity map[string]int `json:"by_severity"` // open findings only
	ByUrgency  map[string]int `json:"by_urgency"`  // open findings only
}

// EffectiveUrgency is the urgency, or the severity for findings raised
// before urgency existed.
func (f *Finding) EffectiveUrgency() string {
	if f.Urgency != "" {
		return f.Urgency
	}
	return f.Severity
}

// Store persists findings.
type Store interface {
	Create(ctx context.Context, f *Finding) error
	Get(ctx context.Context, id string) (*Finding, error)
	Save(ctx context.Context, f *Finding) error
	// Delete removes one finding by ID. A missing finding is not an error.
	Delete(ctx context.Context, id string) error
	Search(ctx context.Context, flt Filter) ([]*Finding, int, error)
	// Exists reports whether a finding with this detection and group key was
	// created at or after since; used for throttling.
	Exists(ctx context.Context, detectionID, groupKey string, since time.Time) (bool, error)
	Summary(ctx context.Context) (*Summary, error)
}

// ErrNotFound is returned for unknown finding IDs.
var ErrNotFound = errors.New("finding not found")

// IsOpen reports whether a status still needs work.
func IsOpen(status string) bool {
	return status != StatusResolved && status != StatusClosed
}
