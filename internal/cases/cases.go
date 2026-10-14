// Package cases stores investigations: a case groups related findings with
// the analyst's notes, the searches they ran and the events they pinned,
// like Splunk ES investigations.
package cases

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Cases use the same statuses and severities as findings, so the queue and
// the case read the same way.
var (
	Statuses   = findings.Statuses
	Severities = findings.Severities
)

// Entry kinds on a case's timeline.
const (
	KindNote    = "note"
	KindSearch  = "search"
	KindEvent   = "event"
	KindFinding = "finding"
	// KindAction is a response action run on the case: Text says what
	// ran, on what, by whom and how it went; RunID names its record in
	// the audit log.
	KindAction = "action"
)

// Limits keep one case document a reasonable size.
const (
	MaxEntries    = 1000
	MaxRows       = 50 // rows kept from a saved search
	MaxEventBytes = 64 << 10
	MaxFindings   = 500
	MaxTextLen    = 20000
)

// Case is one investigation.
type Case struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Owner       string `json:"owner,omitempty"`
	// Resolution is the summary written when the case is closed.
	Resolution string            `json:"resolution,omitempty"`
	Findings   []string          `json:"findings,omitempty"` // finding IDs
	Entities   []Entity          `json:"entities,omitempty"`
	Entries    []Entry           `json:"entries,omitempty"`
	History    []findings.Change `json:"history,omitempty"`
	// Sample marks a case the sample-data feature created, holding the
	// load's ID, so Remove can delete it; empty for real investigations.
	Sample    string    `json:"sample,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
	Created   time.Time `json:"created"`
	Updated   time.Time `json:"updated"`
}

// Entity is a user, host, IP or other value the case is about.
type Entity struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

// Entry is one item on the case timeline: a note, a saved search with a
// snapshot of its results, a pinned event, a finding that was added, or a
// response action that was run.
type Entry struct {
	ID     string    `json:"id"`
	Kind   string    `json:"kind"`
	Author string    `json:"author"`
	Time   time.Time `json:"time"`
	Text   string    `json:"text,omitempty"`

	Query     string           `json:"query,omitempty"`
	Earliest  string           `json:"earliest,omitempty"`
	Latest    string           `json:"latest,omitempty"`
	Result    string           `json:"result_kind,omitempty"` // events, table, timechart
	Columns   []string         `json:"columns,omitempty"`
	Rows      []map[string]any `json:"rows,omitempty"`
	Matched   int64            `json:"matched,omitempty"`
	Truncated bool             `json:"truncated,omitempty"` // more rows than were kept

	Event     map[string]any `json:"event,omitempty"`
	FindingID string         `json:"finding_id,omitempty"`

	RunID  string `json:"run_id,omitempty"`
	Status string `json:"status,omitempty"` // of the run: succeeded or failed
}

// Filter selects cases.
type Filter struct {
	Status    []string
	Owner     string
	Text      string // title, description, ID or an entity value
	FindingID string
	// Sample, when set, keeps only cases with this sample-load marker. A
	// marker is never empty, so a set but empty one matches no case: it
	// never means "every case".
	Sample *string
	Limit  int
}

// Update changes a case. Nil fields stay as they are; a non-empty Comment
// adds a note.
type Update struct {
	Title       *string `json:"title,omitempty"`
	Description *string `json:"description,omitempty"`
	Status      *string `json:"status,omitempty"`
	Severity    *string `json:"severity,omitempty"`
	Owner       *string `json:"owner,omitempty"`
	Resolution  *string `json:"resolution,omitempty"`
	Comment     string  `json:"comment,omitempty"`
}

// Validate checks an update's values.
func (u Update) Validate() error {
	if u.Title != nil && strings.TrimSpace(*u.Title) == "" {
		return errors.New("title cannot be empty")
	}
	if u.Status != nil && !slices.Contains(Statuses, *u.Status) {
		return fmt.Errorf("status must be one of %s", strings.Join(Statuses, ", "))
	}
	if u.Severity != nil && !slices.Contains(Severities, *u.Severity) {
		return fmt.Errorf("severity must be one of %s", strings.Join(Severities, ", "))
	}
	for _, s := range []*string{u.Title, u.Description, u.Resolution, &u.Comment} {
		if s != nil && len(*s) > MaxTextLen {
			return errors.New("text is too long")
		}
	}
	return nil
}

// Apply applies an update, recording history. It reports whether anything
// changed.
func (c *Case) Apply(u Update, author string, now time.Time) bool {
	changed := false
	set := func(field string, cur *string, v *string) {
		if v == nil {
			return
		}
		nv := strings.TrimSpace(*v)
		if nv == *cur {
			return
		}
		from, to := *cur, nv
		if field == "description" || field == "resolution" {
			// Long text would swamp the activity list.
			from, to = "", "edited"
		}
		c.History = append(c.History, findings.Change{Author: author, Field: field, From: from, To: to, Time: now})
		*cur = nv
		changed = true
	}
	set("title", &c.Title, u.Title)
	set("description", &c.Description, u.Description)
	set("status", &c.Status, u.Status)
	set("severity", &c.Severity, u.Severity)
	set("owner", &c.Owner, u.Owner)
	set("resolution", &c.Resolution, u.Resolution)
	if t := strings.TrimSpace(u.Comment); t != "" {
		c.AddEntry(Entry{Kind: KindNote, Text: t}, author, now)
		changed = true
	}
	if changed {
		c.Updated = now
	}
	return changed
}

// AddEntry appends a timeline entry, filling its ID, author and time.
func (c *Case) AddEntry(e Entry, author string, now time.Time) (*Entry, error) {
	if len(c.Entries) >= MaxEntries {
		return nil, fmt.Errorf("a case holds at most %d timeline entries", MaxEntries)
	}
	e.ID = NewEntryID()
	e.Author = author
	e.Time = now
	c.Entries = append(c.Entries, e)
	c.Updated = now
	return &c.Entries[len(c.Entries)-1], nil
}

// RemoveEntry deletes a timeline entry. Finding entries are removed by
// removing the finding instead.
func (c *Case) RemoveEntry(id, author string, now time.Time) error {
	i := slices.IndexFunc(c.Entries, func(e Entry) bool { return e.ID == id })
	if i < 0 {
		return ErrEntryNotFound
	}
	e := c.Entries[i]
	c.Entries = slices.Delete(c.Entries, i, i+1)
	c.History = append(c.History, findings.Change{Author: author, Field: "timeline", From: e.Kind, To: "removed", Time: now})
	c.Updated = now
	return nil
}

// AddFinding links a finding and records it on the timeline. It reports
// false when the finding was already linked.
func (c *Case) AddFinding(f *findings.Finding, author string, now time.Time) (bool, error) {
	if slices.Contains(c.Findings, f.ID) {
		return false, nil
	}
	if len(c.Findings) >= MaxFindings {
		return false, fmt.Errorf("a case holds at most %d findings", MaxFindings)
	}
	if _, err := c.AddEntry(Entry{Kind: KindFinding, FindingID: f.ID, Text: f.Title}, author, now); err != nil {
		return false, err
	}
	c.Findings = append(c.Findings, f.ID)
	c.AddEntities(f.Entities)
	if sevRank(f.EffectiveUrgency()) > sevRank(c.Severity) {
		// A case is at least as urgent as its worst finding.
		c.History = append(c.History, findings.Change{Author: author, Field: "severity", From: c.Severity, To: f.EffectiveUrgency(), Time: now})
		c.Severity = f.EffectiveUrgency()
	}
	return true, nil
}

// RemoveFinding unlinks a finding and drops its timeline entry.
func (c *Case) RemoveFinding(id, author string, now time.Time) bool {
	i := slices.Index(c.Findings, id)
	if i < 0 {
		return false
	}
	c.Findings = slices.Delete(c.Findings, i, i+1)
	c.Entries = slices.DeleteFunc(c.Entries, func(e Entry) bool { return e.Kind == KindFinding && e.FindingID == id })
	c.History = append(c.History, findings.Change{Author: author, Field: "finding", From: id, To: "removed", Time: now})
	c.Updated = now
	return true
}

// EntityFields are the event and finding fields collected as case
// entities.
var EntityFields = []string{"user", "src_user", "src", "src_host", "dest", "dest_host", "host",
	"process_name", "process_sha256", "process_md5", "file_sha256", "object", "member", "query", "url", "risk_object"}

// AddEntities merges entity values, skipping ones already present and
// risk_object_type, which describes rather than names an entity.
func (c *Case) AddEntities(m map[string]any) {
	for _, f := range EntityFields {
		v, ok := m[f]
		if !ok || v == nil {
			continue
		}
		var vals []string
		switch x := v.(type) {
		case []any:
			for _, y := range x {
				vals = append(vals, fmt.Sprint(y))
			}
		default:
			vals = []string{fmt.Sprint(x)}
		}
		for _, s := range vals {
			c.AddEntity(Entity{Field: f, Value: s})
		}
	}
}

// AddEntity adds one entity unless it is empty or already present.
func (c *Case) AddEntity(e Entity) bool {
	e.Field, e.Value = strings.TrimSpace(e.Field), strings.TrimSpace(e.Value)
	if e.Field == "" || e.Value == "" || e.Value == "-" || slices.Contains(c.Entities, e) {
		return false
	}
	c.Entities = append(c.Entities, e)
	return true
}

// EntityValues lists entity values for searching cases.
func (c *Case) EntityValues() []string {
	var out []string
	for _, e := range c.Entities {
		out = append(out, e.Value)
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func sevRank(s string) int { return slices.Index(Severities, s) }

// TrimEvent bounds a pinned event's size, dropping _raw first.
func TrimEvent(ev map[string]any) (map[string]any, error) {
	b, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	if len(b) <= MaxEventBytes {
		return ev, nil
	}
	out := map[string]any{}
	for k, v := range ev {
		if k != "_raw" {
			out[k] = v
		}
	}
	if b, _ := json.Marshal(out); len(b) > MaxEventBytes {
		return nil, errors.New("the event is too large to pin to a case")
	}
	return out, nil
}

// NewID returns a case ID such as "CASE-20261012-3fa9c1d27b40e865". The
// 64 random bits make two cases with one ID practically impossible, and
// stores refuse to create a case whose ID exists (ErrExists) rather than
// replace it.
func NewID(now time.Time) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "CASE-" + now.UTC().Format("20060102") + "-" + hex.EncodeToString(b)
}

// NewEntryID returns a random timeline entry ID.
func NewEntryID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Store persists cases.
type Store interface {
	// Create adds a new case. It returns ErrExists, and changes nothing,
	// when a case with that ID exists.
	Create(ctx context.Context, c *Case) error
	Get(ctx context.Context, id string) (*Case, error)
	// Save replaces a whole case. Changes to a case go through Modify.
	Save(ctx context.Context, c *Case) error
	// Modify reads a case, lets change edit a fresh copy and writes it back
	// if change reports a change, but only if nobody else changed the case
	// in between; if someone did, it reads again and reruns change, so
	// change must be safe to run more than once. It returns the case as
	// written (or as read, when nothing changed), ErrNotFound when it is
	// not there, ErrBusy when others kept changing it, and change's own
	// error as it is.
	Modify(ctx context.Context, id string, change func(c *Case) (bool, error)) (*Case, error)
	// Delete removes one case by ID. A missing case is not an error.
	Delete(ctx context.Context, id string) error
	// Search returns matching cases, most recently updated first, without
	// their timelines, and the total number that match.
	Search(ctx context.Context, flt Filter) ([]*Case, int, error)
}

// Errors returned by stores and case methods.
var (
	ErrNotFound      = errors.New("case not found")
	ErrExists        = errors.New("a case with this ID exists")
	ErrEntryNotFound = errors.New("timeline entry not found")
	// ErrBusy is a Modify that lost to other changes of the same case on
	// every try.
	ErrBusy = errors.New("someone else changed this investigation at the same moment; try again")
)

// changeError carries the error of a Modify's change function through
// the retry loop, so it is returned as it is and never retried.
type changeError struct{ err error }

func (e changeError) Error() string { return e.err.Error() }

// modifyResult turns the outcome of a Modify loop into its error.
func modifyResult(err error) error {
	var ce changeError
	switch {
	case errors.As(err, &ce):
		return ce.err
	case errors.Is(err, store.ErrConflict):
		return ErrBusy
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	}
	return err
}

// OpenStatuses are the statuses that still need work.
var OpenStatuses = []string{findings.StatusNew, findings.StatusInProgress, findings.StatusPending}
