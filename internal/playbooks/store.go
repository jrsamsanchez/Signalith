package playbooks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Run statuses.
const (
	// StatusRunning is a run claimed and doing its steps. One left like
	// this by a server that stopped is marked interrupted, never run
	// again: its step may or may not have happened.
	StatusRunning = "running"
	// StatusWaiting is a run paused at a step that needs approval.
	StatusWaiting = "waiting_approval"
	// StatusApproved is a run an analyst approved; the server that runs
	// the background jobs picks it up and goes on.
	StatusApproved = "approved"
	// StatusQueued is a run that stopped between two steps because its
	// server lost the background jobs; the server that has them goes on.
	StatusQueued      = "queued"
	StatusSucceeded   = "succeeded"
	StatusFailed      = "failed"
	StatusRejected    = "rejected"
	StatusExpired     = "expired"
	StatusInterrupted = "interrupted"
)

// Statuses lists the run statuses.
var Statuses = []string{StatusRunning, StatusWaiting, StatusApproved, StatusQueued, StatusSucceeded, StatusFailed,
	StatusRejected, StatusExpired, StatusInterrupted}

// Step result statuses: a step succeeded or failed, waits for approval,
// was approved (and runs next), rejected, expired, or interrupted.
const (
	StepSucceeded   = "succeeded"
	StepFailed      = "failed"
	StepWaiting     = "waiting"
	StepApproved    = "approved"
	StepRejected    = "rejected"
	StepExpired     = "expired"
	StepInterrupted = "interrupted"
)

// Run is one run of a playbook for one finding, kept in
// <prefix>_playbook_runs: the claim that it runs once, where it is, and
// what each step did.
type Run struct {
	// ID is RunID(finding, playbook).
	ID           string `json:"id"`
	PlaybookID   string `json:"playbook_id"`
	PlaybookName string `json:"playbook_name"`
	// Playbook is the playbook as it was when the run started; the run
	// follows it to the end, even when the playbook changes meanwhile, so
	// what an analyst approves is what was planned.
	Playbook     Playbook `json:"playbook"`
	FindingID    string   `json:"finding_id"`
	FindingTitle string   `json:"finding_title"`
	DetectionID  string   `json:"detection_id,omitempty"`
	Urgency      string   `json:"urgency,omitempty"`
	Sample       bool     `json:"sample,omitempty"`
	Status       string   `json:"status"`
	// Next is the step to do next, from 0.
	Next  int          `json:"next"`
	Steps []StepResult `json:"steps"`
	// CaseID is the case the run opened or added the finding to.
	CaseID string `json:"case_id,omitempty"`
	// Approval is the step that waits, or waited, for approval.
	Approval *Approval `json:"approval,omitempty"`
	// Error says why the run stopped, when it did not finish.
	Error string `json:"error,omitempty"`
	// Server is the Signalith server that ran it last.
	Server   string    `json:"server,omitempty"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
	Finished time.Time `json:"finished,omitzero"`
}

// StepResult is what one step did.
type StepResult struct {
	Step   int    `json:"step"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
	// Text says what happened, as noted on the finding.
	Text  string `json:"text"`
	Error string `json:"error,omitempty"`
	// ActionRun is the response action's run in the audit log.
	ActionRun string    `json:"action_run,omitempty"`
	Time      time.Time `json:"time"`
}

// Approval is an action step waiting for an analyst's approval, with
// what exactly will run.
type Approval struct {
	Step        int    `json:"step"`
	Action      string `json:"action"`
	ActionLabel string `json:"action_label"`
	Target      string `json:"target"`
	TargetKind  string `json:"target_kind"`
	// What says exactly what will happen, in the words of respond's
	// Runner.Describe, as in "Block 203.0.113.7 on the edge firewall."
	What      string    `json:"what"`
	Requested time.Time `json:"requested"`
	Expires   time.Time `json:"expires"`
	// DecidedBy approved or rejected it, with Note.
	DecidedBy string    `json:"decided_by,omitempty"`
	Decided   time.Time `json:"decided,omitzero"`
	Note      string    `json:"note,omitempty"`
}

// Stored is a run as read, with its version for a conditional write.
type Stored struct {
	Run
	Version store.Version
}

// Filter selects runs.
type Filter struct {
	Status     []string
	FindingID  string
	PlaybookID string
	Limit      int // default 50, at most 500
}

func limitOf(flt Filter) int {
	switch {
	case flt.Limit <= 0:
		return 50
	case flt.Limit > 500:
		return 500
	}
	return flt.Limit
}

// ErrNotFound is a run that does not exist.
var ErrNotFound = errors.New("there is no playbook run with this ID")

// Runs keeps the runs.
type Runs interface {
	// Claim writes a new run: store.ErrExists when it is already there,
	// because the playbook ran, or is running, for that finding.
	Claim(ctx context.Context, r *Run) (store.Version, error)
	// Existing returns which of ids are there.
	Existing(ctx context.Context, ids []string) (map[string]bool, error)
	// Get reads one run in real time: ErrNotFound when it is not there.
	Get(ctx context.Context, id string) (Stored, error)
	// Update writes a run only if it is still at version v:
	// store.ErrConflict when it changed.
	Update(ctx context.Context, r *Run, v store.Version) (store.Version, error)
	// Due lists the runs to go on with (approved or queued), those
	// waiting for approval past their expiry by now, and those running
	// but not changed since stale.
	Due(ctx context.Context, now, stale time.Time) (resume, expired, stuck []Stored, err error)
	// List returns runs, newest first, and how many match in all.
	List(ctx context.Context, flt Filter) ([]Run, int, error)
	// Purge deletes finished runs created before t.
	Purge(ctx context.Context, before time.Time) error
}

// Docs is what OpenSearch keeps runs with; *store.Client is one.
type Docs interface {
	Do(ctx context.Context, method, path string, body any, out any) error
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
	MGetVersions(ctx context.Context, refs []store.Ref) (map[store.Ref]store.Version, error)
	SearchDocs(ctx context.Context, index string, query map[string]any) ([]store.Doc, error)
}

// OpenSearch keeps runs in one index, "<prefix>_playbook_runs". Its name
// uses "_" rather than "-" so event searches over "<prefix>-*" never
// include it.
type OpenSearch struct {
	Client Docs
	Index  string
	// Replicas are the index's replicas settings (opensearch.replicas,
	// see config.Replicas.IndexSettings); nil is auto.
	Replicas map[string]any
}

// NewOpenSearch returns the runs index of prefix.
func NewOpenSearch(c Docs, prefix string) *OpenSearch {
	return &OpenSearch{Client: c, Index: prefix + "_playbook_runs"}
}

func properties() map[string]any {
	kw := map[string]any{"type": "keyword"}
	date := map[string]any{"type": "date"}
	off := map[string]any{"type": "object", "enabled": false}
	return map[string]any{
		"id": kw, "playbook_id": kw, "playbook_name": kw, "finding_id": kw, "detection_id": kw, "urgency": kw,
		"sample": map[string]any{"type": "boolean"}, "status": kw, "next": map[string]any{"type": "integer"},
		"case_id": kw, "server": kw, "created": date, "updated": date, "finished": date,
		"finding_title": map[string]any{"type": "text"},
		"error":         map[string]any{"type": "text", "index": false},
		"playbook":      off, "steps": off,
		"approval": map[string]any{"type": "object", "properties": map[string]any{
			"action": kw, "target": kw, "decided_by": kw, "requested": date, "expires": date, "decided": date,
		}},
	}
}

// EnsureIndex creates the index if it does not exist. Any server may.
func (o *OpenSearch) EnsureIndex(ctx context.Context) error {
	body := map[string]any{
		"settings": store.SmallIndexSettings(o.Replicas),
		"mappings": map[string]any{"dynamic": "false", "properties": properties()},
	}
	err := o.Client.Do(ctx, http.MethodPut, "/"+url.PathEscape(o.Index), body, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == 400 && strings.Contains(oe.Body, "resource_already_exists_exception") {
		return nil
	}
	return err
}

// Replicate gives the playbook runs index, when it was made with no copy
// on another node, the replicas settings new indices get (see
// store.Replicate). Only the server that runs the background jobs does,
// when it starts running them; doing it again changes nothing.
func (o *OpenSearch) Replicate(ctx context.Context) error {
	return store.Replicate(ctx, o.Client, o.Index, o.Replicas)
}

func (o *OpenSearch) Claim(ctx context.Context, r *Run) (store.Version, error) {
	return o.Client.Create(ctx, o.Index, r.ID, r, true)
}

func (o *OpenSearch) Existing(ctx context.Context, ids []string) (map[string]bool, error) {
	out := map[string]bool{}
	for len(ids) > 0 {
		n := min(len(ids), 500)
		refs := make([]store.Ref, n)
		for i, id := range ids[:n] {
			refs[i] = store.Ref{Index: o.Index, ID: id}
		}
		got, err := o.Client.MGetVersions(ctx, refs)
		if err != nil {
			return nil, err
		}
		for r := range got {
			out[r.ID] = true
		}
		ids = ids[n:]
	}
	return out, nil
}

func (o *OpenSearch) Get(ctx context.Context, id string) (Stored, error) {
	src, v, found, err := o.Client.Get(ctx, o.Index, id)
	if err != nil {
		return Stored{}, err
	}
	if !found {
		return Stored{}, ErrNotFound
	}
	var r Run
	if err := json.Unmarshal(src, &r); err != nil {
		return Stored{}, err
	}
	return Stored{Run: r, Version: v}, nil
}

func (o *OpenSearch) Update(ctx context.Context, r *Run, v store.Version) (store.Version, error) {
	return o.Client.PutIf(ctx, o.Index, r.ID, r, v, true)
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func (o *OpenSearch) Due(ctx context.Context, now, stale time.Time) (resume, expired, stuck []Stored, err error) {
	term := func(f string, v any) map[string]any { return map[string]any{"term": map[string]any{f: v}} }
	q := map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": []any{
		map[string]any{"terms": map[string]any{"status": []string{StatusApproved, StatusQueued}}},
		map[string]any{"bool": map[string]any{"filter": []any{term("status", StatusWaiting),
			map[string]any{"range": map[string]any{"approval.expires": map[string]any{"lte": ts(now)}}}}}},
		map[string]any{"bool": map[string]any{"filter": []any{term("status", StatusRunning),
			map[string]any{"range": map[string]any{"updated": map[string]any{"lt": ts(stale)}}}}}},
	}}}
	docs, err := o.Client.SearchDocs(ctx, o.Index, q)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, d := range docs {
		var r Run
		if err := json.Unmarshal(d.Source, &r); err != nil {
			continue
		}
		s := Stored{Run: r, Version: d.Version}
		switch r.Status {
		case StatusApproved, StatusQueued:
			resume = append(resume, s)
		case StatusWaiting:
			expired = append(expired, s)
		case StatusRunning:
			stuck = append(stuck, s)
		}
	}
	sortStored(resume)
	return resume, expired, stuck, nil
}

// sortStored orders runs oldest first, so they go on in the order they
// were raised.
func sortStored(list []Stored) {
	sort.SliceStable(list, func(i, j int) bool {
		if !list[i].Created.Equal(list[j].Created) {
			return list[i].Created.Before(list[j].Created)
		}
		return list[i].ID < list[j].ID
	})
}

func (o *OpenSearch) List(ctx context.Context, flt Filter) ([]Run, int, error) {
	var fs []any
	if len(flt.Status) > 0 {
		fs = append(fs, map[string]any{"terms": map[string]any{"status": flt.Status}})
	}
	for _, t := range []struct{ field, v string }{{"finding_id", flt.FindingID}, {"playbook_id", flt.PlaybookID}} {
		if t.v != "" {
			fs = append(fs, map[string]any{"term": map[string]any{t.field: t.v}})
		}
	}
	q := map[string]any{"match_all": map[string]any{}}
	if len(fs) > 0 {
		q = map[string]any{"bool": map[string]any{"filter": fs}}
	}
	body := map[string]any{"query": q, "size": limitOf(flt), "track_total_hits": true,
		"sort": []any{map[string]any{"created": "desc"}, map[string]any{"id": "asc"}}}
	var out struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source Run `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	err := o.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(o.Index)+"/_search?ignore_unavailable=true&allow_no_indices=true", body, &out)
	if err != nil {
		return nil, 0, err
	}
	list := make([]Run, 0, len(out.Hits.Hits))
	for _, h := range out.Hits.Hits {
		list = append(list, h.Source)
	}
	return list, out.Hits.Total.Value, nil
}

func (o *OpenSearch) Purge(ctx context.Context, before time.Time) error {
	q := map[string]any{"bool": map[string]any{
		"filter":   []any{map[string]any{"range": map[string]any{"created": map[string]any{"lt": ts(before)}}}},
		"must_not": []any{map[string]any{"terms": map[string]any{"status": []string{StatusRunning, StatusWaiting, StatusApproved, StatusQueued}}}},
	}}
	return o.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(o.Index)+"/_delete_by_query?conflicts=proceed&ignore_unavailable=true",
		map[string]any{"query": q}, nil)
}

// Memory keeps runs in memory, for tests and for a server without
// OpenSearch.
type Memory struct {
	mu   sync.Mutex
	docs map[string]Stored
	seq  int64
}

// NewMemory returns an empty Memory.
func NewMemory() *Memory { return &Memory{docs: map[string]Stored{}} }

func (m *Memory) next() store.Version {
	m.seq++
	return store.Version{SeqNo: m.seq, PrimaryTerm: 1, Version: m.seq}
}

func (m *Memory) Claim(_ context.Context, r *Run) (store.Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.docs[r.ID]; ok {
		return store.Version{}, store.ErrExists
	}
	v := m.next()
	m.docs[r.ID] = Stored{Run: copyRun(*r), Version: v}
	return v, nil
}

func (m *Memory) Existing(_ context.Context, ids []string) (map[string]bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for _, id := range ids {
		if _, ok := m.docs[id]; ok {
			out[id] = true
		}
	}
	return out, nil
}

func (m *Memory) Get(_ context.Context, id string) (Stored, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.docs[id]
	if !ok {
		return Stored{}, ErrNotFound
	}
	return Stored{Run: copyRun(s.Run), Version: s.Version}, nil
}

func (m *Memory) Update(_ context.Context, r *Run, v store.Version) (store.Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.docs[r.ID]
	if !ok || !cur.Version.Same(v) {
		return store.Version{}, store.ErrConflict
	}
	nv := m.next()
	m.docs[r.ID] = Stored{Run: copyRun(*r), Version: nv}
	return nv, nil
}

func (m *Memory) Due(_ context.Context, now, stale time.Time) (resume, expired, stuck []Stored, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.docs {
		c := Stored{Run: copyRun(s.Run), Version: s.Version}
		switch {
		case s.Status == StatusApproved || s.Status == StatusQueued:
			resume = append(resume, c)
		case s.Status == StatusWaiting && s.Approval != nil && !s.Approval.Expires.After(now):
			expired = append(expired, c)
		case s.Status == StatusRunning && s.Updated.Before(stale):
			stuck = append(stuck, c)
		}
	}
	sortStored(resume)
	sortStored(expired)
	sortStored(stuck)
	return resume, expired, stuck, nil
}

func (m *Memory) List(_ context.Context, flt Filter) ([]Run, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []Stored
	for _, s := range m.docs {
		if (len(flt.Status) > 0 && !slices.Contains(flt.Status, s.Status)) || (flt.FindingID != "" && s.FindingID != flt.FindingID) ||
			(flt.PlaybookID != "" && s.PlaybookID != flt.PlaybookID) {
			continue
		}
		all = append(all, s)
	}
	// Newest first; the write order breaks ties, since the clock can give
	// two runs the same time.
	sort.Slice(all, func(i, j int) bool {
		if !all[i].Created.Equal(all[j].Created) {
			return all[i].Created.After(all[j].Created)
		}
		return all[i].ID < all[j].ID
	})
	out := []Run{}
	for i := 0; i < len(all) && i < limitOf(flt); i++ {
		out = append(out, copyRun(all[i].Run))
	}
	return out, len(all), nil
}

func (m *Memory) Purge(_ context.Context, before time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.docs {
		if s.Created.Before(before) && !slices.Contains([]string{StatusRunning, StatusWaiting, StatusApproved, StatusQueued}, s.Status) {
			delete(m.docs, id)
		}
	}
	return nil
}

func copyRun(r Run) Run {
	b, _ := json.Marshal(r)
	var out Run
	_ = json.Unmarshal(b, &out)
	return out
}
