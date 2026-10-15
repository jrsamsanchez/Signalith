package retention

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// MaxActions is how many recent actions the history keeps: a few weeks of
// daily runs, since one run can touch dozens of days.
const MaxActions = 200

// Run triggers.
const (
	TriggerSchedule = "schedule"
	TriggerManual   = "manual"
	TriggerGuard    = "disk_guard"
	TriggerChange   = "policy_change"
)

// Run reports one enforcement run.
type Run struct {
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Trigger  string    `json:"trigger"`
	By       string    `json:"by,omitempty"`
	// Indices compacted, archived (then deleted) and deleted outright.
	Compacted      int   `json:"compacted"`
	Archived       int   `json:"archived"`
	Deleted        int   `json:"deleted"`
	DeletedRecords int64 `json:"deleted_records"`
	// Skipped counts steps left out because settings saved during the run
	// no longer called for them.
	Skipped int `json:"skipped,omitempty"`
	// FreedBytes is what deletions and compaction freed in OpenSearch.
	FreedBytes int64        `json:"freed_bytes"`
	Errors     []string     `json:"errors"`
	Guard      *GuardStatus `json:"guard,omitempty"`
}

// Action records one thing retention did, or failed to do.
type Action struct {
	Time     time.Time `json:"time"`
	Action   string    `json:"action"` // compact, archive, delete, delete_records, restore
	Category string    `json:"category"`
	Index    string    `json:"index,omitempty"`
	Day      string    `json:"day,omitempty"`
	// Bytes is the index size before the action and Freed what it freed.
	Bytes int64 `json:"bytes,omitempty"`
	Freed int64 `json:"freed,omitempty"`
	// Docs counts events archived or restored, or records deleted.
	Docs   int64  `json:"docs,omitempty"`
	Rule   string `json:"rule,omitempty"`
	Reason string `json:"reason"`
	File   string `json:"file,omitempty"`
	By     string `json:"by,omitempty"`
	Error  string `json:"error,omitempty"`
	// Server is the server that took the action, when servers that share
	// one OpenSearch keep one history.
	Server string `json:"server,omitempty"`
}

// HistorySink keeps the last run and recent actions. A server on its own
// keeps them in a file (HistoryFile); servers that share one OpenSearch
// keep them as audit records, so the history survives a takeover.
type HistorySink interface {
	// Record adds a finished run (when not nil) and actions.
	Record(ctx context.Context, run *Run, acts ...Action) error
	// Recent returns the last run and the most recent actions, newest
	// first, at most MaxActions.
	Recent(ctx context.Context) (*Run, []Action, error)
	// Source names where the history is kept: "file" or "audit".
	Source() string
}

// History sources.
const (
	HistoryFromFile  = "file"
	HistoryFromAudit = "audit"
)

// Record implements HistorySink.
func (h *history) Record(_ context.Context, run *Run, acts ...Action) error {
	return h.add(run, acts...)
}

// Recent implements HistorySink.
func (h *history) Recent(context.Context) (*Run, []Action, error) {
	run, acts := h.get()
	return run, acts, nil
}

// Source implements HistorySink.
func (h *history) Source() string { return HistoryFromFile }

// Actions that are not index decisions.
const (
	ActionDeleteRecords = "delete_records"
	ActionRestore       = "restore"
)

// history is the last run and recent actions, kept in a JSON file.
type history struct {
	path string
	mu   sync.Mutex
	data historyData
}

type historyData struct {
	LastRun *Run     `json:"last_run,omitempty"`
	Actions []Action `json:"actions"`
}

func loadHistory(path string) *history {
	h := &history{path: path}
	if path == "" {
		return h
	}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &h.data)
	}
	return h
}

// add records actions, newest first, and saves the file.
func (h *history) add(run *Run, acts ...Action) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if run != nil {
		r := *run
		h.data.LastRun = &r
	}
	for _, a := range acts {
		h.data.Actions = append([]Action{a}, h.data.Actions...)
	}
	if len(h.data.Actions) > MaxActions {
		h.data.Actions = h.data.Actions[:MaxActions]
	}
	if h.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(h.data, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(h.path, b)
}

func (h *history) get() (*Run, []Action) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var run *Run
	if h.data.LastRun != nil {
		r := *h.data.LastRun
		run = &r
	}
	acts := make([]Action, len(h.data.Actions))
	copy(acts, h.data.Actions)
	return run, acts
}

// ReadHistoryFile reads a history file a server keeps on its own: the
// last run and the recent actions, newest first. A missing file is no
// history.
func ReadHistoryFile(path string) (*Run, []Action, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var d historyData
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, nil, fmt.Errorf("%s is not a retention history: %w", path, err)
	}
	return d.LastRun, d.Actions, nil
}
