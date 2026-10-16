package detect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"sort"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// RunStore reads and writes the run state and throttle documents in the
// runtime index (<prefix>_runtime). *store.Client implements it; a
// Scheduler without one keeps them in memory (NewMemoryRunStore), with
// the same rules.
type RunStore interface {
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
	DeleteIf(ctx context.Context, index, id string, v store.Version, refresh bool) error
	SearchDocs(ctx context.Context, index string, query map[string]any) ([]store.Doc, error)
}

// Document kinds in the runtime index.
const (
	kindDetState  = "detstate"
	kindDetManual = "detmanual"
	kindThrottle  = "throttle"
)

// DetState is the run state of one detection's schedule, as the server
// that runs the detections keeps it in detstate:<rule id>. Every server
// reads it, so the Detections page and the detection health look the
// same on all of them.
type DetState struct {
	Kind        string `json:"kind"`
	DetectionID string `json:"detection_id"`
	// LastSlot is the watermark: every slot up to it has been run (or
	// skipped). NextSlot is the one after it.
	LastSlot       time.Time `json:"last_slot,omitzero"`
	NextSlot       time.Time `json:"next_slot,omitzero"`
	LastRun        time.Time `json:"last_run,omitzero"`
	LastDurationMS int64     `json:"last_duration_ms"`
	LastResults    int       `json:"last_results"`
	LastFindings   int       `json:"last_findings"`
	LastRisk       int       `json:"last_risk"`
	LastThrottled  int       `json:"last_throttled"`
	LastDuplicates int       `json:"last_duplicates"`
	LastSuppressed int       `json:"last_suppressed"`
	LastError      string    `json:"last_error"`
	// ErrorKind is "query" (the rule itself is wrong), "timeout" or
	// "transient" (OpenSearch did not answer; the slot is retried).
	ErrorKind string `json:"error_kind"`
	TimedOut  bool   `json:"timed_out"`
	Capped    bool   `json:"capped"`
	// Attempts counts the runs of the slot after LastSlot that timed out.
	Attempts int       `json:"attempts"`
	LagMS    int64     `json:"lag_ms"`
	LastLate time.Time `json:"last_late,omitzero"`
	LateRuns int       `json:"late_runs"`
	Skipped  Skipped   `json:"skipped,omitzero"`
	// Schedule and Enabled are what the rule said when this server last
	// saw it: a change of either resets the watermark.
	Schedule  string    `json:"schedule"`
	Enabled   bool      `json:"enabled"`
	Created   time.Time `json:"created,omitzero"`
	GoneSince time.Time `json:"gone_since,omitzero"`
	Epoch     int64     `json:"epoch"`
	Node      string    `json:"node,omitempty"`
}

// Skipped records missed slots that were older than detections.catch_up,
// so they were not run: from the watermark From to To, Count slots,
// found At.
type Skipped struct {
	From  time.Time `json:"from,omitzero"`
	To    time.Time `json:"to,omitzero"`
	At    time.Time `json:"at,omitzero"`
	Count int       `json:"count,omitempty"`
}

// ManualRun is the last "Run now" of a detection, on any server, as kept
// in detmanual:<rule id>.
type ManualRun struct {
	At        time.Time `json:"at"`
	By        string    `json:"by,omitempty"`
	Node      string    `json:"node,omitempty"`
	Results   int       `json:"results"`
	Findings  int       `json:"findings"`
	Risk      int       `json:"risk"`
	Throttled int       `json:"throttled"`
	Error     string    `json:"error,omitempty"`
}

// manualDoc is a ManualRun as stored.
type manualDoc struct {
	Kind        string `json:"kind"`
	DetectionID string `json:"detection_id"`
	ManualRun
}

func detStateID(rule string) string  { return kindDetState + ":" + rule }
func detManualID(rule string) string { return kindDetManual + ":" + rule }

// detEntry is the leader's copy of one detstate document and the version
// it was read or written at.
type detEntry struct {
	doc DetState
	ver store.Version
	// read is the epoch stored in the document when it was last read.
	read int64
}

// errStaleEpoch refuses a run state write over one a newer leader made.
var errStaleEpoch = fmt.Errorf("%w (a newer one has written the detection run state)", ErrNotAllowed)

func (s *Scheduler) runStore() (RunStore, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Runtime == nil {
		if s.memRuns == nil {
			s.memRuns = NewMemoryRunStore()
		}
		return s.memRuns, s.runtimeIndex()
	}
	return s.Runtime, s.runtimeIndex()
}

func (s *Scheduler) runtimeIndex() string {
	if s.RuntimeIndex != "" {
		return s.RuntimeIndex
	}
	return "signalith_runtime"
}

func (s *Scheduler) epoch() int64 {
	if s.Epoch != nil {
		return s.Epoch()
	}
	return 0
}

// clusterNow is the time slots are worked out with: OpenSearch's clock
// as this server measures it, so every server agrees on slot boundaries.
func (s *Scheduler) clusterNow() time.Time {
	if s.ClusterNow != nil {
		return s.ClusterNow()
	}
	return s.now()
}

// loadStates reads every detstate document into the leader's copy, once
// per lease epoch: while the epoch stays the same, the copy is the truth.
func (s *Scheduler) loadStates(ctx context.Context) error {
	ep := s.epoch()
	s.mu.Lock()
	if s.det != nil && s.loadedEpoch == ep {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	rs, idx := s.runStore()
	docs, err := rs.SearchDocs(ctx, idx, map[string]any{"term": map[string]any{"kind": kindDetState}})
	if err != nil {
		return fmt.Errorf("could not read the detection run state: %w", err)
	}
	det := make(map[string]*detEntry, len(docs))
	for _, d := range docs {
		var st DetState
		if err := json.Unmarshal(d.Source, &st); err != nil || st.DetectionID == "" {
			continue
		}
		det[st.DetectionID] = &detEntry{doc: st, ver: d.Version, read: st.Epoch}
	}
	s.mu.Lock()
	s.det, s.loadedEpoch = det, ep
	// No run state at all: the first start of this version (or of a new
	// install). The next dispatch runs each enabled rule's current slot
	// once, as the scheduler before run state did on every start, so the
	// time since its last run before the upgrade is searched.
	s.firstStart = len(docs) == 0 && !s.noFirstStart
	s.mu.Unlock()
	return nil
}

// dropStates forgets the leader's copy, so it is read again before the
// next run.
func (s *Scheduler) dropStates() {
	s.mu.Lock()
	s.det = nil
	s.mu.Unlock()
}

// entry returns a copy of the leader's state of a rule.
func (s *Scheduler) entry(id string) (detEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.det[id]
	if !ok {
		return detEntry{}, false
	}
	return *e, true
}

// writeState writes a rule's run state, as worked out under the lease
// epoch ep (the one the leader's copy was read under): over the version
// this server read or wrote last, or as a new document. It is refused
// when the lease has moved on since ep, even if this server holds it
// again, and when a newer leader (a higher epoch) wrote it; this server
// then drops its copy and stops. A conflict is read again and, unless
// refused, written once more. A new document that turns out to exist is
// adopted instead of written over: adopted is then true, and the caller
// decides again.
func (s *Scheduler) writeState(ctx context.Context, e detEntry, ep int64) (adopted bool, err error) {
	rs, idx := s.runStore()
	if s.epoch() != ep || e.read > ep {
		s.dropStates()
		return false, errStaleEpoch
	}
	e.doc.Kind, e.doc.Epoch, e.doc.Node = kindDetState, ep, s.NodeID
	id := detStateID(e.doc.DetectionID)
	for try := 0; ; try++ {
		var nv store.Version
		if e.ver.IsZero() {
			nv, err = rs.Create(ctx, idx, id, e.doc, false)
		} else {
			nv, err = rs.PutIf(ctx, idx, id, e.doc, e.ver, false)
		}
		if err == nil {
			e.ver, e.read = nv, ep
			s.keepState(e, ep)
			return false, nil
		}
		if !store.IsConflict(err) && !errors.Is(err, store.ErrNotFound) || try > 0 {
			return false, err
		}
		raw, v, found, gerr := rs.Get(ctx, idx, id)
		if gerr != nil {
			return false, gerr
		}
		if !found {
			e.ver = store.Version{}
			continue
		}
		var cur DetState
		if json.Unmarshal(raw, &cur) != nil {
			cur = DetState{}
		}
		if cur.Epoch > ep {
			s.dropStates()
			return false, errStaleEpoch
		}
		if e.ver.IsZero() {
			// Another write made it first: take what it says.
			cur.DetectionID = e.doc.DetectionID
			s.keepState(detEntry{doc: cur, ver: v, read: cur.Epoch}, ep)
			return true, nil
		}
		e.ver = v
	}
}

// keepState puts a state written under epoch ep into the leader's copy,
// when that copy was read under the same epoch, and into the status
// cache.
func (s *Scheduler) keepState(e detEntry, ep int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.det != nil && s.loadedEpoch == ep {
		cp := e
		s.det[e.doc.DetectionID] = &cp
	}
	if s.cache != nil {
		s.cache.det[e.doc.DetectionID] = e.doc
	}
}

// statusCache is the run state of every detection as last read from the
// runtime index, shared by every server.
type statusCache struct {
	at     time.Time
	det    map[string]DetState
	manual map[string]ManualRun
}

// statusTTL is how long the run state read from OpenSearch is used.
const statusTTL = 5 * time.Second

// readStatus returns the cached run state, reading it again when it is
// older than statusTTL.
func (s *Scheduler) readStatus(ctx context.Context) (map[string]DetState, map[string]ManualRun, error) {
	s.mu.Lock()
	c := s.cache
	if c != nil && time.Since(c.at) < statusTTL {
		det, man := maps.Clone(c.det), maps.Clone(c.manual)
		s.mu.Unlock()
		return det, man, nil
	}
	s.mu.Unlock()
	rs, idx := s.runStore()
	docs, err := rs.SearchDocs(ctx, idx, map[string]any{"terms": map[string]any{"kind": []string{kindDetState, kindDetManual}}})
	if err != nil {
		if c != nil {
			// keepState and writeManual change the cached maps under s.mu.
			s.mu.Lock()
			det, man := maps.Clone(c.det), maps.Clone(c.manual)
			s.mu.Unlock()
			return det, man, err
		}
		return map[string]DetState{}, map[string]ManualRun{}, err
	}
	nc := &statusCache{at: time.Now(), det: map[string]DetState{}, manual: map[string]ManualRun{}}
	for _, d := range docs {
		var head struct {
			Kind        string `json:"kind"`
			DetectionID string `json:"detection_id"`
		}
		if json.Unmarshal(d.Source, &head) != nil || head.DetectionID == "" {
			continue
		}
		switch head.Kind {
		case kindDetState:
			var st DetState
			if json.Unmarshal(d.Source, &st) == nil {
				nc.det[head.DetectionID] = st
			}
		case kindDetManual:
			var m manualDoc
			if json.Unmarshal(d.Source, &m) == nil {
				nc.manual[head.DetectionID] = m.ManualRun
			}
		}
	}
	s.mu.Lock()
	s.cache = nc
	det, man := maps.Clone(nc.det), maps.Clone(nc.manual)
	s.mu.Unlock()
	return det, man, nil
}

// StatusCtx returns the run state of every detection that has one, as
// every server sees it, with this server's running and waiting flags on
// top. An error says the state could not be read; what was read last is
// still returned.
func (s *Scheduler) StatusCtx(ctx context.Context) (map[string]RunState, error) {
	det, man, err := s.readStatus(ctx)
	s.mu.Lock()
	for id, e := range s.det {
		det[id] = e.doc
	}
	flags := maps.Clone(s.flags)
	s.mu.Unlock()
	out := make(map[string]RunState, len(det)+len(man))
	for id, st := range det {
		out[id] = runStateOf(st)
	}
	for id, m := range man {
		rs := out[id]
		mc := m
		rs.Manual = &mc
		out[id] = rs
	}
	for id, f := range flags {
		if f.running || f.queued {
			rs := out[id]
			rs.Running, rs.queued = f.running, f.queued
			out[id] = rs
		}
	}
	if err != nil {
		for id, rs := range out {
			rs.StatusError = err.Error()
			out[id] = rs
		}
	}
	return out, err
}

// Status returns the run state of every detection that has one (see
// StatusCtx).
func (s *Scheduler) Status() map[string]RunState {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := s.StatusCtx(ctx)
	if err != nil {
		s.log().Warn("could not read the detection run state", "err", err)
	}
	return out
}

func runStateOf(st DetState) RunState {
	rs := RunState{
		LastRun: st.LastRun, NextRun: st.NextSlot, LastSlot: st.LastSlot, LastDuration: st.LastDurationMS,
		LastResults: st.LastResults, LastFindings: st.LastFindings, LastRisk: st.LastRisk,
		LastThrottled: st.LastThrottled, LastDuplicates: st.LastDuplicates, LastSuppressed: st.LastSuppressed,
		LastError: st.LastError, ErrorKind: st.ErrorKind, TimedOut: st.TimedOut, Capped: st.Capped,
		Lag: st.LagMS, LateRuns: st.LateRuns, LastLate: st.LastLate, Node: st.Node,
	}
	if st.Skipped.Count > 0 {
		sk := st.Skipped
		rs.Skipped = &sk
	}
	return rs
}

// memoryRunStore is a RunStore in memory, with the versions and
// conditional writes of the real one.
type memoryRunStore struct {
	mu   sync.Mutex
	seq  int64
	docs map[string]memDoc
}

type memDoc struct {
	index, id string
	src       json.RawMessage
	ver       store.Version
}

// NewMemoryRunStore returns an empty RunStore in memory.
func NewMemoryRunStore() RunStore {
	return &memoryRunStore{docs: map[string]memDoc{}}
}

func memKey(index, id string) string { return index + "\x00" + id }

func (m *memoryRunStore) Get(_ context.Context, index, id string) (json.RawMessage, store.Version, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.docs[memKey(index, id)]
	if !ok {
		return nil, store.Version{}, false, nil
	}
	return append(json.RawMessage(nil), d.src...), d.ver, true, nil
}

func (m *memoryRunStore) put(index, id string, body any, old store.Version) (store.Version, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return store.Version{}, err
	}
	m.seq++
	v := store.Version{SeqNo: m.seq, PrimaryTerm: 1, Version: old.Version + 1}
	m.docs[memKey(index, id)] = memDoc{index: index, id: id, src: raw, ver: v}
	return v, nil
}

func (m *memoryRunStore) Create(_ context.Context, index, id string, body any, _ bool) (store.Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.docs[memKey(index, id)]; ok {
		return store.Version{}, store.ErrExists
	}
	return m.put(index, id, body, store.Version{})
}

// PutIf writes over version v. A zero v writes whatever is there.
func (m *memoryRunStore) PutIf(_ context.Context, index, id string, body any, v store.Version, _ bool) (store.Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.docs[memKey(index, id)]
	if !v.IsZero() && (!ok || !d.ver.Same(v)) {
		return store.Version{}, store.ErrConflict
	}
	return m.put(index, id, body, d.ver)
}

func (m *memoryRunStore) DeleteIf(_ context.Context, index, id string, v store.Version, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.docs[memKey(index, id)]
	switch {
	case !ok:
		return store.ErrNotFound
	case !d.ver.Same(v):
		return store.ErrConflict
	}
	delete(m.docs, memKey(index, id))
	return nil
}

// SearchDocs understands the queries the scheduler sends: term, terms,
// and a bool filter of them.
func (m *memoryRunStore) SearchDocs(_ context.Context, index string, query map[string]any) ([]store.Doc, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Doc
	for _, d := range m.docs {
		if d.index != index {
			continue
		}
		var src map[string]any
		if json.Unmarshal(d.src, &src) != nil || !memMatch(query, src) {
			continue
		}
		out = append(out, store.Doc{Ref: store.Ref{Index: d.index, ID: d.id}, Version: d.ver, Found: true,
			Source: append(json.RawMessage(nil), d.src...)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func memMatch(q map[string]any, src map[string]any) bool {
	for op, arg := range q {
		a, _ := arg.(map[string]any)
		switch op {
		case "match_all":
		case "term":
			for f, v := range a {
				if fmt.Sprint(src[f]) != fmt.Sprint(v) {
					return false
				}
			}
		case "terms":
			for f, v := range a {
				ok := false
				switch vs := v.(type) {
				case []string:
					for _, x := range vs {
						ok = ok || fmt.Sprint(src[f]) == x
					}
				case []any:
					for _, x := range vs {
						ok = ok || fmt.Sprint(src[f]) == fmt.Sprint(x)
					}
				}
				if !ok {
					return false
				}
			}
		case "bool":
			for _, part := range []string{"filter", "must"} {
				list, _ := a[part].([]any)
				for _, c := range list {
					cm, _ := c.(map[string]any)
					if !memMatch(cm, src) {
						return false
					}
				}
			}
		default:
			return false
		}
	}
	return true
}
