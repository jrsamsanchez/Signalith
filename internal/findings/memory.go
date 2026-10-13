package findings

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Memory is an in-memory Store for tests and evaluation.
type Memory struct {
	mu   sync.Mutex
	byID map[string]*Finding
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory { return &Memory{byID: map[string]*Finding{}} }

func clone(f *Finding) *Finding {
	b, _ := json.Marshal(f)
	var out Finding
	_ = json.Unmarshal(b, &out)
	return &out
}

func (m *Memory) Create(_ context.Context, f *Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[f.ID] = clone(f)
	return nil
}

func (m *Memory) Get(_ context.Context, id string) (*Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	return clone(f), nil
}

func (m *Memory) Save(_ context.Context, f *Finding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[f.ID]; !ok {
		return ErrNotFound
	}
	m.byID[f.ID] = clone(f)
	return nil
}

func (m *Memory) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byID, id)
	return nil
}

// Matches reports whether a finding passes a filter.
func Matches(f *Finding, flt Filter) bool {
	if len(flt.Status) > 0 && !slices.Contains(flt.Status, f.Status) {
		return false
	}
	if len(flt.Severity) > 0 && !slices.Contains(flt.Severity, f.Severity) {
		return false
	}
	if len(flt.Urgency) > 0 && !slices.Contains(flt.Urgency, f.EffectiveUrgency()) {
		return false
	}
	if flt.Owner != "" && f.Owner != flt.Owner {
		return false
	}
	if flt.DetectionID != "" && f.DetectionID != flt.DetectionID {
		return false
	}
	if flt.Sample != nil && (*flt.Sample == "" || f.Sample != *flt.Sample) {
		return false
	}
	if len(flt.EntityValues) > 0 {
		ev := entityValues(f)
		any := false
		for _, want := range flt.EntityValues {
			if slices.Contains(ev, want) {
				any = true
				break
			}
		}
		if !any {
			return false
		}
	}
	if !flt.Since.IsZero() && f.Created.Before(flt.Since) {
		return false
	}
	if !flt.UpdatedSince.IsZero() && f.Updated.Before(flt.UpdatedSince) {
		return false
	}
	if flt.Text != "" {
		b, _ := json.Marshal(f)
		if !strings.Contains(strings.ToLower(string(b)), strings.ToLower(flt.Text)) {
			return false
		}
	}
	return true
}

func (m *Memory) Search(_ context.Context, flt Filter) ([]*Finding, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Finding
	for _, f := range m.byID {
		if Matches(f, flt) {
			out = append(out, clone(f))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	total := len(out)
	if flt.Limit > 0 && len(out) > flt.Limit {
		out = out[:flt.Limit]
	}
	return out, total, nil
}

func (m *Memory) Exists(_ context.Context, detectionID, groupKey string, since time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range m.byID {
		if f.DetectionID == detectionID && f.GroupKey == groupKey && !f.Created.Before(since) {
			return true, nil
		}
	}
	return false, nil
}

func (m *Memory) Summary(_ context.Context) (*Summary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &Summary{ByStatus: map[string]int{}, BySeverity: map[string]int{}, ByUrgency: map[string]int{}}
	for _, f := range m.byID {
		s.ByStatus[f.Status]++
		if IsOpen(f.Status) {
			s.Open++
			s.BySeverity[f.Severity]++
			s.ByUrgency[f.EffectiveUrgency()]++
		}
	}
	return s, nil
}
