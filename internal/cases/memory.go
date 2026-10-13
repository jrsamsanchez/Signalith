package cases

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"sync"
)

// Memory is an in-memory Store for tests and evaluation.
type Memory struct {
	mu   sync.Mutex
	byID map[string]*Case
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory { return &Memory{byID: map[string]*Case{}} }

func clone(c *Case) *Case {
	b, _ := json.Marshal(c)
	var out Case
	_ = json.Unmarshal(b, &out)
	return &out
}

func (m *Memory) Create(_ context.Context, c *Case) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[c.ID]; ok {
		return ErrExists
	}
	m.byID[c.ID] = clone(c)
	return nil
}

func (m *Memory) Get(_ context.Context, id string) (*Case, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	return clone(c), nil
}

func (m *Memory) Save(_ context.Context, c *Case) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[c.ID]; !ok {
		return ErrNotFound
	}
	m.byID[c.ID] = clone(c)
	return nil
}

func (m *Memory) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byID, id)
	return nil
}

func matches(c *Case, flt Filter) bool {
	if len(flt.Status) > 0 && !slices.Contains(flt.Status, c.Status) {
		return false
	}
	if flt.Owner != "" && c.Owner != flt.Owner {
		return false
	}
	if flt.FindingID != "" && !slices.Contains(c.Findings, flt.FindingID) {
		return false
	}
	if flt.Sample != nil && (*flt.Sample == "" || c.Sample != *flt.Sample) {
		return false
	}
	if t := strings.ToLower(strings.TrimSpace(flt.Text)); t != "" {
		hay := strings.ToLower(c.ID + "\n" + c.Title + "\n" + c.Description)
		if !strings.Contains(hay, t) && !slices.ContainsFunc(c.EntityValues(), func(v string) bool { return strings.EqualFold(v, t) }) {
			return false
		}
	}
	return true
}

func (m *Memory) Search(_ context.Context, flt Filter) ([]*Case, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Case
	for _, c := range m.byID {
		if matches(c, flt) {
			cc := clone(c)
			cc.Entries, cc.History = nil, nil
			out = append(out, cc)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Updated.After(out[j].Updated) })
	total := len(out)
	if flt.Limit > 0 && len(out) > flt.Limit {
		out = out[:flt.Limit]
	}
	return out, total, nil
}
