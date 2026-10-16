package cases

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Memory is an in-memory Store for tests and evaluation.
type Memory struct {
	mu   sync.Mutex
	byID map[string]*Case
	// ver counts the writes to each case, so Modify can tell whether
	// someone else wrote it while change ran, as OpenSearch's versions do.
	ver map[string]int64
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory { return &Memory{byID: map[string]*Case{}, ver: map[string]int64{}} }

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
	m.ver[c.ID]++
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
	m.ver[c.ID]++
	return nil
}

// Modify runs change without holding the lock, since change may read
// other stores, or this one, and writes only if the case was not written
// meanwhile; otherwise it tries again, like the OpenSearch store.
func (m *Memory) Modify(ctx context.Context, id string, change func(c *Case) (bool, error)) (*Case, error) {
	var out *Case
	err := store.RetryConflicts(ctx, func() error {
		m.mu.Lock()
		cur, ok := m.byID[id]
		var c *Case
		if ok {
			c = clone(cur)
		}
		v := m.ver[id]
		m.mu.Unlock()
		if !ok {
			return ErrNotFound
		}
		changed, err := change(c)
		if err != nil {
			return changeError{err}
		}
		if !changed {
			out = c
			return nil
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if _, ok := m.byID[id]; !ok || m.ver[id] != v {
			return store.ErrConflict
		}
		m.byID[id] = clone(c)
		m.ver[id]++
		out = c
		return nil
	})
	if err != nil {
		return nil, modifyResult(err)
	}
	return out, nil
}

func (m *Memory) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byID, id)
	m.ver[id]++
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
