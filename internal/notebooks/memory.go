package notebooks

import (
	"context"
	"sort"
	"sync"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Memory is an in-memory Store for tests and evaluation.
type Memory struct {
	mu   sync.Mutex
	byID map[string]*Notebook
	// ver counts the writes to each notebook, so Modify can tell whether
	// someone else wrote it while change ran, as OpenSearch's versions do.
	ver map[string]int64
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory { return &Memory{byID: map[string]*Notebook{}, ver: map[string]int64{}} }

func (m *Memory) Create(_ context.Context, n *Notebook) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[n.ID]; ok {
		return ErrExists
	}
	m.byID[n.ID] = clone(n)
	m.ver[n.ID]++
	return nil
}

func (m *Memory) Get(_ context.Context, id string) (*Notebook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	return clone(n), nil
}

// Modify runs change without holding the lock and writes only if the
// notebook was not written meanwhile; otherwise it tries again, like the
// OpenSearch store.
func (m *Memory) Modify(ctx context.Context, id string, change func(n *Notebook) (bool, error)) (*Notebook, error) {
	var out *Notebook
	err := store.RetryConflicts(ctx, func() error {
		m.mu.Lock()
		cur, ok := m.byID[id]
		var n *Notebook
		if ok {
			n = clone(cur)
		}
		v := m.ver[id]
		m.mu.Unlock()
		if !ok {
			return ErrNotFound
		}
		changed, err := change(n)
		if err != nil {
			return changeError{err}
		}
		if !changed {
			out = n
			return nil
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if _, ok := m.byID[id]; !ok || m.ver[id] != v {
			return store.ErrConflict
		}
		m.byID[id] = clone(n)
		m.ver[id]++
		out = n
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

func (m *Memory) Search(_ context.Context, f Filter) ([]*Summary, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []*Summary{}
	for _, n := range m.byID {
		if f.Matches(n) {
			out = append(out, Summarize(clone(n)))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Updated.After(out[j].Updated) })
	total := len(out)
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, total, nil
}
