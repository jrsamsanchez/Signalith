package summary

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Coverage tells searches which slots of each data model summaries
// cover. Every server keeps one, reading the state documents every
// refreshEvery, so a search never waits on them.
type Coverage struct {
	Client interface {
		SearchDocs(ctx context.Context, index string, query map[string]any) ([]store.Doc, error)
	}
	Runtime string
	Log     *slog.Logger

	mu     sync.RWMutex
	ranges map[string][]Range
}

const refreshEvery = 30 * time.Second

// Run reads the states until ctx ends.
func (c *Coverage) Run(ctx context.Context) {
	t := time.NewTicker(refreshEvery)
	defer t.Stop()
	for {
		c.Refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Refresh reads the states once. When they cannot be read, searches read
// events only until they can.
func (c *Coverage) Refresh(ctx context.Context) {
	sts, err := States(ctx, c.Client, c.Runtime)
	out := map[string][]Range{}
	if err == nil {
		for m, s := range sts {
			if r := s.Covered(); len(r) > 0 {
				out[m] = r
			}
		}
	} else if c.Log != nil && ctx.Err() == nil {
		c.Log.Debug("summaries: could not read their state", "error", err)
	}
	c.mu.Lock()
	c.ranges = out
	c.mu.Unlock()
}

// Set replaces the covered ranges, for tests.
func (c *Coverage) Set(ranges map[string][]Range) {
	c.mu.Lock()
	c.ranges = ranges
	c.mu.Unlock()
}

// Ranges returns the ranges model's summaries cover, nil for none.
func (c *Coverage) Ranges(model string) []Range {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ranges[model]
}
