package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Each server keeps its own share of a day's new field names (see
// maxNewNamesPerIndex), but servers come and go within a day, and every
// name another server added before counts towards OpenSearch's limit too.
// So before granting new names to an index, a server also looks at how
// many fields its mapping really has, and grants none once it reaches
// mappingStop. The count is kept for mappingTTL, so a burst of new names
// can pass mappingStop by up to one window's worth of shares, which still
// leaves room under the template's limit of 2000; past that, write keeps
// events with their known fields only (see retryable).
const (
	mappingStop    = 1600
	mappingTTL     = 30 * time.Second
	mappingTimeout = 2 * time.Second
)

// Doer sends OpenSearch REST requests. *store.Client has it.
type Doer interface {
	Do(ctx context.Context, method, path string, body any, out any) error
}

// MappingFieldCount returns a function that counts the fields of an
// index's mapping with GET /<index>/_mapping, as
// index.mapping.total_fields.limit counts them (see CountMappingFields). A
// missing index has none. Pipeline.FieldCount takes it.
func MappingFieldCount(d Doer) func(ctx context.Context, index string) (int, error) {
	return func(ctx context.Context, index string) (int, error) {
		var out map[string]struct {
			Mappings json.RawMessage `json:"mappings"`
		}
		err := d.Do(ctx, http.MethodGet, "/"+url.PathEscape(index)+"/_mapping", nil, &out)
		var oe *store.Error
		if errors.As(err, &oe) && oe.Status == http.StatusNotFound {
			return 0, nil
		}
		if err != nil {
			return 0, err
		}
		n := 0
		for _, ix := range out {
			n += CountMappingFields(ix.Mappings)
		}
		return n, nil
	}
}

// CountMappingFields counts the fields of a mapping as OpenSearch does for
// its total_fields limit: every property, objects included, and every
// multi-field under a property's "fields".
func CountMappingFields(mapping json.RawMessage) int {
	var m mappingNode
	if json.Unmarshal(mapping, &m) != nil {
		return 0
	}
	return m.count()
}

type mappingNode struct {
	Properties map[string]mappingNode `json:"properties"`
	Fields     map[string]mappingNode `json:"fields"`
}

func (m mappingNode) count() int {
	n := 0
	for _, p := range m.Properties {
		n += 1 + p.count()
	}
	for _, f := range m.Fields {
		n += 1 + f.count()
	}
	return n
}

// fieldCounter keeps each index's field count for a while (ttl, 0 is
// mappingTTL, below 0 not at all), and asks OpenSearch for one index at a
// time: a write that finds a count being fetched waits for it. A count
// that could not be had is not kept.
type fieldCounter struct {
	ttl time.Duration

	mu      sync.Mutex
	entries map[string]*fieldCount
}

type fieldCount struct {
	n    int
	err  error
	at   time.Time
	done chan struct{} // closed once n and err are set
}

// count returns index's field count, fetched with fetch when the one kept
// is older than the ttl. It never holds the field budget's lock.
func (c *fieldCounter) count(ctx context.Context, index string, now time.Time, fetch func(ctx context.Context, index string) (int, error)) (int, error) {
	ttl := c.ttl
	if ttl == 0 {
		ttl = mappingTTL
	}
	c.mu.Lock()
	if c.entries == nil {
		c.entries = map[string]*fieldCount{}
	}
	e := c.entries[index]
	if e != nil {
		select {
		case <-e.done:
			if ttl > 0 && now.Sub(e.at) < ttl {
				c.mu.Unlock()
				return e.n, e.err
			}
			e = nil // stale: fetch again
		default:
			// Being fetched: wait for it below.
		}
	}
	if e != nil {
		c.mu.Unlock()
		select {
		case <-e.done:
			return e.n, e.err
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	e = &fieldCount{done: make(chan struct{})}
	// Days pass: forget indices not asked about for a while.
	for k, old := range c.entries {
		select {
		case <-old.done:
			if now.Sub(old.at) > time.Hour {
				delete(c.entries, k)
			}
		default:
		}
	}
	c.entries[index] = e
	c.mu.Unlock()
	// The count is shared by every write to the index, so the writer
	// that fetches it going away does not cut the fetch short.
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mappingTimeout)
	n, err := fetch(fctx, index)
	cancel()
	c.mu.Lock()
	e.n, e.err, e.at = n, err, now
	if err != nil && c.entries[index] == e {
		// A failure is not kept: the next write asks again.
		delete(c.entries, index)
	}
	c.mu.Unlock()
	close(e.done)
	return n, err
}

// mappingFull reports whether index's mapping has reached mappingStop, so
// no new field names should go to it. A count that could not be had counts
// as not full (the retry with known fields stays as the backstop) and is
// logged.
func (p *Pipeline) mappingFull(ctx context.Context, index string) bool {
	if p.FieldCount == nil {
		return false
	}
	n, err := p.counter.count(ctx, index, p.now(), p.FieldCount)
	if err != nil {
		p.warn("mapping", "the number of fields of a daily index could not be read from OpenSearch; new field names are kept within this server's share until it can be",
			"index", index, "err", err)
		return false
	}
	return n >= mappingStop
}

// servers is how many servers share the day's field-name budgets.
func (p *Pipeline) servers() int {
	if p.Servers == nil {
		return 1
	}
	return max(p.Servers(), 1)
}
