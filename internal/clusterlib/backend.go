package clusterlib

import (
	"context"
	"errors"
	"time"

	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Detections keeps a detect.Library's custom detections and the state of
// its shipped ones in the shared collection (detect.Backend).
type Detections struct {
	Docs *Docs
	// Node is this server's name, recorded with each change.
	Node string
	// Writable refuses changes while the shared settings cannot be
	// changed on this server (shared.Runtime.Writable).
	Writable func() error
	// Source is where changes come from, FromPage when empty.
	Source string
	Now    func() time.Time
}

func (b *Detections) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func (b *Detections) source() string {
	if b.Source != "" {
		return b.Source
	}
	return FromPage
}

// Load implements detect.Backend.
func (b *Detections) Load() (map[string]detect.Stored, error) {
	out := map[string]detect.Stored{}
	for _, it := range b.Docs.Detections().List() {
		if it.Value == nil {
			continue
		}
		d, st, err := it.Value.decode(it.Name)
		if err != nil {
			continue
		}
		out[it.Name] = detect.Stored{Custom: d, State: st, By: it.UpdatedBy.User, Node: it.UpdatedBy.Node, At: it.UpdatedAt}
	}
	return out, nil
}

// OnChange implements detect.Backend.
func (b *Detections) OnChange(fn func()) { b.Docs.OnDetections(fn) }

// Change implements detect.Backend.
func (b *Detections) Change(ctx context.Context, by string, ids []string, fn func(string, detect.Stored) (detect.Stored, bool, error)) error {
	if b.Writable != nil {
		if err := b.Writable(); err != nil {
			return err
		}
	}
	c := b.Docs.Detections()
	_, _, err := c.MutateMany(ctx, by, ids, func(id string, cur *DetectionBody) (*DetectionBody, bool, error) {
		var st detect.Stored
		if cur != nil {
			d, s, err := cur.decode(id)
			if err != nil {
				return nil, false, err
			}
			st = detect.Stored{Custom: d, State: s}
			st.By, st.Node, st.At = whoOf(c, id)
		}
		next, write, err := fn(id, st)
		if err != nil || !write {
			return nil, false, err
		}
		body, err := detectionBody(next, cur)
		if err != nil {
			return nil, false, err
		}
		if body != nil {
			body.From = stamp(b.source(), b.Node, b.now())
		}
		return body, true, nil
	})
	return err
}

// whoOf returns who changed item id last, on which server and when.
func whoOf[T any](c *shared.Collection[T], id string) (by, node, at string) {
	it, ok := c.Item(id)
	if !ok {
		return "", "", ""
	}
	return it.UpdatedBy.User, it.UpdatedBy.Node, it.UpdatedAt
}

// detectionBody is the body of s, over old (nil for none), whose fields
// this version does not know it keeps; nil when s holds nothing.
func detectionBody(s detect.Stored, old *DetectionBody) (*DetectionBody, error) {
	if s.Custom == nil && s.State == nil {
		return nil, nil
	}
	b := &DetectionBody{State: s.State}
	if old != nil {
		b.Extra = old.Extra
	}
	if s.Custom != nil {
		c := *s.Custom
		c.Source = ""
		data, err := detect.Encode(&c)
		if err != nil {
			return nil, err
		}
		b.YAML = string(data)
	}
	return b, nil
}

// Dashboards keeps a dashboards.Store's dashboards in the shared
// collection (dashboards.Backend).
type Dashboards struct {
	Docs     *Docs
	Node     string
	Writable func() error
	Source   string
	Now      func() time.Time
}

func (b *Dashboards) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// List implements dashboards.Backend.
func (b *Dashboards) List() ([]dashboards.Stored, error) {
	var out []dashboards.Stored
	for _, it := range b.Docs.Dashboards().List() {
		if it.Value == nil {
			continue
		}
		d, err := it.Value.decode(it.Name)
		if err != nil {
			continue
		}
		out = append(out, dashboards.Stored{Dashboard: d, By: it.UpdatedBy.User, Node: it.UpdatedBy.Node, At: it.UpdatedAt})
	}
	return out, nil
}

// Get implements dashboards.Backend.
func (b *Dashboards) Get(id string) (dashboards.Stored, bool) {
	it, ok := b.Docs.Dashboards().Item(id)
	if !ok {
		return dashboards.Stored{}, false
	}
	d, err := it.Value.decode(id)
	if err != nil {
		return dashboards.Stored{}, false
	}
	return dashboards.Stored{Dashboard: d, By: it.UpdatedBy.User, Node: it.UpdatedBy.Node, At: it.UpdatedAt}, true
}

// Change implements dashboards.Backend.
func (b *Dashboards) Change(ctx context.Context, by, id string, fn func(*dashboards.Stored) (*dashboards.Dashboard, error)) error {
	if b.Writable != nil {
		if err := b.Writable(); err != nil {
			return err
		}
	}
	c := b.Docs.Dashboards()
	source := b.Source
	if source == "" {
		source = FromPage
	}
	_, _, err := c.MutateMany(ctx, by, []string{id}, func(id string, cur *DashboardBody) (*DashboardBody, bool, error) {
		var st *dashboards.Stored
		if cur != nil {
			d, err := cur.decode(id)
			if err != nil {
				// One this version cannot read counts as one with no
				// version, so a page can save over it.
				d = &dashboards.Dashboard{ID: id}
			}
			st = &dashboards.Stored{Dashboard: d}
			st.By, st.Node, st.At = whoOf(c, id)
		}
		next, err := fn(st)
		if err != nil {
			return nil, false, err
		}
		if next == nil {
			return nil, cur != nil, nil
		}
		data, err := dashboards.Encode(next)
		if err != nil {
			return nil, false, err
		}
		body := &DashboardBody{YAML: string(data), From: stamp(source, b.Node, b.now())}
		if cur != nil {
			body.Extra = cur.Extra
		}
		return body, true, nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return dashboards.ErrNotFound
	}
	return err
}
