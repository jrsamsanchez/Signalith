package summary

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

const kindState = "sumstate"

// State is how far one data model's summaries reach, kept in
// sumstate:<model> in the runtime index. Every server reads it to know
// which slots it may read from summaries.
type State struct {
	Kind   string `json:"kind"`
	Model  string `json:"model"`
	Layout string `json:"layout"`
	// The summaries cover [From, Through), except the gaps.
	From    time.Time `json:"from"`
	Through time.Time `json:"through"`
	Gaps    []Gap     `json:"gaps,omitempty"`
	Rows    int64     `json:"rows"`
	// LastBuild, CheckedRecent and CheckedAll are when slots were last
	// built, and the recent and the whole range last checked.
	LastBuild     time.Time `json:"last_build,omitzero"`
	CheckedRecent time.Time `json:"checked_recent,omitzero"`
	CheckedAll    time.Time `json:"checked_all,omitzero"`
	Rebuilt       int64     `json:"rebuilt"`
	LastError     string    `json:"last_error,omitempty"`
	Epoch         int64     `json:"epoch"`
	Node          string    `json:"node,omitempty"`
}

// Gap is a range whose slots had too many distinct values to summarize.
type Gap struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// maxGaps caps the gaps a state keeps; with more, the oldest merge.
const maxGaps = 50

// addGap adds g, merging touching gaps.
func addGap(gs []Gap, g Gap) []Gap {
	gs = append(gs, g)
	slices.SortFunc(gs, func(a, b Gap) int { return a.From.Compare(b.From) })
	var out []Gap
	for _, x := range gs {
		if n := len(out); n > 0 && !x.From.After(out[n-1].To) {
			if x.To.After(out[n-1].To) {
				out[n-1].To = x.To
			}
			continue
		}
		out = append(out, x)
	}
	for len(out) > maxGaps {
		out[1].From = out[0].From
		out = out[1:]
	}
	return out
}

// Covered returns the ranges a state's summaries cover: [From, Through)
// without the gaps.
func (s State) Covered() []Range {
	if !s.Through.After(s.From) {
		return nil
	}
	var out []Range
	at := s.From
	for _, g := range s.Gaps {
		if g.From.After(at) {
			out = append(out, Range{From: at, To: minTime(g.From, s.Through)})
		}
		if g.To.After(at) {
			at = g.To
		}
		if !at.Before(s.Through) {
			return out
		}
	}
	return append(out, Range{From: at, To: s.Through})
}

// Range is a time range [From, To).
type Range struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func stateID(model string) string { return kindState + ":" + model }

// state returns model's state, read from the runtime index once per
// lease.
func (b *Builder) state(ctx context.Context, model string) (*held, error) {
	if h, ok := b.states[model]; ok {
		return h, nil
	}
	raw, v, found, err := b.Client.Get(ctx, b.Runtime, stateID(model))
	if err != nil {
		return nil, err
	}
	h := &held{}
	if found {
		if json.Unmarshal(raw, &h.st) != nil {
			h.st = State{}
		}
		if h.st.Epoch > b.epoch {
			return nil, errStaleEpoch
		}
		h.v, h.ok = v, true
	}
	b.states[model] = h
	return h, nil
}

// save writes a state over the version read or written last; a newer
// jobs server's state is never written over. It does not wait for the
// write to be searchable: Coverage reads states every refreshEvery
// anyway, and until it does searches read more events, never fewer.
func (b *Builder) save(ctx context.Context, h *held) error {
	if !b.allowed() || b.epochNow() != b.epoch {
		return errStaleEpoch
	}
	h.st.Kind, h.st.Epoch, h.st.Node = kindState, b.epoch, b.Node
	id := stateID(h.st.Model)
	var nv store.Version
	var err error
	if h.ok {
		nv, err = b.Client.PutIf(ctx, b.Runtime, id, h.st, h.v, false)
	} else {
		nv, err = b.Client.Create(ctx, b.Runtime, id, h.st, false)
	}
	if err == nil {
		h.v, h.ok = nv, true
		return nil
	}
	if store.IsConflict(err) || errors.Is(err, store.ErrNotFound) {
		// Someone else wrote it: read it again next tick.
		delete(b.states, h.st.Model)
		raw, _, found, gerr := b.Client.Get(ctx, b.Runtime, id)
		if gerr == nil && found {
			var cur State
			if json.Unmarshal(raw, &cur) == nil && cur.Epoch > b.epoch {
				return errStaleEpoch
			}
		}
	}
	return err
}

// States reads every model's state.
func States(ctx context.Context, c interface {
	SearchDocs(ctx context.Context, index string, query map[string]any) ([]store.Doc, error)
}, runtime string) (map[string]State, error) {
	docs, err := c.SearchDocs(ctx, runtime, map[string]any{"term": map[string]any{"kind": kindState}})
	if err != nil {
		return nil, err
	}
	out := map[string]State{}
	for _, d := range docs {
		var s State
		if json.Unmarshal(d.Source, &s) == nil && s.Model != "" && s.Layout == layout(s.Model) {
			out[s.Model] = s
		}
	}
	return out, nil
}
