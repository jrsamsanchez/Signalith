package detect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// Stored is what a Backend keeps for one detection ID: a custom
// detection (or an override of a shipped one), the state chosen for a
// shipped one, or both, and who changed it last, where and when (for a
// backend that records it).
type Stored struct {
	Custom *Detection
	State  *State
	By     string
	Node   string
	At     string
}

// Backend keeps the custom detections and the state of the shipped ones
// in place of the detections folder: the shared settings of a cluster,
// so every server reads and changes the same ones. The Library keeps its
// own copy for reads, made again from Load whenever the backend says
// something changed.
type Backend interface {
	// Load returns every detection the backend keeps, by ID.
	Load() (map[string]Stored, error)
	// Change changes the detections ids, by the user by, one after
	// another: fn gets each as it is now (empty when there is none) and
	// returns it as it should be (empty removes it), or write false to
	// leave it. A detection another server changed in between is read
	// again and fn runs again. An error from fn stops the change; the
	// detections changed before it stay changed.
	Change(ctx context.Context, by string, ids []string, fn func(id string, cur Stored) (next Stored, write bool, err error)) error
	// OnChange adds a function called after anything changed, here or on
	// another server.
	OnChange(fn func())
}

// StaleError refuses a change to a detection that was changed since the
// page that asks for it read it: By changed it on server Node at At,
// when the library knows.
type StaleError struct {
	By   string
	Node string
	At   string
}

func (e *StaleError) Error() string {
	if e.By == "" {
		return "this was changed since you opened it; reload to see the change"
	}
	return fmt.Sprintf("%s changed this on %s at %s; reload to see the change", e.By, e.Node, e.At)
}

// ETag is the version of a detection's saved part: its custom copy and
// the state chosen for it, for If-Match. A shipped detection nobody
// changed has the ETag of nothing; a newer binary or content update that
// improves a rule does not change it.
func ETag(custom *Detection, st *State) string {
	h := sha256.New()
	if custom != nil {
		c := *custom
		c.Source = ""
		if data, err := Encode(&c); err == nil {
			h.Write(data)
		}
	}
	h.Write([]byte{0})
	if st != nil && !st.empty() {
		if data, err := yaml.Marshal(st); err == nil {
			h.Write(data)
		}
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// ETag returns the version of detection id (see the function ETag), ""
// for an unknown one.
func (l *Library) ETag(id string) string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	cust, st := l.custom[id], l.state[id]
	if cust == nil && l.shipped(id) == nil {
		return ""
	}
	return ETag(cust, st)
}

// ETags returns the version of every detection, by ID.
func (l *Library) ETags() map[string]string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make(map[string]string, len(l.builtin)+len(l.pack)+len(l.custom))
	empty := ETag(nil, nil)
	for id := range l.builtin {
		out[id] = empty
	}
	for id := range l.pack {
		out[id] = empty
	}
	for id, st := range l.state {
		if l.shipped(id) != nil {
			out[id] = ETag(nil, st)
		}
	}
	for id, c := range l.custom {
		out[id] = ETag(c, l.state[id])
	}
	return out
}

// UseBackend makes the library keep its custom detections and the state
// of the shipped ones in b rather than in Dir, from now on: what Dir
// holds is no longer read or written by the library.
func (l *Library) UseBackend(b Backend) error {
	l.mu.Lock()
	l.backend = b
	l.mu.Unlock()
	if err := l.load(b); err != nil {
		return err
	}
	b.OnChange(l.reload)
	return nil
}

// Shared reports whether the library keeps its detections in a backend.
func (l *Library) Shared() bool {
	return l.backendOf() != nil
}

// reload takes the backend's detections again, keeping the copy it has
// when they cannot be read.
func (l *Library) reload() {
	if b := l.backendOf(); b != nil {
		_ = l.load(b)
	}
}

func (l *Library) load(b Backend) error {
	items, err := b.Load()
	if err != nil {
		return err
	}
	custom := make(map[string]*Detection, len(items))
	state := make(map[string]*State, len(items))
	for id, it := range items {
		if it.Custom != nil {
			c := *it.Custom
			c.Source = ""
			custom[id] = &c
		}
		if it.State != nil && !it.State.empty() {
			state[id] = copyState(it.State)
		}
	}
	l.mu.Lock()
	l.custom, l.state, l.meta = custom, state, items
	l.mu.Unlock()
	return nil
}

// Changed returns who last changed detection id, on which server and
// when, for a backend that records it.
func (l *Library) Changed(id string) (by, node, at string) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	m := l.meta[id]
	return m.By, m.Node, m.At
}

func (l *Library) backendOf() Backend {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.backend
}

// ExceptionProblems lists what is wrong with a detection's exceptions,
// for a backend that checks the state it reads.
func ExceptionProblems(es []Exception) []string { return exceptionProblems(es) }

// DecodeState reads a shipped detection's state file, rejecting unknown
// keys; an empty file is an empty state.
func DecodeState(data []byte) (*State, error) {
	var st State
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&st); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return &st, nil
}

// EncodeState renders a shipped detection's state as its file holds it.
func EncodeState(st *State) ([]byte, error) { return yaml.Marshal(st) }
