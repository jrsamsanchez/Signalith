package detect

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// Library holds the built-in detections, the content packs' detections
// and the custom ones in Dir.
//
// Turning a built-in or pack detection on or off without changing it
// saves only that choice, in Dir/state/<id>.yaml, not a copy of the rule:
// the rule itself still comes from the binary, so a newer Signalith (or
// content update) improves it without losing the choice.
type Library struct {
	Dir string // where custom detections are saved; "" keeps them in memory only

	mu      sync.RWMutex
	builtin map[string]*Detection
	pack    map[string]*Detection
	custom  map[string]*Detection
	state   map[string]*State
}

// State is what an admin chose for a built-in or pack detection without
// editing it.
type State struct {
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// Exceptions tune the detection (see Exception).
	Exceptions []Exception `yaml:"exceptions,omitempty" json:"exceptions,omitempty"`
}

func (st *State) empty() bool { return st.Enabled == nil && len(st.Exceptions) == 0 }

// StateDir is the folder under the detections folder that holds State
// files.
const StateDir = "state"

// ErrNotFound is returned for unknown detection IDs.
var ErrNotFound = errors.New("detection not found")

// Decode reads one detection from YAML, rejecting unknown keys.
func Decode(data []byte) (*Detection, error) {
	var d Detection
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return nil, err
	}
	d.Defaults()
	return &d, nil
}

// Encode renders a detection as YAML.
func Encode(d *Detection) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return buf.Bytes(), enc.Close()
}

// Builtin returns the detections shipped in the binary.
func Builtin() ([]*Detection, error) {
	files, err := fs.Glob(builtinFS, "builtin/*.yaml")
	if err != nil {
		return nil, err
	}
	var out []*Detection
	for _, f := range files {
		data, err := builtinFS.ReadFile(f)
		if err != nil {
			return nil, err
		}
		d, err := Decode(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if err := d.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if d.ID+".yaml" != path.Base(f) {
			return nil, fmt.Errorf("%s: id %q does not match the file name", f, d.ID)
		}
		d.Source = "builtin"
		out = append(out, d)
	}
	return out, nil
}

// NewLibrary loads built-in detections and every *.yaml file in dir.
// Invalid custom files are reported in the returned problems but do not
// stop the others from loading.
func NewLibrary(dir string) (*Library, []error, error) {
	l := &Library{Dir: dir, builtin: map[string]*Detection{}, pack: map[string]*Detection{},
		custom: map[string]*Detection{}, state: map[string]*State{}}
	bs, err := Builtin()
	if err != nil {
		return nil, nil, err
	}
	for _, d := range bs {
		l.builtin[d.ID] = d
	}
	_, pds, err := Packs()
	if err != nil {
		return nil, nil, err
	}
	for _, d := range pds {
		if _, dup := l.builtin[d.ID]; dup {
			return nil, nil, fmt.Errorf("pack detection %s has a built-in's id", d.ID)
		}
		l.pack[d.ID] = d
	}
	if dir == "" {
		return l, nil, nil
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, nil, err
	}
	var problems []error
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		d, err := Decode(data)
		if err == nil {
			err = d.Validate()
		}
		if err == nil && d.ID+".yaml" != filepath.Base(f) {
			err = fmt.Errorf("id %q does not match the file name", d.ID)
		}
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", f, err))
			continue
		}
		l.custom[d.ID] = d
	}
	states, err := filepath.Glob(filepath.Join(dir, StateDir, "*.yaml"))
	if err != nil {
		return nil, nil, err
	}
	for _, f := range states {
		id := strings.TrimSuffix(filepath.Base(f), ".yaml")
		data, err := os.ReadFile(f)
		var st State
		if err == nil {
			dec := yaml.NewDecoder(bytes.NewReader(data))
			dec.KnownFields(true)
			if err = dec.Decode(&st); err != nil && errors.Is(err, io.EOF) {
				err = nil
			}
		}
		if err == nil && l.builtin[id] == nil && l.pack[id] == nil {
			err = fmt.Errorf("no built-in or pack detection has id %q", id)
		}
		if p := exceptionProblems(st.Exceptions); err == nil && len(p) > 0 {
			err = &ValidationError{ID: id, Problems: p}
		}
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", f, err))
			continue
		}
		l.state[id] = &st
	}
	return l, problems, nil
}

// shipped returns the built-in or pack detection with an id, or nil.
func (l *Library) shipped(id string) *Detection {
	if d, ok := l.builtin[id]; ok {
		return d
	}
	return l.pack[id]
}

func (l *Library) resolve(id string) *Detection {
	if d, ok := l.custom[id]; ok {
		c := *d
		c.Source = "custom"
		if l.shipped(id) != nil {
			c.Source = "override"
		}
		return &c
	}
	if d := l.shipped(id); d != nil {
		c := *d
		c.Source = "builtin"
		if _, ok := l.pack[id]; ok {
			c.Source = "pack"
		}
		if st := l.state[id]; st != nil {
			if st.Enabled != nil {
				c.Enabled = *st.Enabled
			}
			c.Exceptions = st.Exceptions
		}
		return &c
	}
	return nil
}

// List returns every detection, sorted by ID.
func (l *Library) List() []*Detection {
	l.mu.RLock()
	defer l.mu.RUnlock()
	ids := map[string]bool{}
	for id := range l.builtin {
		ids[id] = true
	}
	for id := range l.pack {
		ids[id] = true
	}
	for id := range l.custom {
		ids[id] = true
	}
	out := make([]*Detection, 0, len(ids))
	for id := range ids {
		out = append(out, l.resolve(id))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns one detection.
func (l *Library) Get(id string) (*Detection, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if d := l.resolve(id); d != nil {
		return d, nil
	}
	return nil, ErrNotFound
}

// Put validates and saves a detection. Saving a built-in's or pack
// detection's ID creates an override, and the shipped one comes back
// when the override is deleted; but saving it unchanged apart from being
// on or off only records that choice (see State).
func (l *Library) Put(d *Detection) error {
	c := *d
	c.Source = ""
	c.Defaults()
	if err := c.Validate(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if base := l.shipped(c.ID); base != nil && l.custom[c.ID] == nil && sameApartFromTuning(base, &c) {
		st := l.stateCopy(c.ID)
		st.Exceptions = c.Exceptions
		st.Enabled = nil
		if c.Enabled != base.Enabled {
			st.Enabled = &c.Enabled
		}
		return l.writeState(c.ID, st)
	}
	return l.saveCustom(&c)
}

// sameApartFromTuning reports whether d is the shipped detection apart
// from being on or off and its exceptions, which State records.
func sameApartFromTuning(base, d *Detection) bool {
	a, b := *base, *d
	a.Source, b.Source = "", ""
	a.Enabled, b.Enabled = false, false
	a.Exceptions, b.Exceptions = nil, nil
	ya, err1 := Encode(&a)
	yb, err2 := Encode(&b)
	return err1 == nil && err2 == nil && bytes.Equal(ya, yb)
}

// SetEnabled turns detections on or off. A custom detection or override
// is saved with the change; a built-in or pack detection records only the
// choice. It stops at the first unknown ID, changing none.
func (l *Library) SetEnabled(ids []string, on bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, id := range ids {
		if l.custom[id] == nil && l.shipped(id) == nil {
			return fmt.Errorf("%w: %s", ErrNotFound, id)
		}
	}
	for _, id := range ids {
		if d := l.custom[id]; d != nil {
			if d.Enabled == on {
				continue
			}
			c := *d
			c.Enabled = on
			if err := l.saveCustom(&c); err != nil {
				return err
			}
			continue
		}
		if err := l.setEnabled(id, on); err != nil {
			return err
		}
	}
	return nil
}

// UpdateExceptions changes a detection's exceptions with fn, which gets a
// copy of the current ones, and saves the result: in the detection's file
// for a custom detection or override, and as State for a built-in or pack
// detection. It returns the detection as saved.
func (l *Library) UpdateExceptions(id string, fn func([]Exception) ([]Exception, error)) (*Detection, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cur := l.resolve(id)
	if cur == nil {
		return nil, ErrNotFound
	}
	next, err := fn(slices.Clone(cur.Exceptions))
	if err != nil {
		return nil, err
	}
	if p := exceptionProblems(next); len(p) > 0 {
		return nil, &ValidationError{ID: id, Problems: p}
	}
	if d := l.custom[id]; d != nil {
		c := *d
		c.Exceptions = next
		if err := l.saveCustom(&c); err != nil {
			return nil, err
		}
	} else {
		st := l.stateCopy(id)
		st.Exceptions = next
		if err := l.writeState(id, st); err != nil {
			return nil, err
		}
	}
	return l.resolve(id), nil
}

// setEnabled records the on or off choice for a shipped detection; a
// choice equal to the shipped default removes the record. l.mu is held.
func (l *Library) setEnabled(id string, on bool) error {
	base := l.shipped(id)
	st := l.stateCopy(id)
	if on == base.Enabled {
		st.Enabled = nil
	} else {
		st.Enabled = &on
	}
	return l.writeState(id, st)
}

// stateCopy returns a copy of a shipped detection's state to change; l.mu
// is held.
func (l *Library) stateCopy(id string) *State {
	st := &State{}
	if prev := l.state[id]; prev != nil {
		*st = *prev
		st.Exceptions = slices.Clone(prev.Exceptions)
	}
	return st
}

// writeState saves a shipped detection's state, removing the file when it
// holds nothing; l.mu is held.
func (l *Library) writeState(id string, st *State) error {
	empty := st.empty()
	if l.Dir != "" {
		name := filepath.Join(l.Dir, StateDir, id+".yaml")
		if empty {
			if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		} else {
			data, err := yaml.Marshal(st)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(name), 0o750); err != nil {
				return err
			}
			if err := writeFileAtomic(name, data); err != nil {
				return err
			}
		}
	}
	if empty {
		delete(l.state, id)
	} else {
		l.state[id] = st
	}
	return nil
}

// saveCustom writes a custom detection; l.mu is held.
func (l *Library) saveCustom(c *Detection) error {
	if l.Dir != "" {
		data, err := Encode(c)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(l.Dir, 0o750); err != nil {
			return err
		}
		if err := writeFileAtomic(filepath.Join(l.Dir, c.ID+".yaml"), data); err != nil {
			return err
		}
	}
	l.custom[c.ID] = c
	return nil
}

// Delete removes a custom detection or reverts an override to the
// built-in. Built-ins cannot be deleted; disable them instead.
func (l *Library) Delete(id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.custom[id]; !ok {
		if _, ok := l.builtin[id]; ok {
			return errors.New("built-in detections cannot be deleted; disable it instead")
		}
		if _, ok := l.pack[id]; ok {
			return errors.New("content pack detections cannot be deleted; disable it instead")
		}
		return ErrNotFound
	}
	if l.Dir != "" {
		if err := os.Remove(filepath.Join(l.Dir, id+".yaml")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	delete(l.custom, id)
	return nil
}

func writeFileAtomic(name string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(name), ".tmp-"+strings.TrimSuffix(filepath.Base(name), ".yaml")+"-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), name)
}
