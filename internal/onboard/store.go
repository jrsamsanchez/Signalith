package onboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/syslog"
)

// File keeps a server's custom parsers in its state folder.
const File = "custom-parsers.json"

// ErrNotFound is a parser that does not exist.
var ErrNotFound = errors.New("there is no custom parser of that name")

// Store keeps the saved parsers: a FileStore on a server of its own, or
// the shared settings of a cluster (internal/clusterparsers), so every
// server parses alike whichever one an agent sends to.
type Store interface {
	List() []Parser
	Get(name string) (Parser, bool)
	// Put saves a checked parser (Validate), new or not.
	Put(ctx context.Context, p Parser, by string) error
	Delete(ctx context.Context, name, by string) error
	// Gen changes whenever the parsers change, here or on another server.
	Gen() uint64
	// Err says why the parsers could not be read, if they could not.
	Err() error
}

// FileStore keeps parsers in a file. It is safe for concurrent use.
type FileStore struct {
	path string
	mu   sync.Mutex
	m    map[string]Parser
	err  error
	gen  atomic.Uint64
}

type parsersFile struct {
	Parsers []Parser `json:"parsers"`
}

// NewFileStore reads the parsers from path; "" keeps them in memory only.
// A missing file is no parsers.
func NewFileStore(path string) *FileStore {
	s := &FileStore{path: path, m: map[string]Parser{}}
	if path == "" {
		return s
	}
	ps, err := ReadFile(path)
	if err != nil {
		s.err = err
		return s
	}
	for _, p := range ps {
		s.m[p.Name] = p
	}
	return s
}

// ReadFile reads a parsers file; a missing one holds none. Parsers that no
// longer pass the checks are left out.
func ReadFile(path string) ([]Parser, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f parsersFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out := f.Parsers[:0]
	for _, p := range f.Parsers {
		if p.Validate() == nil {
			out = append(out, p)
		}
	}
	return out, nil
}

// WriteFile writes parsers as a server keeps them in its state folder.
func WriteFile(path string, ps []Parser) error {
	sort.Slice(ps, func(i, j int) bool { return ps[i].Name < ps[j].Name })
	b, err := json.MarshalIndent(parsersFile{Parsers: ps}, "", "  ")
	if err != nil {
		return err
	}
	return securefile.WriteFile(path, append(b, '\n'))
}

func (s *FileStore) List() []Parser {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Parser, 0, len(s.m))
	for _, p := range s.m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *FileStore) Get(name string) (Parser, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.m[name]
	return p, ok
}

func (s *FileStore) Gen() uint64 { return s.gen.Load() }

func (s *FileStore) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *FileStore) Put(_ context.Context, p Parser, by string) error {
	return s.change(func(m map[string]Parser) error {
		if _, ok := m[p.Name]; !ok && len(m) >= MaxParsers {
			return &InputError{fmt.Sprintf("There are %d custom parsers already, the most Signalith keeps.", MaxParsers)}
		}
		p.UpdatedBy, p.UpdatedAt = by, time.Now().UTC().Truncate(time.Second)
		m[p.Name] = p
		return nil
	})
}

func (s *FileStore) Delete(_ context.Context, name, _ string) error {
	return s.change(func(m map[string]Parser) error {
		if _, ok := m[name]; !ok {
			return ErrNotFound
		}
		delete(m, name)
		return nil
	})
}

func (s *FileStore) change(fn func(map[string]Parser) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return fmt.Errorf("the custom parsers file could not be read, so it is not changed: %w", s.err)
	}
	next := make(map[string]Parser, len(s.m)+1)
	for k, v := range s.m {
		next[k] = v
	}
	if err := fn(next); err != nil {
		return err
	}
	if s.path != "" {
		ps := make([]Parser, 0, len(next))
		for _, p := range next {
			ps = append(ps, p)
		}
		if err := WriteFile(s.path, ps); err != nil {
			return err
		}
	}
	s.m = next
	s.gen.Add(1)
	return nil
}

// Registry runs the saved parsers on what arrives: it is the pipeline's
// ingest.CustomParsers, and handles syslog messages (Syslog). It keeps the
// parsers compiled, and compiles them again when the store changes.
type Registry struct {
	store Store
	mu    sync.Mutex
	snap  atomic.Pointer[snapshot]
}

type snapshot struct {
	gen    uint64
	byName map[string]*Compiled
	byApp  map[string]*Compiled
}

// NewRegistry returns the registry of the parsers in store.
func NewRegistry(store Store) *Registry { return &Registry{store: store} }

// Store is where the parsers are kept.
func (r *Registry) Store() Store { return r.store }

func (r *Registry) current() *snapshot {
	g := r.store.Gen()
	if s := r.snap.Load(); s != nil && s.gen == g {
		return s
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s := r.snap.Load(); s != nil && s.gen == g {
		return s
	}
	s := &snapshot{gen: g, byName: map[string]*Compiled{}, byApp: map[string]*Compiled{}}
	for _, p := range r.store.List() {
		c, err := Compile(p)
		if err != nil {
			continue
		}
		s.byName[p.Name] = c
		for _, a := range p.SyslogApps {
			if _, taken := s.byApp[a]; !taken {
				s.byApp[a] = c
			}
		}
	}
	r.snap.Store(s)
	return s
}

// ParseCustom is ingest.CustomParsers.
func (r *Registry) ParseCustom(name string, rec map[string]any, now time.Time) (ingest.Event, bool, bool) {
	c := r.current().byName[name]
	if c == nil {
		return ingest.Event{}, false, false
	}
	ev, drop := c.ParseRecord(rec, now)
	return ev, drop, true
}

// syslogKept are the fields of a syslog event that the receiver set from
// the header and the connection: a parser's fields never replace them.
var syslogKept = map[string]bool{"host": true, "dvc": true, "facility": true, "severity": true, "severity_id": true,
	"app": true, "process_id": true, "message": true}

// Syslog applies the parser that names a syslog message's program to the
// message's text. It keeps what the receiver set from the header and the
// connection (syslogKept), and the event time unless the line has a
// usable one. Messages a built-in parser read (sshd, sudo, firewalls and
// so on: any but plain syslog in Other) are left as they are, so a parser
// cannot turn sign-ins into something the detections for them miss.
func (r *Registry) Syslog(m *syslog.Message, ev *ingest.Event) {
	if m.AppName == "" || m.CEF != nil || m.LEEF != nil || ev.Model != "Other" || ev.Fields["sourcetype"] != "syslog" {
		return
	}
	s := r.current()
	if len(s.byApp) == 0 {
		return
	}
	c := s.byApp[m.AppName]
	if c == nil {
		return
	}
	switch c.P.Format {
	case FormatCEF, FormatLEEF:
		return
	}
	text := m.Text
	if len(text) > MaxLine {
		text = text[:MaxLine]
	}
	fields, ok := c.parseBody(text)
	if !ok {
		return
	}
	parsed := c.finish(fields, m.Raw, time.Time{}, "", "", ev.Time)
	// What the line says wins, but for what the receiver set.
	for k, v := range ev.Fields {
		if _, set := parsed.Fields[k]; !set || syslogKept[k] {
			parsed.Fields[k] = v
		}
	}
	ev.Fields = parsed.Fields
	ev.Model = parsed.Model
	if !parsed.Time.IsZero() && ingest.TimeUsable(parsed.Time, ev.Time, 0) {
		ev.Time = parsed.Time
	}
}
