// Package dashboards holds the built-in security posture summary and the
// custom dashboards users build from Signalith queries, like the Splunk ES
// Security Posture and executive summary dashboards.
//
// A custom dashboard is a YAML file in the dashboards folder, so it can be
// edited by hand and kept in Git. Each panel is a query plus a
// visualization; panels run through the search engine like any search.
package dashboards

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/query"
)

// PostureID is the ID of the built-in posture dashboard. Custom dashboards
// cannot use it.
const PostureID = "posture"

// Visualizations a panel can use.
const (
	VizSingle = "single" // one number, optionally compared with the previous period
	VizTable  = "table"
	VizBar    = "bar"  // horizontal bars, one per row
	VizLine   = "line" // series over time, from timechart
	VizArea   = "area" // like line, filled
)

// Vizs lists valid visualizations.
var Vizs = []string{VizSingle, VizTable, VizBar, VizLine, VizArea}

// Widths lists valid panel widths.
var Widths = []string{"third", "half", "full"}

// MaxPanels caps the panels on one dashboard.
const MaxPanels = 40

// Dashboard is one custom dashboard.
type Dashboard struct {
	ID          string `yaml:"id" json:"id"`
	Title       string `yaml:"title" json:"title"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// TimeRange is how far back panels search unless their query sets
	// earliest=: 15m, 4h, 24h, 7d, 30d.
	TimeRange string `yaml:"time_range,omitempty" json:"time_range,omitempty"`
	// Refresh reloads the dashboard on this interval in the browser; empty
	// is off.
	Refresh string  `yaml:"refresh,omitempty" json:"refresh,omitempty"`
	Panels  []Panel `yaml:"panels" json:"panels"`
}

// Panel is a query and how to show its result.
type Panel struct {
	Title string `yaml:"title" json:"title"`
	Query string `yaml:"query" json:"query"`
	Viz   string `yaml:"viz" json:"viz"`
	// Width is third, half or full.
	Width string `yaml:"width,omitempty" json:"width,omitempty"`
	// Field is the column a single value shows (default: the first number).
	Field string `yaml:"field,omitempty" json:"field,omitempty"`
	// Compare shows a single value's change from the previous period.
	Compare bool `yaml:"compare,omitempty" json:"compare,omitempty"`
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,63}$`)

// Defaults fills empty optional fields.
func (d *Dashboard) Defaults() {
	d.ID = strings.TrimSpace(d.ID)
	d.Title = strings.TrimSpace(d.Title)
	if d.TimeRange == "" {
		d.TimeRange = "24h"
	}
	d.TimeRange = strings.TrimPrefix(strings.TrimSpace(d.TimeRange), "-")
	if d.Panels == nil {
		d.Panels = []Panel{}
	}
	for i := range d.Panels {
		p := &d.Panels[i]
		p.Title = strings.TrimSpace(p.Title)
		p.Query = strings.TrimSpace(p.Query)
		p.Viz = strings.ToLower(strings.TrimSpace(p.Viz))
		if p.Viz == "" {
			p.Viz = SuggestViz(p.Query)
		}
		if p.Width == "" {
			switch p.Viz {
			case VizSingle:
				p.Width = "third"
			case VizLine, VizArea:
				p.Width = "full"
			default:
				p.Width = "half"
			}
		}
	}
}

// ValidationError lists every problem in a dashboard.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid dashboard:\n  - " + strings.Join(e.Problems, "\n  - ")
}

// Validate checks every field and returns all problems at once. The IDs
// of the built-in dashboards are refused, so a custom dashboard can never
// replace one.
func (d *Dashboard) Validate() error {
	var reserved string
	switch {
	case d.ID == PostureID:
		reserved = `id "posture" is the built-in dashboard; choose another`
	case IsBuiltin(d.ID):
		reserved = fmt.Sprintf("id %q is a built-in dashboard; choose another", d.ID)
	}
	err := d.check()
	if reserved == "" {
		return err
	}
	var ve *ValidationError
	if errors.As(err, &ve) {
		ve.Problems = append([]string{reserved}, ve.Problems...)
		return ve
	}
	return &ValidationError{Problems: []string{reserved}}
}

// check validates everything except the reserved IDs; the built-in
// dashboards themselves pass it.
func (d *Dashboard) check() error {
	var p []string
	if !idPattern.MatchString(d.ID) {
		p = append(p, fmt.Sprintf("id %q must be 3-64 lowercase letters, digits, - or _", d.ID))
	}
	if d.Title == "" {
		p = append(p, "title is required")
	} else if len(d.Title) > 200 {
		p = append(p, "title must be 200 characters or fewer")
	}
	if r, err := detect.ParseDuration(d.TimeRange); err != nil {
		p = append(p, "time_range: "+err.Error())
	} else if r < time.Minute || r > 366*24*time.Hour {
		p = append(p, "time_range must be between 1m and 366d")
	}
	if d.Refresh != "" {
		if r, err := detect.ParseDuration(d.Refresh); err != nil {
			p = append(p, "refresh: "+err.Error())
		} else if r < 30*time.Second {
			p = append(p, "refresh must be at least 30s, or empty for off")
		}
	}
	if len(d.Panels) > MaxPanels {
		p = append(p, fmt.Sprintf("a dashboard can have at most %d panels", MaxPanels))
	}
	for i, pn := range d.Panels {
		name := fmt.Sprintf("panel %d", i+1)
		if pn.Title != "" {
			name += fmt.Sprintf(" (%s)", pn.Title)
		}
		if pn.Title == "" {
			p = append(p, name+": title is required")
		}
		if pn.Query == "" {
			p = append(p, name+": query is required")
		} else if _, err := query.Parse(pn.Query); err != nil {
			p = append(p, name+": query: "+queryErr(err))
		}
		if !slices.Contains(Vizs, pn.Viz) {
			p = append(p, fmt.Sprintf("%s: viz %q must be one of %s", name, pn.Viz, strings.Join(Vizs, ", ")))
		}
		if !slices.Contains(Widths, pn.Width) {
			p = append(p, fmt.Sprintf("%s: width %q must be one of %s", name, pn.Width, strings.Join(Widths, ", ")))
		}
		if pn.Compare && pn.Viz != VizSingle {
			p = append(p, name+": compare only applies to single values")
		}
	}
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

func queryErr(err error) string {
	var qe *query.Error
	if errors.As(err, &qe) {
		return fmt.Sprintf("%s (at character %d)", qe.Msg, qe.Pos+1)
	}
	return err.Error()
}

// SuggestViz picks a visualization from the shape of a query: timechart
// becomes a line, a stats with no "by" a single value, other stats and top
// a bar chart, and anything else a table.
func SuggestViz(src string) string {
	q, err := query.Parse(src)
	if err != nil || len(q.Commands) == 0 {
		return VizTable
	}
	viz := VizTable
	for _, c := range q.Commands {
		switch c := c.(type) {
		case *query.Timechart:
			return VizLine
		case *query.Stats:
			if len(c.By) == 0 {
				viz = VizSingle
			} else {
				viz = VizBar
			}
		case *query.Top:
			viz = VizBar
		case *query.Table:
			viz = VizTable
		}
	}
	return viz
}

// Decode reads a dashboard from YAML, rejecting unknown keys.
func Decode(data []byte) (*Dashboard, error) {
	var d Dashboard
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return nil, err
	}
	d.Defaults()
	return &d, nil
}

// Encode renders a dashboard as YAML. Queries are written as block text
// so multi-line queries stay readable in Git diffs.
func Encode(d *Dashboard) ([]byte, error) {
	var node yaml.Node
	if err := node.Encode(d); err != nil {
		return nil, err
	}
	literalQueries(&node)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&node); err != nil {
		return nil, err
	}
	return buf.Bytes(), enc.Close()
}

func literalQueries(n *yaml.Node) {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Value == "query" && v.Kind == yaml.ScalarNode && strings.Contains(v.Value, "\n") {
				v.Style = yaml.LiteralStyle
			}
		}
	}
	for _, c := range n.Content {
		literalQueries(c)
	}
}

// Store keeps custom dashboards as <id>.yaml files in Dir. Files are read
// on every call, so dashboards added or changed on disk (for example by a
// git pull) show up without a restart. With a backend (UseBackend), the
// dashboards are kept there instead, such as in the shared settings of a
// cluster, and Dir is not read or written.
type Store struct {
	Dir     string
	mu      sync.Mutex
	backend Backend
}

// Stored is a dashboard as a Backend keeps it, with who changed it last,
// on which server and when (for a backend that records it).
type Stored struct {
	Dashboard *Dashboard
	By        string
	Node      string
	At        string
}

// Backend keeps the custom dashboards in place of the dashboards folder.
type Backend interface {
	// List returns every dashboard.
	List() ([]Stored, error)
	// Get returns the dashboard id.
	Get(id string) (Stored, bool)
	// Change changes the dashboard id, by the user by: fn gets it as it
	// is now (nil when there is none) and returns it as it should be (nil
	// deletes it). A dashboard another server changed in between is read
	// again and fn runs again. An error from fn changes nothing.
	Change(ctx context.Context, by, id string, fn func(cur *Stored) (*Dashboard, error)) error
}

// ErrNotFound is returned for unknown dashboard IDs.
var ErrNotFound = errors.New("dashboard not found")

// ErrExists is returned when creating a dashboard whose ID is taken.
var ErrExists = errors.New("a dashboard with that id already exists")

// NewStore returns a store for dir. The folder is created on the first
// save.
func NewStore(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("dashboards.dir is not set")
	}
	return &Store{Dir: dir}, nil
}

// UseBackend makes the store keep its dashboards in b rather than in Dir
// from now on.
func (s *Store) UseBackend(b Backend) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.backend = b
}

func (s *Store) backendOf() Backend {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backend
}

// Shared reports whether the store keeps its dashboards in a backend.
func (s *Store) Shared() bool { return s.backendOf() != nil }

// ETag is the version of a saved dashboard, for If-Match; "" for none.
func ETag(d *Dashboard) string {
	if d == nil {
		return ""
	}
	data, err := Encode(d)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}

// Problem is a dashboard file that could not be loaded.
type Problem struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

// List returns every valid dashboard sorted by title, and a problem for
// each file that is not valid.
func (s *Store) List() ([]*Dashboard, []Problem, error) {
	out := []*Dashboard{}
	var problems []Problem
	if b := s.backendOf(); b != nil {
		items, err := b.List()
		if err != nil {
			return nil, nil, err
		}
		for _, it := range items {
			out = append(out, it.Dashboard)
		}
	} else {
		s.mu.Lock()
		files, err := filepath.Glob(filepath.Join(s.Dir, "*.yaml"))
		if err != nil {
			s.mu.Unlock()
			return nil, nil, err
		}
		for _, f := range files {
			if id := strings.TrimSuffix(filepath.Base(f), ".yaml"); IsBuiltin(id) {
				problems = append(problems, Problem{File: filepath.Base(f), Error: fmt.Sprintf(
					"%s.yaml uses the id of the built-in %s dashboard and is ignored. Rename the file and change its id to keep it.", id, builtinTitle(id))})
				continue
			}
			d, err := s.load(f)
			if err != nil {
				problems = append(problems, Problem{File: filepath.Base(f), Error: err.Error()})
				continue
			}
			out = append(out, d)
		}
		s.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := strings.ToLower(out[i].Title), strings.ToLower(out[j].Title); a != b {
			return a < b
		}
		return out[i].ID < out[j].ID
	})
	return out, problems, nil
}

func (s *Store) load(file string) (*Dashboard, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return DecodeFile(filepath.Base(file), data)
}

// DecodeFile reads the dashboard file name holds: it must be valid and
// its id must match the file name.
func DecodeFile(name string, data []byte) (*Dashboard, error) {
	d, err := Decode(data)
	if err != nil {
		return nil, err
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if d.ID+".yaml" != name {
		return nil, fmt.Errorf("id %q does not match the file name", d.ID)
	}
	return d, nil
}

func (s *Store) file(id string) (string, error) {
	if !idPattern.MatchString(id) {
		return "", ErrNotFound
	}
	return filepath.Join(s.Dir, id+".yaml"), nil
}

// Get returns one dashboard. A file with errors returns them.
func (s *Store) Get(id string) (*Dashboard, error) {
	d, _, err := s.GetETag(id)
	return d, err
}

// GetETag returns one dashboard and its version, for If-Match.
func (s *Store) GetETag(id string) (*Dashboard, string, error) {
	if b := s.backendOf(); b != nil {
		it, ok := b.Get(id)
		if !ok {
			return nil, "", ErrNotFound
		}
		return it.Dashboard, ETag(it.Dashboard), nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.file(id)
	if err != nil {
		return nil, "", err
	}
	d, err := s.load(f)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", err
	}
	return d, ETag(d), nil
}

// Exists reports whether a dashboard for id exists, valid or not.
func (s *Store) Exists(id string) bool {
	if b := s.backendOf(); b != nil {
		_, ok := b.Get(id)
		return ok
	}
	f, err := s.file(id)
	if err != nil {
		return false
	}
	_, err = os.Stat(f)
	return err == nil
}

// Put validates and saves a dashboard.
func (s *Store) Put(d *Dashboard) error {
	return s.PutIf(context.Background(), "", d, "")
}

// PutIf saves a dashboard by the user by, for a page that read it at etag
// ("" saves over any version): one changed since gives a
// *detect.StaleError.
func (s *Store) PutIf(ctx context.Context, by string, d *Dashboard, etag string) error {
	c, err := prepare(d)
	if err != nil {
		return err
	}
	if err := s.change(ctx, by, c.ID, func(cur *Stored) (*Dashboard, error) {
		if etag != "" && (cur == nil || ETag(cur.Dashboard) != etag) {
			return nil, staleOf(cur)
		}
		return c, nil
	}); err != nil {
		return err
	}
	*d = *c
	return nil
}

// Create saves a new dashboard: ErrExists when its id is taken.
func (s *Store) Create(ctx context.Context, by string, d *Dashboard) error {
	c, err := prepare(d)
	if err != nil {
		return err
	}
	if err := s.change(ctx, by, c.ID, func(cur *Stored) (*Dashboard, error) {
		if cur != nil {
			return nil, ErrExists
		}
		return c, nil
	}); err != nil {
		return err
	}
	*d = *c
	return nil
}

// Update changes the dashboard id with fn, for a page that read it at
// etag ("" for any version), and returns it as saved.
func (s *Store) Update(ctx context.Context, by, id, etag string, fn func(*Dashboard) error) (*Dashboard, error) {
	var saved *Dashboard
	err := s.change(ctx, by, id, func(cur *Stored) (*Dashboard, error) {
		if cur == nil {
			return nil, ErrNotFound
		}
		if etag != "" && ETag(cur.Dashboard) != etag {
			return nil, staleOf(cur)
		}
		c := *cur.Dashboard
		c.Panels = slices.Clone(c.Panels)
		if err := fn(&c); err != nil {
			return nil, err
		}
		c.ID = id
		next, err := prepare(&c)
		saved = next
		return next, err
	})
	return saved, err
}

// prepare returns a copy of d with its defaults filled in, once it is
// valid.
func prepare(d *Dashboard) (*Dashboard, error) {
	c := *d
	c.Panels = append([]Panel(nil), d.Panels...)
	c.Defaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func staleOf(cur *Stored) error {
	if cur == nil {
		return &detect.StaleError{}
	}
	return &detect.StaleError{By: cur.By, Node: cur.Node, At: cur.At}
}

// Delete removes a dashboard.
func (s *Store) Delete(id string) error {
	return s.DeleteIf(context.Background(), "", id, "")
}

// DeleteIf removes a dashboard by the user by, for a page that read it at
// etag ("" for any version).
func (s *Store) DeleteIf(ctx context.Context, by, id, etag string) error {
	if !idPattern.MatchString(id) {
		return ErrNotFound
	}
	return s.change(ctx, by, id, func(cur *Stored) (*Dashboard, error) {
		if cur == nil {
			return nil, ErrNotFound
		}
		if etag != "" && ETag(cur.Dashboard) != etag {
			return nil, staleOf(cur)
		}
		return nil, nil
	})
}

// change makes the change fn says to the dashboard id: in the backend, or
// in its file while s.mu is held. A file that is not valid counts as a
// dashboard with no version, so a page can save over it.
func (s *Store) change(ctx context.Context, by, id string, fn func(cur *Stored) (*Dashboard, error)) error {
	if b := s.backendOf(); b != nil {
		return b.Change(ctx, by, id, fn)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.file(id)
	if err != nil {
		return err
	}
	var cur *Stored
	if d, err := s.load(f); err == nil {
		cur = &Stored{Dashboard: d}
	} else if !errors.Is(err, os.ErrNotExist) {
		cur = &Stored{Dashboard: &Dashboard{ID: id}}
	}
	next, err := fn(cur)
	if err != nil {
		return err
	}
	if next == nil {
		if err := os.Remove(f); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return ErrNotFound
			}
			return err
		}
		return nil
	}
	data, err := Encode(next)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o750); err != nil {
		return err
	}
	return writeFileAtomic(f, data)
}

// NewID derives a free dashboard ID from a title.
func (s *Store) NewID(title string) string {
	base := strings.Trim(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(title), "-"), "-")
	if len(base) > 50 {
		base = strings.Trim(base[:50], "-")
	}
	if len(base) < 3 {
		base = "dashboard"
	}
	if base == PostureID {
		base = "my-posture"
	}
	id := base
	for n := 2; s.Exists(id) || IsBuiltin(id); n++ {
		id = fmt.Sprintf("%s-%d", base, n)
	}
	return id
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
