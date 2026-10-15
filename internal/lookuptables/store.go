// Package lookuptables keeps the CSV tables the search command lookup
// reads: an admin uploads a table on Settings > Lookups, and a search adds
// its columns to events whose field matches a key column, as in
//
//   - | lookup service_owners host OUTPUT owner, team
package lookuptables

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// Limits on what the tables may hold, so a few uploads cannot fill the
// server's memory: every table is kept in memory for searches.
const (
	MaxTableBytes = 16 << 20
	MaxTotalBytes = 256 << 20
	MaxTables     = 200
	MaxRows       = 1_000_000
	MaxColumns    = 100
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ValidName reports whether name can name a table: lower-case letters,
// digits, - and _, up to 64 characters.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// ErrNotFound is returned for a table that does not exist.
var ErrNotFound = errors.New("no lookup table by that name")

// Table is one table: its header and rows, as uploaded.
type Table struct {
	Name    string
	Columns []string
	Rows    [][]string
	Bytes   int
	Updated time.Time
}

// Info describes a table without its rows.
type Info struct {
	Name    string    `json:"name"`
	Columns []string  `json:"columns"`
	Rows    int       `json:"rows"`
	Bytes   int       `json:"bytes"`
	Updated time.Time `json:"updated"`
}

// Info returns t's description.
func (t *Table) Info() Info {
	return Info{Name: t.Name, Columns: t.Columns, Rows: len(t.Rows), Bytes: t.Bytes, Updated: t.Updated}
}

// Column returns the index of the named column, or -1.
func (t *Table) Column(name string) int { return slices.Index(t.Columns, name) }

// Index maps a key, the values of the key columns joined by keySep, to
// the rows that hold it.
type Index map[string][]int

// keySep joins the values of several key columns; it cannot appear in a
// value read from CSV.
const keySep = "\x00"

// Key joins the values of several key columns into an Index key.
func Key(values []string) string { return strings.Join(values, keySep) }

// Store holds the tables, read from files in one folder.
type Store struct {
	dir string

	mu      sync.RWMutex
	tables  map[string]*Table
	indexes map[string]Index // by table name and key columns
}

// Open reads the tables in dir, which is created when missing. A file that
// does not read is skipped and reported in the returned error, so one bad
// file never hides the rest.
func Open(dir string) (*Store, error) {
	s := &Store{dir: dir, tables: map[string]*Table{}, indexes: map[string]Index{}}
	if dir == "" {
		return s, nil
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	var errs []error
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".csv")
		if !ok || e.IsDir() || !ValidName(name) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		t, err := Parse(name, data)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			continue
		}
		if fi, err := e.Info(); err == nil {
			t.Updated = fi.ModTime().UTC()
		}
		s.tables[name] = t
	}
	return s, errors.Join(errs...)
}

// ParseError lists the lines of an upload that do not read.
type ParseError struct{ Msg string }

func (e *ParseError) Error() string { return e.Msg }

func parseErr(format string, args ...any) error {
	return &ParseError{Msg: fmt.Sprintf(format, args...)}
}

// Parse reads a table from CSV with a header row. Column names are kept as
// written, without surrounding spaces, and must be distinct; rows with
// fewer cells than the header are padded, and rows with more are refused.
func Parse(name string, data []byte) (*Table, error) {
	if len(data) > MaxTableBytes {
		return nil, parseErr("the file is %d MB; a lookup table can be up to %d MB", len(data)>>20, MaxTableBytes>>20)
	}
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(data, []byte("\ufeff"))))
	r.FieldsPerRecord = -1
	r.ReuseRecord = false
	header, err := r.Read()
	if errors.Is(err, io.EOF) {
		return nil, parseErr("the file is empty; the first line names the columns")
	}
	if err != nil {
		return nil, parseErr("%v", err)
	}
	if len(header) > MaxColumns {
		return nil, parseErr("the file has %d columns; a lookup table can have up to %d", len(header), MaxColumns)
	}
	t := &Table{Name: name, Bytes: len(data), Updated: time.Now().UTC()}
	for i, h := range header {
		// A byte order mark is not part of a name, even a second one
		// (and removing one can join the bytes of another).
		for strings.Contains(h, "\ufeff") {
			h = strings.ReplaceAll(h, "\ufeff", "")
		}
		h = strings.TrimSpace(h)
		if h == "" {
			return nil, parseErr("column %d has no name; the first line names the columns", i+1)
		}
		if slices.Contains(t.Columns, h) {
			return nil, parseErr("column %q appears twice", h)
		}
		t.Columns = append(t.Columns, h)
	}
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, parseErr("%v", err)
		}
		line, _ := r.FieldPos(0)
		if len(rec) > len(t.Columns) {
			return nil, parseErr("line %d has %d values but there are %d columns", line, len(rec), len(t.Columns))
		}
		if len(rec) == 1 && strings.TrimSpace(rec[0]) == "" {
			continue // a blank line
		}
		if len(t.Rows) >= MaxRows {
			return nil, parseErr("the file has more than %d rows, the most a lookup table takes", MaxRows)
		}
		row := make([]string, len(t.Columns))
		for i, v := range rec {
			row[i] = strings.TrimSpace(v)
		}
		t.Rows = append(t.Rows, row)
	}
	return t, nil
}

// List describes every table, by name.
func (s *Store) List() []Info {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Info, 0, len(s.tables))
	for _, t := range s.tables {
		out = append(out, t.Info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns a table. It must not be changed.
func (s *Store) Get(name string) (*Table, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tables[name]
	return t, ok
}

// Put replaces or adds a table from CSV, after checking the limits.
func (s *Store) Put(name string, data []byte) (*Table, error) {
	if !ValidName(name) {
		return nil, fmt.Errorf("%q cannot name a lookup table; use lower-case letters, digits, - and _ (up to 64)", name)
	}
	t, err := Parse(name, data)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	total := t.Bytes
	for n, old := range s.tables {
		if n != name {
			total += old.Bytes
		}
	}
	if _, ok := s.tables[name]; !ok && len(s.tables) >= MaxTables {
		return nil, fmt.Errorf("there are already %d lookup tables, the most a server keeps; delete one first", MaxTables)
	}
	if total > MaxTotalBytes {
		return nil, fmt.Errorf("the lookup tables would take %d MB together; the limit is %d MB", total>>20, MaxTotalBytes>>20)
	}
	if s.dir != "" {
		if err := securefile.WriteFile(filepath.Join(s.dir, name+".csv"), data); err != nil {
			return nil, err
		}
	}
	s.tables[name] = t
	s.dropIndexes(name)
	return t, nil
}

// Delete removes a table.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tables[name]; !ok {
		return ErrNotFound
	}
	if s.dir != "" {
		if err := os.Remove(filepath.Join(s.dir, name+".csv")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	delete(s.tables, name)
	s.dropIndexes(name)
	return nil
}

func (s *Store) dropIndexes(name string) {
	for k := range s.indexes {
		if strings.HasPrefix(k, name+keySep) {
			delete(s.indexes, k)
		}
	}
}

// Lookup returns a table and its index on the key columns, built on first
// use and kept until the table changes. An empty key value never matches.
func (s *Store) Lookup(name string, keys []string) (*Table, Index, error) {
	ik := name + keySep + Key(keys)
	s.mu.RLock()
	t, ok := s.tables[name]
	idx, built := s.indexes[ik]
	s.mu.RUnlock()
	if !ok {
		return nil, nil, ErrNotFound
	}
	if built {
		return t, idx, nil
	}
	cols := make([]int, len(keys))
	for i, k := range keys {
		if cols[i] = t.Column(k); cols[i] < 0 {
			return nil, nil, fmt.Errorf("lookup table %s has no column %q; its columns are: %s", name, k, strings.Join(t.Columns, ", "))
		}
	}
	idx = Index{}
	vals := make([]string, len(cols))
rows:
	for i, row := range t.Rows {
		for j, c := range cols {
			if vals[j] = row[c]; vals[j] == "" {
				continue rows
			}
		}
		k := Key(vals)
		idx[k] = append(idx[k], i)
	}
	s.mu.Lock()
	// Keep the index only if the table did not change meanwhile.
	if s.tables[name] == t {
		s.indexes[ik] = idx
	}
	s.mu.Unlock()
	return t, idx, nil
}

// CSV writes a table back out, with cells that a spreadsheet would run
// as formulas made safe.
func (t *Table) CSV() []byte {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	head := make([]string, len(t.Columns))
	for i, c := range t.Columns {
		head[i] = assets.SafeCell(c)
	}
	_ = w.Write(head)
	row := make([]string, len(t.Columns))
	for _, r := range t.Rows {
		for i, v := range r {
			row[i] = assets.SafeCell(v)
		}
		_ = w.Write(row)
	}
	w.Flush()
	return b.Bytes()
}

// Dir is the folder the tables are kept in, within the folder of the
// asset and identity lists (lookups.dir).
func Dir(lookupsDir string) string { return filepath.Join(lookupsDir, "tables") }
