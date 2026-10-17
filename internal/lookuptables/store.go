// Package lookuptables keeps the CSV tables the search command lookup
// reads: an admin uploads a table on Settings > Lookups, and a search adds
// its columns to events whose field matches a key column, as in
//
//   - | lookup service_owners host OUTPUT owner, team
package lookuptables

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
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
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// Limits on what the tables may hold, so a few uploads cannot fill the
// server's memory: every table is kept in memory for searches.
const (
	MaxTableBytes = 16 << 20
	MaxTotalBytes = 256 << 20 // in memory, all tables together (Table.Memory)
	// MaxTableMemory is the most memory one parsed table may take: a file
	// of many short or empty cells takes far more in memory than on disk.
	MaxTableMemory = 64 << 20
	MaxTables      = 200
	MaxRows        = 1_000_000
	MaxColumns     = 100
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
	// Memory estimates what the parsed table takes in memory: each cell's
	// text and string header, and each row's slice.
	Memory int
	// Pack names the content pack a table comes with ("" for a table an
	// admin added); a pack's tables cannot be changed or deleted.
	Pack string
	Options
}

// Options say how a table's key columns match, as Splunk's match_type
// and case_sensitive_match do.
type Options struct {
	// Wildcard columns hold patterns: * in a cell matches any text.
	Wildcard []string `json:"wildcard,omitempty"`
	// IgnoreCase matches key values whatever their case.
	IgnoreCase bool `json:"ignore_case,omitempty"`
}

// check refuses options naming columns t does not have.
func (o Options) check(t *Table) error {
	if len(o.Wildcard) > MaxColumns {
		return fmt.Errorf("a table has at most %d wildcard columns", MaxColumns)
	}
	for _, c := range o.Wildcard {
		if t.Column(c) < 0 {
			return fmt.Errorf("the table has no column %q to match with wildcards; its columns are: %s", c, strings.Join(t.Columns, ", "))
		}
	}
	return nil
}

// optionsFile is where a table's options are kept, next to its CSV.
func optionsFile(dir, name string) string { return filepath.Join(dir, name+".options.json") }

// Per-cell and per-row overhead in memory, on 64-bit platforms.
const (
	cellOverhead = 16
	rowOverhead  = 24
)

// Info describes a table without its rows.
type Info struct {
	Name    string    `json:"name"`
	Columns []string  `json:"columns"`
	Rows    int       `json:"rows"`
	Bytes   int       `json:"bytes"`
	Updated time.Time `json:"updated"`
	Pack    string    `json:"pack,omitempty"`
	Options
}

// Info returns t's description.
func (t *Table) Info() Info {
	return Info{Name: t.Name, Columns: t.Columns, Rows: len(t.Rows), Bytes: t.Bytes, Updated: t.Updated, Pack: t.Pack, Options: t.Options}
}

// Column returns the index of the named column, or -1.
func (t *Table) Column(name string) int { return slices.Index(t.Columns, name) }

// Index finds the rows whose key columns match a row's values: by the
// values joined by keySep for rows without patterns, and by trying each
// row whose wildcard key cells hold a *.
type Index struct {
	Exact    map[string][]int
	Patterns []int // rows to try one by one, in table order
	cols     []int
	wild     []bool // which key columns hold patterns
	fold     bool
	table    *Table // the table it indexes
}

// fold lowercases s when the table ignores case.
func (ix *Index) foldCase(s string) string {
	if ix.fold {
		return strings.ToLower(s)
	}
	return s
}

// Match returns up to limit rows of t that match vals, the values of the
// key columns in order: exact matches first, then patterns in table
// order. step is told what each pattern row tried costs, about a step per
// 16 bytes compared, and stops the search when it returns false.
func (ix *Index) Match(t *Table, vals []string, limit int, step func(n int) bool) ([]int, bool) {
	var key []string
	for _, v := range vals {
		key = append(key, ix.foldCase(v))
	}
	out := ix.Exact[Key(key)]
	out = out[:min(len(out), limit)]
	if len(ix.Patterns) == 0 || len(out) >= limit {
		return out, true
	}
	out = slices.Clone(out)
	cost := 1
	for _, v := range key {
		cost += len(v) / 16
	}
	for _, r := range ix.Patterns {
		n := cost
		for _, c := range ix.cols {
			n += len(t.Rows[r][c]) / 16
		}
		if !step(n) {
			return nil, false
		}
		ok := true
		for i, c := range ix.cols {
			cell := ix.foldCase(t.Rows[r][c])
			if ix.wild[i] && strings.Contains(cell, "*") {
				ok = Glob(cell, key[i])
			} else {
				ok = cell == key[i]
			}
			if !ok {
				break
			}
		}
		if ok {
			if out = append(out, r); len(out) >= limit {
				break
			}
		}
	}
	return out, true
}

// Glob reports whether s matches pattern, in which * matches any text,
// including none, and every other byte matches itself. Each run of text
// between stars is found at its first place, which is enough for *: it
// takes time in proportion to the lengths, not exponential.
func Glob(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	first, last := parts[0], parts[len(parts)-1]
	if len(s) < len(first)+len(last) || !strings.HasPrefix(s, first) || !strings.HasSuffix(s, last) {
		return false
	}
	s = s[len(first) : len(s)-len(last)]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(s, p)
		if i < 0 {
			return false
		}
		s = s[i+len(p):]
	}
	return true
}

// keySep joins the values of several key columns; it cannot appear in a
// value read from CSV.
const keySep = "\x00"

// Key joins the values of several key columns into an Index key.
func Key(values []string) string { return strings.Join(values, keySep) }

// Store holds the tables, read from files in one folder, and the tables
// the content packs in use ship (SetPackTables).
type Store struct {
	dir string

	mu      sync.RWMutex
	tables  map[string]*Table
	indexes map[string]*Index // by table name and key columns
	// packs, when set, are this store's pack tables instead of the ones
	// SetPackTables gives every store (NewPackStore).
	packs map[string]*Table
}

// Content packs ship tables their rules' lookup stages read. Each is named
// <pack>-<table> (splunk-browser_app_list), a name an admin cannot give a
// table of their own, so a pack table never replaces an admin's and an
// admin's never changes what a pack rule finds. They are kept in memory,
// not in the folder, and do not count towards the limits on admins'
// tables.
var packTables atomic.Pointer[map[string]*Table]

// NewPackTable reads a content pack's table from CSV, with options for
// how its key columns match: name is the table's name (<pack>-<table>).
func NewPackTable(pack, name string, data []byte, opts Options) (*Table, error) {
	if !ValidName(name) || !strings.HasPrefix(name, pack+"-") {
		return nil, fmt.Errorf("%q cannot name a table of content pack %s; it must start with %s-", name, pack, pack)
	}
	t, err := Parse(name, data)
	if err != nil {
		return nil, err
	}
	if err := opts.check(t); err != nil {
		return nil, err
	}
	t.Options = opts
	t.Pack = pack
	return t, nil
}

// SetPackTables makes ts the content packs' tables every store reads,
// in place of the ones before (a content update's, or the built-in
// packs').
func SetPackTables(ts []*Table) {
	m := make(map[string]*Table, len(ts))
	for _, t := range ts {
		m[t.Name] = t
	}
	packTables.Store(&m)
}

// NewPackStore is a store with no folder whose pack tables are ts alone,
// whatever SetPackTables gives other stores: for checking a pack's rules.
func NewPackStore(ts []*Table) *Store {
	s, _ := Open("")
	s.packs = map[string]*Table{}
	for _, t := range ts {
		s.packs[t.Name] = t
	}
	return s
}

// packMap is the pack tables s reads.
func (s *Store) packMap() map[string]*Table {
	if s.packs != nil {
		return s.packs
	}
	if m := packTables.Load(); m != nil {
		return *m
	}
	return nil
}

// reserved reports whether name is a pack table's, or has the prefix of
// a pack that ships tables, so an admin cannot use it.
func (s *Store) reserved(name string) (string, bool) {
	for _, t := range s.packMap() {
		if t.Name == name || strings.HasPrefix(name, t.Pack+"-") {
			return t.Pack, true
		}
	}
	return "", false
}

// table is the table named name, a pack's first; s.mu is held.
func (s *Store) table(name string) (*Table, bool) {
	if t, ok := s.packMap()[name]; ok {
		return t, true
	}
	t, ok := s.tables[name]
	return t, ok
}

// Open reads the tables in dir, which is created when missing. A file that
// does not read is skipped and reported in the returned error, so one bad
// file never hides the rest.
func Open(dir string) (*Store, error) {
	s := &Store{dir: dir, tables: map[string]*Table{}, indexes: map[string]*Index{}}
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
		if data, err := os.ReadFile(optionsFile(dir, name)); err == nil {
			var o Options
			if err := json.Unmarshal(data, &o); err != nil || o.check(t) != nil {
				errs = append(errs, fmt.Errorf("%s: the table's options do not read, so it matches exactly", optionsFile(dir, name)))
			} else {
				t.Options = o
			}
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
			t.Memory += len(row[i])
		}
		t.Memory += rowOverhead + cellOverhead*len(row)
		if t.Memory > MaxTableMemory {
			return nil, parseErr("the table would take more than %d MB in memory (line %d); split it or remove empty columns", MaxTableMemory>>20, line)
		}
		t.Rows = append(t.Rows, row)
	}
	return t, nil
}

// List describes the tables admins added, by name; PackList the content
// packs'. A table of an admin's that a pack's of the same name hides is
// in neither.
func (s *Store) List() []Info {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Info, 0, len(s.tables))
	packs := s.packMap()
	for n, t := range s.tables {
		if _, shadowed := packs[n]; !shadowed {
			out = append(out, t.Info())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// PackList describes the content packs' tables, by name.
func (s *Store) PackList() []Info {
	var out []Info
	for _, t := range s.packMap() {
		out = append(out, t.Info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns a table. It must not be changed.
func (s *Store) Get(name string) (*Table, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.table(name)
}

// Put replaces or adds a table from CSV, after checking the limits; its
// key columns match exactly.
func (s *Store) Put(name string, data []byte) (*Table, error) {
	return s.PutWithOptions(name, data, Options{})
}

// PutWithOptions replaces or adds a table from CSV with options for how
// its key columns match.
func (s *Store) PutWithOptions(name string, data []byte, opts Options) (*Table, error) {
	if !ValidName(name) {
		return nil, fmt.Errorf("%q cannot name a lookup table; use lower-case letters, digits, - and _ (up to 64)", name)
	}
	if pack, ok := s.reserved(name); ok {
		return nil, fmt.Errorf("names starting with %s- are kept for the tables of the %s content pack; choose another name", pack, pack)
	}
	t, err := Parse(name, data)
	if err != nil {
		return nil, err
	}
	if err := opts.check(t); err != nil {
		return nil, err
	}
	t.Options = opts
	s.mu.Lock()
	defer s.mu.Unlock()
	total := t.Memory
	for n, old := range s.tables {
		if n != name {
			total += old.Memory
		}
	}
	if _, ok := s.tables[name]; !ok && len(s.tables) >= MaxTables {
		return nil, fmt.Errorf("there are already %d lookup tables, the most a server keeps; delete one first", MaxTables)
	}
	if total > MaxTotalBytes {
		return nil, fmt.Errorf("the lookup tables would take %d MB of memory together; the limit is %d MB", total>>20, MaxTotalBytes>>20)
	}
	if s.dir != "" {
		// The options go first: a table whose CSV is new but whose
		// options are old would match by the old columns.
		if err := s.writeOptions(name, opts); err != nil {
			return nil, err
		}
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
	if t, ok := s.packMap()[name]; ok {
		return fmt.Errorf("%w: %s comes with the %s content pack, whose tables cannot be deleted", ErrNotFound, name, t.Pack)
	}
	if _, ok := s.tables[name]; !ok {
		return ErrNotFound
	}
	if s.dir != "" {
		if err := os.Remove(filepath.Join(s.dir, name+".csv")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Remove(optionsFile(s.dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	delete(s.tables, name)
	s.dropIndexes(name)
	return nil
}

// writeOptions keeps a table's options, or removes the file when it has
// none.
func (s *Store) writeOptions(name string, opts Options) error {
	path := optionsFile(s.dir, name)
	if len(opts.Wildcard) == 0 && !opts.IgnoreCase {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := json.Marshal(opts)
	if err != nil {
		return err
	}
	return securefile.WriteFile(path, data)
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
func (s *Store) Lookup(name string, keys []string) (*Table, *Index, error) {
	ik := name + keySep + Key(keys)
	s.mu.RLock()
	t, ok := s.table(name)
	idx, built := s.indexes[ik]
	s.mu.RUnlock()
	if !ok {
		return nil, nil, ErrNotFound
	}
	if built && idx.table == t {
		return t, idx, nil
	}
	cols := make([]int, len(keys))
	for i, k := range keys {
		if cols[i] = t.Column(k); cols[i] < 0 {
			return nil, nil, fmt.Errorf("lookup table %s has no column %q; its columns are: %s", name, k, strings.Join(t.Columns, ", "))
		}
	}
	idx = &Index{Exact: map[string][]int{}, cols: cols, fold: t.IgnoreCase, table: t}
	for _, c := range cols {
		idx.wild = append(idx.wild, slices.Contains(t.Wildcard, t.Columns[c]))
	}
	vals := make([]string, len(cols))
rows:
	for i, row := range t.Rows {
		pattern := false
		for j, c := range cols {
			if vals[j] = idx.foldCase(row[c]); vals[j] == "" {
				continue rows
			}
			pattern = pattern || idx.wild[j] && strings.Contains(vals[j], "*")
		}
		if pattern {
			idx.Patterns = append(idx.Patterns, i)
			continue
		}
		k := Key(vals)
		idx.Exact[k] = append(idx.Exact[k], i)
	}
	s.mu.Lock()
	// Keep the index only if the table did not change meanwhile.
	if cur, _ := s.table(name); cur == t {
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
