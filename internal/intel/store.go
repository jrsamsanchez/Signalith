package intel

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Backend persists indicators.
type Backend interface {
	// Put creates or replaces indicators by ID.
	Put(ctx context.Context, inds []Indicator) error
	Delete(ctx context.Context, ids []string) error
	All(ctx context.Context) ([]Indicator, error)
	// Version changes whenever indicators change, so servers notice
	// changes another server made without reloading everything.
	Version(ctx context.Context) (string, error)
}

// SourceLister is a Backend that can list the IDs of a source's
// indicators as stored, so a download replaces what is really there
// rather than what this server last loaded.
type SourceLister interface {
	SourceIDs(ctx context.Context, source string) ([]string, error)
}

// Store holds the indicators in memory for fast lookups, backed by a
// Backend. It is safe for concurrent use.
type Store struct {
	Backend Backend
	Now     func() time.Time
	// AfterWrite, when set, is called after each write of indicators (one
	// call per download, upload or change), so other servers that share
	// the backend can be told to reload.
	AfterWrite func()

	mu      sync.RWMutex
	all     map[string]*Indicator // by ID
	byValue map[string][]*Indicator
	nets    []netEntry
	version string
	loaded  bool
	// stale marks a copy changed by this server's own writes since it was
	// last loaded, which the next Sync reloads.
	stale bool
	// wake makes Watch sync now.
	wakeOnce sync.Once
	wake     chan struct{}
}

type netEntry struct {
	prefix netip.Prefix
	ind    *Indicator
}

// NewStore returns a store over a backend; call Load before use.
func NewStore(b Backend) *Store {
	s := &Store{Backend: b}
	s.index(nil)
	return s
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func key(class, value string) string { return class + "\x00" + value }

func (s *Store) index(list []*Indicator) {
	all := make(map[string]*Indicator, len(list))
	byValue := make(map[string][]*Indicator, len(list))
	var nets []netEntry
	for _, ind := range list {
		all[ind.ID] = ind
		if ind.Type == TypeCIDR {
			if p, err := netip.ParsePrefix(ind.Value); err == nil {
				nets = append(nets, netEntry{p, ind})
			}
			continue
		}
		k := key(Class(ind.Type), ind.Value)
		byValue[k] = append(byValue[k], ind)
	}
	sort.SliceStable(nets, func(i, j int) bool { return nets[i].prefix.Bits() > nets[j].prefix.Bits() })
	s.mu.Lock()
	s.all, s.byValue, s.nets = all, byValue, nets
	s.mu.Unlock()
}

// Load reads every indicator from the backend.
func (s *Store) Load(ctx context.Context) error {
	ver, err := s.Backend.Version(ctx)
	if err != nil {
		return err
	}
	list, err := s.Backend.All(ctx)
	if err != nil {
		return err
	}
	ptrs := make([]*Indicator, len(list))
	for i := range list {
		ptrs[i] = &list[i]
	}
	s.index(ptrs)
	s.mu.Lock()
	s.version, s.loaded, s.stale = ver, true, false
	s.mu.Unlock()
	return nil
}

// Sync reloads if another server changed the indicators. It reports
// whether it reloaded.
func (s *Store) Sync(ctx context.Context) (bool, error) {
	ver, err := s.Backend.Version(ctx)
	if err != nil {
		return false, err
	}
	s.mu.RLock()
	same := s.loaded && !s.stale && ver == s.version
	s.mu.RUnlock()
	if same {
		return false, nil
	}
	return true, s.Load(ctx)
}

// Loaded reports whether the indicators have been read from the backend.
func (s *Store) Loaded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loaded
}

func (s *Store) snapshot() []*Indicator {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Indicator, 0, len(s.all))
	for _, ind := range s.all {
		out = append(out, ind)
	}
	return out
}

// afterWrite updates the in-memory copy with what was just written, so
// this server sees its own change at once, and marks the copy stale, so
// the next Sync reloads everything. It does not adopt the backend's
// version after the write: another server may have changed indicators
// between this write and that read, and adopting the version would make
// Sync skip that change for good. The cost is one extra reload after each
// of this server's own writes.
func (s *Store) afterWrite(put []Indicator, deleted []string) {
	s.mu.RLock()
	list := make(map[string]*Indicator, len(s.all)+len(put))
	for id, ind := range s.all {
		list[id] = ind
	}
	s.mu.RUnlock()
	for _, id := range deleted {
		delete(list, id)
	}
	for i := range put {
		ind := put[i]
		list[ind.ID] = &ind
	}
	ptrs := make([]*Indicator, 0, len(list))
	for _, ind := range list {
		ptrs = append(ptrs, ind)
	}
	s.index(ptrs)
	s.mu.Lock()
	s.stale = true
	s.mu.Unlock()
	if s.AfterWrite != nil {
		s.AfterWrite()
	}
}

func (s *Store) wakeCh() chan struct{} {
	s.wakeOnce.Do(func() { s.wake = make(chan struct{}, 1) })
	return s.wake
}

// Wake makes Watch check the backend now, as when another server
// says it changed the indicators. It does not block.
func (s *Store) Wake() {
	select {
	case s.wakeCh() <- struct{}{}:
	default:
	}
}

// prepare fills IDs and times, keeping first_seen of existing indicators.
func (s *Store) prepare(inds []Indicator, now time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range inds {
		ind := &inds[i]
		ind.ID = MakeID(ind.Source, ind.Type, ind.Value)
		if ind.Weight <= 0 {
			ind.Weight = 1
		}
		if ind.LastSeen.IsZero() {
			ind.LastSeen = now
		}
		if old, ok := s.all[ind.ID]; ok && !old.FirstSeen.IsZero() {
			ind.FirstSeen = old.FirstSeen
		} else if ind.FirstSeen.IsZero() {
			ind.FirstSeen = ind.LastSeen
		}
		ind.Updated = now
	}
}

// Add creates or updates indicators. Each needs a normalized Type and
// Value and a Source.
func (s *Store) Add(ctx context.Context, inds []Indicator) error {
	if len(inds) == 0 {
		return nil
	}
	s.prepare(inds, s.now())
	if err := s.Backend.Put(ctx, inds); err != nil {
		return err
	}
	s.afterWrite(inds, nil)
	return nil
}

// Get returns one indicator by ID.
func (s *Store) Get(id string) (Indicator, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ind, ok := s.all[id]
	if !ok {
		return Indicator{}, false
	}
	return *ind, true
}

// Delete removes indicators by ID.
func (s *Store) Delete(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if err := s.Backend.Delete(ctx, ids); err != nil {
		return err
	}
	s.afterWrite(nil, ids)
	return nil
}

// ReplaceSource makes inds the complete set of indicators from a source:
// new ones are added, existing ones get a new last_seen and expiry, and
// ones no longer listed are removed. It returns how many were added and
// removed.
func (s *Store) ReplaceSource(ctx context.Context, source string, inds []Indicator) (added, removed int, err error) {
	now := s.now()
	for i := range inds {
		inds[i].Source = source
		inds[i].LastSeen = now
	}
	s.prepare(inds, now)
	keep := make(map[string]bool, len(inds))
	for _, ind := range inds {
		keep[ind.ID] = true
	}
	ids, err := s.sourceIDs(ctx, source)
	if err != nil {
		return 0, 0, err
	}
	var gone []string
	existing := 0
	for _, id := range ids {
		if keep[id] {
			existing++
		} else {
			gone = append(gone, id)
		}
	}
	if err := s.Backend.Put(ctx, inds); err != nil {
		return 0, 0, err
	}
	if err := s.Backend.Delete(ctx, gone); err != nil {
		return 0, 0, err
	}
	s.afterWrite(inds, gone)
	return len(inds) - existing, len(gone), nil
}

// sourceIDs lists the IDs of a source's indicators: as stored, when the
// backend can say (another server may have written some this one never
// loaded), else as this server last loaded them.
func (s *Store) sourceIDs(ctx context.Context, source string) ([]string, error) {
	if l, ok := s.Backend.(SourceLister); ok {
		ids, err := l.SourceIDs(ctx, source)
		if err != nil {
			return nil, fmt.Errorf("could not list the indicators stored for %s: %w", source, err)
		}
		return ids, nil
	}
	var ids []string
	s.mu.RLock()
	defer s.mu.RUnlock()
	for id, ind := range s.all {
		if ind.Source == source {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// MergeSource adds and updates indicators from a source without removing
// any, for a download that read only part of a feed. It returns how many
// were added.
func (s *Store) MergeSource(ctx context.Context, source string, inds []Indicator) (int, error) {
	now := s.now()
	for i := range inds {
		inds[i].Source = source
		inds[i].LastSeen = now
	}
	s.prepare(inds, now)
	s.mu.RLock()
	added := 0
	for _, ind := range inds {
		if _, ok := s.all[ind.ID]; !ok {
			added++
		}
	}
	s.mu.RUnlock()
	if err := s.Backend.Put(ctx, inds); err != nil {
		return 0, err
	}
	s.afterWrite(inds, nil)
	return added, nil
}

// RemoveSources deletes every indicator whose source is not in keep, so
// a feed that is removed or disabled stops matching. Manual and sample
// indicators are always kept.
func (s *Store) RemoveSources(ctx context.Context, keep []string) (int, error) {
	var gone []string
	for _, ind := range s.snapshot() {
		if ind.Source == ManualSource || ind.Source == SampleSource {
			continue // added by hand or by the sample data; never swept
		}
		if !slices.Contains(keep, ind.Source) {
			gone = append(gone, ind.ID)
		}
	}
	return len(gone), s.Delete(ctx, gone)
}

// Purge deletes expired indicators.
func (s *Store) Purge(ctx context.Context) (int, error) {
	now := s.now()
	var gone []string
	for _, ind := range s.snapshot() {
		if ind.Expired(now) {
			gone = append(gone, ind.ID)
		}
	}
	return len(gone), s.Delete(ctx, gone)
}

// Lookup returns the active indicators that match a value: an exact
// match of the same class, or for an IP address, any network containing
// it. classes limits which classes are tried; none means all. Matches
// are ordered by weight, highest first.
func (s *Store) Lookup(value string, classes ...string) []Indicator {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil
	}
	want := func(c string) bool { return len(classes) == 0 || slices.Contains(classes, c) }
	now := s.now()
	var out []Indicator
	seen := map[string]bool{}
	s.mu.RLock()
	add := func(ind *Indicator) {
		if !ind.Expired(now) && !seen[ind.ID] {
			seen[ind.ID] = true
			out = append(out, *ind)
		}
	}
	try := func(class, val string) {
		for _, ind := range s.byValue[key(class, val)] {
			add(ind)
		}
	}
	if a, err := netip.ParseAddr(v); err == nil {
		a = a.Unmap()
		if want(TypeIP) {
			try(TypeIP, a.String())
			for _, n := range s.nets {
				if n.prefix.Contains(a) {
					add(n.ind)
				}
			}
		}
	} else {
		lower := strings.ToLower(v)
		if want("hash") {
			for _, h := range ParseHashes(v) {
				try("hash", strings.ToLower(h))
			}
		}
		if want(TypeURL) && strings.Contains(v, "://") {
			if n, err := normURL(v); err == nil {
				try(TypeURL, n)
			}
		}
		if want(TypeDomain) {
			d := strings.TrimSuffix(lower, ".")
			if h := URLHost(v); h != "" {
				d = h
			}
			try(TypeDomain, d)
		}
		if want(TypeEmail) && strings.Contains(v, "@") {
			try(TypeEmail, strings.Trim(lower, "<>"))
		}
	}
	s.mu.RUnlock()
	sort.SliceStable(out, func(i, j int) bool { return out[i].Weight > out[j].Weight })
	return out
}

// Values returns the active values of one class, sorted, for building
// search filters. Networks are not included; see Networks.
func (s *Store) Values(class string) []string {
	now := s.now()
	s.mu.RLock()
	set := map[string]bool{}
	for k, inds := range s.byValue {
		c, v, _ := strings.Cut(k, "\x00")
		if c != class {
			continue
		}
		for _, ind := range inds {
			if !ind.Expired(now) {
				set[v] = true
				break
			}
		}
	}
	s.mu.RUnlock()
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// Networks returns the active network indicators, highest weight first.
func (s *Store) Networks() []netip.Prefix {
	now := s.now()
	s.mu.RLock()
	type nw struct {
		p netip.Prefix
		w float64
	}
	var list []nw
	seen := map[netip.Prefix]bool{}
	for _, n := range s.nets {
		if !n.ind.Expired(now) && !seen[n.prefix] {
			seen[n.prefix] = true
			list = append(list, nw{n.prefix, n.ind.Weight})
		}
	}
	s.mu.RUnlock()
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].w != list[j].w {
			return list[i].w > list[j].w
		}
		return list[i].p.String() < list[j].p.String()
	})
	out := make([]netip.Prefix, len(list))
	for i, n := range list {
		out[i] = n.p
	}
	return out
}

// Filter selects indicators to list.
type Filter struct {
	Text   string // substring of the value, description or tags
	Type   string
	Source string
	Limit  int
	Offset int
}

// Summary counts indicators.
type Summary struct {
	Total    int            `json:"total"`
	ByType   map[string]int `json:"by_type"`
	BySource map[string]int `json:"by_source"`
}

// List returns matching indicators, newest first, and how many matched.
func (s *Store) List(f Filter) ([]Indicator, int) {
	text := strings.ToLower(strings.TrimSpace(f.Text))
	// A value typed with defanging or in another case still finds itself.
	_, norm, _ := Normalize("", f.Text)
	var out []Indicator
	for _, ind := range s.snapshot() {
		if f.Type != "" && ind.Type != f.Type && Class(ind.Type) != f.Type {
			continue
		}
		if f.Source != "" && ind.Source != f.Source {
			continue
		}
		if text != "" && !strings.Contains(ind.Value, text) && (norm == "" || !strings.Contains(ind.Value, norm)) &&
			!strings.Contains(strings.ToLower(ind.Description), text) && !slices.ContainsFunc(ind.Tags, func(t string) bool { return strings.EqualFold(t, text) }) {
			continue
		}
		out = append(out, *ind)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Value < out[j].Value
	})
	total := len(out)
	if f.Offset > 0 {
		out = out[min(f.Offset, len(out)):]
	}
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, total
}

// Summary counts the indicators by type and source.
func (s *Store) Summary() Summary {
	sum := Summary{ByType: map[string]int{}, BySource: map[string]int{}}
	for _, ind := range s.snapshot() {
		sum.Total++
		sum.ByType[ind.Type]++
		sum.BySource[ind.Source]++
	}
	return sum
}

// CountSource returns how many indicators a source has.
func (s *Store) CountSource(source string) int {
	n := 0
	for _, ind := range s.snapshot() {
		if ind.Source == source {
			n++
		}
	}
	return n
}

// Memory is an in-memory Backend for tests and single-process demos.
type Memory struct {
	mu   sync.Mutex
	docs map[string]Indicator
	gen  int
}

// NewMemory returns an empty in-memory backend.
func NewMemory() *Memory { return &Memory{docs: map[string]Indicator{}} }

func (m *Memory) Put(_ context.Context, inds []Indicator) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ind := range inds {
		m.docs[ind.ID] = ind
	}
	m.gen++
	return nil
}

func (m *Memory) Delete(_ context.Context, ids []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		delete(m.docs, id)
	}
	m.gen++
	return nil
}

func (m *Memory) All(context.Context) ([]Indicator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Indicator, 0, len(m.docs))
	for _, d := range m.docs {
		out = append(out, d)
	}
	return out, nil
}

func (m *Memory) Version(context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fmt.Sprint(m.gen), nil
}

// DeleteSource deletes every indicator from one source.
func (s *Store) DeleteSource(ctx context.Context, source string) (int, error) {
	var gone []string
	for _, ind := range s.snapshot() {
		if ind.Source == source {
			gone = append(gone, ind.ID)
		}
	}
	return len(gone), s.Delete(ctx, gone)
}
