// Package assets holds the asset and identity lists that give events
// business context, like the Splunk ES asset and identity framework: who
// owns a host, how critical it is, who a username belongs to, and whether
// they are on a watchlist.
//
// Both lists are CSV files an admin can export from a CMDB or HR system.
package assets

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
)

// Priorities, lowest first. Priority scales risk and raises urgency.
var Priorities = []string{"low", "medium", "high", "critical"}

// Asset is one host or network range.
type Asset struct {
	Host     []string `json:"host,omitempty"` // host names, short or fully qualified
	IP       []string `json:"ip,omitempty"`
	CIDR     []string `json:"cidr,omitempty"`
	Owner    string   `json:"owner,omitempty"`
	Priority string   `json:"priority,omitempty"`
	Category []string `json:"category,omitempty"`
	BUnit    string   `json:"bunit,omitempty"`
	Location string   `json:"location,omitempty"`
}

// Identity is one person or service account.
type Identity struct {
	Identity  []string `json:"identity"` // usernames and aliases
	Name      string   `json:"name,omitempty"`
	Email     string   `json:"email,omitempty"`
	Manager   string   `json:"manager,omitempty"`
	Priority  string   `json:"priority,omitempty"`
	Category  []string `json:"category,omitempty"`
	BUnit     string   `json:"bunit,omitempty"`
	Watchlist bool     `json:"watchlist,omitempty"`
}

// Columns are the CSV headers each list accepts. Multi-value cells use |.
var (
	AssetColumns    = []string{"host", "ip", "cidr", "owner", "priority", "category", "bunit", "location"}
	IdentityColumns = []string{"identity", "name", "email", "manager", "priority", "category", "bunit", "watchlist"}
)

// LineError is a problem on one CSV line.
type LineError struct {
	Line int    `json:"line"`
	Msg  string `json:"msg"`
}

// ParseError lists every bad line.
type ParseError struct{ Lines []LineError }

func (e *ParseError) Error() string {
	var parts []string
	for _, l := range e.Lines {
		parts = append(parts, fmt.Sprintf("line %d: %s", l.Line, l.Msg))
	}
	return strings.Join(parts, "; ")
}

func splitMulti(s string) []string {
	var out []string
	for _, p := range strings.Split(s, "|") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// maxRows caps one list, so a wrong or huge file cannot fill memory.
// Tests lower it.
var maxRows = 1_000_000

// readCSV returns rows as maps keyed by lower-case header, checking that
// every header is known and the required one is present.
func readCSV(data []byte, known []string, required string) ([]map[string]string, []int, error) {
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(data, []byte("\ufeff"))))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	header, err := r.Read()
	if errors.Is(err, io.EOF) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	for i, h := range header {
		header[i] = strings.ToLower(strings.TrimSpace(h))
		if !slices.Contains(known, header[i]) {
			return nil, nil, fmt.Errorf("unknown column %q; columns are: %s", h, strings.Join(known, ", "))
		}
	}
	if !slices.Contains(header, required) && !(required == "host" && (slices.Contains(header, "ip") || slices.Contains(header, "cidr"))) {
		return nil, nil, fmt.Errorf("missing column %q", required)
	}
	var rows []map[string]string
	var lines []int
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		line, _ := r.FieldPos(0)
		m := map[string]string{}
		empty := true
		for i, v := range rec {
			if i < len(header) {
				m[header[i]] = strings.TrimSpace(unquoteCell(v))
				if m[header[i]] != "" {
					empty = false
				}
			}
		}
		if !empty {
			if len(rows) >= maxRows {
				return nil, nil, fmt.Errorf("the file has more than %d rows, the most a list takes", maxRows)
			}
			rows = append(rows, m)
			lines = append(lines, line)
		}
	}
	return rows, lines, nil
}

func checkPriority(p string) (string, error) {
	p = strings.ToLower(p)
	if p == "" || slices.Contains(Priorities, p) {
		return p, nil
	}
	return "", fmt.Errorf("priority %q must be one of %s", p, strings.Join(Priorities, ", "))
}

// ParseAssets reads an asset CSV.
func ParseAssets(data []byte) ([]Asset, error) {
	rows, lines, err := readCSV(data, AssetColumns, "host")
	if err != nil {
		return nil, err
	}
	var out []Asset
	var bad []LineError
	for i, m := range rows {
		a := Asset{Host: splitMulti(m["host"]), IP: splitMulti(m["ip"]), CIDR: splitMulti(m["cidr"]),
			Owner: m["owner"], Category: splitMulti(m["category"]), BUnit: m["bunit"], Location: m["location"]}
		var msgs []string
		if a.Priority, err = checkPriority(m["priority"]); err != nil {
			msgs = append(msgs, err.Error())
		}
		for _, ip := range a.IP {
			if _, err := netip.ParseAddr(ip); err != nil {
				msgs = append(msgs, fmt.Sprintf("ip %q is not an IP address", ip))
			}
		}
		for _, c := range a.CIDR {
			if _, err := netip.ParsePrefix(c); err != nil {
				msgs = append(msgs, fmt.Sprintf("cidr %q is not a network like 10.0.0.0/8", c))
			}
		}
		if len(a.Host)+len(a.IP)+len(a.CIDR) == 0 {
			msgs = append(msgs, "needs a host, ip or cidr")
		}
		if len(msgs) > 0 {
			bad = append(bad, LineError{Line: lines[i], Msg: strings.Join(msgs, "; ")})
			continue
		}
		out = append(out, a)
	}
	if len(bad) > 0 {
		return nil, &ParseError{Lines: bad}
	}
	return out, nil
}

// ParseIdentities reads an identity CSV.
func ParseIdentities(data []byte) ([]Identity, error) {
	rows, lines, err := readCSV(data, IdentityColumns, "identity")
	if err != nil {
		return nil, err
	}
	var out []Identity
	var bad []LineError
	for i, m := range rows {
		id := Identity{Identity: splitMulti(m["identity"]), Name: m["name"], Email: m["email"], Manager: m["manager"],
			Category: splitMulti(m["category"]), BUnit: m["bunit"]}
		var msgs []string
		if id.Priority, err = checkPriority(m["priority"]); err != nil {
			msgs = append(msgs, err.Error())
		}
		switch strings.ToLower(m["watchlist"]) {
		case "", "false", "no", "0":
		case "true", "yes", "1":
			id.Watchlist = true
		default:
			msgs = append(msgs, fmt.Sprintf("watchlist %q must be true or false", m["watchlist"]))
		}
		if len(id.Identity) == 0 {
			msgs = append(msgs, "identity is empty")
		}
		if len(msgs) > 0 {
			bad = append(bad, LineError{Line: lines[i], Msg: strings.Join(msgs, "; ")})
			continue
		}
		out = append(out, id)
	}
	if len(bad) > 0 {
		return nil, &ParseError{Lines: bad}
	}
	return out, nil
}

// Store holds both lists and answers lookups. It is safe for concurrent use.
//
// Besides the user's own lists it can hold an overlay: extra rows another
// feature adds for its own hosts and users (the sample data does, for the
// made-up company it loads). The overlay lives in its own files, so the
// user's files are never rewritten for it, and it only answers lookups the
// user's lists do not: a user's row always wins. Assets, Identities, the
// CSV download and uploads see the user's lists alone.
type Store struct {
	Dir string // where assets.csv and identities.csv live; "" keeps them in memory

	mu      sync.RWMutex
	own     *lookup // the user's lists
	overlay *lookup // rows added by the sample data, consulted second
	// found are hosts Signalith found itself (osquery hosts on the
	// Endpoints page), consulted last and kept in memory only.
	found *lookup
	// sums are the contents last loaded from each file in listFiles,
	// zero for a missing one. Contents, not modification times: a file
	// rewritten within the file system's time resolution (Windows) keeps
	// its time.
	sums [4][sha256.Size]byte
}

// lookup indexes one pair of lists. It is never changed once built, so a
// Store swaps in a new one under its lock and readers may keep the old.
type lookup struct {
	assets     []Asset
	identities []Identity
	byHost     map[string]int
	byIP       map[netip.Addr]int
	nets       []netEntry
	byUser     map[string]int
}

type netEntry struct {
	prefix netip.Prefix
	idx    int
}

// File names inside Dir. The overlay files belong to the sample data: it
// writes them when it is loaded and deletes them when it is removed.
const (
	AssetsFile            = "assets.csv"
	IdentitiesFile        = "identities.csv"
	OverlayAssetsFile     = "sample-data-assets.csv"
	OverlayIdentitiesFile = "sample-data-identities.csv"
)

var listFiles = [4]string{AssetsFile, IdentitiesFile, OverlayAssetsFile, OverlayIdentitiesFile}

// NewStore loads the lists from dir. Missing files mean empty lists.
func NewStore(dir string) (*Store, error) {
	s := &Store{Dir: dir, own: newLookup(nil, nil), overlay: newLookup(nil, nil)}
	if dir == "" {
		return s, nil
	}
	if _, err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// OpenStore is NewStore for the server, which must run even when a list
// is damaged: it always returns a store, with empty lists in place of
// ones that cannot be read, and the error. Reload picks the files up once
// they are fixed.
func OpenStore(dir string) (*Store, error) {
	s := &Store{Dir: dir, own: newLookup(nil, nil), overlay: newLookup(nil, nil)}
	if dir == "" {
		return s, nil
	}
	_, err := s.Reload()
	return s, err
}

// Reload rereads the files if they changed. It reports whether it did. The
// user's lists and the overlay load independently, so a damaged list of
// the user's keeps neither the overlay nor the other pair from loading.
func (s *Store) Reload() (bool, error) {
	if s.Dir == "" {
		return false, nil
	}
	var data [4][]byte
	var mod [4][sha256.Size]byte
	for i, name := range listFiles {
		p := filepath.Join(s.Dir, name)
		b, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		data[i] = b
		mod[i] = sha256.Sum256(data[i])
	}
	s.mu.RLock()
	cur := s.sums
	s.mu.RUnlock()

	var errs []error
	var own, overlay *lookup
	for pair := 0; pair < 2; pair++ {
		a, b := pair*2, pair*2+1
		if mod[a] == cur[a] && mod[b] == cur[b] {
			continue
		}
		as, err := ParseAssets(data[a])
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Join(s.Dir, listFiles[a]), err))
			continue
		}
		ids, err := ParseIdentities(data[b])
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Join(s.Dir, listFiles[b]), err))
			continue
		}
		if pair == 0 {
			own = newLookup(as, ids)
		} else {
			overlay = newLookup(as, ids)
		}
	}
	if own == nil && overlay == nil {
		return false, errors.Join(errs...)
	}
	s.mu.Lock()
	if own != nil {
		s.own = own
		s.sums[0], s.sums[1] = mod[0], mod[1]
	}
	if overlay != nil {
		s.overlay = overlay
		s.sums[2], s.sums[3] = mod[2], mod[3]
	}
	s.mu.Unlock()
	return true, errors.Join(errs...)
}

func normHost(h string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), ".")) }

// normUser strips DOMAIN\ and @domain so corp\bob, bob@corp.com and bob match.
func normUser(u string) string {
	u = strings.ToLower(strings.TrimSpace(u))
	if i := strings.LastIndexByte(u, '\\'); i >= 0 {
		u = u[i+1:]
	}
	if i := strings.IndexByte(u, '@'); i > 0 {
		u = u[:i]
	}
	return u
}

func newLookup(as []Asset, ids []Identity) *lookup {
	byHost := map[string]int{}
	byIP := map[netip.Addr]int{}
	var nets []netEntry
	for i, a := range as {
		for _, h := range a.Host {
			h = normHost(h)
			byHost[h] = i
			if short, _, ok := strings.Cut(h, "."); ok {
				if _, taken := byHost[short]; !taken {
					byHost[short] = i
				}
			}
		}
		for _, ip := range a.IP {
			if addr, err := netip.ParseAddr(ip); err == nil {
				byIP[addr.Unmap()] = i
			}
		}
		for _, c := range a.CIDR {
			if p, err := netip.ParsePrefix(c); err == nil {
				nets = append(nets, netEntry{p.Masked(), i})
			}
		}
	}
	// Most specific network first.
	sort.SliceStable(nets, func(i, j int) bool { return nets[i].prefix.Bits() > nets[j].prefix.Bits() })
	byUser := map[string]int{}
	for i, id := range ids {
		for _, u := range id.Identity {
			byUser[normUser(u)] = i
		}
	}
	return &lookup{assets: as, identities: ids, byHost: byHost, byIP: byIP, nets: nets, byUser: byUser}
}

func (l *lookup) asset(v string) (*Asset, bool) {
	if addr, err := netip.ParseAddr(v); err == nil {
		addr = addr.Unmap()
		if i, ok := l.byIP[addr]; ok {
			return &l.assets[i], true
		}
		for _, n := range l.nets {
			if n.prefix.Contains(addr) {
				return &l.assets[n.idx], true
			}
		}
		return nil, false
	}
	h := normHost(v)
	if i, ok := l.byHost[h]; ok {
		return &l.assets[i], true
	}
	if short, _, ok := strings.Cut(h, "."); ok {
		if i, ok := l.byHost[short]; ok {
			return &l.assets[i], true
		}
	}
	return nil, false
}

// lookups returns the user's lists and the overlay, for lock-free reads.
func (s *Store) lookups() (own, overlay *lookup) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.own, s.overlay
}

// Asset finds the asset for a host name or IP address: in the user's list
// first, then in the overlay, then among the hosts Signalith found.
func (s *Store) Asset(v string) (*Asset, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, false
	}
	own, overlay := s.lookups()
	if a, ok := own.asset(v); ok {
		return a, true
	}
	if a, ok := overlay.asset(v); ok {
		return a, true
	}
	s.mu.RLock()
	found := s.found
	s.mu.RUnlock()
	if found == nil {
		return nil, false
	}
	return found.asset(v)
}

// SetFound replaces the hosts Signalith found itself, such as the osquery
// hosts on the Endpoints page. They are never written to a file or the
// user's list, and the user's list and the sample data win over them.
func (s *Store) SetFound(as []Asset) {
	l := newLookup(append([]Asset(nil), as...), nil)
	s.mu.Lock()
	s.found = l
	s.mu.Unlock()
}

// Found returns copies of the hosts Signalith found itself that the
// user's list does not already have.
func (s *Store) Found() []Asset {
	own, _ := s.lookups()
	s.mu.RLock()
	found := s.found
	s.mu.RUnlock()
	if found == nil {
		return nil
	}
	var out []Asset
	for _, a := range found.assets {
		known := false
		for _, h := range a.Host {
			if _, ok := own.asset(h); ok {
				known = true
				break
			}
		}
		if !known {
			out = append(out, a)
		}
	}
	return out
}

// Identity finds the identity for a username in any common form: in the
// user's list first, then in the overlay.
func (s *Store) Identity(v string) (*Identity, bool) {
	u := normUser(v)
	if u == "" {
		return nil, false
	}
	own, overlay := s.lookups()
	if i, ok := own.byUser[u]; ok {
		return &own.identities[i], true
	}
	if i, ok := overlay.byUser[u]; ok {
		return &overlay.identities[i], true
	}
	return nil, false
}

// Assets and Identities return copies of the user's lists (never the
// overlay).
func (s *Store) Assets() []Asset {
	own, _ := s.lookups()
	return append([]Asset(nil), own.assets...)
}

func (s *Store) Identities() []Identity {
	own, _ := s.lookups()
	return append([]Identity(nil), own.identities...)
}

// Overlay returns copies of the overlay's rows.
func (s *Store) Overlay() ([]Asset, []Identity) {
	_, overlay := s.lookups()
	return append([]Asset(nil), overlay.assets...), append([]Identity(nil), overlay.identities...)
}

// Own returns the store without its overlay: lookups answer from the
// user's lists only. It shares the current lists and does not reload, so
// take it again for each use. With no overlay loaded it is s itself.
func (s *Store) Own() *Store {
	if s == nil {
		return nil
	}
	own, overlay := s.lookups()
	if len(overlay.assets) == 0 && len(overlay.identities) == 0 {
		return s
	}
	s.mu.RLock()
	found := s.found
	s.mu.RUnlock()
	return &Store{own: own, overlay: newLookup(nil, nil), found: found}
}

// SetOverlay replaces the overlay with these rows and saves them to the
// overlay files in Dir, or deletes those files when both are empty. The
// user's own files are never touched.
func (s *Store) SetOverlay(as []Asset, ids []Identity) error {
	var mod [2][sha256.Size]byte
	if s.Dir != "" {
		for i, name := range listFiles[2:] {
			p := filepath.Join(s.Dir, name)
			if len(as) == 0 && len(ids) == 0 {
				if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
				continue
			}
			data := MarshalAssets(as)
			if i == 1 {
				data = MarshalIdentities(ids)
			}
			t, err := s.write(name, data)
			if err != nil {
				return err
			}
			mod[i] = t
		}
	}
	l := newLookup(append([]Asset(nil), as...), append([]Identity(nil), ids...))
	s.mu.Lock()
	s.overlay = l
	s.sums[2], s.sums[3] = mod[0], mod[1]
	s.mu.Unlock()
	return nil
}

// SetAssets validates CSV, saves it to Dir and loads it.
func (s *Store) SetAssets(data []byte) (int, error) {
	as, err := ParseAssets(data)
	if err != nil {
		return 0, err
	}
	if err := s.save(AssetsFile, data); err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.own = newLookup(as, s.own.identities)
	s.mu.Unlock()
	return len(as), nil
}

// SetIdentities validates CSV, saves it to Dir and loads it.
func (s *Store) SetIdentities(data []byte) (int, error) {
	ids, err := ParseIdentities(data)
	if err != nil {
		return 0, err
	}
	if err := s.save(IdentitiesFile, data); err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.own = newLookup(s.own.assets, ids)
	s.mu.Unlock()
	return len(ids), nil
}

func (s *Store) save(name string, data []byte) error {
	if s.Dir == "" {
		return nil
	}
	t, err := s.write(name, data)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if name == AssetsFile {
		s.sums[0] = t
	} else {
		s.sums[1] = t
	}
	s.mu.Unlock()
	return nil
}

// write replaces a file in Dir atomically and returns the sum of its
// contents.
func (s *Store) write(name string, data []byte) ([sha256.Size]byte, error) {
	if err := os.MkdirAll(s.Dir, 0o750); err != nil {
		return [sha256.Size]byte{}, err
	}
	if err := replaceFile(filepath.Join(s.Dir, name), data); err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(data), nil
}

// replaceFile writes data to path through a temporary file of its own
// (a unique name, so two servers or two requests writing the same file
// never write into each other's), then renames it over path. The
// temporary file is removed on any failure. os.Rename replaces an
// existing file on Windows too.
func replaceFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		// CreateTemp makes the file readable by its owner only; on Windows
		// Chmod only sets or clears read-only, which is fine.
		err = os.Chmod(name, 0o640)
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		_ = os.Remove(name)
	}
	return err
}

// CSV returns a list as CSV, for download. Cells a spreadsheet would run
// as a formula are written with a leading quote (see SafeCell), as the web
// UI's exports do.
func (s *Store) CSV(kind string) []byte {
	if kind == "assets" {
		return MarshalAssets(s.Assets())
	}
	return MarshalIdentities(s.Identities())
}

func csvWriter() (*bytes.Buffer, func(...string), func()) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	write := func(cells ...string) {
		for i, c := range cells {
			cells[i] = SafeCell(c)
		}
		w.Write(cells)
	}
	return &buf, write, w.Flush
}

func joinMulti(xs []string) string { return strings.Join(xs, "|") }

// MarshalAssets serializes assets to CSV in the column order ParseAssets
// reads, so the result round-trips. The overlay files use it too.
func MarshalAssets(as []Asset) []byte {
	buf, write, flush := csvWriter()
	write(AssetColumns...)
	for _, a := range as {
		write(joinMulti(a.Host), joinMulti(a.IP), joinMulti(a.CIDR), a.Owner, a.Priority, joinMulti(a.Category), a.BUnit, a.Location)
	}
	flush()
	return buf.Bytes()
}

// MarshalIdentities serializes identities to CSV, matching ParseIdentities.
func MarshalIdentities(ids []Identity) []byte {
	buf, write, flush := csvWriter()
	write(IdentityColumns...)
	for _, id := range ids {
		wl := ""
		if id.Watchlist {
			wl = "true"
		}
		write(joinMulti(id.Identity), id.Name, id.Email, id.Manager, id.Priority, joinMulti(id.Category), id.BUnit, wl)
	}
	flush()
	return buf.Bytes()
}

// SafeCell returns a CSV cell that a spreadsheet will not run as a
// formula: a value starting with =, +, -, @, a tab or a carriage return
// gets a leading single quote, which spreadsheets show as text. Reading a
// list back (unquoteCell) removes it again, so a downloaded list can be
// edited and uploaded unchanged.
func SafeCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// unquoteCell undoes SafeCell.
func unquoteCell(s string) string {
	if len(s) > 1 && s[0] == '\'' && strings.ContainsRune("=+-@\t\r", rune(s[1])) {
		return s[1:]
	}
	return s
}

// UserFields hold usernames; every other entity field is looked up as an asset.
var UserFields = []string{"user", "src_user"}

// Context describes one entity value for display and scoring.
type Context struct {
	Kind      string   `json:"kind"` // asset or identity
	Priority  string   `json:"priority,omitempty"`
	Owner     string   `json:"owner,omitempty"`
	Name      string   `json:"name,omitempty"`
	Email     string   `json:"email,omitempty"`
	Category  []string `json:"category,omitempty"`
	BUnit     string   `json:"bunit,omitempty"`
	Location  string   `json:"location,omitempty"`
	Watchlist bool     `json:"watchlist,omitempty"`
}

// Lookup returns context for a field's value; user fields are identities.
func (s *Store) Lookup(field, value string) (*Context, bool) {
	if slices.Contains(UserFields, field) {
		id, ok := s.Identity(value)
		if !ok {
			return nil, false
		}
		return &Context{Kind: "identity", Priority: id.Priority, Name: id.Name, Email: id.Email, Owner: id.Manager,
			Category: id.Category, BUnit: id.BUnit, Watchlist: id.Watchlist}, true
	}
	a, ok := s.Asset(value)
	if !ok {
		return nil, false
	}
	return &Context{Kind: "asset", Priority: a.Priority, Owner: a.Owner, Category: a.Category, BUnit: a.BUnit, Location: a.Location}, true
}

// Multiplier scales risk by priority: critical doubles it, low halves it.
func Multiplier(priority string) float64 {
	switch priority {
	case "critical":
		return 2
	case "high":
		return 1.5
	case "low":
		return 0.5
	}
	return 1
}
