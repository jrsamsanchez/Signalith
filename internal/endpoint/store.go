// Package endpoint manages hosts that run osquery. Signalith is their
// osquery management server: hosts enroll with an ingest token over
// osquery's TLS remote API (the same one Fleet and other managers use),
// each gets its own node key, fetches its configuration (what to collect
// and which files to watch) from Signalith, sends its results back, and
// answers live queries. Everything is kept in OpenSearch, so every
// Signalith server that shares it manages the same hosts.
package endpoint

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Docs is what the store needs from OpenSearch. *store.Client has it.
type Docs interface {
	Do(ctx context.Context, method, path string, body any, out any) error
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
	Update(ctx context.Context, index, id string, fields map[string]any, refresh bool) (store.Version, error)
	DeleteIf(ctx context.Context, index, id string, v store.Version, refresh bool) error
	SearchDocs(ctx context.Context, index string, query map[string]any) ([]store.Doc, error)
}

// Document kinds in the endpoints index.
const (
	kindNode     = "node"
	kindBlocked  = "blocked"
	kindSettings = "settings"
	kindQuery    = "livequery"
	kindResult   = "liveresult"
	kindChecks   = "checks"
)

// Platforms osquery runs on, as Signalith names them.
const (
	Linux   = "linux"
	Windows = "windows"
	Darwin  = "darwin"
)

// Platforms lists them in display order.
var Platforms = []string{Windows, Linux, Darwin}

// Node is one enrolled host.
type Node struct {
	ID string `json:"id"`
	// HostIdentifier is the host's hardware UUID (osquery's
	// --host_identifier=uuid): one row per machine, even after osquery is
	// reinstalled.
	HostIdentifier string    `json:"host_identifier"`
	Hostname       string    `json:"hostname"`
	Platform       string    `json:"platform"`
	OSName         string    `json:"os_name,omitempty"`
	OSVersion      string    `json:"os_version,omitempty"`
	OsqueryVersion string    `json:"osquery_version,omitempty"`
	HardwareVendor string    `json:"hardware_vendor,omitempty"`
	HardwareModel  string    `json:"hardware_model,omitempty"`
	Serial         string    `json:"serial,omitempty"`
	CPU            string    `json:"cpu,omitempty"`
	MemoryBytes    int64     `json:"memory_bytes,omitempty"`
	IPs            []string  `json:"ips,omitempty"`
	Address        string    `json:"address,omitempty"`
	TokenID        string    `json:"token_id,omitempty"`
	EnrolledAt     time.Time `json:"enrolled_at"`
	LastSeen       time.Time `json:"last_seen"`
	// ConfigAt is when the host last fetched its configuration, and
	// ConfigHash which one.
	ConfigAt   time.Time `json:"config_at,omitzero"`
	ConfigHash string    `json:"config_hash,omitempty"`
	// LastError is osquery's latest warning or error about itself, and
	// LastErrorAt when it said it.
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitzero"`
}

// Settings are what every enrolled host collects. They apply to all hosts
// and reach them at their next configuration fetch (within ConfigRefresh).
type Settings struct {
	// FilePaths are the folders and files watched for changes, per
	// platform, in osquery's pattern syntax: % matches within one folder
	// level and %% matches everything below.
	FilePaths map[string][]string `json:"file_paths"`
	// ExcludePaths are left out of FilePaths.
	ExcludePaths map[string][]string `json:"exclude_paths,omitempty"`
	// InventoryMinutes is how often hosts look at their installed
	// software, accounts, services and startup items for changes.
	InventoryMinutes int `json:"inventory_minutes"`
	// FIM turns file integrity monitoring on.
	FIM bool `json:"fim"`
	// Checks turns the configuration checks on; hosts run them every
	// CheckMinutes and report when a result changes.
	Checks       bool `json:"checks"`
	CheckMinutes int  `json:"check_minutes"`
	// UpdatedBy and UpdatedAt say who saved the settings last.
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// DefaultSettings watches the places attackers change to persist or
// escalate: system configuration, programs, boot files, SSH keys,
// scheduled tasks and startup folders.
func DefaultSettings() Settings {
	return Settings{
		FIM:              true,
		InventoryMinutes: 60,
		Checks:           true,
		CheckMinutes:     60,
		FilePaths: map[string][]string{
			Linux: {
				"/etc/%%", "/bin/%%", "/sbin/%%", "/usr/bin/%%", "/usr/sbin/%%", "/usr/local/bin/%%",
				"/usr/local/sbin/%%", "/boot/%%", "/root/.ssh/%%", "/home/%/.ssh/%%", "/var/spool/cron/%%",
			},
			Windows: {
				`C:\Windows\System32\drivers\etc\%%`,
				`C:\Windows\System32\Tasks\%%`,
				`C:\Windows\System32\GroupPolicy\%%`,
				`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\%%`,
				`C:\Users\%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\%%`,
			},
			Darwin: {
				"/etc/%%", "/Library/LaunchDaemons/%%", "/Library/LaunchAgents/%%", "/Users/%/Library/LaunchAgents/%%",
				"/usr/local/bin/%%", "/Users/%/.ssh/%%", "/var/root/.ssh/%%",
			},
		},
		ExcludePaths: map[string][]string{
			Linux: {"/etc/mtab", "/etc/ld.so.cache"},
		},
	}
}

// Limits on settings, since every host gets them.
const (
	maxPaths       = 200
	maxPathLen     = 512
	minInventory   = 5
	maxInventory   = 24 * 60
	maxSQLBytes    = 16 << 10
	maxResultRows  = 1000
	maxValueBytes  = 4 << 10
	liveQueryLife  = 10 * time.Minute
	maxLiveTargets = 5000
)

// Validate checks settings an admin saved and tidies them: paths trimmed,
// empty lines and duplicates dropped.
func (s *Settings) Validate() error {
	if s.InventoryMinutes < minInventory || s.InventoryMinutes > maxInventory {
		return inputErrorf("inventory_minutes must be from %d to %d", minInventory, maxInventory)
	}
	if s.CheckMinutes < minInventory || s.CheckMinutes > maxInventory {
		return inputErrorf("check_minutes must be from %d to %d", minInventory, maxInventory)
	}
	clean := func(name string, in map[string][]string) (map[string][]string, error) {
		out := map[string][]string{}
		for p, paths := range in {
			if p != Linux && p != Windows && p != Darwin {
				return nil, inputErrorf("%s: unknown platform %q; use linux, windows or darwin", name, p)
			}
			seen := map[string]bool{}
			for _, raw := range paths {
				v := strings.TrimSpace(raw)
				if v == "" || seen[v] {
					continue
				}
				if len(v) > maxPathLen {
					return nil, inputErrorf("%s: a %s path is longer than %d characters", name, p, maxPathLen)
				}
				if strings.ContainsAny(v, "\x00\r\n\"") {
					return nil, inputErrorf("%s: %q has a character a path cannot have", name, v)
				}
				abs := strings.HasPrefix(v, "/")
				if p == Windows {
					abs = len(v) >= 3 && v[1] == ':' && (v[2] == '\\' || v[2] == '/')
				}
				if !abs {
					return nil, inputErrorf("%s: %q is not a full path (on %s, start with %s)", name, v, p, map[bool]string{true: `a drive such as C:\`, false: "/"}[p == Windows])
				}
				seen[v] = true
				out[p] = append(out[p], v)
			}
			if len(out[p]) > maxPaths {
				return nil, inputErrorf("%s: at most %d paths per platform", name, maxPaths)
			}
		}
		return out, nil
	}
	var err error
	if s.FilePaths, err = clean("file_paths", s.FilePaths); err != nil {
		return err
	}
	if s.ExcludePaths, err = clean("exclude_paths", s.ExcludePaths); err != nil {
		return err
	}
	return nil
}

// LiveQuery is SQL an admin sent to hosts to run once, now.
type LiveQuery struct {
	ID        string    `json:"id"`
	SQL       string    `json:"sql"`
	Targets   []string  `json:"targets"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Result is one host's answer to a live query.
type Result struct {
	QueryID  string              `json:"query_id"`
	NodeID   string              `json:"node_id"`
	Hostname string              `json:"hostname"`
	State    string              `json:"state"` // sent, done or error
	Error    string              `json:"error,omitempty"`
	Rows     []map[string]string `json:"rows,omitempty"`
	// Truncated says rows or values were cut to fit.
	Truncated bool      `json:"truncated,omitempty"`
	SentAt    time.Time `json:"sent_at"`
	DoneAt    time.Time `json:"done_at,omitzero"`
}

// Result states.
const (
	StateSent  = "sent"
	StateDone  = "done"
	StateError = "error"
)

// Store keeps hosts, settings and live queries in <prefix>_endpoints.
type Store struct {
	Docs  Docs
	Index string
	Now   func() time.Time

	mu       sync.Mutex
	nodes    map[string]cachedNode // by node ID
	settings *cachedSettings
	active   *cachedQueries
	seen     map[string]seenNote // last contact not yet written
}

type cachedNode struct {
	node    *Node // nil: no such node
	fetched time.Time
}

type cachedSettings struct {
	s       Settings
	fetched time.Time
}

type cachedQueries struct {
	qs      []LiveQuery
	fetched time.Time
}

type seenNote struct {
	at      time.Time
	address string
}

// How long this server trusts what it read about a node, the settings and
// the running live queries before reading them again. Another server's
// removal of a host takes up to nodeTTL to reach this one.
const (
	nodeTTL     = 30 * time.Second
	settingsTTL = 15 * time.Second
	queriesTTL  = 2 * time.Second
	maxCached   = 100000
)

// ErrNotFound is a node, query or result that is not there.
var ErrNotFound = errors.New("not found")

// InputError is a request that cannot be done as asked: bad settings or
// a live query with no SQL or no hosts.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

func inputErrorf(format string, args ...any) error {
	return &InputError{Msg: fmt.Sprintf(format, args...)}
}

// ErrBlocked is an enrollment from a host an admin blocked.
var ErrBlocked = errors.New("this host was blocked on the Endpoints page; an admin can unblock it there")

// NewStore returns a store using index "<prefix>_endpoints".
func NewStore(d Docs, prefix string) *Store {
	return &Store{Docs: d, Index: prefix + "_endpoints"}
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func properties() map[string]any {
	kw := map[string]any{"type": "keyword"}
	date := map[string]any{"type": "date"}
	return map[string]any{
		"kind": kw, "id": kw, "host_identifier": kw, "hostname": kw, "platform": kw, "token_id": kw,
		"query_id": kw, "node_id": kw, "state": kw, "targets": kw,
		"last_seen": date, "enrolled_at": date, "expires_at": date, "created_at": date, "sent_at": date,
	}
}

// EnsureIndex creates the endpoints index if it is missing. Any server
// may, at any time.
func (s *Store) EnsureIndex(ctx context.Context) error {
	body := map[string]any{
		"settings": map[string]any{"number_of_shards": 1, "auto_expand_replicas": "0-1", "refresh_interval": "1s"},
		"mappings": map[string]any{"dynamic": "false", "properties": properties()},
	}
	err := s.Docs.Do(ctx, http.MethodPut, "/"+url.PathEscape(s.Index), body, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == http.StatusBadRequest && strings.Contains(oe.Body, "resource_already_exists_exception") {
		return nil
	}
	return err
}

// NewNodeKey returns a new node key and the ID of the node it belongs to.
// Only the key's hash is stored: the ID is its first 20 hex digits, so a
// key leads straight to its document with no search.
func NewNodeKey() (key, id string) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	key = hex.EncodeToString(b)
	return key, NodeID(key)
}

// NodeID is the node ID a node key belongs to.
func NodeID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:10])
}

func nodeDocID(id string) string { return "node:" + id }

func blockedDocID(hostIdentifier string) string {
	sum := sha256.Sum256([]byte(hostIdentifier))
	return "blocked:" + hex.EncodeToString(sum[:10])
}

type nodeDoc struct {
	Kind string `json:"kind"`
	*Node
}

// Enroll records a newly enrolled host. A host enrolling again (osquery
// reinstalled, or its key removed) replaces its earlier record, keeping
// nothing but the row.
func (s *Store) Enroll(ctx context.Context, n *Node) error {
	if n.HostIdentifier != "" {
		_, _, found, err := s.Docs.Get(ctx, s.Index, blockedDocID(n.HostIdentifier))
		if err != nil {
			return err
		}
		if found {
			return ErrBlocked
		}
		old, err := s.Docs.SearchDocs(ctx, s.Index, map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{"kind": kindNode}},
			map[string]any{"term": map[string]any{"host_identifier": n.HostIdentifier}},
		}}})
		if err != nil {
			return err
		}
		for _, d := range old {
			if err := s.Docs.DeleteIf(ctx, s.Index, d.ID, d.Version, false); err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict) {
				return err
			}
			s.forget(strings.TrimPrefix(d.ID, "node:"))
			s.dropChecks(ctx, strings.TrimPrefix(d.ID, "node:"))
		}
	}
	if _, err := s.Docs.Create(ctx, s.Index, nodeDocID(n.ID), nodeDoc{Kind: kindNode, Node: n}, true); err != nil {
		return err
	}
	s.mu.Lock()
	s.cacheNode(n.ID, n)
	s.mu.Unlock()
	return nil
}

func (s *Store) cacheNode(id string, n *Node) {
	if s.nodes == nil {
		s.nodes = map[string]cachedNode{}
	}
	if len(s.nodes) >= maxCached {
		clear(s.nodes)
	}
	s.nodes[id] = cachedNode{node: n, fetched: s.now()}
}

func (s *Store) forget(id string) {
	s.mu.Lock()
	delete(s.nodes, id)
	s.mu.Unlock()
}

// Authenticate returns the node a node key belongs to, or ErrNotFound.
// Answers, also "no such node", are cached for a short while, so a host
// polling every few seconds costs OpenSearch one read per nodeTTL.
func (s *Store) Authenticate(ctx context.Context, key string) (*Node, error) {
	if len(key) != 64 {
		return nil, ErrNotFound
	}
	id := NodeID(key)
	s.mu.Lock()
	c, ok := s.nodes[id]
	s.mu.Unlock()
	if ok && s.now().Sub(c.fetched) < nodeTTL {
		if c.node == nil {
			return nil, ErrNotFound
		}
		return c.node, nil
	}
	n, err := s.node(ctx, id)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	s.mu.Lock()
	s.cacheNode(id, n)
	s.mu.Unlock()
	if n == nil {
		return nil, ErrNotFound
	}
	return n, nil
}

func (s *Store) node(ctx context.Context, id string) (*Node, error) {
	src, _, found, err := s.Docs.Get(ctx, s.Index, nodeDocID(id))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}
	var n Node
	if err := json.Unmarshal(src, &n); err != nil {
		return nil, err
	}
	return &n, nil
}

// Node returns one host.
func (s *Store) Node(ctx context.Context, id string) (*Node, error) { return s.node(ctx, id) }

// Nodes returns every host, by host name.
func (s *Store) Nodes(ctx context.Context) ([]*Node, error) {
	docs, err := s.Docs.SearchDocs(ctx, s.Index, map[string]any{"term": map[string]any{"kind": kindNode}})
	if err != nil {
		return nil, err
	}
	out := make([]*Node, 0, len(docs))
	s.mu.Lock()
	for _, d := range docs {
		var n Node
		if json.Unmarshal(d.Source, &n) != nil || n.ID == "" {
			continue
		}
		// Contact this server noted but has not written yet.
		if seen, ok := s.seen[n.ID]; ok && seen.at.After(n.LastSeen) {
			n.LastSeen = seen.at
			if seen.address != "" {
				n.Address = seen.address
			}
		}
		out = append(out, &n)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].Hostname), strings.ToLower(out[j].Hostname)
		if a != b {
			return a < b
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// Remove deletes a host's record, which makes its node key invalid. A
// host still running osquery enrolls again at its next contact unless
// block is set: then its hardware ID is refused until Unblock.
func (s *Store) Remove(ctx context.Context, id string, block bool, by string) (*Node, error) {
	src, v, found, err := s.Docs.Get(ctx, s.Index, nodeDocID(id))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}
	var n Node
	if err := json.Unmarshal(src, &n); err != nil {
		return nil, err
	}
	if block && n.HostIdentifier != "" {
		_, err := s.Docs.Create(ctx, s.Index, blockedDocID(n.HostIdentifier), map[string]any{
			"kind": kindBlocked, "host_identifier": n.HostIdentifier, "hostname": n.Hostname,
			"blocked_by": by, "blocked_at": s.now().UTC(),
		}, true)
		if err != nil && !errors.Is(err, store.ErrExists) {
			return nil, err
		}
	}
	if err := s.Docs.DeleteIf(ctx, s.Index, nodeDocID(id), v, true); err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	s.forget(id)
	s.dropChecks(ctx, id)
	return &n, nil
}

// Blocked is a host refused enrollment.
type Blocked struct {
	HostIdentifier string    `json:"host_identifier"`
	Hostname       string    `json:"hostname"`
	BlockedBy      string    `json:"blocked_by"`
	BlockedAt      time.Time `json:"blocked_at"`
}

// BlockedHosts lists the hosts refused enrollment.
func (s *Store) BlockedHosts(ctx context.Context) ([]Blocked, error) {
	docs, err := s.Docs.SearchDocs(ctx, s.Index, map[string]any{"term": map[string]any{"kind": kindBlocked}})
	if err != nil {
		return nil, err
	}
	out := []Blocked{}
	for _, d := range docs {
		var b Blocked
		if json.Unmarshal(d.Source, &b) == nil && b.HostIdentifier != "" {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out, nil
}

// Unblock lets a blocked host enroll again.
func (s *Store) Unblock(ctx context.Context, hostIdentifier string) error {
	id := blockedDocID(hostIdentifier)
	_, v, found, err := s.Docs.Get(ctx, s.Index, id)
	if err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}
	if err := s.Docs.DeleteIf(ctx, s.Index, id, v, true); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// RevokeToken removes every host that enrolled with a token, for when a
// token is revoked: their node keys stop working, and they cannot enroll
// again without a valid token.
func (s *Store) RevokeToken(ctx context.Context, tokenID string) (int, error) {
	docs, err := s.Docs.SearchDocs(ctx, s.Index, map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"term": map[string]any{"kind": kindNode}},
		map[string]any{"term": map[string]any{"token_id": tokenID}},
	}}})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, d := range docs {
		if err := s.Docs.DeleteIf(ctx, s.Index, d.ID, d.Version, false); err == nil {
			n++
		} else if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict) {
			return n, err
		}
		s.forget(strings.TrimPrefix(d.ID, "node:"))
		s.dropChecks(ctx, strings.TrimPrefix(d.ID, "node:"))
	}
	return n, nil
}

// Seen notes that a host made contact. Contact is written in bulk by
// Flush, so a host polling every few seconds does not write each time.
func (s *Store) Seen(n *Node, address string) {
	now := s.now().UTC()
	s.mu.Lock()
	if s.seen == nil {
		s.seen = map[string]seenNote{}
	}
	if len(s.seen) < maxCached {
		s.seen[n.ID] = seenNote{at: now, address: address}
	}
	s.mu.Unlock()
}

// Flush writes the contact noted since the last flush.
func (s *Store) Flush(ctx context.Context) error {
	s.mu.Lock()
	seen := s.seen
	s.seen = nil
	s.mu.Unlock()
	var first error
	for id, note := range seen {
		fields := map[string]any{"last_seen": note.at}
		if note.address != "" {
			fields["address"] = note.address
		}
		if _, err := s.Docs.Update(ctx, s.Index, nodeDocID(id), fields, false); err != nil && !errors.Is(err, store.ErrNotFound) && first == nil {
			first = err
		}
	}
	return first
}

// Run flushes contact every interval until ctx ends.
func (s *Store) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.Flush(fctx)
			cancel()
			return
		case <-t.C:
			_ = s.Flush(ctx)
		}
	}
}

// update changes some fields of a node right away.
func (s *Store) update(ctx context.Context, n *Node, fields map[string]any) error {
	_, err := s.Docs.Update(ctx, s.Index, nodeDocID(n.ID), fields, false)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

// NoteConfig records which configuration a host fetched, when it changed.
func (s *Store) NoteConfig(ctx context.Context, n *Node, hash string) error {
	if n.ConfigHash == hash && s.now().Sub(n.ConfigAt) < time.Hour {
		return nil
	}
	now := s.now().UTC()
	if err := s.update(ctx, n, map[string]any{"config_hash": hash, "config_at": now}); err != nil {
		return err
	}
	s.mu.Lock()
	c := *n
	c.ConfigHash, c.ConfigAt = hash, now
	s.cacheNode(n.ID, &c)
	s.mu.Unlock()
	return nil
}

// NoteError records osquery's latest warning or error about itself.
func (s *Store) NoteError(ctx context.Context, n *Node, msg string) error {
	if len(msg) > 500 {
		msg = msg[:500]
	}
	return s.update(ctx, n, map[string]any{"last_error": msg, "last_error_at": s.now().UTC()})
}

// NoteIPs records a host's addresses.
func (s *Store) NoteIPs(ctx context.Context, n *Node, ips []string) error {
	sort.Strings(ips)
	if len(ips) > 32 {
		ips = ips[:32]
	}
	if strings.Join(ips, ",") == strings.Join(n.IPs, ",") {
		return nil
	}
	if err := s.update(ctx, n, map[string]any{"ips": ips}); err != nil {
		return err
	}
	s.mu.Lock()
	c := *n
	c.IPs = ips
	s.cacheNode(n.ID, &c)
	s.mu.Unlock()
	return nil
}

// ---- configuration checks ----

func checksDocID(nodeID string) string { return "chk:" + nodeID }

// HostChecks is one host's latest configuration check results.
type HostChecks struct {
	NodeID  string                 `json:"node_id"`
	Results map[string]CheckResult `json:"results"`
}

// SaveChecks merges new or changed check results into the host's latest
// results.
func (s *Store) SaveChecks(ctx context.Context, n *Node, rs []CheckResult) error {
	id := checksDocID(n.ID)
	for try := 0; try < 10; try++ {
		src, v, found, err := s.Docs.Get(ctx, s.Index, id)
		if err != nil {
			return err
		}
		hc := HostChecks{NodeID: n.ID, Results: map[string]CheckResult{}}
		if found {
			_ = json.Unmarshal(src, &hc)
			if hc.Results == nil {
				hc.Results = map[string]CheckResult{}
			}
		}
		for _, r := range rs {
			if old, ok := hc.Results[r.ID]; !ok || !r.At.Before(old.At) {
				hc.Results[r.ID] = r
			}
		}
		body := struct {
			Kind string `json:"kind"`
			HostChecks
		}{kindChecks, hc}
		if found {
			_, err = s.Docs.PutIf(ctx, s.Index, id, body, v, false)
		} else {
			_, err = s.Docs.Create(ctx, s.Index, id, body, false)
		}
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrExists) {
			continue
		}
		return err
	}
	return store.ErrConflict
}

// dropChecks deletes a removed host's check results.
func (s *Store) dropChecks(ctx context.Context, nodeID string) {
	if _, v, found, err := s.Docs.Get(ctx, s.Index, checksDocID(nodeID)); err == nil && found {
		_ = s.Docs.DeleteIf(ctx, s.Index, checksDocID(nodeID), v, false)
	}
}

// Checks returns every host's latest check results, by node ID.
func (s *Store) Checks(ctx context.Context) (map[string]HostChecks, error) {
	docs, err := s.Docs.SearchDocs(ctx, s.Index, map[string]any{"term": map[string]any{"kind": kindChecks}})
	if err != nil {
		return nil, err
	}
	out := map[string]HostChecks{}
	for _, d := range docs {
		var hc HostChecks
		if json.Unmarshal(d.Source, &hc) == nil && hc.NodeID != "" {
			out[hc.NodeID] = hc
		}
	}
	return out, nil
}

// HostCheckResults returns one host's latest check results.
func (s *Store) HostCheckResults(ctx context.Context, nodeID string) (map[string]CheckResult, error) {
	src, _, found, err := s.Docs.Get(ctx, s.Index, checksDocID(nodeID))
	if err != nil || !found {
		return map[string]CheckResult{}, err
	}
	var hc HostChecks
	if err := json.Unmarshal(src, &hc); err != nil {
		return nil, err
	}
	return hc.Results, nil
}

// ---- settings ----

const settingsID = "settings"

// Settings returns the saved settings, or the defaults.
func (s *Store) Settings(ctx context.Context) (Settings, store.Version, error) {
	src, v, found, err := s.Docs.Get(ctx, s.Index, settingsID)
	if err != nil {
		return Settings{}, store.Version{}, err
	}
	if !found {
		return DefaultSettings(), store.Version{}, nil
	}
	var doc struct {
		Settings Settings `json:"settings"`
	}
	if err := json.Unmarshal(src, &doc); err != nil {
		return Settings{}, store.Version{}, err
	}
	return doc.Settings, v, nil
}

// CachedSettings is Settings, read again at most every settingsTTL: hosts
// fetch their configuration often.
func (s *Store) CachedSettings(ctx context.Context) (Settings, error) {
	s.mu.Lock()
	c := s.settings
	s.mu.Unlock()
	if c != nil && s.now().Sub(c.fetched) < settingsTTL {
		return c.s, nil
	}
	set, _, err := s.Settings(ctx)
	if err != nil {
		if c != nil {
			return c.s, nil // keep serving the last known settings
		}
		return Settings{}, err
	}
	s.mu.Lock()
	s.settings = &cachedSettings{s: set, fetched: s.now()}
	s.mu.Unlock()
	return set, nil
}

// SaveSettings saves settings read at version v (zero: never saved):
// store.ErrConflict when someone saved since.
func (s *Store) SaveSettings(ctx context.Context, set Settings, v store.Version) error {
	if err := set.Validate(); err != nil {
		return err
	}
	set.UpdatedAt = s.now().UTC()
	body := map[string]any{"kind": kindSettings, "settings": set}
	var err error
	if v.IsZero() {
		_, err = s.Docs.Create(ctx, s.Index, settingsID, body, true)
		if errors.Is(err, store.ErrExists) {
			err = store.ErrConflict
		}
	} else {
		_, err = s.Docs.PutIf(ctx, s.Index, settingsID, body, v, true)
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.settings = &cachedSettings{s: set, fetched: s.now()}
	s.mu.Unlock()
	return nil
}

// ---- live queries ----

// NewLiveQuery records SQL for hosts to run at their next poll.
func (s *Store) NewLiveQuery(ctx context.Context, sql string, targets []string, by string) (*LiveQuery, error) {
	sql = strings.TrimSpace(sql)
	switch {
	case sql == "":
		return nil, inputErrorf("write a query first")
	case len(sql) > maxSQLBytes:
		return nil, inputErrorf("the query is longer than %d KB", maxSQLBytes>>10)
	case len(targets) == 0:
		return nil, inputErrorf("pick at least one host")
	case len(targets) > maxLiveTargets:
		return nil, inputErrorf("a live query can go to at most %d hosts", maxLiveTargets)
	}
	b := make([]byte, 9)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	now := s.now().UTC()
	q := &LiveQuery{ID: hex.EncodeToString(b), SQL: sql, Targets: targets, CreatedBy: by, CreatedAt: now, ExpiresAt: now.Add(liveQueryLife)}
	if _, err := s.Docs.Create(ctx, s.Index, "lq:"+q.ID, struct {
		Kind string `json:"kind"`
		*LiveQuery
	}{kindQuery, q}, true); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.active = nil // read again, with this one
	s.mu.Unlock()
	return q, nil
}

// LiveQuery returns a live query and the answers so far, by host name.
func (s *Store) LiveQuery(ctx context.Context, id string) (*LiveQuery, []Result, error) {
	src, _, found, err := s.Docs.Get(ctx, s.Index, "lq:"+id)
	if err != nil {
		return nil, nil, err
	}
	if !found {
		return nil, nil, ErrNotFound
	}
	var q LiveQuery
	if err := json.Unmarshal(src, &q); err != nil {
		return nil, nil, err
	}
	docs, err := s.Docs.SearchDocs(ctx, s.Index, map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"term": map[string]any{"kind": kindResult}},
		map[string]any{"term": map[string]any{"query_id": id}},
	}}})
	if err != nil {
		return nil, nil, err
	}
	res := make([]Result, 0, len(docs))
	for _, d := range docs {
		var r Result
		if json.Unmarshal(d.Source, &r) == nil {
			res = append(res, r)
		}
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Hostname < res[j].Hostname })
	return &q, res, nil
}

// activeQueries returns the live queries that have not expired, read
// again at most every queriesTTL.
func (s *Store) activeQueries(ctx context.Context) ([]LiveQuery, error) {
	s.mu.Lock()
	c := s.active
	s.mu.Unlock()
	now := s.now()
	if c != nil && now.Sub(c.fetched) < queriesTTL {
		return c.qs, nil
	}
	docs, err := s.Docs.SearchDocs(ctx, s.Index, map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"term": map[string]any{"kind": kindQuery}},
		map[string]any{"range": map[string]any{"expires_at": map[string]any{"gt": now.UTC().Format(time.RFC3339Nano)}}},
	}}})
	if err != nil {
		return nil, err
	}
	qs := make([]LiveQuery, 0, len(docs))
	for _, d := range docs {
		var q LiveQuery
		if json.Unmarshal(d.Source, &q) == nil && q.ExpiresAt.After(now) {
			qs = append(qs, q)
		}
	}
	s.mu.Lock()
	s.active = &cachedQueries{qs: qs, fetched: now}
	s.mu.Unlock()
	return qs, nil
}

func resultDocID(queryID, nodeID string) string { return "lqr:" + queryID + ":" + nodeID }

// Pending returns the live queries for a host to run now, and marks them
// sent. Marking creates the host's result document, which only one
// server can do, so a host polling several servers runs each query once.
func (s *Store) Pending(ctx context.Context, n *Node) (map[string]string, error) {
	qs, err := s.activeQueries(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, q := range qs {
		if !containsString(q.Targets, n.ID) {
			continue
		}
		r := Result{QueryID: q.ID, NodeID: n.ID, Hostname: n.Hostname, State: StateSent, SentAt: s.now().UTC()}
		_, err := s.Docs.Create(ctx, s.Index, resultDocID(q.ID, n.ID), struct {
			Kind string `json:"kind"`
			Result
		}{kindResult, r}, false)
		if errors.Is(err, store.ErrExists) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[q.ID] = q.SQL
	}
	return out, nil
}

// SaveResult records a host's answer to a live query it was sent.
func (s *Store) SaveResult(ctx context.Context, n *Node, queryID string, rows []map[string]string, status int, msg string) error {
	src, v, found, err := s.Docs.Get(ctx, s.Index, resultDocID(queryID, n.ID))
	if err != nil {
		return err
	}
	if !found {
		return ErrNotFound // never sent to this host
	}
	var r Result
	if err := json.Unmarshal(src, &r); err != nil {
		return err
	}
	r.DoneAt = s.now().UTC()
	r.State = StateDone
	if status != 0 || msg != "" && len(rows) == 0 {
		r.State = StateError
		r.Error = msg
		if r.Error == "" {
			r.Error = fmt.Sprintf("osquery could not run the query (status %d)", status)
		}
		if len(r.Error) > 1000 {
			r.Error = r.Error[:1000]
		}
	}
	r.Rows, r.Truncated = capRows(rows)
	_, err = s.Docs.PutIf(ctx, s.Index, resultDocID(queryID, n.ID), struct {
		Kind string `json:"kind"`
		Result
	}{kindResult, r}, v, true)
	if errors.Is(err, store.ErrConflict) {
		return nil // another server stored an answer first
	}
	return err
}

// capRows keeps at most maxResultRows rows and maxValueBytes per value.
func capRows(rows []map[string]string) ([]map[string]string, bool) {
	cut := false
	if len(rows) > maxResultRows {
		rows, cut = rows[:maxResultRows], true
	}
	for _, row := range rows {
		for k, v := range row {
			if len(v) > maxValueBytes {
				row[k], cut = v[:maxValueBytes], true
			}
		}
	}
	return rows, cut
}

func containsString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
