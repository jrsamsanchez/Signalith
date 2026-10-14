package agenttokens

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Document kinds and ids in the runtime index. When the shared, signed
// <prefix>_config index of the multi-server design exists, these move
// there with the same bodies; they hold no secret, only fingerprints.
const (
	kindToken  = "agent_token"
	kindLegacy = "agent_token_legacy"
	kindWatch  = "agent_token_watch"
	kindUse    = "agent_token_use"

	legacyDocID = "agenttokens:legacy"
	watchDocID  = "agenttokens:watch"
)

func tokenDocID(id string) string     { return "agenttoken:" + id }
func useDocID(id, node string) string { return "agenttokenuse:" + id + ":" + node }
func validID(id string) bool          { return len(id) == 12 && isHex(id) }
func timePtr(t time.Time) *time.Time  { return &t }
func lowerName(s string) string       { return strings.ToLower(s) }
func isActive(d *tokenDoc) bool       { return d.State == StateActive }
func jitter(min, max time.Duration) time.Duration {
	return min + time.Duration(mrand.Int64N(int64(max-min)))
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Token states.
const (
	StateActive  = "active"
	StateRevoked = "revoked"
)

// tokenDoc is agenttoken:<id>.
type tokenDoc struct {
	Kind      string     `json:"kind"`
	ID        string     `json:"id"`
	State     string     `json:"state"`
	Name      string     `json:"name"`
	Purpose   string     `json:"purpose"`
	Hash      string     `json:"hash"`
	Hint      string     `json:"hint"`
	At        time.Time  `json:"at"`
	CreatedBy string     `json:"created_by"`
	RevokedAt *time.Time `json:"revoked_at"`
	RevokedBy string     `json:"revoked_by"`
	RenamedAt *time.Time `json:"renamed_at"`
	RenamedBy string     `json:"renamed_by"`
}

// refusal is a shared token an admin stopped accepting.
type refusal struct {
	At time.Time `json:"at"`
	By string    `json:"by"`
}

// legacyDoc is agenttokens:legacy. IDKey is the key shared tokens' IDs
// are made with (see legacyID); Refused is keyed by those IDs.
type legacyDoc struct {
	Kind    string             `json:"kind"`
	IDKey   string             `json:"id_key,omitempty"`
	Refused map[string]refusal `json:"refused"`
}

// legacyID is the ID a shared token is listed and recorded under: an
// HMAC-SHA256 of it under a random key every server reads from
// OpenSearch. Shared tokens are often typed in by people, so an ID made
// with a plain hash would let anyone who can read events test guesses
// offline; without the key it tells nothing.
func legacyID(key []byte, secret string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("signalith shared agent token id\x00"))
	m.Write([]byte(secret))
	return hex.EncodeToString(m.Sum(nil))[:12]
}

// useDoc is agenttokenuse:<id>:<node>: how one server saw a token used.
type useDoc struct {
	Kind     string    `json:"kind"`
	Agent    string    `json:"agent"`
	Node     string    `json:"node"`
	LastSeen time.Time `json:"last_seen"`
	Address  string    `json:"address"`
	Events1h int64     `json:"events_1h"`
}

// snapshot is the tokens as last read, never changed once made: ingest
// reads it without a lock.
type snapshot struct {
	loaded  bool
	idKey   []byte
	tokens  map[string]*tokenDoc
	refused map[string]refusal
}

func (s *snapshot) clone() *snapshot {
	n := &snapshot{loaded: s.loaded, idKey: s.idKey, tokens: make(map[string]*tokenDoc, len(s.tokens)+1), refused: make(map[string]refusal, len(s.refused))}
	for k, v := range s.tokens {
		n.tokens[k] = v
	}
	for k, v := range s.refused {
		n.refused[k] = v
	}
	return n
}

// Legacy is a shared token from the configuration.
type Legacy struct {
	Secret string
	// Source is where it is set: signalith.yaml, SIGNALITH_INGEST_TOKEN or
	// SIGNALITH_INGEST_TOKEN_FILE.
	Source string
	// Public is true for the example token of an older docker-compose.yml.
	Public bool
}

// Registry keeps the agent tokens of every server that shares an
// OpenSearch. See the package comment.
type Registry struct {
	// Client reaches OpenSearch; nil keeps no tokens of its own (only the
	// shared ones from the configuration work).
	Client *store.Client
	// Prefix is the index prefix: the tokens are in <prefix>_runtime.
	Prefix string
	// Node names this server in the usage documents; nil uses the host
	// name.
	Node func() string
	// Legacy returns the shared tokens of the configuration in use.
	Legacy func() []Legacy
	Log    *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Poll is how often Run looks for changes (default 2s), Reload how
	// often it reads everything again anyway (5m) and Flush how often it
	// writes how tokens were used (60s).
	Poll, Reload, Flush time.Duration

	snap     atomic.Pointer[snapshot]
	writeMu  sync.Mutex // one change of the snapshot at a time
	gen      uint64     // changes made by apply, under writeMu
	localKey struct {
		once sync.Once
		key  []byte
	}
	ensured  atomic.Bool
	hooksMu  sync.Mutex
	onRevoke []func(ctx context.Context, tokenID string) (int, error)

	useMu sync.Mutex
	uses  map[string]*use

	logMu    sync.Mutex
	lastFail time.Time
}

func (r *Registry) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Registry) index() string {
	p := r.Prefix
	if p == "" {
		p = "signalith"
	}
	return cluster.RuntimeIndex(p)
}

func (r *Registry) node() string {
	if r.Node != nil {
		if n := r.Node(); n != "" {
			return n
		}
	}
	h, _ := os.Hostname()
	if h == "" {
		h = "local"
	}
	return h
}

func (r *Registry) legacy() []Legacy {
	if r == nil || r.Legacy == nil {
		return nil
	}
	return r.Legacy()
}

func (r *Registry) current() *snapshot {
	if r == nil {
		return &snapshot{}
	}
	if s := r.snap.Load(); s != nil {
		return s
	}
	return &snapshot{}
}

// Loaded reports whether the tokens have been read from OpenSearch since
// the process started.
func (r *Registry) Loaded() bool { return r.current().loaded }

// OnRevoke adds a function called once, by the server or command that
// revoked a token or stopped accepting a shared one, after the change was
// saved: osquery hosts enrolled with it are removed. It returns how many
// hosts it removed.
func (r *Registry) OnRevoke(f func(ctx context.Context, tokenID string) (int, error)) {
	r.hooksMu.Lock()
	defer r.hooksMu.Unlock()
	r.onRevoke = append(r.onRevoke, f)
}

func (r *Registry) revoked(ctx context.Context, id string) int {
	r.hooksMu.Lock()
	hooks := append([]func(context.Context, string) (int, error){}, r.onRevoke...)
	r.hooksMu.Unlock()
	n := 0
	for _, h := range hooks {
		k, err := h(ctx, id)
		n += k
		if err != nil && r.Log != nil {
			r.Log.Error("a revoked agent token's osquery hosts could not all be removed; they are refused anyway", "token_id", id, "err", err)
		}
	}
	return n
}

// ---- checking tokens ----

// Result is what Check found.
type Result int

const (
	// Unknown: not a token this server accepts.
	Unknown Result = iota
	// Valid: an active agent token, or an accepted shared one.
	Valid
	// Revoked: an agent token that was revoked.
	Revoked
	// Refused: a shared token an admin stopped accepting.
	Refused
	// NotLoaded: an agent token or a shared one, before the tokens were
	// first read from OpenSearch. Shared tokens wait too, since an admin
	// may have stopped accepting one, and their IDs need the key kept
	// there.
	NotLoaded
)

// Identity is who sent with a token: its ID and its name now.
type Identity struct {
	ID   string
	Name string
	// Legacy is true for a shared token from the configuration, and
	// Public for the example token of an older docker-compose.yml.
	Legacy, Public bool
}

// Check finds the token secret. Agent tokens are compared by their
// SHA-256 in constant time; shared tokens are compared with each one in
// the configuration in constant time. Both give NotLoaded until the
// tokens were first read from OpenSearch.
func (r *Registry) Check(secret string) (Identity, Result) {
	if secret == "" {
		return Identity{}, Unknown
	}
	if strings.HasPrefix(secret, Prefix) {
		if !IsToken(secret) {
			return Identity{}, Unknown
		}
		snap := r.current()
		if !snap.loaded {
			return Identity{}, NotLoaded
		}
		sum := sha256.Sum256([]byte(secret))
		h := hex.EncodeToString(sum[:])
		d := snap.tokens[h[:12]]
		if d == nil || subtle.ConstantTimeCompare([]byte(h), []byte(d.Hash)) != 1 {
			return Identity{}, Unknown
		}
		id := Identity{ID: d.ID, Name: d.Name}
		if !isActive(d) {
			return id, Revoked
		}
		return id, Valid
	}
	match := -1
	legacy := r.legacy()
	for i, l := range legacy {
		// Every one is compared, so the time taken doesn't tell which.
		if subtle.ConstantTimeCompare([]byte(l.Secret), []byte(secret)) == 1 && match < 0 {
			match = i
		}
	}
	if match < 0 {
		return Identity{}, Unknown
	}
	snap := r.current()
	key := r.idKey(snap)
	if key == nil {
		return Identity{Name: "Shared token", Legacy: true, Public: legacy[match].Public}, NotLoaded
	}
	id := legacyID(key, secret)
	ident := Identity{ID: id, Name: LegacyName(id), Legacy: true, Public: legacy[match].Public}
	if _, refused := snap.refused[id]; refused {
		return ident, Refused
	}
	return ident, Valid
}

// idKey is the key shared tokens' IDs are made with, nil until the tokens
// were first read from OpenSearch. With no OpenSearch (tests) the process
// makes its own.
func (r *Registry) idKey(snap *snapshot) []byte {
	if r.Client == nil {
		r.localKey.once.Do(func() {
			k := make([]byte, 32)
			if _, err := rand.Read(k); err == nil {
				r.localKey.key = k
			}
		})
		return r.localKey.key
	}
	if !snap.loaded {
		return nil
	}
	return snap.idKey
}

// findShared returns the shared token of the configuration that the ID id
// names, and its ID as listed. id is either that ID or, for osquery hosts
// enrolled before shared tokens had keyed IDs, IDOf of the token; the
// second is never shown or recorded. listed is "" while the key is not
// known yet.
func (r *Registry) findShared(snap *snapshot, id string) (l Legacy, listed string, ok bool) {
	if !validID(id) {
		return Legacy{}, "", false
	}
	key := r.idKey(snap)
	for _, l := range r.legacy() {
		pub := ""
		if key != nil {
			pub = legacyID(key, l.Secret)
		}
		if pub == id || IDOf(l.Secret) == id {
			return l, pub, true
		}
	}
	return Legacy{}, "", false
}

// LegacyID returns the ID the shared token secret is listed under, "" while
// the tokens have not been read from OpenSearch yet.
func (r *Registry) LegacyID(secret string) string {
	key := r.idKey(r.current())
	if key == nil {
		return ""
	}
	return legacyID(key, secret)
}

// Active reports whether id is an active agent token or an accepted
// shared one. osquery hosts enrolled with any other are refused. Before
// the tokens were first read, a shared token counts as accepted: the hosts
// of one an admin stopped accepting were removed then.
func (r *Registry) Active(id string) bool {
	snap := r.current()
	if d := snap.tokens[id]; d != nil {
		return isActive(d)
	}
	if _, pub, ok := r.findShared(snap, id); ok {
		if pub == "" {
			return true
		}
		_, refused := snap.refused[pub]
		return !refused
	}
	return false
}

// Lookup returns who sends with the token id: an agent token, or a shared
// one by either of its IDs (see findShared), with the ID events record.
// ok is false when id is unknown.
func (r *Registry) Lookup(id string) (Identity, bool) {
	snap := r.current()
	if d := snap.tokens[id]; d != nil {
		return Identity{ID: d.ID, Name: d.Name}, true
	}
	if l, pub, ok := r.findShared(snap, id); ok {
		if pub == "" {
			return Identity{Name: "Shared token", Legacy: true, Public: l.Public}, true
		}
		return Identity{ID: pub, Name: LegacyName(pub), Legacy: true, Public: l.Public}, true
	}
	return Identity{}, false
}

// Name returns the name of the token id, "" when it is unknown.
func (r *Registry) Name(id string) string {
	i, _ := r.Lookup(id)
	return i.Name
}

// ---- loading ----

// errRaced is a Load whose read a change on this server overtook.
var errRaced = errors.New("the agent tokens changed while they were read; they are read again")

// Load reads every token from OpenSearch. When shared tokens are
// configured and the key of their IDs doesn't exist yet, it makes it.
func (r *Registry) Load(ctx context.Context) error {
	if r.Client == nil {
		return errors.New("no OpenSearch to read agent tokens from")
	}
	for try := 0; ; try++ {
		err := r.load(ctx)
		if !errors.Is(err, errRaced) || try >= 2 {
			return err
		}
	}
}

func (r *Registry) load(ctx context.Context) error {
	r.writeMu.Lock()
	gen := r.gen
	r.writeMu.Unlock()
	docs, err := r.Client.SearchDocs(ctx, r.index(), map[string]any{"terms": map[string]any{"kind": []string{kindToken, kindLegacy}}})
	if err != nil {
		return err
	}
	s := &snapshot{loaded: true, tokens: map[string]*tokenDoc{}, refused: map[string]refusal{}}
	for _, d := range docs {
		switch {
		case strings.HasPrefix(d.ID, "agenttoken:"):
			var t tokenDoc
			if json.Unmarshal(d.Source, &t) != nil || !validID(t.ID) || len(t.Hash) != 64 || t.Hash[:12] != t.ID || d.ID != tokenDocID(t.ID) {
				continue
			}
			s.tokens[t.ID] = &t
		case d.ID == legacyDocID:
			var l legacyDoc
			if json.Unmarshal(d.Source, &l) == nil {
				for k, v := range l.Refused {
					s.refused[k] = v
				}
				s.idKey = parseKey(l.IDKey)
			}
		}
	}
	if s.idKey == nil && len(r.legacy()) > 0 {
		k, err := r.makeKey(ctx)
		if err != nil {
			// Agent tokens work; shared ones wait for the key, which Run
			// tries to make again.
			r.failed("the key of shared agent tokens' IDs could not be saved in OpenSearch; shared tokens are refused with \"try again\" until it is", err)
		}
		s.idKey = k
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	if r.gen != gen {
		// A token changed on this server (apply) after the read began:
		// what was read may not have it.
		return errRaced
	}
	r.snap.Store(s)
	return nil
}

func parseKey(s string) []byte {
	k, err := hex.DecodeString(s)
	if err != nil || len(k) != 32 {
		return nil
	}
	return k
}

// makeKey makes the key of shared tokens' IDs, or reads the one another
// server made meanwhile.
func (r *Registry) makeKey(ctx context.Context) ([]byte, error) {
	if err := r.ensureIndex(ctx); err != nil {
		return nil, err
	}
	for try := 0; ; try++ {
		src, v, found, err := r.Client.Get(ctx, r.index(), legacyDocID)
		if err != nil {
			return nil, err
		}
		doc := legacyDoc{Kind: kindLegacy, Refused: map[string]refusal{}}
		if found {
			_ = json.Unmarshal(src, &doc)
			if k := parseKey(doc.IDKey); k != nil {
				return k, nil
			}
			if doc.Refused == nil {
				doc.Refused = map[string]refusal{}
			}
			doc.Kind = kindLegacy
		}
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		doc.IDKey = hex.EncodeToString(k)
		if found {
			_, err = r.Client.PutIf(ctx, r.index(), legacyDocID, &doc, v, true)
		} else {
			_, err = r.Client.Create(ctx, r.index(), legacyDocID, &doc, true)
		}
		if err == nil {
			return k, nil
		}
		if !(store.IsConflict(err) || errors.Is(err, store.ErrExists)) || try >= 9 {
			return nil, err
		}
		if err := sleep(ctx, jitter(10*time.Millisecond, 250*time.Millisecond)); err != nil {
			return nil, err
		}
	}
}

// Run keeps the tokens up to date until ctx ends: it reads them again
// within Poll of any change on any server, and writes how they were used
// every Flush. While OpenSearch can't be reached it keeps the tokens it
// last read.
func (r *Registry) Run(ctx context.Context) {
	poll, reload, flush := r.Poll, r.Reload, r.Flush
	if poll <= 0 {
		poll = 2 * time.Second
	}
	if reload <= 0 {
		reload = 5 * time.Minute
	}
	if flush <= 0 {
		flush = time.Minute
	}
	var seen store.Version
	var seenFound bool
	lastFull := time.Time{}
	lastFlush := time.Now()
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		if r.Client != nil {
			vs, err := r.Client.MGetVersions(ctx, []store.Ref{{Index: r.index(), ID: watchDocID}})
			if err == nil {
				v, found := vs[store.Ref{Index: r.index(), ID: watchDocID}]
				needKey := r.current().idKey == nil && len(r.legacy()) > 0
				if !r.Loaded() || needKey || found != seenFound || !v.Same(seen) || time.Since(lastFull) >= reload {
					if err = r.Load(ctx); err == nil {
						seen, seenFound, lastFull = v, found, time.Now()
					} else if errors.Is(err, errRaced) {
						err = nil // read again at the next tick
					}
				}
			}
			if err != nil && ctx.Err() == nil {
				r.failed("agent tokens could not be read from OpenSearch; the ones read last are used until it answers", err)
			}
			if time.Since(lastFlush) >= flush {
				lastFlush = time.Now()
				r.flushUse(ctx)
			}
		}
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			r.flushUse(fctx)
			cancel()
			return
		case <-t.C:
		}
	}
}

// failed logs at most once a minute.
func (r *Registry) failed(msg string, err error) {
	r.logMu.Lock()
	defer r.logMu.Unlock()
	if r.Log == nil || time.Since(r.lastFail) < time.Minute {
		return
	}
	r.lastFail = time.Now()
	r.Log.Warn(msg, "err", err)
}

// ---- usage ----

// use counts one token's events on this server: per minute for the last
// hour, and the last time and address.
type use struct {
	counts  [60]int64
	minutes [60]int64
	last    time.Time
	addr    string
	dirty   bool
}

func (u *use) events1h(now time.Time) int64 {
	m := now.Unix() / 60
	var n int64
	for i := range u.counts {
		if u.minutes[i] > m-60 && u.minutes[i] <= m {
			n += u.counts[i]
		}
	}
	return n
}

// Note counts events sent with the token id from addr.
func (r *Registry) Note(id, addr string, events int) {
	if r == nil || id == "" {
		return
	}
	now := r.now()
	m := now.Unix() / 60
	r.useMu.Lock()
	defer r.useMu.Unlock()
	if r.uses == nil {
		r.uses = map[string]*use{}
	}
	u := r.uses[id]
	if u == nil {
		if len(r.uses) >= MaxDocs+64 {
			return
		}
		u = &use{}
		r.uses[id] = u
	}
	i := m % 60
	if u.minutes[i] != m {
		u.minutes[i], u.counts[i] = m, 0
	}
	u.counts[i] += int64(events)
	u.last, u.addr, u.dirty = now, addr, true
}

// flushUse writes one usage document per token used since the last flush.
func (r *Registry) flushUse(ctx context.Context) {
	if r.Client == nil {
		return
	}
	now := r.now()
	node := r.node()
	var body strings.Builder
	var flushed []string
	r.useMu.Lock()
	for id, u := range r.uses {
		if !u.dirty {
			continue
		}
		meta, _ := json.Marshal(map[string]any{"index": map[string]any{"_index": r.index(), "_id": useDocID(id, node)}})
		doc, _ := json.Marshal(useDoc{Kind: kindUse, Agent: id, Node: node, LastSeen: u.last.UTC(), Address: u.addr, Events1h: u.events1h(now)})
		body.Write(meta)
		body.WriteByte('\n')
		body.Write(doc)
		body.WriteByte('\n')
		flushed = append(flushed, id)
		u.dirty = false
	}
	r.useMu.Unlock()
	if len(flushed) == 0 {
		return
	}
	if err := r.ensureIndex(ctx); err != nil {
		r.redirty(flushed)
		return
	}
	var out struct {
		Errors bool `json:"errors"`
	}
	if err := r.Client.Do(ctx, "POST", "/_bulk", []byte(body.String()), &out); err != nil || out.Errors {
		r.redirty(flushed)
		if err == nil {
			err = errors.New("some usage documents were refused")
		}
		r.failed("how agent tokens were used could not be saved in OpenSearch; Signalith tries again in a minute", err)
	}
}

func (r *Registry) redirty(ids []string) {
	r.useMu.Lock()
	defer r.useMu.Unlock()
	for _, id := range ids {
		if u := r.uses[id]; u != nil {
			u.dirty = true
		}
	}
}

// Use is how a token was used, on every server.
type Use struct {
	LastSeen time.Time
	Address  string
	Events1h int64
}

// Usage returns how each token was used on every server: the last time
// and address, and the events of the last hour. This server's counts are
// its own, not yet written ones.
func (r *Registry) Usage(ctx context.Context) (map[string]Use, error) {
	out := map[string]Use{}
	now := r.now()
	node := r.node()
	// own is what this server wrote before it last started: its counts
	// since then are in memory, but not how tokens were used before.
	own := map[string]useDoc{}
	var err error
	if r.Client != nil {
		var docs []store.Doc
		docs, err = r.Client.SearchDocs(ctx, r.index(), map[string]any{"term": map[string]any{"kind": kindUse}})
		for _, d := range docs {
			var u useDoc
			if json.Unmarshal(d.Source, &u) != nil {
				continue
			}
			if u.Node == node {
				own[u.Agent] = u
				continue
			}
			o := out[u.Agent]
			if u.LastSeen.After(o.LastSeen) {
				o.LastSeen, o.Address = u.LastSeen, u.Address
			}
			if now.Sub(u.LastSeen) < time.Hour {
				o.Events1h += u.Events1h
			}
			out[u.Agent] = o
		}
	}
	r.useMu.Lock()
	for id, u := range r.uses {
		o := out[id]
		if u.last.After(o.LastSeen) {
			o.LastSeen, o.Address = u.last, u.addr
		}
		o.Events1h += u.events1h(now)
		out[id] = o
		delete(own, id)
	}
	r.useMu.Unlock()
	for id, u := range own {
		o := out[id]
		if u.LastSeen.After(o.LastSeen) {
			o.LastSeen, o.Address = u.LastSeen, u.Address
		}
		if now.Sub(u.LastSeen) < time.Hour {
			o.Events1h += u.Events1h
		}
		out[id] = o
	}
	return out, err
}

// ---- listing ----

// Token is an agent token as listed: never the token itself.
type Token struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Purpose      string     `json:"purpose"`
	Status       string     `json:"status"`
	Hint         string     `json:"hint"`
	CreatedAt    time.Time  `json:"created_at"`
	CreatedBy    string     `json:"created_by"`
	LastUsedAt   *time.Time `json:"last_used_at"`
	LastUsedFrom string     `json:"last_used_from"`
	Events1h     int64      `json:"events_1h"`
	RevokedAt    *time.Time `json:"revoked_at"`
	RevokedBy    string     `json:"revoked_by"`
}

// LegacyToken is a shared token from the configuration as listed.
type LegacyToken struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Source       string     `json:"source"`
	Public       bool       `json:"public"`
	Status       string     `json:"status"` // accepted or refused
	RefusedAt    *time.Time `json:"refused_at"`
	RefusedBy    string     `json:"refused_by"`
	LastUsedAt   *time.Time `json:"last_used_at"`
	LastUsedFrom string     `json:"last_used_from"`
	Events1h     int64      `json:"events_1h"`
	// Length is the token's length, for the security checks.
	Length int `json:"-"`
}

// List is every token.
type List struct {
	Loaded    bool          `json:"loaded"`
	Tokens    []Token       `json:"tokens"`
	Legacy    []LegacyToken `json:"legacy"`
	MaxActive int           `json:"max_active"`
}

func toToken(d *tokenDoc) Token {
	return Token{ID: d.ID, Name: d.Name, Purpose: d.Purpose, Status: d.State, Hint: d.Hint, CreatedAt: d.At, CreatedBy: d.CreatedBy,
		RevokedAt: d.RevokedAt, RevokedBy: d.RevokedBy}
}

func withUse(t *Token, u Use, ok bool) {
	if ok && !u.LastSeen.IsZero() {
		t.LastUsedAt, t.LastUsedFrom, t.Events1h = timePtr(u.LastSeen.UTC()), u.Address, u.Events1h
	}
}

// List lists the tokens: active ones first, then by name; the shared ones
// in the configuration's order. Before the tokens were first read, only
// the shared ones are listed, with Loaded false.
func (r *Registry) List(ctx context.Context) *List {
	snap := r.current()
	uses, _ := r.Usage(ctx)
	out := &List{Loaded: snap.loaded, Tokens: []Token{}, Legacy: r.legacyList(snap, uses), MaxActive: MaxActive}
	for _, d := range snap.tokens {
		t := toToken(d)
		u, ok := uses[d.ID]
		withUse(&t, u, ok)
		out.Tokens = append(out.Tokens, t)
	}
	sort.Slice(out.Tokens, func(i, j int) bool {
		a, b := out.Tokens[i], out.Tokens[j]
		if (a.Status == StateActive) != (b.Status == StateActive) {
			return a.Status == StateActive
		}
		if la, lb := lowerName(a.Name), lowerName(b.Name); la != lb {
			return la < lb
		}
		return a.CreatedAt.Before(b.CreatedAt)
	})
	return out
}

// legacyList lists the shared tokens. Before the tokens were first read
// their IDs aren't known: they are listed with no ID, as "Shared token".
func (r *Registry) legacyList(snap *snapshot, uses map[string]Use) []LegacyToken {
	out := []LegacyToken{}
	seen := map[string]bool{}
	for _, l := range r.legacy() {
		if seen[l.Secret] {
			continue
		}
		seen[l.Secret] = true
		out = append(out, r.legacyToken(snap, l, uses))
	}
	return out
}

func (r *Registry) legacyToken(snap *snapshot, l Legacy, uses map[string]Use) LegacyToken {
	key := r.idKey(snap)
	if key == nil {
		return LegacyToken{Name: "Shared token", Source: l.Source, Public: l.Public, Status: "accepted", Length: len(l.Secret)}
	}
	id := legacyID(key, l.Secret)
	lt := LegacyToken{ID: id, Name: LegacyName(id), Source: l.Source, Public: l.Public, Status: "accepted", Length: len(l.Secret)}
	if ref, ok := snap.refused[id]; ok {
		lt.Status, lt.RefusedAt, lt.RefusedBy = "refused", timePtr(ref.At), ref.By
	}
	if u, ok := uses[id]; ok && !u.LastSeen.IsZero() {
		lt.LastUsedAt, lt.LastUsedFrom, lt.Events1h = timePtr(u.LastSeen.UTC()), u.Address, u.Events1h
	}
	return lt
}

// Counts returns how many agent tokens are active and how many shared
// tokens are still accepted.
func (r *Registry) Counts() (active, legacyAccepted int) {
	snap := r.current()
	for _, d := range snap.tokens {
		if isActive(d) {
			active++
		}
	}
	seen := map[string]bool{}
	key := r.idKey(snap)
	for _, l := range r.legacy() {
		refused := false
		if key != nil {
			_, refused = snap.refused[legacyID(key, l.Secret)]
		}
		if !refused && !seen[l.Secret] {
			legacyAccepted++
		}
		seen[l.Secret] = true
	}
	return active, legacyAccepted
}

// ---- changes ----

func (r *Registry) ensureIndex(ctx context.Context) error {
	if r.ensured.Load() {
		return nil
	}
	if err := cluster.EnsureRuntime(ctx, r.Client, strings.TrimSuffix(r.index(), "_runtime")); err != nil {
		return err
	}
	r.ensured.Store(true)
	return nil
}

// fresh reads the tokens again before a change, so it is checked against
// what every server sees now.
func (r *Registry) fresh(ctx context.Context) error {
	if r.Client == nil {
		return errStore(errors.New("no OpenSearch"))
	}
	if err := r.ensureIndex(ctx); err != nil {
		return errStore(err)
	}
	if err := r.Load(ctx); err != nil {
		if !r.Loaded() {
			return errLoading(err)
		}
		return errStore(err)
	}
	return nil
}

// touch rewrites the watched document, so the other servers read the
// tokens again.
func (r *Registry) touch(ctx context.Context) {
	err := r.Client.Do(ctx, "PUT", "/"+r.index()+"/_doc/"+watchDocID,
		map[string]any{"kind": kindWatch, "at": r.now().UTC(), "node": r.node()}, nil)
	if err != nil && r.Log != nil {
		r.Log.Warn("the other servers could not be told that the agent tokens changed; they read them again within 5 minutes", "err", err)
	}
}

// apply puts one changed token into the snapshot at once.
func (r *Registry) apply(f func(s *snapshot)) {
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	s := r.current().clone()
	s.loaded = true
	f(s)
	r.gen++
	r.snap.Store(s)
}

func (r *Registry) nameTaken(name, except string) bool {
	for _, d := range r.current().tokens {
		if isActive(d) && d.ID != except && strings.EqualFold(d.Name, name) {
			return true
		}
	}
	return false
}

// Create makes a new token named name for purpose. by is who made it.
// It returns the token's listing and the token, which is never shown
// again.
func (r *Registry) Create(ctx context.Context, name, purpose, by string) (Token, string, error) {
	name, ok := CleanName(name)
	if !ok {
		return Token{}, "", errNameInvalid()
	}
	if !ValidPurpose(purpose) {
		return Token{}, "", errPurposeInvalid()
	}
	if err := r.fresh(ctx); err != nil {
		return Token{}, "", err
	}
	snap := r.current()
	active := 0
	for _, d := range snap.tokens {
		if isActive(d) {
			active++
		}
	}
	switch {
	case active >= MaxActive:
		return Token{}, "", errTooMany()
	case len(snap.tokens) >= MaxDocs:
		return Token{}, "", errTooManyDocs()
	case r.nameTaken(name, ""):
		return Token{}, "", errNameTaken(name)
	}
	for try := 0; try < 5; try++ {
		secret, err := NewSecret()
		if err != nil {
			return Token{}, "", err
		}
		h := Fingerprint(secret)
		d := &tokenDoc{Kind: kindToken, ID: h[:12], State: StateActive, Name: name, Purpose: purpose, Hash: h, Hint: hintOf(secret),
			At: r.now().UTC().Truncate(time.Second), CreatedBy: by}
		if _, err := r.Client.Create(ctx, r.index(), tokenDocID(d.ID), d, true); errors.Is(err, store.ErrExists) {
			continue
		} else if err != nil {
			return Token{}, "", errStore(err)
		}
		r.apply(func(s *snapshot) { s.tokens[d.ID] = d })
		r.touch(ctx)
		return toToken(d), secret, nil
	}
	return Token{}, "", errStore(errors.New("five new tokens in a row had an ID already in use"))
}

// casToken changes the token id with change, read and written back only
// if nobody changed it meanwhile.
func (r *Registry) casToken(ctx context.Context, id string, change func(d *tokenDoc) (bool, error)) (*tokenDoc, error) {
	if !validID(id) {
		return nil, errNotFound()
	}
	for try := 0; ; try++ {
		src, v, found, err := r.Client.Get(ctx, r.index(), tokenDocID(id))
		if err != nil {
			return nil, errStore(err)
		}
		if !found {
			return nil, errNotFound()
		}
		var d tokenDoc
		if err := json.Unmarshal(src, &d); err != nil || d.ID != id {
			return nil, errNotFound()
		}
		write, err := change(&d)
		if err != nil || !write {
			return &d, err
		}
		_, err = r.Client.PutIf(ctx, r.index(), tokenDocID(id), &d, v, true)
		if err == nil {
			r.apply(func(s *snapshot) { s.tokens[id] = &d })
			r.touch(ctx)
			return &d, nil
		}
		if !store.IsConflict(err) || try >= 9 {
			return nil, errStore(err)
		}
		if err := sleep(ctx, jitter(10*time.Millisecond, 250*time.Millisecond)); err != nil {
			return nil, errStore(err)
		}
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Rename gives the token id a new name. Events already stored keep the
// old one. It returns the old name too.
func (r *Registry) Rename(ctx context.Context, id, name, by string) (Token, string, error) {
	name, ok := CleanName(name)
	if !ok {
		return Token{}, "", errNameInvalid()
	}
	if err := r.fresh(ctx); err != nil {
		return Token{}, "", err
	}
	if r.nameTaken(name, id) {
		return Token{}, "", errNameTaken(name)
	}
	old := ""
	d, err := r.casToken(ctx, id, func(d *tokenDoc) (bool, error) {
		if !isActive(d) {
			return false, errRevoked()
		}
		old = d.Name
		if d.Name == name {
			return false, nil
		}
		d.Name, d.RenamedAt, d.RenamedBy = name, timePtr(r.now().UTC().Truncate(time.Second)), by
		return true, nil
	})
	if err != nil {
		return Token{}, "", err
	}
	return r.listed(ctx, d), old, nil
}

func (r *Registry) listed(ctx context.Context, d *tokenDoc) Token {
	t := toToken(d)
	uses, _ := r.Usage(ctx)
	u, ok := uses[d.ID]
	withUse(&t, u, ok)
	return t
}

// Revoke revokes the token id: every server refuses it within a few
// seconds, this one at once. Revoking a revoked token changes nothing.
// It returns how many osquery hosts enrolled with it were removed.
func (r *Registry) Revoke(ctx context.Context, id, by string) (Token, int, error) {
	if r.Client == nil {
		return Token{}, 0, errStore(errors.New("no OpenSearch"))
	}
	if err := r.ensureIndex(ctx); err != nil {
		return Token{}, 0, errStore(err)
	}
	d, err := r.casToken(ctx, id, func(d *tokenDoc) (bool, error) {
		if !isActive(d) {
			return false, nil
		}
		d.State, d.RevokedAt, d.RevokedBy = StateRevoked, timePtr(r.now().UTC().Truncate(time.Second)), by
		return true, nil
	})
	if err != nil {
		return Token{}, 0, err
	}
	// Even when it was revoked already, so hosts a failed removal left
	// behind go now.
	r.apply(func(s *snapshot) { s.tokens[id] = d })
	return r.listed(ctx, d), r.revoked(ctx, id), nil
}

// FindByName returns the ID of the active token called name, or of the
// token with that ID.
func (r *Registry) FindByName(name string) (string, bool) {
	snap := r.current()
	if d := snap.tokens[name]; d != nil {
		return d.ID, true
	}
	var ids []string
	for _, d := range snap.tokens {
		if isActive(d) && strings.EqualFold(d.Name, strings.TrimSpace(name)) {
			ids = append(ids, d.ID)
		}
	}
	if len(ids) == 1 {
		return ids[0], true
	}
	return "", false
}

// Get returns the listing of the token id.
func (r *Registry) Get(ctx context.Context, id string) (Token, bool) {
	d := r.current().tokens[id]
	if d == nil {
		return Token{}, false
	}
	return r.listed(ctx, d), true
}

// ---- shared tokens ----

// findLegacy returns the shared token listed under id (never by IDOf).
func (r *Registry) findLegacy(id string) (Legacy, bool) {
	l, pub, ok := r.findShared(r.current(), id)
	return l, ok && pub == id
}

// setRefused stops accepting (refuse) or accepts again the shared token id.
func (r *Registry) setRefused(ctx context.Context, id, by string, refuse bool) (LegacyToken, error) {
	if r.Client == nil {
		return LegacyToken{}, errStore(errors.New("no OpenSearch"))
	}
	if err := r.fresh(ctx); err != nil {
		return LegacyToken{}, err
	}
	l, ok := r.findLegacy(id)
	if !ok {
		return LegacyToken{}, &Error{Status: 404, Code: CodeNotFound, Msg: "There is no shared agent token with this ID in this server's configuration."}
	}
	for try := 0; ; try++ {
		src, v, found, err := r.Client.Get(ctx, r.index(), legacyDocID)
		if err != nil {
			return LegacyToken{}, errStore(err)
		}
		doc := legacyDoc{Kind: kindLegacy, Refused: map[string]refusal{}}
		if found {
			_ = json.Unmarshal(src, &doc)
			if doc.Refused == nil {
				doc.Refused = map[string]refusal{}
			}
			doc.Kind = kindLegacy
		}
		if !hmac.Equal(parseKey(doc.IDKey), r.current().idKey) {
			// The key changed since it was read (the document was
			// deleted and made again): the ID means another token now.
			return LegacyToken{}, errStore(errors.New("the key of shared tokens' IDs changed"))
		}
		_, was := doc.Refused[id]
		if was == refuse {
			r.apply(func(s *snapshot) {
				if refuse {
					s.refused[id] = doc.Refused[id]
				} else {
					delete(s.refused, id)
				}
			})
			break
		}
		if refuse {
			doc.Refused[id] = refusal{At: r.now().UTC().Truncate(time.Second), By: by}
		} else {
			delete(doc.Refused, id)
		}
		if found {
			_, err = r.Client.PutIf(ctx, r.index(), legacyDocID, &doc, v, true)
		} else {
			_, err = r.Client.Create(ctx, r.index(), legacyDocID, &doc, true)
		}
		if err == nil {
			r.apply(func(s *snapshot) { s.refused = doc.Refused })
			r.touch(ctx)
			break
		}
		if !store.IsConflict(err) || try >= 9 {
			return LegacyToken{}, errStore(err)
		}
		if err := sleep(ctx, jitter(10*time.Millisecond, 250*time.Millisecond)); err != nil {
			return LegacyToken{}, errStore(err)
		}
	}
	uses, _ := r.Usage(ctx)
	return r.legacyToken(r.current(), l, uses), nil
}

// Refuse stops accepting the shared token id on every server, and returns
// how many osquery hosts enrolled with it were removed: those enrolled
// under either of its IDs.
func (r *Registry) Refuse(ctx context.Context, id, by string) (LegacyToken, int, error) {
	lt, err := r.setRefused(ctx, id, by, true)
	if err != nil {
		return lt, 0, err
	}
	n := r.revoked(ctx, id)
	if l, ok := r.findLegacy(id); ok {
		n += r.revoked(ctx, IDOf(l.Secret))
	}
	return lt, n, nil
}

// Accept accepts the shared token id again.
func (r *Registry) Accept(ctx context.Context, id, by string) (LegacyToken, error) {
	return r.setRefused(ctx, id, by, false)
}

// LegacyByID returns the shared token id as listed.
func (r *Registry) LegacyByID(ctx context.Context, id string) (LegacyToken, bool) {
	l, ok := r.findLegacy(id)
	if !ok {
		return LegacyToken{}, false
	}
	uses, _ := r.Usage(ctx)
	return r.legacyToken(r.current(), l, uses), true
}

// String is for logs: never the token.
func (i Identity) String() string { return fmt.Sprintf("%s (%s)", i.Name, i.ID) }
