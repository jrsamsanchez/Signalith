// Package agentinv keeps the list of agents that send events, across every
// server that shares an OpenSearch: which computers send, to which
// servers, over HTTPS or plain HTTP, with which agent token, and whether
// their configuration still matches the certificate authority the servers
// use. The Endpoints page shows it next to the osquery hosts.
//
// Each server counts the agents it hears from in memory and, once a
// minute, writes one bulk request of small documents to the runtime index,
// <prefix>_runtime/agent:<agent key>:<node id>, the way the agent tokens
// keep their usage (agenttokens). List merges every server's documents
// into one row per agent.
//
// An agent is told apart by the X-Signalith-Agent header that
// configurations from Add data send (the computer's name). Agents set up
// before that header are told apart by their address and agent token. The
// header is the sender's word: it is a label, never used to let anyone in.
package agentinv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Kind is the kind of the inventory documents in the runtime index.
const Kind = "agent_inventory"

// The headers agent configurations from Add data send.
const (
	AgentHeader  = "X-Signalith-Agent"
	ConfigHeader = "X-Signalith-Config"
)

const (
	// maxAgents caps the agents one server keeps in memory; more are
	// counted in one figure and logged once.
	maxAgents = 10000
	// maxRefusing caps the addresses whose refusals of the certificate
	// are kept.
	maxRefusing = 1000
	// keepFor is how long an agent not heard from stays listed.
	keepFor = 30 * 24 * time.Hour
	// SilentAfter is how long without events makes an agent silent.
	SilentAfter = time.Hour
	// minRefusedMinutes is in how many minutes of the last hour an address
	// that never got a batch through must have refused the certificate to
	// be listed on its own. An agent keeps trying; a browser shown a
	// certificate it does not trust stops once someone accepts it or goes
	// away, so a visit does not make a row.
	minRefusedMinutes = 3
	// maxHeaderValue caps each value of X-Signalith-Config.
	maxHeaderValue = 64
	// maxName is the longest host name kept.
	maxName = 253
)

// Contact is one batch an agent sent.
type Contact struct {
	// Name is the X-Signalith-Agent header as sent; a value that is not a
	// host name counts as none.
	Name string
	// Address is the agent's address, as the server saw it.
	Address string
	// Tag is the Fluent Bit tag of the batch.
	Tag string
	// Intake is how it sent: ingest.IntakeAgent or ingest.IntakeOTLP.
	Intake string
	// TLS is true when the batch came over HTTPS, and Local when it came
	// from this server's own computer, where plain HTTP never crosses the
	// network.
	TLS, Local bool
	// TokenID and TokenName are the agent token it sent with.
	TokenID, TokenName string
	// Config is the X-Signalith-Config header as sent.
	Config string
	// Events is how many of its events were stored.
	Events int
}

// Doc is an inventory document: how one server heard from one agent.
type Doc struct {
	Kind      string `json:"kind"`
	Agent     string `json:"agent"`
	Name      string `json:"name,omitempty"`
	Address   string `json:"address,omitempty"`
	Tag       string `json:"tag,omitempty"`
	Intake    string `json:"intake,omitempty"`
	Node      string `json:"node"`
	Server    string `json:"server"`
	Transport string `json:"transport,omitempty"`
	Local     bool   `json:"local,omitempty"`
	Token     string `json:"token,omitempty"`
	TokenName string `json:"token_name,omitempty"`
	// CA are the pins of the certificate authorities the agent's
	// configuration trusts, comma-separated (see ParseConfig).
	CA            string    `json:"ca,omitempty"`
	ServerCA      string    `json:"server_ca,omitempty"`
	ConfigVersion string    `json:"config_version,omitempty"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Events1h      int64     `json:"events_1h"`
	Refused1h     int64     `json:"refused_1h"`
	// RefusedMinutes is in how many minutes of the last hour the address
	// refused the certificate (see minRefusedMinutes).
	RefusedMinutes int `json:"refused_minutes,omitempty"`
}

// Transports.
const (
	TransportTLS   = "tls"
	TransportPlain = "plain"
)

// minutes counts per minute for the last hour.
type minutes struct {
	counts [60]int64
	at     [60]int64
}

func (m *minutes) add(now time.Time, n int64) {
	t := now.Unix() / 60
	i := t % 60
	if m.at[i] != t {
		m.at[i], m.counts[i] = t, 0
	}
	m.counts[i] += n
}

// last returns the count of the last hour and in how many of its minutes
// there was any.
func (m *minutes) last(now time.Time) (int64, int) {
	t := now.Unix() / 60
	var n int64
	busy := 0
	for i := range m.counts {
		if m.at[i] > t-60 && m.at[i] <= t && m.counts[i] > 0 {
			n += m.counts[i]
			busy++
		}
	}
	return n, busy
}

type entry struct {
	doc    Doc
	events minutes
	dirty  bool
	// written is the hour's count last written.
	written int64
}

type refusing struct {
	addr    string
	first   time.Time
	last    time.Time
	count   minutes
	dirty   bool
	written int64
}

// Inventory counts the agents this server hears from and lists those of
// every server. Its methods do nothing on a nil Inventory.
type Inventory struct {
	// Client reaches OpenSearch; nil keeps the counts in memory only.
	Client *store.Client
	// Prefix is the index prefix: the documents are in <prefix>_runtime.
	Prefix string
	// Node is this server's ID and Server its name; nil uses the host name.
	Node, Server func() string
	// ServerCA returns the pin (see Pin) of the certificate authority this
	// server's certificate comes from now, "" for none of its own.
	ServerCA func() string
	// Retired returns the pins of the certificate authorities the servers
	// no longer use since they took the cluster's; nil has none. An agent
	// whose configuration trusts only those needs a new one (NeedsConfig).
	Retired func() []string
	// Leader reports whether this server runs the background jobs, which
	// remove agents not heard from for 30 days; nil never does.
	Leader func() bool
	Log    *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Flush is how often Run writes the counts (default 1m), Tidy how
	// often it removes old agents (1h).
	Flush, Tidy time.Duration

	mu       sync.Mutex
	agents   map[string]*entry
	refused  map[string]*refusing
	first    map[string]time.Time // first_seen of this server's documents before it started
	overflow int64
	overLog  bool
	ensured  atomic.Bool

	logMu    sync.Mutex
	lastFail time.Time
}

func (v *Inventory) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Inventory) index() string {
	p := v.Prefix
	if p == "" {
		p = "signalith"
	}
	return cluster.RuntimeIndex(p)
}

func hostName() string {
	h, _ := os.Hostname()
	if h == "" {
		h = "local"
	}
	return h
}

func (v *Inventory) node() string {
	if v.Node != nil {
		if n := v.Node(); n != "" {
			return n
		}
	}
	return hostName()
}

func (v *Inventory) server() string {
	if v.Server != nil {
		if n := v.Server(); n != "" {
			return n
		}
	}
	return hostName()
}

func (v *Inventory) serverCA() string {
	if v.ServerCA == nil {
		return ""
	}
	return v.ServerCA()
}

// Pin returns the first 16 hex digits, in lower case, of a certificate
// fingerprint written as AB:CD:..., or "" when fp is not one.
func Pin(fp string) string {
	h := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(fp))
	if len(h) < 16 || !isHex(h) {
		return ""
	}
	return h[:16]
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return s != ""
}

// CleanName returns the agent name from an X-Signalith-Agent header:
// trimmed and in lower case, or "" when it is not a host name (letters,
// digits, dots, hyphens and underscores, at most 253 of them, starting
// with a letter or digit).
func CleanName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > maxName {
		return ""
	}
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case (c == '.' || c == '-' || c == '_') && i > 0:
		default:
			return ""
		}
	}
	return s
}

// ParseConfig reads an X-Signalith-Config header, "ca=<pins>;v=<version>"
// or "v=<version>", where pins are one or more pins separated by commas:
// a configuration made while a new certificate authority was prepared
// trusts both. ca is returned as sent. A header with anything else in it
// counts as none.
func ParseConfig(s string) (ca, version string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	for part := range strings.SplitSeq(s, ";") {
		k, val, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found || val == "" || len(val) > maxHeaderValue {
			return "", "", false
		}
		switch k {
		case "ca":
			if ca != "" {
				return "", "", false
			}
			for pin := range strings.SplitSeq(val, ",") {
				if len(pin) != 16 || !isHex(pin) {
					return "", "", false
				}
			}
			ca = val
		case "v":
			if version != "" || !versionChars(val) {
				return "", "", false
			}
			version = val
		default:
			return "", "", false
		}
	}
	return ca, version, true
}

func versionChars(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(".-+_", c)) {
			return false
		}
	}
	return true
}

func hash16(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])[:16]
}

// Key returns an agent's key: from its name when it sends one, else from
// its address and agent token, so older agents behind one address that
// use different tokens stay apart.
func Key(name, addr, tokenID string) string {
	if name != "" {
		return hash16("name", name)
	}
	return hash16("addr", addr, tokenID)
}

// TrustsCA reports whether the pins of a configuration (as in Doc.CA)
// include pin.
func TrustsCA(pins, pin string) bool {
	return pin != "" && slices.Contains(strings.Split(pins, ","), pin)
}

// refusedKey is the key of an address that refused the certificate.
func refusedKey(addr string) string { return "addr-" + hash16("refused", addr) }

func docID(key, node string) string { return "agent:" + key + ":" + node }

// Note counts a batch an agent sent.
func (v *Inventory) Note(c Contact) {
	if v == nil {
		return
	}
	now := v.now().UTC()
	name := CleanName(c.Name)
	key := Key(name, c.Address, c.TokenID)
	ca, version, _ := ParseConfig(c.Config)
	transport := TransportPlain
	if c.TLS {
		transport = TransportTLS
	}
	serverCA := v.serverCA()
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.agents == nil {
		v.agents = map[string]*entry{}
	}
	e := v.agents[key]
	if e == nil && len(v.agents) >= maxAgents {
		v.evictAgentLocked(now)
	}
	if e == nil {
		if len(v.agents) >= maxAgents {
			v.overflow++
			if !v.overLog && v.Log != nil {
				v.overLog = true
				v.Log.Warn("more than 10,000 agents send to this server; the ones over that are counted together and not listed one by one", "limit", maxAgents)
			}
			return
		}
		first := now
		if t, ok := v.first[key]; ok && t.Before(first) {
			first = t
		}
		e = &entry{doc: Doc{Kind: Kind, Agent: key, FirstSeen: first}}
		v.agents[key] = e
	}
	d := &e.doc
	d.Name, d.Address, d.Tag, d.Intake, d.Transport, d.Local = name, c.Address, c.Tag, c.Intake, transport, c.Local
	d.Token, d.TokenName, d.CA, d.ConfigVersion, d.ServerCA = c.TokenID, c.TokenName, ca, version, serverCA
	d.LastSeen = now
	e.events.add(now, int64(c.Events))
	e.dirty = true
}

// NoteRefusedCA counts a TLS handshake in which the computer at addr
// (host or host:port) refused this server's certificate: an agent pinned
// to a certificate authority this server does not use never gets a batch
// through, so this is the only sign of it.
func (v *Inventory) NoteRefusedCA(addr string) {
	if v == nil {
		return
	}
	host := addr
	if h, _, ok := splitHostPort(addr); ok {
		host = h
	}
	if host == "" {
		return
	}
	now := v.now().UTC()
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.refused == nil {
		v.refused = map[string]*refusing{}
	}
	r := v.refused[host]
	if r == nil && len(v.refused) >= maxRefusing {
		v.evictRefusedLocked()
	}
	if r == nil {
		if len(v.refused) >= maxRefusing {
			return
		}
		r = &refusing{addr: host, first: now}
		v.refused[host] = r
	}
	r.last = now
	r.count.add(now, 1)
	r.dirty = true
}

// evictAgentLocked makes room for a new agent when the list is full: it
// forgets the agent heard from longest ago, once silent for an hour and
// written to OpenSearch, where its document stays until it is 30 days
// old. The caller holds v.mu.
func (v *Inventory) evictAgentLocked(now time.Time) {
	var oldest string
	for k, e := range v.agents {
		if e.dirty || now.Sub(e.doc.LastSeen) < SilentAfter {
			continue
		}
		if oldest == "" || e.doc.LastSeen.Before(v.agents[oldest].doc.LastSeen) {
			oldest = k
		}
	}
	if oldest == "" {
		return
	}
	if len(v.first) < maxAgents {
		if v.first == nil {
			v.first = map[string]time.Time{}
		}
		v.first[oldest] = v.agents[oldest].doc.FirstSeen
	}
	delete(v.agents, oldest)
}

// evictRefusedLocked makes room for a new refusing address when the list
// is full: it forgets the one that refused longest ago, once written.
// Browsers and scanners that refuse the certificate come and go; an
// agent that keeps refusing gets its place back. The caller holds v.mu.
func (v *Inventory) evictRefusedLocked() {
	var oldest string
	for k, r := range v.refused {
		if r.dirty {
			continue
		}
		if oldest == "" || r.last.Before(v.refused[oldest].last) {
			oldest = k
		}
	}
	if oldest != "" {
		delete(v.refused, oldest)
	}
}

// pruneLocked forgets the agents not heard from for 30 days and the
// addresses that last refused the certificate over an hour ago, once
// their documents are written. The caller holds v.mu.
func (v *Inventory) pruneLocked(now time.Time) {
	for k, e := range v.agents {
		if !e.dirty && now.Sub(e.doc.LastSeen) >= keepFor {
			delete(v.agents, k)
		}
	}
	for k, r := range v.refused {
		if !r.dirty && now.Sub(r.last) >= time.Hour {
			delete(v.refused, k)
		}
	}
}

// splitHostPort splits "host:port" and "[v6]:port"; a bare address is not
// split.
func splitHostPort(addr string) (string, string, bool) {
	if strings.HasPrefix(addr, "[") {
		end := strings.Index(addr, "]")
		if end < 0 {
			return "", "", false
		}
		return addr[1:end], strings.TrimPrefix(addr[end+1:], ":"), true
	}
	if strings.Count(addr, ":") != 1 {
		return "", "", false // a bare IPv6 address, or no port
	}
	h, p, _ := strings.Cut(addr, ":")
	return h, p, true
}

// Run writes the counts every Flush, removes agents not heard from for 30
// days every Tidy while this server runs the background jobs, and writes
// the counts a last time when ctx ends.
func (v *Inventory) Run(ctx context.Context) {
	if v == nil || v.Client == nil {
		<-ctx.Done()
		return
	}
	flush, tidy := v.Flush, v.Tidy
	if flush <= 0 {
		flush = time.Minute
	}
	if tidy <= 0 {
		tidy = time.Hour
	}
	v.loadFirstSeen(ctx)
	ft := time.NewTicker(flush)
	defer ft.Stop()
	tt := time.NewTicker(tidy)
	defer tt.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			v.FlushNow(fctx)
			cancel()
			return
		case <-ft.C:
			v.FlushNow(ctx)
		case <-tt.C:
			if _, err := v.TidyNow(ctx); err != nil && ctx.Err() == nil {
				v.failed("agents not heard from for 30 days could not be removed from the Endpoints page; Signalith tries again in an hour", err)
			}
		}
	}
}

// loadFirstSeen reads when this server first heard from each agent,
// before it last started, so a restart does not reset it.
func (v *Inventory) loadFirstSeen(ctx context.Context) {
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	docs, err := v.Client.SearchDocs(rctx, v.index(), map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"term": map[string]any{"kind": Kind}},
		map[string]any{"term": map[string]any{"node": v.node()}},
	}}})
	if err != nil {
		if !notFound(err) {
			v.failed("the agents this server heard from before it started could not be read; they show as first seen now", err)
		}
		return
	}
	first := map[string]time.Time{}
	for _, d := range docs {
		var doc Doc
		if json.Unmarshal(d.Source, &doc) != nil || doc.Agent == "" || doc.FirstSeen.IsZero() {
			continue
		}
		first[doc.Agent] = doc.FirstSeen
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.first = first
	for k, e := range v.agents {
		if t, ok := first[k]; ok && t.Before(e.doc.FirstSeen) {
			e.doc.FirstSeen = t
		}
	}
}

// docsLocked returns this server's documents: of every agent and refusing
// address when all is true, else only of those changed since the last
// write, which it marks written. An hour's count that went down since it
// was written counts as a change, so other servers see it drop to 0 when
// an agent slows down or stops. The caller holds v.mu.
func (v *Inventory) docsLocked(now time.Time, all bool) []Doc {
	node, server := v.node(), v.server()
	var out []Doc
	for _, e := range v.agents {
		n, _ := e.events.last(now)
		if !all && !e.dirty && n == e.written {
			continue
		}
		d := e.doc
		d.Node, d.Server = node, server
		d.Events1h = n
		out = append(out, d)
		if !all {
			e.dirty, e.written = false, n
		}
	}
	for _, r := range v.refused {
		n, busy := r.count.last(now)
		if !all && !r.dirty && n == r.written {
			continue
		}
		out = append(out, Doc{Kind: Kind, Agent: refusedKey(r.addr), Address: r.addr, Node: node, Server: server,
			ServerCA: v.serverCA(), FirstSeen: r.first, LastSeen: r.last, Refused1h: n, RefusedMinutes: busy})
		if !all {
			r.dirty, r.written = false, n
		}
	}
	return out
}

// FlushNow writes one document per agent and refusing address heard from
// since the last write, in one bulk request. What could not be written is
// written at the next one. It also forgets, on every server, the agents
// and refusing addresses whose documents no longer matter (see
// pruneLocked); their documents stay in OpenSearch until TidyNow.
func (v *Inventory) FlushNow(ctx context.Context) {
	if v == nil || v.Client == nil {
		return
	}
	now := v.now().UTC()
	v.mu.Lock()
	docs := v.docsLocked(now, false)
	v.pruneLocked(now)
	v.mu.Unlock()
	if len(docs) == 0 {
		return
	}
	var body strings.Builder
	for _, d := range docs {
		meta, _ := json.Marshal(map[string]any{"index": map[string]any{"_index": v.index(), "_id": docID(d.Agent, d.Node)}})
		doc, _ := json.Marshal(d)
		body.Write(meta)
		body.WriteByte('\n')
		body.Write(doc)
		body.WriteByte('\n')
	}
	err := v.ensureIndex(ctx)
	if err == nil {
		var out struct {
			Errors bool `json:"errors"`
		}
		err = v.Client.Do(ctx, http.MethodPost, "/_bulk", []byte(body.String()), &out)
		if err == nil && out.Errors {
			err = errors.New("some agent documents were refused")
		}
	}
	if err != nil {
		v.redirty(docs)
		v.failed("the agents this server heard from could not be saved in OpenSearch; Signalith tries again in a minute", err)
	}
}

func (v *Inventory) redirty(docs []Doc) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, d := range docs {
		if e := v.agents[d.Agent]; e != nil {
			e.dirty = true
			continue
		}
		for _, r := range v.refused {
			if refusedKey(r.addr) == d.Agent {
				r.dirty = true
			}
		}
	}
}

func (v *Inventory) ensureIndex(ctx context.Context) error {
	if v.ensured.Load() {
		return nil
	}
	if err := cluster.EnsureRuntime(ctx, v.Client, strings.TrimSuffix(v.index(), "_runtime")); err != nil {
		return err
	}
	v.ensured.Store(true)
	return nil
}

// TidyNow removes the documents of agents not heard from for 30 days,
// when this server runs the background jobs, and returns how many it
// removed.
func (v *Inventory) TidyNow(ctx context.Context) (int, error) {
	if v == nil || v.Client == nil || v.Leader == nil || !v.Leader() {
		return 0, nil
	}
	cutoff := v.now().Add(-keepFor).UTC().Format(time.RFC3339Nano)
	var out struct {
		Deleted int `json:"deleted"`
	}
	err := v.Client.Do(ctx, http.MethodPost, "/"+url.PathEscape(v.index())+"/_delete_by_query?conflicts=proceed&refresh=true", map[string]any{
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{"kind": Kind}},
			map[string]any{"range": map[string]any{"last_seen": map[string]any{"lt": cutoff}}},
		}}},
	}, &out)
	if notFound(err) {
		return 0, nil
	}
	return out.Deleted, err
}

func notFound(err error) bool {
	var oe *store.Error
	return errors.As(err, &oe) && oe.Status == http.StatusNotFound
}

// failed logs at most once a minute.
func (v *Inventory) failed(msg string, err error) {
	v.logMu.Lock()
	defer v.logMu.Unlock()
	if v.Log == nil || time.Since(v.lastFail) < time.Minute {
		return
	}
	v.lastFail = time.Now()
	v.Log.Warn(msg, "err", err)
}

// Agent is one agent as listed: what every server heard from it.
type Agent struct {
	Key string `json:"key"`
	// Name is the computer's name the agent sends, "" for one set up
	// before agents sent it, and for an address that only refused the
	// certificate (Refusing).
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	// Servers are the names of the servers it sends to.
	Servers []string `json:"servers"`
	// Transport is how it sent last (tls or plain), and Transports every
	// way it sent.
	Transport  string   `json:"transport"`
	Transports []string `json:"transports"`
	// Local is true when it sent last from a server's own computer.
	Local     bool   `json:"local,omitempty"`
	Tag       string `json:"tag,omitempty"`
	Intake    string `json:"intake,omitempty"`
	TokenID   string `json:"token_id,omitempty"`
	TokenName string `json:"token_name,omitempty"`
	// CA are the pins of the certificate authorities its configuration
	// trusts, each entry one configuration's (as in Doc.CA), from the
	// documents of around its last batch.
	CA            []string `json:"ca"`
	ConfigVersion string   `json:"config_version,omitempty"`
	// CAMismatch is true when its pin differed from the one of a server
	// it sent to, at the time.
	CAMismatch bool      `json:"-"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Events1h   int64     `json:"events_1h"`
	Refused1h  int64     `json:"refused_1h"`
	// Refusing is true for an address that refused the certificate and
	// never got a batch through.
	Refusing bool `json:"refusing,omitempty"`
	// NeedsConfig is true when its configuration trusts only certificate
	// authorities the servers retired, so it needs a new configuration
	// from Add data; Reason says why (ReasonRetiredCA).
	NeedsConfig bool   `json:"needs_config,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// ReasonRetiredCA: the agent's configuration trusts only certificate
// authorities the servers retired when they took the cluster's.
const ReasonRetiredCA = "retired_ca"

// FlagRetired marks the agents whose configurations, around their last
// batch, trust a retired certificate authority (a pin in retired) and
// not the one in use (current): they need a new configuration. One that
// trusts both is fine.
func FlagRetired(agents []Agent, current string, retired []string) {
	if len(retired) == 0 {
		return
	}
	for i := range agents {
		a := &agents[i]
		old, cur := false, false
		for _, pins := range a.CA {
			if TrustsCA(pins, current) {
				cur = true
			}
			if slices.ContainsFunc(retired, func(p string) bool { return p != current && TrustsCA(pins, p) }) {
				old = true
			}
		}
		if old && !cur {
			a.NeedsConfig, a.Reason = true, ReasonRetiredCA
		}
	}
}

// List returns every agent any server heard from in the last 30 days,
// one row per agent, most recently heard from first, and how many more
// this server heard from than it keeps one by one. This server's counts
// are its own, not yet written ones. When OpenSearch cannot be read it
// returns this server's own agents with the error.
func (v *Inventory) List(ctx context.Context) ([]Agent, int64, error) {
	if v == nil {
		return []Agent{}, 0, nil
	}
	now := v.now().UTC()
	node := v.node()
	var docs []Doc
	var err error
	if v.Client != nil {
		var raw []store.Doc
		raw, err = v.Client.SearchDocs(ctx, v.index(), map[string]any{"term": map[string]any{"kind": Kind}})
		if notFound(err) {
			err = nil
		}
		for _, d := range raw {
			var doc Doc
			if json.Unmarshal(d.Source, &doc) != nil || doc.Agent == "" || doc.Node == node {
				continue
			}
			docs = append(docs, doc)
		}
		if err == nil {
			// This server's own written documents, for agents it has not
			// heard from since it started; the ones in memory are newer.
			for _, d := range raw {
				var doc Doc
				if json.Unmarshal(d.Source, &doc) == nil && doc.Node == node && doc.Agent != "" {
					docs = append(docs, doc)
				}
			}
		}
	}
	v.mu.Lock()
	mine := v.docsLocked(now, true)
	overflow := v.overflow
	v.mu.Unlock()
	if len(mine) > 0 {
		have := map[string]bool{}
		for _, d := range mine {
			have[d.Agent] = true
		}
		docs = slices.DeleteFunc(docs, func(d Doc) bool { return d.Node == node && have[d.Agent] })
		docs = append(docs, mine...)
	}
	agents := Merge(docs, now)
	if v.Retired != nil {
		FlagRetired(agents, v.serverCA(), v.Retired())
	}
	return agents, overflow, err
}

// Merge turns inventory documents into one row per agent. A refusing
// address joins the agents whose last address it is; otherwise it is a
// row of its own once it refused in minRefusedMinutes minutes of the last
// hour.
func Merge(docs []Doc, now time.Time) []Agent {
	byKey := map[string]*Agent{}
	latest := map[string]Doc{}
	var refusals []Doc
	var order []string
	for _, d := range docs {
		if now.Sub(d.LastSeen) >= keepFor {
			continue
		}
		if strings.HasPrefix(d.Agent, "addr-") {
			refusals = append(refusals, d)
			continue
		}
		a := byKey[d.Agent]
		if a == nil {
			a = &Agent{Key: d.Agent, FirstSeen: d.FirstSeen, Addresses: []string{}, Servers: []string{}, Transports: []string{}, CA: []string{}}
			byKey[d.Agent] = a
			order = append(order, d.Agent)
		}
		if d.FirstSeen.Before(a.FirstSeen) || a.FirstSeen.IsZero() {
			a.FirstSeen = d.FirstSeen
		}
		if l, ok := latest[d.Agent]; !ok || d.LastSeen.After(l.LastSeen) {
			latest[d.Agent] = d
		}
		addUnique(&a.Addresses, d.Address)
		addUnique(&a.Servers, d.Server)
		addUnique(&a.Transports, d.Transport)
		if now.Sub(d.LastSeen) < time.Hour {
			a.Events1h += d.Events1h
		}
	}
	for k, a := range byKey {
		l := latest[k]
		a.Name, a.LastSeen, a.Transport, a.Tag, a.Intake = l.Name, l.LastSeen, l.Transport, l.Tag, l.Intake
		a.TokenID, a.TokenName, a.ConfigVersion, a.Local = l.Token, l.TokenName, l.ConfigVersion, l.Local
		// The configuration it ran around its last batch, and whether it
		// trusted the servers it sent to then: an older one may have been
		// replaced since.
		for _, d := range docs {
			if d.Agent != k || l.LastSeen.Sub(d.LastSeen) >= time.Hour {
				continue
			}
			addUnique(&a.CA, d.CA)
			if d.CA != "" && d.ServerCA != "" && !TrustsCA(d.CA, d.ServerCA) {
				a.CAMismatch = true
			}
		}
	}
	// Refusals of the last hour, summed over servers per address.
	type refused struct {
		n, minutes int64
		last       time.Time
		first      time.Time
		servers    []string
	}
	byAddr := map[string]*refused{}
	var addrs []string
	for _, d := range refusals {
		if now.Sub(d.LastSeen) >= time.Hour || d.Refused1h == 0 {
			continue
		}
		r := byAddr[d.Address]
		if r == nil {
			r = &refused{first: d.FirstSeen}
			byAddr[d.Address] = r
			addrs = append(addrs, d.Address)
		}
		r.n += d.Refused1h
		r.minutes += int64(d.RefusedMinutes)
		if d.LastSeen.After(r.last) {
			r.last = d.LastSeen
		}
		if d.FirstSeen.Before(r.first) {
			r.first = d.FirstSeen
		}
		addUnique(&r.servers, d.Server)
	}
	for _, addr := range addrs {
		r := byAddr[addr]
		joined := false
		for _, a := range byKey {
			if latest[a.Key].Address == addr {
				a.Refused1h += r.n
				joined = true
			}
		}
		if joined || r.minutes < minRefusedMinutes {
			continue
		}
		key := refusedKey(addr)
		byKey[key] = &Agent{Key: key, Addresses: []string{addr}, Servers: r.servers, Transports: []string{TransportTLS},
			Transport: TransportTLS, CA: []string{}, FirstSeen: r.first, LastSeen: r.last, Refused1h: r.n, Refusing: true}
		order = append(order, key)
	}
	out := make([]Agent, 0, len(order))
	for _, k := range order {
		a := byKey[k]
		slices.Sort(a.Addresses)
		slices.Sort(a.Servers)
		slices.Sort(a.Transports)
		slices.Sort(a.CA)
		out = append(out, *a)
	}
	slices.SortStableFunc(out, func(x, y Agent) int {
		if c := y.LastSeen.Compare(x.LastSeen); c != 0 {
			return c
		}
		return strings.Compare(x.Key, y.Key)
	})
	return out
}

func addUnique(list *[]string, s string) {
	if s != "" && !slices.Contains(*list, s) {
		*list = append(*list, s)
	}
}
