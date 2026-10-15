package clustertls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

const prefix = "signalith"

// env is one fake OpenSearch with the cluster key, and a hub per server.
type env struct {
	t   *testing.T
	cl  *store.Client
	key *shared.ClusterKey
}

func newEnv(t *testing.T) *env {
	t.Helper()
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	if err := shared.EnsureConfig(context.Background(), cl, prefix); err != nil {
		t.Fatal(err)
	}
	key, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, cl: cl, key: key}
}

// server returns a TLS holder tracked on a new hub of server name.
func (e *env) server(name string) (*TLS, *shared.Hub) {
	e.t.Helper()
	h := shared.NewHub(shared.Options{NodeName: name})
	h.SetKeys(shared.NewKeySet(e.key))
	h.Use(e.cl, prefix)
	tl := New()
	tl.Track(h)
	if err := h.Cycle(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	return tl, h
}

type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
	pem  []byte
	fp   string
}

// makeCA makes a certificate authority; with dns, its name constraints
// permit those names, the private ranges and nothing else.
func makeCA(t *testing.T, cn string, notBefore time.Time, dns ...string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: notBefore, NotAfter: notBefore.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	if len(dns) > 0 {
		tmpl.PermittedDNSDomainsCritical = true
		tmpl.PermittedDNSDomains = append([]string{"localhost", "lan", "local"}, dns...)
		_, ten, _ := net.ParseCIDR("10.0.0.0/8")
		_, lo, _ := net.ParseCIDR("127.0.0.0/8")
		_, v6, _ := net.ParseCIDR("::1/128")
		tmpl.PermittedIPRanges = []*net.IPNet{ten, lo, v6}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), fp: tlsauto.Fingerprint(der)}
}

// Two servers publish at once: one wins, the same CA again counts as
// success, another CA gets ErrOtherCA.
func TestPublishRace(t *testing.T) {
	e := newEnv(t)
	ca := makeCA(t, "a", time.Now())
	other := makeCA(t, "b", time.Now())
	ta, _ := e.server("siem-a")
	tb, _ := e.server("siem-b")
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, tl := range []*TLS{ta, tb} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = tl.Publish(ctx, "admin", "siem", ca.pem, ca.key, []string{"agents.lan"})
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("publish %d: %v", i, err)
		}
	}
	if err := tb.Publish(ctx, "admin", "siem-b", other.pem, other.key, nil); !errors.Is(err, ErrOtherCA) {
		t.Errorf("another CA: %v", err)
	}
	b, ok := ta.Get()
	if !ok || !SameFingerprint(b.CASHA256, ca.fp) || !slices.Equal(b.Names, []string{"agents.lan"}) {
		t.Fatalf("doc %+v", b)
	}
	// The key is sealed, not in the clear.
	if strings.Contains(b.CAKey, "PRIVATE KEY") || !strings.HasPrefix(b.CAKey, "enc:") {
		t.Errorf("key stored as %.20q", b.CAKey)
	}
	// Each server opens it.
	for _, tl := range []*TLS{ta, tb} {
		c, k, err := tl.Store().Load()
		if err != nil || !c.Equal(ca.cert) || !samePublicKey(k.Public(), ca.key.Public()) {
			t.Errorf("load: %v", err)
		}
	}
}

// The sealed key is bound to the certificate's fingerprint: put under
// another certificate, it does not open.
func TestSealedKeyBoundToFingerprint(t *testing.T) {
	e := newEnv(t)
	ca := makeCA(t, "a", time.Now())
	other := makeCA(t, "b", time.Now())
	tl, _ := e.server("siem-a")
	if err := tl.Publish(context.Background(), "admin", "siem-a", ca.pem, ca.key, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := tl.Get()
	moved := *b
	moved.CACertPEM, moved.CASHA256 = string(other.pem), other.fp
	fresh := New()
	fresh.hub = tl.hub
	if _, _, err := fresh.open(&moved); err == nil {
		t.Fatal("a key moved under another certificate opened")
	}
	// Under its own certificate but another fingerprint claimed: refused.
	lying := *b
	lying.CASHA256 = other.fp
	if _, _, err := fresh.open(&lying); err == nil {
		t.Fatal("a body whose fingerprint lies opened")
	}
	if err := validate(&lying); err == nil {
		t.Error("validate passed a body whose fingerprint lies")
	}
	if _, _, err := fresh.open(b); err != nil {
		t.Errorf("the real one: %v", err)
	}
}

func TestAddName(t *testing.T) {
	e := newEnv(t)
	ca := makeCA(t, "a", time.Now(), "siem-a.example.com")
	ta, _ := e.server("siem-a")
	tb, _ := e.server("siem-b")
	ctx := context.Background()
	if err := ta.Store().AddName(ctx, "x.lan"); err == nil {
		t.Error("a name added with no CA published")
	}
	if err := ta.Publish(ctx, "admin", "siem-a", ca.pem, ca.key, []string{"www.example.org", "first.lan"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := ta.Get(); !slices.Equal(b.Names, []string{"first.lan"}) {
		t.Errorf("names the CA may not sign were published: %v", b.Names)
	}
	// Refused in the words a server of its own uses.
	err := tb.Store().AddName(ctx, "siem.example.org")
	if err == nil || !strings.Contains(err.Error(), "can't include siem.example.org") {
		t.Errorf("forbidden name: %v", err)
	}
	if err := tb.Store().AddName(ctx, "bad name"); err == nil {
		t.Error("bad name accepted")
	}
	// Up to MaxNames, oldest first out, once each.
	for i := range MaxNames + 3 {
		if err := tb.Store().AddName(ctx, "host"+string(rune('a'+i%26))+string(rune('a'+i/26))+".lan"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tb.Store().AddName(ctx, "HOSTBB.lan."); err != nil {
		t.Fatal(err)
	}
	if err := ta.Doc().Load(ctx); err != nil {
		t.Fatal(err)
	}
	names := ta.Store().Names()
	if len(names) != MaxNames || slices.Contains(names, "first.lan") || names[len(names)-1] != "hostbb.lan" ||
		slices.Index(names, "hostbb.lan") != len(names)-1 {
		t.Errorf("names %v", names)
	}
}

// The cluster's store gives tlsauto the published CA: a new server's
// certificate chains to it and covers the cluster's names.
func TestStoreWithManager(t *testing.T) {
	e := newEnv(t)
	ca := makeCA(t, "a", time.Now().Add(-time.Hour))
	tl, _ := e.server("siem-b")
	if err := tl.Publish(context.Background(), "admin", "siem-a", ca.pem, ca.key, []string{"agents.lan"}); err != nil {
		t.Fatal(err)
	}
	m, err := tlsauto.New(tlsauto.Options{Dir: filepath.Join(t.TempDir(), "tls"), Store: tl.Store()})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	if _, err := m.Leaf().Verify(x509.VerifyOptions{Roots: pool, DNSName: "agents.lan"}); err != nil {
		t.Error(err)
	}
	if m.Store() != tlsauto.KindCluster || m.Fingerprint() != ca.fp {
		t.Errorf("store %s fp %s", m.Store(), m.Fingerprint())
	}
	if err := tl.Store().Make(ca.cert); err == nil {
		t.Error("the cluster store made a CA")
	}
}

func hb(name string, ca testCA, seen time.Time, founder bool, names ...string) Server {
	return Server{NodeID: "n_" + name, Name: name, SeenAt: seen, CACertPEM: string(ca.pem), Founder: founder, Names: names,
		Up: time.Since(seen) < time.Hour}
}

func agent(key string, pins []string, servers []string, last time.Time) agentinv.Agent {
	return agentinv.Agent{Key: key, Name: key, CA: pins, Servers: servers, Transports: []string{agentinv.TransportTLS}, LastSeen: last}
}

func TestCandidates(t *testing.T) {
	now := time.Now()
	old := makeCA(t, "old", now.AddDate(-2, 0, 0), "siem-a.example.com")
	young := makeCA(t, "young", now.AddDate(-1, 0, 0), "siem-b.example.com")
	pin := func(c testCA) string { return agentinv.Pin(c.fp) }
	servers := []Server{
		hb("siem-a", old, now.Add(-time.Minute), false, "siem-a.example.com", "10.0.0.1"),
		hb("siem-b", young, now.Add(-time.Minute), true, "siem-b.example.com"),
		hb("siem-c", young, now.Add(-time.Minute), false, "10.0.0.3"),
		// Not seen for two days: it counts for nothing.
		hb("siem-gone", makeCA(t, "gone", now, "x.example.com"), now.Add(-48*time.Hour), false, "x.example.com"),
		// Its own certificate files: no candidate.
		{NodeID: "n_siem-f", Name: "siem-f", SeenAt: now, Files: true, Up: true, CACertPEM: string(makeCA(t, "corp", now).pem)},
	}
	agents := []agentinv.Agent{
		agent("a1", []string{pin(old)}, []string{"siem-a"}, now),
		agent("a2", []string{pin(old)}, []string{"siem-a"}, now),
		agent("both", []string{pin(old) + "," + pin(young)}, []string{"siem-b"}, now),
		agent("b1", []string{pin(young)}, []string{"siem-b"}, now),
		// No pin: by the servers it reached over HTTPS this week.
		agent("nopin", nil, []string{"siem-c"}, now.Add(-time.Hour)),
		agent("stale", nil, []string{"siem-c"}, now.Add(-8*24*time.Hour)),
		{Key: "plain", Transports: []string{agentinv.TransportPlain}, Servers: []string{"siem-a"}, LastSeen: now, CA: []string{}},
		{Key: "refusing", Refusing: true, Transports: []string{agentinv.TransportTLS}, LastSeen: now},
		// Sends only to the server with its own certificate files: no
		// choice changes it, so it breaks under none.
		agent("files", nil, []string{"siem-f"}, now),
		agent("files-pinned", []string{"0123456789abcdef"}, []string{"siem-f"}, now),
	}
	cs := Candidates(servers, agents, now)
	if len(cs) != 2 {
		t.Fatalf("%d candidates: %+v", len(cs), cs)
	}
	keys := func(rs []AgentRef) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.Key)
		}
		slices.Sort(out)
		return out
	}
	y, o := cs[0], cs[1]
	// young: b1, both, nopin (3) beats old: a1, a2, both (3) on the tie
	// by the founder.
	if !y.Preselected || o.Preselected || y.CASHA256 != young.fp || !y.Founder {
		t.Fatalf("preselected %+v", y)
	}
	if !slices.Equal(y.Servers, []string{"siem-b", "siem-c"}) || !slices.Equal(y.NodeIDs, []string{"n_siem-b", "n_siem-c"}) {
		t.Errorf("servers %v %v", y.Servers, y.NodeIDs)
	}
	if got := keys(y.Agents); !slices.Equal(got, []string{"b1", "both", "nopin"}) {
		t.Errorf("young agents %v", got)
	}
	if got := keys(y.Breaks); !slices.Equal(got, []string{"a1", "a2"}) {
		t.Errorf("young breaks %v", got)
	}
	if got := keys(o.Agents); !slices.Equal(got, []string{"a1", "a2", "both"}) {
		t.Errorf("old agents %v", got)
	}
	if got := keys(o.Breaks); !slices.Equal(got, []string{"b1", "nopin"}) {
		t.Errorf("old breaks %v", got)
	}
	// Each one's constraints forbid the other's server name.
	if len(y.CannotCover) != 1 || y.CannotCover[0].Server != "siem-a" || !slices.Equal(y.CannotCover[0].Names, []string{"siem-a.example.com"}) {
		t.Errorf("young cannot cover %+v", y.CannotCover)
	}
	if len(o.CannotCover) != 1 || o.CannotCover[0].Server != "siem-b" {
		t.Errorf("old cannot cover %+v", o.CannotCover)
	}

	// More agents win over the founder.
	agents = append(agents, agent("a3", []string{pin(old)}, []string{"siem-a"}, now))
	if cs := Candidates(servers, agents, now); cs[0].CASHA256 != old.fp || !cs[0].Preselected {
		t.Errorf("most agents: %s", cs[0].Subject)
	}
	// No founder among them: the oldest.
	servers[1].Founder = false
	if cs := Candidates(servers, agents[:4], now); cs[0].CASHA256 != old.fp {
		t.Errorf("oldest: %s", cs[0].Subject)
	}
	// One CA, or none.
	if cs := Candidates(servers[:1], nil, now); len(cs) != 1 || !cs[0].Preselected || len(cs[0].Breaks) != 0 {
		t.Errorf("one: %+v", cs)
	}
	// One CA and a server with its own files: its agents break under
	// neither.
	if cs := Candidates([]Server{servers[0], servers[4]}, agents, now); len(cs) != 1 || cs[0].BreakCount != 0 {
		t.Errorf("one and files: %+v", cs)
	}
	// The servers that run come first, to publish it; with none running,
	// it cannot be published now.
	down := slices.Clone(servers)
	down[1].Up = false
	for _, c := range Candidates(down, agents, now) {
		if c.CASHA256 == young.fp && (!c.Up || c.NodeIDs[0] != "n_siem-c" || c.Servers[0] != "siem-c") {
			t.Errorf("running first: %+v %v", c.NodeIDs, c.Up)
		}
	}
	down[2].Up = false
	for _, c := range Candidates(down, agents, now) {
		if c.CASHA256 == young.fp && c.Up {
			t.Error("up with no server running")
		}
	}
	if cs := Candidates(servers[4:], nil, now); len(cs) != 0 {
		t.Errorf("files mode: %+v", cs)
	}
}

func TestImporter(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	ca := makeCA(t, "a", now)
	other := makeCA(t, "b", now)
	local := func(c testCA) LocalCA {
		return func() (*x509.Certificate, crypto.Signer, []string) { return c.cert, c.key, []string{"agents.lan"} }
	}

	// Files mode: nothing to import.
	e := newEnv(t)
	tl, _ := e.server("siem-a")
	im := Importer(ImporterOptions{TLS: tl, Local: func() (*x509.Certificate, crypto.Signer, []string) { return nil, nil, nil }})
	if h, err := im.Source(); err != nil || h != "" || im.Name != shared.ImportTLS || im.MinLevel != shared.LevelSharedTLS {
		t.Errorf("files mode source %q %v", h, err)
	}

	// Two CAs among the servers: nothing published, and no error.
	servers := []Server{hb("siem-a", ca, now, true), hb("siem-b", other, now, false)}
	var readErr error
	im = Importer(ImporterOptions{TLS: tl, Local: local(ca), Node: "siem-a",
		Servers: func(context.Context) ([]Server, error) { return servers, readErr }})
	if h, _ := im.Source(); h != ca.fp {
		t.Errorf("source %q", h)
	}
	if err := im.Run(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, ok := tl.Get(); ok {
		t.Fatal("published with two CAs")
	}

	// The heartbeats cannot be read: nothing published, and an error, so
	// the import is tried again.
	servers, readErr = nil, errors.New("timeout")
	if err := im.Run(ctx, "admin"); err == nil {
		t.Fatal("no error when the heartbeats cannot be read")
	}
	if _, ok := tl.Get(); ok {
		t.Fatal("published without the heartbeats")
	}
	readErr = nil
	if err := Importer(ImporterOptions{TLS: tl, Local: local(ca)}).Run(ctx, "admin"); err == nil {
		t.Fatal("no error without a way to read the heartbeats")
	}

	// One (the other server has none of its own, or is long gone): it
	// publishes the founder's.
	servers = []Server{hb("siem-a", ca, now, true), hb("siem-b", other, now.Add(-48*time.Hour), false), {Name: "siem-f", SeenAt: now},
		// Its own certificate files, from another root: it keeps them.
		{Name: "siem-g", SeenAt: now, Files: true, CACertPEM: string(other.pem)}}
	if err := im.Run(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
	b, ok := tl.Get()
	if !ok || !SameFingerprint(b.CASHA256, ca.fp) || b.PublishedBy != "siem-a" || !slices.Equal(b.Names, []string{"agents.lan"}) {
		t.Fatalf("published %+v", b)
	}
	// Again: nothing to do.
	if err := im.Run(ctx, "admin"); err != nil {
		t.Fatal(err)
	}
}

func TestPublishRequest(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	ca := makeCA(t, "a", time.Now())
	other := makeCA(t, "b", time.Now())
	tl, _ := e.server("siem-b")
	cur := ca
	h := Handler(tl, func() (*x509.Certificate, crypto.Signer, []string) { return cur.cert, cur.key, nil }, "siem-b", nil)
	signed := func(fp string, at time.Time, edit func(*PublishArgs)) *shared.Request {
		a, err := tl.publishArgs("n_b", fp, "admin", at)
		if err != nil {
			t.Fatal(err)
		}
		if edit != nil {
			edit(&a)
		}
		raw, _ := json.Marshal(a)
		return &shared.Request{ID: "rq_1", Type: RequestPublish, Target: "n_b", Args: raw, RequestedBy: "admin"}
	}
	req := func(fp string) *shared.Request { return signed(fp, time.Now(), nil) }
	// Not signed with the cluster key, or signed for something else, or
	// long ago: refused, nothing published.
	unsigned, _ := json.Marshal(PublishArgs{CASHA256: ca.fp, Target: "n_b", By: "admin", At: time.Now()})
	other2, _ := shared.NewClusterKey()
	for name, r := range map[string]*shared.Request{
		"unsigned":   {ID: "rq_0", Target: "n_b", Args: unsigned, RequestedBy: "admin"},
		"other user": signed(ca.fp, time.Now(), func(a *PublishArgs) { a.By = "mallory" }),
		"other fp":   signed(ca.fp, time.Now(), func(a *PublishArgs) { a.CASHA256 = other.fp }),
		"other key":  signed(ca.fp, time.Now(), func(a *PublishArgs) { a.KeyID = other2.ID() }),
		"old":        signed(ca.fp, time.Now().Add(-2*time.Hour), nil),
		"ahead":      signed(ca.fp, time.Now().Add(time.Hour), nil),
	} {
		if err := h(ctx, r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	forged := req(ca.fp)
	forged.RequestedBy = "mallory"
	if err := h(ctx, forged); err == nil {
		t.Error("requester changed: accepted")
	}
	forged = req(ca.fp)
	forged.Target = "n_c"
	if err := h(ctx, forged); err == nil {
		t.Error("target changed: accepted")
	}
	if _, ok := tl.Get(); ok {
		t.Fatal("published on a request not signed for it")
	}
	// Chosen when this server had another CA: refused.
	if err := h(ctx, req(other.fp)); err == nil || !strings.Contains(err.Error(), "changed since it was chosen") {
		t.Errorf("stale fingerprint: %v", err)
	}
	if _, ok := tl.Get(); ok {
		t.Fatal("published anyway")
	}
	if err := h(ctx, &shared.Request{Args: json.RawMessage(`{}`)}); err == nil {
		t.Error("no fingerprint accepted")
	}
	r := req(strings.ToLower(strings.ReplaceAll(ca.fp, ":", "")))
	if err := h(ctx, r); err != nil {
		t.Fatal(err)
	}
	if b, ok := tl.Get(); !ok || !SameFingerprint(b.CASHA256, ca.fp) {
		t.Fatal("not published")
	}
	var res PublishResult
	if json.Unmarshal(r.Result, &res) != nil || res.CASHA256 != ca.fp {
		t.Errorf("result %s", r.Result)
	}
	// Again: already there. Another one: refused.
	if err := h(ctx, req(ca.fp)); err != nil {
		t.Error(err)
	}
	cur = other
	if err := h(ctx, req(other.fp)); !errors.Is(err, ErrOtherCA) {
		t.Errorf("second CA: %v", err)
	}
}

// AddRetired records a server's old certificate authority once, never the
// cluster's own, and every server reads it.
func TestAddRetired(t *testing.T) {
	e := newEnv(t)
	ca := makeCA(t, "cluster", time.Now())
	old := makeCA(t, "siem-b's own", time.Now())
	ta, _ := e.server("siem-a")
	tb, hb := e.server("siem-b")
	ctx := context.Background()
	if err := tb.AddRetired(ctx, "siem-b", old.cert); err == nil {
		t.Fatal("AddRetired without a tls document")
	}
	if err := ta.Publish(ctx, "admin", "siem-a", ca.pem, ca.key, nil); err != nil {
		t.Fatal(err)
	}
	if err := hb.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := tb.AddRetired(ctx, "siem-b", old.cert); err != nil {
			t.Fatal(err)
		}
	}
	if err := tb.AddRetired(ctx, "siem-b", ca.cert); err != nil {
		t.Fatal(err)
	}
	if err := ta.Doc().Load(ctx); err != nil {
		t.Fatal(err)
	}
	b, _ := ta.Get()
	if fps := b.RetiredFingerprints(); len(fps) != 1 || !SameFingerprint(fps[0], old.fp) || b.Retired[0].Server != "siem-b" {
		t.Fatalf("retired %+v", b.Retired)
	}
}
