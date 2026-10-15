package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/clusterjoin"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/opensearchcheck"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// joinFixture is a cluster to join: its OpenSearch (over HTTPS, with
// sign-in), its cluster document signed with its key, and the server that
// answers joins.
type joinFixture struct {
	t      *testing.T
	os     *ostest.Server
	osCA   string
	key    *shared.ClusterKey
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	srv    *httptest.Server
	tok    clusterjoin.Token
	status int // what POST /api/cluster/join answers; 0 is 200

	mu       sync.Mutex
	requests []clusterjoin.Request
	// edit changes the bundle before it is sealed.
	edit func(*clusterjoin.Bundle)
}

const joinPrefix = "signalith"

func newJoinFixture(t *testing.T) *joinFixture {
	t.Helper()
	f := &joinFixture{t: t}
	s, h := ostest.NewHandler()
	s.Server = httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	s.Secure(&ostest.Account{User: "signalith", Password: "os-pw"})
	f.os = s
	f.osCA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
	var err error
	if f.key, err = shared.NewClusterKey(); err != nil {
		t.Fatal(err)
	}
	f.putClusterDoc(f.key, "c_test")

	// The cluster's certificate authority.
	f.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Signalith cluster CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, f.caKey.Public(), f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	f.ca, _ = x509.ParseCertificate(der)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/cluster/join/ca", func(w http.ResponseWriter, r *http.Request) {
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	})
	mux.HandleFunc("POST /api/cluster/join", f.answer)
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	id, _ := clusterjoin.NewID()
	secret, _ := clusterjoin.NewSecret()
	f.tok = clusterjoin.Token{URL: f.srv.URL, CA: clusterjoin.Pin(f.srv.Certificate().Raw), ID: id, Secret: secret}
	return f
}

// putClusterDoc puts the cluster document, signed with k, in OpenSearch.
func (f *joinFixture) putClusterDoc(k *shared.ClusterKey, clusterID string) {
	body, _ := json.Marshal(map[string]any{"cluster_id": clusterID, "name": "Plant", "level": shared.LevelMax})
	e := shared.Envelope{Kind: "cluster", ID: shared.ClusterDocID, Format: 1, Rev: 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		UpdatedBy: shared.By{User: "admin", Node: "n_a"}, Body: string(body)}
	if err := shared.Sign(k, shared.ClusterDocID, &e); err != nil {
		f.t.Fatal(err)
	}
	raw, _ := json.Marshal(e)
	var src map[string]any
	_ = json.Unmarshal(raw, &src)
	f.os.Put(shared.ConfigIndex(joinPrefix), shared.ClusterDocID, src)
}

func (f *joinFixture) answer(w http.ResponseWriter, r *http.Request) {
	var req clusterjoin.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.mu.Unlock()
	if f.status != 0 {
		w.WriteHeader(f.status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": clusterjoin.Refused})
		return
	}
	raw, _ := base64.StdEncoding.DecodeString(f.key.Text())
	b := &clusterjoin.Bundle{ClusterID: "c_test", ClusterName: "Plant", IndexPrefix: joinPrefix, KID: f.key.ID(), ClusterKey: raw,
		OpenSearch: clusterjoin.OpenSearch{URL: f.os.URL, CAPEM: f.osCA, Username: "signalith", Password: "os-pw", Shared: true},
		NodeName:   req.Name, Listen: "0.0.0.0:8443", IssuerVersion: version, Level: shared.LevelMax}
	if req.CopySyslog {
		b.Syslog = &clusterjoin.SyslogDefaults{UDP: "0.0.0.0:5514"}
	}
	if req.CSRPEM != "" {
		leaf, err := tlsauto.SignCSR(f.ca, f.caKey, []byte(req.CSRPEM), req.Names, time.Now())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		b.ClusterCAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw}))
		b.LeafPEM = string(leaf)
	}
	if f.edit != nil {
		f.edit(b)
	}
	nodePub, _ := base64.RawURLEncoding.DecodeString(req.NodePub)
	sealed, err := clusterjoin.Seal(b, nodePub, req.NodeID, f.tok.ID, f.tok.Secret)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_ = json.NewEncoder(w).Encode(clusterjoin.Reply{Sealed: sealed})
}

func (f *joinFixture) joins() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// joinMachine is the machine that joins: its folders and what join did
// to its service.
type joinMachine struct {
	dir, config, state, dropIn string
	out                        bytes.Buffer
	env                        *joinEnv
	started                    int
	systemctl                  [][]string
	chowned                    map[string][2]int
}

func newJoinMachine(t *testing.T) *joinMachine {
	t.Helper()
	m := &joinMachine{dir: t.TempDir(), chowned: map[string][2]int{}}
	m.config = filepath.Join(m.dir, "etc", "signalith.yaml")
	m.state = filepath.Join(m.dir, "state")
	m.dropIn = filepath.Join(m.dir, "systemd", "signalith.service.d")
	t.Setenv("SIGNALITH_STATE_DIR", m.state)
	t.Setenv("SIGNALITH_MASTER_KEY", "")
	t.Setenv("SIGNALITH_NODE_NAME", "")
	t.Setenv(clusterKeyFileEnv, "")
	before := secrets.Default()
	t.Cleanup(func() { secrets.SetDefault(before) })
	var mu sync.Mutex
	m.env = &joinEnv{
		out: &m.out, errOut: &m.out, in: strings.NewReader(""),
		getenv: func(string) string { return "" }, goos: "linux", admin: true,
		serviceEnv:    func(string) {},
		serviceActive: func() bool { return false },
		startService:  func() error { m.started++; return nil },
		systemctl: func(args ...string) error {
			m.systemctl = append(m.systemctl, args)
			return nil
		},
		dropInDir: m.dropIn,
		owner:     func() (int, int, bool) { return 4242, 4343, true },
		chown: func(p string, uid, gid int) error {
			mu.Lock()
			defer mu.Unlock()
			m.chowned[p] = [2]int{uid, gid}
			return nil
		},
		check:      opensearchcheck.Check,
		listenFree: func(string) error { return nil },
		transport:  func() *http.Transport { return http.DefaultTransport.(*http.Transport).Clone() },
		now:        time.Now,
	}
	return m
}

func (m *joinMachine) join(t *testing.T, tok clusterjoin.Token, args ...string) int {
	t.Helper()
	return runJoin(context.Background(), m.env, append([]string{tok.String(), "-c", m.config, "--name", "siem-c", "--yes"}, args...))
}

// files lists the files under dir, relative to it.
func files(dir string) []string {
	var out []string
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	slices.Sort(out)
	return out
}

// identityFile reports whether p is part of the identity a package
// install makes too: node.id, the node key and the master key.
func identityFile(p string) bool {
	return p == "state/node.id" || strings.HasPrefix(p, "state/cluster/") || strings.HasPrefix(p, "state/keys/node") || strings.Contains(p, "master")
}

func TestJoinWritesEverything(t *testing.T) {
	f := newJoinFixture(t)
	m := newJoinMachine(t)
	listen := freeAddr(t)
	if code := m.join(t, f.tok, "--listen", listen, "--node-url", "https://siem-c.internal:8443", "--copy-syslog"); code != joinExitOK {
		t.Fatalf("exit %d:\n%s", code, m.out.String())
	}
	out := m.out.String()
	if !strings.Contains(out, "siem-c joined Plant. Add it to your load balancer: https://siem-c.internal:8443") || m.started != 1 {
		t.Errorf("output %q, started %d", out, m.started)
	}
	if strings.Contains(out, "os-pw") || strings.Contains(out, f.tok.String()) {
		t.Error("the output shows a secret")
	}
	req := f.requests[0]
	if req.Name != "siem-c" || req.NodeURL != "https://siem-c.internal:8443" || !req.CopySyslog || req.CSRPEM == "" || !slices.Contains(req.Names, "siem-c.internal") {
		t.Errorf("request %+v", req)
	}

	// The configuration loads with what the cluster sent.
	c, err := config.Load(m.config)
	if err != nil {
		t.Fatal(err)
	}
	if c.OpenSearch.URL != f.os.URL || c.OpenSearch.Username != "signalith" || c.OpenSearch.Password != "os-pw" || c.OpenSearch.IndexPrefix != joinPrefix ||
		c.Server.Listen != listen || c.Server.NodeURL != "https://siem-c.internal:8443" || c.Syslog.UDP != "0.0.0.0:5514" {
		t.Errorf("config: %+v %+v", c.OpenSearch, c.Server)
	}
	ca, _, _ := c.OpenSearchTLSFiles()
	if b, _ := os.ReadFile(ca); string(b) != f.osCA {
		t.Error("OpenSearch's certificate authority was not written")
	}
	settings, _ := os.ReadFile(c.SettingsFile())
	if strings.Contains(string(settings), "os-pw") || !strings.Contains(string(settings), "changed_by: signalith join") {
		t.Errorf("settings file:\n%s", settings)
	}
	// The cluster key, sealed with the master key.
	held, err := shared.KeyStore{Dir: m.state, Master: c.Keyring()}.ClusterKeys()
	if err != nil || len(held) != 1 || held[0].ID() != f.key.ID() {
		t.Fatalf("cluster keys %v %v", held, err)
	}
	// The HTTPS certificate from the cluster's certificate authority: the
	// server starts on it and never makes its own.
	tm, err := tlsauto.New(tlsauto.Options{Dir: c.TLSDir()})
	if err != nil {
		t.Fatal(err)
	}
	if tm.Store() != tlsauto.KindCluster || tm.Leaf() == nil || tm.Leaf().CheckSignatureFrom(f.ca) != nil {
		t.Errorf("tls store %s", tm.Store())
	}
	// Owners: the folders join wrote in are the service's, signalith.yaml
	// root's with the service's group.
	if got := m.chowned[m.config]; got != [2]int{0, 4343} {
		t.Errorf("signalith.yaml owner %v", got)
	}
	for _, p := range []string{m.state, filepath.Join(m.state, "keys"), shared.ClusterKeyPath(m.state, f.key.ID()), filepath.Join(m.state, "opensearch", "ca.pem"), c.SettingsFile(),
		filepath.Join(c.TLSDir(), "server.key")} {
		if got := m.chowned[p]; got != [2]int{4242, 4343} {
			t.Errorf("%s owner %v", p, got)
		}
	}
	for p := range m.chowned {
		if !within(p, m.dir) {
			t.Errorf("gave %s away, outside what join made", p)
		}
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(m.config); err != nil || fi.Mode().Perm() != 0o640 {
			t.Errorf("signalith.yaml mode %v", fi.Mode())
		}
	}
	// The archive folder is outside /var/lib/signalith.
	conf, err := os.ReadFile(filepath.Join(m.dropIn, "archive.conf"))
	if err != nil || !strings.Contains(string(conf), "ReadWritePaths="+c.ArchiveDir()+"\n") {
		t.Errorf("drop-in %q %v", conf, err)
	}
	if !slices.ContainsFunc(m.systemctl, func(a []string) bool { return slices.Equal(a, []string{"daemon-reload"}) }) {
		t.Errorf("systemctl %v", m.systemctl)
	}

	// A second join on the same machine is refused: it is a member.
	m.out.Reset()
	if code := m.join(t, f.tok); code != joinExitFailed || !strings.Contains(m.out.String(), "signalith cluster leave") {
		t.Errorf("second join: %d %s", code, m.out.String())
	}
	if f.joins() != 1 {
		t.Error("a member asked to join again")
	}
}

func TestJoinPinMismatch(t *testing.T) {
	f := newJoinFixture(t)
	m := newJoinMachine(t)
	other := httptest.NewTLSServer(http.NotFoundHandler())
	defer other.Close()
	tok := f.tok
	tok.CA = clusterjoin.Pin([]byte("another certificate"))
	if code := m.join(t, tok, "--no-start"); code != joinExitPin {
		t.Fatalf("exit %d: %s", code, m.out.String())
	}
	if !strings.Contains(m.out.String(), "does not have the certificate this token names. Someone may be intercepting the connection, or the token belongs to another cluster.") {
		t.Errorf("message %q", m.out.String())
	}
	if f.joins() != 0 || len(files(m.dir)) != 0 {
		t.Errorf("joined %d, wrote %v", f.joins(), files(m.dir))
	}
}

func TestJoinRefusedToken(t *testing.T) {
	f := newJoinFixture(t)
	f.status = http.StatusForbidden
	m := newJoinMachine(t)
	if code := m.join(t, f.tok, "--no-start"); code != joinExitRefused || !strings.Contains(m.out.String(), clusterjoin.Refused) {
		t.Fatalf("exit %d: %s", code, m.out.String())
	}
	if code := runJoin(context.Background(), m.env, []string{"SJ1.nonsense", "--yes"}); code != joinExitRefused {
		t.Errorf("a token that is not one: %d", code)
	}
}

func TestJoinPreflightWritesNothing(t *testing.T) {
	cases := map[string]func(f *joinFixture){
		"wrong password": func(f *joinFixture) {
			f.edit = func(b *clusterjoin.Bundle) { b.OpenSearch.Password = "nope" }
		},
		"another cluster's document": func(f *joinFixture) {
			other, _ := shared.NewClusterKey()
			f.putClusterDoc(other, "c_test")
		},
		"clock": func(f *joinFixture) { f.os.Offset = 10 * time.Second },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newJoinFixture(t)
			setup(f)
			m := newJoinMachine(t)
			if code := m.join(t, f.tok, "--no-start"); code != joinExitPreflight {
				t.Fatalf("exit %d: %s", code, m.out.String())
			}
			if !strings.Contains(m.out.String(), "FAIL") || !strings.Contains(m.out.String(), "make a new one") {
				t.Errorf("output %s", m.out.String())
			}
			// Only the identity a package install makes too.
			for _, p := range files(m.dir) {
				if !identityFile(p) {
					t.Errorf("wrote %s", p)
				}
			}
		})
	}
	// The listen address in use.
	f := newJoinFixture(t)
	m := newJoinMachine(t)
	m.env.listenFree = func(string) error { return os.ErrExist }
	if code := m.join(t, f.tok, "--no-start"); code != joinExitPreflight || !strings.Contains(m.out.String(), "is in use") {
		t.Errorf("listen in use: %d %s", code, m.out.String())
	}
}

func TestJoinRollsBack(t *testing.T) {
	f := newJoinFixture(t)
	m := newJoinMachine(t)
	// The server's own certificate authority, made at install, with a
	// change of certificate authority in progress: the seed fails.
	tlsDir := filepath.Join(m.state, "tls")
	if _, err := tlsauto.New(tlsauto.Options{Dir: tlsDir}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tlsDir, "next"), 0o700); err != nil {
		t.Fatal(err)
	}
	before := files(m.dir)
	tlsBefore := map[string]string{}
	for _, p := range files(tlsDir) {
		b, _ := os.ReadFile(filepath.Join(tlsDir, p))
		tlsBefore[p] = string(b)
	}
	if code := m.join(t, f.tok); code != joinExitWrite {
		t.Fatalf("exit %d: %s", code, m.out.String())
	}
	if m.started != 0 || !strings.Contains(m.out.String(), "nothing was kept") {
		t.Errorf("started %d: %s", m.started, m.out.String())
	}
	for _, p := range files(m.dir) {
		if !slices.Contains(before, p) && !identityFile(p) {
			t.Errorf("%s was left behind", p)
		}
	}
	for p, data := range tlsBefore {
		if b, err := os.ReadFile(filepath.Join(tlsDir, p)); err != nil || string(b) != data {
			t.Errorf("tls/%s was not put back", p)
		}
	}
	if len(shared.ClusterKeyFiles(m.state)) != 0 {
		t.Error("the cluster key was left behind")
	}
}

func TestJoinRefusals(t *testing.T) {
	f := newJoinFixture(t)
	m := newJoinMachine(t)
	m.env.admin = false
	if code := m.join(t, f.tok); code != joinExitFailed || !strings.Contains(m.out.String(), "root") {
		t.Errorf("not root: %d %s", code, m.out.String())
	}
	m.env.admin = true
	m.out.Reset()
	if code := runJoin(context.Background(), m.env, []string{f.tok.String(), "-c", m.config, "--name", "not a name", "--yes"}); code != joinExitFailed || f.joins() != 0 {
		t.Errorf("bad name: %d %s", code, m.out.String())
	}
	// Without --yes on a terminal, join asks first.
	m.out.Reset()
	m.env.terminal, m.env.in = true, strings.NewReader("n\n")
	if code := runJoin(context.Background(), m.env, []string{f.tok.String(), "-c", m.config, "--name", "siem-c"}); code != joinExitFailed || f.joins() != 0 {
		t.Errorf("answered no: %d %s", code, m.out.String())
	}
}

func TestJoinServiceDoesNotStart(t *testing.T) {
	f := newJoinFixture(t)
	m := newJoinMachine(t)
	m.env.startService = func() error { return os.ErrPermission }
	if code := m.join(t, f.tok); code != joinExitStart {
		t.Fatalf("exit %d: %s", code, m.out.String())
	}
	if len(shared.ClusterKeyFiles(m.state)) != 1 {
		t.Error("what was written was undone")
	}
}

func TestOpenSearchCheckCommand(t *testing.T) {
	f := newJoinFixture(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, []byte(f.osCA), 0o666); err != nil {
		t.Fatal(err)
	}
	env := func(k string) string {
		if k == "SIGNALITH_OPENSEARCH_PASSWORD" {
			return "os-pw"
		}
		return ""
	}
	var out bytes.Buffer
	if err := runOpenSearchCheck(context.Background(), []string{f.os.URL, "--ca", caFile, "--user", "signalith"}, &out, env, opensearchcheck.Check); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	out.Reset()
	if err := runOpenSearchCheck(context.Background(), []string{f.os.URL, "--user", "signalith"}, &out, env, opensearchcheck.Check); err == nil || !strings.Contains(out.String(), "not trusted") {
		t.Errorf("without the CA: %v\n%s", err, out.String())
	}
	if err := runOpenSearchCheck(context.Background(), []string{f.os.URL, "--cert", "x"}, &out, env, opensearchcheck.Check); err == nil {
		t.Error("--cert without --key")
	}
}

func TestGiveTree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owners are Unix's")
	}
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "a", "b"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "a", "b", "f"), nil, 0o600)
	outside := t.TempDir()
	_ = os.Symlink(outside, filepath.Join(dir, "a", "link"))
	var got []string
	if err := giveTree(filepath.Join(dir, "a"), 1, 2, func(p string, uid, gid int) error {
		got = append(got, p)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || slices.ContainsFunc(got, func(p string) bool { return strings.HasPrefix(p, outside) }) {
		t.Errorf("gave %v", got)
	}
	if err := giveTree(filepath.Join(dir, "missing"), 1, 2, nil); err != nil {
		t.Error(err)
	}
}

func TestWithin(t *testing.T) {
	for _, c := range []struct {
		p, dir string
		want   bool
	}{{"/var/lib/signalith/archive", "/var/lib/signalith", true}, {"/var/lib/signalith", "/var/lib/signalith", true},
		{"/srv/archive", "/var/lib/signalith", false}, {"/var/lib/signalith-old", "/var/lib/signalith", false}} {
		if within(filepath.FromSlash(c.p), filepath.FromSlash(c.dir)) != c.want {
			t.Errorf("within(%s, %s)", c.p, c.dir)
		}
	}
}
