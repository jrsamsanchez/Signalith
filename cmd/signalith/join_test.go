package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"maps"
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

	"github.com/jrsamsanchez/signalith/internal/cluster"
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
	// reply is the error text with status; "" is Refused.
	reply string

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
		_ = json.NewEncoder(w).Encode(map[string]string{"error": cmp.Or(f.reply, clusterjoin.Refused)})
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
		getenv: func(string) string { return "" }, goos: "linux", admin: true, root: true,
		serviceEnv:    func(string) {},
		serviceActive: func() bool { return false },
		startService:  func() error { m.started++; return nil },
		systemctl: func(args ...string) error {
			m.systemctl = append(m.systemctl, args)
			return nil
		},
		dropInDir: m.dropIn,
		owner:     func() (int, int, bool) { return 4242, 4343, true },
		chownFD: func(_ int, p string, uid, gid int) error {
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
	if req.Name != "siem-c" || req.NodeURL != "https://siem-c.internal:8443" || !req.CopySyslog || req.CSRPEM == "" || req.OSCSRPEM == "" || !slices.Contains(req.Names, "siem-c.internal") {
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
	// Owners: what join wrote is the service's, signalith.yaml root's with
	// the service's group, and nothing else: not the folders it only wrote
	// in (the lookups folder of settings.yaml was made by join here).
	if runtime.GOOS != "linux" {
		m.chowned[m.config] = [2]int{0, 4343}
	}
	if got := m.chowned[m.config]; runtime.GOOS == "linux" && got != [2]int{0, 4343} {
		t.Errorf("signalith.yaml owner %v", got)
	}
	for _, p := range []string{m.state, filepath.Join(m.state, "keys"), shared.ClusterKeyPath(m.state, f.key.ID()), filepath.Join(m.state, "opensearch", "ca.pem"), c.SettingsFile(),
		filepath.Join(c.TLSDir(), "server.key")} {
		if got := m.chowned[p]; runtime.GOOS == "linux" && got != [2]int{4242, 4343} {
			t.Errorf("%s owner %v", p, got)
		}
	}
	if strings.Contains(m.out.String(), "opensearch.join-tmp") || slices.ContainsFunc(files(m.dir), func(p string) bool { return strings.Contains(p, "join-tmp") }) {
		t.Error("the preflight's folder was left")
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
	if code := m.join(t, f.tok); code != joinExitFailed || !strings.Contains(m.out.String(), "belongs to a cluster already") {
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
	type look struct {
		mode     os.FileMode
		uid, gid int
	}
	looks := map[string]look{}
	asRoot := runtime.GOOS == "linux" && os.Geteuid() == 0
	_ = filepath.Walk(tlsDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if asRoot {
			// As the service's account owns them after an install.
			_ = os.Lchown(p, 4242, 4343)
		}
		fi, _ = os.Lstat(p)
		u, g, _ := ownerOf(fi)
		looks[p] = look{fi.Mode().Perm(), u, g}
		return nil
	})
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
	// With its modes, and its owners: the service must still read its
	// HTTPS key.
	for p, want := range looks {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		u, g, _ := ownerOf(fi)
		if got := (look{fi.Mode().Perm(), u, g}); runtime.GOOS != "windows" && got != want {
			t.Errorf("%s was put back as %+v, not %+v", p, got, want)
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
	if !strings.Contains(m.out.String(), "Join this server, siem-c,") || len(files(m.dir)) != 0 {
		t.Errorf("wrote %v before the admin said yes: %s", files(m.dir), m.out.String())
	}
	// signalith.yaml names the server otherwise: the service would start
	// with that name, so join refuses another.
	m.env.terminal = false
	if err := os.MkdirAll(filepath.Dir(m.config), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.config, []byte("cluster:\n  node_name: siem-old\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	m.out.Reset()
	if code := m.join(t, f.tok); code != joinExitFailed || !strings.Contains(m.out.String(), "siem-old") || f.joins() != 0 {
		t.Errorf("a name other than signalith.yaml's: %d %s", code, m.out.String())
	}
}

func TestJoinWithoutConfigUsesItsFolders(t *testing.T) {
	// Without signalith.yaml and SIGNALITH_STATE_DIR, the state folder is
	// the one the file join writes will have, not the current folder.
	f := newJoinFixture(t)
	m := newJoinMachine(t)
	t.Setenv("SIGNALITH_STATE_DIR", "")
	t.Chdir(t.TempDir())
	if code := m.join(t, f.tok, "--no-start"); code != joinExitOK {
		t.Fatalf("exit %d: %s", code, m.out.String())
	}
	c, err := config.Load(m.config)
	if err != nil {
		t.Fatal(err)
	}
	if keys := shared.ClusterKeyFiles(c.StateDir()); len(keys) != 1 || !within(c.StateDir(), m.dir) {
		t.Errorf("state folder %s, keys %v", c.StateDir(), keys)
	}
	if cwd, _ := os.Getwd(); len(files(cwd)) != 0 {
		t.Errorf("wrote in the current folder: %v", files(cwd))
	}
}

func TestJoinTokenNotInTheCommandLine(t *testing.T) {
	f := newJoinFixture(t)
	// From the standard input.
	m := newJoinMachine(t)
	m.env.in = strings.NewReader(f.tok.String() + "\n")
	if code := runJoin(context.Background(), m.env, []string{"-", "-c", m.config, "--name", "siem-c", "--yes", "--no-start"}); code != joinExitOK || f.joins() != 1 {
		t.Fatalf("token from the standard input: %d %s", code, m.out.String())
	}
	// Asked for at the terminal, not shown.
	m = newJoinMachine(t)
	m.env.terminal = true
	m.env.readSecret = func() (string, error) { return f.tok.String(), nil }
	if code := runJoin(context.Background(), m.env, []string{"-c", m.config, "--name", "siem-c", "--yes", "--no-start"}); code != joinExitOK || f.joins() != 2 {
		t.Fatalf("token asked for: %d %s", code, m.out.String())
	}
	if strings.Contains(m.out.String(), f.tok.String()) {
		t.Error("the token was shown")
	}
	// Neither: refused before anything happens.
	m = newJoinMachine(t)
	if code := runJoin(context.Background(), m.env, []string{"-c", m.config, "--yes"}); code != joinExitFailed || !strings.Contains(m.out.String(), "signalith join -") {
		t.Errorf("no token: %d %s", code, m.out.String())
	}
	m.env.in = strings.NewReader("")
	if code := runJoin(context.Background(), m.env, []string{"-", "-c", m.config, "--yes"}); code != joinExitFailed || f.joins() != 2 {
		t.Errorf("empty standard input: %d %s", code, m.out.String())
	}
}

func TestJoinStoppedEarlyGivesItsKeys(t *testing.T) {
	// A refused token leaves the identity and keys join made: the service
	// runs as its own account and must read them.
	f := newJoinFixture(t)
	f.status = http.StatusForbidden
	m := newJoinMachine(t)
	if code := m.join(t, f.tok, "--no-start"); code != joinExitRefused {
		t.Fatalf("exit %d: %s", code, m.out.String())
	}
	if runtime.GOOS != "linux" {
		return
	}
	for _, p := range []string{m.state, filepath.Join(m.state, "cluster"), filepath.Join(m.state, "keys")} {
		if got := m.chowned[p]; got != [2]int{4242, 4343} {
			t.Errorf("%s owner %v", p, got)
		}
	}
	if !slices.ContainsFunc(slices.Collect(maps.Keys(m.chowned)), func(p string) bool { return strings.HasPrefix(filepath.Base(p), "node") && strings.Contains(p, "keys") }) {
		t.Errorf("the node key was not given: %v", m.chowned)
	}
}

func TestJoinRefusalsSayTheTokenIsUnused(t *testing.T) {
	f := newJoinFixture(t)
	m := newJoinMachine(t)
	f.status = http.StatusForbidden
	f.reply = "This server runs Signalith 0.1, and the cluster runs 0.2: install Signalith 0.2 first."
	if code := m.join(t, f.tok, "--no-start"); code != joinExitRefused || !strings.Contains(m.out.String(), "The token was not used") {
		t.Errorf("a version refused: %d %s", code, m.out.String())
	}
	// Used, then failed on the answering server: a new token is needed.
	f.status, f.reply = http.StatusInternalServerError, clusterjoin.ErrSpent.Error()
	m = newJoinMachine(t)
	if code := m.join(t, f.tok, "--no-start"); code != joinExitFailed || !strings.Contains(m.out.String(), "Make a new token") {
		t.Errorf("used, then failed: %d %s", code, m.out.String())
	}
}

func TestJoinManagedOpenSearchCertificate(t *testing.T) {
	// The cluster issues this server its own OpenSearch client
	// certificate for the key of the request join sent: the key stays
	// here, and the settings use it.
	f := newJoinFixture(t)
	f.edit = func(b *clusterjoin.Bundle) {
		req := f.requests[len(f.requests)-1]
		blk, _ := pem.Decode([]byte(req.OSCSRPEM))
		csr, err := x509.ParseCertificateRequest(blk.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			t.Errorf("OpenSearch certificate request: %v", err)
			return
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "signalith-server-siem-c"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca, csr.PublicKey, f.caKey)
		if err != nil {
			t.Error(err)
			return
		}
		b.OpenSearch.ClientCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		b.OpenSearch.Managed, b.OpenSearch.Shared = true, false
	}
	m := newJoinMachine(t)
	if code := m.join(t, f.tok, "--no-start"); code != joinExitOK {
		t.Fatalf("exit %d: %s", code, m.out.String())
	}
	c, err := config.Load(m.config)
	if err != nil {
		t.Fatal(err)
	}
	_, certFile, keyFile := c.OpenSearchTLSFiles()
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Errorf("the client certificate and this server's own key: %v (%s, %s)", err, certFile, keyFile)
	}
}

func TestJoinMergeFailureKeepsTheJoin(t *testing.T) {
	// The merge writes to the cluster, which no undo of this machine's
	// files takes back: it runs last, and when it fails the join is kept
	// and the service starts.
	f := newJoinFixture(t)
	m := newJoinMachine(t)
	// The migration report cannot be written.
	f.os.SetFault(func(method, path string) *ostest.Fault {
		if method != http.MethodGet && strings.Contains(path, "migration-report") {
			return &ostest.Fault{Status: http.StatusInternalServerError, Type: "boom"}
		}
		return nil
	})
	if code := m.join(t, f.tok, "--merge"); code != joinExitWrite {
		t.Fatalf("exit %d: %s", code, m.out.String())
	}
	if !strings.Contains(m.out.String(), "siem-c joined the cluster, but merging") || m.started != 1 {
		t.Errorf("started %d: %s", m.started, m.out.String())
	}
	if len(shared.ClusterKeyFiles(m.state)) != 1 {
		t.Error("the join was undone")
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

// The Docker image's first start: signalith join --no-start as its own
// user (not root), with no signalith.yaml yet, the listen address, name
// and node URL from the environment. Join makes the config as signalith
// init does, keeps its state next to it, changes no owner, writes no
// built-in admin password, and the result loads.
func TestJoinInDockerAsItsOwnUser(t *testing.T) {
	f := newJoinFixture(t)
	m := newJoinMachine(t)
	t.Setenv("SIGNALITH_STATE_DIR", "")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", "")
	varLib := filepath.Join(m.dir, "var", "lib", "signalith")
	if err := os.MkdirAll(varLib, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(varLib, "signalith.yaml")
	env := map[string]string{"SIGNALITH_LISTEN": "0.0.0.0:9443", "SIGNALITH_NODE_NAME": "siem-docker", "SIGNALITH_NODE_URL": "https://siem-docker.internal:9443"}
	m.env.getenv = func(k string) string { return env[k] }
	m.env.admin, m.env.root = false, false
	m.env.owner = func() (int, int, bool) { t.Error("looked up the service's account"); return 0, 0, false }

	// Not root, the service cannot be started: refused before anything.
	if code := runJoin(context.Background(), m.env, []string{f.tok.String(), "-c", cfg, "--yes"}); code != joinExitFailed || f.joins() != 0 {
		t.Fatalf("not root without --no-start: %d %s", code, m.out.String())
	}
	m.out.Reset()
	if code := runJoin(context.Background(), m.env, []string{f.tok.String(), "--no-start", "-c", cfg, "--yes"}); code != joinExitOK {
		t.Fatalf("exit %d: %s", code, m.out.String())
	}
	if m.started != 0 || len(m.chowned) != 0 || len(m.systemctl) != 0 {
		t.Errorf("started %d, chowned %v, systemctl %v", m.started, m.chowned, m.systemctl)
	}
	if _, err := os.Stat(m.dropIn); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("wrote a systemd drop-in: %v", err)
	}
	reqs := f.requests
	if len(reqs) != 1 || reqs[0].Name != "siem-docker" || reqs[0].NodeURL != "https://siem-docker.internal:9443" {
		t.Fatalf("requests %+v", reqs)
	}
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "$2") {
		t.Errorf("signalith.yaml holds an admin password hash:\n%s", raw)
	}
	c, err := config.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c.StateDir() != varLib || len(shared.ClusterKeyFiles(varLib)) != 1 {
		t.Errorf("state folder %s, keys %v", c.StateDir(), shared.ClusterKeyFiles(varLib))
	}
	if c.Auth.AdminPasswordHash != "" {
		t.Error("join set a built-in admin password")
	}
	if _, err := os.Stat(config.AdminLocalHashFileIn(varLib)); err == nil {
		t.Error("join wrote a local admin password")
	}
	if c.Server.Listen != "0.0.0.0:9443" || c.Server.NodeURL != "https://siem-docker.internal:9443" {
		t.Errorf("listen %s, node url %s", c.Server.Listen, c.Server.NodeURL)
	}
	if id, err := cluster.ReadIdentity(varLib); err != nil || id.Name != "siem-docker" {
		t.Errorf("identity %+v %v", id, err)
	}
}
