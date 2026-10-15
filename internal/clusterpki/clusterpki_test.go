package clusterpki

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/ospki"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const prefix = "signalith"

func TestMain(m *testing.M) {
	ospki.KeyBits = 2048
	os.Exit(m.Run())
}

// env is one fake OpenSearch with the cluster key.
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

// server returns an osca holder tracked on a new hub of server name, with
// the cluster key when keyed.
func (e *env) server(name string, keyed bool) *OSCA {
	e.t.Helper()
	h := shared.NewHub(shared.Options{NodeName: name})
	if keyed {
		h.SetKeys(shared.NewKeySet(e.key))
	} else {
		other, err := shared.NewClusterKey()
		if err != nil {
			e.t.Fatal(err)
		}
		h.SetKeys(shared.NewKeySet(other))
	}
	h.Use(e.cl, prefix)
	o := New()
	o.Track(h)
	if err := h.Cycle(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	return o
}

func newCA(t *testing.T) *ospki.Pair {
	t.Helper()
	ca, err := ospki.NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestNorm(t *testing.T) {
	for in, want := range map[string]string{
		"siem-a":   "siem-a",
		"SIEM_A":   "siem-a",
		"siem.lan": "siem-lan",
		"-x-":      "x",
		"a" + string(make([]byte, 0)) + "0123456789012345678901234567890123456789012345678901234567890": "a012345678901234567890123456789012345678901234",
	} {
		if got := Norm(in); got != want {
			t.Errorf("Norm(%q) = %q, want %q", in, got, want)
		}
	}
	cn, err := ClientName("Siem_A")
	if err != nil || cn != "signalith-server-siem-a" {
		t.Errorf("ClientName = %q, %v", cn, err)
	}
	if _, err := ClientName("..."); err == nil {
		t.Error("an empty normed name was accepted")
	}
}

func TestImport(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, b := e.server("a", true), e.server("b", true)
	ca, other := newCA(t), newCA(t)
	if err := a.Import(ctx, "admin", "a", ca.CertPEM(), other.KeyPEM()); err == nil {
		t.Fatal("a key that is not the certificate's was imported")
	}
	if err := a.Import(ctx, "admin", "a", ca.CertPEM(), ca.KeyPEM()); err != nil {
		t.Fatal(err)
	}
	// Another server racing with the same CA succeeds, with another fails.
	if err := b.Import(ctx, "admin", "b", ca.CertPEM(), ca.KeyPEM()); err != nil {
		t.Fatal(err)
	}
	if err := b.Import(ctx, "admin", "b", other.CertPEM(), other.KeyPEM()); !errors.Is(err, ErrOtherCA) {
		t.Fatalf("another CA: %v, want ErrOtherCA", err)
	}
	body, ok := a.Get()
	if !ok || body.ImportedBy != "admin" || body.CAKey == "" || string(body.CAKey) == string(ca.KeyPEM()) {
		t.Fatalf("body %+v", body)
	}
	if err := a.Opens(); err != nil {
		t.Fatal(err)
	}
	// A server without the cluster key cannot open it.
	if err := e.server("c", false).Opens(); err == nil {
		t.Fatal("a server with another cluster key opened the CA key")
	}
}

func csr(t *testing.T, cn string) ([]byte, []byte) {
	t.Helper()
	key, req, err := ospki.NewClientRequest(cn)
	if err != nil {
		t.Fatal(err)
	}
	return key, req
}

func parse(t *testing.T, b []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("no PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIssue(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	o := e.server("a", true)
	ca := newCA(t)
	now := time.Now()
	_, req := csr(t, "anything")
	if _, _, err := o.Issue(ctx, "siem-a", "n1", req, now); !errors.Is(err, ErrNoCA) {
		t.Fatalf("before import: %v", err)
	}
	if err := o.Import(ctx, "admin", "a", ca.CertPEM(), ca.KeyPEM()); err != nil {
		t.Fatal(err)
	}
	certPEM, notAfter, err := o.Issue(ctx, "Siem_A", "n1", req, now)
	if err != nil {
		t.Fatal(err)
	}
	c := parse(t, certPEM)
	// The name is ours, whatever the request asked for.
	if c.Subject.CommonName != "signalith-server-siem-a" || !slices.Equal(c.Subject.Organization, []string{ospki.Org}) {
		t.Errorf("subject %v", c.Subject)
	}
	if !slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) || c.IsCA {
		t.Errorf("usage %v, CA %v", c.ExtKeyUsage, c.IsCA)
	}
	if d := c.NotAfter.Sub(now); d < Validity-time.Minute || d > Validity+time.Minute || !c.NotAfter.Equal(notAfter) {
		t.Errorf("lasts %v", d)
	}
	if !chains(c, ca.Cert) {
		t.Error("does not chain to the CA")
	}
	body, _ := o.Get()
	if got := body.Issued["siem-a"]; got.NodeID != "n1" || got.Serial != c.SerialNumber.Text(16) {
		t.Errorf("issued %+v", got)
	}
	// Another server may not take the name while it is valid; the same
	// one renews, and once it expired another may.
	if _, _, err := o.Issue(ctx, "siem.a", "n2", req, now); !errors.Is(err, ErrNameTaken) {
		t.Errorf("taken: %v", err)
	}
	if _, _, err := o.Issue(ctx, "siem-a", "n1", req, now.Add(time.Hour)); err != nil {
		t.Errorf("renew: %v", err)
	}
	if _, _, err := o.Issue(ctx, "siem-a", "n2", req, now.Add(Validity+time.Hour)); err != nil {
		t.Errorf("after expiry: %v", err)
	}
	if _, _, err := o.Issue(ctx, "siem-b", "n3", []byte("junk"), now); err == nil {
		t.Error("a junk request was signed")
	}
	cred, err := o.JoinCredential(ctx, "siem-c", "n4", req)
	if err != nil || !cred.Managed || string(cred.CAPEM) != string(ca.CertPEM()) || parse(t, cred.ClientCertPEM).Subject.CommonName != "signalith-server-siem-c" {
		t.Errorf("join credential %+v, %v", cred, err)
	}
	if _, err := e.server("z", true).JoinCredential(ctx, "x", "n", req); err != nil {
		// The document is shared: a fresh hub of the cluster sees it.
		t.Errorf("on another server: %v", err)
	}
}

func TestJoinCredentialShared(t *testing.T) {
	e := newEnv(t)
	_, req := csr(t, "x")
	if _, err := e.server("a", true).JoinCredential(context.Background(), "x", "n", req); !errors.Is(err, ErrShared) {
		t.Fatalf("%v, want ErrShared", err)
	}
}

// identityEnv is a server's state folder with OpenSearch's files as the
// Docker quick start has them: the CA and the shared CN=signalith
// certificate.
type identityEnv struct {
	dir                     string
	caFile, cert, key       string
	managedCert, managedKey string
	ca                      *ospki.Pair
	mu                      sync.Mutex
	roles                   []string
	asked                   []string
}

func newIdentityEnv(t *testing.T) *identityEnv {
	t.Helper()
	dir := t.TempDir()
	ie := &identityEnv{dir: dir, ca: newCA(t), roles: []string{Role}}
	shared, err := ospki.IssueClient(ie.ca, ospki.ClientName, time.Now(), ospki.Validity)
	if err != nil {
		t.Fatal(err)
	}
	ie.caFile, ie.cert, ie.key = filepath.Join(dir, "ca.pem"), filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
	ie.managedCert, ie.managedKey = filepath.Join(dir, "state", "opensearch", "client.pem"), filepath.Join(dir, "state", "opensearch", "client-key.pem")
	for p, b := range map[string][]byte{ie.caFile: ie.ca.CertPEM(), ie.cert: shared.CertPEM(), ie.key: shared.KeyPEM()} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return ie
}

func (ie *identityEnv) conn() store.Config {
	return store.Config{URL: "https://opensearch:9200", CAFile: ie.caFile, CertFile: ie.cert, KeyFile: ie.key,
		ManagedCertFile: ie.managedCert, ManagedKeyFile: ie.managedKey}
}

// authInfo answers as OpenSearch would for the certificate conn presents.
func (ie *identityEnv) authInfo(_ context.Context, conn store.Config) (string, []string, error) {
	b, err := os.ReadFile(conn.CertFile)
	if err != nil {
		return "", nil, err
	}
	block, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", nil, err
	}
	ie.mu.Lock()
	defer ie.mu.Unlock()
	ie.asked = append(ie.asked, c.Subject.CommonName)
	return c.Subject.CommonName, ie.roles, nil
}

func (ie *identityEnv) importDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(ie.dir, "state", ospki.ImportDir)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, ospki.ExportCAFile), ie.ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, ospki.ExportCAKeyFile), ie.ca.KeyPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	return d
}

func flushFrom(o *OSCA) func(string) (string, error) {
	return func(string) (string, error) {
		b, ok := o.Get()
		if !ok {
			return "", os.ErrNotExist
		}
		out, err := json.Marshal(b)
		return string(out), err
	}
}

func TestIdentityImportAndFounderReissue(t *testing.T) {
	e := newEnv(t)
	ie := newIdentityEnv(t)
	o := e.server("siem-a", true)
	var writable error = errors.New("not a member yet")
	now := time.Now()
	id := NewIdentity(Options{OSCA: o, Name: "siem-a", NodeID: "n1", Conn: ie.conn, ImportDir: ie.importDir(t),
		Writable: func() error { return writable }, Flush: flushFrom(o), AuthInfo: ie.authInfo, Now: func() time.Time { return now }})
	ctx := context.Background()
	keyFile := filepath.Join(ie.dir, "state", ospki.ImportDir, ospki.ExportCAKeyFile)

	// Not writable: the files wait.
	id.Sync(ctx)
	if _, ok := o.Get(); ok {
		t.Fatal("imported while the shared settings could not be changed")
	}
	if st := id.Status(); st.Problem == "" || !st.Shared || st.CN != "signalith" || st.Managed {
		t.Fatalf("status %+v", st)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatal(err)
	}

	// Writable: imported, the key file goes, and the server switches to
	// its own certificate.
	writable = nil
	id.Sync(ctx)
	if _, ok := o.Get(); !ok {
		t.Fatal("not imported")
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatalf("the key file is still there: %v", err)
	}
	st := id.Status()
	if st.CN != "signalith-server-siem-a" || !st.Managed || st.Shared || st.Problem != "" || st.CASHA256 == "" {
		t.Fatalf("status %+v", st)
	}
	if _, err := os.Stat(filepath.Join(ie.dir, "state", "opensearch", ".client-new.pem")); !os.IsNotExist(err) {
		t.Error("the test certificate was left behind")
	}
	first := readCert(ie.managedCert)

	// Nothing to do until RenewBefore its expiry.
	now = now.Add(Validity - RenewBefore - time.Hour)
	id.Sync(ctx)
	if c := readCert(ie.managedCert); c.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatal("renewed too early")
	}
	now = now.Add(2 * time.Hour)
	id.Sync(ctx)
	if c := readCert(ie.managedCert); c.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("not renewed")
	}
}

func TestIdentityWaitsForTheRoleMapping(t *testing.T) {
	e := newEnv(t)
	ie := newIdentityEnv(t)
	ie.roles = nil
	o := e.server("siem-a", true)
	ctx := context.Background()
	if err := o.Import(ctx, "admin", "a", ie.ca.CertPEM(), ie.ca.KeyPEM()); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	id := NewIdentity(Options{OSCA: o, Name: "siem-a", NodeID: "n1", Conn: ie.conn, AuthInfo: ie.authInfo, Now: func() time.Time { return now }})
	id.Sync(ctx)
	if _, err := os.Stat(ie.managedCert); !os.IsNotExist(err) {
		t.Fatal("switched to a certificate OpenSearch gives no role")
	}
	st := id.Status()
	if st.Managed || st.CN != "signalith" || st.Problem == "" {
		t.Fatalf("status %+v", st)
	}
	// It waits RetryAfter before the next try, then switches once the
	// mapping is loaded.
	ie.roles = []string{Role}
	id.Sync(ctx)
	if len(ie.asked) != 1 {
		t.Fatalf("asked %v before RetryAfter", ie.asked)
	}
	now = now.Add(RetryAfter + time.Second)
	id.Sync(ctx)
	if st := id.Status(); !st.Managed || st.Problem != "" {
		t.Fatalf("status %+v", st)
	}
}

func TestIdentityLeavesOtherCredentials(t *testing.T) {
	e := newEnv(t)
	ie := newIdentityEnv(t)
	o := e.server("siem-a", true)
	ctx := context.Background()
	other := newCA(t)
	if err := o.Import(ctx, "admin", "a", other.CertPEM(), other.KeyPEM()); err != nil {
		t.Fatal(err)
	}
	// Its certificate comes from another CA than the one kept.
	id := NewIdentity(Options{OSCA: o, Name: "siem-a", NodeID: "n1", Conn: ie.conn, AuthInfo: ie.authInfo})
	id.Sync(ctx)
	if len(ie.asked) != 0 {
		t.Fatal("issued a certificate for a server whose certificate comes from elsewhere")
	}
	// A password: shared, left alone.
	pw := func() store.Config {
		return store.Config{URL: "https://os:9200", Username: "signalith", ManagedCertFile: ie.managedCert, ManagedKeyFile: ie.managedKey}
	}
	id = NewIdentity(Options{OSCA: o, Name: "siem-a", NodeID: "n1", Conn: pw, AuthInfo: ie.authInfo})
	id.Sync(ctx)
	if st := id.Status(); st.User != "signalith" || !st.Shared || st.Managed || len(ie.asked) != 0 {
		t.Fatalf("status %+v, asked %v", st, ie.asked)
	}
}

func TestImportRefusesAnUntrustedCA(t *testing.T) {
	e := newEnv(t)
	ie := newIdentityEnv(t)
	o := e.server("siem-a", true)
	dir := ie.importDir(t)
	other := newCA(t)
	os.WriteFile(filepath.Join(dir, ospki.ExportCAFile), other.CertPEM(), 0o600)
	os.WriteFile(filepath.Join(dir, ospki.ExportCAKeyFile), other.KeyPEM(), 0o600)
	id := NewIdentity(Options{OSCA: o, Name: "siem-a", NodeID: "n1", Conn: ie.conn, ImportDir: dir, Flush: flushFrom(o), AuthInfo: ie.authInfo})
	id.Sync(context.Background())
	if _, ok := o.Get(); ok {
		t.Fatal("imported a CA opensearch.ca_file does not hold")
	}
	if st := id.Status(); st.Problem == "" {
		t.Fatal("no problem reported")
	}
}

func TestIdentityAfterANewCA(t *testing.T) {
	e := newEnv(t)
	ie := newIdentityEnv(t)
	o := e.server("siem-a", true)
	ctx := context.Background()
	dir := ie.importDir(t)
	id := NewIdentity(Options{OSCA: o, Name: "siem-a", NodeID: "n1", Conn: ie.conn, ImportDir: dir, Flush: flushFrom(o), AuthInfo: ie.authInfo})
	id.Sync(ctx)
	if st := id.Status(); !st.Managed {
		t.Fatalf("status %+v", st)
	}
	// A new CA for OpenSearch and its shared certificate, handed over
	// again while OpenSearch still trusts the old one: refused.
	old := ie.ca
	ie.ca = newCA(t)
	ie.importDir(t)
	id.Sync(ctx)
	if b, _ := o.Get(); !clusterSame(b, old.Cert.Raw) {
		t.Fatal("replaced while OpenSearch still trusts the old CA")
	}
	// Once OpenSearch uses the new one, it replaces the old.
	sh, err := ospki.IssueClient(ie.ca, ospki.ClientName, time.Now(), ospki.Validity)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(ie.caFile, ie.ca.CertPEM(), 0o600)
	os.WriteFile(ie.cert, sh.CertPEM(), 0o600)
	os.WriteFile(ie.key, sh.KeyPEM(), 0o600)
	id.Sync(ctx)
	if b, _ := o.Get(); !clusterSame(b, ie.ca.Cert.Raw) {
		t.Fatal("the new CA did not replace the old")
	}
	if c := readCert(ie.managedCert); !chains(c, ie.ca.Cert) {
		t.Fatal("the server's own certificate was not issued again under the new CA")
	}
}
