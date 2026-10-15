package clusterpki

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustertls"
	"github.com/jrsamsanchez/signalith/internal/ospki"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// Role is the OpenSearch role roles_mapping.yml gives Signalith's servers.
const Role = "signalith_server"

// RetryAfter is how long a server waits before it tries again to issue
// itself a certificate after a failure.
var RetryAfter = 10 * time.Minute

// Options are what a server's Identity needs.
type Options struct {
	OSCA *OSCA
	// Name and NodeID are this server's.
	Name, NodeID string
	// Conn returns OpenSearch's connection as configured
	// (config.OpenSearchConnection), with the files of the certificate the
	// cluster issued this server as ManagedCertFile and ManagedKeyFile.
	Conn func() store.Config
	// ImportDir is the folder OpenSearch's certificate authority is
	// handed over in (<state>/import, ospki.ImportDir).
	ImportDir string
	// Writable says why this server cannot change the shared settings
	// now, nil when it can.
	Writable func() error
	// Flush writes this server's copy of the shared settings (cache.enc)
	// now and returns the body of the document id as it holds it
	// (shared.Runtime.FlushCacheBody): the handed-over key file is
	// deleted only once the copy holds the key too.
	Flush func(id string) (string, error)
	// AuthInfo asks OpenSearch who conn signs in as, and with which
	// roles; nil asks OpenSearch's security plugin.
	AuthInfo func(ctx context.Context, conn store.Config) (user string, roles []string, err error)
	Log      *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Identity keeps one server's own OpenSearch client certificate: it hands
// a certificate authority dropped in ImportDir to the cluster, issues the
// server a certificate once the cluster keeps one (switching away from
// the shared CN=signalith certificate), and renews it RenewBefore it
// expires. Sync does one round.
type Identity struct {
	o Options
	// mu serialises Sync; the fields after it are its own.
	mu sync.Mutex
	// next is when a failed issue may be tried again.
	next time.Time
	// importProblem and issueProblem say what went wrong last, for the
	// heartbeat; logged is the last of each logged.
	importProblem, issueProblem string
	logged                      map[string]string

	smu    sync.Mutex
	status *cluster.OSIdentityStatus
}

// NewIdentity returns the identity of the server o describes.
func NewIdentity(o Options) *Identity {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.AuthInfo == nil {
		o.AuthInfo = authInfo
	}
	return &Identity{o: o, logged: map[string]string{}}
}

func (i *Identity) now() time.Time {
	if i.o.Now != nil {
		return i.o.Now()
	}
	return time.Now()
}

// Status is what this server's heartbeat says of its OpenSearch
// identity, as of the last Sync.
func (i *Identity) Status() *cluster.OSIdentityStatus {
	i.smu.Lock()
	defer i.smu.Unlock()
	if i.status == nil {
		return nil
	}
	st := *i.status
	return &st
}

// Sync does one round: the import, then the certificate.
func (i *Identity) Sync(ctx context.Context) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.importProblem = i.note("import", i.importFiles(ctx))
	i.issueProblem = i.note("issue", i.ensure(ctx))
	st := i.describe()
	i.smu.Lock()
	i.status = st
	i.smu.Unlock()
}

// note logs err once while it stays the same, and returns its text.
func (i *Identity) note(what string, err error) string {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if msg != "" && i.logged[what] != msg {
		if what == "import" {
			i.o.Log.Warn("could not hand OpenSearch's certificate authority to the cluster", "err", msg)
		} else {
			i.o.Log.Warn("this server keeps its OpenSearch client certificate for now", "err", msg)
		}
	}
	i.logged[what] = msg
	return msg
}

// importFiles hands the certificate authority waiting in ImportDir to
// the cluster, and deletes its key file once the cluster keeps it
// safely. Nothing there is no error.
func (i *Identity) importFiles(ctx context.Context) error {
	if i.o.ImportDir == "" {
		return nil
	}
	keyPath := filepath.Join(i.o.ImportDir, ospki.ExportCAKeyFile)
	keyPEM, err := os.ReadFile(keyPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer clear(keyPEM)
	if i.o.Writable != nil {
		if err := i.o.Writable(); err != nil {
			return fmt.Errorf("OpenSearch's certificate authority waits in %s until this server can change the shared settings: %w", i.o.ImportDir, err)
		}
	}
	certPEM, err := os.ReadFile(filepath.Join(i.o.ImportDir, ospki.ExportCAFile))
	if err != nil {
		return fmt.Errorf("%s has the key of OpenSearch's certificate authority but not its certificate: %w", i.o.ImportDir, err)
	}
	ca, err := ospki.PairFromPEM(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("the files in %s: %w", i.o.ImportDir, err)
	}
	if err := Trusted(i.o.Conn().CAFile, ca.Cert); err != nil {
		return err
	}
	err = i.o.OSCA.Import(ctx, systemUser, i.o.Name, certPEM, keyPEM)
	if errors.Is(err, ErrOtherCA) {
		// OpenSearch's certificates were made again under a new CA
		// (bootstrap-docker -new-ca): the new one replaces the old once
		// OpenSearch's connection no longer trusts the old.
		if b, ok := i.o.OSCA.Get(); ok {
			if old, cerr := b.Cert(); cerr == nil && Trusted(i.o.Conn().CAFile, old) != nil {
				err = i.o.OSCA.Replace(ctx, systemUser, i.o.Name, certPEM, keyPEM)
			}
		}
	}
	if err != nil {
		return err
	}
	if !i.kept(ctx, ca.Cert) {
		return errors.New("handed OpenSearch's certificate authority to the cluster, but cannot read it back yet; its key file stays until then")
	}
	if err := os.Remove(keyPath); err != nil {
		return fmt.Errorf("the cluster keeps OpenSearch's certificate authority now, but its key file could not be deleted: %w", err)
	}
	i.o.Log.Info("handed OpenSearch's certificate authority to the cluster and deleted its key file", "audit", true,
		"ca_sha256", tlsauto.Fingerprint(ca.Cert.Raw), "file", keyPath)
	return nil
}

// kept reports whether the cluster keeps the certificate authority ca
// safely: the osca document read back from OpenSearch names it, its key
// opens, and this server's copy of the shared settings holds the same
// sealed key.
func (i *Identity) kept(ctx context.Context, ca *x509.Certificate) bool {
	d := i.o.OSCA.Doc()
	if d == nil {
		return false
	}
	lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := d.Load(lctx); err != nil || d.Missing() {
		return false
	}
	b, ok := d.Get()
	fp := tlsauto.Fingerprint(ca.Raw)
	if !ok || !clustertls.SameFingerprint(b.CASHA256, fp) {
		return false
	}
	if _, err := i.o.OSCA.open(b); err != nil {
		return false
	}
	if i.o.Flush == nil {
		return false
	}
	body, err := i.o.Flush(DocID)
	if err != nil {
		return false
	}
	var cached Body
	if json.Unmarshal([]byte(body), &cached) != nil {
		return false
	}
	return cached.CAKey == b.CAKey && clustertls.SameFingerprint(cached.CASHA256, fp)
}

// Trusted checks that OpenSearch's connection trusts ca: the CA file it
// is checked with (opensearch.ca_file) holds it. Handing over another
// certificate authority would give the servers certificates OpenSearch
// does not accept.
func Trusted(caFile string, ca *x509.Certificate) error {
	if caFile == "" {
		return errors.New("opensearch.ca_file is not set, so this server cannot tell whether OpenSearch's certificate comes from the certificate authority handed over")
	}
	b, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("cannot read opensearch.ca_file: %w", err)
	}
	for rest := b; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" && bytes.Equal(block.Bytes, ca.Raw) {
			return nil
		}
	}
	return fmt.Errorf("the certificate authority handed over (%s) is not the one in opensearch.ca_file, which OpenSearch's certificate is checked with", tlsauto.Fingerprint(ca.Raw))
}

// readCert reads the first certificate of a PEM file, nil when there is
// none.
func readCert(path string) *x509.Certificate {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return c
}

// chains reports whether c was issued by ca and is a client certificate.
func chains(c, ca *x509.Certificate) bool {
	if c == nil || ca == nil {
		return false
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	_, err := c.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: c.NotBefore.Add(time.Minute)})
	return err == nil
}

// ensure issues this server its own certificate, or renews it, when the
// cluster keeps OpenSearch's certificate authority and this server signs
// in with a certificate from it: the shared CN=signalith one, or its own
// that expires within RenewBefore. A server that signs in with a
// password or a certificate from elsewhere is left as it is.
func (i *Identity) ensure(ctx context.Context) error {
	b, ok := i.o.OSCA.Get()
	if !ok {
		return nil
	}
	ca, err := b.Cert()
	if err != nil {
		return err
	}
	conn := i.o.Conn()
	now := i.now()
	want, err := ClientName(i.o.Name)
	if err != nil {
		return err
	}
	managed := readCert(conn.ManagedCertFile)
	if managed != nil && !chains(managed, ca) {
		managed = nil
	}
	if managed == nil && !chains(readCert(conn.CertFile), ca) {
		return nil
	}
	if managed != nil && managed.Subject.CommonName == want && now.Before(managed.NotAfter.Add(-RenewBefore)) {
		return nil
	}
	if now.Before(i.next) {
		// The last try failed: its reason stands until the next.
		return errors.New(i.issueProblem)
	}
	if err := i.issue(ctx, conn, want, now); err != nil {
		i.next = now.Add(RetryAfter)
		if managed != nil && now.Before(managed.NotAfter) {
			return fmt.Errorf("its OpenSearch certificate expires on %s and could not be renewed: %w", managed.NotAfter.Format(time.DateOnly), err)
		}
		return err
	}
	i.next = time.Time{}
	return nil
}

// issue makes a key and a certificate for the common name cn, checks
// that OpenSearch lets it in as cn with Role, and only then puts it where
// conn presents it.
func (i *Identity) issue(ctx context.Context, conn store.Config, cn string, now time.Time) error {
	if conn.ManagedCertFile == "" || conn.ManagedKeyFile == "" {
		return errors.New("no place to keep this server's OpenSearch certificate")
	}
	if i.o.Writable != nil {
		if err := i.o.Writable(); err != nil {
			return err
		}
	}
	if err := i.o.OSCA.Opens(); err != nil {
		return err
	}
	keyPEM, csrPEM, err := ospki.NewClientRequest(cn)
	if err != nil {
		return err
	}
	defer clear(keyPEM)
	certPEM, notAfter, err := i.o.OSCA.Issue(ctx, i.o.Name, i.o.NodeID, csrPEM, now)
	if err != nil {
		return err
	}
	dir := filepath.Dir(conn.ManagedCertFile)
	if err := securefile.MkdirPrivate(dir); err != nil {
		return err
	}
	// Tried from files of their own first, so the certificate in use
	// stays until the new one is known to work.
	testCert, testKey := filepath.Join(dir, ".client-new.pem"), filepath.Join(dir, ".client-new-key.pem")
	defer os.Remove(testCert)
	defer os.Remove(testKey)
	if err := securefile.Replace(testKey, keyPEM); err != nil {
		return err
	}
	if err := securefile.Replace(testCert, certPEM); err != nil {
		return err
	}
	test := conn
	test.CertFile, test.KeyFile, test.ManagedCertFile, test.ManagedKeyFile = testCert, testKey, "", ""
	test.Username, test.Password = "", secrets.New("opensearch.password", "")
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	user, roles, err := i.o.AuthInfo(tctx, test)
	cancel()
	if err != nil {
		return fmt.Errorf("OpenSearch did not let %s in: %w", cn, err)
	}
	if user != cn || !slices.Contains(roles, Role) {
		return fmt.Errorf("OpenSearch does not give %s the %s role yet: load roles_mapping.yml again (bootstrap-docker -apply-security in Docker, securityadmin.sh otherwise)", cn, Role)
	}
	// The key first: until the certificate follows, the pair does not
	// match, and the old one stays in use.
	if err := securefile.Replace(conn.ManagedKeyFile, keyPEM); err != nil {
		return err
	}
	if err := securefile.Replace(conn.ManagedCertFile, certPEM); err != nil {
		return err
	}
	i.o.Log.Info("this server signs in to OpenSearch with its own certificate now", "audit", true, "cn", cn, "expires", notAfter.Format(time.DateOnly))
	return nil
}

// describe is the heartbeat's view of the certificate this server
// presents now.
func (i *Identity) describe() *cluster.OSIdentityStatus {
	conn := i.o.Conn()
	now := i.now()
	st := &cluster.OSIdentityStatus{}
	if c := readCert(conn.ManagedCertFile); c != nil && now.Before(c.NotAfter) {
		t := c.NotAfter.UTC()
		st.CN, st.NotAfter, st.Managed = c.Subject.CommonName, &t, true
	} else if c := readCert(conn.CertFile); c != nil {
		t := c.NotAfter.UTC()
		st.CN, st.NotAfter = c.Subject.CommonName, &t
		st.Shared = st.CN == ospki.ClientName
	} else if conn.Username != "" {
		st.User, st.Shared = conn.Username, true
	}
	if b, ok := i.o.OSCA.Get(); ok {
		st.CASHA256 = b.CASHA256
	}
	st.Problem = i.issueProblem
	if st.Problem == "" {
		st.Problem = i.importProblem
	}
	return st
}

// authInfo asks OpenSearch's security plugin who conn signs in as.
func authInfo(ctx context.Context, conn store.Config) (string, []string, error) {
	c := store.New(conn)
	defer c.CloseIdleConnections()
	var info struct {
		User  string   `json:"user_name"`
		Roles []string `json:"roles"`
	}
	if err := c.Do(ctx, http.MethodGet, "/_plugins/_security/authinfo", nil, &info); err != nil {
		return "", nil, err
	}
	return info.User, info.Roles, nil
}
