package clusterpki

import (
	"context"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/ospki"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

func TestRevokeNode(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	o := e.server("a", true)
	_, req := csr(t, "x")
	if _, err := o.RevokeNode(ctx, "admin", "n1"); !errors.Is(err, ErrShared) {
		t.Fatalf("without a CA: %v", err)
	}
	ca := newCA(t)
	if err := o.Import(ctx, "admin", "a", ca.CertPEM(), ca.KeyPEM()); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	first, _, err := o.Issue(ctx, "siem-a", "n1", req, now)
	if err != nil {
		t.Fatal(err)
	}
	// A renewal: the first certificate stays valid, so it is revoked too.
	second, _, err := o.Issue(ctx, "siem-a", "n1", req, now)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := o.Issue(ctx, "siem-b", "n2", req, now)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := o.RevokeNode(ctx, "admin", "n1")
	if err != nil {
		t.Fatal(err)
	}
	serial := func(b []byte) string { return parse(t, b).SerialNumber.Text(16) }
	var got []string
	for _, r := range revoked {
		got = append(got, r.Serial)
		if r.NodeID != "n1" || r.Name != "siem-a" || r.RevokedAt.IsZero() {
			t.Errorf("revoked %+v", r)
		}
	}
	want := []string{serial(first), serial(second)}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("revoked %v, want %v", got, want)
	}
	b, _ := o.Get()
	if _, ok := b.Issued["siem-a"]; ok {
		t.Error("the name is still taken")
	}
	if !slices.Equal(b.RevokedSerials(now), want) {
		t.Errorf("revoked serials %v", b.RevokedSerials(now))
	}
	// Once expired, they need no listing.
	if s := b.RevokedSerials(now.Add(Validity + time.Hour)); len(s) != 0 {
		t.Errorf("expired ones listed: %v", s)
	}

	// No new certificate for it, and a second revocation changes nothing.
	if _, _, err := o.Issue(ctx, "siem-a", "n1", req, now); !errors.Is(err, ErrRevoked) {
		t.Errorf("issued after revocation: %v", err)
	}
	if r, err := o.RevokeNode(ctx, "admin", "n1"); err != nil || len(r) != 0 {
		t.Errorf("again: %v %v", r, err)
	}

	// The revocation list names them, signed by the CA, until it expires.
	crlPEM, err := o.CRL(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	l, err := ospki.ParseCRL(crlPEM, ca.Cert, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ospki.CRLSerials(l), want) || slices.Contains(ospki.CRLSerials(l), serial(other)) {
		t.Errorf("list names %v", ospki.CRLSerials(l))
	}
	if !l.NextUpdate.Equal(ca.Cert.NotAfter) {
		t.Errorf("next update %v, CA until %v", l.NextUpdate, ca.Cert.NotAfter)
	}

	// Joining anew lets it have one again.
	if _, err := o.JoinCredential(ctx, "siem-a", "n1", req); err != nil {
		t.Errorf("join after revocation: %v", err)
	}
	// Replacing the CA forgets the revocations: the old one opens nothing.
	if err := o.Replace(ctx, "admin", "a", newCA(t).CertPEM(), newCA(t).KeyPEM()); err == nil {
		t.Fatal("a mismatched pair was taken")
	}
	nca := newCA(t)
	if err := o.Replace(ctx, "admin", "a", nca.CertPEM(), nca.KeyPEM()); err != nil {
		t.Fatal(err)
	}
	if b, _ := o.Get(); len(b.Revoked) != 0 {
		t.Errorf("revocations kept under a new CA: %v", b.Revoked)
	}
}

// crlIdentity is a server that keeps the revocation list in dir.
func crlIdentity(t *testing.T, o *OSCA, ie *identityEnv, file string) *Identity {
	t.Helper()
	return NewIdentity(Options{OSCA: o, Name: "siem-a", NodeID: "n1", Conn: ie.conn, ImportDir: filepath.Join(ie.dir, "state", ospki.ImportDir),
		CRLFile: file, Flush: flushFrom(o), AuthInfo: ie.authInfo})
}

func TestIdentityKeepsTheCRL(t *testing.T) {
	e := newEnv(t)
	ie := newIdentityEnv(t)
	o := e.server("siem-a", true)
	ctx := context.Background()
	file := filepath.Join(ie.dir, "crl", ospki.CRLFile)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	id := crlIdentity(t, o, ie, file)

	// No CA kept and no list: it says so loudly, and writes none.
	id.Sync(ctx)
	st := id.Status()
	if st.CRL == nil || !strings.Contains(st.CRL.Problem, "is missing") || !strings.Contains(st.CRL.Problem, "refuses every certificate sign-in") {
		t.Fatalf("status %+v", st.CRL)
	}

	// Once the CA is kept, it writes an empty list, readable by
	// OpenSearch's own user.
	if err := o.Import(ctx, "admin", "siem-a", ie.ca.CertPEM(), ie.ca.KeyPEM()); err != nil {
		t.Fatal(err)
	}
	id.Sync(ctx)
	if st := id.Status(); st.CRL.Problem != "" || st.CRL.Revoked != 0 || st.CRL.NextUpdate == nil {
		t.Fatalf("status %+v", st.CRL)
	}
	if fi, err := os.Stat(file); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm()&0o004 == 0 && os.PathSeparator == '/' {
		t.Errorf("mode %v", fi.Mode())
	}
	written, _ := os.ReadFile(file)

	// Nothing changed: the file is left alone.
	id.Sync(ctx)
	if b, _ := os.ReadFile(file); string(b) != string(written) {
		t.Error("rewritten without a change")
	}

	// Another server is revoked: the list names its certificate.
	_, req := csr(t, "x")
	cert, _, err := o.Issue(ctx, "siem-b", "n2", req, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.RevokeNode(ctx, "admin", "n2"); err != nil {
		t.Fatal(err)
	}
	id.Sync(ctx)
	l, err := ospki.ReadCRL(file, ie.ca.Cert, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if s := ospki.CRLSerials(l); !slices.Equal(s, []string{parse(t, cert).SerialNumber.Text(16)}) {
		t.Errorf("list names %v", s)
	}
	if st := id.Status(); st.CRL.Problem != "" || st.CRL.Revoked != 1 {
		t.Errorf("status %+v", st.CRL)
	}

	// The file disappears: written again at once, still naming it.
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	id.Sync(ctx)
	if l, err := ospki.ReadCRL(file, ie.ca.Cert, time.Now()); err != nil || len(l.RevokedCertificateEntries) != 1 {
		t.Fatalf("after it disappeared: %v", err)
	}
	if st := id.Status(); st.CRL.Problem != "" {
		t.Errorf("status %+v", st.CRL)
	}

	// One from another CA is replaced too.
	if err := os.WriteFile(file, mustCRL(t, newCA(t)), 0o644); err != nil {
		t.Fatal(err)
	}
	id.Sync(ctx)
	if _, err := ospki.ReadCRL(file, ie.ca.Cert, time.Now()); err != nil {
		t.Errorf("another CA's list was kept: %v", err)
	}
}

func TestIdentityCannotWriteTheCRL(t *testing.T) {
	e := newEnv(t)
	ie := newIdentityEnv(t)
	o := e.server("siem-a", true)
	ctx := context.Background()
	if err := o.Import(ctx, "admin", "siem-a", ie.ca.CertPEM(), ie.ca.KeyPEM()); err != nil {
		t.Fatal(err)
	}
	// Its folder is gone: the list is missing and can't be written.
	file := filepath.Join(ie.dir, "no-such-folder", ospki.CRLFile)
	id := crlIdentity(t, o, ie, file)
	id.Sync(ctx)
	st := id.Status()
	if st.CRL == nil || !strings.Contains(st.CRL.Problem, "is missing") || !strings.Contains(st.CRL.Problem, "could not write it") {
		t.Fatalf("status %+v", st.CRL)
	}
	// Without opensearch.crl_file, nothing is said.
	if st := crlIdentity(t, o, ie, "").sync(ctx); st.CRL != nil {
		t.Errorf("status %+v", st.CRL)
	}
}

func TestIdentityCRLFromElsewhere(t *testing.T) {
	// Another server, or bootstrap-docker, wrote it: checked, not written.
	e := newEnv(t)
	ie := newIdentityEnv(t)
	o := e.server("siem-a", false)
	file := filepath.Join(ie.dir, ospki.CRLFile)
	if err := os.WriteFile(file, mustCRL(t, ie.ca), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := crlIdentity(t, o, ie, file).sync(context.Background()); st.CRL == nil || st.CRL.Problem != "" {
		t.Fatalf("status %+v", st.CRL)
	}
	// Signed by another CA, OpenSearch would refuse everyone.
	if err := os.WriteFile(file, mustCRL(t, newCA(t)), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := crlIdentity(t, o, ie, file).sync(context.Background()); st.CRL == nil || !strings.Contains(st.CRL.Problem, "not signed by OpenSearch's certificate authority") {
		t.Fatalf("status %+v", st.CRL)
	}
}

func (i *Identity) sync(ctx context.Context) *cluster.OSIdentityStatus {
	i.Sync(ctx)
	return i.Status()
}

func mustCRL(t *testing.T, ca *ospki.Pair) []byte {
	t.Helper()
	b, err := ospki.MakeCRL(ca, nil, big.NewInt(1), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Renewals that fail to install pile up valid certificates: none is
// forgotten, so a revocation still names the first.
func TestRevokeNodeAfterManyRenewals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	o := e.server("a", true)
	ca := newCA(t)
	if err := o.Import(ctx, "admin", "a", ca.CertPEM(), ca.KeyPEM()); err != nil {
		t.Fatal(err)
	}
	_, req := csr(t, "x")
	now := time.Now()
	var issued []string
	for range 1 + 12 {
		cert, _, err := o.Issue(ctx, "siem-a", "n1", req, now)
		if err != nil {
			t.Fatalf("renewal %d: %v", len(issued), err)
		}
		issued = append(issued, parse(t, cert).SerialNumber.Text(16))
	}
	// Past the cap, the first (in use) and the newest are kept, and those
	// between are revoked at once.
	b, _ := o.Get()
	cur := b.Issued["siem-a"]
	if len(cur.Previous) != MaxPrevious || cur.Previous[0].Serial != issued[0] || cur.Serial != issued[len(issued)-1] {
		t.Fatalf("kept %+v", cur)
	}
	if early := b.RevokedSerials(now); len(early) != len(issued)-1-MaxPrevious {
		t.Fatalf("revoked at once %v", early)
	}
	revoked, err := o.RevokeNode(ctx, "admin", "n1")
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 1+MaxPrevious {
		t.Errorf("revoked %d now", len(revoked))
	}
	b, _ = o.Get()
	got := b.RevokedSerials(now)
	slices.Sort(issued)
	if !slices.Equal(got, issued) {
		t.Fatalf("revoked %v, issued %v", got, issued)
	}
}

// Past the caps, valid revocations and issued certificates are kept, and
// what would need one dropped is refused.
func TestPruneKeepsValid(t *testing.T) {
	now := time.Now()
	var list []Revoked
	for i := range MaxRevoked {
		list = append(list, Revoked{Serial: strconv.Itoa(i), NotAfter: now.Add(time.Hour)})
	}
	list = append(list, Revoked{Serial: "old", NotAfter: now.Add(-time.Hour)})
	got, err := pruneRevoked(list, now)
	if err != nil || len(got) != MaxRevoked || slices.ContainsFunc(got, func(r Revoked) bool { return r.Serial == "old" }) {
		t.Fatalf("expired one: %d %v", len(got), err)
	}
	if _, err := pruneRevoked(append(got, Revoked{Serial: "new", NotAfter: now.Add(time.Minute)}), now); err == nil {
		t.Error("a valid revocation was dropped")
	}

	m := map[string]Issued{}
	for i := range MaxIssued {
		m[strconv.Itoa(i)] = Issued{NotAfter: now.Add(time.Hour)}
	}
	m["old"] = Issued{NotAfter: now.Add(-time.Hour)}
	if err := pruneIssued(m, now); err != nil || len(m) != MaxIssued || hasIssued(m, "old") {
		t.Fatalf("expired one: %d %v", len(m), err)
	}
	m["new"] = Issued{NotAfter: now.Add(time.Minute)}
	if err := pruneIssued(m, now); err == nil || len(m) != MaxIssued+1 {
		t.Errorf("a valid certificate was dropped: %d %v", len(m), err)
	}
}

func hasIssued(m map[string]Issued, k string) bool {
	_, ok := m[k]
	return ok
}

// A server that cannot write the list still says it is behind.
func TestIdentityCRLBehind(t *testing.T) {
	e := newEnv(t)
	ie := newIdentityEnv(t)
	ctx := context.Background()
	o := e.server("siem-c", true)
	if err := o.Import(ctx, "admin", "siem-c", ie.ca.CertPEM(), ie.ca.KeyPEM()); err != nil {
		t.Fatal(err)
	}
	_, req := csr(t, "x")
	if _, _, err := o.Issue(ctx, "siem-b", "n2", req, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := o.RevokeNode(ctx, "admin", "n2"); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(ie.dir, ospki.CRLFile)
	if err := os.WriteFile(file, mustCRL(t, ie.ca), 0o644); err != nil {
		t.Fatal(err)
	}
	// The key is sealed under a key this server lacks, so it cannot
	// write the list.
	other, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.Doc().Mutate(ctx, "test", func(b *Body) error {
		sealed, err := other.SecretsKey().Seal(keyField(b.CASHA256), string(ie.ca.KeyPEM()))
		b.CAKey = sealed
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if o.Opens() == nil {
		t.Fatal("the key still opens")
	}
	if st := crlIdentity(t, o, ie, file).sync(ctx); st.CRL == nil || !strings.Contains(st.CRL.Problem, "does not name 1 revoked certificate") {
		t.Fatalf("status %+v", st.CRL)
	}
}

// A list that names more than this server's view is kept: a server
// behind never takes a revocation off.
func TestIdentityCRLNotShrunk(t *testing.T) {
	e := newEnv(t)
	ie := newIdentityEnv(t)
	ctx := context.Background()
	o := e.server("siem-a", true)
	if err := o.Import(ctx, "admin", "siem-a", ie.ca.CertPEM(), ie.ca.KeyPEM()); err != nil {
		t.Fatal(err)
	}
	_, req := csr(t, "x")
	cert, _, err := o.Issue(ctx, "siem-b", "n2", req, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.RevokeNode(ctx, "admin", "n2"); err != nil {
		t.Fatal(err)
	}
	more, err := ospki.MakeCRL(ie.ca, []*big.Int{parse(t, cert).SerialNumber, big.NewInt(0xbeef)}, big.NewInt(time.Now().Unix()), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(ie.dir, ospki.CRLFile)
	if err := os.WriteFile(file, more, 0o644); err != nil {
		t.Fatal(err)
	}
	if st := crlIdentity(t, o, ie, file).sync(ctx); st.CRL == nil || st.CRL.Problem != "" || st.CRL.Revoked != 2 {
		t.Fatalf("status %+v", st.CRL)
	}
	if b, _ := os.ReadFile(file); string(b) != string(more) {
		t.Error("the longer list was rewritten")
	}
}
