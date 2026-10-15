package tlsauto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// Where a Manager's certificate authority is kept (CAStore.Kind).
const (
	// KindFiles is ca.pem and ca.key in Options.Dir, as on a server of
	// its own.
	KindFiles = "files"
	// KindCluster is the cluster's certificate authority, kept signed in
	// the shared settings with its key sealed under the cluster key.
	KindCluster = "cluster"
)

// Files and folders of the cluster's certificate authority in Options.Dir.
const (
	// clusterMark says ca.pem is the cluster's certificate authority, whose
	// key is not on this disk, and holds its fingerprint. A start without
	// the cluster then never makes a CA of its own.
	clusterMark = "cluster-ca.txt"
	// retiredDir keeps each certificate authority this server used before
	// it took the cluster's, as <stamp>-<fp16>/ca.pem, without its key.
	retiredDir   = "retired"
	stampRetired = "retired_at"
)

// ErrClusterCA refuses a change of certificate authority on a server that
// uses the cluster's.
var ErrClusterCA = &StateError{"This server uses the cluster's certificate authority. Changing it comes in a later version."}

// errNoCAKey: the cluster's certificate authority is known but its key is
// not available here yet.
var errNoCAKey = errors.New("the cluster's certificate authority is not available on this server yet (OpenSearch cannot be reached and there is no saved copy), so the certificate in use stays until it is")

// CAStore keeps a Manager's certificate authority.
type CAStore interface {
	// Load returns the certificate authority and its key, or nil, nil,
	// nil when there is none yet.
	Load() (*x509.Certificate, crypto.Signer, error)
	// Make makes a certificate authority from tmpl. Only the file store
	// can: a cluster's is never made here.
	Make(tmpl *x509.Certificate) error
	// Names lists the names EnsureName added, oldest first.
	Names() []string
	// AddName keeps name among them.
	AddName(ctx context.Context, name string) error
	// Kind is KindFiles or KindCluster.
	Kind() string
}

// fileStore is ca.pem, ca.key and names.txt in dir, the way a server of
// its own has always kept them.
type fileStore struct{ dir string }

func (s fileStore) path(name string) string { return filepath.Join(s.dir, name) }

func (fileStore) Kind() string { return KindFiles }

// Load reads ca.pem and ca.key.
func (s fileStore) Load() (*x509.Certificate, crypto.Signer, error) {
	certPEM, err := os.ReadFile(s.path(CAFile))
	if errors.Is(err, fs.ErrNotExist) {
		if _, kerr := os.Stat(s.path(caKeyFile)); kerr == nil {
			return nil, nil, fmt.Errorf("%s is missing but its key %s is there; restore %s, or delete the tls folder to start over (agents then need the new CA)",
				s.path(CAFile), s.path(caKeyFile), CAFile)
		}
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read Signalith's CA certificate: %w", err)
	}
	ca, err := parseCert(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", s.path(CAFile), err)
	}
	key, err := readCAKey(s.path(caKeyFile))
	if err != nil {
		return nil, nil, err
	}
	if !samePublicKey(ca.PublicKey, key.Public()) {
		return nil, nil, fmt.Errorf("%s does not belong to %s; restore the pair, or delete the tls folder to start over (agents then need the new CA)", caKeyFile, CAFile)
	}
	return ca, key, nil
}

// Make makes a self-signed CA from tmpl and writes its key, then ca.pem.
func (s fileStore) Make(tmpl *x509.Certificate) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	if err := writeCAKey(s.path(caKeyFile), key); err != nil {
		return err
	}
	return writeFile(s.path(CAFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// Names reads the names EnsureName added, one per line.
func (s fileStore) Names() []string {
	b, err := os.ReadFile(s.path(namesFile))
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if n, ok := normalizeName(line); ok && !strings.HasPrefix(line, "#") && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	if len(out) > maxAddedNames {
		out = out[len(out)-maxAddedNames:]
	}
	return out
}

// AddName adds name to names.txt, last, keeping the newest
// maxAddedNames.
func (s fileStore) AddName(_ context.Context, name string) error {
	n, ok := normalizeName(name)
	if !ok {
		return fmt.Errorf("%q is not a host name or IP address", name)
	}
	names := slices.DeleteFunc(s.Names(), func(o string) bool { return o == n })
	names = append(names, n)
	if len(names) > maxAddedNames {
		names = names[len(names)-maxAddedNames:]
	}
	return s.writeNames(names)
}

func (s fileStore) writeNames(names []string) error {
	text := "# Addresses agents were set up with on the Add data page. Signalith keeps them\n" +
		"# in its HTTPS certificate. For names of your own, use server.tls.names instead.\n" +
		strings.Join(names, "\n") + "\n"
	return writeFile(s.path(namesFile), []byte(text), 0o644)
}

// detachedStore is the cluster's certificate authority as this server
// last saw it, from ca.pem, when it starts without the cluster: it serves
// the certificate it has and never makes a CA. Its key is the one in
// ca.key only while the founder still keeps it there.
type detachedStore struct{ fileStore }

func (detachedStore) Kind() string { return KindCluster }

func (s detachedStore) Load() (*x509.Certificate, crypto.Signer, error) {
	b, err := os.ReadFile(s.path(CAFile))
	if err != nil {
		return nil, nil, fmt.Errorf("this server uses the cluster's certificate authority (see %s), but %s cannot be read: %w. "+
			"Restore it, or delete the tls folder to make a certificate authority of this server's own (agents then need the new CA)",
			s.path(clusterMark), s.path(CAFile), err)
	}
	ca, err := parseCert(b)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", s.path(CAFile), err)
	}
	// The key is the founder's, kept until the cluster holds it safely.
	if key, err := readCAKey(s.path(caKeyFile)); err == nil && samePublicKey(ca.PublicKey, key.Public()) {
		return ca, key, nil
	}
	return ca, nil, nil
}

func (detachedStore) Make(*x509.Certificate) error {
	return errors.New("this server uses the cluster's certificate authority, so it never makes one of its own")
}

func (detachedStore) AddName(context.Context, string) error { return errNoCAKey }

// readMark returns the fingerprint in dir's cluster mark, or "".
func readMark(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, clusterMark))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}
	return ""
}

func writeMark(dir, fp string) error {
	text := "# This server uses the cluster's certificate authority: ca.pem is a copy of it, and its key\n" +
		"# is kept sealed in the cluster's shared settings. Signalith never makes a CA of its own here\n" +
		"# while this file exists. Delete the tls folder to give the server a CA of its own again.\n" +
		fp + "\n"
	return writeFile(filepath.Join(dir, clusterMark), []byte(text), 0o644)
}

// Store says where the certificate authority in use is kept: KindFiles or
// KindCluster, or "" with the admin's own certificate files.
func (m *Manager) Store() string {
	if !m.LocalCA() {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store == nil {
		// A Manager that only reads the folder (the command line's).
		if readMark(m.opts.Dir) != "" {
			return KindCluster
		}
		return KindFiles
	}
	return m.store.Kind()
}

// inCluster reports whether the certificate authority is the cluster's.
// The caller holds m.mu.
func (m *Manager) inCluster() bool { return m.store != nil && m.store.Kind() == KindCluster }

// UseStore makes s, the cluster's certificate authority, the one in use:
// it loads it and issues a certificate from it, and only then retires the
// certificate authority this server had (its ca.pem goes to
// retired/<stamp>-<fp16>/, its key is deleted). When s holds the same one,
// as for the server that published it, nothing is retired and ca.key stays
// until DropLocalKey. It refuses while a change of certificate authority
// is in progress, which the admin finishes or cancels first.
func (m *Manager) UseStore(s CAStore) error {
	if !m.LocalCA() {
		return ErrNotAuto
	}
	if s == nil {
		return errors.New("no certificate authority store")
	}
	if err := m.changeInProgress(); err != nil {
		return err
	}
	// The store may read a document: not under m.mu.
	ca, key, err := s.Load()
	if err != nil {
		return err
	}
	if ca == nil || key == nil {
		return errors.New("the cluster has no certificate authority yet")
	}
	if !samePublicKey(ca.PublicKey, key.Public()) {
		return errors.New("the cluster's certificate authority and its key do not belong together")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.changeInProgress(); err != nil {
		return err
	}
	oldStore, oldCA, oldKey, oldAdded := m.store, m.ca, m.caKey, m.added
	m.store, m.ca, m.caKey, m.added = s, ca, key, s.Names()
	restore := func() {
		m.store, m.ca, m.caKey, m.added = oldStore, oldCA, oldKey, oldAdded
		m.wantNames()
	}
	leaf := m.cert.Load()
	if l := m.Leaf(); l == nil || !m.usable(l) {
		if leaf, err = m.issueLeaf(); err != nil {
			restore()
			return fmt.Errorf("could not issue a certificate from the cluster's certificate authority, so this server's stays in use: %w", err)
		}
	}
	if err := m.adoptLocked(ca); err != nil {
		restore()
		return fmt.Errorf("could not retire this server's own certificate authority, so it stays in use: %w", err)
	}
	m.cert.Store(leaf)
	m.switchedAt, m.added = time.Time{}, s.Names()
	m.seen.reset()
	m.log().Info("HTTPS now uses the cluster's certificate authority", "ca_sha256", Fingerprint(ca.Raw),
		"names", strings.Join(certNames(leaf.Leaf), ","))
	return nil
}

// changeInProgress refuses a change of store while a change of
// certificate authority is prepared, kept or half done.
func (m *Manager) changeInProgress() error {
	for _, p := range []string{nextDir, previousDir, journalFile} {
		if exists(m.path(p)) {
			return &StateError{"A change of this server's certificate authority is in progress. Finish it (remove the previous one) or cancel it on the Security page first; then this server takes the cluster's."}
		}
	}
	return nil
}

// adoptLocked records on disk that ca, the cluster's, is in use: a
// different ca.pem goes to retired/ first, without its key, then the
// mark, then ca.pem becomes a copy of ca. Each step leaves a folder a
// start can use (see detachedStore). The caller holds m.mu.
func (m *Manager) adoptLocked(ca *x509.Certificate) error {
	fp := Fingerprint(ca.Raw)
	b, err := os.ReadFile(m.path(CAFile))
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	default:
		old, perr := parseCert(b)
		if perr == nil && Fingerprint(old.Raw) == fp {
			return writeMark(m.opts.Dir, fp)
		}
		if perr == nil {
			if err := m.retire(old); err != nil {
				return err
			}
		}
	}
	if err := writeMark(m.opts.Dir, fp); err != nil {
		return err
	}
	if err := writeFile(m.path(CAFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o644); err != nil {
		return err
	}
	if err := os.Remove(m.path(caKeyFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// retire copies old into retired/<stamp>-<fp16>/, once. It copies rather
// than moves, so a ca.pem another program holds open (which Windows would
// not let move) is replaced only once the copy is safe.
func (m *Manager) retire(old *x509.Certificate) error {
	fp16 := fp16(old.Raw)
	entries, _ := os.ReadDir(m.path(retiredDir))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), "-"+fp16) && exists(filepath.Join(m.path(retiredDir), e.Name(), CAFile)) {
			return nil
		}
	}
	now := m.now().UTC()
	dir := m.path(retiredDir, now.Format("20060102T150405Z")+"-"+fp16)
	if err := securefile.MkdirPrivate(dir); err != nil {
		return err
	}
	if err := writeStamp(filepath.Join(dir, stampRetired), now); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, CAFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: old.Raw}), 0o644); err != nil {
		return err
	}
	m.log().Info("retired this server's own certificate authority; agents set up with it need a new configuration",
		"ca_sha256", Fingerprint(old.Raw), "kept_in", dir)
	return nil
}

// fp16 is the first 16 hex digits of a certificate's SHA-256, lower case,
// as agent pins and folder names use it.
func fp16(der []byte) string {
	return strings.ToLower(strings.ReplaceAll(Fingerprint(der), ":", ""))[:16]
}

// Retired lists the certificate authorities this server used before the
// cluster's, newest first; At is when each was retired.
func (m *Manager) Retired() []CAInfo {
	out := []CAInfo{}
	if !m.LocalCA() {
		return out
	}
	entries, err := os.ReadDir(m.path(retiredDir))
	if err != nil {
		return out
	}
	for _, e := range entries {
		dir := filepath.Join(m.path(retiredDir), e.Name())
		b, err := os.ReadFile(filepath.Join(dir, CAFile))
		if err != nil {
			continue
		}
		ca, err := parseCert(b)
		if err != nil {
			continue
		}
		in := infoOf(ca)
		in.At = readStamp(filepath.Join(dir, stampRetired))
		out = append(out, *in)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out
}

// KeepsKey reports whether ca.key is still on this server's disk.
func (m *Manager) KeepsKey() bool {
	return m.LocalCA() && exists(m.path(caKeyFile))
}

// DropLocalKey deletes ca.key once the cluster keeps the certificate
// authority it belongs to: the server that published its own calls it
// after reading the published copy back and saving it in cache.enc. It
// does nothing unless the cluster's certificate authority is in use and is
// the one in ca.pem.
func (m *Manager) DropLocalKey() error {
	if !m.LocalCA() {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.inCluster() || m.ca == nil || readMark(m.opts.Dir) != Fingerprint(m.ca.Raw) {
		return nil
	}
	if _, detached := m.store.(detachedStore); detached {
		return nil
	}
	if err := os.Remove(m.path(caKeyFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	m.log().Info("deleted ca.key: the cluster keeps the certificate authority's key, sealed", "ca_sha256", Fingerprint(m.ca.Raw))
	return nil
}

// Reissue takes in the names the store keeps and Options.SharedNames,
// and issues a certificate when the one in use no longer covers what it
// should. The cluster's tls document calls it when it changes.
func (m *Manager) Reissue() error {
	if !m.LocalCA() {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.added = m.store.Names()
	if m.usable(m.Leaf()) {
		return nil
	}
	if err := m.issue(); err != nil {
		return err
	}
	m.log().Info("HTTPS certificate reissued for the names it should cover", "names", strings.Join(certNames(m.Leaf()), ", "))
	return nil
}

// keptLeaf is the certificate in the folder when it is from the CA in use
// and has not expired, whatever names it covers: with no key to issue
// another, it is better than none. The caller holds m.mu.
func (m *Manager) keptLeaf() (*tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(m.path(certFile), m.path(keyFile))
	if err != nil {
		return nil, err
	}
	if pair.Leaf.CheckSignatureFrom(m.ca) != nil || !m.now().Before(pair.Leaf.NotAfter) {
		return nil, errNoCAKey
	}
	return &pair, nil
}

// LocalPair returns this server's own certificate authority, its key and
// the names EnsureName added, for publishing it as the cluster's. It
// returns nil when there is none to publish: with the admin's certificate
// files, with the cluster's certificate authority already in use, or
// while a change of certificate authority is in progress.
func (m *Manager) LocalPair() (*x509.Certificate, crypto.Signer, []string) {
	if !m.LocalCA() || m.changeInProgress() != nil {
		return nil, nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inCluster() || m.ca == nil || m.caKey == nil {
		return nil, nil, nil
	}
	return m.ca, m.caKey, slices.Clone(m.added)
}

// InfoOf describes the certificate authority ca.
func InfoOf(ca *x509.Certificate) *CAInfo {
	if ca == nil {
		return nil
	}
	return infoOf(ca)
}

// SetSharedNames replaces Options.SharedNames: a Manager a restart keeps
// takes the cluster's names of the new start. fn is called with the
// Manager's lock held, so it must not call the Manager. Reissue brings
// the certificate in line.
func (m *Manager) SetSharedNames(fn func() []string) {
	if fn == nil {
		m.sharedNames.Store(nil)
		return
	}
	m.sharedNames.Store(&fn)
}

// LocalFiles returns the certificate authority in dir (ca.pem and ca.key),
// and the names EnsureName added, as LocalPair does for a running server,
// without making anything: for publishing it from the command line. It
// returns nil when there is none to publish: the folder has none, it holds
// the cluster's, or a change of certificate authority is in progress.
func LocalFiles(dir string) (*x509.Certificate, crypto.Signer, []string) {
	if dir == "" || readMark(dir) != "" {
		return nil, nil, nil
	}
	for _, p := range []string{nextDir, previousDir, journalFile} {
		if exists(filepath.Join(dir, p)) {
			return nil, nil, nil
		}
	}
	s := fileStore{dir}
	ca, key, err := s.Load()
	if err != nil || ca == nil || key == nil {
		return nil, nil, nil
	}
	return ca, key, s.Names()
}
