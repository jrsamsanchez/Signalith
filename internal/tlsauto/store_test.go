package tlsauto

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// memStore is a cluster's certificate authority held in memory, as the
// cluster's tls document would hold it.
type memStore struct {
	mu    sync.Mutex
	ca    *x509.Certificate
	key   crypto.Signer
	names []string
	added []string // names AddName got
}

func (s *memStore) Load() (*x509.Certificate, crypto.Signer, error) { return s.ca, s.key, nil }
func (s *memStore) Make(*x509.Certificate) error                    { return errors.New("no") }
func (s *memStore) Kind() string                                    { return KindCluster }
func (s *memStore) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.names)
}
func (s *memStore) AddName(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.added = append(s.added, name)
	s.names = append(s.names, name)
	return nil
}

// storeOf is a cluster store holding m's certificate authority.
func storeOf(t *testing.T, m *Manager) *memStore {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	return &memStore{ca: m.ca, key: m.caKey}
}

func readAll(t *testing.T, dir string, names ...string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		out[n] = b
	}
	return out
}

// The file store keeps the files exactly as before: names.txt's text, and
// a restart leaves ca.pem, ca.key, the certificate and names.txt as they
// were.
func TestFileStoreUnchanged(t *testing.T) {
	fakeMachine(t)
	dir := filepath.Join(t.TempDir(), "tls")
	c := &clock{time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)}
	m := newAuto(t, dir, c, "siem.example.com")
	if m.Store() != KindFiles {
		t.Errorf("store %q", m.Store())
	}
	if err := m.EnsureName("192.168.1.20"); err != nil {
		t.Fatal(err)
	}
	if err := m.EnsureName("siem.corp.lan"); err != nil {
		t.Fatal(err)
	}
	const golden = "# Addresses agents were set up with on the Add data page. Signalith keeps them\n" +
		"# in its HTTPS certificate. For names of your own, use server.tls.names instead.\n" +
		"192.168.1.20\nsiem.corp.lan\n"
	files := []string{"ca.pem", "ca.key", "server.pem", "server.key", "names.txt"}
	before := readAll(t, dir, files...)
	if string(before["names.txt"]) != golden {
		t.Errorf("names.txt = %q", before["names.txt"])
	}
	m2 := newAuto(t, dir, c, "siem.example.com")
	after := readAll(t, dir, files...)
	for _, f := range files {
		if !bytes.Equal(before[f], after[f]) {
			t.Errorf("%s changed on restart", f)
		}
	}
	if m2.Fingerprint() != m.Fingerprint() || !m2.Covers("siem.corp.lan") {
		t.Error("restart lost the CA or a name")
	}
	// The store reads what the Manager wrote, and AddName writes what
	// EnsureName would.
	s := fileStore{dir}
	ca, key, err := s.Load()
	if err != nil || Fingerprint(ca.Raw) != m.Fingerprint() || !samePublicKey(ca.PublicKey, key.Public()) {
		t.Fatalf("Load: %v", err)
	}
	other := filepath.Join(t.TempDir(), "names")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	o := fileStore{other}
	for _, n := range []string{"192.168.1.20", "SIEM.corp.lan.", "192.168.1.20"} {
		if err := o.AddName(context.Background(), n); err != nil {
			t.Fatal(err)
		}
	}
	if got := readAll(t, other, "names.txt")["names.txt"]; string(got) != strings.Replace(golden, "192.168.1.20\nsiem.corp.lan\n", "siem.corp.lan\n192.168.1.20\n", 1) {
		t.Errorf("AddName wrote %q", got)
	}
	// No mark, no retired folder: nothing of the cluster's.
	for _, p := range []string{clusterMark, retiredDir} {
		if exists(filepath.Join(dir, p)) {
			t.Errorf("%s made in files mode", p)
		}
	}
	if len(m.Retired()) != 0 {
		t.Error("retired CAs in files mode")
	}
}

// UseStore with another server's CA issues a certificate from it, then
// retires this server's CA without its key. A restart without the
// cluster serves that certificate and never makes a CA; one with the
// cluster's store retires nothing more.
func TestUseStoreRetiresAndReissues(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Now()}
	a := newAuto(t, filepath.Join(t.TempDir(), "a"), c, "siem-a.corp.lan")
	dir := filepath.Join(t.TempDir(), "b")
	b := newAuto(t, dir, c, "siem-b.corp.lan")
	oldFP := b.Fingerprint()
	s := storeOf(t, a)
	s.names = []string{"agents.corp.lan"}
	if err := b.UseStore(s); err != nil {
		t.Fatal(err)
	}
	if b.Store() != KindCluster || b.Fingerprint() != a.Fingerprint() {
		t.Fatalf("store %s, fingerprint %s", b.Store(), b.Fingerprint())
	}
	for _, name := range []string{"siem-b.corp.lan", "agents.corp.lan", "10.1.2.3"} {
		if _, err := b.Leaf().Verify(x509.VerifyOptions{Roots: caPool(t, a), DNSName: name, CurrentTime: c.t}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if exists(filepath.Join(dir, caKeyFile)) {
		t.Error("ca.key of the retired CA kept")
	}
	if got := readAll(t, dir, CAFile)[CAFile]; !bytes.Equal(got, a.CAPEM()) {
		t.Error("ca.pem is not the cluster's")
	}
	if readMark(dir) != a.Fingerprint() {
		t.Errorf("mark %q", readMark(dir))
	}
	ret := b.Retired()
	if len(ret) != 1 || ret[0].Fingerprint != oldFP || ret[0].At.IsZero() {
		t.Fatalf("retired %+v", ret)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, retiredDir))
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), "-"+strings.ToLower(strings.ReplaceAll(oldFP, ":", ""))[:16]) {
		t.Errorf("retired folder %v", entries)
	}
	if exists(filepath.Join(dir, retiredDir, entries[0].Name(), caKeyFile)) {
		t.Error("a retired CA kept its key")
	}

	// The cluster's CA cannot be changed here.
	for name, fn := range map[string]func() error{"prepare": func() error { return b.Prepare(ScopeStandard) }, "switch": b.Switch,
		"rollback": b.Rollback, "discard": b.Discard, "prune": b.Prune} {
		if err := fn(); !errors.Is(err, ErrClusterCA) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Restart without the cluster: the same certificate, no CA made, no
	// key to renew with.
	leaf := b.Leaf()
	d, err := New(Options{Dir: dir, Names: []string{"siem-b.corp.lan"}, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	if d.Store() != KindCluster || d.Fingerprint() != a.Fingerprint() || !bytes.Equal(d.Leaf().Raw, leaf.Raw) {
		t.Errorf("detached start: store %s fp %s", d.Store(), d.Fingerprint())
	}
	if err := d.Prepare(ScopeStandard); !errors.Is(err, ErrClusterCA) {
		t.Errorf("detached prepare: %v", err)
	}
	c.t = leaf.NotAfter.Add(-RenewBefore + time.Hour)
	if err := d.Check(); !errors.Is(err, errNoCAKey) {
		t.Errorf("renewal without the key: %v", err)
	}
	if !bytes.Equal(d.Leaf().Raw, leaf.Raw) {
		t.Error("the certificate in use was dropped")
	}
	// Then the cluster: it renews, and retires nothing more.
	if err := d.UseStore(s); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(d.Leaf().Raw, leaf.Raw) {
		t.Error("not renewed")
	}
	// A start with the cluster's store.
	e, err := New(Options{Dir: dir, Names: []string{"siem-b.corp.lan"}, Now: c.now, Store: s})
	if err != nil {
		t.Fatal(err)
	}
	if e.Fingerprint() != a.Fingerprint() || len(e.Retired()) != 1 {
		t.Errorf("start with the store: fp %s, %d retired", e.Fingerprint(), len(e.Retired()))
	}
}

// A new server that starts with the cluster's store makes no CA.
func TestNewWithStoreMakesNoCA(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Now()}
	a := newAuto(t, filepath.Join(t.TempDir(), "a"), c)
	dir := filepath.Join(t.TempDir(), "new")
	m, err := New(Options{Dir: dir, Now: c.now, Store: storeOf(t, a)})
	if err != nil {
		t.Fatal(err)
	}
	if m.Fingerprint() != a.Fingerprint() || exists(filepath.Join(dir, caKeyFile)) || len(m.Retired()) != 0 {
		t.Error("a CA was made or retired")
	}
	if _, err := New(Options{Dir: filepath.Join(t.TempDir(), "x"), Now: c.now, Store: &memStore{}}); err == nil {
		t.Error("an empty cluster store made a CA")
	}
}

// The server that publishes its own CA keeps ca.key until DropLocalKey,
// and nothing is retired.
func TestUseStoreSameCA(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Now()}
	dir := t.TempDir()
	m := newAuto(t, dir, c)
	leaf := m.Leaf()
	if err := m.UseStore(storeOf(t, m)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Leaf().Raw, leaf.Raw) || len(m.Retired()) != 0 || !exists(filepath.Join(dir, caKeyFile)) {
		t.Error("the same CA changed something")
	}
	if err := m.DropLocalKey(); err != nil || exists(filepath.Join(dir, caKeyFile)) {
		t.Errorf("DropLocalKey: %v", err)
	}
	// In files mode it never deletes the key.
	f := newAuto(t, t.TempDir(), c)
	if err := f.DropLocalKey(); err != nil || !exists(filepath.Join(f.opts.Dir, caKeyFile)) {
		t.Errorf("files mode DropLocalKey: %v", err)
	}
}

func TestUseStoreRefusesDuringChange(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Now()}
	a := newAuto(t, t.TempDir(), c)
	b := newAuto(t, t.TempDir(), c)
	if err := b.Prepare(ScopeStandard); err != nil {
		t.Fatal(err)
	}
	fp := b.Fingerprint()
	var se *StateError
	if err := b.UseStore(storeOf(t, a)); !errors.As(err, &se) {
		t.Fatalf("UseStore with next/: %v", err)
	}
	if b.Fingerprint() != fp || b.Store() != KindFiles {
		t.Error("changed anyway")
	}
	if err := b.Discard(); err != nil {
		t.Fatal(err)
	}
	if err := b.UseStore(storeOf(t, a)); err != nil {
		t.Fatal(err)
	}
}

func TestSharedNamesCovered(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Now()}
	var mu sync.Mutex
	shared := []string{"siem.corp.lan"}
	m, err := New(Options{Dir: t.TempDir(), Now: c.now, SharedNames: func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(shared)
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Covers("siem.corp.lan") {
		t.Error("shared name not covered")
	}
	mu.Lock()
	shared = append(shared, "10.20.30.40")
	mu.Unlock()
	if err := m.Reissue(); err != nil || !m.Covers("10.20.30.40") {
		t.Errorf("Reissue: %v", err)
	}
	before := m.Leaf()
	if err := m.Reissue(); err != nil || m.Leaf() != before {
		t.Error("Reissue with nothing new made a certificate")
	}
}

// With the cluster's CA, EnsureName keeps the name through PersistName,
// called without the Manager's lock (it calls back into the Manager here,
// which would deadlock otherwise), and not in names.txt.
func TestPersistNameOutsideLock(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Now()}
	a := newAuto(t, t.TempDir(), c)
	dir := t.TempDir()
	var m *Manager
	var mu sync.Mutex
	var persisted []string
	persist := func(_ context.Context, name string) error {
		_ = m.Outside()
		_ = m.CanCover(name)
		_ = m.Store()
		mu.Lock()
		persisted = append(persisted, name)
		mu.Unlock()
		return nil
	}
	var err error
	m, err = New(Options{Dir: dir, Now: c.now, PersistName: persist})
	if err != nil {
		t.Fatal(err)
	}
	// Files mode: names.txt, not PersistName.
	if err := m.EnsureName("192.168.7.7"); err != nil || len(persisted) != 0 || !exists(filepath.Join(dir, namesFile)) {
		t.Fatalf("files mode: %v %v", err, persisted)
	}
	s := storeOf(t, a)
	if err := m.UseStore(s); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := range 4 {
			wg.Add(2)
			go func() {
				defer wg.Done()
				if err := m.EnsureName("host" + string(rune('a'+i)) + ".corp.lan"); err != nil {
					t.Error(err)
				}
			}()
			go func() {
				defer wg.Done()
				_ = m.Reissue()
			}()
		}
		wg.Wait()
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("EnsureName deadlocked: PersistName runs under the lock")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(persisted) != 4 {
		t.Errorf("persisted %v", persisted)
	}
	// Without PersistName, the store's AddName.
	m2, err := New(Options{Dir: t.TempDir(), Now: c.now, Store: s})
	if err != nil {
		t.Fatal(err)
	}
	if err := m2.EnsureName("other.corp.lan"); err != nil || !slices.Contains(s.added, "other.corp.lan") || !m2.Covers("other.corp.lan") {
		t.Errorf("AddName: %v %v", err, s.added)
	}
}

// A ca.pem another program holds open: on Windows it may refuse to be
// replaced, which leaves this server's CA in use and the next try works.
func TestUseStoreWhileCAFileOpen(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Now()}
	a := newAuto(t, t.TempDir(), c)
	dir := t.TempDir()
	b := newAuto(t, dir, c)
	own := b.Fingerprint()
	f, err := os.Open(filepath.Join(dir, CAFile))
	if err != nil {
		t.Fatal(err)
	}
	err = b.UseStore(storeOf(t, a))
	if err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}
		if b.Fingerprint() != own || b.Store() != KindFiles {
			t.Error("a failed UseStore changed the CA in use")
		}
	}
	f.Close()
	if err != nil {
		if err := b.UseStore(storeOf(t, a)); err != nil {
			t.Fatal(err)
		}
	}
	if b.Fingerprint() != a.Fingerprint() || len(b.Retired()) != 1 {
		t.Errorf("fp %s, retired %d", b.Fingerprint(), len(b.Retired()))
	}
}

func TestUseStoreFilesMode(t *testing.T) {
	cert, key, _ := selfSignedPair(t, t.TempDir(), "own", "siem.example.com")
	m, err := New(Options{CertFile: cert, KeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.UseStore(&memStore{}); !errors.Is(err, ErrNotAuto) || m.Store() != "" {
		t.Errorf("files mode: %v %q", err, m.Store())
	}
}

// SetSharedNames replaces Options.SharedNames on a Manager a restart
// keeps; Reissue covers the new names.
func TestSetSharedNames(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Now()}
	m, err := New(Options{Dir: t.TempDir(), Now: c.now, SharedNames: func() []string { return []string{"old.corp.lan"} }})
	if err != nil {
		t.Fatal(err)
	}
	m.SetSharedNames(func() []string { return []string{"node-b.corp.lan"} })
	if err := m.Reissue(); err != nil || !m.Covers("node-b.corp.lan") || m.Covers("old.corp.lan") {
		t.Fatalf("Reissue: %v, names %v", err, m.Names())
	}
	m.SetSharedNames(nil)
	if err := m.Reissue(); err != nil || !m.Covers("old.corp.lan") {
		t.Fatalf("back to the options: %v, names %v", err, m.Names())
	}
}

// LocalFiles reads the CA a server of its own keeps, without making one,
// and returns nothing for the cluster's or during a change of CA.
func TestLocalFiles(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Now()}
	dir := t.TempDir()
	if ca, _, _ := LocalFiles(dir); ca != nil || fileCount(t, dir) != 0 {
		t.Fatal("LocalFiles of an empty folder")
	}
	m, err := New(Options{Dir: dir, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.EnsureName("agents.lan"); err != nil {
		t.Fatal(err)
	}
	ca, key, names := LocalFiles(dir)
	if ca == nil || key == nil || Fingerprint(ca.Raw) != m.Fingerprint() || !slices.Equal(names, []string{"agents.lan"}) {
		t.Fatalf("LocalFiles: %v %v %v", ca != nil, key != nil, names)
	}
	if err := os.MkdirAll(filepath.Join(dir, nextDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if ca, _, _ := LocalFiles(dir); ca != nil {
		t.Error("LocalFiles during a change of CA")
	}
	if err := os.Remove(filepath.Join(dir, nextDir)); err != nil {
		t.Fatal(err)
	}
	other := storeOf(t, m)
	if err := m.UseStore(other); err != nil {
		t.Fatal(err)
	}
	if ca, _, _ := LocalFiles(dir); ca != nil {
		t.Error("LocalFiles with the cluster's CA")
	}
}

func fileCount(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// A server that uses the cluster's CA and has lost its certificate (or
// whose certificate expired while it was off) still starts, without the
// CA's key: it serves a stand-in no client trusts, makes no CA, and the
// cluster's store gives it a real certificate.
func TestDetachedStartWithoutLeaf(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Now()}
	a := newAuto(t, filepath.Join(t.TempDir(), "a"), c)
	s := storeOf(t, a)
	for _, lose := range []string{"deleted", "expired"} {
		t.Run(lose, func(t *testing.T) {
			c := &clock{c.t}
			dir := filepath.Join(t.TempDir(), "b")
			b := newAuto(t, dir, c, "siem-b.corp.lan")
			if err := b.UseStore(s); err != nil {
				t.Fatal(err)
			}
			if lose == "deleted" {
				if err := os.Remove(filepath.Join(dir, certFile)); err != nil {
					t.Fatal(err)
				}
			} else {
				c.t = b.Leaf().NotAfter.Add(time.Hour)
			}
			d, err := New(Options{Dir: dir, Names: []string{"siem-b.corp.lan"}, Now: c.now})
			if err != nil {
				t.Fatalf("start: %v", err)
			}
			leaf := d.Leaf()
			if leaf == nil || leaf.IsCA || leaf.CheckSignatureFrom(a.ca) == nil {
				t.Fatal("no stand-in, or one from the cluster's CA")
			}
			if d.Fingerprint() != a.Fingerprint() || exists(filepath.Join(dir, caKeyFile)) {
				t.Error("a CA was made")
			}
			if lose == "deleted" && exists(filepath.Join(dir, certFile)) {
				t.Error("the stand-in was written to disk")
			}
			if err := d.UseStore(s); err != nil {
				t.Fatal(err)
			}
			if err := d.Leaf().CheckSignatureFrom(a.ca); err != nil {
				t.Errorf("not reissued from the cluster's CA: %v", err)
			}
		})
	}
}

// A change of CA started while the cluster's CA is taken is refused once
// it is: the check is under the same lock as UseStore.
func TestPrepareRacesUseStore(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Now()}
	a := newAuto(t, filepath.Join(t.TempDir(), "a"), c)
	s := storeOf(t, a)
	for range 20 {
		dir := t.TempDir()
		b := newAuto(t, dir, c)
		var wg sync.WaitGroup
		var prepErr, useErr error
		wg.Add(2)
		go func() { defer wg.Done(); prepErr = b.Prepare(ScopeStandard) }()
		go func() { defer wg.Done(); useErr = b.UseStore(s) }()
		wg.Wait()
		switch {
		case useErr == nil && prepErr == nil:
			t.Fatal("both a change of CA and the cluster's CA went ahead")
		case useErr == nil && exists(filepath.Join(dir, nextDir)):
			t.Fatal("next/ left behind under the cluster's CA")
		}
	}
}
