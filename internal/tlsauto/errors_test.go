// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package tlsauto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLeafExpiry(t *testing.T) {
	fakeMachine(t)
	dir := filepath.Join(t.TempDir(), "tls")
	m := newAuto(t, dir, &clock{time.Now()})
	got, err := LeafExpiry(dir)
	if err != nil || !got.Equal(m.Leaf().NotAfter.UTC()) {
		t.Fatalf("LeafExpiry = %v, %v; want %v", got, err, m.Leaf().NotAfter)
	}
	if _, err := LeafExpiry(t.TempDir()); err == nil {
		t.Fatal("LeafExpiry of a folder with no certificate")
	}
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, certFile), []byte("not PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LeafExpiry(bad); err == nil {
		t.Fatal("LeafExpiry of a damaged certificate")
	}
}

// With the cluster's certificate authority, the next and previous ones
// come from the cluster, not from the folder.
func TestClusterNextAndPrevious(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Now()}
	a := newAuto(t, filepath.Join(t.TempDir(), "a"), c, "siem-a.corp.lan")
	other := newAuto(t, filepath.Join(t.TempDir(), "o"), c, "siem-o.corp.lan")
	b := newAuto(t, filepath.Join(t.TempDir(), "b"), c, "siem-b.corp.lan")
	if err := b.UseStore(storeOf(t, a)); err != nil {
		t.Fatal(err)
	}
	if b.Next() != nil || b.NextPEM() != nil {
		t.Fatal("a next certificate authority with none set")
	}
	at := c.t.Add(-time.Minute).UTC()
	var next, prev *ClusterCA
	b.SetClusterCAs(func() (*ClusterCA, *ClusterCA) { return next, prev })
	count := func() int { return strings.Count(string(b.AgentCAPEM()), "BEGIN CERTIFICATE") }

	next = &ClusterCA{Cert: other.ca, At: at}
	if n := b.Next(); n == nil || n.Fingerprint != other.Fingerprint() || !n.At.Equal(at) {
		t.Fatalf("Next = %+v", n)
	}
	if b.NextPEM() == nil || count() != 2 {
		t.Fatalf("the next one is not handed out: %s", b.AgentCAPEM())
	}
	// The one in use, given as next or previous, is not another one.
	next, prev = &ClusterCA{Cert: a.ca}, &ClusterCA{Cert: a.ca}
	if b.Next() != nil || count() != 1 {
		t.Fatal("the certificate authority in use counted as another one")
	}
	next, prev = nil, &ClusterCA{Cert: other.ca, At: at}
	if b.Next() != nil || count() != 2 {
		t.Fatalf("the previous one is not handed out: %s", b.AgentCAPEM())
	}
	b.SetClusterCAs(nil)
	if count() != 1 {
		t.Fatal("SetClusterCAs(nil) kept the previous one")
	}
	if in := b.CAInfo(); in == nil || in.Fingerprint != a.Fingerprint() {
		t.Fatalf("CAInfo = %+v", in)
	}
}

func TestPrepareFailsCleanly(t *testing.T) {
	fakeMachine(t)
	dir := filepath.Join(t.TempDir(), "tls")
	m := newAuto(t, dir, &clock{time.Now()})
	// A file where the next certificate authority's folder goes.
	if err := os.WriteFile(m.path(nextDir), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Prepare(ScopeStandard); err == nil {
		t.Fatal("prepared into a file")
	}
	if exists(m.path(nextDir)) {
		t.Fatal("a failed prepare left its folder")
	}
	// A folder where the next key goes.
	if err := os.MkdirAll(m.path(nextDir, caKeyFile, "x"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := m.Prepare(ScopeStandard); err == nil {
		t.Fatal("prepared over a folder")
	}
	if exists(m.path(nextDir)) {
		t.Fatal("a failed prepare left its folder")
	}
	if err := m.Prepare(ScopeStandard); err != nil {
		t.Fatal(err)
	}
	if m.Next() == nil {
		t.Fatal("no next certificate authority after prepare")
	}
}

func TestRefreshWithCoveredNames(t *testing.T) {
	fakeMachine(t)
	dir := filepath.Join(t.TempDir(), "tls")
	m := newAuto(t, dir, &clock{time.Now()}, "siem.corp.lan")
	leaf := m.Leaf()
	// names.txt holds only what the certificate covers already: the list
	// is taken, and no certificate is issued.
	if err := m.EnsureName("localhost"); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.added = append(m.added, "stale.corp.lan")
	m.mu.Unlock()
	if err := m.Refresh(); err != nil {
		t.Fatal(err)
	}
	if !m.Leaf().Equal(leaf) {
		t.Fatal("a certificate was issued for names it covers")
	}
}

func TestFileHelpersFail(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing", "f")
	folder := filepath.Join(dir, "folder")
	if err := os.MkdirAll(filepath.Join(folder, "x"), 0o750); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{missing, folder} {
		if err := writeFile(p, []byte("x"), 0o644); err == nil {
			t.Errorf("writeFile %s: no error", p)
		}
	}
	// A key is written with its folder made, but not over a folder.
	if err := writeKey(folder, key); err == nil {
		t.Error("writeKey over a folder: no error")
	}
	// The journal goes in the folder; one that is gone, or a folder in
	// its place, fails it.
	for _, d := range []string{filepath.Join(dir, "gone"), dir} {
		m := &Manager{opts: Options{Dir: d}}
		if d == dir {
			if err := os.MkdirAll(filepath.Join(dir, journalFile, "x"), 0o750); err != nil {
				t.Fatal(err)
			}
		}
		if err := m.writeJournal(&journal{Op: "switch"}); err == nil {
			t.Errorf("writeJournal in %s: no error", d)
		}
	}

	// What cannot be read is nothing.
	bad := t.TempDir()
	m := &Manager{opts: Options{Dir: bad}}
	if m.caFingerprint() != "" || m.leafChains() {
		t.Fatal("an empty folder has a certificate authority")
	}
	if _, _, err := readPair(bad); err == nil {
		t.Fatal("readPair of an empty folder")
	}
	for _, f := range []string{CAFile, certFile, "stamp"} {
		if err := os.WriteFile(filepath.Join(bad, f), []byte("damaged"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if m.caFingerprint() != "" || m.leafChains() {
		t.Fatal("a damaged certificate authority was read")
	}
	if !readStamp(filepath.Join(bad, "stamp")).IsZero() || !readStamp(filepath.Join(bad, "none")).IsZero() {
		t.Fatal("a damaged stamp was read")
	}
}

func TestLeafChainsWithoutLeaf(t *testing.T) {
	fakeMachine(t)
	dir := filepath.Join(t.TempDir(), "tls")
	m := newAuto(t, dir, &clock{time.Now()})
	if !m.leafChains() {
		t.Fatal("the leaf does not chain to its own certificate authority")
	}
	if err := os.Remove(m.path(certFile)); err != nil {
		t.Fatal(err)
	}
	if m.leafChains() {
		t.Fatal("a missing leaf chains")
	}
	if err := os.WriteFile(m.path(certFile), []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if m.leafChains() {
		t.Fatal("a damaged leaf chains")
	}
}

// A switch back cut short after its last move, before its stamp, is
// finished by the next start: the newer CA is kept, ready again.
func TestRollbackCutShortAfterTheMoves(t *testing.T) {
	fakeMachine(t)
	dir := t.TempDir()
	c := &clock{time.Now()}
	m := newAuto(t, dir, c, "siem.example.com")
	oldFP := m.Fingerprint()
	if err := m.Prepare(ScopeStrict); err != nil {
		t.Fatal(err)
	}
	newFP := m.Next().Fingerprint
	if err := m.Switch(); err != nil {
		t.Fatal(err)
	}
	last := filepath.Join(dir, keyFile)
	rename = func(from, to string) error {
		if err := os.Rename(from, to); err != nil {
			return err
		}
		if to == last {
			return errCrash
		}
		return nil
	}
	t.Cleanup(func() { rename = os.Rename })
	if err := m.Rollback(); !errors.Is(err, errCrash) {
		t.Fatalf("the switch back did not stop after its moves: %v", err)
	}
	rename = os.Rename
	r, err := New(Options{Dir: dir, Names: []string{"siem.example.com"}, Now: c.now})
	if err != nil {
		t.Fatalf("start after the crash: %v", err)
	}
	if r.Fingerprint() != oldFP || r.Next() == nil || r.Next().Fingerprint != newFP || r.Previous() != nil {
		t.Fatalf("after recovery: in use %s, next %v, previous %v", r.Fingerprint(), r.Next(), r.Previous())
	}
	for _, left := range []string{journalFile, discardedDir, previousDir} {
		if exists(filepath.Join(dir, left)) {
			t.Errorf("%s left", left)
		}
	}
	if !exists(filepath.Join(dir, nextDir, stampMade)) {
		t.Error("the newer CA has no stamp")
	}
}

// A server that cannot keep a copy of its own CA in retired/ keeps using
// it, and takes the cluster's once it can.
func TestUseStoreCannotRetire(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Now()}
	a := newAuto(t, t.TempDir(), c, "siem-a.corp.lan")
	dir := t.TempDir()
	b := newAuto(t, dir, c, "siem-b.corp.lan")
	own := b.Fingerprint()
	blocker := filepath.Join(dir, retiredDir)
	if err := os.WriteFile(blocker, []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := b.UseStore(storeOf(t, a))
	if err == nil || !strings.Contains(err.Error(), "could not retire") {
		t.Fatalf("UseStore with retired/ a file: %v", err)
	}
	if b.Store() != KindFiles || b.Fingerprint() != own || b.Leaf().CheckSignatureFrom(b.ca) != nil {
		t.Fatalf("after the refusal: store %v, CA %s", b.Store(), b.Fingerprint())
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err := b.UseStore(storeOf(t, a)); err != nil {
		t.Fatal(err)
	}
	if b.Fingerprint() != a.Fingerprint() || len(b.Retired()) != 1 {
		t.Errorf("after retired/ was fixed: CA %s, retired %v", b.Fingerprint(), b.Retired())
	}
}

// A seed whose key or certificate cannot be written is an error.
func TestSeedClusterCannotWrite(t *testing.T) {
	cluster, err := New(Options{Dir: t.TempDir(), Names: []string{"siem.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, err := SignCSR(cluster.ca, cluster.caKey, csrFor(t, key), []string{"siem-c.internal"}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, blocked := range []string{keyFile, certFile} {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, blocked, "x"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := SeedCluster(dir, cluster.CAPEM(), leafPEM, keyPEM(t, key), now); err == nil {
			t.Errorf("seeded with %s a folder", blocked)
		}
	}
}

// A name that cannot be kept in names.txt, or a certificate that cannot
// be written, is an error, and the certificate in use stays.
func TestEnsureNameCannotWrite(t *testing.T) {
	fakeMachine(t)
	dir := t.TempDir()
	m := newAuto(t, dir, &clock{time.Now()}, "siem.example.com")
	leaf := m.Leaf()
	names := filepath.Join(dir, namesFile)
	if err := os.RemoveAll(names); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(names, "x"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := m.EnsureName("ws-9.internal"); err == nil {
		t.Error("a name kept though names.txt is a folder")
	}
	if err := os.RemoveAll(names); err != nil {
		t.Fatal(err)
	}
	cert := filepath.Join(dir, certFile)
	if err := os.Remove(cert); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cert, "x"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := m.EnsureName("ws-10.internal"); err == nil {
		t.Error("a certificate written over a folder")
	}
	if !m.Leaf().Equal(leaf) {
		t.Error("the certificate in use changed though the new one was not written")
	}
}
