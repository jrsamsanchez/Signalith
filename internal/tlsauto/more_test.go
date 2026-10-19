// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package tlsauto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestInspect: Inspect reads what the folder holds without making
// anything.
func TestInspect(t *testing.T) {
	fakeMachine(t)
	dir := t.TempDir()
	if _, err := Inspect(Options{Dir: dir}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("empty folder = %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("Inspect wrote %d files", len(entries))
	}

	c := &clock{time.Now()}
	m := newAuto(t, dir, c, "siem.example.com")
	in, err := Inspect(Options{Dir: dir, Names: []string{"siem.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if in.Fingerprint() != m.Fingerprint() || in.Leaf() == nil || !in.Leaf().Equal(m.Leaf()) || !in.Covers("siem.example.com") {
		t.Errorf("inspected %s, leaf %v", in.Fingerprint(), in.Leaf())
	}
	if in.Store() != KindFiles || in.CAInfo() == nil || in.Next() != nil {
		t.Errorf("store %q info %v next %v", in.Store(), in.CAInfo(), in.Next())
	}

	// A server certificate that cannot be read leaves no leaf.
	os.WriteFile(filepath.Join(dir, certFile), []byte("junk"), 0o644)
	if in, err := Inspect(Options{Dir: dir}); err != nil || in.Leaf() != nil {
		t.Errorf("junk leaf = %v %v", in, err)
	}
	// Nor a CA certificate.
	os.WriteFile(filepath.Join(dir, CAFile), []byte("junk"), 0o644)
	if _, err := Inspect(Options{Dir: dir}); err == nil {
		t.Error("a junk CA was inspected")
	}

	// A folder marked as the cluster's says so.
	os.WriteFile(filepath.Join(dir, CAFile), m.CAPEM(), 0o644)
	if err := writeMark(dir, m.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if in, err := Inspect(Options{Dir: dir}); err != nil || in.Store() != KindCluster {
		t.Errorf("cluster folder = %v %v", in, err)
	}

	// Files mode reads the admin's files.
	fdir := t.TempDir()
	cert, key, _ := selfSignedPair(t, fdir, "own", "own.example.com")
	in, err = Inspect(Options{CertFile: cert, KeyFile: key})
	if err != nil || in.Store() != "" || !in.Covers("own.example.com") || in.CAInfo() != nil {
		t.Errorf("files mode = %v %v", in, err)
	}
	if _, err := Inspect(Options{CertFile: filepath.Join(fdir, "missing.pem"), KeyFile: key}); err == nil {
		t.Error("a missing certificate file was inspected")
	}
}

// TestNilManager: a server with no Manager answers as one with nothing.
func TestNilManager(t *testing.T) {
	var m *Manager
	if m.CAPEM() != nil || m.PublicCA() || m.Fingerprint() != "" || m.Leaf() != nil || m.CanCover("x") != nil ||
		len(m.Refusals()) != 0 || !m.SwitchedAt().IsZero() || len(m.SeenNames()) != 0 || m.Outside() != nil ||
		m.LocalCA() || m.CAPath() != "" || m.CAInfo() != nil || m.Next() != nil || m.Previous() != nil || m.NextPEM() != nil ||
		m.AgentCAPEM() != nil || m.WouldCover("") != nil || m.WouldAllow("", "x") || m.Store() != "" || m.KeepsKey() ||
		len(m.Retired()) != 0 || m.DropLocalKey() != nil || m.Reissue() != nil {
		t.Error("a nil Manager answered with something")
	}
	m.NoteName("x")
	m.NoteRefusal("10.0.0.1:1", "https")
	if ca, key, names := m.LocalPair(); ca != nil || key != nil || names != nil {
		t.Error("LocalPair")
	}
}

func TestNameHelpers(t *testing.T) {
	fakeMachine(t)
	if _, err := CheckName(nil, "not a name!"); err == nil {
		t.Error("a bad name was checked")
	}
	if n, err := CheckName(nil, "Host.Example."); err != nil || n != "host.example" {
		t.Errorf("no CA = %q %v", n, err)
	}
	m := newScoped(t, t.TempDir(), &clock{time.Now()}, ScopeStrict, "siem.example.com")
	if n, err := CheckName(m.ca, "siem.example.com"); err != nil || n != "siem.example.com" {
		t.Errorf("allowed = %q %v", n, err)
	}
	if _, err := CheckName(m.ca, "www.example.org"); err == nil {
		t.Error("a name outside a strict CA was allowed")
	}
	if !CAAllows(m.ca, "siem.example.com") || CAAllows(m.ca, "www.example.org") || !CAAllows(nil, "anything") {
		t.Error("CAAllows")
	}
	if n, ok := NormalizeName(" WS-1 "); !ok || n != "ws-1" {
		t.Errorf("NormalizeName = %q %v", n, ok)
	}
	if InfoOf(nil) != nil || InfoOf(m.ca) == nil || InfoOf(m.ca).Fingerprint != m.Fingerprint() {
		t.Error("InfoOf")
	}
	if got := shortList(nil, 3); !strings.Contains(got, "only this computer") {
		t.Errorf("shortList(nil) = %q", got)
	}
	if got := shortList([]string{"a.example", "b.example", "10.0.0.1", "127.0.0.1", "localhost"}, 2); got != "10.0.0.1, a.example and others" {
		t.Errorf("shortList = %q", got)
	}
	if m.CanCover("bad name!") == nil {
		t.Error("CanCover took a bad name")
	}
	if m.CanCover("0.0.0.0") != nil {
		t.Error("CanCover refused the unspecified address")
	}
	if m.CanCover("www.example.org") == nil {
		t.Error("CanCover allowed a name the strict CA may not sign")
	}
	if m.EnsureName("www.example.org") == nil {
		t.Error("EnsureName added a name the CA may not sign")
	}
}

func TestLocalPairAndKey(t *testing.T) {
	fakeMachine(t)
	dir := t.TempDir()
	c := &clock{time.Now()}
	m := newAuto(t, dir, c, "siem.example.com")
	if err := m.EnsureName("ws-9.internal"); err != nil {
		t.Fatal(err)
	}
	ca, key, names := m.LocalPair()
	if ca == nil || key == nil || !slices.Contains(names, "ws-9.internal") || !m.KeepsKey() {
		t.Errorf("LocalPair = %v %v %v, keeps %v", ca != nil, key != nil, names, m.KeepsKey())
	}
	if err := m.Prepare(ScopeStandard); err != nil {
		t.Fatal(err)
	}
	if ca, _, _ := m.LocalPair(); ca != nil {
		t.Error("LocalPair during a change")
	}
	if len(m.AgentCAPEM()) <= len(m.CAPEM()) || m.NextPEM() == nil {
		t.Error("the agents' CA file lacks the next CA")
	}
	if err := m.Discard(); err != nil {
		t.Fatal(err)
	}
	// Not in the cluster: DropLocalKey keeps it.
	if err := m.DropLocalKey(); err != nil || !m.KeepsKey() {
		t.Errorf("DropLocalKey = %v, keeps %v", err, m.KeepsKey())
	}
	if len(m.Retired()) != 0 {
		t.Errorf("retired %v", m.Retired())
	}
	if err := m.Reissue(); err != nil {
		t.Errorf("Reissue = %v", err)
	}

	// The admin's own files: nothing of Signalith's.
	fdir := t.TempDir()
	cert, keyPath, _ := selfSignedPair(t, fdir, "own", "own.example.com")
	f, err := New(Options{CertFile: cert, KeyFile: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if ca, _, _ := f.LocalPair(); ca != nil || f.KeepsKey() || f.Store() != "" || f.CAPath() != "" {
		t.Error("files mode has a local CA")
	}
	if f.Prepare(ScopeStandard) != ErrNotAuto || f.WouldAllow("", "own.example.com") {
		t.Error("files mode can change CA")
	}
	if err := f.CanCover("other.example.com"); err == nil || !strings.Contains(err.Error(), "own.example.com") {
		t.Errorf("files mode CanCover = %v", err)
	}
}

// TestRunStops: Run returns when its context ends.
func TestRunStops(t *testing.T) {
	fakeMachine(t)
	m := newAuto(t, t.TempDir(), &clock{time.Now()}, "siem.example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// TestCheckNearCAExpiry: a CA about to expire is warned about, and the
// certificate is renewed up to the CA's end.
func TestCheckNearCAExpiry(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Now()}
	m, err := New(Options{Dir: t.TempDir(), Names: []string{"siem.example.com"}, Now: c.now, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	c.t = m.ca.NotAfter.Add(-RenewBefore / 2)
	if err := m.Check(); err != nil {
		t.Fatal(err)
	}
	if !m.Leaf().NotAfter.Equal(m.ca.NotAfter) {
		t.Errorf("leaf ends %v, CA %v", m.Leaf().NotAfter, m.ca.NotAfter)
	}
}

func TestSignCSRErrors(t *testing.T) {
	fakeMachine(t)
	m := newAuto(t, t.TempDir(), &clock{time.Now()}, "siem.example.com")
	now := time.Now()
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good := csrFor(t, ek)
	names := []string{"siem-c.internal"}
	if _, err := SignCSR(nil, nil, good, names, now); err == nil {
		t.Error("signed with no CA")
	}
	if _, err := SignCSR(m.ca, m.caKey, []byte("junk"), names, now); err == nil {
		t.Error("signed junk")
	}
	if _, err := SignCSR(m.ca, m.caKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("junk")}), names, now); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("unreadable request = %v", err)
	}
	// A request whose signature was tampered with.
	b, _ := pem.Decode(good)
	csr, _ := x509.ParseCertificateRequest(b.Bytes)
	raw := slices.Clone(b.Bytes)
	sig := csr.Signature
	i := len(raw) - len(sig) + len(sig)/2
	raw[i] ^= 0xff
	if _, err := SignCSR(m.ca, m.caKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw}), names, now); err == nil {
		t.Error("signed a tampered request")
	}

	// Ed25519 and RSA keys are taken; RSA may also encipher keys.
	_, edk, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := SignCSR(m.ca, m.caKey, csrFor(t, edk), names, now); err != nil {
		t.Errorf("ed25519 = %v", err)
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	out, err := SignCSR(m.ca, m.caKey, csrFor(t, rk), names, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := parseCert(out)
	if leaf.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("an RSA certificate cannot encipher keys")
	}
	// Signed near the CA's end, the certificate ends with it.
	late := m.ca.NotAfter.Add(-24 * time.Hour)
	out, err = SignCSR(m.ca, m.caKey, good, names, late)
	if err != nil {
		t.Fatal(err)
	}
	if leaf, _ := parseCert(out); !leaf.NotAfter.Equal(m.ca.NotAfter) {
		t.Errorf("late leaf ends %v, CA %v", leaf.NotAfter, m.ca.NotAfter)
	}
}

func TestSeedClusterErrors(t *testing.T) {
	fakeMachine(t)
	cluster := newAuto(t, t.TempDir(), &clock{time.Now()}, "siem.example.com")
	now := time.Now()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, err := SignCSR(cluster.ca, cluster.caKey, csrFor(t, key), []string{"siem-c.internal"}, now)
	if err != nil {
		t.Fatal(err)
	}
	other := newAuto(t, t.TempDir(), &clock{time.Now()}, "other.example.com")
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caPEM, kp := cluster.CAPEM(), keyPEM(t, key)
	for name, tc := range map[string]struct {
		ca, leaf, key []byte
		want          string
	}{
		"bad ca":     {[]byte("x"), leaf, kp, "certificate authority"},
		"bad leaf":   {caPEM, []byte("x"), kp, "server's certificate"},
		"other ca":   {other.CAPEM(), leaf, kp, "not from the cluster"},
		"bad key":    {caPEM, leaf, []byte("x"), "no PEM key"},
		"broken key": {caPEM, leaf, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}), "the server's key"},
		"wrong key":  {caPEM, leaf, keyPEM(t, otherKey), "not for its key"},
	} {
		if err := SeedCluster(t.TempDir(), tc.ca, tc.leaf, tc.key, now); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s = %v", name, err)
		}
	}
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, nextDir), 0o750)
	var se *StateError
	if err := SeedCluster(dir, caPEM, leaf, kp, now); !errors.As(err, &se) {
		t.Errorf("during a change = %v", err)
	}
	// A folder that is a file.
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, []byte("x"), 0o600)
	if err := SeedCluster(file, caPEM, leaf, kp, now); err == nil {
		t.Error("seeded a file")
	}
}

// TestDamagedFolders: New says what is wrong with a folder it cannot use.
func TestDamagedFolders(t *testing.T) {
	fakeMachine(t)
	mk := func(t *testing.T) string {
		dir := t.TempDir()
		newAuto(t, dir, &clock{time.Now()}, "siem.example.com")
		return dir
	}
	for name, tc := range map[string]struct {
		damage func(dir string)
		want   string
	}{
		"ca missing, key there": {func(d string) { os.Remove(filepath.Join(d, CAFile)) }, "is missing but its key"},
		"ca junk":               {func(d string) { os.WriteFile(filepath.Join(d, CAFile), []byte("x"), 0o644) }, CAFile},
		"key missing":           {func(d string) { os.Remove(filepath.Join(d, caKeyFile)) }, caKeyFile},
		"key junk":              {func(d string) { os.WriteFile(filepath.Join(d, caKeyFile), []byte("x"), 0o600) }, "no PEM key"},
		"key not pkcs8": {func(d string) {
			os.WriteFile(filepath.Join(d, caKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}), 0o600)
		}, caKeyFile},
		"key of another": {func(d string) {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			writeKey(filepath.Join(d, caKeyFile), k)
		}, "does not belong"},
		"journal damaged": {func(d string) { os.WriteFile(filepath.Join(d, journalFile), []byte("{"), 0o644) }, "is damaged"},
		"journal folder": {func(d string) {
			os.Mkdir(filepath.Join(d, journalFile), 0o750)
			os.WriteFile(filepath.Join(d, journalFile, "x"), []byte("x"), 0o644)
		}, "cannot read"},
		"cluster ca missing": {func(d string) {
			writeMark(d, "AB")
			os.Remove(filepath.Join(d, CAFile))
		}, "uses the cluster's certificate authority"},
		"cluster ca junk": {func(d string) {
			writeMark(d, "AB")
			os.WriteFile(filepath.Join(d, CAFile), []byte("x"), 0o644)
		}, CAFile},
	} {
		t.Run(name, func(t *testing.T) {
			dir := mk(t)
			tc.damage(dir)
			_, err := New(Options{Dir: dir, Names: []string{"siem.example.com"}, Log: quiet()})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("New = %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := New(Options{}); err == nil {
		t.Error("New with no folder")
	}
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, []byte("x"), 0o600)
	if _, err := New(Options{Dir: file}); err == nil {
		t.Error("New in a file")
	}
}

func TestDetachedStore(t *testing.T) {
	s := detachedStore{fileStore{t.TempDir()}}
	if s.Make(nil) == nil || !errors.Is(s.AddName(context.Background(), "x"), errNoCAKey) || s.Kind() != KindCluster {
		t.Error("a detached store makes or adds")
	}
	if err := (fileStore{t.TempDir()}).AddName(context.Background(), "not a name!"); err == nil {
		t.Error("added a bad name")
	}
	// names.txt keeps the newest maxAddedNames.
	fsx := fileStore{t.TempDir()}
	var lines []string
	for i := range maxAddedNames + 5 {
		lines = append(lines, "host-"+string(rune('a'+i%26))+strings.Repeat("x", i/26)+".internal")
	}
	fsx.writeNames(lines)
	if got := fsx.Names(); len(got) != maxAddedNames || got[len(got)-1] != lines[len(lines)-1] {
		t.Errorf("names %d, last %v", len(got), got[len(got)-1])
	}
	if err := fsx.AddName(context.Background(), "new.internal"); err != nil {
		t.Fatal(err)
	}
	if got := fsx.Names(); len(got) != maxAddedNames || got[len(got)-1] != "new.internal" {
		t.Errorf("after add %d %v", len(got), got[len(got)-1])
	}
}

type errStore struct{ memStore }

func (*errStore) Load() (*x509.Certificate, crypto.Signer, error) {
	return nil, nil, errors.New("settings unreadable")
}

func TestUseStoreRefusals(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Now()}
	a := newAuto(t, t.TempDir(), c, "siem-a.corp.lan")
	dir := t.TempDir()
	b := newAuto(t, dir, c, "siem-b.corp.lan")
	if b.UseStore(nil) == nil {
		t.Error("used no store")
	}
	if err := b.UseStore(&errStore{}); err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Errorf("unreadable store = %v", err)
	}
	if err := b.UseStore(&memStore{}); err == nil || !strings.Contains(err.Error(), "no certificate authority yet") {
		t.Errorf("empty store = %v", err)
	}
	if err := b.UseStore(&memStore{ca: a.ca, key: b.caKey}); err == nil || !strings.Contains(err.Error(), "do not belong") {
		t.Errorf("mismatched store = %v", err)
	}
	if b.Store() != KindFiles || b.Fingerprint() == a.Fingerprint() {
		t.Error("a refused store was used")
	}

	// Leftovers in retired/ that are not a CA are skipped.
	os.MkdirAll(filepath.Join(dir, retiredDir, "empty"), 0o750)
	os.MkdirAll(filepath.Join(dir, retiredDir, "junk"), 0o750)
	os.WriteFile(filepath.Join(dir, retiredDir, "junk", CAFile), []byte("x"), 0o644)
	if err := b.UseStore(storeOf(t, a)); err != nil {
		t.Fatal(err)
	}
	if ret := b.Retired(); len(ret) != 1 {
		t.Errorf("retired %+v", ret)
	}
	if ca, _, _ := b.LocalPair(); ca != nil {
		t.Error("LocalPair with the cluster's CA in use")
	}
	if len(b.Names()) == 0 {
		t.Error("no names")
	}
	// Using it again retires nothing more.
	if err := b.UseStore(storeOf(t, a)); err != nil {
		t.Fatal(err)
	}
	if ret := b.Retired(); len(ret) != 1 {
		t.Errorf("retired again %+v", ret)
	}

	// A detached start keeps ca.key: DropLocalKey leaves it.
	d, err := New(Options{Dir: dir, Names: []string{"siem-b.corp.lan"}, Now: c.now, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	if d.Store() != KindCluster {
		t.Fatalf("restarted store %q", d.Store())
	}
	if err := d.DropLocalKey(); err != nil {
		t.Errorf("DropLocalKey detached = %v", err)
	}
	if d.EnsureName("new-name.corp.lan") == nil {
		t.Error("a detached server added a name with no key")
	}
}

// TestSwitchGuards: Switch and Rollback refuse a folder in the wrong
// state, or with a CA pair that does not load.
func TestSwitchGuards(t *testing.T) {
	fakeMachine(t)
	dir := t.TempDir()
	m := newAuto(t, dir, &clock{time.Now()}, "siem.example.com")
	if err := m.Prepare(ScopeStandard); err != nil {
		t.Fatal(err)
	}
	if err := m.Switch(); err != nil {
		t.Fatal(err)
	}
	// A next CA beside the previous one.
	os.MkdirAll(filepath.Join(dir, nextDir), 0o750)
	os.WriteFile(filepath.Join(dir, nextDir, CAFile), m.CAPEM(), 0o644)
	if err := m.Switch(); !errors.Is(err, ErrPreviousKept) {
		t.Errorf("switch with previous kept = %v", err)
	}
	var se *StateError
	if err := m.Rollback(); !errors.As(err, &se) || !strings.Contains(err.Error(), "Cancel the new") {
		t.Errorf("rollback with a next CA = %v", err)
	}
	// The previous CA's key does not load.
	os.RemoveAll(filepath.Join(dir, nextDir))
	os.WriteFile(filepath.Join(dir, previousDir, caKeyFile), []byte("x"), 0o600)
	if err := m.Rollback(); err == nil || !strings.Contains(err.Error(), "no PEM key") {
		t.Errorf("rollback with a broken key = %v", err)
	}
	// The next CA has no key, or one of another.
	os.RemoveAll(filepath.Join(dir, previousDir))
	os.MkdirAll(filepath.Join(dir, nextDir), 0o750)
	os.WriteFile(filepath.Join(dir, nextDir, CAFile), m.CAPEM(), 0o644)
	if err := m.Switch(); err == nil {
		t.Error("switched to a CA with no key")
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	writeKey(filepath.Join(dir, nextDir, caKeyFile), k)
	if err := m.Switch(); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("switch to a mismatched pair = %v", err)
	}
	os.WriteFile(filepath.Join(dir, nextDir, CAFile), []byte("x"), 0o644)
	if err := m.Switch(); err == nil {
		t.Error("switched to a junk CA")
	}
	if m.Next() != nil || m.NextPEM() != nil {
		t.Error("a junk next CA was described")
	}
}
