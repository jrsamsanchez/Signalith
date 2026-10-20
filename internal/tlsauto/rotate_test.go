// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package tlsauto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func newScoped(t *testing.T, dir string, c *clock, scope string, names ...string) *Manager {
	t.Helper()
	m, err := New(Options{Dir: dir, Names: names, Now: c.now, Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// forgeWith signs a certificate for name with the CA's key, the way a
// stolen key would be used.
func forgeWith(t *testing.T, m *Manager, at time.Time, name string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: serial(), NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.ca, key.Public(), m.caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return leaf
}

func TestStrictConstraintsAreExact(t *testing.T) {
	fakeMachine(t)
	dir := t.TempDir()
	c := &clock{time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)}
	m := newScoped(t, dir, c, ScopeStrict, "siem.corp.local", "198.51.100.7")
	if got := m.CAInfo().Scope; got != ScopeStrict {
		t.Fatalf("scope %s", got)
	}
	for _, d := range m.ca.PermittedDNSDomains {
		if slices.Contains(privateDomains, d) && d != "localhost" {
			t.Errorf("strict CA allows the private suffix %s", d)
		}
	}
	for _, r := range m.ca.PermittedIPRanges {
		if ones, bits := r.Mask.Size(); ones != bits {
			t.Errorf("strict CA allows the range %s", r)
		}
	}
	pool := caPool(t, m)
	for name, ok := range map[string]bool{
		"siem.corp.local": true, "ws-test": true, "localhost": true,
		// Exact names only: nothing under them.
		"a.siem.corp.local": false, "x.ws-test": false, "x.localhost": false,
		"198.51.100.7": true, "10.1.2.3": true, "127.0.0.1": true, "::1": true,
		"intranet.corp": false, "nas.home.arpa": false, "other.corp.local": false, "192.168.1.20": false, "10.1.2.4": false,
		"127.0.0.2": false, "www.bank.example": false, "8.8.8.8": false,
	} {
		_, err := forgeWith(t, m, c.t, name).Verify(x509.VerifyOptions{Roots: pool, DNSName: name, CurrentTime: c.t})
		if (err == nil) != ok {
			t.Errorf("%s: verify error %v, want allowed %v", name, err, ok)
		}
	}
	// EnsureName says the CA is strict and what to do.
	err := m.EnsureName("192.168.1.20")
	if err == nil || !strings.Contains(err.Error(), "certificate authority is strict") ||
		!strings.Contains(err.Error(), "Add 192.168.1.20 under Extra certificate names") || !strings.Contains(err.Error(), "Security page") {
		t.Errorf("EnsureName: %v", err)
	}
	if err := m.CanCover("192.168.1.20"); err == nil || !strings.Contains(err.Error(), "strict") {
		t.Errorf("CanCover: %v", err)
	}
	info := m.CAInfo()
	for _, n := range []string{"siem.corp.local", "198.51.100.7", "ws-test", "10.1.2.3", "localhost", "127.0.0.1", "::1"} {
		if !slices.Contains(info.Names, n) {
			t.Errorf("CAInfo names %v lack %s", info.Names, n)
		}
	}
}

// A machine named like a public top-level domain: the CA vouches for the
// name itself, never for the websites under it.
func TestHostNamedLikeATopLevelDomain(t *testing.T) {
	prev := localNames
	localNames = func() []string { return []string{"localhost", "127.0.0.1", "dev"} }
	t.Cleanup(func() { localNames = prev })
	for _, scope := range []string{ScopeStandard, ScopeStrict} {
		c := &clock{time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)}
		m := newScoped(t, t.TempDir(), c, scope)
		if got := m.CAInfo().Scope; got != scope {
			t.Errorf("%s: classified as %s", scope, got)
		}
		if !slices.Contains(m.CAInfo().Names, "dev") || slices.Contains(m.CAInfo().Names, ".dev") {
			t.Errorf("%s: names %v", scope, m.CAInfo().Names)
		}
		pool := caPool(t, m)
		for name, ok := range map[string]bool{"dev": true, "web.dev": false, "www.google.dev": false} {
			_, err := forgeWith(t, m, c.t, name).Verify(x509.VerifyOptions{Roots: pool, DNSName: name, CurrentTime: c.t})
			if (err == nil) != ok {
				t.Errorf("%s %s: verify error %v, want allowed %v", scope, name, err, ok)
			}
			if got := m.CanCover(name) == nil; got != ok {
				t.Errorf("%s CanCover(%s) = %v", scope, name, got)
			}
			if got := m.WouldAllow(scope, name); got != ok {
				t.Errorf("%s WouldAllow(%s) = %v", scope, name, got)
			}
		}
		// The server's own certificate still verifies for dev.
		leaf, _ := m.GetCertificate(nil)
		if err := leaf.Leaf.VerifyHostname("dev"); err != nil {
			t.Errorf("%s: %v", scope, err)
		}
	}
}

// A CA made before names were kept exact says which of its names also
// allow the names under them; a new one has none.
func TestCAInfoSubtrees(t *testing.T) {
	fakeMachine(t)
	m := newScoped(t, t.TempDir(), &clock{time.Now()}, ScopeStandard, "siem.example.com")
	if in := m.CAInfo(); len(in.Subtrees) != 0 {
		t.Errorf("new CA: %v", in.Subtrees)
	}
	old := &x509.Certificate{PermittedDNSDomains: append(slices.Clone(privateDomains), "siem.example.com", "ws-test"),
		PermittedIPRanges: []*net.IPNet{{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)}}}
	if in := infoOf(old); in.Scope != ScopeStandard || !slices.Equal(in.Subtrees, []string{"siem.example.com", "ws-test"}) {
		t.Errorf("old CA: %s %v", in.Scope, in.Subtrees)
	}
}

func TestExcludedSubtrees(t *testing.T) {
	// Standard: private names keep their subtree; a name with another
	// permitted name under it keeps its own.
	got := excludedSubtrees([]string{"local", "corp", "siem.corp.local", "example.com", "siem.example.com", "dev"}, false)
	if !slices.Equal(got, []string{".siem.example.com", ".dev"}) {
		t.Errorf("standard %v", got)
	}
	got = excludedSubtrees([]string{"localhost", "siem.corp.local", "invalid"}, true)
	if !slices.Equal(got, []string{".localhost", ".siem.corp.local"}) {
		t.Errorf("strict %v", got)
	}
}

// A name and one under it, both this server's: both are covered.
func TestNameUnderAnother(t *testing.T) {
	fakeMachine(t)
	for _, scope := range []string{ScopeStandard, ScopeStrict} {
		c := &clock{time.Now()}
		m := newScoped(t, t.TempDir(), c, scope, "example.com", "siem.example.com")
		pool := caPool(t, m)
		for _, name := range []string{"example.com", "siem.example.com"} {
			if _, err := forgeWith(t, m, c.t, name).Verify(x509.VerifyOptions{Roots: pool, DNSName: name, CurrentTime: c.t}); err != nil {
				t.Errorf("%s %s: %v", scope, name, err)
			}
		}
		leaf, _ := m.GetCertificate(nil)
		if leaf.Leaf.VerifyHostname("siem.example.com") != nil || leaf.Leaf.VerifyHostname("example.com") != nil {
			t.Errorf("%s: the certificate lacks a name", scope)
		}
	}
}

func TestPrivateName(t *testing.T) {
	for name, want := range map[string]bool{
		"siem.corp.local": true, "nas.home.arpa": true, "localhost": true, "10.1.2.3": true, "fd00::5": true, "::ffff:192.168.1.2": true,
		"paypal.com": false, "dev": false, "8.8.8.8": false, "not a name": false,
	} {
		if PrivateName(name) != want {
			t.Errorf("%s: %v", name, !want)
		}
	}
}

func TestStrictConstraintsNeverEmpty(t *testing.T) {
	dns, ips := strictConstraints(nil)
	if !slices.Equal(dns, []string{"invalid"}) || len(ips) != 1 || ips[0].String() != "255.255.255.255/32" {
		t.Errorf("empty strict constraints %v %v", dns, ips)
	}
	dns, ips = strictConstraints([]string{"a.example", "10.0.0.1", "a.example", "10.0.0.1", "::1"})
	if !slices.Equal(dns, []string{"a.example"}) || len(ips) != 2 || ips[0].String() != "10.0.0.1/32" || ips[1].String() != "::1/128" {
		t.Errorf("strict constraints %v %v", dns, ips)
	}
}

func TestStandardScopeUnchanged(t *testing.T) {
	fakeMachine(t)
	for _, scope := range []string{"", ScopeStandard, "STANDARD", "nonsense"} {
		m := newScoped(t, t.TempDir(), &clock{time.Now()}, scope, "siem.example.com")
		if got := m.CAInfo().Scope; got != ScopeStandard {
			t.Errorf("scope %q made a %s CA", scope, got)
		}
		if !slices.Contains(m.ca.PermittedDNSDomains, "home.arpa") {
			t.Errorf("standard constraints %v", m.ca.PermittedDNSDomains)
		}
		info := m.CAInfo()
		if slices.Contains(info.Names, "corp") || !slices.Contains(info.Names, "siem.example.com") || slices.Contains(info.Names, "10.1.2.3") {
			t.Errorf("standard names %v", info.Names)
		}
	}
}

func TestClassify(t *testing.T) {
	mk := func(dns []string, ips ...string) *x509.Certificate {
		c := &x509.Certificate{PermittedDNSDomains: dns}
		for _, s := range ips {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				t.Fatal(err)
			}
			c.PermittedIPRanges = append(c.PermittedIPRanges, n)
		}
		return c
	}
	for want, ca := range map[string]*x509.Certificate{
		ScopeUnconstrained: mk(nil),
		ScopeStandard:      mk([]string{"siem", "local", "corp", "lan"}, "10.0.0.5/32"),
		"standard2":        mk([]string{"siem"}, "10.0.0.0/8"),
		ScopeStrict:        mk([]string{"siem", "localhost", "home"}, "10.0.0.5/32", "::1/128"),
	} {
		if want == "standard2" {
			want = ScopeStandard
		}
		if got := classify(ca); got != want {
			t.Errorf("classify %v = %s, want %s", ca.PermittedDNSDomains, got, want)
		}
	}
}

// An older CA without name constraints is unconstrained.
func TestUnconstrainedCA(t *testing.T) {
	fakeMachine(t)
	dir := t.TempDir()
	c := &clock{time.Now()}
	m := newAuto(t, dir, c)
	// Replace the CA with one without constraints, as an older version
	// made it.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: serial(), NotBefore: c.t.Add(-time.Hour), NotAfter: c.t.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err := writeKey(filepath.Join(dir, caKeyFile), key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, CAFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = m
	m2 := newAuto(t, dir, c)
	if got := m2.CAInfo().Scope; got != ScopeUnconstrained {
		t.Errorf("scope %s", got)
	}
}

// dialer serves m on a TLS listener and returns a function that connects
// to it trusting the CAs in pemCAs.
func dialer(t *testing.T, m *Manager) func(pemCAs []byte) (*x509.Certificate, error) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", m.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	return func(pemCAs []byte) (*x509.Certificate, error) {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pemCAs)
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "siem.example.com"})
		if err != nil {
			return nil, err
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0], nil
	}
}

func TestPrepareSwitchRollbackPrune(t *testing.T) {
	fakeMachine(t)
	dir := t.TempDir()
	c := &clock{time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)}
	c.t = time.Now() // handshakes check certificates against the real clock
	m := newAuto(t, dir, c, "siem.example.com")
	oldPEM := m.CAPEM()
	oldFP := m.Fingerprint()
	dial := dialer(t, m)
	if _, err := dial(oldPEM); err != nil {
		t.Fatal(err)
	}

	// Nothing to switch to, cancel, switch back to or remove yet.
	for name, err := range map[string]error{"switch": m.Switch(), "discard": m.Discard(), "rollback": m.Rollback(), "prune": m.Prune()} {
		var se *StateError
		if !errors.As(err, &se) {
			t.Errorf("%s with nothing prepared: %v", name, err)
		}
	}
	if m.Next() != nil || m.Previous() != nil || m.NextPEM() != nil || string(m.AgentCAPEM()) != string(oldPEM) {
		t.Error("next or previous before Prepare")
	}

	// Prepare a strict one: the CA in use stays.
	c.t = c.t.Add(time.Minute)
	if err := m.Prepare(ScopeStrict); err != nil {
		t.Fatal(err)
	}
	if err := m.Prepare(ScopeStrict); !errors.Is(err, ErrNextExists) {
		t.Errorf("second Prepare: %v", err)
	}
	next := m.Next()
	if next == nil || next.Scope != ScopeStrict || !next.At.Equal(c.t.UTC().Truncate(time.Second)) || !strings.Contains(next.Subject, ", "+c.t.UTC().Format(time.DateOnly)+")") || m.Fingerprint() != oldFP {
		t.Fatalf("next %+v", next)
	}
	// Agents get both while it is prepared; Go's pool takes the bundle.
	bundle := m.AgentCAPEM()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) || strings.Count(string(bundle), "BEGIN CERTIFICATE") != 2 {
		t.Errorf("bundle %q", bundle)
	}
	if _, err := dial(bundle); err != nil {
		t.Errorf("before the switch, with the bundle: %v", err)
	}

	// Switch: new handshakes get the new certificate at once.
	nextPEM := m.NextPEM()
	c.t = c.t.Add(time.Minute)
	if err := m.Switch(); err != nil {
		t.Fatal(err)
	}
	if m.Fingerprint() != next.Fingerprint || m.CAInfo().Scope != ScopeStrict || m.Next() != nil {
		t.Fatalf("after switch: %s, next %v", m.Fingerprint(), m.Next())
	}
	if _, err := dial(oldPEM); err == nil {
		t.Error("a client trusting only the old CA still connects after the switch")
	}
	if _, err := dial(nextPEM); err != nil {
		t.Errorf("a client trusting the new CA: %v", err)
	}
	if _, err := dial(bundle); err != nil {
		t.Errorf("a client given both: %v", err)
	}
	prev := m.Previous()
	if prev == nil || prev.Fingerprint != oldFP || !prev.At.Equal(c.t.UTC().Truncate(time.Second)) || !m.SwitchedAt().Equal(prev.At) {
		t.Fatalf("previous %+v", prev)
	}
	if exists(filepath.Join(dir, journalFile)) || exists(filepath.Join(dir, nextDir)) {
		t.Error("journal or next/ left after the switch")
	}
	if err := m.Prepare(ScopeStandard); !errors.Is(err, ErrPreviousKept) || !strings.Contains(err.Error(), "Remove the previous certificate authority first") {
		t.Errorf("Prepare while previous is kept: %v", err)
	}

	// Refusals are noted while the previous CA is kept.
	m.NoteRefusal("192.0.2.9:51234", "https")
	m.NoteRefusal("192.0.2.9:51235", "https")
	m.NoteRefusal("[2001:db8::5]:6514", "syslog")
	if r := m.Refusals(); len(r) != 2 || r[0].Count+r[1].Count != 3 {
		t.Errorf("refusals %+v", r)
	}

	// A restart keeps the switched files.
	m2 := newAuto(t, dir, c, "siem.example.com")
	if m2.Fingerprint() != next.Fingerprint || m2.Previous() == nil || !m2.SwitchedAt().Equal(prev.At) {
		t.Errorf("after restart: %s, previous %v", m2.Fingerprint(), m2.Previous())
	}

	// Switch back: the newer one is kept as next/, ready again.
	if err := m.Rollback(); err != nil {
		t.Fatal(err)
	}
	if m.Fingerprint() != oldFP || m.Previous() != nil || m.Next() == nil || m.Next().Fingerprint != next.Fingerprint {
		t.Fatalf("after rollback: %s next %v previous %v", m.Fingerprint(), m.Next(), m.Previous())
	}
	if _, err := dial(oldPEM); err != nil {
		t.Errorf("old CA after switching back: %v", err)
	}
	if len(m.Refusals()) != 0 {
		t.Error("refusals kept after switching back")
	}
	m.NoteRefusal("192.0.2.9:1", "https")
	if len(m.Refusals()) != 0 {
		t.Error("a refusal was noted with no switch in progress")
	}

	// Switch again with no new sharing, then remove the old one.
	if err := m.Switch(); err != nil {
		t.Fatal(err)
	}
	if err := m.Prune(); err != nil {
		t.Fatal(err)
	}
	if m.Previous() != nil || exists(filepath.Join(dir, previousDir)) || !m.SwitchedAt().IsZero() {
		t.Error("previous kept after Prune")
	}
	if err := m.Rollback(); !errors.Is(err, ErrNoPrevious) {
		t.Errorf("rollback after prune: %v", err)
	}

	// Discard removes a prepared one.
	if err := m.Prepare(ScopeStandard); err != nil {
		t.Fatal(err)
	}
	if err := m.Discard(); err != nil || m.Next() != nil {
		t.Errorf("discard: %v, next %v", err, m.Next())
	}
}

func TestFilesModeRefusesCAChanges(t *testing.T) {
	dir := t.TempDir()
	cert, key, _ := selfSignedPair(t, dir, "srv", "siem.example.com")
	m, err := New(Options{CertFile: cert, KeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{m.Prepare(ScopeStrict), m.Switch(), m.Rollback(), m.Discard(), m.Prune()} {
		if !errors.Is(err, ErrNotAuto) {
			t.Errorf("files mode: %v", err)
		}
	}
	if m.CAInfo() != nil || m.Next() != nil || m.WouldCover(ScopeStrict) != nil {
		t.Error("files mode has CA info")
	}
}

// A failing rename at any step leaves the CA in use, with its files back
// where they were.
func TestSwitchFailureRestores(t *testing.T) {
	fakeMachine(t)
	for step := 0; step < 6; step++ {
		t.Run(fmt.Sprint(step), func(t *testing.T) {
			dir := t.TempDir()
			c := &clock{time.Now()}
			m := newAuto(t, dir, c, "siem.example.com")
			fp, leaf := m.Fingerprint(), m.Leaf()
			if err := m.Prepare(ScopeStrict); err != nil {
				t.Fatal(err)
			}
			nextFP := m.Next().Fingerprint
			n := 0
			rename = func(a, b string) error {
				if n == step {
					n++
					return errors.New("disk said no")
				}
				n++
				return os.Rename(a, b)
			}
			t.Cleanup(func() { rename = os.Rename })
			err := m.Switch()
			if err == nil || !strings.Contains(err.Error(), "disk said no") {
				t.Fatalf("switch: %v", err)
			}
			if m.Fingerprint() != fp || m.Leaf() != leaf || m.Next() == nil || m.Next().Fingerprint != nextFP || m.Previous() != nil {
				t.Errorf("after a failed switch: %s next %v previous %v", m.Fingerprint(), m.Next(), m.Previous())
			}
			if exists(filepath.Join(dir, journalFile)) {
				t.Error("journal left")
			}
			rename = os.Rename
			m2 := newAuto(t, dir, c, "siem.example.com")
			if m2.Fingerprint() != fp {
				t.Error("a restart sees another CA")
			}
			if err := m.Switch(); err != nil {
				t.Errorf("switch after the failure: %v", err)
			}
		})
	}
}

// A crash at any point of a switch, or a switch back, is finished or
// undone by the next start, which then has a matching CA, key and
// certificate.
func TestJournalRecovery(t *testing.T) {
	fakeMachine(t)
	points := []string{"journal", "move:0", "move:1", "move:2", "move:3", "move:4", "move:5", "leaf", "stamp"}
	for _, op := range []string{"switch", "rollback"} {
		for _, point := range points {
			if op == "rollback" && (point == "leaf" || point == "stamp") {
				continue
			}
			t.Run(op+"/"+point, func(t *testing.T) {
				dir := t.TempDir()
				c := &clock{time.Now()}
				m := newAuto(t, dir, c, "siem.example.com")
				oldFP := m.Fingerprint()
				if err := m.Prepare(ScopeStrict); err != nil {
					t.Fatal(err)
				}
				newFP := m.Next().Fingerprint
				from, to := oldFP, newFP
				if op == "rollback" {
					if err := m.Switch(); err != nil {
						t.Fatal(err)
					}
					from, to = newFP, oldFP
				}
				testCrash = func(p string) bool { return p == point }
				t.Cleanup(func() { testCrash = nil })
				var err error
				if op == "switch" {
					err = m.Switch()
				} else {
					err = m.Rollback()
				}
				if !errors.Is(err, errCrash) {
					t.Fatalf("%s did not stop at %s: %v", op, point, err)
				}
				testCrash = nil
				r, err := New(Options{Dir: dir, Names: []string{"siem.example.com"}, Now: c.now})
				if err != nil {
					t.Fatalf("start after the crash: %v", err)
				}
				got := r.Fingerprint()
				if got != from && got != to {
					t.Fatalf("CA after recovery is neither: %s", got)
				}
				if exists(filepath.Join(dir, journalFile)) || exists(filepath.Join(dir, discardedDir)) {
					t.Error("journal or discarded/ left")
				}
				if r.Leaf().CheckSignatureFrom(r.ca) != nil {
					t.Error("certificate not from the CA in use")
				}
				// The other CA is kept where it belongs.
				if op == "switch" {
					if got == from && (r.Next() == nil || r.Next().Fingerprint != to || r.Previous() != nil) {
						t.Errorf("undone switch: next %v previous %v", r.Next(), r.Previous())
					}
					if got == to && (r.Previous() == nil || r.Previous().Fingerprint != from || r.Next() != nil || r.SwitchedAt().IsZero()) {
						t.Errorf("finished switch: next %v previous %v", r.Next(), r.Previous())
					}
				} else {
					if got == from && (r.Previous() == nil || r.Previous().Fingerprint != to || r.Next() != nil) {
						t.Errorf("undone rollback: next %v previous %v", r.Next(), r.Previous())
					}
					if got == to && (r.Next() == nil || r.Next().Fingerprint != from || r.Previous() != nil) {
						t.Errorf("finished rollback: next %v previous %v", r.Next(), r.Previous())
					}
				}
				// Undone before any file moved; finished once the stamp
				// is written.
				if point == "journal" && got != from {
					t.Error("a switch stopped before any move was finished")
				}
				if point == "stamp" && got != to {
					t.Error("a switch stopped after the stamp was undone")
				}
			})
		}
	}
}

func TestWouldCoverAndSeenNames(t *testing.T) {
	fakeMachine(t)
	c := &clock{time.Now()}
	m := newAuto(t, t.TempDir(), c, "siem.example.com")
	got := m.WouldCover(ScopeStrict)
	for _, n := range []string{"siem.example.com", "localhost", "127.0.0.1", "::1", "ws-test", "10.1.2.3"} {
		if !slices.Contains(got, n) {
			t.Errorf("WouldCover %v lacks %s", got, n)
		}
	}
	if !m.WouldAllow(ScopeStandard, "192.168.1.20") || m.WouldAllow(ScopeStrict, "192.168.1.20") || !m.WouldAllow(ScopeStrict, "10.1.2.3") {
		t.Error("WouldAllow is wrong")
	}
	m.NoteName("192.168.1.20:8080")
	m.NoteName("SIEM.example.com")
	m.NoteName("not a name")
	// The name asked for in a handshake isn't noted: anyone could send it.
	m.GetCertificate(&tls.ClientHelloInfo{ServerName: "alias.corp"})
	seen := m.SeenNames()
	var names []string
	for _, s := range seen {
		names = append(names, s.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"192.168.1.20", "siem.example.com"}) {
		t.Errorf("seen %v", names)
	}
	c.t = c.t.Add(25 * time.Hour)
	if len(m.SeenNames()) != 0 {
		t.Error("names older than a day are listed")
	}
}

// A computer that refuses over HTTPS and over syslog has an entry for
// each, so neither hides the other.
func TestRecorderKeepsEachWayIn(t *testing.T) {
	var r recorder
	at := time.Now()
	r.note("10.0.0.9", "https", at, maxRefusals)
	r.note("10.0.0.9", "syslog", at.Add(time.Second), maxRefusals)
	r.note("10.0.0.9", "https", at.Add(2*time.Second), maxRefusals)
	list := r.list(time.Time{})
	if len(list) != 2 || list[0].Via != "https" || list[0].Count != 2 || list[1].Via != "syslog" || list[1].Count != 1 ||
		list[0].Address != "10.0.0.9" || list[1].Address != "10.0.0.9" {
		t.Errorf("%+v", list)
	}
}

func TestRecorderKeepsNewest(t *testing.T) {
	var r recorder
	at := time.Now()
	for i := range 210 {
		r.note(fmt.Sprintf("10.0.%d.%d", i/256, i%256), "https", at.Add(time.Duration(i)*time.Second), maxRefusals)
	}
	list := r.list(time.Time{})
	if len(list) != maxRefusals || list[0].Address != "10.0.0.209" {
		t.Errorf("%d kept, newest %s", len(list), list[0].Address)
	}
	for _, e := range list {
		if e.Address == "10.0.0.0" {
			t.Error("oldest kept")
		}
	}
}

// A certificate authority made to replace another keeps its name
// constraints exactly, and the template every one of Signalith's has.
func TestNewCALike(t *testing.T) {
	now := time.Now()
	dns, excluded, ips := constraints([]string{"siem-a.example.com", "10.1.2.3"}, false)
	cur := caTemplate("old", now.AddDate(-2, 0, 0), dns, excluded, ips)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificate(rand.Reader, cur, cur, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := x509.ParseCertificate(der)
	if _, _, err := NewCALike(nil, "x", now); err == nil {
		t.Error("made one like nothing")
	}
	ca, k, err := NewCALike(old, "Signalith Cluster CA (test)", now)
	if err != nil {
		t.Fatal(err)
	}
	if !samePublicKey(ca.PublicKey, k.Public()) || samePublicKey(ca.PublicKey, key.Public()) {
		t.Error("not a new key of its own")
	}
	if !slices.Equal(ca.PermittedDNSDomains, old.PermittedDNSDomains) || !slices.Equal(ca.ExcludedDNSDomains, old.ExcludedDNSDomains) ||
		len(ca.PermittedIPRanges) != len(old.PermittedIPRanges) || !ca.PermittedDNSDomainsCritical {
		t.Errorf("constraints %v %v %v", ca.PermittedDNSDomains, ca.ExcludedDNSDomains, ca.PermittedIPRanges)
	}
	for i := range ca.PermittedIPRanges {
		if ca.PermittedIPRanges[i].String() != old.PermittedIPRanges[i].String() {
			t.Errorf("IP range %d: %s, want %s", i, ca.PermittedIPRanges[i], old.PermittedIPRanges[i])
		}
	}
	if !ca.IsCA || !ca.MaxPathLenZero || !ServerOnly(ca) || ca.KeyUsage != old.KeyUsage ||
		!slices.Equal(ca.PermittedEmailAddresses, []string{noSuchName}) || ca.NotAfter.Before(now.AddDate(CAYears, 0, -1)) {
		t.Errorf("template %+v", ca)
	}
	if classify(ca) != classify(old) {
		t.Errorf("scope %s, was %s", classify(ca), classify(old))
	}
}
