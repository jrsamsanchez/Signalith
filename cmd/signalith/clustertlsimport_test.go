// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/clustertls"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

func writeKeyPEM(t *testing.T, path string, key any) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// signalith cluster tls import gives back the cluster certificate
// authority's key emptied by reset-key, from an export's tls folder: only
// its own key, with its own certificate, read from a plain file.
func TestClusterTLSImport(t *testing.T) {
	t.Setenv(clusterKeyFileEnv, "")
	fastSharedCheck(t)
	fastTLSPoll(t)
	fos := ostest.New(t)
	a := startRunnerWith(t, runOptions{scheduler: true, os: fos, name: "siem-a"})
	fpA := caFingerprint(t, a.ownCA())
	a.settingsShared()
	s := a.r.sharedContent.tls
	eventually(t, "A publishes its certificate authority", func() bool {
		b, ok := s.tls.Get()
		return ok && clustertls.SameFingerprint(b.CASHA256, fpA)
	})
	ca, key, err := s.tls.Store().Load()
	if err != nil || key == nil {
		t.Fatal(err)
	}
	// The tls folder of an export --to-files.
	exp := filepath.Join(t.TempDir(), "tls")
	if err := os.MkdirAll(exp, 0o700); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(exp, "ca.key")
	writeKeyPEM(t, keyFile, key)
	if err := os.WriteFile(filepath.Join(exp, tlsauto.CAFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}

	// What reset-key leaves: the certificate authority with no key.
	ctx := context.Background()
	if _, err := s.tls.Doc().Mutate(ctx, "admin", func(b *clustertls.Body) error { b.CAKey = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	out, err := a.clusterCmd("tls")
	if err != nil || !strings.Contains(out, "lost with the cluster key") {
		t.Fatalf("cluster tls: %v\n%s", err, out)
	}

	// Another key: refused, and never printed.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrong := filepath.Join(t.TempDir(), "ca.key")
	writeKeyPEM(t, wrong, other)
	out, err = a.clusterCmd("tls", "import", wrong, "-yes")
	if err == nil || !strings.Contains(err.Error(), "does not belong") || strings.Contains(out, "PRIVATE KEY") {
		t.Fatalf("wrong key: %v\n%s", err, out)
	}
	// The right key with another certificate made from it: another
	// fingerprint, refused.
	tmpl := *ca
	tmpl.SerialNumber = big.NewInt(42)
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	twin := filepath.Join(t.TempDir(), "twin.pem")
	if err := os.WriteFile(twin, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := a.clusterCmd("tls", "import", "-cert", twin, keyFile, "-yes"); err == nil || !strings.Contains(err.Error(), "is not the cluster's") {
		t.Fatalf("another fingerprint: %v\n%s", err, out)
	}
	// A link is not read.
	link := filepath.Join(t.TempDir(), "link.key")
	if os.Symlink(keyFile, link) == nil {
		if out, err := a.clusterCmd("tls", "import", link, "-yes"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("link: %v\n%s", err, out)
		}
	}
	if b, _ := s.tls.Get(); !b.KeyLost() {
		t.Fatal("a refused import changed the document")
	}

	out, err = a.clusterCmd("tls", "import", keyFile, "-yes")
	if err != nil || !strings.Contains(out, "holds its certificate authority's key again") || strings.Contains(out, "PRIVATE KEY") {
		t.Fatalf("import: %v\n%s", err, out)
	}
	eventually(t, "A reads the key back", func() bool {
		b, ok := s.tls.Get()
		return ok && !b.KeyLost()
	})
	if _, k, err := s.tls.Store().Load(); err != nil || k == nil {
		t.Fatalf("the key does not open: %v", err)
	}
	out, err = a.clusterCmd("tls", "import", keyFile, "-yes")
	if err != nil || !strings.Contains(out, "already holds") {
		t.Fatalf("again: %v\n%s", err, out)
	}

	// What remove and leave print about the certificate authority.
	c, err := loadConfig(filepath.Join(a.dir, "signalith.yaml"), a.r.log)
	if err != nil {
		t.Fatal(err)
	}
	var note strings.Builder
	x := &clusterCLI{c: c, tls: s, out: &note}
	x.leafNote()
	x.caKeptNote("siem-z")
	leaf, err := tlsauto.LeafExpiry(filepath.Join(a.dir, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	if got := note.String(); !strings.Contains(got, "works until "+leaf.Format(time.DateOnly)) ||
		!strings.Contains(got, "siem-z may still hold the cluster's HTTPS certificate authority key ("+fpA) || !strings.Contains(got, "rotate-ca prepare") {
		t.Errorf("notes:\n%s", got)
	}
}

func TestReadPlainFile(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, maxKeyFile+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPlainFile(big); err == nil {
		t.Error("a file over the cap was read")
	}
	if _, err := readPlainFile(dir); err == nil {
		t.Error("a folder was read")
	}
	ok := filepath.Join(dir, "ok")
	if err := os.WriteFile(ok, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := readPlainFile(ok); err != nil || string(b) != "x" {
		t.Errorf("plain file: %q %v", b, err)
	}
}
