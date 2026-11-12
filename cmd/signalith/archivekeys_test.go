// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/archivecrypt"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// TestArchiveEncryption checks that archives are encrypted with the
// master key and the cluster key, that another server of the cluster
// reads them with the cluster key alone, and that archives written
// before encryption still read.
func TestArchiveEncryption(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(dir, "state"))
	c := config.Default()
	if !c.ArchiveEncryption() {
		t.Fatal("archive encryption is off by default")
	}
	ck, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	cluster := func() *secrets.Key { return ck.SecretsKey() }
	mem := retention.NewMemory()
	write := func(a *retention.Archive, index string) retention.Manifest {
		t.Helper()
		mem.AddIndex(index, 1, retention.Doc{ID: "a", Source: []byte(`{"user":"alice"}`)}, retention.Doc{ID: "b", Source: []byte(`{"user":"bob"}`)})
		m, err := a.Write(context.Background(), mem, retention.Source{Index: index, Category: "endpoint", Day: index[len(index)-10:]}, 2)
		if err != nil {
			t.Fatal(err)
		}
		return *m
	}
	read := func(a *retention.Archive, m retention.Manifest) error {
		n := 0
		err := a.Read(m, func(retention.Doc) error { n++; return nil })
		if err == nil && n != 2 {
			t.Errorf("%s: read %d documents", m.ID, n)
		}
		return err
	}
	folder := filepath.Join(dir, "archive")

	plain := write(&retention.Archive{Dir: folder}, "signalith-endpoint-2026.07.01")
	a := &retention.Archive{Dir: folder}
	archiveCrypto(a, c, cluster)
	m := write(a, "signalith-endpoint-2026.07.02")
	if m.Encryption != archivecrypt.Scheme || strings.Count(m.KID, ",") != 1 {
		t.Errorf("manifest encryption %q kid %q", m.Encryption, m.KID)
	}
	if b, _ := os.ReadFile(filepath.Join(folder, m.File)); !strings.HasPrefix(string(b), "SGLARC1\n") || strings.Contains(string(b), "alice") {
		t.Error("the archive file is not encrypted")
	}
	if err := read(a, m); err != nil {
		t.Errorf("%s: %v", m.ID, err)
	}
	// A plain archive no key authenticates (written before encryption,
	// and before manifests had MACs) needs the override while archives
	// are encrypted (CRYPTO-01).
	if len(plain.MAC) != 0 {
		t.Fatalf("an archive written without keys has MACs %q", plain.MAC)
	}
	if err := read(a, plain); !errors.Is(err, retention.ErrUnauthenticated) {
		t.Errorf("a plain archive no key authenticates: %v", err)
	}
	over := config.Default()
	over.Retention.AllowUnauthenticatedArchives = true
	ao := &retention.Archive{Dir: folder}
	archiveCrypto(ao, over, cluster)
	if err := read(ao, plain); err != nil {
		t.Errorf("with retention.allow_unauthenticated_archives: %v", err)
	}

	// decrypt gives the plain gzip, as written before encryption.
	var out bytes.Buffer
	if err := archiveDecrypt(a, m, &out); err != nil {
		t.Fatal(err)
	}
	if zr, err := gzip.NewReader(&out); err != nil {
		t.Errorf("decrypt: %v", err)
	} else if b, _ := io.ReadAll(zr); !strings.Contains(string(b), "alice") {
		t.Errorf("decrypt: %q", b)
	}

	// Another server: its own master key, the same cluster key.
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(dir, "other"))
	other := &retention.Archive{Dir: folder}
	archiveCrypto(other, config.Default(), cluster)
	if err := read(other, m); err != nil {
		t.Errorf("another server of the cluster: %v", err)
	}
	// A server with neither key.
	stranger := &retention.Archive{Dir: folder}
	archiveCrypto(stranger, config.Default(), nil)
	if err := read(stranger, m); err == nil || !strings.Contains(err.Error(), "no key") {
		t.Errorf("a server without the keys: %v", err)
	}

	// Turned off: new archives are plain, encrypted ones still read.
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(dir, "state"))
	off := config.Default()
	no := false
	off.Retention.EncryptArchives = &no
	b := &retention.Archive{Dir: folder}
	archiveCrypto(b, off, nil)
	p := write(b, "signalith-endpoint-2026.07.03")
	if p.Encryption != "" || len(p.MAC) != 1 {
		t.Errorf("encryption off: %q, MACs %q", p.Encryption, p.MAC)
	}
	// Its manifest is authenticated, so it reads once encryption is on.
	if err := read(a, p); err != nil {
		t.Errorf("a plain archive with a MAC, encryption on: %v", err)
	}
	if err := read(b, m); err != nil {
		t.Errorf("encryption off, reading an encrypted archive: %v", err)
	}
}

// TestArchiveManifestForgery checks that an encrypted archive cannot be
// swapped for a plain one by rewriting its manifest (CRYPTO-01), and that
// encrypted archives written before manifests had MACs still read.
func TestArchiveManifestForgery(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(dir, "state"))
	ck, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	cluster := func() *secrets.Key { return ck.SecretsKey() }
	folder := filepath.Join(dir, "archive")
	a := &retention.Archive{Dir: folder}
	archiveCrypto(a, config.Default(), cluster)
	mem := retention.NewMemory()
	const index = "signalith-endpoint-2026.07.02"
	mem.AddIndex(index, 1, retention.Doc{ID: "a", Source: []byte(`{"user":"alice"}`)})
	m, err := a.Write(context.Background(), mem, retention.Source{Index: index, Category: "endpoint", Day: "2026-07-02"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.MAC) != 2 {
		t.Fatalf("MACs %q, want one for the master key and one for the cluster key", m.MAC)
	}
	// Another server of the cluster checks the cluster key's MAC.
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(dir, "other"))
	other := &retention.Archive{Dir: folder}
	archiveCrypto(other, config.Default(), cluster)
	if err := other.Verify(*m); err != nil {
		t.Errorf("another server of the cluster: %v", err)
	}
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(dir, "state"))

	// An encrypted archive whose manifest has no MAC is refused: the
	// file's encryption does not name its day, so it could be another
	// day's archive (CRYPTO-01).
	old := *m
	old.MAC = nil
	if err := a.Verify(old); !errors.Is(err, retention.ErrUnauthenticatedEncrypted) {
		t.Errorf("an encrypted archive without a MAC: %v", err)
	}
	// One written before manifests had MACs, found when this version
	// first started, reads.
	manifestFile := filepath.Join(folder, m.ID+".json")
	saved, err := os.ReadFile(manifestFile)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := json.Marshal(old); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(manifestFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recordLegacyArchives(a, config.Default()); err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(old); err != nil {
		t.Errorf("an encrypted archive from before MACs, listed at the upgrade: %v", err)
	}
	// The list is made once: a later run keeps it.
	if err := recordLegacyArchives(a, config.Default()); err != nil {
		t.Fatal(err)
	}
	// Another archive put in its place (another checksum) is refused, and
	// reads with the override.
	swapped := old
	swapped.SHA256 = strings.Repeat("0", 64)
	if err := a.Verify(swapped); !errors.Is(err, retention.ErrUnauthenticatedEncrypted) {
		t.Errorf("another archive under a listed archive's name: %v", err)
	}
	overEnc := config.Default()
	overEnc.Retention.AllowUnauthenticatedArchives = true
	aoe := &retention.Archive{Dir: folder}
	archiveCrypto(aoe, overEnc, cluster)
	if err := aoe.Verify(swapped); errors.Is(err, retention.ErrUnauthenticatedEncrypted) {
		t.Errorf("with the override: %v", err)
	}
	if err := os.WriteFile(manifestFile, saved, 0o600); err != nil {
		t.Fatal(err)
	}

	// Forge: a plain gzip of other events and a manifest that matches it.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(`{"_id":"x","_source":{"user":"mallory"}}` + "\n"))
	zw.Close()
	if err := os.WriteFile(filepath.Join(folder, m.File), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	forged := *m
	forged.Encryption, forged.KID = "", ""
	forged.SHA256, forged.Bytes, forged.Docs = hex.EncodeToString(sum[:]), int64(buf.Len()), 1
	// With the MACs kept, they no longer match: refused, even with the
	// override.
	over := config.Default()
	over.Retention.AllowUnauthenticatedArchives = true
	ao := &retention.Archive{Dir: folder}
	archiveCrypto(ao, over, cluster)
	for _, x := range []*retention.Archive{a, ao} {
		if err := x.Verify(forged); err == nil || !strings.Contains(err.Error(), "changed") {
			t.Errorf("a forged manifest with the old MACs: %v", err)
		}
	}
	// Without MACs it is refused while archives are encrypted.
	forged.MAC = nil
	if err := a.Verify(forged); !errors.Is(err, retention.ErrUnauthenticated) {
		t.Errorf("a forged plain archive without MACs: %v", err)
	}
	// The manifest file, as restore reads it, is refused the same way.
	b, _ := json.Marshal(forged)
	if err := os.WriteFile(filepath.Join(folder, m.ID+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := a.Get(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Read(got, func(retention.Doc) error { t.Error("a forged event was read"); return nil }); err == nil {
		t.Error("a forged archive read")
	}
}
