package main

import (
	"bytes"
	"compress/gzip"
	"context"
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
	for _, x := range []retention.Manifest{plain, m} {
		if err := read(a, x); err != nil {
			t.Errorf("%s: %v", x.ID, err)
		}
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
	if p := write(b, "signalith-endpoint-2026.07.03"); p.Encryption != "" {
		t.Errorf("encryption off: %q", p.Encryption)
	}
	if err := read(b, m); err != nil {
		t.Errorf("encryption off, reading an encrypted archive: %v", err)
	}
}
