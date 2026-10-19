// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"bytes"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ospki"
)

func TestCRLFacts(t *testing.T) {
	dir := t.TempDir()
	ca, err := ospki.NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	other, err := ospki.NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ospki.MakeCRL(ca, []*big.Int{big.NewInt(7), big.NewInt(9)}, big.NewInt(1), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	crlPath := write("revoked.crl", crl)
	junk := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})
	bundle := write("bundle.pem", append(append(junk, other.CertPEM()...), ca.CertPEM()...))
	wrong := write("other.pem", other.CertPEM())
	empty := write("empty.pem", ca.CertPEM())

	facts := func(caFile, crlFile string) *CRLFacts {
		t.Helper()
		c := loadConfig(t, "opensearch:\n  url: https://127.0.0.1:9200\n  ca_file: "+caFile+"\n  crl_file: "+crlFile+"\n")
		f, denied := crlFacts(Host{Config: c})
		if denied {
			t.Fatalf("denied reading %s", crlFile)
		}
		return f
	}
	// The CA that signed it is found among others in the bundle.
	if f := facts(bundle, crlPath); f.Err != "" || f.Revoked != 2 || !f.NextUpdate.Equal(ca.Cert.NotAfter.UTC().Truncate(time.Second)) {
		t.Errorf("good = %+v", f)
	}
	if f := facts(wrong, crlPath); f.Err == "" || f.Revoked != 0 {
		t.Errorf("signed by another CA = %+v", f)
	}
	// The CA file changed after the configuration was read.
	c := loadConfig(t, "opensearch:\n  url: https://127.0.0.1:9200\n  ca_file: "+empty+"\n  crl_file: "+crlPath+"\n")
	write("empty.pem", []byte("no certificates"))
	if f, _ := crlFacts(Host{Config: c}); !strings.Contains(f.Err, "holds no certificate authority") {
		t.Errorf("no CA = %+v", f)
	}
	if f := facts(bundle, filepath.Join(dir, "gone.crl")); !f.Missing {
		t.Errorf("missing = %+v", f)
	}
	if f := facts(bundle, dir); f.Err == "" || f.Missing {
		t.Errorf("a folder = %+v", f)
	}
	if f, denied := crlFacts(Host{Config: loadConfig(t, "")}); f != nil || denied {
		t.Errorf("no CRL set = %+v %v", f, denied)
	}
}

func TestArchiveFacts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "archive")
	c := loadConfig(t, "retention:\n  archive_dir: "+dir+"\n")
	h := Host{Config: c, Docker: true}
	// No folder and no policy: nothing to say.
	if a, denied := archiveFacts(h, false); denied || a.Count != 0 || a.Perm != nil || a.Dir != dir {
		t.Errorf("no folder = %+v %v", a, denied)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if a, _ := archiveFacts(h, false); a.Count != 0 || a.Perm != nil {
		t.Errorf("empty folder, no policy = %+v", a)
	}
	files := map[string][]byte{
		"2026-01-01.ndjson.gz":     []byte("plain gzip"),
		"sub/2026-01-02.ndjson.gz": append([]byte("SGLARC1\n"), bytes.Repeat([]byte{0}, 32)...),
		"notes.txt":                []byte("not an archive"),
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a, denied := archiveFacts(h, true)
	if denied || a.Count != 2 || a.Plain != 1 || a.Bytes != int64(len(files["2026-01-01.ndjson.gz"])+len(files["sub/2026-01-02.ndjson.gz"])) ||
		!a.Policies || !a.Encrypting || (a.Perm == nil && goosForTest() != "windows") {
		t.Errorf("archives = %+v", a)
	}
	if archiveEncrypted(filepath.Join(dir, "gone.ndjson.gz")) {
		t.Error("a missing file is encrypted")
	}
}
