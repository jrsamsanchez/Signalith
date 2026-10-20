// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package oslocal

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ospki"
)

type zipEntry struct {
	name string
	mode fs.FileMode
	body string
}

// orderedZip writes the entries in the order given.
func orderedZip(t *testing.T, entries ...zipEntry) string {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Store}
		h.SetMode(e.mode)
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(f, e.body)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "os.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExtractKinds(t *testing.T) {
	z := orderedZip(t,
		zipEntry{name: "opensearch-3.9.0/logs/", mode: fs.ModeDir | 0o755},
		zipEntry{name: "opensearch-3.9.0/bin/run", mode: 0o755, body: "run"},
	)
	dest := filepath.Join(t.TempDir(), "3.9.0")
	if err := Extract(z, dest); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dest, "logs")); err != nil || !fi.IsDir() {
		t.Errorf("logs folder = %v %v", fi, err)
	}

	for name, z := range map[string]string{
		"link": orderedZip(t, zipEntry{name: "opensearch-3.9.0/bin/link", mode: fs.ModeSymlink | 0o777, body: "/etc/passwd"}),
		"twice": orderedZip(t,
			zipEntry{name: "opensearch-3.9.0/a", mode: 0o644, body: "1"},
			zipEntry{name: "opensearch-3.9.0/a", mode: 0o644, body: "2"}),
		"file then folder": orderedZip(t,
			zipEntry{name: "opensearch-3.9.0/a", mode: 0o644, body: "1"},
			zipEntry{name: "opensearch-3.9.0/a/b", mode: 0o644, body: "2"}),
		"file then folder entry": orderedZip(t,
			zipEntry{name: "opensearch-3.9.0/a", mode: 0o644, body: "1"},
			zipEntry{name: "opensearch-3.9.0/a/", mode: fs.ModeDir | 0o755}),
	} {
		parent := t.TempDir()
		dest := filepath.Join(parent, "3.9.0")
		err := Extract(z, dest)
		if err == nil {
			t.Errorf("%s: extracted", name)
		}
		if name == "link" && !strings.Contains(err.Error(), "not a file or a folder") {
			t.Errorf("link: %v", err)
		}
		if entries, _ := os.ReadDir(parent); len(entries) != 0 {
			t.Errorf("%s: left %d entries", name, len(entries))
		}
	}

	notZip := filepath.Join(t.TempDir(), "x.zip")
	os.WriteFile(notZip, []byte("not a zip"), 0o600)
	if err := Extract(notZip, filepath.Join(t.TempDir(), "d")); err == nil {
		t.Error("extracted a file that is not a zip")
	}
}

func TestLoadStateRefuses(t *testing.T) {
	l := testLayout(t)
	os.MkdirAll(l.Data, 0o700)
	for name, body := range map[string]string{
		"not JSON":    "nope",
		"no port":     `{"version":"3.9.0"}`,
		"big port":    `{"version":"3.9.0","port":70000}`,
		"bad version": `{"version":"latest","port":9200}`,
	} {
		os.WriteFile(l.stateFile(), []byte(body), 0o600)
		if st, err := LoadState(l); err == nil || st != nil {
			t.Errorf("%s: %+v %v", name, st, err)
		}
	}
	os.Remove(l.stateFile())
	os.Mkdir(l.stateFile(), 0o700)
	if _, err := LoadState(l); err == nil {
		t.Error("a folder was read as the state")
	}
	// The data folder is a file.
	os.WriteFile(filepath.Join(l.Data, "file"), nil, 0o600)
	blocked := Layout{Data: filepath.Join(l.Data, "file", "data")}
	if err := SaveState(blocked, State{Version: "3.9.0", Port: 9200}); err == nil {
		t.Error("saved under a file")
	}
}

func TestFetchAndDownloadProblems(t *testing.T) {
	dir := t.TempDir()
	if _, err := Fetch(context.Background(), filepath.Join(dir, "missing.zip"), dir, io.Discard); err == nil {
		t.Error("fetched a missing file")
	}
	file := filepath.Join(dir, "file")
	os.WriteFile(file, []byte("x"), 0o600)
	if _, err := save(strings.NewReader("x"), filepath.Join(file, "sub"), "x"); err == nil {
		t.Error("saved under a file")
	}
	if _, err := download(context.Background(), "http://bad host/", dir, io.Discard, http.DefaultClient); err == nil {
		t.Error("a bad address was fetched")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	var out bytes.Buffer
	if _, err := download(context.Background(), srv.URL, dir, &out, srv.Client()); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("404 = %v", err)
	}
	if !strings.Contains(out.String(), "Downloading OpenSearch "+Version) {
		t.Errorf("out = %q", out.String())
	}
	url := srv.URL
	srv.Close()
	if _, err := download(context.Background(), url, dir, io.Discard, srv.Client()); err == nil || !strings.Contains(err.Error(), "OPENSEARCHZIP") {
		t.Errorf("unreachable = %v", err)
	}
}

func TestWriteConfigProblems(t *testing.T) {
	l := testLayout(t)
	home := l.VersionHome("3.9.0")
	write := func(name, body string) {
		p := filepath.Join(home, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	if err := WriteConfig(l, home, 9200, 1024); err == nil || !strings.Contains(err.Error(), "log4j2") {
		t.Errorf("no log4j2 = %v", err)
	}
	write("config/log4j2.properties", "status = error\n")
	if err := WriteConfig(l, home, 9200, 1024); err == nil || !strings.Contains(err.Error(), "jvm.options") {
		t.Errorf("no jvm.options = %v", err)
	}
	write("config/jvm.options", releaseJVM)
	if err := WriteConfig(l, home, 9200, 1024); err == nil || !strings.Contains(err.Error(), "opensearch-security") {
		t.Errorf("no security folder = %v", err)
	}
	write("config/opensearch-security/roles.yml", "_meta: {}\n")
	if err := WriteConfig(l, home, 9200, 1024); err != nil {
		t.Errorf("complete = %v", err)
	}

	blocked := testLayout(t)
	os.MkdirAll(filepath.Dir(blocked.Data), 0o700)
	os.WriteFile(blocked.Data, []byte("x"), 0o600)
	if err := WriteConfig(blocked, home, 9200, 1024); err == nil {
		t.Error("wrote config under a file")
	}
}

func TestMakeCertsBlocked(t *testing.T) {
	bits := ospki.KeyBits
	ospki.KeyBits = 2048
	t.Cleanup(func() { ospki.KeyBits = bits })
	l := testLayout(t)
	os.MkdirAll(filepath.Dir(l.Client), 0o700)
	os.WriteFile(l.Client, []byte("x"), 0o600)
	if err := MakeCerts(l, time.Now()); err == nil {
		t.Error("made certificates with the client folder a file")
	}
}
