package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/retention"
)

// writeArchivedDay archives one day of two endpoint events into dir and
// returns its manifest.
func writeArchivedDay(t *testing.T, dir string) retention.Manifest {
	t.Helper()
	index := "signalith-endpoint-2026.07.01"
	mem := retention.NewMemory()
	mem.AddIndex(index, 2, retention.Doc{ID: "a", Source: []byte(`{"user":"alice"}`)}, retention.Doc{ID: "b", Source: []byte(`{"user":"bob"}`)})
	arch := &retention.Archive{Dir: dir}
	m, err := arch.Write(context.Background(), mem, retention.Source{Index: index, Category: "endpoint", Day: "2026-07-01"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	return *m
}

func TestArchiveCommands(t *testing.T) {
	path := sampleConfig(t, "http://127.0.0.1:1")
	dir := filepath.Join(t.TempDir(), "archive")
	m := writeArchivedDay(t, dir)

	out, err := capture(t, func() error { return cmdArchive([]string{"list", "-c", path, "-dir", dir}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Archive folder: " + dir, "DAY", "2026-07-01", m.ID, "1 archived days, "} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}

	out, err = capture(t, func() error { return cmdArchive([]string{"verify", "-c", path, "-dir", dir, m.ID}) })
	if err != nil || !strings.Contains(out, m.File+": OK, 2 events, sha256 "+m.SHA256) {
		t.Errorf("verify: %v\n%s", err, out)
	}
	// By its file path, with the folder taken from it.
	out, err = capture(t, func() error { return cmdArchive([]string{"verify", "-c", path, filepath.Join(dir, m.File)}) })
	if err != nil || !strings.Contains(out, ": OK, 2 events") {
		t.Errorf("verify by path: %v\n%s", err, out)
	}

	out, err = capture(t, func() error { return cmdArchive([]string{"decrypt", "-c", path, "-dir", dir, m.ID}) })
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(strings.NewReader(out))
	if err != nil {
		t.Fatalf("decrypt does not write gzip: %v", err)
	}
	plain, _ := io.ReadAll(zr)
	if !bytes.Contains(plain, []byte("alice")) || !bytes.Contains(plain, []byte("bob")) {
		t.Errorf("decrypted:\n%s", plain)
	}

	if _, err := capture(t, func() error { return cmdArchive([]string{"verify", "-c", path, "-dir", dir, m.ID, "no-such-id"}) }); err == nil ||
		!strings.Contains(err.Error(), "1 of 2 failed") {
		t.Errorf("verify of a missing id: %v", err)
	}
	if _, err := capture(t, func() error { return cmdArchive([]string{"verify", "-c", path, "-dir", dir}) }); err == nil || !strings.Contains(err.Error(), "name at least one") {
		t.Errorf("verify of nothing: %v", err)
	}
}

func TestArchiveListEmptyAndMissing(t *testing.T) {
	path := sampleConfig(t, "http://127.0.0.1:1")
	out, err := capture(t, func() error { return cmdArchive([]string{"list", "-c", path, "-dir", t.TempDir()}) })
	if err != nil || !strings.Contains(out, "No archived days.") {
		t.Errorf("empty folder: %v\n%s", err, out)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	out, err = capture(t, func() error { return cmdArchive([]string{"list", "-c", path, "-dir", missing}) })
	if err != nil || !strings.Contains(out, "That folder does not exist yet.") {
		t.Errorf("missing folder: %v\n%s", err, out)
	}
}

func TestArchiveCommandErrors(t *testing.T) {
	if err := cmdArchive(nil); err == nil || !strings.Contains(err.Error(), "signalith archive list") {
		t.Errorf("no command: %v", err)
	}
	path := sampleConfig(t, "http://127.0.0.1:1")
	if err := cmdArchive([]string{"bogus", "-c", path}); err == nil || !strings.Contains(err.Error(), `unknown archive command "bogus"`) {
		t.Errorf("bogus: %v", err)
	}
	if err := cmdArchive([]string{"list", "-c", filepath.Join(t.TempDir(), "missing.yaml")}); err == nil {
		t.Error("list with no config file")
	}
	if err := cmdArchive([]string{"restore", "-c", path, "-keep-days", "0", "x"}); err == nil || !strings.Contains(err.Error(), "-keep-days must be between") {
		t.Errorf("-keep-days 0: %v", err)
	}
	if err := cmdArchive([]string{"restore", "-c", path, "x"}); err == nil {
		t.Error("restore with no OpenSearch")
	}
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KB", 1536: "1.5 KB", 5 << 20: "5.0 MB", 3 << 30: "3.0 GB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
