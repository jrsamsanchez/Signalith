package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// sampleConfig writes a signalith.yaml whose folders are in a temporary
// folder and which uses OpenSearch at url.
func sampleConfig(t *testing.T, url string) string {
	t.Helper()
	noServiceSettings(t)
	for _, k := range []string{"SIGNALITH_OPENSEARCH_URL", "SIGNALITH_LOOKUPS_DIR", "SIGNALITH_DETECTIONS_DIR", "SIGNALITH_SETTINGS_FILE",
		"SIGNALITH_STATE_DIR", "SIGNALITH_MASTER_KEY", "SIGNALITH_MASTER_KEY_FILE"} {
		t.Setenv(k, "")
	}
	dir := t.TempDir()
	h, err := config.HashPassword("s3cret-pass")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "signalith.yaml")
	body := "opensearch:\n  url: " + url + "\nauth:\n  admin_password_hash: " + h + "\nlookups:\n  dir: " + filepath.ToSlash(filepath.Join(dir, "lookups")) +
		"\ndetections:\n  dir: " + filepath.ToSlash(filepath.Join(dir, "detections")) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSampleDataCommandUsage(t *testing.T) {
	if err := cmdSampleData(nil); err == nil || !strings.Contains(err.Error(), "signalith sample-data load") {
		t.Errorf("no command: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	noServiceSettings(t)
	if _, err := capture(t, func() error { return cmdSampleData([]string{"status", "-c", missing}) }); err == nil {
		t.Error("status with no config file")
	}
}

func TestSampleDataCommandWithoutOpenSearch(t *testing.T) {
	path := sampleConfig(t, "http://127.0.0.1:1")
	for _, sub := range []string{"status", "load", "remove"} {
		_, err := capture(t, func() error { return cmdSampleData([]string{sub, "-c", path}) })
		if err == nil || !strings.Contains(err.Error(), "OpenSearch is not reachable") {
			t.Errorf("%s: %v", sub, err)
		}
	}
}

func TestSampleDataCommandNothingLoaded(t *testing.T) {
	fos := newFakeOpenSearch(t)
	path := sampleConfig(t, fos.URL)
	out, err := capture(t, func() error { return cmdSampleData([]string{"status", "-c", path}) })
	if err != nil || !strings.Contains(out, "No sample data is loaded.") {
		t.Errorf("status: %v\n%s", err, out)
	}
	out, err = capture(t, func() error { return cmdSampleData([]string{"remove", "-c", path}) })
	if err != nil || !strings.Contains(out, "There is no sample data to remove.") {
		t.Errorf("remove: %v\n%s", err, out)
	}
	// The loader put the index template in place first.
	found := false
	for _, n := range fos.Templates() {
		if strings.Contains(n, "signalith") {
			found = true
		}
	}
	if !found {
		t.Errorf("no index template: %v", fos.Templates())
	}
	if _, err := capture(t, func() error { return cmdSampleData([]string{"load", "-c", path, "-size", "huge"}) }); err == nil || !strings.Contains(err.Error(), "-size must be") {
		t.Errorf("load -size huge: %v", err)
	}
	if _, err := capture(t, func() error { return cmdSampleData([]string{"bogus", "-c", path}) }); err == nil || !strings.Contains(err.Error(), `unknown sample-data command "bogus"`) {
		t.Errorf("bogus: %v", err)
	}
}

func TestSampleDataCommandLoadStatusRemove(t *testing.T) {
	fos := newFakeOpenSearch(t)
	path := sampleConfig(t, fos.URL)
	out, err := capture(t, func() error { return cmdSampleData([]string{"load", "-c", path, "-size", "small"}) })
	if err != nil {
		t.Fatalf("load: %v\n%s", err, out)
	}
	for _, want := range []string{"Loading the small sample data.", "  Writing events (", "  Running detections (", "\nDone. Loaded ", "sample-data remove"} {
		if !strings.Contains(out, want) {
			t.Errorf("load lacks %q:\n%s", want, out)
		}
	}
	out, err = capture(t, func() error { return cmdSampleData([]string{"status", "-c", path}) })
	for _, want := range []string{"Sample data is loaded (small set, loaded ", "  events:   ", "  threat intel indicators:", "  stories:\n    - "} {
		if err != nil || !strings.Contains(out, want) {
			t.Errorf("status lacks %q (%v):\n%s", want, err, out)
		}
	}
	if _, err := capture(t, func() error { return cmdSampleData([]string{"load", "-c", path, "-size", "small"}) }); err == nil || !strings.Contains(err.Error(), "already loaded") {
		t.Errorf("load again: %v", err)
	}
	// The fake OpenSearch counts every document whatever the query, so the
	// removal's last check may find events left; it has removed the rest.
	out, err = capture(t, func() error { return cmdSampleData([]string{"remove", "-c", path}) })
	if !strings.Contains(out, "Removing the sample data.\n") || !strings.Contains(out, "  Removing threat intel (") {
		t.Errorf("remove: %v\n%s", err, out)
	}
	if err == nil && !strings.Contains(out, "All of the sample data is gone") {
		t.Errorf("remove: %s", out)
	}
}
