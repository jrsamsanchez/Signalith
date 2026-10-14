package main

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/config"
)

// backupInstall makes an install in a new folder: signalith.yaml with
// its folders next to it, and a state folder of its own, as the systemd
// unit and Docker give one. It returns the config file.
func backupInstall(t *testing.T, files map[string]string) string {
	t.Helper()
	top := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(top, "state"))
	for _, v := range []string{"SIGNALITH_LOOKUPS_DIR", "SIGNALITH_DETECTIONS_DIR", "SIGNALITH_DASHBOARDS_DIR", "SIGNALITH_ARCHIVE_DIR", "SIGNALITH_SETTINGS_FILE"} {
		t.Setenv(v, "")
	}
	cfg := filepath.Join(top, "etc", "signalith.yaml")
	files["etc/signalith.yaml"] = "lookups:\n  dir: ../data/lookups\ndetections:\n  dir: ../data/detections\ndashboards:\n  dir: ../data/dashboards\n"
	for name, body := range files {
		p := filepath.Join(top, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return cfg
}

func loadForBackup(t *testing.T, path string) *config.Config {
	t.Helper()
	c, err := config.LoadUnchecked(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func zipEntries(t *testing.T, name string) map[string]string {
	t.Helper()
	zr, err := zip.OpenReader(name)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	out := map[string]string{}
	for _, f := range zr.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r)
		r.Close()
		out[f.Name] = string(b)
	}
	return out
}

func TestBackupAndRestore(t *testing.T) {
	src := backupInstall(t, map[string]string{
		"state/keys/master.key":      "the key",
		"state/keys/cluster-abc.key": "sealed cluster key",
		"state/tls/ca.pem":           "ca",
		"state/node.id":              `{"node_id":"n_1","name":"siem-a"}`,
		"state/cluster/lock":         "",
		"data/lookups/users.json":    "[]",
		"data/lookups/settings.yaml": "retention:\n  days: 30\n",
		"data/lookups/assets.csv":    "host\nweb-01\n",
		"data/detections/mine.yml":   "id: mine\n",
		"data/dashboards/soc.json":   "{}",
		"data/archive/day.ndjson.gz": "events",
	})
	c := loadForBackup(t, src)
	zipFile := filepath.Join(t.TempDir(), "b.zip")
	m, err := writeBackup(zipFile, c, false, false)
	if err != nil {
		t.Fatal(err)
	}
	got := zipEntries(t, zipFile)
	for _, want := range []string{"config/signalith.yaml", "state/keys/master.key", "state/keys/cluster-abc.key", "state/tls/ca.pem", "state/node.id",
		"settings/settings.yaml", "users/users.json", "lookups/assets.csv", "detections/mine.yml", "dashboards/soc.json", manifestName} {
		if _, ok := got[want]; !ok {
			t.Errorf("backup has no %s; it has %v", want, keys(got))
		}
	}
	for _, not := range []string{"state/cluster/lock", "state/signalith-backup.zip", "lookups/settings.yaml", "lookups/users.json", "archive/day.ndjson.gz"} {
		if _, ok := got[not]; ok {
			t.Errorf("backup has %s", not)
		}
	}
	if m.Files != len(got)-1 {
		t.Errorf("manifest counts %d files, the zip has %d", m.Files, len(got)-1)
	}
	// It never overwrites a file.
	if _, err := writeBackup(zipFile, c, false, false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("second backup to the same file: %v", err)
	}

	// Restore on another install, laid out the same way, replaces its
	// own files with the backup's and sets the others aside.
	dst := backupInstall(t, map[string]string{
		"state/keys/master.key":      "a new key",
		"state/keys/cluster-new.key": "sealed with the new key",
		"data/lookups/users.json":    `[{"name":"new"}]`,
		"data/lookups/extra.csv":     "set aside",
		"data/archive/new-day.gz":    "kept",
	})
	dc := loadForBackup(t, dst)
	if err := restoreBackup(zipFile, dc, true, os.Stdin, io.Discard); err != nil {
		t.Fatal(err)
	}
	top := filepath.Dir(filepath.Dir(dst))
	for name, want := range map[string]string{
		"state/keys/master.key":      "the key",
		"state/node.id":              `{"node_id":"n_1","name":"siem-a"}`,
		"data/lookups/users.json":    "[]",
		"data/lookups/settings.yaml": "retention:\n  days: 30\n",
		"data/archive/new-day.gz":    "kept",
		"data/detections/mine.yml":   "id: mine\n",
		"etc/signalith.yaml":         got["config/signalith.yaml"],
	} {
		b, err := os.ReadFile(filepath.Join(top, filepath.FromSlash(name)))
		if err != nil || string(b) != want {
			t.Errorf("%s = %q, %v; want %q", name, b, err, want)
		}
	}
	if _, err := os.Stat(filepath.Join(top, "data", "archive", "day.ndjson.gz")); err == nil {
		t.Error("restore wrote an archived day that was not backed up")
	}
	aside, _ := filepath.Glob(filepath.Join(top, "state", setAsidePrefix+"*"))
	if len(aside) != 1 {
		t.Fatalf("set aside in %v", aside)
	}
	for _, name := range []string{"state/keys/cluster-new.key", "lookups/extra.csv"} {
		if _, err := os.Stat(filepath.Join(aside[0], filepath.FromSlash(name))); err != nil {
			t.Errorf("%s was not set aside: %v", name, err)
		}
	}
	for _, name := range []string{"state/keys/cluster-new.key", "data/lookups/extra.csv"} {
		if _, err := os.Stat(filepath.Join(top, filepath.FromSlash(name))); err == nil {
			t.Errorf("%s is still in place", name)
		}
	}
	// A backup of the restored install leaves what was set aside out.
	again := filepath.Join(t.TempDir(), "again.zip")
	if _, err := writeBackup(again, dc, false, false); err != nil {
		t.Fatal(err)
	}
	for name := range zipEntries(t, again) {
		if strings.Contains(name, setAsidePrefix) {
			t.Errorf("backup holds %s", name)
		}
	}
}

func TestBackupOptions(t *testing.T) {
	src := backupInstall(t, map[string]string{
		"state/keys/master.key":      "the key",
		"state/keys/master.key.old":  "the old key",
		"data/archive/day.ndjson.gz": "events",
	})
	c := loadForBackup(t, src)
	zipFile := filepath.Join(t.TempDir(), "b.zip")
	m, err := writeBackup(zipFile, c, true, true)
	if err != nil {
		t.Fatal(err)
	}
	got := zipEntries(t, zipFile)
	if _, ok := got["archive/day.ndjson.gz"]; !ok {
		t.Errorf("-archive: no archived day in %v", keys(got))
	}
	for name := range got {
		if strings.Contains(name, "master.key") {
			t.Errorf("-no-master-key: backup has %s", name)
		}
	}
	if !m.NoMasterKey {
		t.Error("the manifest does not say the key was left out")
	}
	// Restoring it keeps the master key in place.
	dst := backupInstall(t, map[string]string{"state/keys/master.key": "this install's key"})
	if err := restoreBackup(zipFile, loadForBackup(t, dst), true, os.Stdin, io.Discard); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(dst)), "state", "keys", "master.key"))
	if err != nil || string(b) != "this install's key" {
		t.Errorf("master key after restore: %q, %v", b, err)
	}
}

func TestRestoreRefuses(t *testing.T) {
	src := backupInstall(t, map[string]string{"state/node.id": `{"node_id":"n_1"}`})
	zipFile := filepath.Join(t.TempDir(), "b.zip")
	if _, err := writeBackup(zipFile, loadForBackup(t, src), false, false); err != nil {
		t.Fatal(err)
	}

	// While a server holds the state folder.
	dst := backupInstall(t, map[string]string{})
	dc := loadForBackup(t, dst)
	l, err := cluster.OpenLocal(dc.StateDir(), cluster.LocalOptions{Name: "siem-b"})
	if err != nil {
		t.Fatal(err)
	}
	err = restoreBackup(zipFile, dc, true, os.Stdin, io.Discard)
	l.Close()
	if err == nil || !strings.Contains(err.Error(), "Stop it first") {
		t.Errorf("restore while running: %v", err)
	}
	if err := restoreBackup(zipFile, dc, true, os.Stdin, io.Discard); err != nil {
		t.Errorf("restore once stopped: %v", err)
	}

	// A zip that is not a backup, or whose names leave its folders.
	for name, entries := range map[string][]string{
		"not a backup": {"state/node.id"},
		"escapes":      {manifestName, "state/../../evil"},
	} {
		bad := filepath.Join(t.TempDir(), "bad.zip")
		f, _ := os.Create(bad)
		zw := zip.NewWriter(f)
		for _, e := range entries {
			w, _ := zw.Create(e)
			if e == manifestName {
				io.WriteString(w, `{"format":1,"roots":[{"role":"state","dir":true}]}`)
			} else {
				io.WriteString(w, "x")
			}
		}
		zw.Close()
		f.Close()
		if err := restoreBackup(bad, dc, true, os.Stdin, io.Discard); err == nil {
			t.Errorf("%s: restored", name)
		}
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
