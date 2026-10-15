package clusterarchive

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// The retention history exported is the history file imported: its last
// run and its actions, newest first.
func TestHistoryExportIsTheInverseOfImport(t *testing.T) {
	cl := newClient(t)
	dir := t.TempDir()
	histFile := filepath.Join(dir, "lookups", "retention_history.json")
	at := time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC)
	run := retention.Run{Started: at, Finished: at, Trigger: "schedule", Deleted: 2}
	acts := []retention.Action{
		{Time: at, Action: retention.ActionDelete, Category: "authentication", Index: "signalith-authentication-2026.06.01", Reason: "Older than 90 days", Server: "a"},
		{Time: at.Add(-time.Hour), Action: retention.ActionArchive, Category: "authentication", Index: "signalith-authentication-2026.06.02", Reason: "Older than 90 days", Server: "a"},
	}
	hist, _ := json.Marshal(map[string]any{"last_run": run, "actions": acts})
	if err := os.MkdirAll(filepath.Dir(histFile), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(histFile, hist, 0o666); err != nil {
		t.Fatal(err)
	}
	im := Importers(ImportOptions{Client: cl, Prefix: prefix, HistoryFile: histFile, Archive: &retention.Archive{}, Server: "a", NodeID: "na"})[0]
	if err := im.Run(context.Background(), "signalith"); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	ex := HistoryExporter(func() (Client, string) { return prefixAsAll{cl}, prefix }, histFile)
	if ex.Name != shared.ImportRetentionHistory {
		t.Fatalf("exporter %s", ex.Name)
	}
	files, err := ex.Run(context.Background(), shared.ExportTarget{Under: func(p string) string {
		rel, _ := filepath.Rel(dir, p)
		return filepath.Join(root, rel)
	}})
	if err != nil || len(files) != 1 || files[0].Dest != histFile {
		t.Fatalf("files %+v, %v", files, err)
	}
	gotRun, gotActs, err := retention.ReadHistoryFile(files[0].Path)
	if err != nil || gotRun == nil || gotRun.Deleted != 2 || !gotRun.Started.Equal(at) {
		t.Fatalf("last run %+v, %v", gotRun, err)
	}
	if len(gotActs) != len(acts) {
		t.Fatalf("actions %+v", gotActs)
	}
	for i := range acts {
		if gotActs[i].Index != acts[i].Index || gotActs[i].Action != acts[i].Action || !gotActs[i].Time.Equal(acts[i].Time) || gotActs[i].Server != "a" {
			t.Errorf("action %d: %+v, want %+v", i, gotActs[i], acts[i])
		}
	}

	// Nothing recorded: nothing written.
	empty := HistoryExporter(func() (Client, string) { return prefixAsAll{newClient(t)}, prefix }, histFile)
	if files, err := empty.Run(context.Background(), shared.ExportTarget{Under: func(p string) string { return filepath.Join(t.TempDir(), "x") }}); err != nil || len(files) != 0 {
		t.Errorf("an empty history wrote %+v, %v", files, err)
	}
}
