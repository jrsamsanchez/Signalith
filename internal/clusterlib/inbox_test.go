package clusterlib

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
)

// runImporter runs the importer name of s's folders as the runtime does.
func runImporter(t *testing.T, s *server, name string) {
	t.Helper()
	for _, im := range Importers(s.docs, s.files()) {
		if im.Name != name {
			continue
		}
		if h, err := im.Source(); err != nil || h == "" {
			t.Fatalf("%s: nothing to import (%q, %v)", name, h, err)
		}
		if err := im.Run(ctx, "signalith"); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("no importer %s", name)
}

func TestImportIsIdempotent(t *testing.T) {
	o := newOS(t)
	a := newServer(t, o, "siem-a", nil)
	id, on := builtinID(t)
	writeFile(t, filepath.Join(a.detDir, "my-rule.yaml"), encodeDet(t, custom("my-rule", "Mine")))
	writeFile(t, filepath.Join(a.detDir, "bad.yaml"), []byte("id: bad\nnot_a_field: 1\n"))
	writeFile(t, filepath.Join(a.detDir, detect.StateDir, id+".yaml"), []byte("enabled: "+map[bool]string{true: "false", false: "true"}[on]+"\n"))
	writeFile(t, filepath.Join(a.dbDir, "ops.yaml"), encodeBoard(t, board("ops", "Ops")))
	// An item made before the import is left as it is: an import that
	// stopped half way goes on without changing what it wrote.
	if err := a.lib.PutIf(ctx, "alice", custom("my-rule", "Made on the page"), ""); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		runImporter(t, a, "detections")
		runImporter(t, a, "dashboards")
	}
	if d, _ := a.lib.Get("my-rule"); d.Title != "Made on the page" {
		t.Fatalf("the import wrote over %q", d.Title)
	}
	if d, _ := a.lib.Get(id); d.Enabled == on {
		t.Fatal("the state file was not imported")
	}
	if _, err := a.lib.Get("bad"); err == nil {
		t.Fatal("a file that is not valid was imported")
	}
	if !a.boards.Exists("ops") {
		t.Fatal("the dashboard was not imported")
	}
	if n := len(a.docs.Detections().List()); n != 2 {
		t.Fatalf("%d detections shared", n)
	}
}

func TestInboxPushesChangedFilesOnce(t *testing.T) {
	_, a, b := pair(t)
	// B had a stale copy of a rule when it joined: a starting point,
	// not a change.
	writeFile(t, filepath.Join(b.detDir, "my-rule.yaml"), encodeDet(t, custom("my-rule", "Stale on B")))
	if err := a.lib.PutIf(ctx, "alice", custom("my-rule", "Shared"), ""); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	inB := b.inbox(false)
	if err := inB.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	// The stale file was not pushed; the shared rule was written back.
	if d, _ := a.lib.Get("my-rule"); d.Title != "Shared" {
		t.Fatalf("a stale file reverted the shared rule: %q", d.Title)
	}
	data, _ := os.ReadFile(filepath.Join(b.detDir, "my-rule.yaml"))
	if !strings.Contains(string(data), "Shared") {
		t.Fatalf("B's folder was not brought in step:\n%s", data)
	}
	// A git pull on B changes the file: it is pushed, once.
	writeFile(t, filepath.Join(b.detDir, "my-rule.yaml"), encodeDet(t, custom("my-rule", "From git")))
	writeFile(t, filepath.Join(b.dbDir, "ops.yaml"), encodeBoard(t, board("ops", "Ops")))
	if err := inB.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	a.cycle()
	d, _ := a.lib.Get("my-rule")
	if d.Title != "From git" {
		t.Fatalf("the changed file was not pushed: %q", d.Title)
	}
	if by, _, _ := a.lib.Changed("my-rule"); by != "file on siem-b" {
		t.Fatalf("changed by %q", by)
	}
	if !a.boards.Exists("ops") {
		t.Fatal("the new dashboard file was not pushed")
	}
	etag := a.lib.ETag("my-rule")
	if err := inB.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	a.cycle()
	if a.lib.ETag("my-rule") != etag {
		t.Fatal("an unchanged file was pushed again")
	}
	// A change on A is written back into B's folder, and not pushed
	// again from there.
	if err := a.lib.PutIf(ctx, "alice", custom("my-rule", "Edited on A"), ""); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if err := inB.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(b.detDir, "my-rule.yaml"))
	if !strings.Contains(string(data), "Edited on A") {
		t.Fatalf("A's change was not written back:\n%s", data)
	}
	if by, _, _ := b.lib.Changed("my-rule"); by != "alice" {
		t.Fatalf("the write-back was pushed again (changed by %q)", by)
	}
	// A rule deleted on A disappears from B's folder.
	if err := a.lib.DeleteIf(ctx, "alice", "my-rule", ""); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if err := inB.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.detDir, "my-rule.yaml")); !os.IsNotExist(err) {
		t.Fatalf("the deleted rule's file is still there: %v", err)
	}
}

func TestInboxStateFilesAndMirror(t *testing.T) {
	_, a, b := pair(t)
	id, on := builtinID(t)
	in := a.inbox(false)
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	// Turning a shipped rule on or off on B writes its state file into
	// A's folder.
	if err := b.lib.SetEnabledBy(ctx, "bob", []string{id}, !on); err != nil {
		t.Fatal(err)
	}
	a.cycle()
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(a.detDir, detect.StateDir, id+".yaml")
	if _, err := os.Stat(stateFile); err != nil {
		t.Fatalf("no state file: %v", err)
	}
	// Removing a file in inbox mode removes nothing shared: the file
	// comes back.
	writeFile(t, filepath.Join(a.dbDir, "ops.yaml"), encodeBoard(t, board("ops", "Ops")))
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(a.dbDir, "ops.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if !a.boards.Exists("ops") {
		t.Fatal("inbox mode removed a shared dashboard")
	}
	if _, err := os.Stat(filepath.Join(a.dbDir, "ops.yaml")); err != nil {
		t.Fatalf("the dashboard's file was not written back: %v", err)
	}
	// With mirror, removing it removes the shared item.
	mirror := a.inbox(true)
	if err := mirror.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(a.dbDir, "ops.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(stateFile); err != nil {
		t.Fatal(err)
	}
	if err := mirror.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if b.boards.Exists("ops") {
		t.Fatal("mirror mode kept a dashboard whose file was removed")
	}
	if d, _ := b.lib.Get(id); d.Enabled != on {
		t.Fatal("mirror mode kept the state whose file was removed")
	}
}

func TestInboxIgnoresInvalidFilesUntilChanged(t *testing.T) {
	_, a, _ := pair(t)
	in := a.inbox(false)
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(a.dbDir, "broken.yaml")
	writeFile(t, p, []byte("id: broken\ntitle: [\n"))
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if a.boards.Exists("broken") {
		t.Fatal("a broken file was shared")
	}
	writeFile(t, p, encodeBoard(t, &dashboards.Dashboard{ID: "broken", Title: "Fixed", Panels: board("x", "y").Panels}))
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if !a.boards.Exists("broken") {
		t.Fatal("the fixed file was not shared")
	}
}
