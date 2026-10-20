// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterlib

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestInboxMissingFolderRemovesNothing(t *testing.T) {
	_, a, b := pair(t)
	if err := a.lib.PutIf(ctx, "alice", custom("my-rule", "Shared"), ""); err != nil {
		t.Fatal(err)
	}
	if err := a.boards.PutIf(ctx, "alice", board("ops", "Ops"), ""); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	in := b.inbox(true)
	for range 2 {
		if err := in.Sync(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(b.detDir, "my-rule.yaml")); err != nil {
		t.Fatalf("the shared rule was not written back: %v", err)
	}
	// The folders are gone (a volume that did not mount): that is not
	// the removal of every file, even with mirror.
	if err := os.RemoveAll(b.detDir); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(b.dbDir); err != nil {
		t.Fatal(err)
	}
	if err := in.Sync(ctx); err == nil {
		t.Fatal("a missing folder was taken for an empty one")
	}
	if err := b.inbox(true).Sync(ctx); err == nil {
		t.Fatal("a missing folder was taken for an empty one after a restart")
	}
	a.cycle()
	if _, err := a.lib.Get("my-rule"); err != nil {
		t.Fatalf("a missing folder removed the shared rule: %v", err)
	}
	if !a.boards.Exists("ops") {
		t.Fatal("a missing folder removed the shared dashboard")
	}
}

func TestInboxNewFolderIsAStartingPoint(t *testing.T) {
	_, a, b := pair(t)
	if err := a.lib.PutIf(ctx, "alice", custom("my-rule", "Shared"), ""); err != nil {
		t.Fatal(err)
	}
	if err := a.lib.PutIf(ctx, "alice", custom("other-rule", "Other"), ""); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if err := b.inbox(true).Sync(ctx); err != nil {
		t.Fatal(err)
	}
	// detections.dir now names another folder, which holds a stale copy
	// of one rule and not the other.
	b.detDir = filepath.Join(t.TempDir(), "detections")
	writeFile(t, filepath.Join(b.detDir, "my-rule.yaml"), encodeDet(t, custom("my-rule", "Stale")))
	if err := b.inbox(true).Sync(ctx); err != nil {
		t.Fatal(err)
	}
	a.cycle()
	if d, err := a.lib.Get("other-rule"); err != nil || d == nil {
		t.Fatalf("a new folder removed the shared rule it did not hold: %v", err)
	}
	if d, _ := a.lib.Get("my-rule"); d == nil || d.Title != "Shared" {
		t.Fatalf("a stale file in a new folder reverted the shared rule: %+v", d)
	}
	for id, title := range map[string]string{"my-rule": "Shared", "other-rule": "Other"} {
		data, _ := os.ReadFile(filepath.Join(b.detDir, id+".yaml"))
		if !strings.Contains(string(data), title) {
			t.Fatalf("the shared rule %s was not written into the new folder:\n%s", id, data)
		}
	}
}

func TestItemNamesStayInTheFolders(t *testing.T) {
	_, a, _ := pair(t)
	on := true
	if _, err := a.docs.Detections().Create(ctx, "alice", "../../escape", &DetectionBody{State: &detect.State{Enabled: &on}}); err == nil {
		t.Fatal("a state-only detection with a name that is not an id was accepted")
	}
	if _, err := a.docs.Dashboards().Create(ctx, "alice", "../escape", &DashboardBody{}); err == nil {
		t.Fatal("a dashboard with a name that is not an id was accepted")
	}
	in := a.inbox(false)
	if p, err := in.pathOf("detections/state/../../../escape.yaml"); err == nil {
		t.Fatalf("a file outside the folder was allowed: %s", p)
	}
	if p, err := in.pathOf("detections/state/my-rule.yaml"); err != nil || p != filepath.Join(a.detDir, detect.StateDir, "my-rule.yaml") {
		t.Fatalf("pathOf: %q %v", p, err)
	}
}

// libraryOf shares rules custom rules and boards dashboards from A, and
// returns B's mirror inbox once it wrote them into B's folders.
func libraryOf(t *testing.T, rules, boards int) (a, b *server, in *Inbox) {
	t.Helper()
	_, a, b = pair(t)
	for i := range rules {
		if err := a.lib.PutIf(ctx, "alice", custom(fmt.Sprintf("rule-%d", i), "Shared"), ""); err != nil {
			t.Fatal(err)
		}
	}
	for i := range boards {
		if err := a.boards.PutIf(ctx, "alice", board(fmt.Sprintf("board-%d", i), "Ops"), ""); err != nil {
			t.Fatal(err)
		}
	}
	b.cycle()
	in = b.inbox(true)
	for range 2 {
		if err := in.Sync(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(in.Problems()) != 0 {
		t.Fatalf("problems before anything was removed: %q", in.Problems())
	}
	return a, b, in
}

// emptyFolder removes every file from dir, leaving the folder.
func emptyFolder(t *testing.T, dir string) {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
}

// counts returns how many detections and dashboards A shares.
func counts(t *testing.T, a *server) (rules, boards int) {
	t.Helper()
	a.cycle()
	return len(a.docs.Detections().List()), len(a.docs.Dashboards().List())
}

func TestMirrorRefusesToEmptyTheLibrary(t *testing.T) {
	a, b, in := libraryOf(t, 5, 1)
	// A volume made again: the folders are there, and empty.
	emptyFolder(t, b.detDir)
	emptyFolder(t, b.dbDir)
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, d := counts(t, a); r != 5 || d != 1 {
		t.Fatalf("%d detections and %d dashboards left of 5 and 1", r, d)
	}
	p := in.Problems()
	if len(p) != 1 || !strings.Contains(p[0], "1 of the 1 dashboard files and 5 of the 5 detection files") || !strings.Contains(p[0], AllowDeleteFile) {
		t.Fatalf("problems %q", p)
	}
	// The files were written back, and the next pass removes nothing.
	if _, err := os.Stat(filepath.Join(b.detDir, "rule-0.yaml")); err != nil {
		t.Fatalf("the files were not written back: %v", err)
	}
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, d := counts(t, a); r != 5 || d != 1 {
		t.Fatalf("%d detections and %d dashboards left of 5 and 1", r, d)
	}
	// The problem stays for a day.
	in.Files.Now = func() time.Time { return time.Now().Add(refusedFor + time.Hour) }
	if p := in.Problems(); len(p) != 0 {
		t.Fatalf("problems a day later: %q", p)
	}
}

// Each folder is guarded on its own: emptying the smaller one is
// refused too, however many files the other holds.
func TestMirrorRefusesToEmptyOneFolder(t *testing.T) {
	a, b, in := libraryOf(t, 30, 10)
	emptyFolder(t, b.dbDir)
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, d := counts(t, a); r != 30 || d != 10 {
		t.Fatalf("emptying the dashboards folder left %d detections and %d dashboards of 30 and 10", r, d)
	}
	if p := in.Problems(); len(p) != 1 || !strings.Contains(p[0], "10 of the 10 dashboard files") {
		t.Fatalf("problems %q", p)
	}

	a, b, in = libraryOf(t, 15, 30)
	for i := range 15 {
		if err := os.Remove(filepath.Join(b.detDir, fmt.Sprintf("rule-%d.yaml", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, d := counts(t, a); r != 15 || d != 30 {
		t.Fatalf("emptying the detections folder left %d detections and %d dashboards of 15 and 30", r, d)
	}
	if p := in.Problems(); len(p) != 1 || !strings.Contains(p[0], "15 of the 15 detection files") {
		t.Fatalf("problems %q", p)
	}
}

func TestMirrorRemovesAFewFiles(t *testing.T) {
	a, b, in := libraryOf(t, 5, 3)
	for _, id := range []string{"rule-0", "rule-1"} {
		if err := os.Remove(filepath.Join(b.detDir, id+".yaml")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(b.dbDir, "board-0.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, d := counts(t, a); r != 3 || d != 2 {
		t.Fatalf("%d detections and %d dashboards left, want 3 and 2", r, d)
	}
	if p := in.Problems(); len(p) != 0 {
		t.Fatalf("problems %q", p)
	}
}

func TestMirrorAllowFileRemovesAllOnce(t *testing.T) {
	a, b, in := libraryOf(t, 5, 4)
	emptyFolder(t, b.detDir)
	emptyFolder(t, b.dbDir)
	allowDet, allowDb := filepath.Join(b.detDir, AllowDeleteFile), filepath.Join(b.dbDir, AllowDeleteFile)
	writeFile(t, allowDet, nil)
	writeFile(t, allowDb, nil)
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, d := counts(t, a); r != 0 || d != 0 {
		t.Fatalf("%d detections and %d dashboards left with the allow files", r, d)
	}
	for _, p := range []string{allowDet, allowDb} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("the allow file was not removed once used: %v", err)
		}
	}
	// Once only: the next mass removal is refused again.
	for i := range 4 {
		if err := a.lib.PutIf(ctx, "alice", custom(fmt.Sprintf("again-%d", i), "Shared"), ""); err != nil {
			t.Fatal(err)
		}
	}
	b.cycle()
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	emptyFolder(t, b.detDir)
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _ := counts(t, a); r != 4 {
		t.Fatalf("%d detections left of 4 after the allow file was used", r)
	}
}

// An allow file covers its own folder only, shows on the Servers page
// while it waits, and is ignored once an hour old or when it is a link.
func TestMirrorAllowFileLimits(t *testing.T) {
	a, b, in := libraryOf(t, 5, 4)
	allowDb := filepath.Join(b.dbDir, AllowDeleteFile)
	writeFile(t, allowDb, nil)
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if p := in.Problems(); len(p) != 1 || !strings.HasPrefix(p[0], "Mass delete allowed.") || !strings.Contains(p[0], allowDb) {
		t.Fatalf("problems while the allow file waits: %q", p)
	}
	// The dashboards folder's file does not allow emptying the
	// detections folder, and stays for the dashboards.
	emptyFolder(t, b.detDir)
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, d := counts(t, a); r != 5 || d != 4 {
		t.Fatalf("%d detections and %d dashboards left of 5 and 4", r, d)
	}
	if _, err := os.Stat(allowDb); err != nil {
		t.Fatalf("the dashboards folder's allow file was used: %v", err)
	}

	// An hour old: ignored.
	old := time.Now().Add(-allowFor - time.Minute)
	if err := os.Chtimes(allowDb, old, old); err != nil {
		t.Fatal(err)
	}
	emptyFolder(t, b.dbDir)
	writeFile(t, allowDb, nil)
	if err := os.Chtimes(allowDb, old, old); err != nil {
		t.Fatal(err)
	}
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, d := counts(t, a); d != 4 {
		t.Fatalf("an old allow file let %d of 4 dashboards go", 4-d)
	}
	for _, p := range in.Problems() {
		if strings.HasPrefix(p, "Mass delete allowed.") {
			t.Fatalf("an old allow file shows as allowing: %q", p)
		}
	}

	// A link: ignored.
	if err := os.Remove(allowDb); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	writeFile(t, target, nil)
	if err := os.Symlink(target, allowDb); err != nil {
		t.Skip("no symbolic links here:", err)
	}
	emptyFolder(t, b.dbDir)
	if err := os.Symlink(target, allowDb); err != nil {
		t.Fatal(err)
	}
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, d := counts(t, a); d != 4 {
		t.Fatalf("a linked allow file let %d of 4 dashboards go", 4-d)
	}
}

func TestMassDelete(t *testing.T) {
	for _, c := range []struct {
		gone, total int
		want        bool
	}{{0, 0, false}, {2, 2, false}, {3, 3, true}, {3, 100, false}, {20, 30, false}, {21, 40, true}, {21, 42, false}, {50, 60, true}} {
		if got := massDelete(c.gone, c.total); got != c.want {
			t.Errorf("massDelete(%d, %d) = %v", c.gone, c.total, got)
		}
	}
}
