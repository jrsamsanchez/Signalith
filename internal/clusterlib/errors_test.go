// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterlib

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// logRecorder keeps the messages logged through it.
type logRecorder struct {
	mu   sync.Mutex
	msgs []string
}

func (r *logRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *logRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, rec.Message)
	return nil
}
func (r *logRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *logRecorder) WithGroup(string) slog.Handler      { return r }

// has reports whether a message containing part was logged.
func (r *logRecorder) has(part string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.msgs {
		if strings.Contains(m, part) {
			return true
		}
	}
	return false
}

// waitFor polls cond until it holds, failing the test after 5 seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func sharedDetection(s *server, id string) *DetectionBody {
	for _, it := range s.docs.Detections().List() {
		if it.Name == id {
			return it.Value
		}
	}
	return nil
}

func sharedDashboard(s *server, id string) *DashboardBody {
	for _, it := range s.docs.Dashboards().List() {
		if it.Name == id {
			return it.Value
		}
	}
	return nil
}

func cancelled() context.Context {
	c, cancel := context.WithCancel(context.Background())
	cancel()
	return c
}

func TestInboxRunPushesAndStops(t *testing.T) {
	o := newOS(t)
	a := newServer(t, o, "siem-a", nil)
	in := a.inbox(false)
	in.Every = 20 * time.Millisecond
	// Two kicks before Run: the second finds one already waiting.
	in.Kick()
	in.Kick()
	runCtx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); in.Run(runCtx) }()
	waitFor(t, "the first look at the folders", func() bool {
		_, err := os.Stat(in.SeenFile)
		return err == nil
	})
	writeFile(t, filepath.Join(a.detDir, "my-rule.yaml"), encodeDet(t, custom("my-rule", "From the folder")))
	in.Kick()
	waitFor(t, "the file to be pushed", func() bool { return sharedDetection(a, "my-rule") != nil })
	stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop when its context ended")
	}
}

func TestInboxRunDefaultsAndLogsErrors(t *testing.T) {
	o := newOS(t)
	a := newServer(t, o, "siem-a", nil)
	rec := &logRecorder{}
	in := a.inbox(false)
	in.Files.Log = slog.New(rec)
	// A record that is a folder cannot be read: every pass fails, and is
	// logged.
	in.SeenFile = t.TempDir()
	if err := in.Sync(ctx); err == nil {
		t.Fatal("a record that cannot be read did not fail the pass")
	}
	runCtx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); in.Run(runCtx) }()
	waitFor(t, "the failed pass to be logged", func() bool { return rec.has("could not bring") })
	stop()
	<-done
}

func TestListInboxRunAndErrors(t *testing.T) {
	o := newOS(t)
	a := newServer(t, o, "siem-a", nil)
	rec := &logRecorder{}
	in := a.listInbox()
	in.Files.Log = slog.New(rec)
	in.Every = 20 * time.Millisecond
	in.Kick()
	in.Kick()
	writeFile(t, filepath.Join(a.lkDir, assets.AssetsFile), assetsCSV("web1"))
	runCtx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); in.Run(runCtx) }()
	waitFor(t, "the first look at the lookups folder", func() bool {
		_, err := os.Stat(in.SeenFile)
		return err == nil
	})
	stop()
	<-done

	// A record that is a folder fails every pass, which Run logs.
	bad := a.listInbox()
	bad.Files.Log = slog.New(rec)
	bad.SeenFile = t.TempDir()
	if err := bad.Sync(ctx); err == nil {
		t.Fatal("a record that cannot be read did not fail the pass")
	}
	if bad.seen != nil {
		t.Fatal("a record that cannot be read was kept as an empty one")
	}
	runCtx, stop = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() { defer close(done); bad.Run(runCtx) }()
	waitFor(t, "the failed pass to be logged", func() bool { return rec.has("could not bring the asset") })
	stop()
	<-done
}

// A record whose folder cannot be made is an error, for both inboxes.
func TestSeenRecordCannotBeSaved(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-folder")
	writeFile(t, blocker, []byte("x"))
	path := filepath.Join(blocker, "state", SeenFileName)
	if err := (&Inbox{SeenFile: path}).saveSeen(&seenFile{Version: 1, Files: map[string]*seenEntry{}}); err == nil {
		t.Error("the inbox's record saved under a file")
	}
	if err := (&ListInbox{SeenFile: path}).saveSeen(); err == nil {
		t.Error("the list inbox's record saved under a file")
	}
	if err := writeFileAtomic(filepath.Join(blocker, "rule.yaml"), []byte("x")); err == nil {
		t.Error("a file written under a file")
	}
}

func TestInboxSeenRecord(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record string
		pushed bool
	}{
		// A damaged record is started again: the files are a starting
		// point, not changes.
		{"damaged", "{not json", false},
		// A record with no files holds nothing seen: every file is new.
		{"no files", `{"version":1}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newOS(t)
			a := newServer(t, o, "siem-a", nil)
			in := a.inbox(false)
			writeFile(t, in.SeenFile, []byte(tc.record))
			writeFile(t, filepath.Join(a.detDir, "my-rule.yaml"), encodeDet(t, custom("my-rule", "Mine")))
			if err := in.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			if got := sharedDetection(a, "my-rule") != nil; got != tc.pushed {
				t.Fatalf("pushed %v, want %v", got, tc.pushed)
			}
		})
	}
}

func TestInboxPushSkipsWhatIsNotAChange(t *testing.T) {
	o := newOS(t)
	a := newServer(t, o, "siem-a", nil)
	in := a.inbox(false)
	if err := a.lib.PutIf(ctx, "alice", custom("my-rule", "Shared"), ""); err != nil {
		t.Fatal(err)
	}
	if err := a.boards.PutIf(ctx, "alice", board("ops", "Ops"), ""); err != nil {
		t.Fatal(err)
	}
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	detVer := a.lib.ETag("my-rule")
	boardBy := func() string { s, _ := (&Dashboards{Docs: a.docs}).Get("ops"); return s.By }

	id, on := builtinID(t)
	bs := dashboards.Builtin()
	if len(bs) == 0 {
		t.Fatal("no built-in dashboards")
	}
	bad := map[string][]byte{
		// The same rule laid out another way.
		filepath.Join(a.detDir, "my-rule.yaml"): append([]byte("# a comment\n"), encodeDet(t, custom("my-rule", "Shared"))...),
		// A rule whose id is not its file's name.
		filepath.Join(a.detDir, "wrong-name.yaml"): encodeDet(t, custom("other-id", "Wrong")),
		// A state file that is not YAML, and one that holds nothing.
		filepath.Join(a.detDir, detect.StateDir, id+".yaml"):         []byte("enabled: [\n"),
		filepath.Join(a.detDir, detect.StateDir, "empty-state.yaml"): []byte("{}\n"),
		// The same dashboard laid out another way, and a built-in one.
		filepath.Join(a.dbDir, "ops.yaml"):       append([]byte("# a comment\n"), encodeBoard(t, board("ops", "Ops"))...),
		filepath.Join(a.dbDir, bs[0].ID+".yaml"): encodeBoard(t, board(bs[0].ID, "Mine now")),
	}
	for p, data := range bad {
		writeFile(t, p, data)
	}
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if a.lib.ETag("my-rule") != detVer {
		t.Fatal("a file holding the same rule was pushed")
	}
	if sharedDetection(a, "wrong-name") != nil || sharedDetection(a, "other-id") != nil {
		t.Fatal("a rule in a file of another name was shared")
	}
	if sharedDetection(a, "empty-state") != nil {
		t.Fatal("an empty state file was shared")
	}
	if d, _ := a.lib.Get(id); d.Enabled != on {
		t.Fatal("a state file that is not valid was shared")
	}
	if by := boardBy(); by != "alice" {
		t.Fatalf("a file holding the same dashboard was pushed (by %q)", by)
	}
	if sharedDashboard(a, bs[0].ID) != nil {
		t.Fatal("a built-in dashboard's file was shared")
	}

	// Fixed, the state file is pushed; a changed dashboard keeps what
	// this version does not know of the shared one.
	writeFile(t, filepath.Join(a.detDir, detect.StateDir, id+".yaml"), []byte("enabled: "+map[bool]string{true: "false", false: "true"}[on]+"\n"))
	writeFile(t, filepath.Join(a.dbDir, "ops.yaml"), encodeBoard(t, board("ops", "Ops renamed")))
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if d, _ := a.lib.Get(id); d.Enabled == on {
		t.Fatal("the fixed state file was not pushed")
	}
	if b := sharedDashboard(a, "ops"); b == nil || !strings.Contains(b.YAML, "Ops renamed") || b.From == nil || b.From.Source != FromFile {
		t.Fatalf("the changed dashboard was not pushed: %+v", b)
	}
}

func TestInboxPushFailsWhenTheSharedSettingsDo(t *testing.T) {
	o := newOS(t)
	a := newServer(t, o, "siem-a", nil)
	in := a.inbox(false)
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(a.detDir, "my-rule.yaml"), encodeDet(t, custom("my-rule", "Mine")))
	writeFile(t, filepath.Join(a.dbDir, "ops.yaml"), encodeBoard(t, board("ops", "Ops")))
	if err := in.Sync(cancelled()); err == nil {
		t.Fatal("a push that failed did not fail the pass")
	}
	// What failed is pushed at the next pass.
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if sharedDetection(a, "my-rule") == nil || sharedDashboard(a, "ops") == nil {
		t.Fatal("the files were not pushed after the failure")
	}
}

func TestInboxKeepsLocalChangesWhileReadOnly(t *testing.T) {
	o := newOS(t)
	a := newServer(t, o, "siem-a", nil)
	if err := a.lib.PutIf(ctx, "alice", custom("my-rule", "Shared"), ""); err != nil {
		t.Fatal(err)
	}
	if err := a.lib.PutIf(ctx, "alice", custom("gone-rule", "Gone"), ""); err != nil {
		t.Fatal(err)
	}
	in := a.inbox(false)
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	paused := errors.New("paused")
	in.Writable = func() error { return paused }
	// Changed here while nothing can be pushed: left for the next push.
	local := encodeDet(t, custom("my-rule", "Changed here"))
	writeFile(t, filepath.Join(a.detDir, "my-rule.yaml"), local)
	// A rule deleted elsewhere whose file was changed here is kept too.
	if err := a.lib.DeleteIf(ctx, "alice", "gone-rule", ""); err != nil {
		t.Fatal(err)
	}
	gone := encodeDet(t, custom("gone-rule", "Changed here too"))
	writeFile(t, filepath.Join(a.detDir, "gone-rule.yaml"), gone)
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string][]byte{"my-rule.yaml": local, "gone-rule.yaml": gone} {
		data, err := os.ReadFile(filepath.Join(a.detDir, p))
		if err != nil || !sameText(data, want) {
			t.Fatalf("%s was written over while it waits to be pushed: %v\n%s", p, err, data)
		}
	}
	if d, _ := a.lib.Get("my-rule"); d.Title != "Shared" {
		t.Fatalf("a change was pushed while the settings are read-only: %q", d.Title)
	}
}

func TestInboxFolderErrors(t *testing.T) {
	t.Run("write back over a folder", func(t *testing.T) {
		o := newOS(t)
		a := newServer(t, o, "siem-a", nil)
		if err := a.lib.PutIf(ctx, "alice", custom("my-rule", "Shared"), ""); err != nil {
			t.Fatal(err)
		}
		// A folder where the rule's file goes cannot be written over.
		if err := os.MkdirAll(filepath.Join(a.detDir, "my-rule.yaml"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := a.inbox(false).Sync(ctx); err == nil {
			t.Fatal("a file that could not be written back did not fail the pass")
		}
	})
	for _, sub := range []string{"state", "dashboards"} {
		t.Run(sub+" folder is a file", func(t *testing.T) {
			o := newOS(t)
			a := newServer(t, o, "siem-a", nil)
			p := filepath.Join(a.detDir, detect.StateDir)
			if sub == "dashboards" {
				p = a.dbDir
			}
			writeFile(t, filepath.Join(a.detDir, "keep.txt"), []byte("x"))
			writeFile(t, p, []byte("not a folder"))
			err := a.inbox(false).Sync(ctx)
			if err == nil || !strings.Contains(err.Error(), "cannot be read") {
				t.Fatalf("a folder that cannot be read: %v", err)
			}
		})
	}
}

func TestDetectionBodyDecode(t *testing.T) {
	valid := string(mustEncode(t, custom("my-rule", "Mine")))
	bad := &detect.State{Exceptions: []detect.Exception{{}}}
	if len(detect.ExceptionProblems(bad.Exceptions)) == 0 {
		t.Skip("an empty exception is valid in this version")
	}
	for _, tc := range []struct {
		name, id string
		body     DetectionBody
		want     string
	}{
		{"bad name", "X", DetectionBody{YAML: valid}, "not a valid id"},
		{"not yaml", "my-rule", DetectionBody{YAML: "id: [\n"}, ""},
		{"not valid", "my-rule", DetectionBody{YAML: "id: my-rule\n"}, ""},
		{"other id", "other-rule", DetectionBody{YAML: valid}, "holds the detection"},
		{"bad exceptions", "my-rule", DetectionBody{State: bad}, ""},
		{"empty", "my-rule", DetectionBody{}, "neither"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := tc.body.decode(tc.id)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("decode: %v, want an error with %q", err, tc.want)
			}
		})
	}
	if d, st, err := (&DetectionBody{YAML: valid}).decode("my-rule"); err != nil || d == nil || st != nil {
		t.Fatalf("a valid body: %v %v %v", d, st, err)
	}
}

func mustEncode(t *testing.T, d *detect.Detection) []byte { return encodeDet(t, d) }

func TestNamesID(t *testing.T) {
	for _, tc := range []struct {
		text string
		ok   bool
	}{
		{"", true},
		{"id: my-rule\n", true},
		{"id: other\n", false},
		{"id: [\n", false},
	} {
		if err := namesID("my-rule", tc.text); (err == nil) != tc.ok {
			t.Errorf("namesID(%q) = %v", tc.text, err)
		}
	}
}

func TestDocsSubscribers(t *testing.T) {
	o := newOS(t)
	a := newServer(t, o, "siem-a", nil)
	var mu sync.Mutex
	heard := map[string]int{}
	note := func(k string) func() {
		return func() { mu.Lock(); heard[k]++; mu.Unlock() }
	}
	a.docs.OnDashboards(note("dashboards"))
	a.docs.OnLookups(note("lookups"))
	if err := a.boards.PutIf(ctx, "alice", board("ops", "Ops"), ""); err != nil {
		t.Fatal(err)
	}
	if err := setList(t, a); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if heard["dashboards"] == 0 || heard["lookups"] == 0 {
		t.Fatalf("subscribers not told: %v", heard)
	}
	mu.Unlock()
	a.docs.Reset()
	before := map[string]int{}
	mu.Lock()
	for k, v := range heard {
		before[k] = v
	}
	mu.Unlock()
	if err := a.boards.PutIf(ctx, "alice", board("ops2", "Ops"), ""); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if heard["dashboards"] != before["dashboards"] {
		t.Fatal("a subscriber was told after Reset")
	}
	// The collection refuses an item that holds nothing.
	if err := a.docs.Detections().ValidateItem("my-rule", &DetectionBody{}); err == nil {
		t.Fatal("an empty detection item was valid")
	}
	if err := a.docs.Dashboards().ValidateItem("Bad Name", &DashboardBody{}); err == nil {
		t.Fatal("a dashboard item with a bad name was valid")
	}
}

func TestReadDetectionFilesLeavesOutBadFiles(t *testing.T) {
	dir := t.TempDir()
	id, on := builtinID(t)
	writeFile(t, filepath.Join(dir, "good-rule.yaml"), encodeDet(t, custom("good-rule", "Good")))
	writeFile(t, filepath.Join(dir, "not-valid.yaml"), []byte("id: not-valid\n"))
	writeFile(t, filepath.Join(dir, "wrong-name.yaml"), encodeDet(t, custom("other-id", "Wrong")))
	// A folder named like a file cannot be read.
	if err := os.MkdirAll(filepath.Join(dir, "folder.yaml"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, detect.StateDir, "folder.yaml"), 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, detect.StateDir, id+".yaml"), []byte("enabled: "+map[bool]string{true: "false", false: "true"}[on]+"\n"))
	writeFile(t, filepath.Join(dir, detect.StateDir, "broken.yaml"), []byte("enabled: [\n"))
	writeFile(t, filepath.Join(dir, detect.StateDir, "empty.yaml"), []byte("{}\n"))
	rec := &logRecorder{}
	got := readDetectionFiles(dir, slog.New(rec))
	if len(got) != 2 || got["good-rule"] == nil || got[id] == nil || got[id].State == nil {
		t.Fatalf("read %v", got)
	}
	for _, m := range []string{"could not read a detection file", "could not read a detection state file", "not valid and was left out"} {
		if !rec.has(m) {
			t.Errorf("not logged: %q", m)
		}
	}
	// hashFiles fails on what it cannot read, and is empty with no files.
	if _, err := hashFiles([]string{filepath.Join(dir, "folder.yaml")}); err == nil {
		t.Fatal("hashFiles read a folder")
	}
	if h, err := hashFiles([]string{filepath.Join(dir, "missing.yaml")}); err != nil || h != "" {
		t.Fatalf("hashFiles of no files: %q %v", h, err)
	}
}

func TestImportDashboardsLeavesOutBadFiles(t *testing.T) {
	o := newOS(t)
	a := newServer(t, o, "siem-a", nil)
	rec := &logRecorder{}
	f := a.files()
	f.Log = slog.New(rec)
	bs := dashboards.Builtin()
	writeFile(t, filepath.Join(a.dbDir, "ops.yaml"), encodeBoard(t, board("ops", "Ops")))
	writeFile(t, filepath.Join(a.dbDir, bs[0].ID+".yaml"), encodeBoard(t, board(bs[0].ID, "Mine")))
	writeFile(t, filepath.Join(a.dbDir, "broken.yaml"), []byte("id: broken\ntitle: [\n"))
	if err := os.MkdirAll(filepath.Join(a.dbDir, "folder.yaml"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := importDashboards(ctx, a.docs, f, "signalith"); err != nil {
		t.Fatal(err)
	}
	if n := len(a.docs.Dashboards().List()); n != 1 || sharedDashboard(a, "ops") == nil {
		t.Fatalf("%d dashboards imported", n)
	}
	if !rec.has("could not read a dashboard file") || !rec.has("a dashboard file is not valid") {
		t.Fatalf("not logged: %v", rec.msgs)
	}
}

func TestLookupImporterErrors(t *testing.T) {
	o := newOS(t)
	a := newServer(t, o, "siem-a", nil)
	none := Files{Node: "siem-a"}
	if h, err := LookupImporters(a.docs, none)[0].Source(); err != nil || h != "" {
		t.Fatalf("no lookups folder: %q %v", h, err)
	}
	rec := &logRecorder{}
	f := a.files()
	f.Log = slog.New(rec)
	im := LookupImporters(a.docs, f)[0]
	// A damaged list is left out, with a warning.
	writeFile(t, filepath.Join(a.lkDir, assets.AssetsFile), []byte("no,host,column\n\"open"))
	if err := im.Run(ctx, "signalith"); err != nil {
		t.Fatal(err)
	}
	if (&Lookups{Docs: a.docs}).Head(assets.KindAssets) != nil || !rec.has("cannot be read was left out") {
		t.Fatal("a damaged list was imported")
	}
	// A list that cannot be shared fails the import.
	writeFile(t, filepath.Join(a.lkDir, assets.AssetsFile), assetsCSV("web1"))
	if err := im.Run(cancelled(), "signalith"); err == nil {
		t.Fatal("an import that could not share the list did not fail")
	}
	// A list file that cannot be read fails it too.
	if err := os.Remove(filepath.Join(a.lkDir, assets.AssetsFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(a.lkDir, assets.AssetsFile), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := im.Run(ctx, "signalith"); err == nil {
		t.Fatal("a list file that cannot be read did not fail the import")
	}
}

// failingLists refuses every list written to it.
type failingLists struct{}

func (failingLists) Write(string, []byte) error { return errors.New("disk full") }

func TestListInboxErrors(t *testing.T) {
	_, a, b := pair(t)
	inA := a.listInbox()
	inB := b.listInbox()
	inB.Lists = failingLists{}
	for _, in := range []*ListInbox{inA, inB} {
		if err := in.Sync(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// A list uploaded on A that B cannot write fails B's pass.
	if err := setList(t, a); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if err := inB.Sync(ctx); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("a list that could not be written: %v", err)
	}
	// A list changed in A's folder while the settings are read-only is
	// left for later; one that cannot be uploaded fails the pass.
	writeFile(t, filepath.Join(a.lkDir, assets.IdentitiesFile), []byte("identity\nbob\n"))
	inA.Lookups = &Lookups{Docs: a.docs, Node: "siem-a", Writable: func() error { return errors.New("paused") }}
	if err := inA.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if inA.Lookups.Head(assets.KindIdentities) != nil {
		t.Fatal("a list was uploaded while the settings are read-only")
	}
	inA.Lookups = a.lk
	if err := inA.Sync(cancelled()); err == nil {
		t.Fatal("an upload that failed did not fail the pass")
	}
	// A list file that cannot be read fails the pass.
	if err := os.Remove(filepath.Join(a.lkDir, assets.IdentitiesFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(a.lkDir, assets.IdentitiesFile), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := inA.Sync(ctx); err == nil {
		t.Fatal("a list file that cannot be read did not fail the pass")
	}
	// A damaged record is a starting point.
	c := b.listInbox()
	writeFile(t, c.SeenFile, []byte("{not json"))
	if base, err := c.loadSeen(); err != nil || !base {
		t.Fatalf("a damaged record: %v %v", base, err)
	}
}

func TestExportErrors(t *testing.T) {
	o := newOS(t)
	a := newServer(t, o, "siem-a", nil)
	none := Files{Node: "siem-a"}
	root := t.TempDir()
	target := exportTo(t, a.state, root)
	for _, ex := range Exporters(a.docs, none) {
		if files, err := ex.Run(ctx, target); err != nil || len(files) != 0 {
			t.Fatalf("%s with no folder: %v %v", ex.Name, files, err)
		}
	}
	if err := a.lib.PutIf(ctx, "alice", custom("my-rule", "Mine"), ""); err != nil {
		t.Fatal(err)
	}
	id, on := builtinID(t)
	if err := a.lib.SetEnabledBy(ctx, "bob", []string{id}, !on); err != nil {
		t.Fatal(err)
	}
	if err := a.boards.PutIf(ctx, "alice", board("ops", "Ops"), ""); err != nil {
		t.Fatal(err)
	}
	if err := setList(t, a); err != nil {
		t.Fatal(err)
	}
	// A file where the export's folders go: nothing can be written.
	blocked := filepath.Join(t.TempDir(), "file")
	writeFile(t, blocked, []byte("x"))
	under := shared.ExportTarget{Under: func(p string) string { return filepath.Join(blocked, filepath.Base(p)) }}
	for _, ex := range Exporters(a.docs, a.files()) {
		if _, err := ex.Run(ctx, under); err == nil {
			t.Errorf("%s wrote under a file", ex.Name)
		}
	}
	// A state file whose folder cannot be made fails the export too.
	stateOnly := shared.ExportTarget{Under: func(p string) string {
		if filepath.Base(filepath.Dir(p)) == detect.StateDir {
			return filepath.Join(blocked, filepath.Base(p))
		}
		return filepath.Join(root, filepath.Base(p))
	}}
	if _, err := exportDetections(a.docs, a.files(), stateOnly); err == nil {
		t.Error("a state file that could not be written did not fail the export")
	}
	if _, err := exportLookups(cancelled(), a.docs, a.files(), target); err == nil {
		t.Error("a list that could not be read did not fail the export")
	}
}

func TestItemsThisVersionCannotRead(t *testing.T) {
	o := newOS(t)
	a := newServer(t, o, "siem-a", nil)
	// Items that name their own id, as the shared settings check, but
	// that this version cannot read (written by a newer one).
	if _, err := a.docs.Detections().Create(ctx, "newer", "odd-rule", &DetectionBody{YAML: "id: odd-rule\n"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.docs.Dashboards().Create(ctx, "newer", "odd-board", &DashboardBody{YAML: "id: odd-board\n"}); err != nil {
		t.Fatal(err)
	}
	det := &Detections{Docs: a.docs, Node: "siem-a", Source: FromImport, Now: func() time.Time { return time.Unix(1700000000, 0) }}
	if got, err := det.Load(); err != nil || got["odd-rule"].Custom != nil {
		t.Fatalf("Load kept an item it cannot read: %v %v", got, err)
	}
	called := false
	err := det.Change(ctx, "alice", []string{"odd-rule"}, func(string, detect.Stored) (detect.Stored, bool, error) {
		called = true
		return detect.Stored{}, false, nil
	})
	if err == nil || called {
		t.Fatalf("a change over an item that cannot be read: %v (called %v)", err, called)
	}
	// A new detection is stamped with the backend's source and clock.
	if err := det.Change(ctx, "alice", []string{"new-rule"}, func(string, detect.Stored) (detect.Stored, bool, error) {
		return detect.Stored{Custom: custom("new-rule", "New")}, true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if b := sharedDetection(a, "new-rule"); b == nil || b.From == nil || b.From.Source != FromImport || !strings.HasPrefix(b.From.At, "2023-") {
		t.Fatalf("the new detection: %+v", b)
	}

	boards := &Dashboards{Docs: a.docs, Node: "siem-a", Now: func() time.Time { return time.Unix(1700000000, 0) }}
	if list, _ := boards.List(); len(list) != 0 {
		t.Fatalf("List kept a dashboard it cannot read: %v", list)
	}
	if _, ok := boards.Get("odd-board"); ok {
		t.Fatal("Get returned a dashboard it cannot read")
	}
	// A page can save over a dashboard it cannot read.
	var seen *dashboards.Stored
	if err := boards.Change(ctx, "alice", "odd-board", func(st *dashboards.Stored) (*dashboards.Dashboard, error) {
		seen = st
		return board("odd-board", "Saved over"), nil
	}); err != nil {
		t.Fatal(err)
	}
	if seen == nil || seen.Dashboard.ID != "odd-board" || seen.By != "newer" {
		t.Fatalf("the change saw %+v", seen)
	}
	if s, ok := boards.Get("odd-board"); !ok || s.Dashboard.Title != "Saved over" {
		t.Fatalf("the dashboard was not saved over: %+v", s)
	}

	// Exports and the inbox leave out the detection they cannot read.
	files, err := exportDetections(a.docs, a.files(), exportTo(t, a.state, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.Contains(f.Dest, "odd-rule") {
			t.Fatal("a detection that cannot be read was exported")
		}
	}
	if err := a.inbox(false).Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(a.detDir, "odd-rule.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a detection that cannot be read was written into the folder: %v", err)
	}
}

func TestBackendsRefuseWhileReadOnly(t *testing.T) {
	o := newOS(t)
	a := newServer(t, o, "siem-a", nil)
	paused := errors.New("paused")
	ro := func() error { return paused }
	if err := (&Detections{Docs: a.docs, Writable: ro}).Change(ctx, "alice", []string{"x-rule"}, nil); !errors.Is(err, paused) {
		t.Fatalf("Detections.Change: %v", err)
	}
	if err := (&Dashboards{Docs: a.docs, Writable: ro}).Change(ctx, "alice", "ops", nil); !errors.Is(err, paused) {
		t.Fatalf("Dashboards.Change: %v", err)
	}
	if err := (&Lookups{Docs: a.docs, Writable: ro}).Put(ctx, "alice", assets.KindAssets, assetsCSV("web1"), ""); !errors.Is(err, paused) {
		t.Fatalf("Lookups.Put: %v", err)
	}
	if err := (&Lookups{Docs: a.docs, Writable: ro}).Housekeep(ctx, "signalith"); err != nil {
		t.Fatalf("Housekeep while read-only: %v", err)
	}
	// Before the shared settings are read there is nothing to write to.
	var pe *shared.PausedError
	if err := (&Lookups{Docs: NewDocs()}).Put(ctx, "alice", assets.KindAssets, assetsCSV("web1"), ""); !errors.As(err, &pe) {
		t.Fatalf("Put before the settings are read: %v", err)
	}
	if err := (&Lookups{Docs: NewDocs()}).Housekeep(ctx, "signalith"); err != nil {
		t.Fatalf("Housekeep before the settings are read: %v", err)
	}
	// A list that is not valid is refused before anything is written.
	if err := a.lk.Put(ctx, "alice", assets.KindAssets, []byte("no,host,column\n\"open"), ""); err == nil {
		t.Fatal("a damaged list was put")
	}
	if a.lk.Head(assets.KindAssets) != nil {
		t.Fatal("a damaged list left a head")
	}
	if _, err := countRows("other", nil); err == nil {
		t.Fatal("countRows of an unknown list")
	}
}

func TestLookupHeadCheck(t *testing.T) {
	sum := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name string
		h    LookupHead
		ok   bool
	}{
		{assets.KindAssets, LookupHead{Gen: 1, Chunks: 1, SHA256: sum}, true},
		{"other", LookupHead{Gen: 1, Chunks: 1, SHA256: sum}, false},
		{assets.KindAssets, LookupHead{Gen: 0, Chunks: 1, SHA256: sum}, false},
		{assets.KindAssets, LookupHead{Gen: 1, Chunks: 0, SHA256: sum}, false},
		{assets.KindAssets, LookupHead{Gen: 1, Chunks: 1, SHA256: "short"}, false},
	} {
		if err := tc.h.check(tc.name); (err == nil) != tc.ok {
			t.Errorf("check(%s, %+v) = %v", tc.name, tc.h, err)
		}
	}
}

// setList uploads an assets list on s, as the page does.
func setList(t *testing.T, s *server) error {
	t.Helper()
	_, err := s.lists.SetIf(ctx, "alice", assets.KindAssets, assetsCSV("web1"), "")
	return err
}

// Housekeeping reports old chunks it cannot delete and a head it cannot
// write, and keeps the generation listed until both are done.
func TestHousekeepFailures(t *testing.T) {
	o, a, _ := pair(t)
	now := time.Now()
	a.lk.Now = func() time.Time { return now }
	for _, rows := range []string{"identity,name\nbob,Bob Jones\n", "identity,name\ncarl,Carl Diaz\n"} {
		if _, err := a.lists.SetIf(ctx, "alice", assets.KindIdentities, []byte(rows), ""); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(RetireAfter + time.Second)
	o.fake.FailN(1, "DELETE", "", 500, "internal_error")
	if err := a.lk.Housekeep(ctx, "signalith"); err == nil {
		t.Error("chunks that could not be deleted were no error")
	}
	if h := a.lk.Head(assets.KindIdentities); len(h.Retired) != 1 {
		t.Fatalf("retired after a failed delete: %+v", h.Retired)
	}
	o.fake.FailN(1, "PUT", "", 400, "mapper_parsing_exception")
	if err := a.lk.Housekeep(ctx, "signalith"); err == nil {
		t.Error("a head that could not be written was no error")
	}
	o.fake.SetFault(nil)
	if err := a.lk.Housekeep(ctx, "signalith"); err != nil {
		t.Fatal(err)
	}
	if h := a.lk.Head(assets.KindIdentities); len(h.Retired) != 0 {
		t.Fatalf("still retired: %+v", h.Retired)
	}
}

// A server that has not read a list another server made meanwhile: an
// upload that expected no list is stale, one for the latest replaces it.
func TestListMadeMeanwhileOnAnotherServer(t *testing.T) {
	_, a, b := pair(t)
	if err := setList(t, a); err != nil {
		t.Fatal(err)
	}
	if b.lk.ETag(assets.KindAssets) != NoList {
		t.Fatal("B read the list already")
	}
	err := b.lk.Put(ctx, "bob", assets.KindAssets, assetsCSV("web2"), NoList)
	var stale *shared.StaleError
	if !errors.As(err, &stale) || stale.By != "alice" || stale.Node != "siem-a" {
		t.Fatalf("an upload expecting no list: %v", err)
	}

	ids := []byte("identity,name\nbob,Bob Jones\n")
	if _, err := a.lists.SetIf(ctx, "alice", assets.KindIdentities, ids, ""); err != nil {
		t.Fatal(err)
	}
	if b.lk.Head(assets.KindIdentities) != nil {
		t.Fatal("B read the identities already")
	}
	newer := []byte("identity,name\nann,Ann Lee\n")
	if err := b.lk.Put(ctx, "bob", assets.KindIdentities, newer, ""); err != nil {
		t.Fatalf("an upload for the latest: %v", err)
	}
	a.cycle()
	got, h, err := a.lk.Read(ctx, assets.KindIdentities)
	if err != nil || string(got) != string(newer) || h.From.Node != "siem-b" || len(h.Retired) != 1 {
		t.Fatalf("A reads %q %+v %v", got, h, err)
	}
}
