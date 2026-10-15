package clusterlib

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// smallChunks cuts lists into chunks of 64 bytes, so a test list has
// several.
func smallChunks(t *testing.T) {
	old := shared.ChunkSize
	shared.ChunkSize = 64
	t.Cleanup(func() { shared.ChunkSize = old })
}

func assetsCSV(hosts ...string) []byte {
	var b strings.Builder
	b.WriteString("host,owner,priority\n")
	for _, h := range hosts {
		fmt.Fprintf(&b, "%s,ops,high\n", h)
	}
	return []byte(b.String())
}

func TestListUploadedOnOneServerIsUsedOnAnother(t *testing.T) {
	smallChunks(t)
	_, a, b := pair(t)
	data := assetsCSV("web1", "web2", "db1", "db2", "mail1")
	if n, err := a.lists.SetIf(ctx, "alice", assets.KindAssets, data, ""); err != nil || n != 5 {
		t.Fatalf("upload: %d %v", n, err)
	}
	b.cycle()
	got, h, err := b.lk.Read(ctx, assets.KindAssets)
	if err != nil || string(got) != string(data) {
		t.Fatalf("B reads %q (%v)", got, err)
	}
	if h.Chunks < 2 || h.Rows != 5 || h.From.Node != "siem-a" {
		t.Fatalf("head %+v", h)
	}
	// B's inbox writes it into B's folder, and B uses it.
	if err := b.listInbox().Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.lists.Asset("db2"); !ok {
		t.Fatal("B does not use the list uploaded on A")
	}
	if f, _ := os.ReadFile(filepath.Join(b.lkDir, assets.AssetsFile)); string(f) != string(data) {
		t.Fatalf("B's folder has %q", f)
	}
}

func TestConcurrentListUploadsOneIsStale(t *testing.T) {
	_, a, b := pair(t)
	if _, err := a.lists.SetIf(ctx, "alice", assets.KindAssets, assetsCSV("web1"), ""); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	etag := b.lists.ETag(assets.KindAssets)
	if etag == "" {
		t.Fatal("no version for If-Match")
	}
	if _, err := a.lists.SetIf(ctx, "alice", assets.KindAssets, assetsCSV("web2"), etag); err != nil {
		t.Fatal(err)
	}
	_, err := b.lists.SetIf(ctx, "bob", assets.KindAssets, assetsCSV("web3"), etag)
	var stale *shared.StaleError
	if !errors.As(err, &stale) {
		t.Fatalf("an upload over a stale version: %v", err)
	}
	if _, ok := b.lists.Asset("web3"); ok {
		t.Fatal("the refused list is used")
	}
	// Even when B has not seen A's change yet, the head refuses it.
	b2 := *b.lk
	b.docs.Lookups().Refresh(ctx, assets.KindAssets)
	if err := b2.Put(ctx, "bob", assets.KindAssets, assetsCSV("web4"), etag); !errors.As(err, &stale) || stale.By != "alice" {
		t.Fatalf("stale upload: %v", err)
	}
}

func TestReplacedListIsReadableUntilHousekept(t *testing.T) {
	smallChunks(t)
	o, a, _ := pair(t)
	now := time.Now()
	a.lk.Now = func() time.Time { return now }
	if _, err := a.lists.SetIf(ctx, "alice", assets.KindIdentities, []byte("identity,name\nbob,Bob Jones\nann,Ann Lee\n"), ""); err != nil {
		t.Fatal(err)
	}
	old := *a.lk.Head(assets.KindIdentities)
	if _, err := a.lists.SetIf(ctx, "alice", assets.KindIdentities, []byte("identity,name\ncarl,Carl Diaz\n"), ""); err != nil {
		t.Fatal(err)
	}
	// A reader that took the old head still reads the whole old list.
	if data, err := a.docs.Hub().ReadChunks(ctx, old.ref(assets.KindIdentities), old.SHA256); err != nil || !strings.Contains(string(data), "ann") {
		t.Fatalf("the old list while it is kept: %q %v", data, err)
	}
	if err := a.lk.Housekeep(ctx, "signalith"); err != nil {
		t.Fatal(err)
	}
	if h := a.lk.Head(assets.KindIdentities); len(h.Retired) != 1 {
		t.Fatalf("retired too early: %+v", h.Retired)
	}
	now = now.Add(RetireAfter + time.Second)
	if err := a.lk.Housekeep(ctx, "signalith"); err != nil {
		t.Fatal(err)
	}
	if h := a.lk.Head(assets.KindIdentities); len(h.Retired) != 0 {
		t.Fatalf("still retired: %+v", h.Retired)
	}
	if _, err := a.docs.Hub().ReadChunks(ctx, old.ref(assets.KindIdentities), old.SHA256); !errors.Is(err, shared.ErrChunkMissing) {
		t.Fatalf("the old list's chunks were not deleted: %v", err)
	}
	if o.fake.Source(shared.ConfigIndex(testPrefix), old.ref(assets.KindIdentities).Kind+":identities:"+fmt.Sprint(old.Gen)+":0") != nil {
		t.Fatal("a chunk of the old list is still there")
	}
	if data, _, err := a.lk.Read(ctx, assets.KindIdentities); err != nil || !strings.Contains(string(data), "carl") {
		t.Fatalf("the list in use: %q %v", data, err)
	}
}

func TestForgedChunkIsNotUsed(t *testing.T) {
	o, a, b := pair(t)
	if _, err := a.lists.SetIf(ctx, "alice", assets.KindAssets, assetsCSV("web1"), ""); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	h := b.lk.Head(assets.KindAssets)
	idx := shared.ConfigIndex(testPrefix)
	id := LookupChunkKind + ":assets:" + fmt.Sprint(h.Gen) + ":0"
	src := o.fake.Source(idx, id)
	src["body"] = strings.Replace(src["body"].(string), `"data":"`, `"data":"AA`, 1)
	o.fake.Put(idx, id, src)
	if _, _, err := b.lk.Read(ctx, assets.KindAssets); !errors.Is(err, shared.ErrChunkMissing) {
		t.Fatalf("a forged chunk was read: %v", err)
	}
}

func TestListInbox(t *testing.T) {
	_, a, b := pair(t)
	// B had a stale assets.csv when it started to share the lists: a
	// starting point, not a change.
	writeFile(t, filepath.Join(b.lkDir, assets.AssetsFile), assetsCSV("stale"))
	if _, err := a.lists.SetIf(ctx, "alice", assets.KindAssets, assetsCSV("web1"), ""); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	in := b.listInbox()
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if h := a.lk.Head(assets.KindAssets); h.From.Node != "siem-a" {
		t.Fatalf("the stale file was uploaded: %+v", h.From)
	}
	if _, ok := b.lists.Asset("web1"); !ok {
		t.Fatal("the shared list was not written back")
	}
	// A new export copied into B's folder is uploaded, once.
	writeFile(t, filepath.Join(b.lkDir, assets.AssetsFile), assetsCSV("web1", "web9"))
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	a.cycle()
	h := a.lk.Head(assets.KindAssets)
	if h.Rows != 2 || h.From.Source != FromFile || h.From.Node != "siem-b" {
		t.Fatalf("the changed file was not uploaded: %+v %+v", h, h.From)
	}
	gen := h.Gen
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if b.lk.Head(assets.KindAssets).Gen != gen {
		t.Fatal("an unchanged file was uploaded again")
	}
	// A broken file is not uploaded, and nothing breaks.
	writeFile(t, filepath.Join(b.lkDir, assets.IdentitiesFile), []byte("nope,nope\n1,2\n"))
	if err := in.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if b.lk.Head(assets.KindIdentities) != nil {
		t.Fatal("a broken file was uploaded")
	}
}

func TestLookupImporterIsIdempotent(t *testing.T) {
	o := newOS(t)
	a := newServer(t, o, "siem-a", nil)
	writeFile(t, filepath.Join(a.lkDir, assets.AssetsFile), assetsCSV("web1"))
	writeFile(t, filepath.Join(a.lkDir, assets.IdentitiesFile), []byte("identity\nbob\n"))
	ims := LookupImporters(a.docs, a.files())
	if h, err := ims[0].Source(); err != nil || h == "" {
		t.Fatalf("nothing to import: %q %v", h, err)
	}
	for range 2 {
		if err := ims[0].Run(ctx, "signalith"); err != nil {
			t.Fatal(err)
		}
	}
	h := a.lk.Head(assets.KindAssets)
	if h == nil || h.From.Source != FromImport || len(h.Retired) != 0 {
		t.Fatalf("assets head %+v", h)
	}
	if a.lk.Head(assets.KindIdentities) == nil {
		t.Fatal("identities not imported")
	}
}

func TestListInboxNewFolderIsAStartingPoint(t *testing.T) {
	_, a, b := pair(t)
	if _, err := a.lists.SetIf(ctx, "alice", assets.KindAssets, assetsCSV("web1"), ""); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if err := b.listInbox().Sync(ctx); err != nil {
		t.Fatal(err)
	}
	// lookups.dir now names another folder, with a stale assets.csv.
	b.lkDir = filepath.Join(t.TempDir(), "lookups")
	writeFile(t, filepath.Join(b.lkDir, assets.AssetsFile), assetsCSV("stale"))
	if err := b.listInbox().Sync(ctx); err != nil {
		t.Fatal(err)
	}
	a.cycle()
	if h := a.lk.Head(assets.KindAssets); h.From.Node != "siem-a" {
		t.Fatalf("the stale file in the new folder was uploaded: %+v", h.From)
	}
}
