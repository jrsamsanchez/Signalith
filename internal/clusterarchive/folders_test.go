package clusterarchive

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFoldersOneFolderPerCluster(t *testing.T) {
	cl := newClient(t)
	ctx := context.Background()
	clock := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	id := func(s string) func() (string, error) { return func() (string, error) { return s, nil } }
	a := &Folders{Client: cl, Prefix: prefix, Server: "a", NodeID: "na", Dir: "/srv/archive", StoreID: id("one"), Now: now}
	b := &Folders{Client: cl, Prefix: prefix, Server: "b", NodeID: "nb", Dir: "/local/archive", StoreID: id("two"), Now: now}
	c := &Folders{Client: cl, Prefix: prefix, Server: "c", NodeID: "nc", Dir: "/srv/archive", StoreID: id("one"), Now: now}
	for _, f := range []*Folders{a, b, c} {
		if err := f.Report(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if on, err := a.On(ctx); err != nil || len(on) != 0 {
		t.Fatalf("On before any folder = %v, %v", on, err)
	}
	if ok, why := a.CanArchive(ctx); !ok {
		t.Fatalf("first server cannot archive: %s", why)
	}
	if ok, why := b.CanArchive(ctx); ok || !strings.Contains(why, "retention.archive_dir") {
		t.Fatalf("server with another folder: %v %q", ok, why)
	}
	if ok, why := c.CanArchive(ctx); !ok {
		t.Fatalf("server with the same folder cannot archive: %s", why)
	}
	on, err := b.On(ctx)
	if err != nil || strings.Join(on, ",") != "a,c" {
		t.Fatalf("On = %v, %v", on, err)
	}
	// Once no server has reported the cluster's folder for a while, the
	// next server to archive makes its own the cluster's.
	clock = clock.Add(2 * FolderSeen)
	if err := b.Report(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, why := b.CanArchive(ctx); !ok {
		t.Fatalf("server with the only live folder cannot archive: %s", why)
	}
	if on, _ := b.On(ctx); strings.Join(on, ",") != "b" {
		t.Fatalf("On after the move = %v", on)
	}
	// A folder that cannot be used is never the cluster's.
	bad := &Folders{Client: cl, Prefix: prefix, Server: "d", NodeID: "nd", StoreID: func() (string, error) { return "", errors.New("read-only") }, Now: now}
	if ok, why := bad.CanArchive(ctx); ok || !strings.Contains(why, "read-only") {
		t.Fatalf("broken folder: %v %q", ok, why)
	}
}
