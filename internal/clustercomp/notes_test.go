// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clustercomp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/compliance"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const prefix = "signalith"

var now = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)

// cluster is one fake OpenSearch with a cluster key; server adds a server
// that reads the notes from it.
type cluster struct {
	t   *testing.T
	cl  *store.Client
	key *shared.ClusterKey
}

func newCluster(t *testing.T) *cluster {
	t.Helper()
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	if err := shared.EnsureConfig(context.Background(), cl, prefix); err != nil {
		t.Fatal(err)
	}
	key, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	return &cluster{t: t, cl: cl, key: key}
}

func (c *cluster) server(name string, writable func() error) (*Notes, *shared.Hub) {
	c.t.Helper()
	h := shared.NewHub(shared.Options{NodeName: name})
	h.SetKeys(shared.NewKeySet(c.key))
	h.Use(c.cl, prefix)
	n := New(writable)
	n.Track(h)
	if err := h.Cycle(context.Background()); err != nil {
		c.t.Fatal(err)
	}
	return n, h
}

// Interface check: the API takes either store.
var _ compliance.NoteStore = (*Notes)(nil)

func TestNotesShared(t *testing.T) {
	ctx := context.Background()
	c := newCluster(t)
	a, _ := c.server("siem-a", nil)
	b, hb := c.server("siem-b", nil)

	if _, err := a.Set(ctx, "pci-dss", "10.6.1", compliance.External, "  ", "ann", now); err == nil {
		t.Error("an empty note was saved")
	}
	at, err := a.Set(ctx, "pci-dss", "10.6.1", compliance.External, " Chrony on every host. ", "ann", now)
	if err != nil || at.Note != "Chrony on every host." || at.By != "ann" {
		t.Fatalf("set = %+v, %v", at, err)
	}
	if err := hb.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	got := b.All()[compliance.Key("pci-dss", "10.6.1")]
	if got.Status != compliance.External || got.Note != "Chrony on every host." || got.By != "ann" || !got.At.Equal(now) {
		t.Fatalf("siem-b reads %+v", got)
	}

	// The other server changes it without having read the latest copy:
	// the last save wins.
	if _, err := a.Set(ctx, "pci-dss", "10.6.1", compliance.NotApplicable, "No card data here.", "ann", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Set(ctx, "pci-dss", "10.6.1", compliance.External, "Handled by the NTP team.", "bob", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("a save over a newer copy: %v", err)
	}
	if got := b.All()[compliance.Key("pci-dss", "10.6.1")]; got.By != "bob" || got.Status != compliance.External {
		t.Errorf("after the second save: %+v", got)
	}

	// Removing it removes it everywhere; removing it again is fine.
	if _, err := b.Set(ctx, "pci-dss", "10.6.1", "", "", "bob", now); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Set(ctx, "pci-dss", "10.6.1", "", "", "bob", now); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Set(ctx, "pci-dss", "10.6.1", "", "", "ann", now); err != nil {
		t.Fatalf("removing a note this server last saw: %v", err)
	}
	if len(a.All()) != 0 || len(b.All()) != 0 {
		t.Errorf("notes left: %v %v", a.All(), b.All())
	}
	// And it can be written again over its tombstone.
	if _, err := a.Set(ctx, "hipaa", "164.312(b)", compliance.External, "Audit controls in the EHR.", "ann", now); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.All()[compliance.Key("hipaa", "164.312(b)")]; !ok {
		t.Error("the HIPAA note is missing")
	}
}

func TestNotesPaused(t *testing.T) {
	c := newCluster(t)
	paused := &shared.PausedError{Why: "test"}
	n, _ := c.server("siem-a", func() error { return paused })
	if _, err := n.Set(context.Background(), "pci-dss", "10.6.1", compliance.External, "x", "ann", now); !errors.Is(err, paused) {
		t.Errorf("err = %v", err)
	}
	var closed Notes
	if closed.Err() == nil || len(closed.All()) != 0 {
		t.Error("a holder not tracked yet reads as open")
	}
}

func TestImporter(t *testing.T) {
	ctx := context.Background()
	c := newCluster(t)
	n, _ := c.server("siem-a", nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "compliance-notes.json")
	imp := Importer(n, func() string { return path })

	if src, err := imp.Source(); src != "" || err != nil {
		t.Errorf("no file: %q %v", src, err)
	}
	local := compliance.NewNotes(path)
	for _, x := range []struct{ fw, ctl, note string }{{"pci-dss", "10.6.1", "Chrony."}, {"nist-800-53", "AU-8", "Chrony too."}} {
		if _, err := local.Set(ctx, x.fw, x.ctl, compliance.External, x.note, "ann", now); err != nil {
			t.Fatal(err)
		}
	}
	// A note the cluster already has is kept.
	if _, err := n.Set(ctx, "pci-dss", "10.6.1", compliance.NotApplicable, "Not in scope.", "bob", now); err != nil {
		t.Fatal(err)
	}
	src, err := imp.Source()
	if err != nil || src == "" {
		t.Fatalf("source = %q %v", src, err)
	}
	if err := imp.Run(ctx, "ann"); err != nil {
		t.Fatal(err)
	}
	all := n.All()
	if all[compliance.Key("pci-dss", "10.6.1")].By != "bob" || all[compliance.Key("nist-800-53", "AU-8")].Note != "Chrony too." {
		t.Errorf("after the import: %+v", all)
	}

	// The export writes them back as a server on its own keeps them.
	outDir := t.TempDir()
	files, err := Exporter(n, func() string { return path }).Run(ctx, shared.ExportTarget{Under: func(p string) string { return filepath.Join(outDir, filepath.Base(p)) }})
	if err != nil || len(files) != 1 || files[0].Dest != path {
		t.Fatalf("export = %+v %v", files, err)
	}
	back := compliance.NewNotes(files[0].Path).All()
	if back[compliance.Key("pci-dss", "10.6.1")].By != "bob" || len(back) != 2 {
		t.Errorf("exported notes = %+v", back)
	}

	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := imp.Source(); err == nil {
		t.Error("a broken file was read")
	}
}
