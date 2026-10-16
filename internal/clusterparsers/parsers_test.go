package clusterparsers

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/onboard"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const prefix = "signalith"

// Interface check: the API and the pipeline take either store.
var _ onboard.Store = (*Parsers)(nil)

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

func (c *cluster) server(name string, writable func() error) (*Parsers, *shared.Hub) {
	c.t.Helper()
	h := shared.NewHub(shared.Options{NodeName: name})
	h.SetKeys(shared.NewKeySet(c.key))
	h.Use(c.cl, prefix)
	p := New(writable)
	p.Track(h)
	if err := h.Cycle(context.Background()); err != nil {
		c.t.Fatal(err)
	}
	return p, h
}

var acme = onboard.Parser{Name: "acme", Sourcetype: "acme:fw", Model: "Network_Traffic", Format: onboard.FormatKV, KVSeparator: "=",
	Mappings: []onboard.Mapping{{From: "srcip", To: "src"}}}

// TestParsersShared: a parser saved on one server parses on another as
// soon as that server reads the shared settings.
func TestParsersShared(t *testing.T) {
	ctx := context.Background()
	c := newCluster(t)
	a, _ := c.server("siem-a", nil)
	b, hb := c.server("siem-b", nil)
	regB := onboard.NewRegistry(b)

	if err := a.Put(ctx, acme, "ann"); err != nil {
		t.Fatal(err)
	}
	if err := hb.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	got, ok := b.Get("acme")
	if !ok || got.UpdatedBy != "ann" || got.Sourcetype != "acme:fw" {
		t.Fatalf("siem-b reads %+v %v", got, ok)
	}
	ev, _, ok := regB.ParseCustom("acme", map[string]any{"log": "srcip=10.0.0.1"}, time.Now())
	if !ok || ev.Fields["src"] != "10.0.0.1" {
		t.Fatalf("siem-b parses %v %v", ev, ok)
	}

	// siem-b changes it without having read a's latest: the write retries.
	changed := acme
	changed.Mappings = []onboard.Mapping{{From: "srcip", To: "dest"}}
	if err := a.Put(ctx, changed, "ann"); err != nil {
		t.Fatal(err)
	}
	changed.Sourcetype = "acme:firewall"
	if err := b.Put(ctx, changed, "bob"); err != nil {
		t.Fatal(err)
	}
	if ev, _, _ := regB.ParseCustom("acme", map[string]any{"log": "srcip=10.0.0.1"}, time.Now()); ev.Fields["dest"] != "10.0.0.1" || ev.Fields["sourcetype"] != "acme:firewall" {
		t.Errorf("after the change siem-b parses %v", ev.Fields)
	}

	if err := b.Delete(ctx, "acme", "bob"); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(ctx, "acme", "bob"); !errors.Is(err, onboard.ErrNotFound) {
		t.Errorf("delete again = %v", err)
	}
	if _, _, ok := regB.ParseCustom("acme", map[string]any{"log": "x"}, time.Now()); ok {
		t.Error("a deleted parser still runs")
	}
}

func TestReadOnly(t *testing.T) {
	c := newCluster(t)
	ro := errors.New("a newer server holds the settings")
	p, _ := c.server("siem-a", func() error { return ro })
	if err := p.Put(context.Background(), acme, "ann"); !errors.Is(err, ro) {
		t.Errorf("put = %v", err)
	}
	if err := p.Delete(context.Background(), "acme", "ann"); !errors.Is(err, ro) {
		t.Errorf("delete = %v", err)
	}
}

// TestImportExport: a server's own parsers move into the cluster when it
// founds or joins one, keeping those the cluster has; export writes them
// back as the file.
func TestImportExport(t *testing.T) {
	ctx := context.Background()
	c := newCluster(t)
	p, _ := c.server("siem-a", nil)
	theirs := acme
	theirs.Sourcetype = "cluster:fw"
	if err := p.Put(ctx, theirs, "ann"); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, onboard.File)
	other := onboard.Parser{Name: "app", Sourcetype: "app:json", Model: "Other", Format: onboard.FormatJSON}
	if err := onboard.WriteFile(path, []onboard.Parser{acme, other}); err != nil {
		t.Fatal(err)
	}
	imp := Importer(p, func() string { return path })
	if src, err := imp.Source(); err != nil || src == "" {
		t.Fatalf("source = %q %v", src, err)
	}
	if err := imp.Run(ctx, "ann"); err != nil {
		t.Fatal(err)
	}
	if got, _ := p.Get("acme"); got.Sourcetype != "cluster:fw" {
		t.Errorf("the cluster's parser was replaced: %+v", got)
	}
	if _, ok := p.Get("app"); !ok {
		t.Error("the server's own parser was not imported")
	}

	out := t.TempDir()
	files, err := Exporter(p, func() string { return path }).Run(ctx, shared.ExportTarget{Under: func(s string) string { return filepath.Join(out, filepath.Base(s)) }})
	if err != nil || len(files) != 1 {
		t.Fatalf("export = %v %v", files, err)
	}
	back, err := onboard.ReadFile(files[0].Path)
	if err != nil || len(back) != 2 {
		t.Errorf("exported %v %v", back, err)
	}

	// No file: nothing to import.
	none := Importer(p, func() string { return filepath.Join(dir, "missing.json") })
	if src, err := none.Source(); err != nil || src != "" {
		t.Errorf("missing file source = %q %v", src, err)
	}
}
