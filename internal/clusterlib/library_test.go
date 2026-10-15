package clusterlib

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

var ctx = context.Background()

func TestDetectionEditedOnOneServerShowsOnTheOther(t *testing.T) {
	_, a, b := pair(t)
	d := custom("my-rule", "Many failures")
	if err := a.lib.PutIf(ctx, "alice", d, ""); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	got, err := b.lib.Get("my-rule")
	if err != nil {
		t.Fatalf("B does not see the rule A saved: %v", err)
	}
	if got.Title != "Many failures" || got.Source != "custom" {
		t.Fatalf("B sees %+v", got)
	}
	if by, node, _ := b.lib.Changed("my-rule"); by != "alice" || node != "siem-a" {
		t.Fatalf("changed by %q on %q", by, node)
	}
	// Turning a shipped rule on or off on B records only that choice,
	// and A sees it.
	id, on := builtinID(t)
	if err := b.lib.SetEnabledBy(ctx, "bob", []string{id, "my-rule"}, !on); err != nil {
		t.Fatal(err)
	}
	a.cycle()
	got, _ = a.lib.Get(id)
	if got.Enabled == on || got.Source != "builtin" {
		t.Fatalf("A sees the shipped rule as %+v", got)
	}
	if got, _ := a.lib.Get("my-rule"); got.Enabled == true {
		t.Fatal("A does not see my-rule turned off")
	}
	// Nothing went to the folders: the library keeps them in the shared
	// settings.
	if _, err := os.Stat(filepath.Join(a.detDir, "my-rule.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the library wrote its folder: %v", err)
	}
	// Deleting it leaves a tombstone, so B drops it.
	if err := b.lib.DeleteIf(ctx, "bob", "my-rule", b.lib.ETag("my-rule")); err != nil {
		t.Fatal(err)
	}
	a.cycle()
	if _, err := a.lib.Get("my-rule"); !errors.Is(err, detect.ErrNotFound) {
		t.Fatalf("A still has the deleted rule: %v", err)
	}
	if _, _, ok := a.docs.Detections().Get("my-rule"); ok {
		t.Fatal("the collection still lists the deleted rule")
	}
}

func TestConcurrentDetectionEditsOneIsStale(t *testing.T) {
	_, a, b := pair(t)
	if err := a.lib.PutIf(ctx, "alice", custom("my-rule", "One"), ""); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	etag := a.lib.ETag("my-rule")
	if etag == "" || etag != b.lib.ETag("my-rule") {
		t.Fatalf("ETags differ: %q and %q", etag, b.lib.ETag("my-rule"))
	}
	if err := a.lib.PutIf(ctx, "alice", custom("my-rule", "Two"), etag); err != nil {
		t.Fatal(err)
	}
	// B has not seen A's change: the backend reads it before it writes,
	// and refuses B's page.
	err := b.lib.PutIf(ctx, "bob", custom("my-rule", "Three"), etag)
	var stale *detect.StaleError
	if !errors.As(err, &stale) {
		t.Fatalf("B's edit over a stale version: %v", err)
	}
	if stale.By != "alice" || stale.Node != "siem-a" || stale.At == "" {
		t.Fatalf("stale error says %+v", stale)
	}
	// Without an ETag (a script) it applies to the latest version.
	if err := b.lib.PutIf(ctx, "bob", custom("my-rule", "Three"), ""); err != nil {
		t.Fatal(err)
	}
	a.cycle()
	if got, _ := a.lib.Get("my-rule"); got.Title != "Three" {
		t.Fatalf("A sees %q", got.Title)
	}
	// Exceptions follow the same rule.
	_, err = a.lib.UpdateExceptionsIf(ctx, "alice", "my-rule", etag, func(es []detect.Exception) ([]detect.Exception, error) { return es, nil })
	if !errors.As(err, &stale) {
		t.Fatalf("an exception change over a stale version: %v", err)
	}
}

func TestManyDetectionsTurnedOnInOneBatch(t *testing.T) {
	o, a, b := pair(t)
	all := a.lib.List()
	var ids []string
	for _, d := range all {
		if d.Source == "pack" && !d.Enabled {
			ids = append(ids, d.ID)
		}
		if len(ids) == 50 {
			break
		}
	}
	if len(ids) < 10 {
		t.Skip("not enough pack rules")
	}
	o.fake.Requests()
	if err := a.lib.SetEnabledBy(ctx, "alice", ids, true); err != nil {
		t.Fatal(err)
	}
	bumps := 0
	for _, r := range o.fake.Requests() {
		if strings.Contains(r, "watch%3Adetections") || strings.Contains(r, "watch:detections") {
			bumps++
		}
	}
	if bumps != 1 {
		t.Fatalf("%d bumps of the watch document for one batch", bumps)
	}
	b.cycle()
	for _, id := range ids {
		if d, _ := b.lib.Get(id); !d.Enabled {
			t.Fatalf("B does not see %s turned on", id)
		}
	}
	// Turning them on again writes nothing.
	o.fake.Requests()
	if err := a.lib.SetEnabledBy(ctx, "alice", ids, true); err != nil {
		t.Fatal(err)
	}
	for _, r := range o.fake.Requests() {
		if strings.Contains(r, "detection%3A") || strings.Contains(r, "detection:") {
			t.Fatalf("a change to nothing wrote %s", r)
		}
	}
}

func TestForgedDetectionIsNotUsed(t *testing.T) {
	o, a, b := pair(t)
	if err := a.lib.PutIf(ctx, "alice", custom("my-rule", "Real"), ""); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	// Someone with write access to OpenSearch changes the rule without
	// the cluster key.
	idx := shared.ConfigIndex(testPrefix)
	src := o.fake.Source(idx, "detection:my-rule")
	src["body"] = strings.Replace(src["body"].(string), "Real", "Forged", 1)
	o.fake.Put(idx, "detection:my-rule", src)
	if _, err := a.docs.Hub().Bump(ctx, DetectionWatch); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if got, _ := b.lib.Get("my-rule"); got == nil || got.Title != "Real" {
		t.Fatalf("B uses the forged rule: %+v", got)
	}
	if len(b.rt.Hub().Tamper()) == 0 {
		t.Fatal("the forged document is not reported")
	}
}

func TestUnknownFieldsRoundTrip(t *testing.T) {
	o, a, b := pair(t)
	if err := a.lib.PutIf(ctx, "alice", custom("my-rule", "One"), ""); err != nil {
		t.Fatal(err)
	}
	// A newer version adds a field to the body.
	c := a.docs.Detections()
	if _, err := c.Mutate(ctx, "newer", "my-rule", func(b *DetectionBody) error {
		b.Extra = shared.Extra{"owner": json.RawMessage(`"soc-team"`)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if err := b.lib.PutIf(ctx, "bob", custom("my-rule", "Two"), ""); err != nil {
		t.Fatal(err)
	}
	src := o.fake.Source(shared.ConfigIndex(testPrefix), "detection:my-rule")
	var body map[string]any
	if err := json.Unmarshal([]byte(src["body"].(string)), &body); err != nil {
		t.Fatal(err)
	}
	if got := body["owner"]; got != "soc-team" || !strings.Contains(body["yaml"].(string), "Two") {
		t.Fatalf("the field a newer version wrote was lost: %v", src["body"])
	}
}

func TestDashboardsShared(t *testing.T) {
	_, a, b := pair(t)
	d := board("ops-overview", "Ops overview")
	if err := a.boards.Create(ctx, "alice", d); err != nil {
		t.Fatal(err)
	}
	if err := b.boards.Create(ctx, "bob", board("ops-overview", "Mine")); !errors.Is(err, dashboards.ErrExists) {
		t.Fatalf("a second dashboard with a taken id: %v", err)
	}
	b.cycle()
	list, _, err := b.boards.List()
	if err != nil || len(list) != 1 || list[0].Title != "Ops overview" {
		t.Fatalf("B lists %v (%v)", list, err)
	}
	_, etag, err := b.boards.GetETag("ops-overview")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.boards.Update(ctx, "alice", "ops-overview", etag, func(d *dashboards.Dashboard) error {
		d.Title = "Ops"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c := board("ops-overview", "Bob's")
	var stale *detect.StaleError
	if err := b.boards.PutIf(ctx, "bob", c, etag); !errors.As(err, &stale) || stale.By != "alice" {
		t.Fatalf("B saved over a stale version: %v", err)
	}
	b.cycle()
	_, etag, _ = b.boards.GetETag("ops-overview")
	if err := b.boards.DeleteIf(ctx, "bob", "ops-overview", etag); err != nil {
		t.Fatal(err)
	}
	a.cycle()
	if a.boards.Exists("ops-overview") {
		t.Fatal("A still has the deleted dashboard")
	}
	if err := a.boards.DeleteIf(ctx, "alice", "ops-overview", ""); !errors.Is(err, dashboards.ErrNotFound) {
		t.Fatalf("deleting a deleted dashboard: %v", err)
	}
}

func TestWritesPausedWhenDegraded(t *testing.T) {
	_, a, _ := pair(t)
	paused := &shared.PausedError{Why: "test"}
	be := &Detections{Docs: a.docs, Writable: func() error { return paused }}
	lib, _, _ := detect.NewLibrary("")
	if err := lib.UseBackend(be); err != nil {
		t.Fatal(err)
	}
	var p *shared.PausedError
	if err := lib.PutIf(ctx, "alice", custom("my-rule", "One"), ""); !errors.As(err, &p) {
		t.Fatalf("a write while paused: %v", err)
	}
}
