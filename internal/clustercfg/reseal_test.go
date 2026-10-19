// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clustercfg

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// A server joining with --merge adds the shared settings its own files
// set and the cluster lacks, and reports those whose values differ,
// keeping the cluster's.
func TestMergeSettings(t *testing.T) {
	o := newOS(t)
	dirA := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dirA, authConfig(t, dirA, "search:\n  max_events: 500\nassistant:\n  api_key: test-key-of-a\n"), nil)
	a.cycle()
	dirB := t.TempDir()
	b := newAuthMember(t, o, "siem-b", dirB, authConfig(t, dirB,
		"search:\n  max_events: 777\n  default_earliest: -24h\nassistant:\n  api_key: test-key-of-b\n"), a.key())
	b.cycle()
	ctx := context.Background()
	rep, err := Merge(ctx, b.docs, b.files, "signalith join", MergeOptions{Settings: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := itemIDs(rep.Added, MergeSetting); !slices.Equal(got, []string{"search.default_earliest"}) {
		t.Errorf("settings added %v", got)
	}
	if got := itemIDs(rep.Differ, MergeSetting); !slices.Equal(got, []string{"assistant.api_key", "search.max_events"}) {
		t.Errorf("settings differing %v", got)
	}
	for _, it := range rep.Differ {
		switch it.ID {
		case "search.max_events":
			if !strings.Contains(it.Detail, "777 here, 500 in the cluster") {
				t.Errorf("max_events: %q", it.Detail)
			}
		case "assistant.api_key":
			if strings.Contains(it.Detail, "test-key") {
				t.Errorf("a report item shows a secret: %q", it.Detail)
			}
		}
	}
	a.cycle()
	if v, ok := a.setting("search.max_events"); !ok || rawString(v.Value) != "500" {
		t.Errorf("the cluster's max_events = %+v %v", v, ok)
	}
	if v, ok := a.setting("search.default_earliest"); !ok || rawString(v.Value) != `"-24h"` {
		t.Errorf("the added default_earliest = %+v %v", v, ok)
	}
	// Again: nothing more to add.
	b.cycle()
	again, err := Merge(ctx, b.docs, b.files, "signalith join", MergeOptions{Settings: true})
	if err != nil || len(itemIDs(again.Added, MergeSetting)) != 0 {
		t.Errorf("merge again: %v %+v", err, again)
	}
}

// The default policy and the disk guard merge as the policies do: added
// when the cluster has none, reported and held when they differ.
func TestMergeRetentionDefaultAndGuard(t *testing.T) {
	ctx := context.Background()
	withRetention := func(t *testing.T, dir string, def int, disk int) *config.Config {
		c := authConfig(t, dir, "")
		if err := retention.NewStore(RetentionFile(c)).Update(func(s *retention.Saved) {
			if def > 0 {
				s.Default = &retention.Policy{KeepDays: def}
			}
			if disk > 0 {
				s.Guard = &retention.Guard{MaxDiskPercent: disk, MinDays: 3}
			}
		}); err != nil {
			t.Fatal(err)
		}
		return c
	}

	t.Run("added", func(t *testing.T) {
		o := newOS(t)
		dirA := t.TempDir()
		a := newAuthMember(t, o, "siem-a", dirA, authConfig(t, dirA, ""), nil)
		dirB := t.TempDir()
		b := newAuthMember(t, o, "siem-b", dirB, withRetention(t, dirB, 100, 80), a.key())
		b.cycle()
		rep, err := Merge(ctx, b.docs, b.files, "signalith join", MergeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if got := itemIDs(rep.Added, MergeRetention); !slices.Equal(got, []string{"default", "guard"}) {
			t.Errorf("added %v", got)
		}
		a.cycle()
		rb, _ := a.docs.Retention().Get()
		if rb.Default == nil || rb.Default.KeepDays != 100 || rb.Guard == nil || rb.Guard.MaxDiskPercent != 80 || rb.Confirm != nil {
			t.Errorf("shared retention = %+v", rb)
		}
	})
	t.Run("differ", func(t *testing.T) {
		o := newOS(t)
		dirA := t.TempDir()
		a := newAuthMember(t, o, "siem-a", dirA, withRetention(t, dirA, 200, 85), nil)
		dirB := t.TempDir()
		b := newAuthMember(t, o, "siem-b", dirB, withRetention(t, dirB, 100, 80), a.key())
		b.cycle()
		rep, err := Merge(ctx, b.docs, b.files, "signalith join", MergeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if got := itemIDs(rep.Differ, MergeRetention); !slices.Equal(got, []string{"default", "guard"}) {
			t.Errorf("differ %v", got)
		}
		if !rep.Held {
			t.Error("differing defaults did not hold retention")
		}
		a.cycle()
		rb, _ := a.docs.Retention().Get()
		if rb.Default == nil || rb.Default.KeepDays != 200 || rb.Guard.MaxDiskPercent != 85 {
			t.Errorf("the cluster's retention changed: %+v", rb)
		}
	})
	t.Run("no cluster key", func(t *testing.T) {
		if _, err := Merge(ctx, NewDocs(), Files{}, "x", MergeOptions{}); err == nil {
			t.Error("merged without a cluster key")
		}
	})
}

// A key rotation seals the shared settings' secrets again: the new key
// alone then opens them, and a second run changes nothing.
func TestResealSharedSettings(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dir, authConfig(t, dir, "assistant:\n  api_key: test-assistant-key\n"), nil)
	a.cycle()
	ctx := context.Background()
	if err := Resealer(NewDocs())(ctx); err != nil {
		t.Errorf("without shared settings: %v", err)
	}
	sv, ok := a.setting("assistant.api_key")
	if !ok || sv.Secret == "" {
		t.Fatalf("assistant.api_key = %+v %v", sv, ok)
	}
	old := a.key()
	if secrets.KeyID(sv.Secret) != old.ID() {
		t.Fatalf("sealed with %q", secrets.KeyID(sv.Secret))
	}
	k2, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	h := a.rt.Hub()
	h.SetKeys(shared.NewKeySet(k2, old))
	if err := Resealer(a.docs)(ctx); err != nil {
		t.Fatal(err)
	}
	sv, _ = a.setting("assistant.api_key")
	if secrets.KeyID(sv.Secret) != k2.ID() {
		t.Errorf("after the reseal, sealed with %q", secrets.KeyID(sv.Secret))
	}
	plain, err := openFor(shared.NewKeySet(k2), "assistant.api_key", sv.Secret, sv.SentTo)
	if err != nil || plain != "test-assistant-key" {
		t.Errorf("the new key opens %q, %v", plain, err)
	}
	// A key this server lacks: the reseal fails rather than lose it.
	k3, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	h.SetKeys(shared.NewKeySet(k3))
	if err := Resealer(a.docs)(ctx); err == nil {
		t.Error("resealed a value no key of this server opens")
	}
}
