// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"testing"
	"time"
)

// Every level from shared users on has a feature, so a new level cannot
// be added without saying what it greys out while versions are mixed.
func TestEveryLevelHasAFeature(t *testing.T) {
	levels := map[int]bool{}
	names := map[string]bool{}
	for _, f := range Features {
		if f.Name == "" || f.Label == "" || f.On == nil {
			t.Errorf("feature %+v is incomplete", f)
		}
		if names[f.Name] {
			t.Errorf("feature %s listed twice", f.Name)
		}
		names[f.Name] = true
		levels[f.Level] = true
	}
	for l := LevelSharedUsers; l <= LevelMax; l++ {
		if !levels[l] {
			t.Errorf("level %d has no entry in Features", l)
		}
	}
}

func featureState(t *testing.T, states []FeatureState, name string) FeatureState {
	t.Helper()
	for _, s := range states {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no feature %s in %+v", name, states)
	return FeatureState{}
}

func TestFeatureStates(t *testing.T) {
	self := Peer{NodeID: "n_siem-a", Name: "siem-a", Live: true, LevelMax: LevelMax, Version: "1.6.0"}
	old := Peer{NodeID: "n_siem-old", Name: "siem-old", Live: true, Version: "1.5.0"}
	t.Run("not a member", func(t *testing.T) {
		e := newEnv(t)
		a := e.server("siem-a", func(o *RuntimeOptions) { o.KeyFile = "" })
		for _, s := range a.rt.FeatureStates() {
			if s.On || s.Why != "This server is not a member of a cluster" {
				t.Errorf("%+v", s)
			}
		}
	})
	t.Run("level below", func(t *testing.T) {
		e := newEnv(t)
		var peers peerList
		gone := Peer{NodeID: "n_siem-gone", Name: "siem-gone", SeenAgo: LevelSeen + time.Hour}
		recent := Peer{NodeID: "n_siem-off", Name: "siem-off", SeenAgo: time.Hour, Version: "1.4.0"}
		peers.set(self, old, gone, recent)
		a := e.server("siem-a", func(o *RuntimeOptions) {
			o.Peers = peers.get
			o.Version = "1.6.0"
		})
		a.holds.Store(true)
		a.step()
		a.wantMode(ModeMember)
		wantLevel(t, e, 1)
		s := featureState(t, a.rt.FeatureStates(), "api_tokens")
		if s.On || s.Why != "Available when every server runs 1.6.0 or later" || s.Level != LevelAPITokens {
			t.Errorf("api_tokens %+v", s)
		}
		if len(s.Waiting) != 2 || s.Waiting[0].Name != "siem-off" || s.Waiting[1].Name != "siem-old" {
			t.Errorf("waiting %+v: want the servers seen in 24 hours, this one left out", s.Waiting)
		}
	})
	t.Run("import pending, then on", func(t *testing.T) {
		e := newEnv(t)
		a := e.server("siem-a", func(o *RuntimeOptions) { o.Version = "1.6.0" })
		a.holds.Store(true)
		a.step()
		a.wantMode(ModeMember)
		wantLevel(t, e, LevelMax)
		s := featureState(t, a.rt.FeatureStates(), "shared_users")
		if s.On || s.Why != "Waiting for siem-a to bring in its files" || len(s.Waiting) != 0 {
			t.Errorf("shared_users %+v", s)
		}
		if _, err := a.rt.Cluster().Mutate(context.Background(), "test", func(b *ClusterBody) error {
			if b.Import.Done == nil {
				b.Import.Done = map[string]string{}
			}
			for _, name := range []string{ImportUsers, ImportDirectory, ImportSettings, ImportRetentionHistory, ImportArchives, ImportTLS,
				ImportDetections, ImportDashboards, ImportLookups, ImportTenants} {
				b.Import.Done[name] = "none"
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for _, s := range a.rt.FeatureStates() {
			if !s.On || s.Why != "" {
				t.Errorf("%+v is not on", s)
			}
		}
	})
}
