package shared

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

// The cluster's certificate authority is handled only once the settings
// are shared, the cluster is at LevelSharedTLS and the tls importer ran.
func TestSharedTLSGate(t *testing.T) {
	e := newEnv(t)
	before := func() []Importer {
		return []Importer{{Name: ImportUsers, MinLevel: LevelSharedUsers}, {Name: ImportDirectory, MinLevel: LevelSharedUsers},
			{Name: ImportSettings, MinLevel: LevelSharedSettings}}
	}
	// A version that reads up to the level before founds the cluster.
	prev := e.server("siem-a", func(o *RuntimeOptions) {
		o.levelMax = LevelSharedTLS - 1
		o.Importers = before()
	})
	prev.holds.Store(true)
	prev.step()
	prev.wantMode(ModeMember)
	wantLevel(t, e, LevelSharedTLS-1)
	if !prev.rt.SharedSettings() || prev.rt.SharedTLS() {
		t.Fatalf("settings shared %v, tls %v below its level", prev.rt.SharedSettings(), prev.rt.SharedTLS())
	}
	k := prev.key()

	var peers peerList
	self := Peer{NodeID: "n_siem-a", Name: "siem-a", Live: true, LevelMax: LevelMax}
	other := Peer{NodeID: "n_siem-b", Name: "siem-b", Live: true, LevelMax: LevelSharedTLS - 1}
	peers.set(self, other)
	var fail atomic.Bool
	fail.Store(true)
	var runs atomic.Int32
	tlsIm := Importer{Name: ImportTLS, MinLevel: LevelSharedTLS, Source: func() (string, error) { return "h-ca", nil },
		Run: func(context.Context, string) error {
			runs.Add(1)
			if fail.Load() {
				return errors.New("cannot reach OpenSearch")
			}
			return nil
		}}
	a := e.server("siem-a", func(o *RuntimeOptions) {
		o.KeyFile = writeKeyFile(t, k)
		o.Peers = peers.get
		// Reads up to this level, whatever levels come after it.
		o.levelMax = LevelSharedTLS
		o.Importers = append(before(), tlsIm)
	})
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	wantLevel(t, e, LevelSharedTLS-1)
	if a.rt.SharedTLS() || runs.Load() != 0 {
		t.Fatalf("tls %v, import ran %d times below the level", a.rt.SharedTLS(), runs.Load())
	}

	// Every server reads the level: it goes up, and the gate opens once
	// the import is recorded.
	other.LevelMax = LevelMax
	peers.set(self, other)
	a.step()
	wantLevel(t, e, LevelSharedTLS)
	if runs.Load() != 1 || a.rt.SharedTLS() {
		t.Fatalf("import ran %d times; tls %v before it was done", runs.Load(), a.rt.SharedTLS())
	}
	fail.Store(false)
	a.step()
	body := wantLevel(t, e, LevelSharedTLS)
	if body.Import.Done[ImportTLS] != "h-ca" || !a.rt.SharedTLS() || !a.rt.SharedSettings() {
		t.Fatalf("import %+v, tls %v", body.Import, a.rt.SharedTLS())
	}
}

// FlushCacheBody says when this server keeps no copy of the shared
// settings, rather than nil: here the runtime is stepped by hand, so its
// cache writer never starts. (The server that publishes its certificate
// authority reads the copy back before deleting ca.key: see
// TestClusterCAAcrossServers in cmd/signalith.)
func TestFlushCacheBodyWithoutCopy(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	if _, err := a.rt.FlushCacheBody(ClusterDocID); !errors.Is(err, ErrNoCache) {
		t.Fatalf("before the cluster: %v", err)
	}
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	if _, err := a.rt.FlushCacheBody(ClusterDocID); !errors.Is(err, ErrNoCache) {
		t.Fatalf("a member without a copy: %v", err)
	}
}
