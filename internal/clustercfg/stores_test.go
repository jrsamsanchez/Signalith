// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clustercfg

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tenants"
)

// The founder's tenants.json is imported into the shared list, and the
// export writes it back.
func TestTenantsImportAndExport(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	c := authConfig(t, dir, "")
	created := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	list := []tenants.Tenant{{ID: "acme", Name: "Acme", Created: created, CreatedBy: "sam"},
		{ID: "beta", Name: "Beta", Disabled: true, Created: created}}
	if err := tenants.WriteFile(c.TenantsFile(), list); err != nil {
		t.Fatal(err)
	}
	a := newAuthMember(t, o, "siem-a", dir, c, nil)
	a.cycle()
	got, ok := a.auth.TenantsKept()
	if !ok || len(got) != 2 || got[0].ID != "acme" || !got[1].Disabled {
		t.Fatalf("shared tenants = %+v %v", got, ok)
	}

	root := t.TempDir()
	var written []shared.ExportedFile
	for _, ex := range Exporters(a.docs, a.files) {
		if ex.Name != shared.ImportTenants {
			continue
		}
		var err error
		if written, err = ex.Run(context.Background(), exportUnder(t, dir, root)); err != nil {
			t.Fatal(err)
		}
	}
	if len(written) != 1 || written[0].Dest != c.TenantsFile() {
		t.Fatalf("written %+v", written)
	}
	reg, err := tenants.Open(written[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	back, err := reg.List()
	if err != nil || len(back) != 2 || back[0].Name != "Acme" || !back[1].Disabled {
		t.Errorf("exported tenants = %+v, %v", back, err)
	}
	if filepath.Dir(written[0].Path) == filepath.Dir(c.TenantsFile()) {
		t.Error("the export wrote over the server's own file")
	}
}

// The retention page saves a change against the revision it read: one
// made since is refused as stale.
func TestPolicyStoreUpdateIf(t *testing.T) {
	o := newOS(t)
	a := newMember(t, o, "siem-a", "", nil, nil)
	a.cycle()
	ps := &PolicyStore{Docs: a.docs}
	etag := ps.ETag()
	if etag == "" {
		t.Fatal("no etag for the shared policies")
	}
	if err := ps.UpdateIf(etag, func(s *retention.Saved) {
		s.Policies = map[string]retention.Policy{retention.Findings: {KeepDays: 40}}
	}); err != nil {
		t.Fatal(err)
	}
	saved, err := ps.Get()
	if err != nil || saved.Policies[retention.Findings].KeepDays != 40 {
		t.Errorf("saved = %+v, %v", saved, err)
	}
	// The same old etag again: stale.
	err = ps.UpdateIf(etag, func(s *retention.Saved) { s.Policies = nil })
	var stale *shared.StaleError
	if !errors.As(err, &stale) {
		t.Errorf("an update of an old revision: %v", err)
	}
	if saved, _ := ps.Get(); saved.Policies[retention.Findings].KeepDays != 40 {
		t.Errorf("the stale update changed the policies: %+v", saved)
	}
}

// The feed status store writes what was saved in the background, and
// what is left when it stops.
func TestStatusStoreRun(t *testing.T) {
	o := newOS(t)
	st := &StatusStore{Client: o.cl, Index: cluster.RuntimeIndex(testPrefix), Node: "n_siem-a",
		Leads: func() bool { return true }, Epoch: func() int64 { return 3 }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { st.Run(ctx); close(done) }()
	next := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	st.Save("feed-one", &intel.FeedStatus{NextRun: next, Count: 9, Running: true})
	cancel()
	<-done
	got, err := st.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s := got["feed-one"]
	if s == nil || s.Count != 9 || !s.NextRun.Equal(next) || s.Running {
		t.Errorf("stored status = %+v", s)
	}
	// Deleting it: saved as nil.
	st.Save("feed-one", nil)
	if n := st.Flush(context.Background()); n != 0 {
		t.Errorf("%d kept", n)
	}
	if got, _ := st.read(context.Background()); got["feed-one"] != nil {
		t.Errorf("deleted status still stored: %+v", got["feed-one"])
	}
	// A server that does not run the jobs keeps nothing.
	follower := &StatusStore{Client: o.cl, Index: cluster.RuntimeIndex(testPrefix), Leads: func() bool { return false }}
	follower.Save("feed-two", &intel.FeedStatus{Count: 1})
	if n := follower.Flush(context.Background()); n != 0 {
		t.Errorf("%d kept", n)
	}
	if got, _ := st.read(context.Background()); got["feed-two"] != nil {
		t.Error("a follower stored a status")
	}
}
