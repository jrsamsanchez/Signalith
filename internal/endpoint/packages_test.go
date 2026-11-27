// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package endpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

func TestPackagesQueryOnlyOnLinux(t *testing.T) {
	for _, p := range Platforms {
		raw, _ := Config(p, DefaultSettings())
		var cfg struct {
			Schedule map[string]struct {
				Query    string `json:"query"`
				Interval int    `json:"interval"`
				Snapshot bool   `json:"snapshot"`
			} `json:"schedule"`
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatal(err)
		}
		q, ok := cfg.Schedule[QueryPrefix+qPackages]
		if ok != (p == Linux) {
			t.Errorf("%s: packages query scheduled = %v", p, ok)
		}
		if ok && (!q.Snapshot || q.Interval != packagesInterval || !strings.Contains(q.Query, "deb_packages") ||
			!strings.Contains(q.Query, "rpm_packages") || !strings.Contains(q.Query, "epoch") || !strings.Contains(q.Query, "os_version")) {
			t.Errorf("packages query = %+v", q)
		}
	}
}

func TestParseResultsPackages(t *testing.T) {
	n := &Node{ID: "n1", Hostname: "web1", Platform: Linux}
	now := time.Now().UTC().Truncate(time.Second)
	sent := now.Add(-time.Minute)
	snap := `{"name":"signalith_packages","unixTime":` + strconv.FormatInt(sent.Unix(), 10) + `,"snapshot":[` +
		`{"name":"openssh-server","version":"1:8.9p1-3ubuntu0.1","source":"openssh","type":"deb"},` +
		`{"name":"libssl3","version":"3.0.2-0ubuntu1.10","source":"openssl","type":"deb"},` +
		`{"name":"ubuntu","version":"22.4","source":"debian","type":"os"},` +
		`{"name":"","version":"1","type":"deb"},` +
		`{"name":"x","version":"1","type":"windows"}]}`
	b := ParseResults(n, lines(t, snap,
		// A differential result is not a whole list: ignored.
		`{"name":"signalith_packages","diffResults":{"added":[{"name":"vim","version":"2","type":"deb"}]}}`,
	), now)
	if len(b.Events) != 0 || b.Skipped != 0 {
		t.Errorf("package lists are not events: %d events, %d skipped", len(b.Events), b.Skipped)
	}
	pl := b.Packages
	if pl == nil {
		t.Fatal("no package list")
	}
	if pl.OS != "ubuntu" || pl.OSVersion != "22.4" || pl.OSLike != "debian" || !pl.At.Equal(sent) {
		t.Errorf("system = %+v", pl)
	}
	if len(pl.Packages) != 2 || pl.Packages[0].Name != "libssl3" || pl.Packages[1] != (Package{Name: "openssh-server", Version: "1:8.9p1-3ubuntu0.1", Source: "openssh", Type: "deb"}) {
		t.Errorf("packages = %+v", pl.Packages)
	}
	// Only differential rows: no list.
	if b := ParseResults(n, lines(t, `{"name":"signalith_packages","diffResults":{"added":[{"name":"vim","version":"2","type":"deb"}]}}`), now); b.Packages != nil {
		t.Errorf("differential rows made a list: %+v", b.Packages)
	}
}

func TestSaveAndListPackages(t *testing.T) {
	ctx := context.Background()
	d := NewMemoryDocs()
	s := NewStore(d, "sig")
	clock := time.Now().UTC()
	s.Now = func() time.Time { return clock }
	n, _ := enroll(t, s, "uuid-1", "web1")
	win := &Node{ID: "w1", HostIdentifier: "uuid-2", Hostname: "pc1", Platform: Windows, EnrolledAt: clock}
	if err := s.Enroll(ctx, win); err != nil {
		t.Fatal(err)
	}
	pl := &PackageList{OS: "debian", OSVersion: "12.5", At: clock, Packages: []Package{{Name: "bash", Version: "5.2.15-2+b2", Type: "deb"}}}
	if err := s.SavePackages(ctx, n, pl); err != nil {
		t.Fatal(err)
	}
	// A Windows host's stray list is never listed.
	if err := s.SavePackages(ctx, win, pl); err != nil {
		t.Fatal(err)
	}
	got, err := s.HostPackages(ctx)
	if err != nil || len(got) != 1 {
		t.Fatalf("HostPackages = %+v, %v", got, err)
	}
	h := got[0]
	if h.NodeID != n.ID || h.Hostname != "web1" || h.OS != "debian" || len(h.Packages) != 1 || !h.Changed.Equal(clock) || h.Hash == "" {
		t.Errorf("host = %+v", h)
	}
	// The same list later only moves its time.
	clock = clock.Add(6 * time.Hour)
	same := *pl
	same.At = clock
	if err := s.SavePackages(ctx, n, &same); err != nil {
		t.Fatal(err)
	}
	got, _ = s.HostPackages(ctx)
	if !got[0].At.Equal(clock) || !got[0].Changed.Equal(clock.Add(-6*time.Hour)) || got[0].Hash != h.Hash {
		t.Errorf("unchanged list = at %v changed %v", got[0].At, got[0].Changed)
	}
	// A changed list is written whole.
	changed := same
	changed.Packages = []Package{{Name: "bash", Version: "5.2.15-2+b3", Type: "deb"}}
	if err := s.SavePackages(ctx, n, &changed); err != nil {
		t.Fatal(err)
	}
	got, _ = s.HostPackages(ctx)
	if got[0].Packages[0].Version != "5.2.15-2+b3" || got[0].Hash == h.Hash || !got[0].Changed.Equal(clock) {
		t.Errorf("changed list = %+v", got[0])
	}
	// Removing the host drops its list.
	if _, err := s.Remove(ctx, n.ID, false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, _, found, _ := d.Get(ctx, "", packagesDocID(n.ID)); found {
		t.Error("package list kept after the host was removed")
	}
}

func TestPackageListCaps(t *testing.T) {
	rows := make([]map[string]any, 0, maxPackages+10)
	for i := range maxPackages + 10 {
		rows = append(rows, map[string]any{"name": "p" + strconv.Itoa(i), "version": strings.Repeat("1", 500), "type": "rpm"})
	}
	pl := packageList(rows, time.Now())
	if len(pl.Packages) != maxPackages || len(pl.Packages[0].Version) != maxPackageField {
		t.Errorf("kept %d packages, version of %d bytes", len(pl.Packages), len(pl.Packages[0].Version))
	}
}

// countingDocs counts single-document reads of package lists.
type countingDocs struct {
	*MemoryDocs
	gets, mgets int
}

func (c *countingDocs) Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error) {
	if strings.HasPrefix(id, "pkg:") {
		c.gets++
	}
	return c.MemoryDocs.Get(ctx, index, id)
}

func (c *countingDocs) MGet(ctx context.Context, refs []store.Ref) ([]store.Doc, error) {
	c.mgets++
	return c.MemoryDocs.MGet(ctx, refs)
}

func TestHostPackagesReadsInBatches(t *testing.T) {
	ctx := context.Background()
	d := &countingDocs{MemoryDocs: NewMemoryDocs()}
	s := NewStore(d, "sig")
	clock := time.Now().UTC()
	s.Now = func() time.Time { return clock }
	const hosts = packagesBatch*2 + 3
	for i := range hosts {
		n := &Node{ID: fmt.Sprintf("n%03d", i), HostIdentifier: fmt.Sprintf("uuid-%d", i), Hostname: fmt.Sprintf("web%03d", i), Platform: Linux, EnrolledAt: clock}
		if err := s.Enroll(ctx, n); err != nil {
			t.Fatal(err)
		}
		// One host has sent no list yet.
		if i == 7 {
			continue
		}
		pl := &PackageList{OS: "debian", OSVersion: "12", At: clock, Packages: []Package{{Name: "bash", Version: fmt.Sprint(i), Type: "deb"}}}
		if err := s.SavePackages(ctx, n, pl); err != nil {
			t.Fatal(err)
		}
	}
	d.gets = 0
	got, err := s.HostPackages(ctx)
	if err != nil || len(got) != hosts-1 {
		t.Fatalf("HostPackages = %d lists, %v", len(got), err)
	}
	if d.gets != 0 || d.mgets != 3 {
		t.Errorf("reads = %d gets, %d batches; want 0 gets and 3 batches", d.gets, d.mgets)
	}
	for _, hp := range got {
		if hp.NodeID == "n007" {
			t.Error("a host with no list was listed")
		}
		if want := "web" + strings.TrimPrefix(hp.NodeID, "n"); hp.Hostname != want || hp.Packages[0].Version != fmt.Sprint(mustAtoi(t, strings.TrimPrefix(hp.NodeID, "n"))) {
			t.Errorf("list of %s = %+v", hp.NodeID, hp)
		}
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
