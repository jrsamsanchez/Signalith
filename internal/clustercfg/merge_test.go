// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clustercfg

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// prepareServer gives the server of c users, retention policies saved on
// its page and feeds added on its page.
func prepareServer(t *testing.T, c *config.Config, us []users.NewUser, policies map[string]retention.Policy, feeds []intel.FeedSpec) {
	t.Helper()
	ctx := users.WithActor(context.Background(), "sam")
	fs, err := users.Open(c.UsersFile())
	if err != nil {
		t.Fatal(err)
	}
	for _, nu := range us {
		if _, err := fs.Create(ctx, nu); err != nil {
			t.Fatal(err)
		}
	}
	if err := retention.NewStore(RetentionFile(c)).Update(func(s *retention.Saved) { s.Policies = policies }); err != nil {
		t.Fatal(err)
	}
	if _, err := (&intel.FileList{Path: c.IntelFeedsFile()}).Mutate(ctx, "", func(s *intel.FeedSet) error {
		s.UI = feeds
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func itemIDs(items []MergeItem, kind string) []string {
	var out []string
	for _, it := range items {
		if it.Kind == kind {
			out = append(out, it.ID)
		}
	}
	slices.Sort(out)
	return out
}

// A server with files of its own joins with --merge: what the cluster
// lacks is added, what it has is kept, and what differs is reported, the
// retention policies held until an admin confirms them.
func TestMerge(t *testing.T) {
	o := newOS(t)
	dirA := t.TempDir()
	cA := authConfig(t, dirA, "")
	prepareServer(t, cA, []users.NewUser{{Username: "jlee", Role: users.Analyst, Password: "a-good-password"}},
		map[string]retention.Policy{"findings": {KeepDays: 30}},
		[]intel.FeedSpec{{Name: "shared", URL: "https://a.example.com/l", Format: "lines", Type: "ip"}})
	a := newAuthMember(t, o, "siem-a", dirA, authConfig(t, dirA, ""), nil)

	dirB := t.TempDir()
	cB := authConfig(t, dirB, "")
	prepareServer(t, cB, []users.NewUser{{Username: "jlee", Role: users.Admin, Password: "another-good-password"},
		{Username: "newbie", Role: users.Viewer, Password: "a-good-password"}, {Username: "admin", Role: users.Admin, Password: "a-good-password"}},
		map[string]retention.Policy{"findings": {KeepDays: 60}, "cases": {KeepDays: 10}},
		[]intel.FeedSpec{{Name: "shared", URL: "https://b.example.com/l", Format: "lines", Type: "ip"},
			{Name: "mine", URL: "https://mine.example.com/l", Format: "lines", Type: "domain"}})
	b := newAuthMember(t, o, "siem-b", dirB, authConfig(t, dirB, ""), a.key())

	ctx := context.Background()
	rep, err := Merge(ctx, b.docs, b.files, "signalith join", MergeOptions{Users: true, Settings: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := itemIDs(rep.Added, MergeFeed); !slices.Equal(got, []string{"mine"}) {
		t.Errorf("feeds added %v", got)
	}
	if got := itemIDs(rep.Added, MergeRetention); !slices.Equal(got, []string{"cases"}) {
		t.Errorf("policies added %v", got)
	}
	if got := itemIDs(rep.Added, MergeUser); !slices.Equal(got, []string{"newbie"}) {
		t.Errorf("users added %v", got)
	}
	if got := itemIDs(rep.Differ, MergeFeed); !slices.Equal(got, []string{"shared"}) {
		t.Errorf("feeds differing %v", got)
	}
	if got := itemIDs(rep.Differ, MergeRetention); !slices.Equal(got, []string{"findings"}) {
		t.Errorf("policies differing %v", got)
	}
	if got := itemIDs(rep.Differ, MergeUser); !slices.Equal(got, []string{"admin", "jlee"}) {
		t.Errorf("users differing %v", got)
	}
	for _, it := range rep.Differ {
		if strings.Contains(it.Detail, "$2") || strings.Contains(it.Detail, "password-") {
			t.Errorf("a report item shows a secret: %+v", it)
		}
		if it.ID == "jlee" && !strings.Contains(it.Detail, "role admin here, analyst in the cluster") {
			t.Errorf("jlee: %q", it.Detail)
		}
	}
	if !rep.Held {
		t.Error("differing policies did not hold retention")
	}

	// The cluster kept its own, and has what it lacked.
	a.cycle()
	rb, _ := a.docs.Retention().Get()
	if rb.Policies["findings"].KeepDays != 30 || rb.Policies["cases"].KeepDays != 10 {
		t.Errorf("shared policies %+v", rb.Policies)
	}
	if rb.Confirm == nil || rb.Confirm.Reason != ConfirmMerge || rb.Confirm.Servers["siem-b"] == "" {
		t.Errorf("hold %+v", rb.Confirm)
	}
	recs, _ := (&clusterauth.UsersBackend{Docs: a.auth}).Load()
	if recs["jlee"].Role != users.Analyst || recs["newbie"].Role != users.Viewer || recs["newbie"].Epoch != 1 {
		t.Errorf("shared users %+v", recs)
	}
	fb, _ := a.docs.Feeds().Get()
	var urls []string
	for _, e := range fb.Feeds {
		urls = append(urls, e.Name+"="+e.URL)
	}
	slices.Sort(urls)
	if !slices.Equal(urls, []string{"mine=https://mine.example.com/l", "shared=https://a.example.com/l"}) {
		t.Errorf("shared feeds %v", urls)
	}

	// Again: nothing more to add.
	b.cycle()
	again, err := Merge(ctx, b.docs, b.files, "signalith join", MergeOptions{Users: true, Settings: true})
	if err != nil || len(again.Added) != 0 || len(again.Differ) != len(rep.Differ) {
		t.Fatalf("merge again: %v %+v", err, again)
	}

	// The report is kept, signed, in the shared settings.
	r := NewReports()
	r.Track(b.rt.Hub())
	if err := r.Save(ctx, "signalith join", rep); err != nil {
		t.Fatal(err)
	}
	if err := r.Save(ctx, "signalith join", again); err != nil {
		t.Fatalf("save again: %v", err)
	}
	ra := NewReports()
	ra.Track(a.rt.Hub())
	a.cycle()
	got, ok := ra.Get("n_siem-b")
	if !ok || got.Name != "siem-b" || len(got.Differ) != len(rep.Differ) || len(got.Added) != 0 {
		t.Fatalf("report on siem-a: %v %+v", ok, got)
	}
}
