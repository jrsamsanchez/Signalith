// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clustercfg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

func TestRetentionBodyRoundTrip(t *testing.T) {
	days := 30
	on := true
	b := &RetentionBody{Days: &days, Default: &retention.Policy{KeepDays: 90}, Guard: &retention.Guard{Enabled: &on, MaxDiskPercent: 85},
		Policies: map[string]retention.Policy{retention.Findings: {KeepDays: 40}},
		From:     map[string]From{"days": {Source: FromYAML, Node: "siem-a"}}}
	s := b.saved()
	if *s.Days != 30 || s.Default.KeepDays != 90 || s.Guard.MaxDiskPercent != 85 || s.Policies[retention.Findings].KeepDays != 40 || s.From["days"].Node != "siem-a" {
		t.Fatalf("saved %+v", s)
	}
	// What saved returns is a copy.
	s.Default.KeepDays, s.Guard.MaxDiskPercent = 1, 1
	if b.Default.KeepDays != 90 || b.Guard.MaxDiskPercent != 85 {
		t.Fatal("saved shares the body's policies")
	}
	var back RetentionBody
	back.set(retention.Saved{Default: &retention.Policy{KeepDays: 7}, Policies: map[string]retention.Policy{}})
	if back.Policies != nil || back.From != nil || back.Default.KeepDays != 7 {
		t.Fatalf("set %+v", back)
	}
}

func TestHoldText(t *testing.T) {
	merge := (&Confirm{Reason: ConfirmMerge, Servers: map[string]string{"siem-b": "x", "siem-a": "y"}}).HoldText()
	if !strings.Contains(merge, "joined (siem-a, siem-b)") {
		t.Errorf("merge: %s", merge)
	}
	imp := (&Confirm{Reason: ConfirmImport}).HoldText()
	if !strings.Contains(imp, "the other servers had different policies") {
		t.Errorf("import: %s", imp)
	}
}

func TestSettingsBodyRevisions(t *testing.T) {
	var b SettingsBody
	if b.ResetValue("search.timeout", shared.From{By: "admin"}) != 0 {
		t.Fatal("a reset of a setting at its default")
	}
	if rev := b.set("search.timeout", SettingValue{}); rev != 1 {
		t.Fatalf("first revision %d", rev)
	}
	from := shared.From{By: "admin", At: time.Unix(1700000000, 0).UTC()}
	if rev := b.ResetValue("search.timeout", from); rev != 2 {
		t.Fatalf("reset revision %d", rev)
	}
	if got := b.changedFrom("search.timeout"); got.By != "admin" || !got.At.Equal(from.At) {
		t.Fatalf("changedFrom after a reset: %+v", got)
	}
	if b.Rev("search.timeout") != 2 {
		t.Fatalf("Rev after a reset %d", b.Rev("search.timeout"))
	}
}

func TestSameSecret(t *testing.T) {
	k, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	keys := shared.NewKeySet(k)
	seal := func(plain, to string) string {
		s, err := sealFor(keys, "alerts.smtp_password", plain, to)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	a := SettingValue{Secret: seal("pw", "smtp.example.com"), SentTo: "smtp.example.com"}
	again := SettingValue{Secret: seal("pw", "smtp.example.com"), SentTo: "smtp.example.com"}
	other := SettingValue{Secret: seal("other", "smtp.example.com"), SentTo: "smtp.example.com"}
	for _, tc := range []struct {
		name string
		x, y SettingValue
		want bool
	}{
		{"same sealed value", a, a, true},
		{"sealed again", a, again, true},
		{"another password", a, other, false},
		{"another address", a, SettingValue{Secret: a.Secret, SentTo: "evil.example.com"}, false},
		{"one empty", a, SettingValue{SentTo: "smtp.example.com"}, false},
		{"cannot be opened", a, SettingValue{Secret: "enc:junk", SentTo: "smtp.example.com"}, false},
	} {
		if got := sameSecret(keys, "alerts.smtp_password", tc.x, tc.y); got != tc.want {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
	if _, err := sealFor(nil, "alerts.smtp_password", "pw", ""); err == nil {
		t.Error("sealed with no keys")
	}
}

func TestDocsSubscribers(t *testing.T) {
	d := NewDocs()
	heard := map[string]int{}
	d.OnRetention(func() { heard["retention"]++ })
	d.OnSettings(func() { heard["settings"]++ })
	d.OnIntel(func() { heard["intel"]++ })
	for _, k := range []string{changeRetention, changeSettings, changeIntel} {
		d.fire(k)
	}
	if heard["retention"] != 1 || heard["settings"] != 1 || heard["intel"] != 1 {
		t.Fatalf("heard %v", heard)
	}
	d.Reset()
	d.fire(changeRetention)
	if heard["retention"] != 1 {
		t.Fatal("a subscriber was told after Reset")
	}
}

// A cluster with nothing shared exports no files of what it does not
// have.
func TestExportOfAnEmptyCluster(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dir, authConfig(t, dir, ""), nil)
	target := exportUnder(t, dir, t.TempDir())
	files := a.files
	files.NodeCfg = nil
	for _, ex := range Exporters(a.docs, files) {
		got, err := ex.Run(context.Background(), target)
		if err != nil {
			t.Errorf("%s: %v", ex.Name, err)
			continue
		}
		switch ex.Name {
		case shared.ImportDirectory, shared.ImportTenants:
			if len(got) != 0 {
				t.Errorf("%s exported %v from nothing", ex.Name, got)
			}
		}
	}
}

// Before the shared policies are read, retention pauses rather than use
// or change policies it has not seen.
func TestPolicyStoreBeforeRead(t *testing.T) {
	d := NewDocs()
	d.Track(shared.NewHub(shared.Options{NodeName: "siem-a"}))
	ps := &PolicyStore{Docs: d}
	if _, err := ps.Get(); !errors.Is(err, ErrPoliciesUnavailable) {
		t.Errorf("Get: %v", err)
	}
	if err := ps.UpdateIf("1", func(*retention.Saved) {}); !errors.Is(err, ErrPoliciesUnavailable) {
		t.Errorf("UpdateIf: %v", err)
	}
	if _, err := (&FeedList{Docs: d}).Load(); !errors.Is(err, intel.ErrFeedsUnavailable) {
		t.Errorf("feeds: %v", err)
	}
	// Nothing read is nothing to export.
	a := clusterauth.NewDocs()
	a.Track(shared.NewHub(shared.Options{NodeName: "siem-a"}))
	var target shared.ExportTarget
	for name, run := range map[string]func() ([]shared.ExportedFile, error){
		"feeds":     func() ([]shared.ExportedFile, error) { return exportFeeds(d, Files{}, target) },
		"retention": func() ([]shared.ExportedFile, error) { return exportRetention(d, Files{}, target) },
		"directory": func() ([]shared.ExportedFile, error) {
			return exportDirectory(context.Background(), a, Files{}, target)
		},
	} {
		if got, err := run(); err != nil || got != nil {
			t.Errorf("%s exported %v, %v", name, got, err)
		}
	}
}

func TestPolicyStoreHoldAndConfirm(t *testing.T) {
	o := newOS(t)
	a := newMember(t, o, "siem-a", "", nil, nil)
	a.cycle()
	ps := &PolicyStore{Docs: a.docs}
	if held, _ := ps.Hold(); held {
		t.Fatal("held with nothing to confirm")
	}
	if err := ps.Confirm(context.Background(), "admin"); !errors.Is(err, retention.ErrNoHold) {
		t.Fatalf("confirm with no hold: %v", err)
	}
}

// A file whose address holds a key is refused; one that changes the
// retention policies or leaves a secret empty is planned as such.
func TestPlanFileEdges(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dir, authConfig(t, dir, ""), nil)
	a.cycle()
	cur := a.load()
	f := a.settingsFile("assistant:\n  url: https://api.example.com/?api_key=x\n")
	if _, err := PlanFile(a.rt, a.docs, cur, f); err == nil || !strings.Contains(err.Error(), "assistant.url: leave passwords and keys out") {
		t.Fatalf("an address with a key: %v", err)
	}
	f = a.settingsFile("assistant:\n  api_key: \"\"\nretention:\n  days: 5\n")
	p, err := PlanFile(a.rt, a.docs, cur, f)
	if err != nil {
		t.Fatal(err)
	}
	keys := changeKeys(p)
	if contains(keys, "assistant.api_key") || !contains(keys, "retention.days") {
		t.Fatalf("planned %v", keys)
	}
}

// The built-in admin's two-step sign-in in users.json is imported, and a
// second import keeps the cluster's.
func TestImportBuiltinMFA(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	c := authConfig(t, dir, "")
	secrets.SetDefault(secrets.NewKeyring(dir))
	m := &users.MFA{Secret: "JBSWY3DPEHPK3PXP", Since: time.Now().UTC(), Recovery: []string{"x"}}
	if err := users.WriteFileMFA(c.UsersFile(), map[string]users.Record{}, nil, m); err != nil {
		t.Fatal(err)
	}
	a := newAuthMember(t, o, "siem-a", dir, c, nil)
	ub := &clusterauth.UsersBackend{Docs: a.auth}
	got := ub.BuiltinMFA()
	if !got.On() || got.Secret != m.Secret {
		t.Fatalf("the built-in admin's two-step sign-in: %+v", got)
	}
	if err := a.importer(shared.ImportUsers).Run(context.Background(), "sam"); err != nil {
		t.Fatal(err)
	}
	if again := ub.BuiltinMFA(); !again.On() || again.Secret != m.Secret {
		t.Fatalf("after a second import: %+v", again)
	}
}

// Passwords and keys are never kept unsealed: without a cluster key they
// are refused.
func TestSealingWithAndWithoutAKey(t *testing.T) {
	k, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	keys := shared.NewKeySet(k)
	on := true
	spec := intel.FeedSpec{Name: "f", URL: "https://feeds.example.com/x", Enabled: &on, Password: "pw",
		Headers: map[string]string{"X-Key": "secret", "X-Empty": ""}}
	if _, err := entryOf(spec, nil, nil); err == nil || !strings.Contains(err.Error(), "no cluster key") {
		t.Errorf("a feed sealed with no key: %v", err)
	}
	e, err := entryOf(spec, k, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.Password == "pw" || e.Headers["X-Key"] == "secret" || e.Headers["X-Empty"] != "" || e.Enabled == spec.Enabled || !*e.Enabled {
		t.Errorf("entry %+v", e)
	}
	if spec.Headers["X-Key"] != "secret" {
		t.Error("sealing changed the feed's own headers")
	}
	if got := origin("Not A URL "); got != "not a url" {
		t.Errorf("origin of no address: %q", got)
	}
	if (*From)(nil).note() != "" {
		t.Error("a note for no source")
	}

	from := shared.From{By: "admin"}
	if sv, err := settingValue(keys, "assistant.api_key", "", "", from); err != nil || sv.Secret != "" || sv.Value != nil {
		t.Errorf("an empty key: %+v %v", sv, err)
	}
	if _, err := settingValue(nil, "assistant.api_key", "k", "https://api.example.com", from); err == nil {
		t.Error("a key sealed with no keys")
	}
	if _, err := settingValue(keys, "search.max_events", func() {}, "", from); err == nil {
		t.Error("a value JSON cannot hold")
	}
	if _, _, err := setTokens(nil, nil, "n_a", "siem-a", "yaml", []string{"tok-0123456789abcdef"}, time.Now()); err == nil {
		t.Error("tokens sealed with no keys")
	}
}

// A server that lost its cluster key applies and records nothing.
func TestApplyWithoutAClusterKey(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dir, authConfig(t, dir, ""), nil)
	a.cycle()
	a.docs.Hub().SetKeys(shared.NewKeySet(nil))
	ctx := context.Background()
	if _, err := Apply(ctx, a.rt, a.docs, a.cfg.Load(), a.name, a.log); err == nil || !strings.Contains(err.Error(), "no cluster key") {
		t.Errorf("Apply: %v", err)
	}
	if _, err := write(ctx, a.rt, a.docs, a.cfg.Load(), nil, a.name, a.log, nil); err == nil || !strings.Contains(err.Error(), "no cluster key") {
		t.Errorf("write: %v", err)
	}
	if err := recordAuth(ctx, a.files, a.auth); err == nil || !strings.Contains(err.Error(), "no cluster key") {
		t.Errorf("recordAuth: %v", err)
	}
	files := a.files
	files.NodeCfg = nil
	if err := recordAuth(ctx, files, a.auth); err != nil {
		t.Errorf("recordAuth with no nodecfg: %v", err)
	}
}

// Load shows this server's own statuses not written yet over what the
// index holds, leaves out documents that are not a status, and keeps
// the last copy when the index cannot be read.
func TestStatusLoadPending(t *testing.T) {
	o := newOS(t)
	ctx := context.Background()
	index := cluster.RuntimeIndex(testPrefix)
	w := &StatusStore{Client: o.cl, Index: index, Node: "n_a", Epoch: func() int64 { return 1 }}
	for name, n := range map[string]int{"a": 1, "b": 2, "c": 3} {
		if err := w.write(ctx, name, &intel.FeedStatus{Count: n}, 1); err != nil {
			t.Fatal(err)
		}
	}
	o.fake.Put(index, StatusID("d"), map[string]any{"kind": FeedStatusKind, "name": "other"})
	s := &StatusStore{Client: o.cl, Index: index, Node: "n_b"}
	s.Save("a", &intel.FeedStatus{Count: 10})
	s.Save("b", nil)
	s.mu.Lock()
	s.readAt = time.Time{}
	s.mu.Unlock()
	got := s.Load()
	if len(got) != 2 || got["a"] == nil || got["a"].Count != 10 || got["c"] == nil || got["c"].Count != 3 || got["b"] != nil {
		t.Fatalf("loaded %v", got)
	}
	o.fake.SetFault(func(method, path string) *ostest.Fault {
		if strings.Contains(path, "_search") {
			return &ostest.Fault{Status: 400, Type: "search_phase_execution_exception"}
		}
		return nil
	})
	defer o.fake.SetFault(nil)
	s.mu.Lock()
	s.readAt = time.Time{}
	s.mu.Unlock()
	if again := s.Load(); len(again) != 2 || again["c"] == nil {
		t.Fatalf("loaded without the index: %v", again)
	}
}

// A merge reports each way a user or feed of the joining server differs
// from the cluster's of the same name: how they sign in, whether they are
// turned off, and a feed's format.
func TestMergeReportsEachDifference(t *testing.T) {
	o := newOS(t)
	dirA := t.TempDir()
	cA := authConfig(t, dirA, "")
	prepareServer(t, cA, []users.NewUser{{Username: "pat", Role: users.Analyst, Password: "a-good-password"},
		{Username: "dora", Role: users.Viewer, Password: "a-good-password"}}, nil,
		[]intel.FeedSpec{{Name: "shared", URL: "https://feeds.example.com/l", Format: "lines", Type: "ip"}})
	a := newAuthMember(t, o, "siem-a", dirA, authConfig(t, dirA, ""), nil)

	dirB := t.TempDir()
	cB := authConfig(t, dirB, "")
	prepareServer(t, cB, []users.NewUser{{Username: "pat", Role: users.Analyst, Password: "a-good-password"}}, nil,
		[]intel.FeedSpec{{Name: "shared", URL: "https://feeds.example.com/l", Format: "csv", Type: "ip", Column: "1"}})
	ctx := users.WithActor(context.Background(), "sam")
	fs, err := users.Open(cB.UsersFile())
	if err != nil {
		t.Fatal(err)
	}
	off := true
	if _, err := fs.Update(ctx, "pat", users.Change{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.SeeDirectoryUser(ctx, users.DirectoryUser{Username: "dora", DN: "CN=Dora,DC=corp", Name: "Dora", Role: users.Viewer}); err != nil {
		t.Fatal(err)
	}
	b := newAuthMember(t, o, "siem-b", dirB, authConfig(t, dirB, ""), a.key())

	rep, err := Merge(context.Background(), b.docs, b.files, "signalith join", MergeOptions{Users: true, Settings: true})
	if err != nil {
		t.Fatal(err)
	}
	details := map[string]string{}
	for _, it := range rep.Differ {
		details[it.Kind+":"+it.ID] = it.Detail
	}
	for key, want := range map[string]string{
		MergeUser + ":pat":    "disabled here",
		MergeUser + ":dora":   "sign-in by directory here, by local in the cluster",
		MergeFeed + ":shared": "its format differ",
	} {
		if !strings.Contains(details[key], want) {
			t.Errorf("%s: %q, want %q", key, details[key], want)
		}
	}
}
