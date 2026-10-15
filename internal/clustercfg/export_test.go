package clustercfg

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// exportUnder returns an export target that writes under root what a
// server keeps under base.
func exportUnder(t *testing.T, base, root string) shared.ExportTarget {
	t.Helper()
	return shared.ExportTarget{Under: func(p string) string {
		rel, err := filepath.Rel(base, p)
		if err != nil || !filepath.IsLocal(rel) {
			t.Fatalf("%s is not under %s", p, base)
		}
		return filepath.Join(root, rel)
	}, Server: "n_siem-a"}
}

// copyFile copies a file, making its folder.
func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The files the exporters write, imported by a new cluster, give the same
// shared settings: users with their password hashes, feeds with their
// passwords (sealed with the master key in the files), their status, the
// retention policies, the directory sign-in settings and the settings of
// the Settings page, a password among them.
func TestExportIsTheInverseOfImport(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	master := secrets.NewKeyring(dir)
	secrets.SetDefault(master)
	t.Cleanup(func() { secrets.SetDefault(nil) })
	c := authConfig(t, dir, "")
	ctx := users.WithActor(context.Background(), "sam")

	fileStore, err := users.Open(c.UsersFile())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fileStore.Create(ctx, users.NewUser{Username: "jlee", Role: users.Analyst, Password: "a-good-password"}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&intel.FileList{Path: c.IntelFeedsFile()}).Mutate(ctx, "", func(s *intel.FeedSet) error {
		s.UI = []intel.FeedSpec{{Name: "mine", URL: "https://mine.example.com/l", Username: "u", Password: "feed-pass"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	next := time.Now().Add(3 * time.Hour).UTC().Truncate(time.Second)
	(&intel.StatusFile{Path: FeedStatusFile(c)}).Save("mine", &intel.FeedStatus{NextRun: next, Count: 7})
	if err := retention.NewStore(RetentionFile(c)).Update(func(s *retention.Saved) {
		s.Policies = map[string]retention.Policy{retention.Findings: {KeepDays: 45}}
	}); err != nil {
		t.Fatal(err)
	}
	d, err := users.OpenDirectory(c.DirectoryFile(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ls := users.Preset(users.TypeActiveDirectory)
	on := true
	ls.Enabled, ls.URL, ls.BindDN, ls.BindPassword = &on, "ldaps://dc1.corp.example.com", "CN=svc,DC=corp,DC=example,DC=com", "svc-pass"
	ls.UserBaseDN = "DC=corp,DC=example,DC=com"
	ls.AdminGroups = []string{"CN=Admins,DC=corp,DC=example,DC=com"}
	ls.Normalize()
	if err := d.Save(ctx, ls); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	page := &config.PageSettings{}
	if err := page.Set("search.max_events", 500, "alice", at); err != nil {
		t.Fatal(err)
	}
	if err := page.SetSecret("assistant.api_key", "sk-page-secret", "https://api.anthropic.com:443", "alice", at); err != nil {
		t.Fatal(err)
	}
	if err := config.WritePageSettings(c.SettingsFile(), page); err != nil {
		t.Fatal(err)
	}
	c = authConfig(t, dir, "")
	a := newAuthMember(t, o, "siem-a", dir, c, nil)

	root := t.TempDir()
	target := exportUnder(t, dir, root)
	written := map[string]shared.ExportedFile{}
	for _, ex := range Exporters(a.docs, a.files) {
		list, err := ex.Run(ctx, target)
		if err != nil {
			t.Fatalf("%s: %v", ex.Name, err)
		}
		for _, f := range list {
			written[ex.Name] = f
		}
	}
	for _, name := range []string{ImportFeeds, "feed_status", ImportRetention, shared.ImportUsers, shared.ImportDirectory, shared.ImportSettings} {
		f, ok := written[name]
		if !ok {
			t.Fatalf("%s wrote nothing", name)
		}
		st, err := os.Stat(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		if f.Secret && runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s holds secrets and is %v", f.Path, st.Mode().Perm())
		}
	}
	for name, want := range map[string]string{ImportFeeds: c.IntelFeedsFile(), shared.ImportUsers: c.UsersFile(), shared.ImportSettings: c.SettingsFile()} {
		if written[name].Dest != want {
			t.Errorf("%s goes to %s, want %s", name, written[name].Dest, want)
		}
	}
	if !written[ImportFeeds].Secret || !written[shared.ImportSettings].Secret || !written[shared.ImportDirectory].Secret {
		t.Errorf("files with secrets not marked: %+v", written)
	}
	// The secrets in the files are sealed with the master key, never in
	// the clear.
	for _, name := range []string{ImportFeeds, shared.ImportDirectory, shared.ImportSettings} {
		raw, _ := os.ReadFile(written[name].Path)
		for _, plain := range []string{"feed-pass", "svc-pass", "sk-page-secret"} {
			if strings.Contains(string(raw), plain) {
				t.Errorf("%s holds %q in the clear", written[name].Path, plain)
			}
		}
	}
	set, err := (&intel.FileList{Path: written[ImportFeeds].Path}).Load()
	if err != nil || len(set.UI) != 1 || set.UI[0].Password != "feed-pass" || set.UI[0].From != "" {
		t.Fatalf("exported feeds %+v %v", set, err)
	}

	// A new cluster founded from the files written has the same settings.
	copyFile(t, filepath.Join(dir, "signalith.yaml"), filepath.Join(root, "signalith.yaml"))
	copyFile(t, master.DefaultPath(), filepath.Join(root, "keys", filepath.Base(master.DefaultPath())))
	c2, err := config.Load(filepath.Join(root, "signalith.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c2.UsersFile() != written[shared.ImportUsers].Path {
		t.Fatalf("the files are not where the configuration reads them: %s, %s", c2.UsersFile(), written[shared.ImportUsers].Path)
	}
	o2 := newOS(t)
	b := newAuthMember(t, o2, "siem-b", root, c2, nil)
	before, _ := (&clusterauth.UsersBackend{Docs: a.auth}).Load()
	after, _ := (&clusterauth.UsersBackend{Docs: b.auth}).Load()
	if len(after) != len(before) || after["jlee"].Hash != before["jlee"].Hash || after["jlee"].Role != users.Analyst || after["jlee"].Hash == "" {
		t.Errorf("users %+v, want %+v", after, before)
	}
	fa, _ := (&FeedList{Docs: a.docs}).Load()
	fb, _ := (&FeedList{Docs: b.docs}).Load()
	if len(fb.UI) != 1 || fb.UI[0].Password != fa.UI[0].Password || fb.UI[0].URL != fa.UI[0].URL || fb.UI[0].Username != "u" {
		t.Errorf("feeds %+v, want %+v", fb.UI, fa.UI)
	}
	ra, _ := (&PolicyStore{Docs: a.docs}).Get()
	rb, _ := (&PolicyStore{Docs: b.docs}).Get()
	if rb.Policies[retention.Findings].KeepDays != 45 || rb.Policies[retention.Findings] != ra.Policies[retention.Findings] {
		t.Errorf("retention %+v, want %+v", rb.Policies, ra.Policies)
	}
	da, _, _ := (&clusterauth.DirectoryBackend{Docs: a.auth}).Load()
	db, _, problem := (&clusterauth.DirectoryBackend{Docs: b.auth}).Load()
	if problem != "" || db.URL != da.URL || db.BindPassword != "svc-pass" || db.BindDN != da.BindDN {
		t.Errorf("directory %+v (%s), want %+v", db, problem, da)
	}
	if v, ok := b.setting("search.max_events"); !ok || rawString(v.Value) != "500" || v.From.By != "alice" {
		t.Errorf("search.max_events %+v", v)
	}
	key, ok := b.setting("assistant.api_key")
	if !ok {
		t.Fatal("the API key was not exported")
	}
	if got, err := openFor(b.rt.Hub().Keys(), "assistant.api_key", key.Secret, key.SentTo); err != nil || got != "sk-page-secret" || key.SentTo != "https://api.anthropic.com:443" {
		t.Errorf("the API key opens to %q (%v), sent to %s", got, err, key.SentTo)
	}

	// While the policies wait to be confirmed, the export is refused.
	if _, err := a.docs.Retention().Mutate(ctx, "test", func(b *RetentionBody) error {
		b.Confirm = &Confirm{Reason: ConfirmImport, At: "2026-10-15T10:00:00Z"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, ex := range Exporters(a.docs, a.files) {
		if ex.Name != ImportRetention {
			continue
		}
		if _, err := ex.Run(ctx, exportUnder(t, dir, t.TempDir())); !errors.Is(err, ErrRetentionUnconfirmed) {
			t.Errorf("exported unconfirmed policies: %v", err)
		}
	}
}
