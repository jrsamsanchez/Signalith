package clustercfg

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// exportFixture founds a cluster from a server whose files have a user,
// a feed with its status, a retention policy, directory sign-in settings
// and a setting of the Settings page; it returns the server and the
// folder its files are in.
func exportFixture(t *testing.T, o *testOS) (*authMember, string) {
	t.Helper()
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
	(&intel.StatusFile{Path: FeedStatusFile(c)}).Save("mine", &intel.FeedStatus{NextRun: time.Now().Add(time.Hour), Count: 7})
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
	page := &config.PageSettings{}
	if err := page.Set("search.max_events", 500, "alice", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := config.WritePageSettings(c.SettingsFile(), page); err != nil {
		t.Fatal(err)
	}
	return newAuthMember(t, o, "siem-a", dir, authConfig(t, dir, ""), nil), dir
}

func exporter(t *testing.T, m *authMember, name string) shared.Exporter {
	t.Helper()
	for _, ex := range Exporters(m.docs, m.files) {
		if ex.Name == name {
			return ex
		}
	}
	t.Fatalf("no exporter %s", name)
	return shared.Exporter{}
}

// An export folder whose files cannot be written is reported by every
// exporter that has something to write.
func TestExportUnwritable(t *testing.T) {
	o := newOS(t)
	a, dir := exportFixture(t, o)
	root := t.TempDir()
	// The folder the files go in is a file.
	if err := os.WriteFile(filepath.Join(root, "lookups"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "lookups")); err != nil {
		t.Fatalf("the files are not under lookups: %v", err)
	}
	target := exportUnder(t, dir, root)
	for _, ex := range Exporters(a.docs, a.files) {
		files, err := ex.Run(context.Background(), target)
		if ex.Name == shared.ImportTenants {
			// No tenants: nothing to write.
			if err != nil || len(files) != 0 {
				t.Errorf("tenants: %v %v", files, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s wrote %v into a folder that is a file", ex.Name, files)
		}
	}
}

// The feeds' status and the users' last sign-ins that cannot be read:
// the status is refused, the users are written without their sign-ins.
// The own settings of another server are read from OpenSearch.
func TestExportReadRefusals(t *testing.T) {
	o := newOS(t)
	a, dir := exportFixture(t, o)
	ctx := context.Background()
	seen := &clusterauth.LastSeen{Client: a.files.Client, Node: a.name}
	if err := seen.Record(ctx, "jlee", "password"); err != nil {
		t.Fatal(err)
	}
	logs := &logBuffer{}
	target := exportUnder(t, dir, t.TempDir())
	target.Log = slog.New(slog.NewTextHandler(logs, nil))

	// With the runtime index read, the user's last sign-in comes along.
	files, err := exporter(t, a, shared.ImportUsers).Run(ctx, target)
	if err != nil || len(files) != 1 {
		t.Fatalf("users: %v %v", files, err)
	}
	recs, _, err := users.ReadFile(files[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if r := recs["jlee"]; r.LastSignIn == nil || time.Since(*r.LastSignIn) > time.Hour {
		t.Errorf("jlee's last sign-in: %+v", r.LastSignIn)
	}

	o.fake.SetFault(func(method, path string) *ostest.Fault {
		if strings.Contains(path, testPrefix+"_runtime") && strings.Contains(path, "_search") {
			return &ostest.Fault{Status: http.StatusInternalServerError, Type: "internal_error"}
		}
		return nil
	})
	if _, err := exporter(t, a, "feed_status").Run(ctx, target); err == nil || !strings.Contains(err.Error(), "could not read the feeds' status") {
		t.Errorf("feed status: %v", err)
	}
	if files, err := exporter(t, a, shared.ImportUsers).Run(ctx, target); err != nil || len(files) != 1 {
		t.Errorf("users without their sign-ins: %v %v", files, err)
	}
	mustContain(t, "the log", logs.String(), "last sign-ins cannot be read")
	o.fake.SetFault(nil)

	// Another server's own settings: read from OpenSearch, and refused
	// when they cannot be.
	other := target
	other.Server = "n_siem-x"
	if _, err := exporter(t, a, shared.ImportSettings).Run(ctx, other); err != nil {
		t.Errorf("a server with no own settings: %v", err)
	}
	o.fake.SetFault(func(method, path string) *ostest.Fault {
		if strings.Contains(path, "nodecfg") {
			return &ostest.Fault{Status: http.StatusInternalServerError, Type: "internal_error"}
		}
		return nil
	})
	if _, err := exporter(t, a, shared.ImportSettings).Run(ctx, other); err == nil || !strings.Contains(err.Error(), "could not read the own settings of n_siem-x") {
		t.Errorf("unreadable own settings: %v", err)
	}
	o.fake.SetFault(nil)

	// No OpenSearch at all for the status.
	f := a.files
	f.Client = nil
	if _, err := exportFeedStatus(ctx, f, target); err == nil {
		t.Error("the status was read without OpenSearch")
	}
}
