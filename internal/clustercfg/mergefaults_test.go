package clustercfg

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/shared"
)

// The reports of a merge, before and after the shared settings are open.
func TestReportsList(t *testing.T) {
	ctx := context.Background()
	r := NewReports()
	r.Reset()
	if _, ok := r.Get("n_siem-a"); ok || r.List() != nil {
		t.Error("reports before the shared settings are open")
	}
	if err := r.Save(ctx, "test", &MigrationReport{NodeID: "n_siem-a"}); err == nil {
		t.Error("saved before the shared settings are open")
	}
	o := newOS(t)
	a := newMember(t, o, "siem-a", "", nil, nil)
	r.Track(a.rt.Hub())
	for _, id := range []string{"n_siem-a", "n_siem-b"} {
		if err := r.Save(ctx, "test", &MigrationReport{NodeID: id, Name: strings.TrimPrefix(id, "n_")}); err != nil {
			t.Fatal(err)
		}
	}
	got := map[string]bool{}
	for _, rep := range r.List() {
		got[rep.Name] = true
	}
	if len(got) != 2 || !got["siem-a"] || !got["siem-b"] {
		t.Errorf("reports %v", got)
	}
}

// A merge says which of this server's files it could not read, and needs
// the cluster key.
func TestMergeRefusals(t *testing.T) {
	ctx := context.Background()
	if _, err := Merge(ctx, NewDocs(), Files{}, "test", MergeOptions{}); err == nil || !strings.Contains(err.Error(), "no cluster key") {
		t.Errorf("without the shared settings: %v", err)
	}
	o := newOS(t)
	a, _ := exportFixture(t, o)
	opts := MergeOptions{Users: true, Settings: true}
	if _, err := Merge(ctx, a.docs, a.files, "test", opts); err != nil {
		t.Fatal(err)
	}
	c := a.cfg.Load()
	for _, s := range []struct{ file, want string }{
		{c.IntelFeedsFile(), "the threat intel feeds"},
		{RetentionFile(c), "the retention policies"},
		{c.UsersFile(), "the users"},
	} {
		keep, err := os.ReadFile(s.file)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.file, []byte("{[ not this file's format\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Merge(ctx, a.docs, a.files, "test", opts); err == nil || !strings.HasPrefix(err.Error(), s.want+":") {
			t.Errorf("%s: %v", s.file, err)
		}
		if err := os.WriteFile(s.file, keep, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The page's file is read as the configuration has it: one that
	// cannot be read is no refusal.
	if err := os.WriteFile(c.SettingsFile(), []byte("{[ not this file's format\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Merge(ctx, a.docs, a.files, "test", opts); err != nil {
		t.Errorf("an unreadable settings.yaml: %v", err)
	}
}

// A reseal whose document cannot be written is reported.
func TestResealWriteRefusals(t *testing.T) {
	o := newOS(t)
	a, _ := exportFixture(t, o)
	ctx := context.Background()
	if _, err := a.docs.Settings().Mutate(ctx, "test", func(b *SettingsBody) error {
		sealed, err := sealFor(a.rt.Hub().Keys(), "assistant.api_key", "test-assistant-key", "")
		if err != nil {
			return err
		}
		if b.Values == nil {
			b.Values = map[string]SettingValue{}
		}
		b.Values["assistant.api_key"] = SettingValue{Secret: sealed}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	k2, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	a.rt.Hub().SetKeys(shared.NewKeySet(k2, a.key()))
	for _, id := range []string{SettingsID, FeedsID} {
		failWrites(o, id+"?")
		if err := Resealer(a.docs)(ctx); err == nil {
			t.Errorf("resealed while %s cannot be written", id)
		}
		o.fake.SetFault(nil)
	}
	if err := Resealer(a.docs)(ctx); err != nil {
		t.Fatal(err)
	}
}
