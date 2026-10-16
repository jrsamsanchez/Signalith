package tenants

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestValidID(t *testing.T) {
	for _, id := range []string{"ac", "acme", "contoso2", "a1b2c3", strings.Repeat("a", 24)} {
		if err := ValidID(id); err != nil {
			t.Errorf("ValidID(%q) = %v, want nil", id, err)
		}
	}
	for _, id := range []string{"", "a", "default", "Acme", "1acme", "ac-me", "ac_me", "ac.me", "ac me", "acme*", strings.Repeat("a", 25), "acmé"} {
		if ValidID(id) == nil {
			t.Errorf("ValidID(%q) = nil, want an error", id)
		}
	}
}

func TestPrefix(t *testing.T) {
	if got := Prefix("signalith", Default); got != "signalith" {
		t.Errorf("default prefix = %q", got)
	}
	if got := Prefix("signalith", ""); got != "signalith" {
		t.Errorf("empty tenant prefix = %q", got)
	}
	if got := Prefix("signalith", "acme"); got != "signalith.t.acme" {
		t.Errorf("acme prefix = %q", got)
	}
	if ValidConfiguredPrefix("signalith") != nil || ValidConfiguredPrefix("siem.t.x") == nil {
		t.Error("ValidConfiguredPrefix must refuse only prefixes with .t.")
	}
}

func TestRegistry(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(File(dir))
	if err != nil {
		t.Fatal(err)
	}
	if list, _ := r.List(); len(list) != 0 {
		t.Fatalf("new registry lists %v", list)
	}
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	if _, err := r.Add("zeta", "Zeta Corp", "admin", now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add("acme", " Acme ", "admin", now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add("acme", "Again", "admin", now); !errors.Is(err, ErrExists) {
		t.Errorf("adding acme twice: %v", err)
	}
	if _, err := r.Add("default", "Default", "admin", now); err == nil {
		t.Error("the default tenant's ID was accepted")
	}
	for _, bad := range []string{"line\nbreak", "be\u0085ll", "evil\u202eemca", "iso\u2067x", ""} {
		if _, err := r.Add("bad", bad, "admin", now); err == nil {
			t.Errorf("the name %q was accepted", bad)
		}
	}
	list, err := r.List()
	if err != nil || len(list) != 2 || list[0].ID != "acme" || list[0].Name != "Acme" || list[1].ID != "zeta" {
		t.Fatalf("List = %+v, %v", list, err)
	}
	off := true
	if _, err := r.Change("acme", nil, &off, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Change("nobody", nil, &off, "test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("changing a missing tenant: %v", err)
	}
	// Another process reading the same file sees the change.
	r2, err := Open(File(dir))
	if err != nil {
		t.Fatal(err)
	}
	got, err := r2.Get("acme")
	if err != nil || !got.Disabled || got.CreatedBy != "admin" || !got.Created.Equal(now) {
		t.Errorf("Get(acme) = %+v, %v", got, err)
	}
	if _, err := r2.Get(Default); !errors.Is(err, ErrNotFound) {
		t.Errorf("the default tenant is in the registry: %v", err)
	}
}

func TestRegistryRefusesDamagedFile(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"not json":  "{",
		"bad id":    `{"version":1,"tenants":[{"id":"ac-me","name":"x"}]}`,
		"duplicate": `{"version":1,"tenants":[{"id":"acme","name":"x"},{"id":"acme","name":"y"}]}`,
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(p); err == nil {
			t.Errorf("%s: Open accepted the file", name)
		}
	}
}

// fakeShared is a cluster's shared list of tenants.
type fakeShared struct {
	on   bool
	list []Tenant
	err  error
}

func (f *fakeShared) On() bool { return f.on }

func (f *fakeShared) List() ([]Tenant, error) { return slices.Clone(f.list), f.err }

func (f *fakeShared) Mutate(_ context.Context, _ string, fn func([]Tenant) ([]Tenant, error)) error {
	out, err := fn(slices.Clone(f.list))
	if err != nil {
		return err
	}
	f.list = out
	return nil
}

// Once a cluster keeps the tenants, the list is the shared one only;
// before, nothing can change it.
func TestRegistryShared(t *testing.T) {
	r, err := Open(File(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add("acme", "Acme", "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	sh := &fakeShared{}
	r.UseShared(sh)
	if _, err := r.Add("contoso", "Contoso", "test", time.Now()); !errors.Is(err, ErrNotShared) {
		t.Fatalf("add before the cluster keeps tenants: %v", err)
	}
	if list, _ := r.List(); len(list) != 1 || list[0].ID != "acme" {
		t.Fatalf("before the cluster keeps tenants: %v", list)
	}
	sh.on, sh.list = true, []Tenant{{ID: "acme", Name: "Acme"}}
	if _, err := r.Add("contoso", "Contoso", "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	// Another server turns acme off.
	sh.list[0].Disabled = true
	if tn, err := r.Get("acme"); err != nil || !tn.Disabled {
		t.Errorf("acme: %+v %v", tn, err)
	}
	if list, _ := r.List(); len(list) != 2 {
		t.Errorf("shared list: %v", list)
	}
	if _, err := r.Add("contoso", "Contoso", "test", time.Now()); !errors.Is(err, ErrExists) {
		t.Errorf("adding a tenant twice: %v", err)
	}
	// The file is this server's own, as it was.
	local, _ := Open(r.Path)
	if list, _ := local.List(); len(list) != 1 {
		t.Errorf("the file changed: %v", list)
	}
	// A shared list that cannot be read leaves no tenant usable, never
	// the file's.
	sh.err = errors.New("not read yet")
	if _, err := r.Get("acme"); err == nil {
		t.Error("acme is found while the shared list cannot be read")
	}
}
