package users

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func newUser(name string, role Role) NewUser {
	return NewUser{Username: name, Name: strings.ToUpper(name[:1]) + name[1:], Role: role, Password: "temporary-pass", MustChangePassword: true}
}

func TestStorePersistsAndIgnoresCase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lookups", "users.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.BuiltinAdmin = "admin"
	u, err := s.Create(context.Background(), NewUser{Username: " JDoe ", Name: "Jane Doe", Email: "jdoe@example.com", Role: Analyst, Password: "first-password", MustChangePassword: true})
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "jdoe" || u.Source != SourceLocal || !u.MustChangePassword || u.Created.IsZero() {
		t.Errorf("created %+v", u)
	}
	if _, err := s.Create(context.Background(), newUser("JDOE", Viewer)); !errors.Is(err, ErrExists) {
		t.Errorf("same name, other case: %v", err)
	}
	if _, err := s.Create(context.Background(), newUser("Admin", Viewer)); !errors.Is(err, ErrReserved) {
		t.Errorf("built-in admin's name: %v", err)
	}
	for _, bad := range []string{"", "-x", "has space", "a/b", "x!y", strings.Repeat("a", 65)} {
		in := newUser("x", Viewer)
		in.Username = bad
		if _, err := s.Create(context.Background(), in); err == nil {
			t.Errorf("username %q accepted", bad)
		}
	}
	if _, err := s.Create(context.Background(), NewUser{Username: "short", Role: Viewer, Password: "1234567"}); err == nil || !strings.Contains(err.Error(), "at least 8") {
		t.Errorf("short password: %v", err)
	}
	if _, err := s.Create(context.Background(), NewUser{Username: "mail", Role: Viewer, Password: "long-enough", Email: "not an email"}); err == nil {
		t.Error("bad email accepted")
	}
	if !s.CheckPassword("JDOE", "first-password") || s.CheckPassword("jdoe", "wrong-password") || s.CheckPassword("nobody", "first-password") {
		t.Error("password checks")
	}
	s.RecordSignIn(context.Background(), "jdoe")
	s.RecordBuiltinSignIn(context.Background())

	// The file is written owner-only, and holds the hash but never the password.
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v %v", fi.Mode(), err)
		}
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "first-password") || !strings.Contains(string(raw), `"password_hash": "$2a$`) {
		t.Errorf("file = %s", raw)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := again.Get("JDoe")
	if !ok || got.Name != "Jane Doe" || got.Role != Analyst || got.LastSignIn == nil || again.BuiltinLastSignIn() == nil {
		t.Errorf("reloaded %+v %v", got, ok)
	}
	if !again.CheckPassword("jdoe", "first-password") {
		t.Error("password lost on reload")
	}
	// A damaged file is an error, not an empty list that would overwrite it.
	os.WriteFile(path, []byte("{not json"), 0o600)
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Errorf("damaged file: %v", err)
	}
}

func TestStoreLastAdminGuard(t *testing.T) {
	s := NewMemory() // no built-in admin, so local admins are all there is
	s.Create(context.Background(), newUser("ann", Admin))
	s.Create(context.Background(), newUser("ben", Analyst))
	viewer, off := Viewer, true
	if _, err := s.Update(context.Background(), "ann", Change{Role: &viewer}); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demote last admin: %v", err)
	}
	if _, err := s.Update(context.Background(), "ann", Change{Disabled: &off}); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("disable last admin: %v", err)
	}
	if _, err := s.Delete(context.Background(), "ann"); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("delete last admin: %v", err)
	}
	admin := Admin
	if _, err := s.Update(context.Background(), "ben", Change{Role: &admin}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Delete(context.Background(), "ann"); err != nil {
		t.Errorf("delete with another admin left: %v", err)
	}
	// The built-in admin always counts.
	s.BuiltinAdmin = "admin"
	if _, err := s.Update(context.Background(), "ben", Change{Disabled: &off}); err != nil {
		t.Errorf("built-in admin should count: %v", err)
	}
}

func TestStoreDirectoryUsers(t *testing.T) {
	s := NewMemory()
	s.Now = func() time.Time { return time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC) }
	u, err := s.SeeDirectoryUser(context.Background(), DirectoryUser{Username: "Bob", DN: "CN=Bob,DC=x", Name: "Bob A", Role: Analyst})
	if err != nil || u.Username != "bob" || u.Source != SourceDirectory || u.LastSignIn == nil {
		t.Fatalf("first sign-in %+v %v", u, err)
	}
	// Role and details follow the directory at each sign-in.
	u, _ = s.SeeDirectoryUser(context.Background(), DirectoryUser{Username: "bob", DN: "CN=Bob,DC=x", Name: "Bob B", Role: Viewer})
	if u.Role != Viewer || u.Name != "Bob B" {
		t.Errorf("second sign-in %+v", u)
	}
	// Only disabling is allowed here.
	admin, off := Admin, true
	if _, err := s.Update(context.Background(), "bob", Change{Role: &admin}); !errors.Is(err, ErrManaged) {
		t.Errorf("role change on a directory user: %v", err)
	}
	if _, err := s.SetPassword(context.Background(), "bob", "new-password", false); !errors.Is(err, ErrManaged) {
		t.Errorf("password on a directory user: %v", err)
	}
	if u, err := s.Update(context.Background(), "bob", Change{Disabled: &off}); err != nil || !u.Disabled {
		t.Errorf("disable %+v %v", u, err)
	}
	// A disabled directory user stays disabled at sign-in.
	if u, _ := s.SeeDirectoryUser(context.Background(), DirectoryUser{Username: "bob", Role: Admin}); !u.Disabled || u.Role != Viewer {
		t.Errorf("disabled sign-in %+v", u)
	}
	// A local user's name cannot be taken over from the directory.
	s.Create(context.Background(), newUser("carol", Viewer))
	if _, err := s.SeeDirectoryUser(context.Background(), DirectoryUser{Username: "carol", Role: Admin}); !errors.Is(err, ErrExists) {
		t.Errorf("takeover of a local name: %v", err)
	}
}

func TestPasswordsAndRoles(t *testing.T) {
	p := GeneratePassword()
	if len(p) != 19 || strings.Count(p, "-") != 3 || GeneratePassword() == p {
		t.Errorf("generated %q", p)
	}
	if _, err := HashPassword(strings.Repeat("x", 73)); err == nil {
		t.Error("73-byte password accepted")
	}
	if !Admin.AtLeast(Analyst) || Viewer.AtLeast(Analyst) || Role("root").AtLeast(Viewer) {
		t.Error("role ranks")
	}
	if Highest(Viewer, Admin, Analyst) != Admin || Highest() != "" {
		t.Error("highest")
	}
	var roles []RoleInfo
	b, _ := json.Marshal(RoleInfos)
	json.Unmarshal(b, &roles)
	if len(roles) != 3 || roles[0].ID != Viewer {
		t.Errorf("role infos %s", b)
	}
}
