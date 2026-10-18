package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFirstPasswordNotes(t *testing.T) {
	dir := t.TempDir()
	if fp, err := ReadFirstPassword(dir); err != nil || fp != (FirstPassword{}) {
		t.Fatalf("none yet: %+v %v", fp, err)
	}
	if err := RecordFirstPassword(dir, "$2a$12$hash"); err != nil {
		t.Fatal(err)
	}
	if fp, err := ReadFirstPassword(dir); err != nil || fp.Hash != "$2a$12$hash" || !fp.Changed.IsZero() {
		t.Fatalf("recorded: %+v %v", fp, err)
	}
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	if err := NoteFirstPasswordChanged(dir, at); err != nil {
		t.Fatal(err)
	}
	// A later change keeps the first time.
	if err := NoteFirstPasswordChanged(dir, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if fp, err := ReadFirstPassword(dir); err != nil || fp.Hash != "" || !fp.Changed.Equal(at) {
		t.Fatalf("changed: %+v %v", fp, err)
	}
	// A new first password (init -force) starts again.
	if err := RecordFirstPassword(dir, "$2a$12$other"); err != nil {
		t.Fatal(err)
	}
	if fp, _ := ReadFirstPassword(dir); fp.Hash != "$2a$12$other" || !fp.Changed.IsZero() {
		t.Errorf("recorded again: %+v", fp)
	}
	os.WriteFile(FirstPasswordFileIn(dir), []byte("{"), 0o600)
	if _, err := ReadFirstPassword(dir); err == nil {
		t.Error("a damaged file was read")
	}
}

func TestInitialPasswordFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "signalith.yaml")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", "")
	if f, own := InitialPasswordFile(path); f != filepath.Join(filepath.Dir(path), InitialPasswordFileName) || !own {
		t.Errorf("next to the config: %q %v", f, own)
	}
	if f, _ := InitialPasswordFile(""); f != "" {
		t.Errorf("without a config file: %q", f)
	}
	docker := filepath.Join(t.TempDir(), InitialPasswordFileName)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", docker)
	if f, own := InitialPasswordFile(path); f != docker || own {
		t.Errorf("the environment's: %q %v", f, own)
	}
	// A file of someone's own is no password Signalith made.
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", filepath.Join(t.TempDir(), "admin-password"))
	if f, _ := InitialPasswordFile(path); f != "" {
		t.Errorf("someone's own file: %q", f)
	}
}

// Load reads the noted hash, and the page's change, kept in
// AdminHashFile, replaces it.
func TestLoadFirstPassword(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	t.Setenv("SIGNALITH_STATE_DIR", state)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", "")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "")
	h, _ := HashPassword("the first password")
	path := filepath.Join(root, "signalith.yaml")
	os.WriteFile(path, []byte("auth:\n  admin_password_hash: "+h+"\ningest:\n  tokens: [tok-0123456789abcdef]\n"), 0o600)
	if err := RecordFirstPassword(state, h); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.FirstPasswordHash() != h {
		t.Fatalf("noted hash %q", c.FirstPasswordHash())
	}
	h2, _ := HashPassword("chosen on the page")
	next := c.WithAdminHashFile(h2)
	if next.FirstPasswordHash() != "" || next.AdminPasswordChanged() != c.AdminHashFile() || !next.CheckPassword("admin", "chosen on the page") {
		t.Error("the page's password is not in use")
	}
	if !c.CheckPassword("admin", "the first password") {
		t.Error("the config loaded before changed")
	}
}
