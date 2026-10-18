package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// A first password for the built-in admin that Signalith made (the Docker
// quick start's setup step, or signalith init) must be changed when it is
// first used: while it is the password in use, the server asks whoever
// signs in with it to choose their own before anything else, as it asks a
// local user with a temporary password.
//
// The server knows it is still in use in one of two ways. Where it can
// read the file that keeps the first password (SIGNALITH_ADMIN_PASSWORD_FILE
// in the Docker quick start, and the config folder on Windows), it checks
// the password hash in use against it. The Linux packages keep that file
// readable by root only, so signalith init also notes in the state folder
// the hash it gave the built-in admin (FirstPassword): while that is still
// the hash in use, so is the first password. An install made before that
// gets it noted at every start, by the Linux unit's root step (signalith
// initial-password -note): next to the config file, readable by the
// service's group, since root writes nothing in the folder the service
// owns.

// InitialPasswordFileName is the file that keeps a first admin password
// Signalith made: in the Docker quick start's secrets folder, and next to
// the config file for signalith init -save-password (the packages).
const InitialPasswordFileName = "initial-admin-password"

// firstPasswordFile, in the state folder, keeps FirstPassword.
const firstPasswordFile = "first-admin-password.json"

// FirstPassword is what the state folder keeps about the built-in admin's
// first password.
type FirstPassword struct {
	// Hash is the password hash signalith init gave the built-in admin
	// with the password it made, while that may still be in use.
	Hash string `json:"hash,omitempty"`
	// Changed is when the first password was replaced, on the page or
	// with signalith passwd: signalith initial-password no longer shows
	// it from then on.
	Changed time.Time `json:"changed,omitzero"`
}

// FirstPasswordFileIn is where FirstPassword is kept in the state folder
// dir.
func FirstPasswordFileIn(dir string) string { return filepath.Join(dir, firstPasswordFile) }

// ReadFirstPassword reads FirstPassword from the state folder dir: the
// zero value when there is none.
func ReadFirstPassword(dir string) (FirstPassword, error) {
	var fp FirstPassword
	path := FirstPasswordFileIn(dir)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fp, nil
	}
	if err != nil {
		return fp, err
	}
	if err := json.Unmarshal(b, &fp); err != nil {
		return FirstPassword{}, fmt.Errorf("%s is damaged", path)
	}
	return fp, nil
}

func writeFirstPassword(dir string, fp FirstPassword) error {
	b, err := json.MarshalIndent(fp, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(FirstPasswordFileIn(dir), append(b, '\n'))
}

// RecordFirstPassword notes in the state folder dir that hash, the
// built-in admin's password hash, is that of a first password Signalith
// made. It replaces what was noted before.
func RecordFirstPassword(dir, hash string) error {
	return writeFirstPassword(dir, FirstPassword{Hash: hash})
}

// NoteFirstPasswordChanged notes in the state folder dir that the first
// password was replaced at now. A change noted before keeps its time.
func NoteFirstPasswordChanged(dir string, now time.Time) error {
	fp, _ := ReadFirstPassword(dir)
	if !fp.Changed.IsZero() && fp.Hash == "" {
		return nil
	}
	if fp.Changed.IsZero() {
		fp.Changed = now.UTC()
	}
	fp.Hash = ""
	return writeFirstPassword(dir, fp)
}

// InitialPasswordFile returns the file that keeps the first admin
// password Signalith made for the config file at path, or "" when there
// can be none: the file SIGNALITH_ADMIN_PASSWORD_FILE names when it is
// InitialPasswordFileName (the Docker quick start's), else the one next
// to the config file (signalith init -save-password's). own reports
// whether Signalith may remove it once the password is changed: never the
// one the environment names, which the server reads at every start.
func InitialPasswordFile(path string) (file string, own bool) {
	if f := os.Getenv("SIGNALITH_ADMIN_PASSWORD_FILE"); f != "" {
		if filepath.Base(f) == InitialPasswordFileName {
			return f, false
		}
		return "", false
	}
	if path == "" {
		return "", false
	}
	return filepath.Join(filepath.Dir(path), InitialPasswordFileName), true
}

// InitialPasswordFile is InitialPasswordFile for c's config file.
func (c *Config) InitialPasswordFile() (file string, own bool) { return InitialPasswordFile(c.path) }

// FirstPasswordHash returns the hash of a first password Signalith made,
// as the state folder kept it when c was loaded, or "".
func (c *Config) FirstPasswordHash() string { return c.firstPassword.Hash }

// readFirstPassword reads FirstPassword from the state folder, or the
// hash noted next to the config file (RecordFirstPasswordNextTo) where the
// state folder has nothing. A damaged file counts as none.
func (c *Config) readFirstPassword() {
	c.firstPassword, _ = ReadFirstPassword(c.StateDir())
	if c.firstPassword.Hash == "" && c.firstPassword.Changed.IsZero() && c.path != "" {
		if fp, err := ReadFirstPassword(filepath.Dir(c.path)); err == nil {
			c.firstPassword.Hash = fp.Hash
		}
	}
}

// RecordFirstPasswordNextTo notes next to the config file at path that
// hash, the built-in admin's password hash, is that of a first password
// Signalith made, for a server that cannot read the file that keeps it.
// The note can be read by the group of the config folder (the service's,
// for the Linux packages), as the config file can: it holds a hash the
// service has anyway.
func RecordFirstPasswordNextTo(path, hash string) error {
	dir := filepath.Dir(path)
	if fp, err := ReadFirstPassword(dir); err == nil && fp.Hash == hash {
		return shareWithGroup(FirstPasswordFileIn(dir), dir)
	}
	if err := writeFirstPassword(dir, FirstPassword{Hash: hash}); err != nil {
		return err
	}
	return shareWithGroup(FirstPasswordFileIn(dir), dir)
}

// WithAdminHashFile returns a copy of c whose built-in admin's password
// is hash, as kept in AdminHashFile, where the page saved it.
func (c *Config) WithAdminHashFile(hash string) *Config {
	next := *c
	next.Auth.AdminPasswordHash = hash
	next.adminHashFile = c.AdminHashFile()
	next.firstPassword.Hash = ""
	return &next
}
