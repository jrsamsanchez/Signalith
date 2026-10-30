// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// passwdEnv clears what would pick another state folder or password.
func passwdEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"SIGNALITH_STATE_DIR", "SIGNALITH_LOOKUPS_DIR", "SIGNALITH_ADMIN_PASSWORD", "SIGNALITH_ADMIN_PASSWORD_FILE", "SIGNALITH_NEW_PASSWORD"} {
		t.Setenv(k, "")
	}
	noServiceSettings(t)
}

func initForPasswd(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	captureStdout(t, func() {
		if err := cmdInit([]string{"-c", path, "-admin-password", "first-password-1"}); err != nil {
			t.Fatal(err)
		}
	})
	return path
}

func TestPasswdErrors(t *testing.T) {
	passwdEnv(t)
	if _, err := capture(t, func() error { return cmdPasswd([]string{"-c", filepath.Join(t.TempDir(), "missing.yaml")}) }); err == nil || !strings.Contains(err.Error(), "config file") {
		t.Errorf("no config: %v", err)
	}
	path := initForPasswd(t)
	before, _ := os.ReadFile(path)
	// A password with the admin's name in it is refused.
	t.Setenv("SIGNALITH_NEW_PASSWORD", "x-"+config.DefaultAdminUser+"-x-long")
	if _, err := capture(t, func() error { return cmdPasswd([]string{"-c", path}) }); err == nil {
		t.Error("a password with the username in it was taken")
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("a refused password changed the file")
	}
}

// signalith passwd -local on a server that was never a member of a
// cluster keeps the password in the state folder; a later passwd without
// -local keeps using that file, since it replaces signalith.yaml's.
func TestPasswdLocalThenAgain(t *testing.T) {
	passwdEnv(t)
	path := initForPasswd(t)
	before, _ := os.ReadFile(path)
	t.Setenv("SIGNALITH_NEW_PASSWORD", "second-password-2")
	out, err := capture(t, func() error { return cmdPasswd([]string{"-local", "-c", path}) })
	if err != nil || !strings.Contains(out, "on this server only. It replaces the configured password") {
		t.Fatalf("-local: %v\n%s", err, out)
	}
	hashFile := config.AdminHashFileIn(config.StateDirFor(path))
	if _, err := os.Stat(hashFile); err != nil {
		t.Fatalf("no hash file: %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("-local changed signalith.yaml")
	}
	if strings.Contains(out, "second-password-2") {
		t.Errorf("the password was printed:\n%s", out)
	}
	c, err := config.Load(path)
	if err != nil || !c.CheckPassword(config.DefaultAdminUser, "second-password-2") {
		t.Fatalf("the -local password does not work: %v", err)
	}

	t.Setenv("SIGNALITH_NEW_PASSWORD", "third-password-3")
	out, err = capture(t, func() error { return cmdPasswd([]string{"-c", path}) })
	if err != nil || !strings.Contains(out, "It is kept in "+hashFile+" and replaces the first password") {
		t.Fatalf("again: %v\n%s", err, out)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("passwd changed signalith.yaml while a hash file replaces it")
	}
	c, err = config.Load(path)
	if err != nil || !c.CheckPassword(config.DefaultAdminUser, "third-password-3") || c.CheckPassword(config.DefaultAdminUser, "second-password-2") {
		t.Fatalf("the new password does not work: %v", err)
	}
}

// With SIGNALITH_ADMIN_PASSWORD set in this shell, passwd says that it
// replaces the password in the file wherever it is set.
func TestPasswdNotesTheEnvironmentPassword(t *testing.T) {
	passwdEnv(t)
	path := initForPasswd(t)
	t.Setenv("SIGNALITH_NEW_PASSWORD", "second-password-2")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "env-password-9")
	out, err := capture(t, func() error { return cmdPasswd([]string{"-c", path}) })
	if err != nil || !strings.Contains(out, "Note: SIGNALITH_ADMIN_PASSWORD is set in this environment") {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "env-password-9") {
		t.Errorf("the password was printed:\n%s", out)
	}
}

func TestInitRefusesToOverwrite(t *testing.T) {
	passwdEnv(t)
	path := initForPasswd(t)
	before, _ := os.ReadFile(path)
	if _, err := capture(t, func() error { return cmdInit([]string{"-c", path, "-admin-password", "other-password-1"}) }); err == nil || !strings.Contains(err.Error(), "use -force to overwrite it") {
		t.Errorf("init over a config: %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("the config was changed")
	}
	if _, err := capture(t, func() error {
		return cmdInit([]string{"-c", path, "-force", "-admin-password", config.DefaultAdminUser + "-password"})
	}); err == nil || !strings.Contains(err.Error(), "-admin-password") {
		t.Errorf("a password with the username in it: %v", err)
	}
	// A generated password is shown once.
	out, err := capture(t, func() error { return cmdInit([]string{"-c", path, "-force"}) })
	if err != nil || !strings.Contains(out, "(shown once;") {
		t.Errorf("-force with a generated password: %v\n%s", err, out)
	}
}

func TestHTTPSSummaryModes(t *testing.T) {
	c := config.Default()
	c.Server.TLS = &config.ServerTLS{Mode: config.TLSOff}
	if got := httpsSummary(c); !strings.Contains(got, "HTTPS is off") {
		t.Errorf("off: %s", got)
	}
	dir := t.TempDir()
	c.Server.TLS = &config.ServerTLS{Mode: config.TLSFiles}
	c.Server.TLSCert, c.Server.TLSKey = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if got := httpsSummary(c); !strings.Contains(got, "HTTPS is on with the certificate in") || !strings.Contains(got, "cert.pem") {
		t.Errorf("files: %s", got)
	}
}

// signalith passwd is the way back in when every other admin is locked
// out, so it turns a built-in admin that was turned off on again.
func TestPasswdTurnsTheBuiltinAdminOn(t *testing.T) {
	passwdEnv(t)
	path := initForPasswd(t)
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.SetFileBuiltinDisabled(c.UsersFile(), true); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_NEW_PASSWORD", "harbor-kettle-violet-9")
	out := captureStdout(t, func() {
		if err := cmdPasswd([]string{"-c", path}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, builtinOnAtRestart) {
		t.Errorf("passwd does not say the built-in admin turns on again:\n%s", out)
	}
	// Still off until the server starts with the new password.
	if off, err := users.ReadFileBuiltinDisabled(c.UsersFile()); err != nil || !off {
		t.Errorf("turned on before the new password is in use: %v, %v", off, err)
	}
	people, err := users.Open(c.UsersFile())
	if err != nil {
		t.Fatal(err)
	}
	people.BuiltinAdmin = c.Auth.AdminUser
	if on, err := people.StartBuiltin(context.Background()); err != nil || !on || people.BuiltinDisabled() {
		t.Errorf("at start: %v, %v, off %v", on, err, people.BuiltinDisabled())
	}
	// Not turned off: nothing is said.
	out = captureStdout(t, func() {
		if err := cmdPasswd([]string{"-c", path}); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, builtinOnAtRestart) {
		t.Errorf("passwd says it turns on a built-in admin that is on:\n%s", out)
	}
}
