// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// sealWithLostKey replaces opensearch.password in path with a value
// encrypted with a master key this server does not have.
func sealWithLostKey(t *testing.T, path string) string {
	t.Helper()
	other := secrets.NewKeyring(t.TempDir())
	sealed, err := other.Seal("opensearch.password", "lost-pw")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "password:") {
			lines[i] = "  password: " + sealed
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	return sealed
}

// decrypt and rotate-master leave a value they cannot decrypt as it is,
// and say so.
func TestSecretsDecryptAndRotateLeaveUnreadable(t *testing.T) {
	path, _ := secretsSetup(t)
	if _, err := runCmd(t, "", "encrypt", "-c", path); err != nil {
		t.Fatal(err)
	}
	sealed := sealWithLostKey(t, path)

	out, err := runCmd(t, "", "rotate-master", "-c", path)
	if err == nil || !strings.Contains(err.Error(), "cannot be decrypted") {
		t.Errorf("rotate: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), sealed) {
		t.Error("rotate changed the unreadable value")
	}
	out, err = runCmd(t, "", "decrypt", "-c", path)
	if err == nil || !strings.Contains(err.Error(), "cannot be decrypted") {
		t.Errorf("decrypt: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), sealed) {
		t.Error("decrypt changed the unreadable value")
	}
	// Decrypting again finds nothing it can decrypt.
	out, err = runCmd(t, "", "decrypt", "-c", path)
	if !strings.Contains(out, "Nothing to decrypt") {
		t.Errorf("decrypt again: %v\n%s", err, out)
	}
}

// The secrets commands refuse what they cannot use.
func TestSecretsCommandRefusals(t *testing.T) {
	path, _ := secretsSetup(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"bogus"}, `unknown secrets command "bogus"`},
		{[]string{"status", "extra", "-c", path}, "takes no arguments"},
		{[]string{"set", "-c", path}, "name the setting"},
		{[]string{"set", "nope.field", "-c", path}, "cannot be set this way"},
		{[]string{"status", "-bogus"}, "flag provided but not defined"},
		{[]string{"status", "-c", filepath.Join(t.TempDir(), "none.yaml")}, ""},
	} {
		if out, err := runCmd(t, "", c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v\n%s", c.args, err, out)
		}
	}
	if out, err := runCmd(t, "", "help"); err != nil || !strings.Contains(out, "rotate-master") {
		t.Errorf("help: %v\n%s", err, out)
	}
	// set with nothing entered, or with a key longer than any.
	if out, err := runCmd(t, "", "set", "okta.private_key", "-c", path); err == nil || !strings.Contains(err.Error(), "nothing entered") {
		t.Errorf("empty okta key: %v\n%s", err, out)
	}
	// A file, not a pipe: a pipe's buffer may be smaller than the key.
	long := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(long, []byte(strings.Repeat("k", 17<<10)), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(long)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	var out strings.Builder
	if err := runSecrets([]string{"set", "okta.private_key", "-c", path}, in, &out); err == nil || !strings.Contains(err.Error(), "longer than any") {
		t.Errorf("long okta key: %v\n%s", err, out.String())
	}
}
