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

func TestSecretsCommandArguments(t *testing.T) {
	var out strings.Builder
	if err := runSecrets(nil, os.Stdin, &out); err == nil || !strings.Contains(out.String(), "signalith secrets") {
		t.Errorf("no command: %v\n%s", err, out.String())
	}
	for _, help := range []string{"help", "-h", "--help"} {
		out.Reset()
		if err := runSecrets([]string{help}, os.Stdin, &out); err != nil || !strings.Contains(out.String(), "signalith secrets") {
			t.Errorf("%s: %v\n%s", help, err, out.String())
		}
	}
	path, _ := secretsSetup(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"bogus"}, `unknown secrets command "bogus"`},
		{[]string{"status", "extra", "-c", path}, "takes no arguments"},
		{[]string{"set", "-c", path}, "name the setting to store"},
		{[]string{"set", "server.listen", "-c", path}, "server.listen cannot be set this way"},
		{[]string{"status", "-nosuchflag"}, "flag provided but not defined"},
		{[]string{"status", "-c", filepath.Join(t.TempDir(), "missing.yaml")}, ""},
	} {
		out.Reset()
		if err := runSecrets(c.args, os.Stdin, &out); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v", c.args, err)
		}
	}
}

// A value encrypted with a master key this server does not have is
// reported, and left as it is.
func TestSecretsUnreadableValue(t *testing.T) {
	path, _ := secretsSetup(t)
	var out strings.Builder
	if err := runSecrets([]string{"encrypt", "-c", path}, os.Stdin, &out); err != nil {
		t.Fatalf("encrypt: %v\n%s", err, out.String())
	}
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
	replaced := false
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "password:") {
			lines[i] = "  password: " + sealed
			replaced = true
		}
	}
	if !replaced {
		t.Fatalf("no password line in\n%s", b)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	err = runSecrets([]string{"status", "-c", path}, os.Stdin, &out)
	if err == nil || !strings.Contains(err.Error(), "1 stored value cannot be decrypted") || !strings.Contains(out.String(), "cannot be decrypted") {
		t.Errorf("status: %v\n%s", err, out.String())
	}
	if strings.Contains(out.String(), "lost-pw") {
		t.Errorf("status shows the value:\n%s", out.String())
	}
	out.Reset()
	err = runSecrets([]string{"encrypt", "-c", path}, os.Stdin, &out)
	if err == nil || !strings.Contains(err.Error(), "cannot be decrypted and was left as it was") {
		t.Errorf("encrypt: %v\n%s", err, out.String())
	}
	if after, _ := os.ReadFile(path); !strings.Contains(string(after), sealed) {
		t.Errorf("the value was changed:\n%s", after)
	}
}
