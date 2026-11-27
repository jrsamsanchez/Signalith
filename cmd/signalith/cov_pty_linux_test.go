// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// openPTY returns a pseudo-terminal: what is written to master is typed
// at slave. It skips the test where none can be made.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		t.Skipf("no pseudo-terminal: %v", err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		m.Close()
		t.Skipf("no pseudo-terminal: %v", err)
	}
	s, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		t.Skipf("no pseudo-terminal: %v", err)
	}
	if !term.IsTerminal(int(s.Fd())) {
		m.Close()
		s.Close()
		t.Skip("the pseudo-terminal is not a terminal")
	}
	// Echo is drained so the terminal never blocks.
	go io.Copy(io.Discard, m)
	t.Cleanup(func() { s.Close(); m.Close() })
	return m, s
}

// typeLines types each line at the terminal, a little apart, so each is
// read by the question it answers.
func typeLines(m *os.File, lines ...string) {
	go func() {
		for _, l := range lines {
			time.Sleep(50 * time.Millisecond)
			io.WriteString(m, l+"\n")
		}
	}()
}

// At a terminal, readSecret asks twice and the entries must match.
func TestReadSecretAtATerminal(t *testing.T) {
	for _, c := range []struct {
		name    string
		lines   []string
		orEmpty bool
		want    string
		err     string
	}{
		{"match", []string{"s3cret-value", "s3cret-value"}, false, "s3cret-value", ""},
		{"differ", []string{"one-value", "another"}, false, "", "do not match"},
		{"empty", []string{""}, false, "", "nothing entered"},
		{"empty allowed", []string{""}, true, "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			m, s := openPTY(t)
			typeLines(m, c.lines...)
			var prompt bytes.Buffer
			got, err := readSecret(s, &prompt, "Value: ", c.orEmpty)
			if got != c.want || (err == nil) != (c.err == "") || err != nil && !strings.Contains(err.Error(), c.err) {
				t.Errorf("got %q, %v", got, err)
			}
			if !strings.Contains(prompt.String(), "Value: ") {
				t.Errorf("prompt %q", prompt.String())
			}
		})
	}
}

// secrets set at a terminal: Enter makes a shared agent token.
func TestSecretsSetMakesTokenAtATerminal(t *testing.T) {
	path, _ := secretsSetup(t)
	m, s := openPTY(t)
	typeLines(m, "")
	var out bytes.Buffer
	if err := runSecrets([]string{"set", "ingest.tokens", "-c", path}, s, &out); err != nil || !strings.Contains(out.String(), "It is shown only now") {
		t.Errorf("%v\n%s", err, out.String())
	}
}

// At a terminal, confirm asks and takes only yes.
func TestClusterConfirmAtATerminal(t *testing.T) {
	for _, c := range []struct {
		answer string
		ok     bool
	}{{"y", true}, {"YES", true}, {"n", false}, {"", false}} {
		m, s := openPTY(t)
		typeLines(m, c.answer)
		var errOut bytes.Buffer
		x := &clusterCLI{in: s, errOut: &errOut}
		err := x.confirm("Go on?", false)
		if (err == nil) != c.ok || !strings.Contains(errOut.String(), "Go on? [y/N]") {
			t.Errorf("%q: %v %q", c.answer, err, errOut.String())
		}
	}
	// Not at a terminal, -yes is needed.
	devnull, _ := os.Open(os.DevNull)
	defer devnull.Close()
	if err := (&clusterCLI{in: devnull}).confirm("Go on?", false); err == nil || !strings.Contains(err.Error(), "add -yes") {
		t.Errorf("not at a terminal: %v", err)
	}
	if err := (&clusterCLI{in: devnull}).confirm("Go on?", true); err != nil {
		t.Errorf("-yes: %v", err)
	}
}

// At a terminal, readPassphrase asks once.
func TestReadPassphraseAtATerminal(t *testing.T) {
	m, s := openPTY(t)
	typeLines(m, "a long passphrase")
	var prompt bytes.Buffer
	if got, err := readPassphrase(s, &prompt, "Passphrase: "); err != nil || got != "a long passphrase" || !strings.Contains(prompt.String(), "Passphrase: ") {
		t.Errorf("%q %v %q", got, err, prompt.String())
	}
	m, s = openPTY(t)
	typeLines(m, "")
	if _, err := readPassphrase(s, &prompt, "Passphrase: "); err == nil || !strings.Contains(err.Error(), "no passphrase entered") {
		t.Errorf("empty: %v", err)
	}
}

// restore asks before writing at a terminal.
func TestRestoreAsksAtATerminal(t *testing.T) {
	src := backupInstall(t, map[string]string{"data/lookups/a.csv": "x\n"})
	zipFile := filepath.Join(t.TempDir(), "b.zip")
	if _, err := writeBackup(zipFile, loadForBackup(t, src), false, false, ""); err != nil {
		t.Fatal(err)
	}
	dst := backupInstall(t, map[string]string{})
	m, s := openPTY(t)
	typeLines(m, "n")
	var out bytes.Buffer
	if err := restoreBackup(zipFile, "", loadForBackup(t, dst), false, s, &out); err == nil || !strings.Contains(err.Error(), "nothing was changed") || !strings.Contains(out.String(), "Restore these files? [y/N]") {
		t.Errorf("no: %v\n%s", err, out.String())
	}
	m, s = openPTY(t)
	typeLines(m, "y")
	out.Reset()
	if err := restoreBackup(zipFile, "", loadForBackup(t, dst), false, s, &out); err != nil || !strings.Contains(out.String(), "Restored") {
		t.Errorf("yes: %v\n%s", err, out.String())
	}
}

// tokens revoke asks before revoking at a terminal.
func TestTokensRevokeAsksAtATerminal(t *testing.T) {
	noServiceSettings(t)
	path := tokensConfig(t)
	devnull, _ := os.Open(os.DevNull)
	defer devnull.Close()
	var out, errOut bytes.Buffer
	if err := runTokens([]string{"create", "-c", path, "Web"}, devnull, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	if err := runTokens([]string{"revoke", "-c", path, "Web"}, devnull, &out, &errOut); err == nil || !strings.Contains(err.Error(), "add -yes") {
		t.Errorf("not at a terminal: %v", err)
	}
	m, s := openPTY(t)
	typeLines(m, "no")
	if err := runTokens([]string{"revoke", "-c", path, "Web"}, s, &out, &errOut); err == nil || !strings.Contains(err.Error(), "nothing was revoked") {
		t.Errorf("no: %v", err)
	}
	m, s = openPTY(t)
	typeLines(m, "yes")
	out.Reset()
	if err := runTokens([]string{"revoke", "-c", path, "Web"}, s, &out, &errOut); err != nil || !strings.Contains(out.String(), `Revoked "Web"`) {
		t.Errorf("yes: %v %s", err, out.String())
	}
	if !strings.Contains(errOut.String(), `Revoke "Web"?`) {
		t.Errorf("no question: %s", errOut.String())
	}
}
