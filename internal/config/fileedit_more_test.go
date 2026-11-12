// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetOpenSearchKeepsTheRest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	text := "# my settings\nopensearch:\n    url: https://old:9200 # the old one\nsearch:\n    max_events: 500\n"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetOpenSearch(path, "https://os.internal:9200", "ca.pem", "cert.pem", "key.pem"); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"# my settings", "# the old one", "os.internal:9200", "ca_file: ca.pem", "cert_file: cert.pem", "key_file: key.pem", "max_events: 500"} {
		if !strings.Contains(s, want) {
			t.Errorf("the file lacks %q:\n%s", want, s)
		}
	}
	if err := SetOpenSearch(filepath.Join(dir, "missing.yaml"), "u", "", "", ""); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("SetOpenSearch of a missing file = %v", err)
	}
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("opensearch: just text\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetOpenSearch(bad, "u", "", "", ""); err == nil || !strings.Contains(err.Error(), "is not a section of settings") {
		t.Errorf("SetOpenSearch over a value = %v", err)
	}
}

func TestSetScalarRefusals(t *testing.T) {
	for _, c := range []struct {
		text string
		keys []string
		err  string
	}{
		{"- a\n- b\n", []string{"auth", "x"}, "not a YAML mapping"},
		{"auth:\n    x:\n        y: 1\n", []string{"auth", "x"}, "is not a single value"},
		{"auth: [\n", []string{"auth", "x"}, "not valid YAML"},
	} {
		if _, err := setScalar([]byte(c.text), c.keys, "v"); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("setScalar(%q) = %v, want %q", c.text, err, c.err)
		}
	}
	// Quoted values are replaced in place, the comment kept.
	for _, text := range []string{
		"auth:\n    x: \"a \\\" b\" # c\n",
		"auth:\n    x: 'it''s' # c\n",
	} {
		out, err := setScalar([]byte(text), []string{"auth", "x"}, "new")
		if err != nil || !strings.Contains(string(out), "# c") || valueAt(out, []string{"auth", "x"}) != "new" {
			t.Errorf("setScalar(%q) = %q, %v", text, out, err)
		}
	}
	// A block value is written out again.
	out, err := setScalar([]byte("auth:\n    x: |\n        two\n        lines\n"), []string{"auth", "x"}, "one")
	if err != nil || valueAt(out, []string{"auth", "x"}) != "one" {
		t.Errorf("setScalar of a block = %q, %v", out, err)
	}
	if got := valueAt([]byte("a: [\n"), []string{"a"}); got != "" {
		t.Errorf("valueAt of broken YAML = %q", got)
	}
	if got := valueAt([]byte("a: 1\n"), []string{"a", "b"}); got != "" {
		t.Errorf("valueAt through a value = %q", got)
	}
}

func TestClosingQuote(t *testing.T) {
	for _, c := range []struct {
		b      string
		q, esc byte
		want   int
	}{
		{`"abc" x`, '"', '\\', 5}, {`"a\"b"`, '"', '\\', 6}, {`'it''s'`, '\'', 0, 7},
		{`"open`, '"', '\\', -1}, {``, '"', '\\', -1}, {`x"`, '"', '\\', -1},
	} {
		if got := closingQuote([]byte(c.b), c.q, c.esc); got != c.want {
			t.Errorf("closingQuote(%q) = %d, want %d", c.b, got, c.want)
		}
	}
}

func TestCheckSecretValues(t *testing.T) {
	for _, c := range []struct {
		field, value, err string
	}{
		{"assistant.api_key", "sk-123", ""},
		{"assistant.api_key", "enc:v1:abc:def", "cannot start with enc:v"},
		{"okta.private_key", "  ", "the private key is empty"},
		{"okta.private_key", "not a key", "key"},
		{"ingest.tokens", "short", "at least 16 characters"},
		{"ingest.tokens", strings.Repeat("t", 20), ""},
		{"server.listen", "x", "cannot be set this way"},
	} {
		err := CheckSecret(c.field, c.value)
		if c.err == "" && err != nil || c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)) {
			t.Errorf("CheckSecret(%s, %q) = %v, want %q", c.field, c.value, err, c.err)
		}
	}
	if _, err := ReadForEdit(filepath.Join(t.TempDir(), "none.yaml")); err == nil || !strings.Contains(err.Error(), "signalith init") {
		t.Errorf("ReadForEdit of a missing file = %v", err)
	}
}

func TestMoveURLPasswordForms(t *testing.T) {
	// Already a username: the address's are only removed.
	text := "opensearch:\n    url: https://u:p@os:9200\n    username: admin\n    password: other\n"
	out, changed, err := MoveURLPassword([]byte(text))
	if err != nil || !changed {
		t.Fatalf("MoveURLPassword = %v %v", changed, err)
	}
	if s := string(out); strings.Contains(s, "u:p@") || !strings.Contains(s, "username: admin") || !strings.Contains(s, "password: other") {
		t.Errorf("out = %s", s)
	}
	// A flow-style section takes the document route.
	out, changed, err = MoveURLPassword([]byte("opensearch: {url: \"https://u:p@os:9200\"}\n"))
	if err != nil || !changed || valueAt(out, []string{"opensearch", "password"}) != "p" || valueAt(out, []string{"opensearch", "username"}) != "u" {
		t.Errorf("flow style = %q %v %v", out, changed, err)
	}
	if _, _, err := MoveURLPassword([]byte("opensearch: [\n")); err == nil {
		t.Error("MoveURLPassword of broken YAML")
	}
	if out, ok := addAfter([]byte("opensearch:\n    url: x\n    password: y\n"), "opensearch", "url", "password", "z"); ok {
		t.Errorf("addAfter over a key that is there = %q", out)
	}
	if _, ok := addAfter([]byte("other: 1\n"), "opensearch", "url", "password", "z"); ok {
		t.Error("addAfter without the section")
	}
	if _, ok := addAfter([]byte("opensearch:\n    url: |\n        x\n"), "opensearch", "url", "password", "z"); ok {
		t.Error("addAfter after a block value")
	}
	out, ok := addAfter([]byte("opensearch:\n    url: x"), "opensearch", "url", "password", "a b")
	if !ok || valueAt(out, []string{"opensearch", "password"}) != "a b" {
		t.Errorf("addAfter at the end of a file without a line break = %q %v", out, ok)
	}
}

func TestPageFileOfAConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	if err := validConfig(t).Save(path); err != nil {
		t.Fatal(err)
	}
	f := PageFile{Config: path}
	p, err := f.Read()
	if err != nil || len(p.Settings) != 0 {
		t.Fatalf("Read of no settings file = %+v %v", p, err)
	}
	if _, err := f.Backup(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Backup of no settings file = %v", err)
	}
	settings, err := SettingsFileFor(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte("not: [valid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var pe *PageFileError
	if _, err := f.Read(); !errors.As(err, &pe) || pe.Unwrap() == nil {
		t.Errorf("Read of a broken file = %v", err)
	}
	backup, err := f.Backup()
	if err != nil || backup != settings+".broken" {
		t.Fatalf("Backup = %q %v", backup, err)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Errorf("the backup is not there: %v", err)
	}
	missing := PageFile{Config: filepath.Join(dir, "none.yaml")}
	if _, err := missing.Read(); err == nil {
		t.Error("Read for a missing config")
	}
	if _, err := missing.Backup(); err == nil {
		t.Error("Backup for a missing config")
	}
	if err := missing.Write(&PageSettings{}); err == nil {
		t.Error("Write for a missing config")
	}
}
