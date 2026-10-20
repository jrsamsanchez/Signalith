// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommands(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"version"}, &out, &errOut); err != nil || out.String() != "dev\n" {
		t.Errorf("version: %v %q", err, out.String())
	}
	out.Reset()
	if err := run([]string{"help"}, &out, &errOut); err != nil || !strings.Contains(out.String(), "signalith-agent run") {
		t.Errorf("help: %v %q", err, out.String())
	}
	for _, args := range [][]string{nil, {"bogus"}, {"run", "extra"}} {
		errOut.Reset()
		if err := run(args, &out, &errOut); err == nil || !strings.Contains(errOut.String(), "usage:") {
			t.Errorf("%v: %v %q", args, err, errOut.String())
		}
	}
}

func TestOsqueryFlagsRefusesExtensions(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	if err := os.WriteFile(in, []byte("--utc\n--extensions_autoload=/tmp/x.ext\n--disable_extensions=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"osquery-flags", in, out}, io.Discard, io.Discard); err == nil {
		t.Fatal("extensions accepted")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("checked copy written: %v", err)
	}
}
