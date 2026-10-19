// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package safelog

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type longName struct{ n int }

func (l longName) String() string { return strings.Repeat("s", l.n) }

func TestGroupsAndStringers(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(New(slog.NewTextHandler(&buf, nil)))
	log.WithGroup("req").Info("seen", "user", longName{MaxShort + 50}, "note", longName{10})
	line := buf.String()
	if !strings.Contains(line, "req.user=") || !strings.Contains(line, "…[50 more bytes]") || !strings.Contains(line, "req.note=ssssssssss") {
		t.Errorf("line = %s", line)
	}
	if strings.Contains(line, strings.Repeat("s", MaxShort+1)) {
		t.Errorf("the user was not cut: %s", line)
	}
	if !New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})).Enabled(t.Context(), slog.LevelWarn) {
		t.Error("warnings are off")
	}
}

func TestRotatingDefaultsAndFailures(t *testing.T) {
	dir := t.TempDir()
	r, err := OpenRotating(filepath.Join(dir, "a.log"), 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	if r.maxSize != DefaultMaxSize || r.backups != DefaultBackups {
		t.Errorf("defaults = %d %d", r.maxSize, r.backups)
	}
	// Writing after Close opens the file again.
	r.Close()
	if err := r.Close(); err != nil {
		t.Errorf("second close = %v", err)
	}
	if _, err := r.Write([]byte("again\n")); err != nil {
		t.Fatal(err)
	}
	r.Close()
	if b, _ := os.ReadFile(filepath.Join(dir, "a.log")); string(b) != "again\n" {
		t.Errorf("file = %q", b)
	}

	if _, err := OpenRotating(filepath.Join(dir, "missing", "a.log"), 10, 1); err == nil {
		t.Error("a file in a missing folder opened")
	}

	// The old file's name is taken by a folder that cannot be removed, so
	// rotating fails; once the file is twice its size it is emptied.
	path := filepath.Join(dir, "b.log")
	if err := os.MkdirAll(filepath.Join(path+".1", "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err = OpenRotating(path, 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Write([]byte(strings.Repeat("x", 25))); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "log rotation failed") || !strings.HasSuffix(string(b), "y") || strings.Contains(string(b), "xxx") {
		t.Errorf("file = %q", b)
	}
	// Rotation is not tried again straight away.
	if _, err := r.Write([]byte("z")); err != nil {
		t.Fatal(err)
	}
	if b2, _ := os.ReadFile(path); string(b2) != string(b)+"z" {
		t.Errorf("file after retry = %q", b2)
	}
}

func TestShortFailedRotationKeepsLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.log")
	if err := os.MkdirAll(filepath.Join(path+".1", "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRotating(path, 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.Write([]byte(strings.Repeat("x", 12)))
	r.Write([]byte("y"))
	if b, _ := os.ReadFile(path); string(b) != strings.Repeat("x", 12)+"y" {
		t.Errorf("file = %q", b)
	}
}
