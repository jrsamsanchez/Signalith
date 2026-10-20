// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package safelog

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLongValuesAreCut(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(New(slog.NewTextHandler(&buf, nil)))
	huge := strings.Repeat("A", 1_000_000)
	log.Warn("sign-in failed", "user", huge, "client", "203.0.113.9", "locked_out", false)
	line := buf.String()
	if len(line) > 400 || !strings.Contains(line, "more bytes]") || !strings.Contains(line, "client=203.0.113.9") || !strings.Contains(line, "locked_out=false") {
		t.Errorf("%d bytes: %.300s", len(line), line)
	}

	buf.Reset()
	log.With("host", huge).Error("ingest failed", "err", errors.New(huge), "records", 3, slog.Group("req", "path", huge))
	line = buf.String()
	if len(line) > MaxValue+3*MaxShort+300 || !strings.Contains(line, "records=3") {
		t.Errorf("%d bytes: %.300s", len(line), line)
	}

	buf.Reset()
	log.Info("ok", "err", errors.New("short error"), "list", []string{"a", "b"}, "n", 5)
	if got := buf.String(); !strings.Contains(got, `err="short error"`) || !strings.Contains(got, `list="[a b]"`) || !strings.Contains(got, "n=5") {
		t.Errorf("short values changed: %s", got)
	}
}

func TestCut(t *testing.T) {
	if got := Cut("héllo wörld", 2); got != "h…[12 more bytes]" {
		t.Errorf("Cut = %q", got)
	}
	if got := Cut("short", 10); got != "short" {
		t.Errorf("Cut = %q", got)
	}
}

func TestRotatingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.log")
	r, err := OpenRotating(path, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	line := strings.Repeat("x", 39) + "\n"
	for i := 0; i < 20; i++ {
		fmt.Fprint(r, line)
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	total := int64(0)
	for _, e := range entries {
		names = append(names, e.Name())
		info, _ := e.Info()
		total += info.Size()
		if info.Size() > 100 {
			t.Errorf("%s is %d bytes, over the limit", e.Name(), info.Size())
		}
	}
	if strings.Join(names, ",") != "signalith.log,signalith.log.1,signalith.log.2" || total > 300 {
		t.Errorf("files %v, %d bytes in all", names, total)
	}
	// Reopening continues the current file instead of starting over.
	r.Close()
	r2, err := OpenRotating(path, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	before, _ := os.Stat(path)
	fmt.Fprint(r2, "y\n")
	after, _ := os.Stat(path)
	if after.Size() != before.Size()+2 && after.Size() != 2 {
		t.Errorf("size %d -> %d", before.Size(), after.Size())
	}
}
