// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAskKeyRefusesBadAnswers(t *testing.T) {
	key := "sgh_" + strings.Repeat("k", 52)
	answer := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, answer)
	}))
	dir := t.TempDir()
	p := Paths{Conf: dir, State: dir}
	a := &Agent{Paths: p, Settings: Settings{Server: srv.URL, Token: "sgl_" + strings.Repeat("l", 52)}, Name: "web-01", Client: srv.Client(),
		Log: slog.New(slog.DiscardHandler), Facts: func() facts { return facts{} }}
	for name, body := range map[string]string{
		"not JSON":  "{nope",
		"no key":    `{"key":"","host":"web-01"}`,
		"a bad key": `{"key":"sgh_short","host":"web-01"}`,
	} {
		answer = body
		if got, err := a.askKey(context.Background()); err == nil {
			t.Errorf("%s: key %q", name, got)
		}
	}
	answer = `{"key":"` + key + `","host":"web-01"}`
	if got, err := a.askKey(context.Background()); err != nil || got != key {
		t.Fatalf("a good answer: %q %v", got, err)
	}
	// The server is gone.
	srv.Close()
	if _, err := a.askKey(context.Background()); err == nil {
		t.Error("asked a server that is gone")
	}
}

// A key that cannot be kept on disk is not used: the agent keeps its
// line's token.
func TestEnrollKeepsNothingItCannotWrite(t *testing.T) {
	key := "sgh_" + strings.Repeat("k", 52)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"key":"`+key+`","host":"web-01"}`)
	}))
	defer srv.Close()
	for _, blocked := range []func(Paths) string{Paths.hostLineFile, Paths.hostKeyFile} {
		dir := t.TempDir()
		p := Paths{Conf: dir, State: dir}
		// A folder where the file goes.
		if err := os.MkdirAll(filepath.Join(blocked(p), "x"), 0o700); err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		a := &Agent{Paths: p, Settings: Settings{Server: srv.URL, Token: "sgl_" + strings.Repeat("l", 52)}, Name: "web-01", Client: srv.Client(),
			Log: slog.New(slog.DiscardHandler), now: func() time.Time { return now }, Facts: func() facts { return facts{} }}
		a.enroll(context.Background())
		if a.Settings.HostKey != "" {
			t.Errorf("used a key it could not keep (%s blocked)", filepath.Base(blocked(p)))
		}
		if _, err := os.Stat(blocked(p) + ".new"); err == nil {
			t.Errorf("left %s.new behind", filepath.Base(blocked(p)))
		}
	}
	if err := writePrivate(filepath.Join(t.TempDir(), "missing", "f"), "x"); err == nil {
		t.Error("wrote into a folder that is not there")
	}
}

func TestReadHostKeyRefusesDamagedKeys(t *testing.T) {
	dir := t.TempDir()
	p := Paths{Conf: dir, State: dir}
	if err := os.WriteFile(p.hostKeyFile(), []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if key, current := p.readHostKey("sgl_x"); key != "" || current {
		t.Fatalf("a damaged key was read: %q %v", key, current)
	}
	key := "sgh_" + strings.Repeat("k", 52)
	if err := os.WriteFile(p.hostKeyFile(), []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// With no line file the key is not the current line's.
	if got, current := p.readHostKey("sgl_x"); got != key || current {
		t.Fatalf("a key with no line: %q %v", got, current)
	}
}
