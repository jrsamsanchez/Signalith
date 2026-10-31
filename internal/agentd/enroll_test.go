// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
)

func TestEnrollKeepsTheComputerKey(t *testing.T) {
	key := "sgh_" + strings.Repeat("k", 52)
	line := "sgl_" + strings.Repeat("l", 52)
	answer := http.StatusOK
	var auths, olds []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auths = append(auths, r.URL.Path+" "+r.Header.Get("Authorization"))
		olds = append(olds, r.Header.Get(agentproto.HeaderHostKey))
		switch {
		case r.URL.Path == agentproto.RouteEnroll && answer == http.StatusOK:
			io.WriteString(w, `{"key":"`+key+`","host":"web-01"}`)
		case r.URL.Path == agentproto.RouteEnroll:
			w.WriteHeader(answer)
			io.WriteString(w, `{"error":"no","code":"host_enrolled"}`)
		case r.URL.Path == agentproto.RouteConfig:
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":"unknown","code":"token_unknown"}`)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	p := Paths{Conf: dir, State: dir}
	writeSettings(t, p, line)
	now := time.Now()
	a := &Agent{Paths: p, Settings: Settings{Server: srv.URL, Token: line}, Name: "web-01", Client: srv.Client(),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), now: func() time.Time { return now },
		Facts: func() facts { return facts{} }}

	// Refused: the line's token stays, and the agent asks again in an hour.
	answer = http.StatusConflict
	a.enroll(context.Background())
	if a.Settings.HostKey != "" || exists(p.hostKeyFile()) {
		t.Fatal("kept a key it was refused")
	}
	a.enroll(context.Background())
	if len(auths) != 1 {
		t.Fatalf("asked again at once: %v", auths)
	}
	now = now.Add(enrollRetry)
	answer = http.StatusOK
	a.enroll(context.Background())
	if a.Settings.HostKey != key || a.Settings.secret() != key || p.enrollSecretFile() != p.hostKeyFile() {
		t.Fatalf("settings %+v", a.Settings)
	}
	if auths[1] != agentproto.RouteEnroll+" Bearer "+line {
		t.Errorf("enrolled with %q", auths[1])
	}
	if fi, err := os.Stat(p.hostKeyFile()); err != nil || fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("hostkey file: %v %v", fi, err)
	}
	if s, err := ReadSettings(p); err != nil || s.HostKey != key || s.Token != line {
		t.Errorf("read back: %+v %v", s, err)
	}
	// Installed again with another line's token: the key is only shown,
	// to get one for the new line.
	other := "sgl_" + strings.Repeat("m", 52)
	writeSettings(t, p, other)
	if s, err := ReadSettings(p); err != nil || s.HostKey != "" || s.OldHostKey != key || s.secret() != other || p.enrollSecretFile() != p.tokenFile() {
		t.Errorf("another line: %+v %v", s, err)
	}
	b := &Agent{Paths: p, Settings: Settings{Server: srv.URL, Token: other, OldHostKey: key}, Name: "web-01", Client: srv.Client(),
		Log: a.Log, now: a.now}
	b.enroll(context.Background())
	if olds[len(olds)-1] != key || b.Settings.HostKey != key || b.Settings.OldHostKey != "" {
		t.Errorf("moved: %v %+v", olds, b.Settings)
	}
	if s, err := ReadSettings(p); err != nil || s.HostKey != key {
		t.Errorf("read back after the move: %+v %v", s, err)
	}
	writeSettings(t, p, line)
	a.Settings.HostKey = key

	// A server that no longer knows the key: back to the line's token.
	err := a.sync(context.Background())
	if !errors.Is(err, errHostKeyUnknown) {
		t.Fatalf("sync: %v", err)
	}
	a.forgetHostKey()
	if a.Settings.HostKey != "" || exists(p.hostKeyFile()) || !a.enrollNext.IsZero() || a.Settings.secret() != line {
		t.Fatalf("after forget: %+v", a.Settings)
	}
	// The line's token refused is a refusal, as before.
	if err := a.sync(context.Background()); !errors.Is(err, errTokenRefused) {
		t.Fatalf("sync with the line's token: %v", err)
	}
}

func writeSettings(t *testing.T, p Paths, token string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(p.Conf, "agent.conf"), []byte("SERVER=https://siem:7779\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.tokenFile(), []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
