// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// failSettings is nodeSettings whose own layer, or saves of one scope,
// fail as the test says.
type failSettings struct {
	*nodeSettings
	fmu       sync.Mutex
	ownErr    error
	saveErr   error
	saveScope config.Scope // "" fails every save
}

func (f *failSettings) fail(own, save error, scope config.Scope) {
	f.fmu.Lock()
	defer f.fmu.Unlock()
	f.ownErr, f.saveErr, f.saveScope = own, save, scope
}

func (f *failSettings) Layer(ctx context.Context, node string) (*config.Shared, *shared.NodeCfg, error) {
	f.fmu.Lock()
	err := f.ownErr
	f.fmu.Unlock()
	if node == "" && err != nil {
		return nil, nil, err
	}
	return f.nodeSettings.Layer(ctx, node)
}

func (f *failSettings) Save(ctx context.Context, by, node string, base *config.Shared, res *config.SharedEditResult, versions map[string]int64) (map[string]int64, error) {
	f.fmu.Lock()
	err, scope := f.saveErr, f.saveScope
	f.fmu.Unlock()
	if err != nil && (scope == "" || scope == res.Scope) {
		return nil, err
	}
	return f.nodeSettings.Save(ctx, by, node, base, res, versions)
}

func newFailSettingsServer(t *testing.T) (*failSettings, *Server, func(method, path, body string) (int, map[string]any)) {
	t.Helper()
	fs := &failSettings{nodeSettings: newNodeSettings()}
	ts, srv, _ := newSettingsServer(t, "", func(s *Server) { s.Settings, s.Cluster = fs, threeServers() })
	return fs, srv, func(method, path, body string) (int, map[string]any) {
		t.Helper()
		return do(t, ts, method, path, body, true)
	}
}

// A shared save refused part way says what was saved before; a store
// that cannot be read or written refuses the change.
func TestSharedPutFailures(t *testing.T) {
	fs, srv, call := newFailSettingsServer(t)

	fs.fail(errDown, nil, "")
	if code, _ := call("PUT", "/api/settings", `{"values":{"search.max_events":5}}`); code != http.StatusInternalServerError {
		t.Errorf("own layer unreadable: %d", code)
	}
	fs.fail(nil, nil, "")

	fs.memSettings.mu.Lock()
	fs.memSettings.writable = errors.New("the shared settings are being moved")
	fs.memSettings.mu.Unlock()
	if code, out := call("PUT", "/api/settings", `{"values":{"search.max_events":5}}`); code != http.StatusServiceUnavailable || !strings.Contains(out["error"].(string), "being moved") {
		t.Errorf("not writable: %d %v", code, out)
	}
	fs.memSettings.mu.Lock()
	fs.memSettings.writable = nil
	fs.memSettings.mu.Unlock()

	// The shared value is saved first; the server's own is then refused
	// as stale, and the answer says which were saved.
	code, out := call("PUT", "/api/settings", `{"values":{"search.max_events":5,"syslog.udp":"0.0.0.0:1514"},"if_version":{"syslog.udp":9}}`)
	if code != http.StatusPreconditionFailed || !slices.Equal(toList(out["saved"]), []string{"search.max_events"}) {
		t.Errorf("stale part way: %d %v", code, out)
	}

	fs.fail(nil, errDown, config.ScopeServer)
	code, out = call("PUT", "/api/settings", `{"values":{"search.max_events":6,"syslog.udp":"0.0.0.0:2514"}}`)
	if code != http.StatusInternalServerError || !strings.Contains(out["error"].(string), "(search.max_events were saved before this)") {
		t.Errorf("failed part way: %d %v", code, out)
	}
	fs.fail(nil, nil, "")

	// A connection setting needs the settings file this server's page
	// writes, which cannot be read.
	file := srv.conf().SettingsFile()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("values: [this is: not: settings\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := call("PUT", "/api/settings", `{"values":{"opensearch.username":"siem"}}`); code != http.StatusConflict || out["code"] != "settings_file" {
		t.Errorf("unreadable settings file: %d %v", code, out)
	}
}

// Taking another server's refusal out of its settings is refused when
// they cannot be saved.
func TestSharedPutRetryOnOtherServerFails(t *testing.T) {
	fs, _, call := newFailSettingsServer(t)
	fs.others["n_a"] = &config.Shared{Self: "siem-a", Server: map[string]*config.PageEntry{},
		Refused: map[string]config.SharedRefusal{"search.max_events": {Reason: "too many", At: time.Now().Add(-time.Hour)}}}
	fs.fail(nil, errDown, "")
	if code, out := call("PUT", "/api/settings", `{"server":"siem-a","retry":["search.max_events"]}`); code != http.StatusInternalServerError {
		t.Errorf("retry: %d %v", code, out)
	}
	fs.fail(nil, &shared.PausedError{}, "")
	if code, out := call("PUT", "/api/settings", `{"server":"siem-a","retry":["search.max_events"]}`); code != http.StatusServiceUnavailable {
		t.Errorf("retry while paused: %d %v", code, out)
	}
}
