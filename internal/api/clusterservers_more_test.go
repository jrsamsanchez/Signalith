// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// failLifecycle is fakeLifecycle whose requests and removals fail while
// their errors are set.
type failLifecycle struct {
	*fakeLifecycle
	mu                   sync.Mutex
	submitErr, removeErr error
}

func (f *failLifecycle) fail(submit, remove error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.submitErr, f.removeErr = submit, remove
}

func (f *failLifecycle) Submit(ctx context.Context, typ, target string, args any, by string) (*shared.Request, error) {
	f.mu.Lock()
	err := f.submitErr
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return f.fakeLifecycle.Submit(ctx, typ, target, args, by)
}

func (f *failLifecycle) Remove(ctx context.Context, nodeID, name, by string, live bool) (shared.RemovedServer, []string, error) {
	f.mu.Lock()
	err := f.removeErr
	f.mu.Unlock()
	if err != nil {
		return shared.RemovedServer{}, nil, err
	}
	return f.fakeLifecycle.Remove(ctx, nodeID, name, by, live)
}

// Moving the background jobs names a server that can take them; the
// server cannot be one that is not running normally, and a request that
// cannot be made is 503.
func TestJobsMoveRefusals(t *testing.T) {
	cl := &lifecycleCluster{cState: cluster.StateDraining}
	lf := &failLifecycle{fakeLifecycle: &fakeLifecycle{rotation: true, members: []string{"siem-a", "siem-b", "siem-c"}}}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Cluster = cl
		s.ClusterServers = lf
	})
	for _, c := range []struct {
		body string
		code int
		want string
	}{
		{`{`, http.StatusBadRequest, ""},
		{`{"to":"n_x"}`, http.StatusBadRequest, "name the server"},
		{`{"to":"n_a"}`, http.StatusConflict, "runs the background jobs already"},
		{`{"to":"n_c"}`, http.StatusConflict, "it is not running normally"},
	} {
		code, out := do(t, ts, "POST", "/api/cluster/jobs/move", c.body, true)
		if msg, _ := out["error"].(string); code != c.code || !strings.Contains(msg, c.want) {
			t.Errorf("%s: %d %v", c.body, code, out)
		}
	}
	cl.set(cluster.StateReady, 0)
	lf.fail(errDown, nil)
	if code, out := do(t, ts, "POST", "/api/cluster/jobs/move", `{"to":"n_c"}`, true); code != http.StatusServiceUnavailable {
		t.Errorf("request refused: %d %v", code, out)
	}
	if asked, _ := lf.take(); len(asked) != 0 {
		t.Errorf("asked %v", asked)
	}

	// Outside a cluster there is nothing to move.
	ts, _ = newTestServer(t)
	if code, _ := do(t, ts, "POST", "/api/cluster/jobs/move", `{"to":"n_c"}`, true); code != http.StatusServiceUnavailable {
		t.Errorf("not in a cluster: %d", code)
	}
}

// Removing a server: rotate must be a boolean, the last member stays, a
// removal that fails says so, and a key that cannot be rotated is
// reported, not fatal.
func TestServerRemoveRefusals(t *testing.T) {
	cl := &lifecycleCluster{cState: cluster.StateStopped, cAgo: time.Hour}
	lf := &failLifecycle{fakeLifecycle: &fakeLifecycle{rotation: true, members: []string{"siem-c"}}}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Cluster = cl
		s.ClusterServers = lf
	})
	if code, out := do(t, ts, "DELETE", "/api/cluster/servers/n_c?rotate=maybe", "", true); code != http.StatusBadRequest || out["error"] != "rotate is true or false" {
		t.Errorf("bad rotate: %d %v", code, out)
	}
	if code, _ := do(t, ts, "DELETE", "/api/cluster/servers/n_x", "", true); code != http.StatusNotFound {
		t.Errorf("unknown server: %d", code)
	}
	if code, out := do(t, ts, "DELETE", "/api/cluster/servers/n_c", "", true); code != http.StatusConflict || out["error"] != shared.ErrLastMember.Error() {
		t.Errorf("last member: %d %v", code, out)
	}

	lf.fakeLifecycle.mu.Lock()
	lf.members = []string{"siem-a", "siem-b", "siem-c"}
	lf.fakeLifecycle.mu.Unlock()
	lf.fail(nil, errDown)
	if code, out := do(t, ts, "DELETE", "/api/cluster/servers/n_c", "", true); code != http.StatusServiceUnavailable {
		t.Errorf("removal fails: %d %v", code, out)
	}
	// Removed, but the key could not be rotated now.
	lf.fail(errDown, nil)
	code, out := do(t, ts, "DELETE", "/api/cluster/servers/n_c", "", true)
	if msg, _ := out["rotate_skipped"].(string); code != http.StatusOK || !strings.Contains(msg, "could not be rotated now") || out["request_id"] != nil {
		t.Errorf("rotation refused: %d %v", code, out)
	}
	// Below the version that rotates keys, it is not tried.
	lf.fail(nil, nil)
	lf.fakeLifecycle.mu.Lock()
	lf.rotation = false
	lf.fakeLifecycle.mu.Unlock()
	code, out = do(t, ts, "DELETE", "/api/cluster/servers/n_c", "", true)
	if msg, _ := out["rotate_skipped"].(string); code != http.StatusOK || !strings.Contains(msg, "upgrade them") {
		t.Errorf("rotation off: %d %v", code, out)
	}
	if asked, removed := lf.take(); len(asked) != 0 || len(removed) != 2 {
		t.Errorf("asked %v, removed %v", asked, removed)
	}
}
