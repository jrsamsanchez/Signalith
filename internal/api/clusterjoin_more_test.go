// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// A join token needs joins on, a body that reads, a time to live that is
// not negative and a CA the new server can check this one by; what Issue
// refuses otherwise is a 400.
func TestJoinTokenNewRefusals(t *testing.T) {
	ts, _ := newJoinServer(t, nil, true)
	if code, _ := do(t, ts, "POST", "/api/cluster/tokens", `{}`, true); code != http.StatusServiceUnavailable {
		t.Errorf("without joins: %d", code)
	}
	if code, _ := do(t, ts, "DELETE", "/api/cluster/tokens/jt_x", "", true); code != http.StatusServiceUnavailable {
		t.Errorf("revoke without joins: %d", code)
	}

	j := &fakeJoin{}
	ts, _ = newJoinServer(t, j, true)
	if code, _ := do(t, ts, "POST", "/api/cluster/tokens", `{`, true); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	if code, out := do(t, ts, "POST", "/api/cluster/tokens", `{"ttl_minutes":-5}`, true); code != http.StatusBadRequest || !strings.Contains(out["error"].(string), "ttl_minutes") {
		t.Errorf("negative ttl: %d %v", code, out)
	}
	j.mu.Lock()
	j.issueErr = errors.New("the platform must be linux, windows or docker")
	j.mu.Unlock()
	if code, out := do(t, ts, "POST", "/api/cluster/tokens", `{"platform":"amiga"}`, true); code != http.StatusBadRequest || !strings.Contains(out["error"].(string), "platform") {
		t.Errorf("refused by Issue: %d %v", code, out)
	}

	ts, _ = newJoinServer(t, &fakeJoin{}, false)
	if code, out := do(t, ts, "POST", "/api/cluster/tokens", `{}`, true); code != http.StatusConflict || !strings.Contains(out["error"].(string), "cannot make a join token") {
		t.Errorf("no CA: %d %v", code, out)
	}
}
