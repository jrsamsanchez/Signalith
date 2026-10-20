// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clusterjoin"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// fakeJoin is the cluster's joins as the API sees them.
type fakeJoin struct {
	mu       sync.Mutex
	issued   []JoinTokenRequest
	tokens   []clusterjoin.TokenInfo
	pending  []shared.PendingDoc
	answer   func(*clusterjoin.Request) (string, error)
	answered int
	waiting  string
	issueErr error
	// approveErr is what Approve answers when set.
	approveErr error
}

func (f *fakeJoin) Issue(_ context.Context, by string, req JoinTokenRequest) (*clusterjoin.Issued, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issueErr != nil {
		return nil, f.issueErr
	}
	f.issued = append(f.issued, req)
	id, _ := clusterjoin.NewID()
	secret, _ := clusterjoin.NewSecret()
	tok := clusterjoin.Token{URL: "https://siem-a:8443", CA: clusterjoin.Pin(req.CADER), ID: id, Secret: secret}
	exp := time.Now().Add(time.Hour)
	f.tokens = append(f.tokens, clusterjoin.TokenInfo{ID: id, ExpiresAt: exp, CreatedBy: by, State: "open", Note: req.Note})
	return &clusterjoin.Issued{Token: tok, ExpiresAt: exp}, nil
}

func (f *fakeJoin) Revoke(_ context.Context, _, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, t := range f.tokens {
		if t.ID == id {
			f.tokens = slices.Delete(f.tokens, i, i+1)
			return nil
		}
	}
	return clusterjoin.ErrTokenUnknown
}

func (f *fakeJoin) Tokens() []clusterjoin.TokenInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.tokens)
}

func (f *fakeJoin) Pending(context.Context) ([]shared.PendingDoc, error) { return f.pending, nil }

func (f *fakeJoin) Approve(_ context.Context, nodeID, fp, _ string) (*shared.PendingDoc, error) {
	if f.approveErr != nil {
		return nil, f.approveErr
	}
	for _, p := range f.pending {
		if p.NodeID == nodeID {
			if !clusterjoin.SameFingerprint(p.Fingerprint, fp) {
				return nil, clusterjoin.ErrFingerprint
			}
			return &p, nil
		}
	}
	return nil, clusterjoin.ErrNoPending
}

func (f *fakeJoin) Answer(_ context.Context, req *clusterjoin.Request) (string, error) {
	f.mu.Lock()
	f.answered++
	f.mu.Unlock()
	return f.answer(req)
}

func (f *fakeJoin) Waiting() string { return f.waiting }

func newJoinServer(t *testing.T, j *fakeJoin, withTLS bool) (*httptest.Server, *Server) {
	t.Helper()
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		srv = s
		if j != nil {
			s.Join = j
		}
		s.Cluster = &tlsCluster{}
		if withTLS {
			m, err := tlsauto.New(tlsauto.Options{Dir: t.TempDir(), Names: []string{"siem-a"}})
			if err != nil {
				t.Fatal(err)
			}
			s.TLS = m
		}
		s.UI = fstest.MapFS{"login.html": {Data: []byte(`<form><p class="auth__help" id="join-wait" hidden></p></form>`)}}
	})
	return ts, srv
}

func joinPost(t *testing.T, ts *httptest.Server, path, body string) (int, map[string]any) {
	t.Helper()
	return do(t, ts, "POST", path, body, false)
}

func TestJoinRoutesArePublic(t *testing.T) {
	for _, r := range joinPublicRoutes {
		if !slices.Contains(publicRoutes, r) {
			t.Errorf("%s is not in publicRoutes", r)
		}
	}
	ts, srv := newJoinServer(t, &fakeJoin{}, true)
	resp, err := http.Get(ts.URL + "/api/cluster/join/ca")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(body, srv.TLS.CAPEM()) || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("join ca = %d %q", resp.StatusCode, body)
	}
	// No certificate authority to pin: 404, and no token can be made.
	ts2, _ := newJoinServer(t, &fakeJoin{}, false)
	if code, _ := do(t, ts2, "GET", "/api/cluster/join/ca", "", false); code != http.StatusNotFound {
		t.Errorf("no CA = %d", code)
	}
	if code, out := do(t, ts2, "POST", "/api/cluster/tokens", `{}`, true); code != http.StatusConflict || !strings.Contains(out["error"].(string), "fingerprint") {
		t.Errorf("token without a CA = %d %v", code, out)
	}
	// The admin routes need an admin.
	for _, p := range []string{"/api/cluster/join/tokens", "/api/cluster/pending"} {
		if code, _ := do(t, ts, "GET", p, "", false); code != http.StatusUnauthorized {
			t.Errorf("%s without signing in = %d", p, code)
		}
	}
}

func joinBody(t *testing.T, id string) string {
	t.Helper()
	tok := clusterjoin.Token{URL: "https://siem-a", CA: clusterjoin.Pin([]byte("x")), ID: id, Secret: make([]byte, 32)}
	req, err := clusterjoin.NewRequest(tok, "n_c", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	req.Name, req.Version, req.LevelMax = "siem-c", "1.5.0", 5
	b, _ := json.Marshal(req)
	return string(b)
}

func TestJoinAnswers(t *testing.T) {
	j := &fakeJoin{}
	ts, _ := newJoinServer(t, j, true)
	id, _ := clusterjoin.NewID()

	var from net.IP
	j.answer = func(r *clusterjoin.Request) (string, error) { from = r.RemoteIP; return "j1:sealed", nil }
	code, out := joinPost(t, ts, "/api/cluster/join", joinBody(t, id))
	if code != 200 || out["sealed"] != "j1:sealed" {
		t.Fatalf("join = %d %v", code, out)
	}
	if from == nil || !from.IsLoopback() {
		t.Errorf("the request's address is %v", from)
	}
	// Used, then failed: the new server is told it needs a new token,
	// not to try again.
	j.answer = func(*clusterjoin.Request) (string, error) {
		return "", errors.Join(clusterjoin.ErrSpent, errors.New("keyring conflict"))
	}
	if code, out := joinPost(t, ts, "/api/cluster/join", joinBody(t, id)); code != 500 || out["error"] != clusterjoin.ErrSpent.Error() {
		t.Errorf("spent = %d %v", code, out)
	}
	j.answer = func(*clusterjoin.Request) (string, error) {
		return "", &clusterjoin.JoinError{Msg: "install Signalith 1.5.0 first"}
	}
	if code, out := joinPost(t, ts, "/api/cluster/join", joinBody(t, id)); code != 403 || out["error"] != "install Signalith 1.5.0 first" {
		t.Errorf("join error = %d %v", code, out)
	}
	j.answer = func(*clusterjoin.Request) (string, error) {
		return "", errors.Join(clusterjoin.ErrUnavailable, errors.New("opensearch down"))
	}
	if code, out := joinPost(t, ts, "/api/cluster/join", joinBody(t, id)); code != 503 || strings.Contains(out["error"].(string), "opensearch down") {
		t.Errorf("unavailable = %d %v", code, out)
	}
	// Every refusal reads the same, whatever the reason.
	for _, reason := range []error{clusterjoin.ErrTokenUsed, clusterjoin.ErrProof, clusterjoin.ErrTokenExpired} {
		j.answer = func(*clusterjoin.Request) (string, error) { return "", &clusterjoin.RefusedError{Reason: reason} }
		if code, out := joinPost(t, ts, "/api/cluster/join", joinBody(t, id)); code != 403 || out["error"] != clusterjoin.Refused {
			t.Errorf("%v = %d %v", reason, code, out)
		}
	}
	// A body that is not a request, or too large, is refused the same
	// way, and never reaches OpenSearch.
	before := j.answered
	if code, out := joinPost(t, ts, "/api/cluster/join", "{"); code != 403 || out["error"] != clusterjoin.Refused {
		t.Errorf("not JSON = %d %v", code, out)
	}
	big := `{"token_id":"` + strings.Repeat("a", clusterjoin.MaxRequest) + `"}`
	if code, out := joinPost(t, ts, "/api/cluster/join", big); code != 403 || out["error"] != clusterjoin.Refused {
		t.Errorf("too large = %d %v", code, out)
	}
	if j.answered != before {
		t.Error("a request that is not one was answered")
	}
}

func TestJoinLimited(t *testing.T) {
	j := &fakeJoin{answer: func(*clusterjoin.Request) (string, error) {
		return "", &clusterjoin.RefusedError{Reason: clusterjoin.ErrProof}
	}}
	ts, _ := newJoinServer(t, j, true)
	id, _ := clusterjoin.NewID()
	var code int
	n := 0
	for n = 0; n < 40; n++ {
		if code, _ = joinPost(t, ts, "/api/cluster/join", joinBody(t, id)); code == http.StatusTooManyRequests {
			break
		}
	}
	if code != http.StatusTooManyRequests || n > 10 {
		t.Fatalf("not limited after %d refusals (%d)", n, code)
	}
	answered := j.answered
	if code, _ := joinPost(t, ts, "/api/cluster/join", joinBody(t, id)); code != http.StatusTooManyRequests || j.answered != answered {
		t.Errorf("a limited join reached OpenSearch (%d)", code)
	}
}

func TestJoinTokensAPI(t *testing.T) {
	j := &fakeJoin{pending: []shared.PendingDoc{{NodeID: "n_b", Name: "siem-b", Fingerprint: "4F2A-91C0", RequestedAt: time.Now()}}}
	ts, srv := newJoinServer(t, j, true)
	code, out := do(t, ts, "POST", "/api/cluster/tokens", `{"platform":"linux","ttl_minutes":30,"note":"rack 4"}`, true)
	if code != http.StatusCreated {
		t.Fatalf("make token = %d %v", code, out)
	}
	tok, _ := out["token"].(string)
	parsed, err := clusterjoin.Parse(tok)
	if err != nil || parsed.ID != out["id"] {
		t.Fatalf("token %q: %v", tok, err)
	}
	cmds := out["commands"].(map[string]any)
	for _, k := range []string{"linux", "windows", "docker"} {
		if !strings.Contains(cmds[k].(string), tok) {
			t.Errorf("%s command %q has no token", k, cmds[k])
		}
	}
	if len(j.issued) != 1 || j.issued[0].TTLMinutes != 30 || !parsed.MatchesPin(j.issued[0].CADER) || clusterjoin.Pin(j.issued[0].CADER) != clusterjoin.Pin(derOf(t, srv.TLS.CAPEM())) {
		t.Errorf("issued %+v", j.issued)
	}
	// The token is never in a listing.
	for _, p := range []string{"/api/cluster/join/tokens", "/api/cluster"} {
		raw := rawGet(t, ts, p)
		if strings.Contains(raw, tok) || strings.Contains(raw, tok[len(clusterjoin.TokenPrefix):]) {
			t.Errorf("%s shows the token", p)
		}
		if !strings.Contains(raw, parsed.ID) {
			t.Errorf("%s does not list the token: %s", p, raw)
		}
	}
	_, cl := do(t, ts, "GET", "/api/cluster", "", true)
	if p, _ := cl["pending"].([]any); len(p) != 1 {
		t.Errorf("cluster pending %v", cl["pending"])
	}

	// Revoke.
	if code, _ := do(t, ts, "DELETE", "/api/cluster/tokens/"+parsed.ID, "", true); code != http.StatusNoContent {
		t.Errorf("revoke = %d", code)
	}
	if code, _ := do(t, ts, "DELETE", "/api/cluster/tokens/"+parsed.ID, "", true); code != http.StatusNotFound {
		t.Errorf("revoke again = %d", code)
	}
	// Refusals of Issue.
	j.issueErr = clusterjoin.ErrNotSecured
	if code, _ := do(t, ts, "POST", "/api/cluster/tokens", `{}`, true); code != http.StatusConflict {
		t.Errorf("not secured = %d", code)
	}
	j.issueErr = &shared.PausedError{Why: "degraded"}
	if code, _ := do(t, ts, "POST", "/api/cluster/tokens", `{}`, true); code != http.StatusServiceUnavailable {
		t.Errorf("paused = %d", code)
	}
}

func TestJoinApproveAPI(t *testing.T) {
	j := &fakeJoin{pending: []shared.PendingDoc{{NodeID: "n_b", Name: "siem-b", Fingerprint: "4F2A-91C0", At: time.Now()}}}
	ts, _ := newJoinServer(t, j, true)
	code, out := do(t, ts, "GET", "/api/cluster/pending", "", true)
	if p, _ := out["pending"].([]any); code != 200 || len(p) != 1 || p[0].(map[string]any)["fingerprint"] != "4F2A-91C0" {
		t.Fatalf("pending = %d %v", code, out)
	}
	if code, _ := do(t, ts, "POST", "/api/cluster/servers/n_b/approve", `{"fingerprint":"0000-0000"}`, true); code != http.StatusConflict {
		t.Errorf("wrong fingerprint = %d", code)
	}
	if code, _ := do(t, ts, "POST", "/api/cluster/servers/n_b/approve", `{}`, true); code != http.StatusBadRequest {
		t.Errorf("no fingerprint = %d", code)
	}
	if code, _ := do(t, ts, "POST", "/api/cluster/servers/n_x/approve", `{"fingerprint":"4F2A-91C0"}`, true); code != http.StatusNotFound {
		t.Errorf("not waiting = %d", code)
	}
	if code, out := do(t, ts, "POST", "/api/cluster/servers/n_b/approve", `{"fingerprint":"4f2a91c0"}`, true); code != 200 || out["name"] != "siem-b" {
		t.Errorf("approve = %d %v", code, out)
	}
	// A server that would take a member's place.
	j.approveErr = &clusterjoin.ClashError{NodeID: "n_b", Name: "siem-b"}
	if code, _ := do(t, ts, "POST", "/api/cluster/servers/n_b/approve", `{"fingerprint":"4f2a91c0"}`, true); code != http.StatusConflict {
		t.Errorf("clash = %d", code)
	}
}

func TestJoinWithoutJoin(t *testing.T) {
	ts, _ := newJoinServer(t, nil, true)
	if code, _ := joinPost(t, ts, "/api/cluster/join", joinBody(t, "jt_aaaaaaaaaaaaaaaaaaaa")); code != http.StatusServiceUnavailable {
		t.Errorf("join without shared settings = %d", code)
	}
	_, out := do(t, ts, "GET", "/api/cluster/join/tokens", "", true)
	if l, ok := out["tokens"].([]any); !ok || len(l) != 0 {
		t.Errorf("tokens = %v", out)
	}
}

func TestLoginPageWaiting(t *testing.T) {
	j := &fakeJoin{}
	ts, _ := newJoinServer(t, j, true)
	if p := rawGet(t, ts, "/login"); !strings.Contains(p, `id="join-wait" hidden`) {
		t.Errorf("not waiting: %s", p)
	}
	j.waiting = "This server waits to join cluster '<b>'. Fingerprint 4F2A"
	p := rawGet(t, ts, "/login")
	if !strings.Contains(p, `id="join-wait">This server waits to join cluster &#39;&lt;b&gt;&#39;. Fingerprint 4F2A</p>`) {
		t.Errorf("waiting: %s", p)
	}
}

func rawGet(t *testing.T, ts *httptest.Server, path string) string {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func derOf(t *testing.T, p []byte) []byte {
	t.Helper()
	b, _ := pem.Decode(p)
	if b == nil {
		t.Fatal("no PEM")
	}
	return b.Bytes
}
