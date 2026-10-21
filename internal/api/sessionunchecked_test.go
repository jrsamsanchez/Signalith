// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/clusterauth"
)

// checkingSessions is a SessionStore that cannot check one cookie now
// and refuses every other.
type checkingSessions struct {
	SessionStore
	unchecked string
}

func (c checkingSessions) Check(_ context.Context, token string, _ bool) (auth.Session, error) {
	if token == c.unchecked {
		return auth.Session{}, clusterauth.ErrSessionUnchecked
	}
	return auth.Session{}, errors.New("no session")
}

// A session the store cannot check now is answered 503 with Retry-After,
// never 401, so the page does not sign out; one it refuses is 401 as
// before, and Basic credentials still work next to the cookie.
func TestSessionUncheckedIs503(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.SessionStore = checkingSessions{SessionStore: MemorySessions(auth.NewSessions(0)), unchecked: "slow-cookie"}
	})
	get := func(cookie, accept string, basic bool) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/me", nil)
		if accept != "" {
			req, _ = http.NewRequest(http.MethodGet, ts.URL+"/", nil)
			req.Header.Set("Accept", accept)
		}
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		if basic {
			req.SetBasicAuth("admin", "s3cret-pass")
		}
		c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return resp, string(raw)
	}

	resp, body := get("slow-cookie", "", false)
	var out struct{ Code, Error string }
	_ = json.Unmarshal([]byte(body), &out)
	if resp.StatusCode != http.StatusServiceUnavailable || out.Code != "session_unchecked" || resp.Header.Get("Retry-After") == "" {
		t.Errorf("unchecked session on the API: %d %s (Retry-After %q)", resp.StatusCode, body, resp.Header.Get("Retry-After"))
	}
	resp, body = get("slow-cookie", "text/html", false)
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, `href="/login"`) || !strings.Contains(body, "http-equiv=\"refresh\"") {
		t.Errorf("unchecked session on a page: %d %s", resp.StatusCode, body)
	}
	if resp, body = get("slow-cookie", "", true); resp.StatusCode != http.StatusOK {
		t.Errorf("unchecked session with Basic credentials: %d %s", resp.StatusCode, body)
	}
	if resp, body = get("other-cookie", "", false); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("refused session: %d %s", resp.StatusCode, body)
	}
	if resp, _ = get("other-cookie", "text/html", false); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("refused session on a page: %d, want a redirect to sign in", resp.StatusCode)
	}
}
