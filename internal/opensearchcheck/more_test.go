// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package opensearchcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func TestCheckOddAnswers(t *testing.T) {
	ctx := context.Background()
	// https:// to a server that speaks plain HTTP.
	plain := ostest.New(t)
	fs := Check(ctx, store.Config{URL: strings.Replace(plain.URL, "http://", "https://", 1)})
	if !strings.Contains(failed(fs), "HTTPS does not match") {
		t.Errorf("https to http: %+v", fs)
	}

	// An OpenSearch whose security route fails and that does not say its
	// time.
	_, h := ostest.NewHandler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/_plugins/_security/authinfo"):
			http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
		case strings.HasPrefix(r.URL.Path, "/_nodes/"):
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"nodes":{"n1":{"os":{}}}}`))
		default:
			h.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	got := failed(Check(ctx, store.Config{URL: srv.URL}))
	for _, want := range []string{"security turned on could not be read", "clock could not be read"} {
		if !strings.Contains(got, want) {
			t.Errorf("odd OpenSearch lacks %q: %s", want, got)
		}
	}

	// One that asks for a sign-in has security.
	if on, err := securityOn(ctx, store.Config{URL: unauthorized(t)}); err != nil || !on {
		t.Errorf("401 = %v %v", on, err)
	}
}

func unauthorized(t *testing.T) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}
