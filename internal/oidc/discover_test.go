// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// docServer answers the discovery document with what doc makes of the
// server's own address, and the key set with keys.
func docServer(t *testing.T, doc func(base string) map[string]any, keys func(w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(doc(srv.URL))
		case "/keys":
			keys(w)
		case "/big":
			w.Write([]byte(strings.Repeat(" ", maxBody+1)))
		case "/notjson":
			w.Write([]byte("<html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func baseDoc(base string) map[string]any {
	return map[string]any{"issuer": base, "authorization_endpoint": base + "/auth", "token_endpoint": base + "/token", "jwks_uri": base + "/keys"}
}

func TestDiscoverChecks(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		mod  func(base string, d map[string]any)
		want string
	}{
		"other endpoint scheme": {func(b string, d map[string]any) { d["token_endpoint"] = "ftp://id.example/token" }, "token_endpoint"},
		"no code flow":          {func(b string, d map[string]any) { d["response_types_supported"] = []string{"id_token"} }, "authorization code"},
		"no S256":               {func(b string, d map[string]any) { d["code_challenge_methods_supported"] = []string{"plain"} }, "PKCE"},
	} {
		srv := docServer(t, func(base string) map[string]any { d := baseDoc(base); c.mod(base, d); return d }, nil)
		if _, err := (&Client{HTTP: srv.Client()}).Discover(ctx, srv.URL); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// A userinfo endpoint that is not https is dropped, not refused.
	srv := docServer(t, func(base string) map[string]any {
		d := baseDoc(base)
		d["userinfo_endpoint"] = "http://elsewhere.example/userinfo"
		return d
	}, nil)
	md, err := (&Client{HTTP: srv.Client()}).Discover(ctx, srv.URL)
	if err != nil || md.UserinfoEndpoint != "" {
		t.Errorf("userinfo = %+v %v", md, err)
	}
	if _, err := (&Client{}).Discover(ctx, "ftp://id.example"); err == nil {
		t.Error("an ftp issuer was taken")
	}
	if _, err := (&Client{HTTP: srv.Client()}).Discover(ctx, srv.URL+"/missing"); err == nil || !strings.Contains(err.Error(), "discovery document") {
		t.Errorf("missing document = %v", err)
	}
}

func TestGetJSONProblems(t *testing.T) {
	ctx := context.Background()
	srv := docServer(t, baseDoc, nil)
	c := &Client{HTTP: srv.Client()}
	var v map[string]any
	for path, want := range map[string]string{"/big": "larger than 1 MB", "/notjson": "did not answer with JSON", "/nothing": "404"} {
		if err := c.getJSON(ctx, srv.URL+path, "", &v); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", path, err, want)
		}
	}
	if err := c.getJSON(ctx, "http://bad host/", "", &v); err == nil {
		t.Error("a bad address was fetched")
	}
	url := srv.URL
	srv.Close()
	if err := c.getJSON(ctx, url+"/keys", "", &v); err == nil {
		t.Error("a closed server answered")
	}
}

func TestKeySetFetching(t *testing.T) {
	ctx := context.Background()
	answer := `{"keys":[{"kty":"oct","k":"AAAA"}]}`
	srv := docServer(t, baseDoc, func(w http.ResponseWriter) { w.Write([]byte(answer)) })
	now := time.Now()
	c := &Client{HTTP: srv.Client(), Now: func() time.Time { return now }}
	md := &Metadata{JWKSURI: srv.URL + "/keys"}
	if _, err := c.Keys(ctx, md); err == nil || !strings.Contains(err.Error(), "no RSA or EC signing key") {
		t.Errorf("no usable key = %v", err)
	}
	answer = `{"keys":[{"kty":"EC","crv":"P-256","x":"` + strings.Repeat("A", 43) + `","y":"` + strings.Repeat("A", 43) + `"}]}`
	if _, err := c.Keys(ctx, md); err == nil {
		t.Error("a point not on the curve was taken")
	}
	if _, err := c.Keys(ctx, &Metadata{JWKSURI: srv.URL + "/nothing"}); err == nil || !strings.Contains(err.Error(), "signing keys") {
		t.Errorf("missing keys = %v", err)
	}
}

func TestClaimChecks(t *testing.T) {
	now := time.Now()
	base := func(mod func(c Claims)) Claims {
		c := Claims{"iss": "https://id.example", "sub": "alice", "aud": "app", "nonce": "n1",
			"exp": float64(now.Add(time.Hour).Unix()), "iat": float64(now.Unix())}
		mod(c)
		return c
	}
	for name, c := range map[string]struct {
		claims Claims
		want   string
	}{
		"no subject":  {base(func(c Claims) { delete(c, "sub") }), "no subject"},
		"no expiry":   {base(func(c Claims) { delete(c, "exp") }), "no expiry"},
		"no iat":      {base(func(c Claims) { delete(c, "iat") }), "no issue time"},
		"not yet":     {base(func(c Claims) { c["nbf"] = float64(now.Add(time.Hour).Unix()) }), "not valid yet"},
		"bad number":  {base(func(c Claims) { c["exp"] = json.Number("soon") }), "no expiry"},
		"json number": {base(func(c Claims) { c["exp"] = json.Number("1") }), "expired"},
	} {
		if err := checkClaims(c.claims, "https://id.example", "app", "n1", now); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	if err := checkClaims(base(func(Claims) {}), "https://id.example", "app", "n1", now); err != nil {
		t.Errorf("good claims = %v", err)
	}
	if got, err := (&Client{}).UserInfo(context.Background(), &Metadata{}, "tok", "alice"); got != nil || err != nil {
		t.Errorf("no userinfo endpoint = %v %v", got, err)
	}
}
