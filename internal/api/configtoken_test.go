// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

type tokenBody struct {
	Name         string `json:"name"`
	shared.Extra `json:"-"`
}

// U27: every answer carries X-Signalith-Build, and every signed-in one
// X-Signalith-Version and X-Signalith-Config; a change reports its own
// write; a server one write behind a page's X-Signalith-Config-Min reads
// once and answers; one behind a token no server has answers
// X-Signalith-Stale; the web UI's files are served under /v/<build>/.
// WEB-01: nothing a visitor who is not signed in gets names the version.
func TestConfigHeadersAndVersionedFiles(t *testing.T) {
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	ctx := context.Background()
	const prefix = "signalith"
	if err := shared.EnsureConfig(ctx, cl, prefix); err != nil {
		t.Fatal(err)
	}
	key, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	hub := func(name string) *shared.Hub {
		h := shared.NewHub(shared.Options{NodeName: name})
		h.SetKeys(shared.NewKeySet(key))
		h.Use(cl, prefix)
		return h
	}
	ha, hb := hub("siem-a"), hub("siem-b")
	da := shared.NewDoc[tokenBody](ha, "settings", "settings", 1)
	shared.NewDoc[tokenBody](hb, "settings", "settings", 1)
	for _, h := range []*shared.Hub{ha, hb} {
		if err := h.Cycle(ctx); err != nil {
			t.Fatal(err)
		}
	}

	index := `<!doctype html><html><head><meta name="signalith-version" content="">` +
		`<script src="assets/loader.js" data-unversioned></script><link rel="stylesheet" href="assets/css/app.css">` +
		`</head><body><a href="api/security?format=text">x</a><script src="app.js"></script></body></html>`
	ui := fstest.MapFS{
		"index.html":          {Data: []byte(index)},
		"login.html":          {Data: []byte(`<head><meta name="signalith-version" content=""><link rel="stylesheet" href="assets/css/app.css"></head>`)},
		"app.js":              {Data: []byte("// app")},
		"assets/loader.js":    {Data: []byte("// loader")},
		"assets/css/app.css":  {Data: []byte("body{}")},
		"assets/favicon.svg":  {Data: []byte("<svg/>")},
		"assets/fonts/x.woff": {Data: []byte("font")},
	}
	ts, _ := newUsersServer(t, func(s *Server) {
		s.Version, s.ConfigToken, s.UI = "1.5.0", hb, ui
	})
	_, _, cookie := login(t, ts, "admin", adminPass)
	get := func(path, min string, signedIn bool) *http.Response {
		t.Helper()
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		if signedIn {
			req.AddCookie(cookie)
		}
		if min != "" {
			req.Header.Set(headerConfigMin, min)
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	build := makeBuildToken("1.5.0", ui)
	if build == "" || strings.Contains(build, "1.5") || versionSegment(build) != build {
		t.Fatalf("build token %q", build)
	}
	resp := get("/api/health", "", true)
	if v := resp.Header.Get(headerVersion); v != "1.5.0" {
		t.Errorf("version %q", v)
	}
	if b := resp.Header.Get(headerBuild); b != build {
		t.Errorf("build %q, want %q", b, build)
	}
	if c := resp.Header.Get(headerConfig); c == "" || c != hb.Token() {
		t.Errorf("config %q, want %q", c, hb.Token())
	}
	// Someone not signed in gets the build token, but neither the version
	// nor anything about the config index.
	if resp := get("/api/health", "", false); resp.Header.Get(headerBuild) != build || resp.Header.Get(headerVersion) != "" || resp.Header.Get(headerConfig) != "" {
		t.Errorf("signed out: %v", resp.Header)
	}
	if resp := get("/login", "", false); resp.Header.Get(headerConfig) != "" || resp.Header.Get(headerVersion) != "" {
		t.Errorf("sign-in page: %v", resp.Header)
	}
	// A failed sign-in tells nothing either; a successful one does.
	for _, c := range []struct {
		pass string
		ok   bool
	}{{"wrong-password", false}, {adminPass, true}} {
		body := strings.NewReader(`{"username":"admin","password":"` + c.pass + `"}`)
		req, _ := http.NewRequest("POST", ts.URL+"/api/login", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", ts.URL)
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := resp.Header.Get(headerConfig) != ""; got != c.ok || (resp.StatusCode < 300) != c.ok {
			t.Errorf("sign-in (%v): %d, config %q", c.ok, resp.StatusCode, resp.Header.Get(headerConfig))
		}
		if got := resp.Header.Get(headerVersion) == "1.5.0"; got != c.ok {
			t.Errorf("sign-in (%v): version %q", c.ok, resp.Header.Get(headerVersion))
		}
	}

	// A change on A reports the token of its own write.
	a := &Server{Version: "1.5.0", ConfigToken: ha}
	var seq int64
	write := a.configToken(false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		if seq, err = da.Mutate(r.Context(), "sam", func(b *tokenBody) error { b.Name = "x"; return nil }); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	write.ServeHTTP(rec, httptest.NewRequest("PUT", "/api/retention/default", nil))
	tok := rec.Header().Get(headerConfig)
	if want := ha.TokenAfter(seq); tok != want || !strings.HasSuffix(tok, "."+strconv.FormatInt(seq, 10)) {
		t.Fatalf("token of the change %q, want %q", tok, want)
	}
	// A read on A that wrote nothing reports how far A has read.
	rec = httptest.NewRecorder()
	a.configToken(false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, httptest.NewRequest("GET", "/api/x", nil))
	if got := rec.Header().Get(headerConfig); got != ha.Token() {
		t.Errorf("read token %q, want %q", got, ha.Token())
	}

	// B is one write behind: it reads once, then answers, not stale.
	start := time.Now()
	resp = get("/api/health", tok, true)
	if resp.Header.Get(headerStale) != "" {
		t.Error("stale after one cycle")
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("waited %v", time.Since(start))
	}
	if got := resp.Header.Get(headerConfig); got != tok {
		t.Errorf("B answered with %q, want %q", got, tok)
	}
	// Ahead of anything: stale, after at most a second or so.
	uuid, _, _ := shared.ParseToken(tok)
	start = time.Now()
	if resp := get("/api/health", uuid+".99999", true); resp.Header.Get(headerStale) != "1" {
		t.Error("not stale")
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("waited %v", time.Since(start))
	}
	// Another index's token, or a request not signed in, never waits.
	if resp := get("/api/health", "other.99999", true); resp.Header.Get(headerStale) != "" {
		t.Error("stale for another index")
	}
	if resp := get("/api/health", uuid+".99999", false); resp.Header.Get(headerStale) != "" {
		t.Error("stale while signed out")
	}

	// Versioned files.
	body := func(r *http.Response) string {
		b, _ := io.ReadAll(r.Body)
		return string(b)
	}
	page := body(get("/", "", true))
	for _, want := range []string{`content="` + build + `"`, `src="assets/loader.js" data-unversioned`, `href="v/` + build + `/assets/css/app.css"`,
		`src="v/` + build + `/app.js"`, `href="api/security?format=text"`} {
		if !strings.Contains(page, want) {
			t.Errorf("index.html lacks %s: %s", want, page)
		}
	}
	if p := body(get("/login", "", false)); !strings.Contains(p, `href="v/`+build+`/assets/css/app.css"`) || !strings.Contains(p, `content="`+build+`"`) || strings.Contains(p, "1.5.0") {
		t.Errorf("login.html %s", p)
	}
	for _, c := range []struct {
		path     string
		signedIn bool
		code     int
		cache    string
	}{
		{"/v/" + build + "/app.js", true, 200, "private, max-age=31536000, immutable"},
		{"/v/" + build + "/assets/css/app.css", false, 200, "public, max-age=31536000, immutable"},
		{"/v/" + build + "/assets/fonts/x.woff", false, 200, "public, max-age=31536000, immutable"},
		{"/app.js", true, 200, "no-cache"},
		{"/assets/css/app.css", false, 200, ""},
		{"/v/" + build + "/app.js", false, 401, ""},
		{"/v/1.4.0/app.js", true, 404, ""},
		{"/v/1.4.0/assets/css/app.css", true, 404, ""},
		// A guessed version answers as any other path does.
		{"/v/1.5.0/assets/css/app.css", false, 401, ""},
		{"/v/" + build + "/index.html", true, 404, ""},
		{"/v/" + build + "/assets/..%2f..%2fapp.js", false, 404, ""},
	} {
		resp := get(c.path, "", c.signedIn)
		if resp.StatusCode != c.code {
			t.Errorf("%s = %d, want %d", c.path, resp.StatusCode, c.code)
		}
		if c.cache != "" && resp.Header.Get("Cache-Control") != c.cache {
			t.Errorf("%s Cache-Control %q, want %q", c.path, resp.Header.Get("Cache-Control"), c.cache)
		}
	}
}

// The build token changes with the version and with any file of the web
// UI (so browsers that keep /v/<build>/ for a year get new files), and is
// the same for the same build on every server.
func TestBuildToken(t *testing.T) {
	ui := fstest.MapFS{"app.js": {Data: []byte("// a")}, "assets/x.css": {Data: []byte("x{}")}}
	a := makeBuildToken("1.5.0", ui)
	if a == "" || a != makeBuildToken("1.5.0", fstest.MapFS{"app.js": {Data: []byte("// a")}, "assets/x.css": {Data: []byte("x{}")}}) {
		t.Fatalf("token %q is not stable", a)
	}
	if b := makeBuildToken("1.5.1", ui); b == a {
		t.Error("same token for another version")
	}
	if b := makeBuildToken("1.5.0", fstest.MapFS{"app.js": {Data: []byte("// b")}, "assets/x.css": {Data: []byte("x{}")}}); b == a {
		t.Error("same token for another app.js")
	}
	for _, v := range []string{"", "..", "1.5.0/x"} {
		if b := makeBuildToken(v, ui); b != "" {
			t.Errorf("version %q: token %q, want none", v, b)
		}
	}
}
