// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
)

// TestStaticFilesStayInTheirFolder: the public /assets/ route serves only
// the assets folder, lists no folder, and refuses encoded slashes and dot
// segments, so the app's own scripts stay behind sign-in.
func TestStaticFilesStayInTheirFolder(t *testing.T) {
	ts, _ := newUsersServer(t, func(s *Server) {
		s.UI = fstest.MapFS{
			"index.html":       {Data: []byte("<h1>app</h1>")},
			"login.html":       {Data: []byte("<h1>sign in</h1>")},
			"app.js":           {Data: []byte("// app")},
			"assets/login.js":  {Data: []byte("// login")},
			"assets/css/a.css": {Data: []byte("body{}")},
		}
	})
	get := func(path string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", ts.URL+"/", nil)
		req.URL.Opaque = path // sent exactly as written
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		return resp.StatusCode, b.String()
	}
	for _, path := range []string{"/assets/login.js", "/assets/css/a.css"} {
		if code, _ := get(path); code != 200 {
			t.Errorf("%s = %d, want 200", path, code)
		}
	}
	for _, path := range []string{
		"/assets/..%2fapp.js", "/assets/..%2Fapp.js", "/assets/%2e%2e/app.js", "/assets/%2e%2e%2fapp.js",
		"/assets/..%5capp.js", "/assets/", "/assets/css/", "/assets/..%2f", "/assets/%2e%2e/",
	} {
		code, body := get(path)
		if code != 404 || strings.Contains(body, "// app") || strings.Contains(body, "<h1>app") {
			t.Errorf("%s without a session = %d %q, want 404", path, code, body)
		}
	}
	if code, _ := get("/app.js"); code != 401 {
		t.Errorf("/app.js without a session = %d, want 401", code)
	}
	// Signed in, folders are still not listed.
	_, _, c := login(t, ts, "admin", adminPass)
	req, _ := http.NewRequest("GET", ts.URL+"/assets/css/", nil)
	req.AddCookie(c)
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("signed-in folder listing = %d, want 404", resp.StatusCode)
	}
}
