// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/content"
	"github.com/jrsamsanchez/signalith/internal/detect"
)

// Without content updates every route says so.
func TestContentOff(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, rt := range []struct{ method, path string }{
		{"GET", "/api/detections/content"}, {"POST", "/api/detections/content/check"},
		{"POST", "/api/detections/content/upload"}, {"DELETE", "/api/detections/content"},
	} {
		if code, out := do(t, ts, rt.method, rt.path, "", true); code != http.StatusServiceUnavailable || out["error"] != errContentOff.Error() {
			t.Errorf("%s %s: %d %v", rt.method, rt.path, code, out)
		}
	}
}

// Check for updates downloads the bundle and its signature from the
// update address; one not published is a 502, one already in use is
// fine. An upload that is not a form, or lacks the bundle, is a 400.
func TestContentCheckAndUploadRefusals(t *testing.T) {
	t.Cleanup(func() { detect.UsePacks(nil, nil, "") })
	priv, pub, err := content.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := content.ParsePrivateKey(priv)
	keys, _ := content.ParseKeys(pub)
	data, _, err := content.Build("../detect/packs", time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	sig := content.Sign(key, data)
	var published atomic.Bool
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case !published.Load():
			http.NotFound(w, r)
		case strings.HasSuffix(r.URL.Path, ".sig"):
			w.Write(sig)
		default:
			w.Write(data)
		}
	}))
	defer site.Close()
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Content = &content.Updater{Dir: filepath.Join(t.TempDir(), "content"), Keys: keys, Library: s.Detections}
		s.Config.Detections.ContentURL = site.URL + "/signalith-content.tar.gz"
	})

	if code, out := do(t, ts, "POST", "/api/detections/content/check", "", true); code != http.StatusBadGateway || !strings.Contains(out["error"].(string), "404") {
		t.Errorf("not published: %d %v", code, out)
	}
	published.Store(true)
	code, out := do(t, ts, "POST", "/api/detections/content/check", "", true)
	if st, _ := out["status"].(map[string]any); code != http.StatusOK || st["version"] != "20990101000000" {
		t.Fatalf("check: %d %v", code, out)
	}
	if code, out := do(t, ts, "POST", "/api/detections/content/check", "", true); code != http.StatusOK {
		t.Errorf("check again: %d %v", code, out)
	}

	if code, _ := do(t, ts, "POST", "/api/detections/content/upload", `{"bundle":"x"}`, true); code != http.StatusBadRequest {
		t.Errorf("not a form: %d", code)
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	w, _ := mw.CreateFormFile("signature", "signalith-content.tar.gz.sig")
	w.Write(sig)
	mw.Close()
	req, _ := http.NewRequest("POST", ts.URL+"/api/detections/content/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no bundle: %d", resp.StatusCode)
	}
}
