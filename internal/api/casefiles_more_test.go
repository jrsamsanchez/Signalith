// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/casefiles"
	"github.com/jrsamsanchez/signalith/internal/cases"
)

// flakyFiles is a case file store whose calls fail while the matching
// switch is set.
type flakyFiles struct {
	casefiles.Store
	put, get, del atomic.Bool
	lose          atomic.Bool // Get answers not found
}

var errFilesDown = errors.New("file store down")

func (f *flakyFiles) Put(ctx context.Context, file *casefiles.File, data []byte) error {
	if f.put.Load() {
		return errFilesDown
	}
	return f.Store.Put(ctx, file, data)
}

func (f *flakyFiles) Get(ctx context.Context, caseID, id string) (*casefiles.File, []byte, error) {
	switch {
	case f.lose.Load():
		return nil, nil, casefiles.ErrNotFound
	case f.get.Load():
		return nil, nil, errFilesDown
	}
	return f.Store.Get(ctx, caseID, id)
}

func (f *flakyFiles) Delete(ctx context.Context, caseID, id string) error {
	if f.del.Load() {
		return errFilesDown
	}
	return f.Store.Delete(ctx, caseID, id)
}

// postForm sends a hand-made multipart body to a case's files.
func postForm(t *testing.T, ts *httptest.Server, caseID, contentType string, body io.Reader) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+"/api/cases/"+caseID+"/files", body)
	req.Header.Set("Content-Type", contentType)
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = decodeJSON(raw, &out)
	return resp.StatusCode, out
}

// An upload form is read strictly: one file, a short note, nothing
// empty, and a form at all; nothing is stored or added to the case when
// it is not.
func TestCaseFileFormChecks(t *testing.T) {
	files := &flakyFiles{Store: casefiles.NewMemory()}
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) { srv, s.CaseFiles = s, files })
	_, out := do(t, ts, "POST", "/api/cases", `{"title":"Phish"}`, true)
	id := out["case"].(map[string]any)["id"].(string)

	form := func(build func(mw *multipart.Writer)) (string, io.Reader) {
		var b bytes.Buffer
		mw := multipart.NewWriter(&b)
		build(mw)
		mw.Close()
		return mw.FormDataContentType(), &b
	}
	file := func(mw *multipart.Writer, name, data string) {
		fw, _ := mw.CreateFormFile("file", name)
		fw.Write([]byte(data))
	}
	for _, c := range []struct {
		name  string
		build func(mw *multipart.Writer)
		want  string
	}{
		{"two files", func(mw *multipart.Writer) { file(mw, "a.txt", "a"); file(mw, "b.txt", "b") }, "one file at a time"},
		{"long note", func(mw *multipart.Writer) {
			mw.WriteField("text", strings.Repeat("n", cases.MaxTextLen+1))
			file(mw, "a.txt", "a")
		}, "text is too long"},
		{"no file", func(mw *multipart.Writer) { mw.WriteField("text", "just a note") }, "no file was sent"},
		{"empty file", func(mw *multipart.Writer) { file(mw, "a.txt", "") }, "empty"},
	} {
		ct, body := form(c.build)
		code, out := postForm(t, ts, id, ct, body)
		if msg, _ := out["error"].(string); code != http.StatusBadRequest || !strings.Contains(msg, c.want) {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
	}
	if code, out := postForm(t, ts, id, "application/json", strings.NewReader(`{"file":"x"}`)); code != http.StatusBadRequest ||
		!strings.Contains(out["error"].(string), "multipart/form-data") {
		t.Errorf("not a form: %d %v", code, out)
	}
	// A form cut off part way.
	if code, _ := postForm(t, ts, id, "multipart/form-data; boundary=xyz", strings.NewReader("--xyz\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\"\r\n\r\nabc")); code != http.StatusBadRequest {
		t.Errorf("cut-off form: %d", code)
	}
	// A file for a case that does not exist is never stored.
	ct, body := form(func(mw *multipart.Writer) { file(mw, "a.txt", "a") })
	if code, _ := postForm(t, ts, "CASE-20260101-0123456789abcdef", ct, body); code != http.StatusNotFound {
		t.Errorf("missing case: %d", code)
	}
	if c, _ := srv.Cases.Get(t.Context(), id); len(c.Entries) != 0 {
		t.Errorf("entries after refused uploads: %+v", c.Entries)
	}

	// A store that refuses the file: 502, and the case has no entry.
	files.put.Store(true)
	ct, body = form(func(mw *multipart.Writer) { file(mw, "a.txt", "a") })
	if code, out := postForm(t, ts, id, ct, body); code != http.StatusBadGateway {
		t.Errorf("store refuses: %d %v", code, out)
	}
	files.put.Store(false)
	if c, _ := srv.Cases.Get(t.Context(), id); len(c.Entries) != 0 {
		t.Errorf("entry for a file not stored: %+v", c.Entries)
	}
}

// A stored file that cannot be read is 502, one gone from the store 404,
// and one never on the timeline 404; removing an entry whose file cannot
// be deleted still removes the entry.
func TestCaseFileDownloadFailures(t *testing.T) {
	files := &flakyFiles{Store: casefiles.NewMemory()}
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) { srv, s.CaseFiles = s, files })
	_, out := do(t, ts, "POST", "/api/cases", `{"title":"Phish"}`, true)
	id := out["case"].(map[string]any)["id"].(string)
	code, out := upload(t, ts, id, "mail.eml", []byte("From: x"), "")
	if code != http.StatusCreated {
		t.Fatalf("upload: %d %v", code, out)
	}
	ent := out["entry"].(map[string]any)
	fid, eid := ent["file_id"].(string), ent["id"].(string)
	path := "/api/cases/" + id + "/files/" + fid

	if code, _ := do(t, ts, "GET", "/api/cases/"+id+"/files/nope", "", true); code != http.StatusNotFound {
		t.Errorf("unknown file: %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/cases/CASE-20260101-0123456789abcdef/files/"+fid, "", true); code != http.StatusNotFound {
		t.Errorf("unknown case: %d", code)
	}
	files.get.Store(true)
	if code, _ := do(t, ts, "GET", path, "", true); code != http.StatusBadGateway {
		t.Errorf("store down: %d", code)
	}
	files.get.Store(false)
	files.lose.Store(true)
	if code, _ := do(t, ts, "GET", path, "", true); code != http.StatusNotFound {
		t.Errorf("file gone from the store: %d", code)
	}
	files.lose.Store(false)
	if code, _ := do(t, ts, "GET", path, "", true); code != http.StatusOK {
		t.Errorf("download: %d", code)
	}

	files.del.Store(true)
	if code, out := do(t, ts, "DELETE", "/api/cases/"+id+"/entries/"+eid, "", true); code != http.StatusOK {
		t.Fatalf("remove entry: %d %v", code, out)
	}
	c, _ := srv.Cases.Get(t.Context(), id)
	for _, e := range c.Entries {
		if e.ID == eid {
			t.Errorf("entry still on the timeline: %+v", e)
		}
	}
	if code, _ := do(t, ts, "GET", path, "", true); code != http.StatusNotFound {
		t.Errorf("download after removal: %d", code)
	}
}
