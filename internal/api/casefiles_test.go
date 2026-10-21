// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/casefiles"
	"github.com/jrsamsanchez/signalith/internal/casereport"
)

// upload attaches a file to a case as the browser does.
func upload(t *testing.T, ts *httptest.Server, caseID, name string, data []byte, text string) (int, map[string]any) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if text != "" {
		mw.WriteField("text", text)
	}
	fw, _ := mw.CreateFormFile("file", name)
	fw.Write(data)
	mw.Close()
	req, _ := http.NewRequest("POST", ts.URL+"/api/cases/"+caseID+"/files", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestCaseFiles(t *testing.T) {
	files := casefiles.NewMemory()
	ts, _ := newTestServerWith(t, func(s *Server) { s.CaseFiles = files })
	_, out := do(t, ts, "POST", "/api/cases", `{"title":"Phish"}`, true)
	id := out["case"].(map[string]any)["id"].(string)

	page := []byte("<html><script>alert(document.cookie)</script></html>")
	code, out := upload(t, ts, id, `C:\Users\ana\mail “original”.html`, page, "The email as received")
	if code != http.StatusCreated {
		t.Fatalf("upload: %d %v", code, out)
	}
	ent := out["entry"].(map[string]any)
	fid := ent["file_id"].(string)
	if ent["kind"] != "file" || ent["file_name"] != "mail “original”.html" || ent["text"] != "The email as received" || ent["sha256"] == "" || len(ent["file_sha256"].(string)) != 64 {
		t.Fatalf("entry %v", ent)
	}

	// A download is only ever a download.
	resp, got := get(t, ts, "/api/cases/"+id+"/files/"+fid)
	h := resp.Header
	if resp.StatusCode != http.StatusOK || got != string(page) || h.Get("Content-Type") != "application/octet-stream" ||
		h.Get("X-Content-Type-Options") != "nosniff" || !strings.HasPrefix(h.Get("Content-Security-Policy"), "sandbox") ||
		!strings.HasPrefix(h.Get("Content-Disposition"), "attachment;") || !strings.Contains(h.Get("Content-Disposition"), "filename*=utf-8''") ||
		h.Get("X-Signalith-Evidence") != "" {
		t.Fatalf("download: %d %v", resp.StatusCode, h)
	}
	if resp, _ := get(t, ts, "/api/cases/"+id+"/files/0123456789abcdef"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown file: %d", resp.StatusCode)
	}
	_, other := do(t, ts, "POST", "/api/cases", `{"title":"Other"}`, true)
	oid := other["case"].(map[string]any)["id"].(string)
	if resp, _ := get(t, ts, "/api/cases/"+oid+"/files/"+fid); resp.StatusCode != http.StatusNotFound {
		t.Errorf("a file through another case: %d", resp.StatusCode)
	}

	// The report lists the file and checks its bytes.
	_, rep := get(t, ts, "/api/cases/"+id+"/report?format=json")
	res, err := casereport.Verify([]byte(rep), nil, false)
	if err != nil || len(res.Report.Evidence) != 1 || !res.Report.Evidence[0].Intact || res.Report.Evidence[0].FileSHA256 != ent["file_sha256"] {
		t.Fatalf("report: %+v %v", res, err)
	}
	files.Tamper(fid, []byte("changed"))
	if resp, _ := get(t, ts, "/api/cases/"+id+"/files/"+fid); resp.Header.Get("X-Signalith-Evidence") != "changed" {
		t.Error("a changed file is not flagged on download")
	}
	// HEAD would read the file and count as a download.
	req, _ := http.NewRequest("HEAD", ts.URL+"/api/cases/"+id+"/files/"+fid, nil)
	req.SetBasicAuth("admin", "s3cret-pass")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("HEAD: %v %v", resp, err)
	}

	// Bad uploads.
	if code, _ := upload(t, ts, id, "empty.txt", nil, ""); code != http.StatusBadRequest {
		t.Errorf("empty: %d", code)
	}
	if code, _ := upload(t, ts, id, "big.bin", make([]byte, casefiles.MaxFileBytes+1), ""); code != http.StatusRequestEntityTooLarge {
		t.Errorf("too big: %d", code)
	}
	if code, _ := upload(t, ts, "CASE-nope", "a.txt", []byte("a"), ""); code != http.StatusNotFound {
		t.Errorf("missing case: %d", code)
	}
	if code, _ := do(t, ts, "POST", "/api/cases/"+id+"/files", `{"file":"x"}`, true); code != http.StatusBadRequest {
		t.Errorf("not multipart: %d", code)
	}
	for i := 1; i < casefiles.MaxPerCase; i++ {
		if code, out := upload(t, ts, id, "n.txt", []byte{byte(i)}, ""); code != http.StatusCreated {
			t.Fatalf("file %d: %d %v", i, code, out)
		}
	}
	if code, out := upload(t, ts, id, "one-too-many.txt", []byte("x"), ""); code != http.StatusBadRequest || !strings.Contains(out["error"].(string), "at most") {
		t.Errorf("over the count: %d %v", code, out)
	}

	// A file gone from the store shows as changed in the report.
	if code, out := upload(t, ts, oid, "gone.txt", []byte("gone"), ""); code == http.StatusCreated {
		gid := out["entry"].(map[string]any)["file_id"].(string)
		files.Delete(t.Context(), oid, gid)
		_, rep := get(t, ts, "/api/cases/"+oid+"/report?format=json")
		if res, err := casereport.Verify([]byte(rep), nil, false); err != nil || res.Report.Evidence[0].Intact {
			t.Errorf("missing file in report: %+v %v", res, err)
		}
	} else {
		t.Fatalf("upload: %d", code)
	}

	// Removing the entry deletes the file.
	if code, _ := do(t, ts, "DELETE", "/api/cases/"+id+"/entries/"+ent["id"].(string), "", true); code != http.StatusOK {
		t.Fatalf("remove: %d", code)
	}
	if _, _, err := files.Get(t.Context(), id, fid); err != casefiles.ErrNotFound {
		t.Errorf("file after its entry was removed: %v", err)
	}
	if resp, _ := get(t, ts, "/api/cases/"+id+"/files/"+fid); resp.StatusCode != http.StatusNotFound {
		t.Errorf("download after removal: %d", resp.StatusCode)
	}
}

func TestCaseFilesOff(t *testing.T) {
	ts, _ := newTestServer(t)
	_, out := do(t, ts, "POST", "/api/cases", `{"title":"Phish"}`, true)
	id := out["case"].(map[string]any)["id"].(string)
	if code, _ := upload(t, ts, id, "a.txt", []byte("a"), ""); code != http.StatusServiceUnavailable {
		t.Errorf("no store: %d", code)
	}
}

func TestAttachmentHeader(t *testing.T) {
	for name, want := range map[string]string{
		"report.pdf":  `attachment; filename=report.pdf`,
		"a;b c.txt":   `attachment; filename="a;b c.txt"`,
		"naïve;x.txt": `attachment; filename*=utf-8''na%C3%AFve%3Bx.txt; filename="na_ve_x.txt"`,
	} {
		if got := attachment(name); got != want {
			t.Errorf("attachment(%q) = %s, want %s", name, got, want)
		}
	}
}

func TestFileTransferLimit(t *testing.T) {
	var held []func()
	for i := 0; i < maxUserTransfers; i++ {
		release, ok := fileTransfers.take("ana")
		if !ok {
			t.Fatalf("transfer %d refused", i)
		}
		held = append(held, release)
	}
	if _, ok := fileTransfers.take("ana"); ok {
		t.Error("one user ran more than the cap")
	}
	for i := maxUserTransfers; i < maxTransfers; i++ {
		release, ok := fileTransfers.take(fmt.Sprintf("user%d", i))
		if !ok {
			t.Fatalf("transfer %d refused", i)
		}
		held = append(held, release)
	}
	if _, ok := fileTransfers.take("bob"); ok {
		t.Error("the server ran more than the cap")
	}
	for _, release := range held {
		release()
	}
	if release, ok := fileTransfers.take("ana"); !ok {
		t.Error("released transfers were not freed")
	} else {
		release()
	}
}
