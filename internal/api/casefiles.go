// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/casefiles"
	"github.com/jrsamsanchez/signalith/internal/cases"
)

// Files attached to a case are evidence: adding one is an analyst's step,
// and every upload and download is audited.
func (s *Server) routeCaseFiles(api *router) {
	api.analyst("POST /api/cases/{id}/files", s.handleAttachCaseFile)
	api.viewer("GET /api/cases/{id}/files/{file}", s.handleCaseFile)
}

// errNoFiles is a server that keeps no files.
var errNoFiles = errors.New("this server cannot keep files")

// handleAttachCaseFile adds a file to a case: a multipart form with the
// file in "file" and an optional note in "text". The file is stored with
// the SHA-256 of its bytes, then named on the timeline; when the case
// cannot take it, the stored file is removed again.
func (s *Server) handleAttachCaseFile(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	if s.CaseFiles == nil {
		writeError(w, http.StatusServiceUnavailable, errNoFiles)
		return
	}
	name, text, data, err := readCaseFile(w, r)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("a file is at most %d MiB", casefiles.MaxFileBytes>>20))
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	caseID, user := r.PathValue("id"), userOf(r)
	// Check the case first, so a file for a case that is missing or full
	// is never stored.
	c, err := s.Cases.Get(r.Context(), caseID)
	if err != nil {
		writeCaseError(w, err)
		return
	}
	if err := fileRoom(c, int64(len(data))); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	f := casefiles.New(c.ID, name, data, user, time.Now())
	if err := s.CaseFiles.Put(r.Context(), f, data); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	var added *cases.Entry
	c, err = s.modifyCase(r.Context(), caseID, func(c *cases.Case) (bool, error) {
		if err := fileRoom(c, f.Size); err != nil {
			return false, badRequest{err}
		}
		ent, err := c.AddEntry(cases.Entry{Kind: cases.KindFile, Text: text, FileID: f.ID, FileName: f.Name,
			FileSize: f.Size, FileType: f.ContentType, FileSHA256: f.SHA256}, user, time.Now().UTC())
		if err != nil {
			return false, badRequest{err}
		}
		added = ent
		return true, nil
	})
	if err != nil {
		if derr := s.CaseFiles.Delete(context.WithoutCancel(r.Context()), caseID, f.ID); derr != nil {
			s.Log.Warn("a file the case did not take was not removed", "case", caseID, "file", f.ID, "err", derr)
		}
		s.writeModifyError(w, err)
		return
	}
	s.audit(r, "case file attached", "case", caseID, "file", f.ID, "name", f.Name, "size", f.Size, "sha256", f.SHA256)
	writeJSON(w, http.StatusCreated, map[string]any{"case": c, "entry": added})
}

// fileRoom says why a case cannot take one more file of size bytes.
func fileRoom(c *cases.Case, size int64) error {
	n, total := c.FileUsage()
	if n >= casefiles.MaxPerCase {
		return fmt.Errorf("a case holds at most %d files", casefiles.MaxPerCase)
	}
	if total+size > casefiles.MaxCaseBytes {
		return fmt.Errorf("the files of a case are at most %d MiB together", casefiles.MaxCaseBytes>>20)
	}
	return nil
}

// readCaseFile reads the upload form without temporary files: the file
// part into memory, up to the size cap, and the note.
func readCaseFile(w http.ResponseWriter, r *http.Request) (name, text string, data []byte, err error) {
	r.Body = http.MaxBytesReader(w, r.Body, casefiles.MaxFileBytes+64<<10)
	mr, err := r.MultipartReader()
	if err != nil {
		return "", "", nil, errors.New("send the file as multipart/form-data")
	}
	got := false
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", nil, err
		}
		switch p.FormName() {
		case "file":
			if got {
				return "", "", nil, errors.New("send one file at a time")
			}
			var buf bytes.Buffer
			n, err := io.Copy(&buf, io.LimitReader(p, casefiles.MaxFileBytes+1))
			if err != nil {
				return "", "", nil, err
			}
			if n > casefiles.MaxFileBytes {
				return "", "", nil, &http.MaxBytesError{Limit: casefiles.MaxFileBytes}
			}
			name, data, got = p.FileName(), buf.Bytes(), true
		case "text":
			b, err := io.ReadAll(io.LimitReader(p, cases.MaxTextLen+1))
			if err != nil {
				return "", "", nil, err
			}
			if len(b) > cases.MaxTextLen {
				return "", "", nil, errors.New("text is too long")
			}
			text = strings.TrimSpace(string(b))
		}
		p.Close()
	}
	if !got {
		return "", "", nil, errors.New("no file was sent")
	}
	if len(data) == 0 {
		return "", "", nil, errors.New("the file is empty")
	}
	return name, text, data, nil
}

// handleCaseFile downloads a file of a case. It is always a download
// that the browser does not open: application/octet-stream, no sniffing,
// and a policy that allows nothing, whatever the file holds. Bytes that
// no longer match their SHA-256 are still sent, so they can be examined,
// with a header saying so.
func (s *Server) handleCaseFile(w http.ResponseWriter, r *http.Request) {
	if !s.casesReady(w) {
		return
	}
	if s.CaseFiles == nil {
		writeError(w, http.StatusServiceUnavailable, errNoFiles)
		return
	}
	c, err := s.Cases.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeCaseError(w, err)
		return
	}
	id := r.PathValue("file")
	// Only a file still on the timeline: one removed from it is gone.
	i := slices.IndexFunc(c.Entries, func(e cases.Entry) bool { return e.Kind == cases.KindFile && e.FileID == id })
	if i < 0 {
		writeError(w, http.StatusNotFound, casefiles.ErrNotFound)
		return
	}
	e := c.Entries[i]
	f, data, err := s.CaseFiles.Get(r.Context(), c.ID, id)
	if errors.Is(err, casefiles.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	intact := f.Matches(data) && f.SHA256 == e.FileSHA256 && cases.EvidenceIntact(e)
	s.audit(r, "case file downloaded", "case", c.ID, "file", id, "sha256", e.FileSHA256, "intact", intact)
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", attachment(e.FileName))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(len(data)))
	h.Set("X-Signalith-SHA256", e.FileSHA256)
	if !intact {
		h.Set("X-Signalith-Evidence", "changed")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// attachment is a Content-Disposition naming a download: the name in
// UTF-8, with a plain ASCII fallback for older clients.
func attachment(name string) string {
	ascii := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' || r == ';' {
			return '_'
		}
		return r
	}, name)
	if ascii == name {
		return `attachment; filename="` + name + `"`
	}
	return mime.FormatMediaType("attachment", map[string]string{"filename": name}) + `; filename="` + ascii + `"`
}

// caseFileIntact checks an attached file's bytes for a report.
func (s *Server) caseFileIntact(ctx context.Context, caseID string) func(cases.Entry) bool {
	return func(e cases.Entry) bool {
		if s.CaseFiles == nil {
			return false
		}
		f, data, err := s.CaseFiles.Get(ctx, caseID, e.FileID)
		return err == nil && f.Matches(data) && f.SHA256 == e.FileSHA256
	}
}

// removeCaseFile deletes the stored file of a timeline entry removed
// from a case.
func (s *Server) removeCaseFile(r *http.Request, caseID string, e cases.Entry) {
	if s.CaseFiles == nil || e.Kind != cases.KindFile {
		return
	}
	if err := s.CaseFiles.Delete(context.WithoutCancel(r.Context()), caseID, e.FileID); err != nil {
		s.Log.Warn("a file removed from a case was not deleted; retention removes it with the case", "case", caseID, "file", e.FileID, "err", err)
		return
	}
	s.audit(r, "case file removed", "case", caseID, "file", e.FileID, "name", e.FileName, "sha256", e.FileSHA256)
}
