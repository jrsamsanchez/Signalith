// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package casefiles keeps the files attached to cases: a screenshot, an
// email with its headers, a memory dump's report. Each file is stored
// once, with the SHA-256 of its bytes taken when it was added; the case's
// timeline holds an entry naming it (cases.KindFile), so the file shows
// in the case and its report like other evidence.
//
// Files are only ever handed back as downloads: the server never shows
// one in the browser, so a file that is a web page or a script cannot run
// on the server's own pages.
package casefiles

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Limits keep files from filling OpenSearch.
const (
	// MaxFileBytes caps one file.
	MaxFileBytes = 10 << 20
	// MaxPerCase caps how many files one case holds.
	MaxPerCase = 25
	// MaxCaseBytes caps the files of one case together.
	MaxCaseBytes = 100 << 20
	// MaxNameLen caps a file's name, in characters.
	MaxNameLen = 200
)

// ErrNotFound is a file the case does not have.
var ErrNotFound = errors.New("the case has no such file")

// File is one attached file, without its bytes.
type File struct {
	ID     string `json:"id"`
	CaseID string `json:"case_id"`
	Name   string `json:"name"`
	// ContentType is what the bytes look like (http.DetectContentType),
	// to show; downloads are always sent as application/octet-stream.
	ContentType string    `json:"content_type"`
	Size        int64     `json:"size"`
	SHA256      string    `json:"sha256"`
	Added       time.Time `json:"added"`
	AddedBy     string    `json:"added_by"`
}

// New describes data as a file of a case, taking its SHA-256 now.
func New(caseID, name string, data []byte, by string, now time.Time) *File {
	sum := sha256.Sum256(data)
	return &File{
		ID: newID(), CaseID: caseID, Name: CleanName(name), ContentType: http.DetectContentType(data),
		Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Added: now.UTC().Truncate(time.Millisecond), AddedBy: by,
	}
}

// Matches reports whether data is still the file's bytes.
func (f *File) Matches(data []byte) bool {
	sum := sha256.Sum256(data)
	return int64(len(data)) == f.Size && hex.EncodeToString(sum[:]) == f.SHA256
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ValidID is true for an ID New could have made.
func ValidID(id string) bool {
	if len(id) != 16 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil && strings.ToLower(id) == id
}

// CleanName keeps the last part of a file name a browser sent, without
// folders, control characters or invisible formatting (such as a
// right-to-left mark that makes "exe.pdf" read as "fdp.exe"), and at most
// MaxNameLen characters. An empty name becomes "file".
func CleanName(name string) string {
	name = strings.ReplaceAll(name, `\`, "/")
	name = path.Base(name)
	var b strings.Builder
	for _, r := range name {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '"' {
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	out = strings.Trim(out, ".")
	if r := []rune(out); len(r) > MaxNameLen {
		out = string(r[:MaxNameLen])
	}
	if out == "" || out == "/" {
		return "file"
	}
	return out
}
