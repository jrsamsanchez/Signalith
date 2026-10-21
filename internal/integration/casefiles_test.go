// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/casefiles"
	"github.com/jrsamsanchez/signalith/internal/cases"
)

// Files attached to cases round-trip through OpenSearch byte for byte,
// stay with their case, and go when retention deletes the case.
func TestCaseFilesInOpenSearch(t *testing.T) {
	cl, _, prefix := setup(t)
	ctx := context.Background()
	cs := cases.NewOpenSearch(cl, prefix)
	if err := cs.EnsureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	fs := casefiles.NewOpenSearch(cl, prefix)
	// Before any file: nothing to prune, no index needed.
	if n, err := fs.Prune(ctx, cs.Index); err != nil || n != 0 {
		t.Fatalf("prune with no index: %d %v", n, err)
	}
	now := time.Now()
	keep := &cases.Case{ID: "CASE-keep", Title: "kept", Status: "open", Severity: "low", Created: now, Updated: now}
	gone := &cases.Case{ID: "CASE-gone", Title: "gone", Status: "closed", Severity: "low", Created: now, Updated: now}
	for _, c := range []*cases.Case{keep, gone} {
		if err := cs.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	data := append([]byte{0, 1, 2, 0xff}, bytes.Repeat([]byte("binary"), 1000)...)
	kf := casefiles.New(keep.ID, "dump.bin", data, "ana", now)
	gf := casefiles.New(gone.ID, "mail.eml", []byte("From: x"), "ana", now)
	for _, f := range []*casefiles.File{kf, gf} {
		d := data
		if f == gf {
			d = []byte("From: x")
		}
		if err := fs.Put(ctx, f, d); err != nil {
			t.Fatal(err)
		}
	}
	got, back, err := fs.Get(ctx, keep.ID, kf.ID)
	if err != nil || !bytes.Equal(back, data) || !got.Matches(back) || got.Name != "dump.bin" {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, _, err := fs.Get(ctx, gone.ID, kf.ID); err != casefiles.ErrNotFound {
		t.Errorf("a file through another case: %v", err)
	}
	if err := cs.Delete(ctx, gone.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := fs.Prune(ctx, cs.Index); err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if _, _, err := fs.Get(ctx, gone.ID, gf.ID); err != casefiles.ErrNotFound {
		t.Errorf("file of a deleted case: %v", err)
	}
	if _, _, err := fs.Get(ctx, keep.ID, kf.ID); err != nil {
		t.Errorf("file of a kept case: %v", err)
	}
	if err := fs.Delete(ctx, keep.ID, kf.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fs.Get(ctx, keep.ID, kf.ID); err != casefiles.ErrNotFound {
		t.Errorf("after delete: %v", err)
	}
}
