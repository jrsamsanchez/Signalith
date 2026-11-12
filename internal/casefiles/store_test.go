// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package casefiles

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// fakeDoer answers each request with handle, recording the requests and
// round-tripping answers through JSON as the real client does.
type fakeDoer struct {
	calls  []string
	bodies []any
	handle func(method, path string, body any) (any, error)
}

func (d *fakeDoer) Do(_ context.Context, method, path string, body, out any) error {
	d.calls = append(d.calls, method+" "+path)
	d.bodies = append(d.bodies, body)
	resp, err := d.handle(method, path, body)
	if err != nil {
		return err
	}
	if out != nil && resp != nil {
		b, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		return json.Unmarshal(b, out)
	}
	return nil
}

func TestNewOpenSearch(t *testing.T) {
	s := NewOpenSearch(&fakeDoer{}, "sig")
	if s.Index != "sig_case_files" {
		t.Errorf("index %q", s.Index)
	}
}

func TestEnsureIndex(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{"created", nil, false},
		{"exists", &store.Error{Status: 400, Body: `{"error":{"type":"resource_already_exists_exception"}}`}, false},
		{"other 400", &store.Error{Status: 400, Body: "mapper_parsing_exception"}, true},
		{"down", errors.New("connection refused"), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeDoer{handle: func(string, string, any) (any, error) { return nil, tc.err }}
			err := NewOpenSearch(d, "p").EnsureIndex(t.Context())
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, want error %v", err, tc.wantErr)
			}
			if len(d.calls) != 1 || d.calls[0] != "PUT /p_case_files" {
				t.Errorf("calls %v", d.calls)
			}
			m := d.bodies[0].(map[string]any)["mappings"].(map[string]any)
			if m["dynamic"] != "false" {
				t.Errorf("mapping %v", m)
			}
		})
	}
}

func TestOpenSearchPut(t *testing.T) {
	data := []byte("evidence")
	f := New("CASE-1", "a.txt", data, "ana", time.Now())
	d := &fakeDoer{handle: func(string, string, any) (any, error) { return nil, nil }}
	s := NewOpenSearch(d, "p")
	if err := s.Put(t.Context(), f, data); err != nil {
		t.Fatal(err)
	}
	if len(d.calls) != 2 || d.calls[1] != "PUT /p_case_files/_create/"+f.ID+"?refresh=wait_for" {
		t.Fatalf("calls %v", d.calls)
	}
	dc := d.bodies[1].(doc)
	if dc.Data != base64.StdEncoding.EncodeToString(data) || dc.File != f {
		t.Errorf("doc %+v", dc)
	}

	// The index cannot be made: nothing is written.
	d = &fakeDoer{handle: func(string, string, any) (any, error) { return nil, errors.New("down") }}
	if err := NewOpenSearch(d, "p").Put(t.Context(), f, data); err == nil || len(d.calls) != 1 {
		t.Errorf("put without index: %v, calls %v", err, d.calls)
	}
}

func TestOpenSearchGetAndStat(t *testing.T) {
	data := []byte("evidence")
	f := New("CASE-1", "a.txt", data, "ana", time.Now())
	src := map[string]any{
		"id": f.ID, "case_id": f.CaseID, "name": f.Name, "size": f.Size, "sha256": f.SHA256,
		"content_type": f.ContentType, "added": f.Added, "added_by": f.AddedBy,
		"data": base64.StdEncoding.EncodeToString(data),
	}
	tests := []struct {
		name     string
		caseID   string
		id       string
		resp     any
		err      error
		want     error // ErrNotFound, or nil
		wantFail bool  // another error
		calls    int
	}{
		{"found", "CASE-1", f.ID, map[string]any{"found": true, "_source": src}, nil, nil, false, 1},
		{"bad id", "CASE-1", "../x", nil, nil, ErrNotFound, false, 0},
		{"not found", "CASE-1", f.ID, map[string]any{"found": false}, nil, ErrNotFound, false, 1},
		{"other case", "CASE-2", f.ID, map[string]any{"found": true, "_source": src}, nil, ErrNotFound, false, 1},
		{"index missing", "CASE-1", f.ID, nil, &store.Error{Status: 404}, ErrNotFound, false, 1},
		{"down", "CASE-1", f.ID, nil, errors.New("down"), nil, true, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeDoer{handle: func(string, string, any) (any, error) { return tc.resp, tc.err }}
			s := NewOpenSearch(d, "p")
			got, b, err := s.Get(t.Context(), tc.caseID, tc.id)
			check := func(op string, err error) {
				t.Helper()
				switch {
				case tc.want != nil && !errors.Is(err, tc.want):
					t.Errorf("%s: err = %v, want %v", op, err, tc.want)
				case tc.wantFail && (err == nil || errors.Is(err, ErrNotFound)):
					t.Errorf("%s: err = %v, want a failure", op, err)
				case tc.want == nil && !tc.wantFail && err != nil:
					t.Errorf("%s: %v", op, err)
				}
			}
			check("get", err)
			if err == nil && (string(b) != "evidence" || got.ID != f.ID || !got.Matches(b)) {
				t.Errorf("get: %+v %q", got, b)
			}
			st, err := s.Stat(t.Context(), tc.caseID, tc.id)
			check("stat", err)
			if err == nil && (st.ID != f.ID || st.SHA256 != f.SHA256) {
				t.Errorf("stat: %+v", st)
			}
			if len(d.calls) != 2*tc.calls {
				t.Errorf("calls %v", d.calls)
			}
			if tc.calls > 0 && !strings.HasSuffix(d.calls[1], "?_source_excludes=data") {
				t.Errorf("stat asked for the bytes: %v", d.calls)
			}
		})
	}

	// Bytes that are not base64.
	bad := map[string]any{"id": f.ID, "case_id": "CASE-1", "data": "!!!"}
	d := &fakeDoer{handle: func(string, string, any) (any, error) {
		return map[string]any{"found": true, "_source": bad}, nil
	}}
	if _, _, err := NewOpenSearch(d, "p").Get(t.Context(), "CASE-1", f.ID); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("bad base64: %v", err)
	}
}

func TestOpenSearchDelete(t *testing.T) {
	id := New("C", "a", nil, "", time.Now()).ID
	tests := []struct {
		name    string
		id      string
		err     error
		wantErr bool
		calls   int
	}{
		{"deleted", id, nil, false, 1},
		{"bad id", "nope", nil, false, 0},
		{"index missing", id, &store.Error{Status: 404}, false, 1},
		{"down", id, errors.New("down"), true, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeDoer{handle: func(string, string, any) (any, error) { return nil, tc.err }}
			err := NewOpenSearch(d, "p").Delete(t.Context(), "CASE-1", tc.id)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v", err)
			}
			if len(d.calls) != tc.calls {
				t.Fatalf("calls %v", d.calls)
			}
			if tc.calls == 1 {
				b, _ := json.Marshal(d.bodies[0])
				if !strings.Contains(string(b), `"case_id":"CASE-1"`) || !strings.Contains(string(b), `"id":"`+id+`"`) {
					t.Errorf("query %s", b)
				}
			}
		})
	}
}

// pruneFake is an OpenSearch with files and cases for Prune.
type pruneFake struct {
	files     []map[string]any // _source of files, in added order
	cases     map[string][]string
	caseErr   map[string]bool // cases whose mget answer is an error
	count     int64
	searchErr error
	mgetErr   error
	countErr  error
	deleteErr error
	deleted   [][]string
}

func (p *pruneFake) handle(method, path string, body any) (any, error) {
	switch {
	case strings.HasSuffix(path, "/_search"):
		if p.searchErr != nil {
			return nil, p.searchErr
		}
		q := body.(map[string]any)
		start := 0
		if after, ok := q["search_after"].([]any); ok {
			b, _ := json.Marshal(after[0])
			var n int
			_ = json.Unmarshal(b, &n)
			start = n + 1
		}
		size := q["size"].(int)
		var hits []any
		for i := start; i < len(p.files) && i < start+size; i++ {
			hits = append(hits, map[string]any{"_source": p.files[i], "sort": []any{i, p.files[i]["id"]}})
		}
		return map[string]any{"hits": map[string]any{"hits": hits}}, nil
	case strings.Contains(path, "/_mget"):
		if p.mgetErr != nil {
			return nil, p.mgetErr
		}
		var docs []any
		for _, id := range body.(map[string]any)["ids"].([]string) {
			if p.caseErr[id] {
				docs = append(docs, map[string]any{"_id": id, "error": map[string]any{"type": "x"}})
				continue
			}
			fs, ok := p.cases[id]
			var entries []any
			for _, f := range fs {
				entries = append(entries, map[string]any{"file_id": f})
			}
			docs = append(docs, map[string]any{"_id": id, "found": ok, "_source": map[string]any{"entries": entries}})
		}
		return map[string]any{"docs": docs}, nil
	case strings.HasSuffix(path, "/_count"):
		return map[string]any{"count": p.count}, p.countErr
	case strings.Contains(path, "/_delete_by_query"):
		if p.deleteErr != nil {
			return nil, p.deleteErr
		}
		ids := body.(map[string]any)["query"].(map[string]any)["terms"].(map[string]any)["id"].([]string)
		p.deleted = append(p.deleted, ids)
		return map[string]any{"deleted": len(ids)}, nil
	}
	return nil, errors.New("unexpected " + method + " " + path)
}

func TestPrune(t *testing.T) {
	file := func(id, caseID string) map[string]any { return map[string]any{"id": id, "case_id": caseID} }
	now := time.Now()

	t.Run("deletes files no case names", func(t *testing.T) {
		p := &pruneFake{
			files:   []map[string]any{file("f1", "C1"), file("f2", "C1"), file("f3", "C2"), file("f4", "C3")},
			cases:   map[string][]string{"C1": {"f1"}, "C3": {"f4"}},
			caseErr: map[string]bool{},
		}
		d := &fakeDoer{handle: p.handle}
		n, err := NewOpenSearch(d, "p").Prune(t.Context(), "p_cases", now)
		if err != nil || n != 2 {
			t.Fatalf("Prune = %d, %v", n, err)
		}
		got := map[string]bool{}
		for _, ids := range p.deleted {
			for _, id := range ids {
				got[id] = true
			}
		}
		if len(got) != 2 || !got["f2"] || !got["f3"] {
			t.Errorf("deleted %v, want f2 and f3", p.deleted)
		}
		q := d.bodies[0].(map[string]any)
		lt := q["query"].(map[string]any)["range"].(map[string]any)["added"].(map[string]any)["lt"].(string)
		cut, err := time.Parse(time.RFC3339Nano, lt)
		if err != nil || !cut.Equal(now.Add(-PruneGrace).UTC()) {
			t.Errorf("grace cut %q", lt)
		}
	})

	t.Run("pages", func(t *testing.T) {
		p := &pruneFake{cases: map[string][]string{"C1": {}}, caseErr: map[string]bool{}}
		for i := range prunePage + 5 {
			p.files = append(p.files, file(fmt.Sprintf("f%d", i), "C1"))
		}
		n, err := NewOpenSearch(&fakeDoer{handle: p.handle}, "p").Prune(t.Context(), "p_cases", now)
		if err != nil || n != int64(prunePage+5) || len(p.deleted) != 2 {
			t.Errorf("Prune = %d, %v over %d pages", n, err, len(p.deleted))
		}
	})

	t.Run("an error keeps the case's files", func(t *testing.T) {
		p := &pruneFake{
			files:   []map[string]any{file("f1", "C1"), file("f2", "C2")},
			cases:   map[string][]string{"C2": {"f2"}},
			caseErr: map[string]bool{"C1": true},
		}
		n, err := NewOpenSearch(&fakeDoer{handle: p.handle}, "p").Prune(t.Context(), "p_cases", now)
		if err != nil || n != 0 || len(p.deleted) != 0 {
			t.Errorf("Prune = %d, %v, deleted %v", n, err, p.deleted)
		}
	})

	t.Run("empty cases index keeps files", func(t *testing.T) {
		p := &pruneFake{files: []map[string]any{file("f1", "C1")}, cases: map[string][]string{}, count: 0}
		n, err := NewOpenSearch(&fakeDoer{handle: p.handle}, "p").Prune(t.Context(), "p_cases", now)
		if err != nil || n != 0 || len(p.deleted) != 0 {
			t.Errorf("Prune = %d, %v, deleted %v", n, err, p.deleted)
		}
	})

	t.Run("deleted cases lose their files", func(t *testing.T) {
		p := &pruneFake{files: []map[string]any{file("f1", "C1")}, cases: map[string][]string{}, count: 3}
		n, err := NewOpenSearch(&fakeDoer{handle: p.handle}, "p").Prune(t.Context(), "p_cases", now)
		if err != nil || n != 1 {
			t.Errorf("Prune = %d, %v", n, err)
		}
	})

	t.Run("no files", func(t *testing.T) {
		p := &pruneFake{}
		n, err := NewOpenSearch(&fakeDoer{handle: p.handle}, "p").Prune(t.Context(), "p_cases", now)
		if err != nil || n != 0 {
			t.Errorf("Prune = %d, %v", n, err)
		}
	})

	down := errors.New("down")
	for _, tc := range []struct {
		name    string
		p       *pruneFake
		wantErr bool
	}{
		{"files index missing", &pruneFake{searchErr: &store.Error{Status: 404}}, false},
		{"search fails", &pruneFake{searchErr: down}, true},
		{"mget fails", &pruneFake{files: []map[string]any{file("f1", "C1")}, mgetErr: down}, true},
		{"count fails", &pruneFake{files: []map[string]any{file("f1", "C1")}, countErr: down}, true},
		{"delete fails", &pruneFake{files: []map[string]any{file("f1", "C1")}, cases: map[string][]string{"C1": nil}, deleteErr: down}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, err := NewOpenSearch(&fakeDoer{handle: tc.p.handle}, "p").Prune(t.Context(), "p_cases", now)
			if (err != nil) != tc.wantErr || n != 0 {
				t.Errorf("Prune = %d, %v", n, err)
			}
		})
	}
}

func TestMemoryStatTamperAndDuplicate(t *testing.T) {
	m := NewMemory()
	f := New("CASE-1", "a.txt", []byte("hello"), "ana", time.Now())
	if err := m.Put(t.Context(), f, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := m.Put(t.Context(), f, []byte("again")); !errors.Is(err, store.ErrExists) {
		t.Errorf("second put: %v", err)
	}
	st, err := m.Stat(t.Context(), "CASE-1", f.ID)
	if err != nil || st.Name != "a.txt" {
		t.Errorf("stat: %+v %v", st, err)
	}
	if _, err := m.Stat(t.Context(), "CASE-2", f.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("stat for another case: %v", err)
	}
	m.Tamper(f.ID, []byte("HELLO"))
	got, data, err := m.Get(t.Context(), "CASE-1", f.ID)
	if err != nil || got.Matches(data) {
		t.Errorf("tampered file still matches: %q %v", data, err)
	}
}
