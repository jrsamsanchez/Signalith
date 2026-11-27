// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package compliancehist

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/compliance"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// fakeDoer answers each request with handle, round-tripping answers
// through JSON as the real client does.
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

func answer(resp any, err error) func(string, string, any) (any, error) {
	return func(string, string, any) (any, error) { return resp, err }
}

func TestEnsureIndex(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{"created", nil, false},
		{"exists", &store.Error{Status: 400, Body: "resource_already_exists_exception"}, false},
		{"other 400", &store.Error{Status: 400, Body: "illegal_argument_exception"}, true},
		{"down", errors.New("down"), true},
	}
	for _, tc := range tests {
		d := &fakeDoer{handle: answer(nil, tc.err)}
		s := NewOpenSearch(d, "sig")
		err := s.EnsureIndex(t.Context())
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: %v", tc.name, err)
		}
		if d.calls[0] != "PUT /sig_compliance_history" {
			t.Errorf("%s: calls %v", tc.name, d.calls)
		}
	}
}

func TestOpenSearchCreate(t *testing.T) {
	now := time.Now()
	rec, err := Sign(record(now), nil)
	if err != nil {
		t.Fatal(err)
	}
	down := errors.New("down")
	tests := []struct {
		name  string
		rec   *Signed
		resps []error // per call: index, create
		want  error
		fails bool
		calls int
	}{
		{"created", rec, []error{nil, nil}, nil, false, 2},
		{"bad id", &Signed{ID: "../x"}, nil, nil, true, 0},
		{"no index", rec, []error{down}, down, true, 1},
		{"exists", rec, []error{nil, &store.Error{Status: 409}}, store.ErrExists, true, 2},
		{"down", rec, []error{nil, down}, down, true, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := 0
			d := &fakeDoer{handle: func(string, string, any) (any, error) {
				err := tc.resps[n]
				n++
				return nil, err
			}}
			err := NewOpenSearch(d, "sig").Create(t.Context(), tc.rec)
			if (err != nil) != tc.fails || tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("err = %v", err)
			}
			if len(d.calls) != tc.calls {
				t.Fatalf("calls %v", d.calls)
			}
			if tc.calls == 2 && d.calls[1] != "PUT /sig_compliance_history/_create/"+rec.ID+"?refresh=wait_for" {
				t.Errorf("create call %q", d.calls[1])
			}
		})
	}
}

func TestOpenSearchGet(t *testing.T) {
	now := time.Now()
	rec, _ := Sign(record(now), nil)
	other := MonthID(now.AddDate(0, -1, 0))
	down := errors.New("down")
	tests := []struct {
		name  string
		id    string
		resp  any
		err   error
		want  error
		fails bool
	}{
		{"found", rec.ID, map[string]any{"found": true, "_source": rec}, nil, nil, false},
		{"bad id", "nope", nil, nil, ErrNotFound, true},
		{"not found", rec.ID, map[string]any{"found": false}, nil, ErrNotFound, true},
		{"no index", rec.ID, nil, &store.Error{Status: 404}, ErrNotFound, true},
		{"down", rec.ID, nil, down, down, true},
		{"copy under another id", other, map[string]any{"found": true, "_source": rec}, nil, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewOpenSearch(&fakeDoer{handle: answer(tc.resp, tc.err)}, "sig").Get(t.Context(), tc.id)
			if (err != nil) != tc.fails || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v", err)
			}
			if err != nil {
				return
			}
			// The record is the document's own ID: a copy of another
			// month's record is checked as changed.
			if got.ID != tc.id || got.SHA256 != rec.SHA256 {
				t.Errorf("got %+v", got)
			}
			c := Check(got, nil)
			if tc.id != rec.ID && c.Check != Changed {
				t.Errorf("a copy under another ID checks as %s", c.Check)
			}
		})
	}
}

func TestOpenSearchList(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	month, _ := Sign(record(now.AddDate(0, -1, 0)), nil)
	manualRec := record(now)
	manualRec.ID = ManualID(now)
	manual, _ := Sign(manualRec, nil)
	hit := func(id string, s *Signed) map[string]any { return map[string]any{"_id": id, "_source": s} }
	d := &fakeDoer{handle: func(_, _ string, body any) (any, error) {
		b, _ := json.Marshal(body)
		if strings.Contains(string(b), "must_not") {
			return map[string]any{"hits": map[string]any{"hits": []any{hit(manual.ID, manual)}}}, nil
		}
		// A record stored under another ID shows under that ID.
		return map[string]any{"hits": map[string]any{"hits": []any{hit(month.ID, month), hit("2001-01", month)}}}, nil
	}}
	list, err := NewOpenSearch(d, "sig").List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 || list[0].ID != manual.ID {
		t.Fatalf("list %+v", list)
	}
	ids := map[string]bool{}
	for _, s := range list {
		ids[s.ID] = true
	}
	if !ids["2001-01"] || !ids[month.ID] {
		t.Errorf("ids %v", ids)
	}
	if len(d.calls) != 2 || d.calls[0] != "POST /sig_compliance_history/_search" {
		t.Errorf("calls %v", d.calls)
	}
	q := d.bodies[0].(map[string]any)
	if q["size"] != MaxList {
		t.Errorf("size %v", q["size"])
	}

	// No index yet: an empty history.
	list, err = NewOpenSearch(&fakeDoer{handle: answer(nil, &store.Error{Status: 404})}, "sig").List(t.Context())
	if err != nil || list == nil || len(list) != 0 {
		t.Errorf("no index: %v %v", list, err)
	}

	down := errors.New("down")
	if _, err := NewOpenSearch(&fakeDoer{handle: answer(nil, down)}, "sig").List(t.Context()); !errors.Is(err, down) {
		t.Errorf("down: %v", err)
	}
	// The second search fails.
	n := 0
	d = &fakeDoer{handle: func(string, string, any) (any, error) {
		n++
		if n == 2 {
			return nil, down
		}
		return map[string]any{"hits": map[string]any{"hits": []any{}}}, nil
	}}
	if _, err := NewOpenSearch(d, "sig").List(t.Context()); !errors.Is(err, down) {
		t.Errorf("second search down: %v", err)
	}
}

func TestMemoryTamperAndEmptyList(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	if list, err := m.List(ctx); err != nil || list == nil || len(list) != 0 {
		t.Errorf("empty: %v %v", list, err)
	}
	priv, _, keys := keyring(t)
	s, _ := Sign(record(time.Now()), priv)
	if err := m.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := m.Create(ctx, s); !errors.Is(err, store.ErrExists) {
		t.Errorf("second create: %v", err)
	}
	if _, err := m.Get(ctx, "1999-01"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	m.Tamper(s.ID, base64.StdEncoding.EncodeToString([]byte(`{"id":"x"}`)))
	got, _ := m.Get(ctx, s.ID)
	if c := Check(got, keys); c.Check != Changed {
		t.Errorf("tampered record checks as %s", c.Check)
	}
}

func TestDueReportsErrors(t *testing.T) {
	down := errors.New("down")
	due, err := Due(t.Context(), NewOpenSearch(&fakeDoer{handle: answer(nil, down)}, "sig"), time.Now())
	if due || !errors.Is(err, down) {
		t.Errorf("Due = %v, %v", due, err)
	}
}

func TestCheckProblems(t *testing.T) {
	priv, _, keys := keyring(t)
	now := time.Now()
	s, _ := Sign(record(now), priv)
	tests := []struct {
		name string
		edit func(x *Signed)
		want string
	}{
		{"not base64", func(x *Signed) { x.Payload = "!!" }, "not base64"},
		{"not a record", func(x *Signed) {
			b := []byte("[1]")
			x.Payload = base64.StdEncoding.EncodeToString(b)
			sum := sha256.Sum256(b)
			x.SHA256 = hex.EncodeToString(sum[:])
		}, "not a record"},
		{"signature not base64", func(x *Signed) { x.Sig = "!!" }, "does not match"},
	}
	for _, tc := range tests {
		x := *s
		tc.edit(&x)
		if c := Check(&x, keys); c.Check != Changed || !strings.Contains(c.Problem, tc.want) {
			t.Errorf("%s: %+v", tc.name, c)
		}
	}
}

func TestFromReportCopiesAttestationsAndCapabilities(t *testing.T) {
	at := time.Now().Add(-time.Hour)
	rep := &compliance.Report{Generated: at, Notes: []string{"n"}, Frameworks: []compliance.FrameworkReport{{
		Framework: compliance.Framework{ID: "iso", Name: "ISO"},
		Controls: []compliance.ControlReport{{Control: compliance.Control{ID: "A.1"}, Status: compliance.External,
			Attestation: &compliance.Attestation{Note: "done", By: "ann", At: at}}},
	}}}
	rep.Capabilities = append(rep.Capabilities, compliance.CapabilityResult{ID: "edr", Status: compliance.Met, Detail: "ok"})
	r := FromReport(rep, ManualID(at), "manual", "ann", "s", "v", "t")
	c := r.Frameworks[0].Controls[0]
	if c.AttestedBy != "ann" || c.AttestedAt == nil || !c.AttestedAt.Equal(at) {
		t.Errorf("control %+v", c)
	}
	if len(r.Capabilities) != 1 || r.Capabilities[0].Detail != "ok" {
		t.Errorf("capabilities %+v", r.Capabilities)
	}
}

func TestBrokenLinkReadsOlderRecords(t *testing.T) {
	now := time.Now()
	prev, _ := Sign(record(now.AddDate(0, -1, 0)), nil)
	r := record(now)
	r.PrevID, r.PrevSHA256 = prev.ID, prev.SHA256
	get := func(id string) (*Signed, error) {
		if id == prev.ID {
			return prev, nil
		}
		return nil, ErrNotFound
	}
	if why := BrokenLink(r, nil, get); why != "" {
		t.Errorf("read back: %q", why)
	}
	if why := BrokenLink(r, nil, func(string) (*Signed, error) { return nil, errors.New("down") }); why != "" {
		t.Errorf("a read error is not a broken link: %q", why)
	}
	if why := BrokenLink(r, nil, func(string) (*Signed, error) { return nil, ErrNotFound }); !strings.Contains(why, "deleted") {
		t.Errorf("deleted: %q", why)
	}
	if why := BrokenLink(r, map[string]string{prev.ID: "other"}, get); !strings.Contains(why, "changed") {
		t.Errorf("changed: %q", why)
	}
}
