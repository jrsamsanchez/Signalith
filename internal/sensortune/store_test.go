// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sensortune

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// failing fails reads while fail is set.
type failing struct {
	Docs
	fail bool
}

func (f *failing) Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error) {
	if f.fail {
		return nil, store.Version{}, false, errors.New("opensearch is down")
	}
	return f.Docs.Get(ctx, index, id)
}

func TestStore(t *testing.T) {
	ctx := context.Background()
	docs := &failing{Docs: endpoint.NewMemoryDocs()}
	s := NewStore(docs, "sig")
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	if s.Index != "sig_endpoints" {
		t.Fatal(s.Index)
	}

	// Never saved: empty, version zero.
	tu, v, err := s.Get(ctx)
	if err != nil || !v.IsZero() || tu.Hash() != (Tuning{}).Hash() {
		t.Fatalf("first: %+v %v %v", tu, v, err)
	}

	// Refused lines are not saved.
	if _, _, err := s.Save(ctx, Tuning{Disable: "nope"}, v, "admin"); err == nil {
		t.Fatal("bad line saved")
	}
	saved, v1, err := s.Save(ctx, Tuning{Disable: "2014520\r\n"}, v, "admin")
	if err != nil || v1.IsZero() || saved.Disable != "2014520" || saved.UpdatedBy != "admin" || !saved.UpdatedAt.Equal(now) {
		t.Fatalf("save: %+v %v %v", saved, v1, err)
	}
	// A second first save, and a save from a stale version, conflict.
	if _, _, err := s.Save(ctx, Tuning{Disable: "1"}, store.Version{}, "bob"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("create twice: %v", err)
	}
	if _, v2, err := s.Save(ctx, Tuning{Disable: "2"}, v1, "bob"); err != nil || v2.Same(v1) {
		t.Fatalf("second save: %v", err)
	}
	if _, _, err := s.Save(ctx, Tuning{Disable: "3"}, v1, "carl"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("stale save: %v", err)
	}

	// Another server sees the save; a failed read keeps the last copy.
	other := NewStore(docs, "sig")
	got, _, err := other.Get(ctx)
	if err != nil || got.Disable != "2" || got.UpdatedBy != "bob" {
		t.Fatalf("other server: %+v %v", got, err)
	}
	docs.fail = true
	now = now.Add(time.Minute)
	if got, _, err := s.Get(ctx); err != nil || got.Disable != "2" {
		t.Errorf("failed read: %+v %v", got, err)
	}
	if _, _, err := NewStore(docs, "sig").Get(ctx); err == nil {
		t.Error("a failed first read gave a tuning")
	}
}
