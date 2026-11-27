// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/intel"
)

// flakyIntel is an indicator backend whose writes fail while down is set.
type flakyIntel struct {
	*intel.Memory
	down atomic.Bool
}

func (f *flakyIntel) Put(ctx context.Context, inds []intel.Indicator) error {
	if f.down.Load() {
		return errors.New("opensearch down")
	}
	return f.Memory.Put(ctx, inds)
}

func (f *flakyIntel) Delete(ctx context.Context, ids []string) error {
	if f.down.Load() {
		return errors.New("opensearch down")
	}
	return f.Memory.Delete(ctx, ids)
}

func newIntelServer(t *testing.T, withFeeds bool) (*httptest.Server, *flakyIntel, *intel.Store) {
	t.Helper()
	be := &flakyIntel{Memory: intel.NewMemory()}
	st := intel.NewStore(be)
	if err := st.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Intel = st
		s.Engine.Intel = st
		if withFeeds {
			s.Feeds = &intel.Feeds{Store: st, Log: s.Log, File: filepath.Join(t.TempDir(), "intel_feeds.yaml"), List: []intel.Feed{
				{Name: "partner", URL: "https://feeds.example.com/list.txt", Format: "lines", Type: "auto",
					Interval: time.Hour, MaxAge: 24 * time.Hour, Weight: 1, Enabled: true},
			}}
		}
	})
	return ts, be, st
}

// Every intel route that takes a body refuses one that is not JSON, and
// a feed test names a saved feed that exists.
func TestIntelRefusesBadBodies(t *testing.T) {
	ts, _, st := newIntelServer(t, true)
	for _, c := range []struct {
		method, path, body string
		status             int
		want               string
	}{
		{"POST", "/api/intel/indicators", `{`, 400, "must be JSON"},
		{"POST", "/api/intel/feeds", `{`, 400, "must be JSON"},
		{"PUT", "/api/intel/feeds/partner", `{`, 400, "must be JSON"},
		{"POST", "/api/intel/catalog", `{`, 400, "must be JSON"},
		{"POST", "/api/intel/catalog", `{"ids":[]}`, 400, "ids lists"},
		{"POST", "/api/intel/feeds/test", `{`, 400, "must be JSON"},
		{"POST", "/api/intel/feeds/test", `{"feed":"partner","weight":"heavy"}`, 400, "must be JSON"},
		{"POST", "/api/intel/feeds/test", `{"feed":"nope"}`, 404, ""},
		{"POST", "/api/intel/taxii/collections", `{`, 400, "must be JSON"},
		{"POST", "/api/intel/taxii/collections", `{"feed":"nope"}`, 404, ""},
		{"POST", "/api/intel/upload", "# only a comment\n\n", 400, "no indicators"},
	} {
		code, out := do(t, ts, c.method, c.path, c.body, true)
		if msg, _ := out["error"].(string); code != c.status || !strings.Contains(msg, c.want) {
			t.Errorf("%s %s %.30q: %d %v", c.method, c.path, c.body, code, out)
		}
	}
	if _, n := st.List(intel.Filter{}); n != 0 {
		t.Errorf("%d indicators after refused requests", n)
	}
}

// When OpenSearch refuses the write, adding, uploading and deleting
// indicators answer 502 and the indicator list is as it was.
func TestIntelWritesFailCleanly(t *testing.T) {
	ts, be, st := newIntelServer(t, false)
	code, out := do(t, ts, "POST", "/api/intel/indicators", `{"value":"203.0.113.5","comment":"seen in phishing"}`, true)
	if code != 200 {
		t.Fatalf("add: %d %v", code, out)
	}
	id, _ := out["id"].(string)
	be.down.Store(true)
	if code, out := do(t, ts, "POST", "/api/intel/indicators", `{"value":"203.0.113.6"}`, true); code != http.StatusBadGateway {
		t.Errorf("add while down: %d %v", code, out)
	}
	if code, out := do(t, ts, "POST", "/api/intel/upload", "203.0.113.7\nevil.example.com\n", true); code != http.StatusBadGateway {
		t.Errorf("upload while down: %d %v", code, out)
	}
	if code, out := do(t, ts, "DELETE", "/api/intel/indicators/"+id, "", true); code != http.StatusBadGateway {
		t.Errorf("delete while down: %d %v", code, out)
	}
	if got, _ := st.List(intel.Filter{}); len(got) != 1 || got[0].ID != id {
		t.Errorf("indicators %v", got)
	}
	// Without feeds there is no feed to refresh.
	if code, _ := do(t, ts, "POST", "/api/intel/feeds/partner/refresh", "", true); code != http.StatusNotFound {
		t.Errorf("refresh without feeds: %d", code)
	}
	// Lookups of nothing known answer an empty list, not null.
	be.down.Store(false)
	code, out = do(t, ts, "GET", "/api/intel/lookup?value=198.51.100.200", "", true)
	if code != 200 {
		t.Fatalf("lookup: %d %v", code, out)
	}
	if m, ok := out["matches"].([]any); !ok || len(m) != 0 {
		t.Errorf("lookup %v", out)
	}
}
