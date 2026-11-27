// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/reportkeys"
)

// flakyKeys is a report key list that fails while down is set.
type flakyKeys struct {
	reportkeys.Memory
	down atomic.Bool
}

func (k *flakyKeys) List(ctx context.Context) ([]reportkeys.Key, error) {
	if k.down.Load() {
		return nil, errors.New("keys down")
	}
	return k.Memory.List(ctx)
}

func (k *flakyKeys) Revoke(ctx context.Context, id, by, reason string, now time.Time) error {
	if k.down.Load() {
		return errors.New("keys down")
	}
	return k.Memory.Revoke(ctx, id, by, reason, now)
}

// goneFindings answers not found for one finding, as when it was deleted
// after it was linked to a case.
type goneFindings struct {
	findings.Store
	gone string
	on   *atomic.Bool
}

func (g goneFindings) Get(ctx context.Context, id string) (*findings.Finding, error) {
	if id == g.gone && g.on.Load() {
		return nil, findings.ErrNotFound
	}
	return g.Store.Get(ctx, id)
}

func reportJSON(t *testing.T, raw string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("report is not JSON: %.200s", raw)
	}
	return out
}

// A report is signed only with a key in the list that is not revoked;
// otherwise it is exported unsigned, with the reason. Findings deleted
// since they were linked are named as missing.
func TestCaseReportKeysAndMissingFindings(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	keys := &flakyKeys{}
	var signer atomic.Value
	var gone atomic.Bool
	signer.Store(priv)
	ts, _ := newTestServerWith(t, func(s *Server) {
		now := time.Now()
		for _, id := range []string{"f-kept", "f-gone"} {
			if err := s.Findings.Create(context.Background(), &findings.Finding{ID: id, Title: "Brute force", Severity: "high", Status: findings.StatusNew, Created: now, Updated: now}); err != nil {
				t.Fatal(err)
			}
		}
		s.Findings = goneFindings{Store: s.Findings, gone: "f-gone", on: &gone}
		s.ReportSigner = func() (ed25519.PrivateKey, string, error) {
			k, _ := signer.Load().(ed25519.PrivateKey)
			return k, reportkeys.FromMaster, nil
		}
		s.ReportKeys = keys
	})
	_, out := do(t, ts, "POST", "/api/cases", `{"title":"Report","findings":["f-kept"]}`, true)
	id := out["case"].(map[string]any)["id"].(string)
	if code, out := do(t, ts, "POST", "/api/cases/"+id+"/findings", `{"ids":["f-gone"]}`, true); code != http.StatusOK {
		t.Fatalf("link: %d %v", code, out)
	}
	gone.Store(true)
	report := func() map[string]any {
		t.Helper()
		code, _, raw := call(t, ts, "GET", "/api/cases/"+id+"/report?format=json", "", "admin", adminPass, nil)
		if code != http.StatusOK {
			t.Fatalf("report: %d %s", code, raw)
		}
		return reportJSON(t, raw)
	}
	if code, _ := do(t, ts, "GET", "/api/cases/"+id+"/report?format=pdf", "", true); code != http.StatusBadRequest {
		t.Errorf("format=pdf: %d", code)
	}
	rep := report()
	payload, _ := base64.StdEncoding.DecodeString(rep["payload"].(string))
	if !strings.Contains(string(payload), "f-gone") || rep["key_id"] == nil || rep["key_id"] == "" {
		t.Errorf("signed report with a missing finding: %v %s", rep["key_id"], payload)
	}
	keyID, _ := rep["key_id"].(string)

	// The list cannot be read: the report goes out unsigned, and the
	// keys page says it could not read them.
	keys.down.Store(true)
	if rep := report(); rep["key_id"] != nil && rep["key_id"] != "" {
		t.Errorf("signed while the key list is down: %v", rep["key_id"])
	}
	if code, _ := do(t, ts, "GET", "/api/cases/reports/keys", "", true); code != http.StatusBadGateway {
		t.Errorf("keys while down: %d", code)
	}
	if code, _ := do(t, ts, "POST", "/api/cases/reports/keys/"+keyID+"/revoke", `{"reason":"leaked"}`, true); code != http.StatusBadGateway {
		t.Errorf("revoke while down: %d", code)
	}
	keys.down.Store(false)

	// A revoked key never signs again.
	if code, out := do(t, ts, "POST", "/api/cases/reports/keys/"+keyID+"/revoke", `{"reason":"the master key leaked"}`, true); code != http.StatusOK {
		t.Fatalf("revoke: %d %v", code, out)
	}
	if rep := report(); rep["key_id"] != nil && rep["key_id"] != "" {
		t.Errorf("signed with a revoked key: %v", rep["key_id"])
	}
	// Nor does a signer that has no key.
	signer.Store(ed25519.PrivateKey(nil))
	if rep := report(); rep["key_id"] != nil && rep["key_id"] != "" {
		t.Errorf("signed without a key: %v", rep["key_id"])
	}
	// Revoking a key the list never had is 404.
	if code, _ := do(t, ts, "POST", "/api/cases/reports/keys/0123456789ab/revoke", `{"reason":"x"}`, true); code != http.StatusNotFound {
		t.Errorf("unknown key: %d", code)
	}
}
