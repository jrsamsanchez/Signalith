// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/compliancehist"
	"github.com/jrsamsanchez/signalith/internal/reportkeys"
)

func TestComplianceHistory(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	keys := &reportkeys.Memory{}
	hist := compliancehist.NewMemory()
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.ReportSigner = func() (ed25519.PrivateKey, string, error) { return priv, reportkeys.FromMaster, nil }
		s.ReportKeys = keys
		s.ComplianceHistory = hist
		srv = s
	})
	if _, out := do(t, ts, "GET", "/api/compliance/history", "", true); len(out["records"].([]any)) != 0 {
		t.Fatalf("empty: %v", out)
	}

	// The month's record is taken once, however often the job looks.
	now := time.Now()
	srv.complianceMonth(t.Context(), now)
	srv.complianceMonth(t.Context(), now)
	code, out := do(t, ts, "POST", "/api/compliance/history", "", true)
	if code != http.StatusCreated {
		t.Fatalf("take: %d %v", code, out)
	}
	if code, out := do(t, ts, "POST", "/api/compliance/history", "", true); code != http.StatusTooManyRequests {
		t.Errorf("a second one at once: %d %v", code, out)
	}
	_, out = do(t, ts, "GET", "/api/compliance/history", "", true)
	recs := out["records"].([]any)
	if len(recs) != 2 {
		t.Fatalf("records: %v", out)
	}
	for _, r := range recs {
		r := r.(map[string]any)
		if r["check"] != compliancehist.Verified || len(r["frameworks"].([]any)) == 0 {
			t.Errorf("record %v", r)
		}
	}
	if recs[0].(map[string]any)["trigger"] != compliancehist.Manual || recs[0].(map[string]any)["by"] != "admin" {
		t.Errorf("newest first, by whom: %v", recs[0])
	}
	month := compliancehist.MonthID(now)
	code, out = do(t, ts, "GET", "/api/compliance/history/"+month, "", true)
	rec := out["record"].(map[string]any)
	if code != http.StatusOK || rec["check"] != compliancehist.Verified || rec["record"].(map[string]any)["trigger"] != compliancehist.Monthly {
		t.Fatalf("month: %d %v", code, out)
	}
	if code, _ := do(t, ts, "GET", "/api/compliance/history/2001-01", "", true); code != http.StatusNotFound {
		t.Errorf("missing: %d", code)
	}

	// A record changed in OpenSearch shows as changed, with nothing of it.
	hist.Tamper(month, base64.StdEncoding.EncodeToString([]byte(`{"id":"`+month+`"}`)))
	_, out = do(t, ts, "GET", "/api/compliance/history/"+month, "", true)
	if rec := out["record"].(map[string]any); rec["check"] != compliancehist.Changed || rec["record"] != nil {
		t.Errorf("tampered: %v", out)
	}

	// Records signed with a revoked key say so.
	keys.Revoke(t.Context(), reportkeys.KeyID(priv.Public().(ed25519.PublicKey)), "admin", "leaked", time.Now())
	_, out = do(t, ts, "GET", "/api/compliance/history", "", true)
	if r := out["records"].([]any)[0].(map[string]any); r["check"] != compliancehist.Revoked {
		t.Errorf("revoked: %v", r)
	}
}
