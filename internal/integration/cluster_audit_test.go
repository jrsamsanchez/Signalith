//go:build integration && linux

package integration

// Audit records and archives across servers (multi-server design, PR 8),
// with real `signalith serve` processes: once the cluster keeps audit
// records, a change made on one server is found on the Audit page of the
// other; a day archived by the server that runs retention is listed on
// the other, with the action in the shared retention history; and a
// restore asked on the other server is made by the one that runs
// retention.
//
// The unit tests in internal/audit, internal/clusterarchive,
// internal/retention and internal/api cover the rest against the
// in-memory fake: the spool while OpenSearch is away, claims refused to a
// lower epoch, two servers that never write the same archive, archives
// left unfinished, the importers, and the restore request.

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// auditPage is GET /api/audit as the tests need it.
type auditPage struct {
	Enabled bool `json:"enabled"`
	Events  []struct {
		Server  string `json:"server"`
		User    string `json:"user"`
		Target  string `json:"target"`
		Message string `json:"message"`
	} `json:"events"`
}

func (s *testServer) audit(query string) (v auditPage, ok bool) {
	return v, s.call(http.MethodGet, "/api/audit?"+query, nil, &v) == http.StatusOK
}

func TestClusterAuditAndArchives(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	t.Cleanup(func() {
		_ = h.os.Do(context.Background(), http.MethodDelete, "/_index_template/"+h.prefix+"_audit", nil, nil)
	})
	// One shared archive folder, and a policy that archives the
	// authentication days older than 30 days.
	archive := filepath.Join(h.root, "archive")
	yaml := fmt.Sprintf("retention:\n  archive_dir: %q\n", archive)
	policy := "policies:\n  authentication:\n    keep_days: 30\n    archive: true\n"
	a := h.startLeader("siem-a", serverOptions{yaml: yaml, retention: policy})
	b := h.start("siem-b", serverOptions{yaml: yaml, retention: policy})
	waitSettingsShared(t, a, b)
	waitUntil(t, 120*time.Second, "both servers keep audit records in OpenSearch", func() bool {
		va, oka := a.audit("size=1")
		vb, okb := b.audit("size=1")
		return oka && okb && va.Enabled && vb.Enabled
	})

	// A change on siem-a is on siem-b's Audit page.
	a.addUser("auditee", "analyst", "a-long-password-for-auditee")
	waitUntil(t, 30*time.Second, "siem-b finds siem-a's audit record", func() bool {
		v, _ := b.audit("server=siem-a&size=200")
		return slices.ContainsFunc(v.Events, func(e struct {
			Server  string `json:"server"`
			User    string `json:"user"`
			Target  string `json:"target"`
			Message string `json:"message"`
		}) bool {
			return e.Message == "user created" && e.Target == "auditee" && e.User == "admin"
		})
	})

	if h.fake != nil {
		// The in-memory OpenSearch reports no index sizes or days, which
		// retention plans from, and no prefix queries, which the history
		// reads with.
		t.Log("archives across servers need a real OpenSearch (SIGNALITH_TEST_OPENSEARCH)")
		return
	}

	// An old day, archived by siem-a when siem-b asks for a run.
	day := time.Now().UTC().AddDate(0, 0, -60)
	index := fmt.Sprintf("%s-authentication-%s", h.prefix, day.Format("2006.01.02"))
	if err := h.os.Do(context.Background(), http.MethodPut, "/"+index+"/_doc/1?refresh=true",
		map[string]any{"@timestamp": day.Format(time.RFC3339), "user": "alice", "action": "success"}, nil); err != nil {
		t.Fatal(err)
	}
	if code, _, body := b.request(http.MethodPost, "/api/retention/run", nil, nil); code != http.StatusAccepted {
		t.Fatalf("Run now on siem-b: %d %s", code, body)
	}
	var list struct {
		Archives []struct {
			ID         string `json:"id"`
			Index      string `json:"index"`
			Server     string `json:"server"`
			Searchable bool   `json:"searchable"`
		} `json:"archives"`
	}
	id := ""
	waitUntil(t, 90*time.Second, "siem-b lists the day siem-a archived", func() bool {
		if b.call(http.MethodGet, "/api/retention/archive", nil, &list) != http.StatusOK {
			return false
		}
		for _, x := range list.Archives {
			if x.Index == index && x.Server == "siem-a" && !x.Searchable {
				id = x.ID
				return true
			}
		}
		return false
	})
	var ov struct {
		HistorySource string `json:"history_source"`
		Recent        []struct {
			Action string `json:"action"`
			Index  string `json:"index"`
			Server string `json:"server"`
		} `json:"recent"`
	}
	waitUntil(t, 30*time.Second, "siem-b shows siem-a's archive in the shared history", func() bool {
		if b.call(http.MethodGet, "/api/retention", nil, &ov) != http.StatusOK || ov.HistorySource != "audit" {
			return false
		}
		for _, r := range ov.Recent {
			if r.Action == "archive" && r.Index == index && r.Server == "siem-a" {
				return true
			}
		}
		return false
	})

	// A restore asked on siem-b is made by siem-a.
	code, _, body := b.request(http.MethodPost, "/api/retention/archive/restore",
		map[string]any{"ids": []string{id}, "keep_days": 7, "confirm": true}, nil)
	if code != http.StatusAccepted || !strings.Contains(string(body), "request_id") {
		t.Fatalf("restore on siem-b: %d %s", code, body)
	}
	waitUntil(t, 90*time.Second, "the day is searchable again", func() bool {
		if b.call(http.MethodGet, "/api/retention/archive", nil, &list) != http.StatusOK {
			return false
		}
		for _, x := range list.Archives {
			if x.ID == id && x.Searchable {
				return true
			}
		}
		return false
	})
}
