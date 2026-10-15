//go:build integration && linux

package integration

// Detections and dashboards shared by the servers of a cluster
// (multi-server design, PR 7), with real `signalith serve` processes: a
// detection, dashboard or asset list saved on one server is used by the
// other; two
// edits of one detection from pages that read the same version give one
// 412 naming who changed it; a file dropped into one server's folder is
// shared, and every server's folder gets the shared copy.
//
// The unit tests in internal/clusterlib cover the rest against the
// in-memory fake.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// libraryShared reports whether the server's detections and dashboards
// come from the shared settings.
func (s *testServer) libraryShared() bool {
	var d, b struct {
		Shared bool `json:"shared"`
	}
	return s.call(http.MethodGet, "/api/detections", nil, &d) == http.StatusOK && d.Shared &&
		s.call(http.MethodGet, "/api/dashboards", nil, &b) == http.StatusOK && b.Shared
}

type detectionETag struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	ETag  string `json:"etag"`
}

func TestClusterLibrarySharedEdits(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := h.startLeader("siem-a", serverOptions{})
	b := h.start("siem-b", serverOptions{})
	waitUntil(t, 120*time.Second, "both servers share the detections and dashboards", func() bool {
		return a.libraryShared() && b.libraryShared()
	})

	rule := map[string]any{"id": "shared-rule", "title": "Made on B", "query": "event.action=failure", "schedule": "5m",
		"lookback": "5m", "severity": "low", "enabled": true}
	if code, _, body := b.request(http.MethodPost, "/api/detections", rule, nil); code != http.StatusCreated {
		t.Fatalf("creating a detection on siem-b: %d %s", code, body)
	}
	var onA detectionETag
	waitUntil(t, 30*time.Second, "siem-a has the detection made on siem-b", func() bool {
		return a.call(http.MethodGet, "/api/detections/shared-rule", nil, &onA) == http.StatusOK
	})
	// Both pages read the same version; the second save is refused,
	// naming who changed it and where.
	rule["title"] = "Edited on A"
	if code, _, body := a.request(http.MethodPut, "/api/detections/shared-rule", rule, map[string]string{"If-Match": onA.ETag}); code != http.StatusOK {
		t.Fatalf("editing on siem-a: %d %s", code, body)
	}
	rule["title"] = "Edited on B"
	code, _, body := b.request(http.MethodPut, "/api/detections/shared-rule", rule, map[string]string{"If-Match": onA.ETag})
	var stale struct {
		Code      string `json:"code"`
		ChangedBy string `json:"changed_by"`
		ChangedOn string `json:"changed_on"`
	}
	_ = json.Unmarshal(body, &stale)
	if code != http.StatusPreconditionFailed || stale.Code != "stale" || stale.ChangedOn != "siem-a" || stale.ChangedBy == "" {
		t.Fatalf("the second edit: %d %s", code, body)
	}

	// A dashboard saved on A is listed on B.
	board := map[string]any{"id": "shared-board", "title": "Shared board", "panels": []map[string]any{{"title": "Events", "query": "* | stats count"}}}
	if code, _, body := a.request(http.MethodPost, "/api/dashboards", board, nil); code != http.StatusCreated {
		t.Fatalf("creating a dashboard on siem-a: %d %s", code, body)
	}
	waitUntil(t, 30*time.Second, "siem-b lists the dashboard saved on siem-a", func() bool {
		return b.call(http.MethodGet, "/api/dashboards/shared-board", nil, nil) == http.StatusOK
	})

	// Every server's folders get the shared copies.
	waitUntil(t, 60*time.Second, "siem-b's folders hold the shared detection and dashboard", func() bool {
		d, err1 := os.ReadFile(filepath.Join(b.dir, "detections", "shared-rule.yaml"))
		_, err2 := os.Stat(filepath.Join(b.dir, "dashboards", "shared-board.yaml"))
		return err1 == nil && strings.Contains(string(d), "Edited on A") && err2 == nil
	})

	// A file dropped into B's folder (a git pull) is shared.
	file := "id: from-git\ntitle: From git\nquery: event.action=failure\nschedule: 5m\nlookback: 5m\nseverity: low\nenabled: false\n"
	if err := os.WriteFile(filepath.Join(b.dir, "detections", "from-git.yaml"), []byte(file), 0o666); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 60*time.Second, "siem-a has the detection from siem-b's folder", func() bool {
		var d detectionETag
		return a.call(http.MethodGet, "/api/detections/from-git", nil, &d) == http.StatusOK && d.Title == "From git"
	})
}

// lookupList is the answer of GET /api/lookups/{kind}.
type lookupList struct {
	Shared bool   `json:"shared"`
	ETag   string `json:"etag"`
	Count  int    `json:"count"`
	Items  []struct {
		Host []string `json:"host"`
	} `json:"items"`
}

// putList uploads csv as the list kind.
func (s *testServer) putList(kind, csv, etag string) (int, []byte) {
	req, _ := http.NewRequest(http.MethodPut, fmt.Sprintf("https://127.0.0.1:%d/api/lookups/%s", s.port, kind), strings.NewReader(csv))
	req.SetBasicAuth("admin", clusterPassword)
	req.Header.Set("Content-Type", "text/csv")
	if etag != "" {
		req.Header.Set("If-Match", `"`+etag+`"`)
	}
	resp, err := s.api.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestClusterLibrarySharedLists(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := h.startLeader("siem-a", serverOptions{})
	b := h.start("siem-b", serverOptions{})
	var la, lb lookupList
	waitUntil(t, 120*time.Second, "both servers share the asset list", func() bool {
		return a.call(http.MethodGet, "/api/lookups/assets", nil, &la) == http.StatusOK && la.Shared &&
			b.call(http.MethodGet, "/api/lookups/assets", nil, &lb) == http.StatusOK && lb.Shared
	})

	// An asset list uploaded on B is used on A, and A's folder gets it.
	if code, body := b.putList("assets", "host,priority\nweb1,high\ndb1,critical\n", lb.ETag); code != http.StatusOK {
		t.Fatalf("uploading on siem-b: %d %s", code, body)
	}
	waitUntil(t, 60*time.Second, "siem-a uses the list uploaded on siem-b", func() bool {
		var l lookupList
		return a.call(http.MethodGet, "/api/lookups/assets", nil, &l) == http.StatusOK && l.Count == 2
	})
	waitUntil(t, 60*time.Second, "siem-a's lookups folder holds the shared list", func() bool {
		d, err := os.ReadFile(filepath.Join(a.dir, "lookups", "assets.csv"))
		return err == nil && strings.Contains(string(d), "db1")
	})
	// A page that read the list before B's upload is told it changed.
	code, body := a.putList("assets", "host\nother\n", la.ETag)
	if code != http.StatusPreconditionFailed || !strings.Contains(string(body), "siem-b") {
		t.Fatalf("an upload over a changed list: %d %s", code, body)
	}

	// A new export copied into A's folder is shared.
	if err := os.WriteFile(filepath.Join(a.dir, "lookups", "assets.csv"), []byte("host\nweb1\ndb1\nmail1\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 60*time.Second, "siem-b uses the list from siem-a's folder", func() bool {
		var l lookupList
		return b.call(http.MethodGet, "/api/lookups/assets", nil, &l) == http.StatusOK && l.Count == 3
	})
}
