package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// saveWhileMoving starts a server that cannot reach OpenSearch, so it
// keeps everything in its own files, then lets it found the cluster. As
// the importer named moves its files into the shared settings, and
// still holds them, a page sends save. A save made then would go to a
// file that is no longer read once the server switches to the shared
// settings: it must either be refused, saying to try again (and the
// test then sends it again), or reach the shared settings. kept reports
// whether the change is there once the server switched.
func saveWhileMoving(t *testing.T, importer, extra string, save func(*running) (int, map[string]any, error), kept func(*running) bool) {
	t.Setenv(clusterKeyFileEnv, "")
	type result struct {
		code int
		out  map[string]any
		err  error
	}
	saved := make(chan result, 1)
	var once sync.Once
	var cur atomic.Pointer[running]
	importHoldHook = func(name string) {
		rs := cur.Load()
		if rs == nil || name != importer {
			return
		}
		once.Do(func() {
			// Sent while the importer holds the files it read, to the
			// start that still keeps them there.
			go func() {
				code, out, err := save(rs)
				saved <- result{code, out, err}
			}()
			// Without the hold the save lands in the file now, after
			// the import read it; with it, it waits for this to return.
			time.Sleep(300 * time.Millisecond)
		})
	}
	t.Cleanup(func() { importHoldHook = nil })
	fos := ostest.New(t)
	down := ostest.Fault{Status: 503, Type: "unavailable_shards_exception"}
	fos.SetFault(func(string, string) *ostest.Fault { return &down })
	rs := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, name: "siem-a", extra: extra})
	if m, _ := rs.r.shared.Mode(); m != shared.ModeLegacyA {
		t.Fatalf("mode %s", m)
	}
	rs.signIn()
	cur.Store(rs)
	fos.SetFault(nil)
	var res result
	select {
	case res = <-saved:
	case <-time.After(30 * time.Second):
		t.Fatalf("no save was made while the %s moved\n%s", importer, rs.logs.String())
	}
	rs.usersShared()
	eventually(t, "the content is shared", rs.r.sharedContent.on.Load)
	switch {
	case res.err != nil:
		t.Fatal(res.err)
	case res.code == http.StatusServiceUnavailable:
		// Refused, saying why: sent again, it reaches the shared settings.
		if msg, _ := res.out["error"].(string); !strings.Contains(msg, "moving its") || !strings.Contains(msg, "try again in a moment") {
			t.Fatalf("refused with %v", res.out)
		}
		if kept(rs) {
			t.Fatal("a refused save was kept")
		}
		if code, out, err := save(rs); err != nil || code != http.StatusOK && code != http.StatusCreated {
			t.Fatalf("sent again: %d %v %v", code, out, err)
		}
		if !kept(rs) {
			t.Fatal("the save sent again was not kept")
		}
	case res.code == http.StatusOK || res.code == http.StatusCreated:
		if !kept(rs) {
			t.Errorf("the save made while the %s moved was lost\n%s", importer, rs.logs.String())
		}
	default:
		t.Fatalf("save while the %s moved: %d %v", importer, res.code, res.out)
	}
}

// A feed added while the founder moves its feed list into the shared
// settings is not lost.
func TestFeedSaveWhileFeedsMove(t *testing.T) {
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("203.0.113.9\n"))
	}))
	defer feed.Close()
	saveWhileMoving(t, clustercfg.ImportFeeds, "intel:\n  allow_loopback_feeds: true\n",
		func(rs *running) (int, map[string]any, error) {
			return rs.call("", "POST", "/api/intel/feeds", `{"name":"blocklist","url":"`+feed.URL+`","format":"lines","type":"ip","interval":"24h"}`)
		},
		func(rs *running) bool {
			_, out, _ := rs.call("", "GET", "/api/intel/feeds", "")
			return strings.Contains(fmt.Sprint(out["feeds"]), "blocklist")
		})
}

// A retention policy saved while the founder moves its policies into the
// shared settings is not lost.
func TestRetentionSaveWhilePoliciesMove(t *testing.T) {
	saveWhileMoving(t, clustercfg.ImportRetention, "",
		func(rs *running) (int, map[string]any, error) {
			return rs.call("", "PUT", "/api/retention/default", `{"keep_days":3}`)
		},
		func(rs *running) bool {
			_, out, _ := rs.call("", "GET", "/api/retention", "")
			def, _ := out["default"].(map[string]any)
			pol, _ := def["policy"].(map[string]any)
			return pol["keep_days"] == float64(3)
		})
}

// A user added while the founder moves its users into the shared
// settings is not lost.
func TestUserSaveWhileUsersMove(t *testing.T) {
	saveWhileMoving(t, shared.ImportUsers, "",
		func(rs *running) (int, map[string]any, error) {
			return rs.call("", "POST", "/api/users", `{"username":"carol","password":"carol-password-1","role":"analyst","must_change_password":false}`)
		},
		func(rs *running) bool {
			_, out, _ := rs.call("", "GET", "/api/users", "")
			return strings.Contains(fmt.Sprint(out["users"]), "carol")
		})
}
