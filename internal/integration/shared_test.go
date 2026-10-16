//go:build integration && linux

package integration

// The shared settings of servers that share one OpenSearch (multi-server
// design, PR 4), with real `signalith serve` processes where it matters:
// the MAC of a shared document survives OpenSearch re-serializing it, and
// a document forged in OpenSearch is refused; a server that may not run
// the background jobs, upgraded first, does not found the cluster, and the
// one that may founds it with its own retention policies, held until
// confirmed because the other's differed; a feed added on one server is
// downloaded once, by the one that runs the jobs, and a retention change
// made on one server is read on the other at once; deleting the config
// index does not split the cluster, and a member's cache brings it back;
// a server started while OpenSearch is down serves from its files and
// founds the cluster once OpenSearch is back.
//
// What stays manual: a page open on one version reloads once when it
// reaches a server of another (docs/servers.md, "Several servers behind
// one address"), and a server killed in the middle of its import resumes
// it (the importers are keyed by their source's hash; see the clustercfg
// unit tests).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/shared"
)

// request makes an API request as the built-in admin over HTTPS, with
// headers hdr, and returns the status (0 when there was no answer), the
// response headers and the body.
func (s *testServer) request(method, path string, body any, hdr map[string]string) (int, http.Header, []byte) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, fmt.Sprintf("https://127.0.0.1:%d%s", s.port, path), rd)
	req.SetBasicAuth("admin", clusterPassword)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if s.api == nil {
		return 0, nil, nil
	}
	resp, err := s.api.Do(req)
	if err != nil {
		return 0, nil, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

// call is request with a JSON answer decoded into out.
func (s *testServer) call(method, path string, body, out any) int {
	code, _, b := s.request(method, path, body, nil)
	if out != nil && len(b) > 0 {
		_ = json.Unmarshal(b, out)
	}
	return code
}

// mode is how the server uses the shared settings, as it lists itself.
func (s *testServer) mode() string {
	v, ok := s.view()
	if !ok {
		return ""
	}
	for _, sv := range v.Servers {
		if sv.Self && sv.Shared != nil {
			return sv.Shared.Mode
		}
	}
	return ""
}

// cli runs `signalith <args> -c <its config>` as the server's command
// line, with stdin.
func (s *testServer) cli(stdin string, args ...string) (string, error) {
	cmd := exec.Command(signalithBinary(s.h.t), append(args, "-c", filepath.Join(s.dir, "signalith.yaml"))...)
	cmd.Env = s.env()
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// clusterID reads the cluster's id as the server's command line sees it.
func (s *testServer) clusterID() string {
	out, err := s.cli("", "cluster", "status", "-json")
	if err != nil {
		return ""
	}
	var st struct {
		Shared struct {
			ClusterID string `json:"cluster_id"`
		} `json:"shared"`
	}
	if i := strings.Index(out, "{"); i >= 0 {
		_ = json.Unmarshal([]byte(out[i:]), &st)
	}
	return st.Shared.ClusterID
}

type retentionView struct {
	Default struct {
		Policy struct {
			KeepDays int `json:"keep_days"`
		} `json:"policy"`
	} `json:"default"`
	Hold *struct {
		Reason string `json:"reason"`
	} `json:"hold"`
	Shared bool   `json:"shared"`
	ETag   string `json:"etag"`
}

type macBody struct {
	Name  string   `json:"name"`
	Notes []string `json:"notes"`
	Count int      `json:"count"`
	shared.Extra
}

// The MAC of a shared document survives OpenSearch re-serializing its
// source (an _update), with <>&, quotes and text outside ASCII; a body
// changed in OpenSearch with the MAC kept is refused, and the last good
// copy stays in use.
func TestClusterSharedSettingsMACSurvivesOpenSearch(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	t.Cleanup(func() {
		if os.Getenv("SIGNALITH_TEST_OPENSEARCH") != "" {
			_ = h.os.DeleteIndex(context.Background(), shared.ConfigIndex(h.prefix))
		}
	})
	ctx := context.Background()
	if err := shared.EnsureConfig(ctx, h.os, h.prefix); err != nil {
		t.Fatal(err)
	}
	key, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	hub := func(name string) *shared.Hub {
		hb := shared.NewHub(shared.Options{NodeName: name})
		hb.SetKeys(shared.NewKeySet(key))
		hb.Use(h.os, h.prefix)
		return hb
	}
	a, b := hub("siem-a"), hub("siem-b")
	da := shared.NewDoc[macBody](a, "settings", "settings", 1)
	db := shared.NewDoc[macBody](b, "settings", "settings", 1)
	name := `<script>alert("x")</script> & Zoë – 東京 ü`
	if _, err := da.Mutate(ctx, "sam", func(v *macBody) error {
		v.Name, v.Notes, v.Count = name, []string{"a\tb", "\u2028line", `back\slash`}, 12345678901
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	index := "/" + url.PathEscape(shared.ConfigIndex(h.prefix))
	// OpenSearch reads the source and writes it again, with a field added.
	if err := h.os.Do(ctx, http.MethodPost, index+"/_update/settings?refresh=true", map[string]any{"doc": map[string]any{"added_by_update": true}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := b.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	got, ok := db.Get()
	if !ok || got.Name != name || len(got.Notes) != 3 || got.Count != 12345678901 {
		t.Fatalf("after _update siem-b reads %+v %v", got, ok)
	}
	if tm := b.Tamper(); len(tm) != 0 {
		t.Fatalf("refused after _update: %v %+v", tm, b.Problems())
	}
	// A body changed in OpenSearch, MAC kept.
	src, _, found, err := h.os.Get(ctx, shared.ConfigIndex(h.prefix), "settings")
	if err != nil || !found {
		t.Fatal(found, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(src, &doc); err != nil {
		t.Fatal(err)
	}
	doc["body"] = strings.Replace(doc["body"].(string), "Zoë", "Mallory", 1)
	if err := h.os.Do(ctx, http.MethodPut, index+"/_doc/settings?refresh=true", doc, nil); err != nil {
		t.Fatal(err)
	}
	if err := b.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	if tm := b.Tamper(); len(tm) != 1 || tm[0] != "settings" {
		t.Errorf("forged document: tamper %v", tm)
	}
	if got, _ := db.Get(); got == nil || got.Name != name {
		t.Errorf("the last good copy is not kept: %+v", got)
	}
}

// A pair whose server that may not run the jobs is upgraded first: it
// does not found the cluster. The server that may founds it with its own
// retention policies, which wait to be confirmed since the other's
// differed; an admin confirms them on either server.
func TestClusterNonSchedulerUpgradedFirst(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	b := h.start("siem-b", serverOptions{noJobs: true, retention: "default:\n  keep_days: 60\n"})
	// Long enough for a founder to have founded.
	time.Sleep(15 * time.Second)
	if m := b.mode(); m != "legacy_c" {
		t.Fatalf("siem-b alone is %q, want legacy_c", m)
	}
	if _, _, found, _ := h.os.Get(context.Background(), shared.ConfigIndex(h.prefix), "cluster"); found {
		t.Fatal("siem-b, which may not run the jobs, founded the cluster")
	}
	a := h.startLeader("siem-a", serverOptions{retention: "default:\n  keep_days: 30\n"})
	waitUntil(t, 60*time.Second, "both servers are members", func() bool { return a.mode() == "member" && b.mode() == "member" })
	var ov retentionView
	waitUntil(t, 30*time.Second, "siem-a holds the shared policies", func() bool {
		return a.call(http.MethodGet, "/api/retention", nil, &ov) == http.StatusOK && ov.Hold != nil
	})
	if ov.Default.Policy.KeepDays != 30 || !ov.Shared {
		t.Errorf("the founder's policies: keep_days %d, shared %v", ov.Default.Policy.KeepDays, ov.Shared)
	}
	if !strings.Contains(ov.Hold.Reason, "siem-b") {
		t.Errorf("the hold does not name siem-b: %q", ov.Hold.Reason)
	}
	// Confirmed on siem-b, the server that does not run retention.
	code, hdr, body := b.request(http.MethodPost, "/api/retention/policies/confirm", map[string]any{}, nil)
	if code != http.StatusOK {
		t.Fatalf("confirm on siem-b: %d %s", code, body)
	}
	tok := hdr.Get("X-Signalith-Config")
	code, hdr, body = a.request(http.MethodGet, "/api/retention", nil, map[string]string{"X-Signalith-Config-Min": tok})
	ov = retentionView{}
	_ = json.Unmarshal(body, &ov)
	if code != http.StatusOK || ov.Hold != nil || hdr.Get("X-Signalith-Stale") != "" {
		t.Errorf("siem-a after the confirmation on siem-b (token %q): %d, hold %+v, stale %q", tok, code, ov.Hold, hdr.Get("X-Signalith-Stale"))
	}
	if code := b.call(http.MethodPost, "/api/retention/policies/confirm", map[string]any{}, nil); code != http.StatusConflict {
		t.Errorf("a second confirmation: %d, want 409", code)
	}
}

// A feed added on siem-b is downloaded once, by siem-a, which runs the
// jobs; siem-b shows its status. A retention change on siem-b is what
// siem-a reads on the next request, and enforces.
func TestClusterSharedEditsOnAnyServer(t *testing.T) {
	t.Parallel()
	var downloads atomic.Int32
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		fmt.Fprint(w, "# test feed\n8.8.8.8\n1.1.1.1\n")
	}))
	t.Cleanup(feed.Close)
	h := newClusterHarness(t)
	loopback := "intel:\n  allow_loopback_feeds: true\n"
	a := h.startLeader("siem-a", serverOptions{yaml: loopback})
	b := h.start("siem-b", serverOptions{yaml: loopback})
	waitStandby(t, a, b)
	waitUntil(t, 60*time.Second, "both servers are members", func() bool { return a.mode() == "member" && b.mode() == "member" })

	code, hdr, body := b.request(http.MethodPost, "/api/intel/feeds",
		map[string]any{"name": "test-feed", "url": feed.URL + "/ips.txt", "format": "lines", "type": "ip", "interval": "24h"}, nil)
	if code != http.StatusOK {
		t.Fatalf("adding a feed on siem-b: %d %s", code, body)
	}
	if hdr.Get("X-Signalith-Version") == "" || hdr.Get("X-Signalith-Config") == "" {
		t.Errorf("headers %v", hdr)
	}
	waitUntil(t, 60*time.Second, "siem-a downloads the feed", func() bool { return downloads.Load() >= 1 })
	type feedsView struct {
		Feeds []struct {
			Name   string `json:"name"`
			Status struct {
				Count int `json:"count"`
			} `json:"status"`
		} `json:"feeds"`
	}
	waitUntil(t, 30*time.Second, "siem-b shows the feed's status", func() bool {
		var v feedsView
		if b.call(http.MethodGet, "/api/intel/feeds", nil, &v) != http.StatusOK {
			return false
		}
		for _, f := range v.Feeds {
			if f.Name == "test-feed" && f.Status.Count == 2 {
				return true
			}
		}
		return false
	})
	time.Sleep(5 * time.Second)
	if n := downloads.Load(); n != 1 {
		t.Errorf("the feed was downloaded %d times, want once", n)
	}

	var before retentionView
	b.call(http.MethodGet, "/api/retention", nil, &before)
	code, hdr, body = b.request(http.MethodPut, "/api/retention/default", map[string]any{"keep_days": 45}, map[string]string{"If-Match": before.ETag})
	if code != http.StatusOK {
		t.Fatalf("a retention change on siem-b: %d %s", code, body)
	}
	var ov retentionView
	code, ahdr, abody := a.request(http.MethodGet, "/api/retention", nil, map[string]string{"X-Signalith-Config-Min": hdr.Get("X-Signalith-Config")})
	_ = json.Unmarshal(abody, &ov)
	if code != http.StatusOK || ov.Default.Policy.KeepDays != 45 || ahdr.Get("X-Signalith-Stale") != "" {
		t.Errorf("siem-a after the change on siem-b: %d keep_days %d stale %q", code, ov.Default.Policy.KeepDays, ahdr.Get("X-Signalith-Stale"))
	}
	// The same page's version again is refused: the policies changed.
	if code, _, _ := b.request(http.MethodPut, "/api/retention/default", map[string]any{"keep_days": 50}, map[string]string{"If-Match": before.ETag}); code != http.StatusPreconditionFailed {
		t.Errorf("a stale If-Match: %d, want 412", code)
	}
}

// Deleting the config index does not split the cluster: the members find
// their shared settings gone and found nothing, and a member's cache
// brings them back, the same cluster.
func TestClusterConfigIndexDeletedAndRestored(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := h.startLeader("siem-a", serverOptions{})
	b := h.start("siem-b", serverOptions{})
	waitUntil(t, 60*time.Second, "both servers are members", func() bool { return a.mode() == "member" && b.mode() == "member" })
	id := b.clusterID()
	if id == "" {
		t.Fatal("no cluster id")
	}
	waitUntil(t, 60*time.Second, "siem-b keeps a cache of the shared settings", func() bool {
		_, err := os.Stat(filepath.Join(b.dir, "cluster", "cache.enc"))
		return err == nil
	})
	if err := h.os.DeleteIndex(context.Background(), shared.ConfigIndex(h.prefix)); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 60*time.Second, "both servers find the shared settings gone", func() bool { return a.mode() == "gone" && b.mode() == "gone" })
	if a.readyz() != http.StatusServiceUnavailable {
		t.Error("/readyz is not 503 while the shared settings are gone")
	}
	if out, err := b.cli("", "cluster", "import", "-from-cache"); err != nil {
		t.Fatalf("import -from-cache: %v\n%s", err, out)
	}
	waitUntil(t, 60*time.Second, "both servers are members again", func() bool { return a.mode() == "member" && b.mode() == "member" })
	if got := a.clusterID(); got != id {
		t.Errorf("cluster %q after the restore, want %q", got, id)
	}
}

// A server started while OpenSearch cannot be reached, with no copy of
// the shared settings, serves from its own files (legacy mode a); once
// OpenSearch is back, it founds the cluster by itself.
func TestClusterStartWithOpenSearchDown(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	p := newSwitchProxy(t, h.url)
	a := h.add("siem-a", serverOptions{opensearch: p.url})
	a.startNoWait()
	waitUntil(t, 60*time.Second, "siem-a answers its API", func() bool {
		a.api = a.httpsClientOrNil()
		return a.api != nil && a.mode() == "legacy_a"
	})
	if _, _, found, _ := h.os.Get(context.Background(), shared.ConfigIndex(h.prefix), "cluster"); found {
		t.Fatal("a cluster exists while OpenSearch could not be reached")
	}
	p.up.Store(true)
	waitUntil(t, 90*time.Second, "siem-a founds the cluster once OpenSearch is back", func() bool { return a.mode() == "member" })
}

// startNoWait runs the server without waiting for /readyz.
func (s *testServer) startNoWait() {
	t := s.h.t
	t.Helper()
	logf, err := os.OpenFile(s.logPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(signalithBinary(t), "serve", "-c", filepath.Join(s.dir, "signalith.yaml"))
	cmd.Env = s.env()
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		logf.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		logf.Close()
		close(done)
	}()
	s.cmd, s.done = cmd, done
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-done
		if t.Failed() {
			t.Logf("log of %s:\n%s", s.name, s.logTail(60))
		}
	})
}

// httpsClientOrNil is httpsClient once the server made its certificate
// authority, nil before.
func (s *testServer) httpsClientOrNil() *http.Client {
	if _, err := os.Stat(filepath.Join(s.dir, "tls", "ca.pem")); err != nil {
		return nil
	}
	return s.httpsClient()
}

// switchProxy passes TCP connections to OpenSearch while up is set, and
// closes them at once otherwise, as an OpenSearch that is down.
type switchProxy struct {
	url string
	up  atomic.Bool
}

func newSwitchProxy(t *testing.T, target string) *switchProxy {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &switchProxy{}
	// The same host name as the target, so its certificate still fits.
	pu := *u
	pu.Host = net.JoinHostPort(u.Hostname(), fmt.Sprint(l.Addr().(*net.TCPAddr).Port))
	p.url = pu.String()
	var wg sync.WaitGroup
	t.Cleanup(func() {
		l.Close()
		wg.Wait()
	})
	dst := u.Host
	if u.Port() == "" {
		dst = net.JoinHostPort(u.Hostname(), map[string]string{"https": "443", "http": "80"}[u.Scheme])
	}
	wg.Go(func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			if !p.up.Load() {
				c.Close()
				continue
			}
			wg.Go(func() {
				defer c.Close()
				o, err := net.Dial("tcp", dst)
				if err != nil {
					return
				}
				defer o.Close()
				go func() { _, _ = io.Copy(o, c); o.(*net.TCPConn).CloseWrite() }()
				_, _ = io.Copy(c, o)
			})
		}
	})
	return p
}
