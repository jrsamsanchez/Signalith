//go:build integration && linux

package integration

// Servers of two versions sharing one OpenSearch, as during a rolling
// upgrade: the previous release next to this commit. The mixed-version
// workflow builds both and runs these tests:
//
//	SIGNALITH_TEST_UPGRADE=1 SIGNALITH_TEST_PREV_BIN=... SIGNALITH_TEST_PREV_VERSION=0.1.0 \
//	SIGNALITH_TEST_NEXT_BIN=... SIGNALITH_TEST_NEXT_VERSION=0.1.0-next+abc1234 \
//	go test -tags integration -run '^TestUpgrade' ./internal/integration/
//
// Without SIGNALITH_TEST_UPGRADE they skip, so the integration job, which
// runs every test but the cluster ones, leaves them out. The previous
// release may be one that cannot do what this commit checks (shared
// settings, the version header, upgrade-check itself): every such check
// is skipped with a log line saying so.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// upgradeBins are the two versions under test.
type upgradeBins struct {
	prev, prevVersion string
	next, nextVersion string
}

// upgradeEnv returns the binaries of the two versions, and skips the test
// unless SIGNALITH_TEST_UPGRADE=1.
func upgradeEnv(t *testing.T) upgradeBins {
	t.Helper()
	if os.Getenv("SIGNALITH_TEST_UPGRADE") != "1" {
		t.Skip("set SIGNALITH_TEST_UPGRADE=1 (and SIGNALITH_TEST_PREV_BIN) to run the mixed-version tests")
	}
	b := upgradeBins{
		prev: os.Getenv("SIGNALITH_TEST_PREV_BIN"), prevVersion: os.Getenv("SIGNALITH_TEST_PREV_VERSION"),
		next: os.Getenv("SIGNALITH_TEST_NEXT_BIN"), nextVersion: os.Getenv("SIGNALITH_TEST_NEXT_VERSION"),
	}
	if b.prev == "" {
		t.Fatal("SIGNALITH_TEST_UPGRADE=1 needs SIGNALITH_TEST_PREV_BIN, the previous release's binary")
	}
	if b.next == "" {
		b.next, b.nextVersion = signalithBinary(t), "dev"
	}
	if b.prevVersion == "" || b.nextVersion == "" || b.prevVersion == b.nextVersion {
		t.Fatalf("the two versions must be set and differ: %q and %q", b.prevVersion, b.nextVersion)
	}
	return b
}

// startBin runs the server on bin, as start does with this commit's
// binary, and waits until it answers /readyz with 200.
func startBin(s *testServer, bin string) {
	t := s.h.t
	t.Helper()
	logf, err := os.OpenFile(s.logPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(logf, "--- %s serve\n", bin)
	cmd := exec.Command(bin, "serve", "-c", filepath.Join(s.dir, "signalith.yaml"))
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
		_ = cmd.Process.Signal(syscall.SIGCONT)
		_ = cmd.Process.Kill()
		<-done
	})
	waitUntil(t, 90*time.Second, s.name+" ready on "+filepath.Base(bin), func() bool {
		select {
		case <-done:
			t.Fatalf("%s exited at start:\n%s", s.name, s.logTail(40))
		default:
		}
		return s.readyz() == http.StatusOK
	})
	s.api = s.httpsClient()
}

// stopGraceful stops the server as a service stop does, and waits until
// it exited.
func stopGraceful(s *testServer) {
	t := s.h.t
	t.Helper()
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.done:
	case <-time.After(60 * time.Second):
		t.Fatalf("%s did not stop within a minute:\n%s", s.name, s.logTail(40))
	}
	s.api = nil
}

// upgradeCheck runs bin's signalith cluster upgrade-check -json on s's
// folder and returns its exit code and output. Code -1 is a run that did
// not end with an exit code.
func upgradeCheck(t *testing.T, s *testServer, bin string) (int, upgradeOutput, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "cluster", "upgrade-check", "-c", filepath.Join(s.dir, "signalith.yaml"), "-json")
	cmd.Env = s.env()
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		code = -1
	}
	var v upgradeOutput
	_ = json.Unmarshal(out, &v)
	return code, v, string(out) + stderr.String()
}

// upgradeOutput is what upgrade-check -json prints, as far as the tests
// read it.
type upgradeOutput struct {
	Safe     bool   `json:"safe"`
	Single   bool   `json:"single"`
	Next     string `json:"next"`
	Blockers []struct {
		Code   string `json:"code"`
		Server string `json:"server"`
	} `json:"blockers"`
	Warnings []struct {
		Code   string `json:"code"`
		Server string `json:"server"`
	} `json:"warnings"`
}

func (o upgradeOutput) has(code string) bool {
	for _, n := range append(o.Blockers, o.Warnings...) {
		if n.Code == code {
			return true
		}
	}
	return false
}

// prevCaps is what the previous release can do that this commit checks.
type prevCaps struct {
	// level is the highest cluster level it reads, 0 before shared
	// settings.
	level         int
	versionHeader bool
	upgradeCheck  bool
	sharedUsers   bool
}

// detectCaps reads what s, which runs the previous release, can do.
func detectCaps(t *testing.T, b upgradeBins, s *testServer) prevCaps {
	t.Helper()
	var c prevCaps
	if hb, ok := s.h.heartbeat(s.name); ok {
		c.level = hb.LevelMax
	}
	_, hdr, _ := s.request(http.MethodGet, "/api/cluster", nil, nil)
	c.versionHeader = hdr.Get("X-Signalith-Version") != ""
	code, _, _ := upgradeCheck(t, s, b.prev)
	c.upgradeCheck = code == 0 || code == 3
	c.sharedUsers = c.level >= shared.LevelSharedUsers
	t.Logf("prev %s: level %d, version header %v, upgrade-check %v, shared users %v", b.prevVersion, c.level, c.versionHeader, c.upgradeCheck, c.sharedUsers)
	return c
}

// heartbeat reads a server's heartbeat from OpenSearch by its name.
func (h *clusterHarness) heartbeat(name string) (cluster.Heartbeat, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	docs, err := h.os.SearchDocs(ctx, cluster.RuntimeIndex(h.prefix), map[string]any{"term": map[string]any{"kind": "node"}})
	if err != nil {
		return cluster.Heartbeat{}, false
	}
	for _, d := range docs {
		var hb cluster.Heartbeat
		if json.Unmarshal(d.Source, &hb) == nil && hb.Name == name {
			return hb, true
		}
	}
	return cluster.Heartbeat{}, false
}

// lease reads lease:jobs from OpenSearch.
func (h *clusterHarness) lease() (cluster.LeaseDoc, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	src, _, found, err := h.os.Get(ctx, cluster.RuntimeIndex(h.prefix), "lease:jobs")
	var l cluster.LeaseDoc
	if err != nil || !found || json.Unmarshal(src, &l) != nil {
		return l, false
	}
	return l, true
}

// jobsWatch samples, every second, which server holds the job lease and
// which servers each running server's page says run the jobs.
type jobsWatch struct {
	mu      sync.Mutex
	holders []string
	// both counts consecutive samples in which a page showed two
	// servers running the jobs; worst is the highest count seen.
	both, worst int
	stop        chan struct{}
	done        chan struct{}
}

func watchJobs(h *clusterHarness, servers ...*testServer) *jobsWatch {
	w := &jobsWatch{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		for {
			select {
			case <-w.stop:
				return
			case <-time.After(time.Second):
			}
			holder := h.leaseHolder()
			two := false
			for _, s := range servers {
				if v, ok := s.view(); ok && len(v.runners()) > 1 {
					two = true
				}
			}
			w.mu.Lock()
			if holder != "" && (len(w.holders) == 0 || w.holders[len(w.holders)-1] != holder) {
				w.holders = append(w.holders, holder)
			}
			if two {
				w.both++
				w.worst = max(w.worst, w.both)
			} else {
				w.both = 0
			}
			w.mu.Unlock()
		}
	}()
	return w
}

// end stops the sampling and returns the lease holders in order and the
// longest run of samples with two servers running the jobs.
func (w *jobsWatch) end() ([]string, int) {
	close(w.stop)
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.holders), w.worst
}

// Two servers of the previous release are upgraded one at a time to this
// commit's: neither stops serving for long, the jobs move at most once,
// and the cluster ends with one runner on the new version.
func TestUpgradeRollingPair(t *testing.T) {
	b := upgradeEnv(t)
	t.Parallel()
	h := newClusterHarness(t)
	a := h.add("siem-a", serverOptions{})
	startBin(a, b.prev)
	waitUntil(t, 45*time.Second, "siem-a runs the jobs", func() bool {
		v, ok := a.view()
		return ok && v.Lease.Mine
	})
	sb := h.add("siem-b", serverOptions{})
	startBin(sb, b.prev)
	waitStandby(t, a, sb)
	caps := detectCaps(t, b, a)

	var session *http.Cookie
	if caps.sharedUsers {
		if session, _ = a.signIn("admin", clusterPassword); session == nil {
			t.Fatal("could not sign in on siem-a before the upgrade")
		}
	} else {
		t.Logf("prev %s: no shared sessions, skipped", b.prevVersion)
	}

	// A heartbeat can still say starting for a moment after the pages
	// say ready, and upgrade-check rightly waits for it.
	safeNext := func(s *testServer, want string) {
		t.Helper()
		var code int
		var raw string
		deadline := time.Now().Add(60 * time.Second)
		for {
			var out upgradeOutput
			code, out, raw = upgradeCheck(t, s, b.next)
			if code == 0 && out.Safe && strings.Contains(out.Next, want) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("upgrade-check does not say %q: exit %d\n%s", want, code, raw)
			}
			time.Sleep(time.Second)
		}
	}
	safeNext(sb, "Upgrade siem-b next")

	w := watchJobs(h, a, sb)
	stopGraceful(sb)
	startBin(sb, b.next)
	waitStandby(t, a, sb)

	safeNext(a, "Upgrade siem-a next")
	stopGraceful(a)
	waitUntil(t, 90*time.Second, "siem-b takes over the jobs", func() bool { return h.leaseHolder() == "siem-b" })
	startBin(a, b.next)
	waitStandby(t, sb, a)
	holders, worst := w.end()

	if len(holders) > 2 || (len(holders) == 2 && holders[1] != "siem-b") {
		t.Errorf("the jobs moved more than once: %v", holders)
	}
	if worst >= 3 {
		t.Errorf("a page showed two servers running the jobs for %d seconds", worst)
	}
	l, ok := h.lease()
	if !ok || l.HolderVersion != b.nextVersion || l.HolderName != "siem-b" {
		t.Errorf("lease after the upgrade: %+v, want siem-b on %s", l, b.nextVersion)
	}
	if v, ok := a.view(); !ok || len(v.runners()) != 1 {
		t.Errorf("runners after the upgrade: %v", v.runners())
	}

	hb, _ := h.heartbeat("siem-a")
	if caps.level > 0 {
		var level int
		waitUntil(t, 90*time.Second, "the cluster reaches the new version's level", func() bool {
			level = clusterLevel(t, a, b.next)
			return hb.LevelMax > 0 && level == hb.LevelMax
		})
	} else {
		t.Logf("prev %s: no cluster level, skipped (level now %d)", b.prevVersion, clusterLevel(t, a, b.next))
	}
	if session != nil {
		if code := a.me(session); code != http.StatusOK {
			t.Errorf("the session from before the upgrade: %d", code)
		}
	}
}

// clusterLevel is the cluster's level as bin's cluster status reads it.
func clusterLevel(t *testing.T, s *testServer, bin string) int {
	t.Helper()
	cmd := exec.Command(bin, "cluster", "status", "-c", filepath.Join(s.dir, "signalith.yaml"), "-json")
	cmd.Env = s.env()
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	var st struct {
		Shared struct {
			Level int `json:"level"`
		} `json:"shared"`
	}
	_ = json.Unmarshal(out, &st)
	return st.Shared.Level
}

// knownGone lists API paths that an older release's pages call and a
// newer release removed on purpose, each with why. No endpoint goes away
// for one release (multi-server design, upgrades), so it starts empty.
var knownGone = map[string]string{}

// apiPathRE finds the API paths in a page's scripts.
var apiPathRE = regexp.MustCompile("['\"`](/?api/[A-Za-z0-9_\\-/]+)")

// pageScripts lists the scripts index.html of s names, and their text.
func pageScripts(t *testing.T, s *testServer) map[string]string {
	t.Helper()
	code, _, body := s.request(http.MethodGet, "/", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("GET / on %s: %d", s.name, code)
	}
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`<script[^>]*\ssrc="([^"]+)"`).FindAllStringSubmatch(string(body), -1) {
		src := m[1]
		if strings.Contains(src, "://") {
			continue
		}
		if !strings.HasPrefix(src, "/") {
			src = "/" + src
		}
		code, _, js := s.request(http.MethodGet, src, nil, nil)
		if code != http.StatusOK {
			t.Errorf("%s names script %s, which it answers with %d", s.name, src, code)
			continue
		}
		out[src] = string(js)
	}
	if len(out) == 0 {
		t.Fatalf("%s's index.html names no script", s.name)
	}
	return out
}

// apiPaths are the API paths a page's scripts call, without parameters.
func apiPaths(scripts map[string]string) []string {
	var out []string
	for _, js := range scripts {
		for _, m := range apiPathRE.FindAllStringSubmatch(js, -1) {
			p, _, _ := strings.Cut(m[1], "${")
			if strings.HasSuffix(p, "/") || strings.HasSuffix(p, "?") {
				continue
			}
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	slices.Sort(out)
	return out
}

// getStatus GETs path on s as admin: its status, content type, version
// header and body; status 0 when it did not answer in time (a stream).
func getStatus(s *testServer, path string) (int, string, string, []byte) {
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d%s", s.port, path), nil)
	req.SetBasicAuth("admin", clusterPassword)
	client := *s.api
	client.Timeout = 10 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", "", nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	return resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("X-Signalith-Version"), b
}

// Each version's pages against the other version's API, as a load balancer
// in front of both sends them during an upgrade. The previous release's
// pages must find every API path they call on the new version. The new
// version's pages may call paths the previous release does not have: the
// version header makes them reload from the server that answered, so it
// must say a different version.
func TestUpgradePagesAgainstOtherAPI(t *testing.T) {
	b := upgradeEnv(t)
	t.Parallel()
	h := newClusterHarness(t)
	old := h.add("siem-old", serverOptions{})
	startBin(old, b.prev)
	waitUntil(t, 45*time.Second, "siem-old runs the jobs", func() bool {
		v, ok := old.view()
		return ok && v.Lease.Mine
	})
	nw := h.add("siem-new", serverOptions{})
	startBin(nw, b.next)
	waitStandby(t, old, nw)
	caps := detectCaps(t, b, old)

	for _, dir := range []struct {
		pages, api *testServer
		// strict: a path the pages call must exist on the API's server.
		strict bool
	}{{old, nw, true}, {nw, old, false}} {
		pages, apiS := dir.pages, dir.api
		paths := apiPaths(pageScripts(t, pages))
		missing := 0
		for _, p := range paths {
			if why, ok := knownGone[p]; ok {
				t.Logf("%s: gone on purpose: %s", p, why)
				continue
			}
			code, ctype, ver, body := getStatus(apiS, p)
			own, _, ownVer, _ := getStatus(pages, p)
			switch {
			case code == http.StatusNotFound && own != http.StatusNotFound:
				if dir.strict {
					t.Errorf("a page of %s calls %s which %s does not have", pages.name, p, apiS.name)
				} else {
					missing++
				}
			case code >= 500 && own < 500:
				t.Errorf("a page of %s calls %s, which %s answers with %d: %.200s", pages.name, p, apiS.name, code, body)
			case code == http.StatusOK && strings.HasPrefix(ctype, "application/json") && !json.Valid(body):
				t.Errorf("%s answers %s with invalid JSON: %.200s", apiS.name, p, body)
			}
			if ver != "" && ownVer != "" && ver == ownVer {
				t.Errorf("%s and %s both say version %s on %s, so a page would not reload", pages.name, apiS.name, ver, p)
			}
		}
		if missing > 0 {
			t.Logf("pages of %s call %d paths %s does not have; they reload on its version header", pages.name, missing, apiS.name)
		}
		t.Logf("checked %d API paths of %s's pages against %s", len(paths), pages.name, apiS.name)
	}
	if !caps.versionHeader {
		t.Logf("prev %s: no X-Signalith-Version header, skipped", b.prevVersion)
		return
	}
	_, _, oldVer, _ := getStatus(old, "/api/cluster")
	_, _, newVer, _ := getStatus(nw, "/api/cluster")
	if oldVer == "" || newVer == "" || oldVer == newVer {
		t.Errorf("version headers %q and %q: they must differ for the pages to reload", oldVer, newVer)
	}
}

// What upgrade-check says on two servers of this commit: a warning while
// only one may run the jobs, another while a server is offline, and a
// blocker while a server restarts to apply new settings (exit code 3).
func TestUpgradeCheckSays(t *testing.T) {
	b := upgradeEnv(t)
	t.Parallel()
	h := newClusterHarness(t)
	a := h.add("siem-a", serverOptions{})
	startBin(a, b.next)
	waitUntil(t, 45*time.Second, "siem-a runs the jobs", func() bool {
		v, ok := a.view()
		return ok && v.Lease.Mine
	})
	sb := h.add("siem-b", serverOptions{noJobs: true})
	startBin(sb, b.next)

	var raw string
	waitUntil(t, 90*time.Second, "upgrade-check says only siem-a can run the jobs", func() bool {
		var code int
		var out upgradeOutput
		code, out, raw = upgradeCheck(t, a, b.next)
		return code == 0 && out.Safe && out.has("only_eligible")
	})
	t.Logf("two servers:\n%s", raw)

	sb.pause()
	waitUntil(t, 75*time.Second, "upgrade-check says siem-b is offline", func() bool {
		code, out, r := upgradeCheck(t, a, b.next)
		raw = r
		return code == 0 && out.has("offline")
	})
	sb.resume()
	waitUntil(t, 60*time.Second, "siem-b is live again", func() bool {
		v, ok := a.view()
		st, _, _ := v.server("siem-b")
		return ok && st == cluster.StateReady
	})

	// A restart in place by request ends within a second, faster than
	// heartbeats are written, so a server that is restarting is planted:
	// a third heartbeat that says so.
	hb, ok := h.heartbeat("siem-b")
	if !ok {
		t.Fatal("no heartbeat of siem-b")
	}
	hb.NodeID, hb.Name, hb.BootID = "n_restarting", "siem-c", "boot-c"
	hb.Restart = &cluster.RestartStatus{Busy: true}
	plant := func() {
		hb.HeartbeatAt = time.Now().UTC()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.os.Do(ctx, http.MethodPut, "/"+cluster.RuntimeIndex(h.prefix)+"/_doc/node:n_restarting?refresh=true", hb, nil); err != nil {
			t.Fatal(err)
		}
	}
	plant()
	code, out, raw := upgradeCheck(t, a, b.next)
	if code != 3 || out.Safe || !out.has("restart_running") {
		t.Errorf("upgrade-check while siem-c restarts: exit %d\n%s", code, raw)
	}
	hb.Restart = &cluster.RestartStatus{}
	plant()
	if code, out, raw := upgradeCheck(t, a, b.next); code != 0 || out.has("restart_running") {
		t.Errorf("upgrade-check once siem-c restarted: exit %d\n%s", code, raw)
	}
}

// One server alone on its OpenSearch: upgrade-check says to stop it,
// install and start it, and changes nothing.
func TestUpgradeSingleServer(t *testing.T) {
	b := upgradeEnv(t)
	t.Parallel()
	h := newClusterHarness(t)
	s := h.add("siem-a", serverOptions{})
	startBin(s, b.next)
	waitUntil(t, 45*time.Second, "siem-a runs the jobs", func() bool {
		v, ok := s.view()
		return ok && v.Lease.Mine
	})
	before, _ := s.view()
	code, out, raw := upgradeCheck(t, s, b.next)
	if code != 0 || !out.Single || !strings.Contains(raw, "the only one using this OpenSearch") {
		t.Fatalf("upgrade-check on one server: exit %d\n%s", code, raw)
	}
	if s.readyz() != http.StatusOK {
		t.Error("/readyz after upgrade-check")
	}
	after, ok := s.view()
	if !ok || len(after.Servers) != len(before.Servers) || strings.Join(after.runners(), ",") != strings.Join(before.runners(), ",") {
		t.Errorf("the cluster view changed: %+v, then %+v", before, after)
	}
}
