//go:build integration && linux

package integration

// Several `signalith serve` processes that share one OpenSearch, each with
// its own state folder, the way two servers share one in production:
// exactly one runs the background jobs, another takes over when it dies,
// none takes over while its files differ, and a server that crashed and
// starts again at once keeps its identity.
//
// The CI cluster job runs them against the secured OpenSearch of the
// Docker quick start, as servers that share one OpenSearch need it:
//
//	SIGNALITH_TEST_OPENSEARCH=https://localhost:9200 SIGNALITH_TEST_OPENSEARCH_CA=... \
//	SIGNALITH_TEST_OPENSEARCH_CERT=... SIGNALITH_TEST_OPENSEARCH_KEY=... \
//	go test -tags integration -run '^TestCluster' ./internal/integration/
//
// The servers get the same CA, certificate and key (see storeConfig), and
// index prefixes under signalith*, which is all that certificate may use.
// Without SIGNALITH_TEST_OPENSEARCH they run against the in-memory fake
// (internal/cluster/ostest), so they can be tried on a laptop; in CI that
// is an error rather than a quiet switch. They are Linux-only because they
// stop processes with kill -9 and SIGSTOP.
//
// Each server serves HTTPS with its own certificate, as by default: the
// tests ask /readyz over plain HTTP on the same port, as a load balancer
// may, and call the API over HTTPS, trusting that server's own CA.
//
// Every server gets one cluster key through SIGNALITH_CLUSTER_KEY_FILE,
// as servers set up by hand are told to, so each one joins the cluster
// the first server founds; a server started with noKey does not.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const clusterPassword = "cluster-test-password"

// The binary is built once for every test in the package. It is built
// with the clustertest tag, which is meant to let members share an
// OpenSearch without security until the CI job's OpenSearch runs secured
// (multi-server design, section 5). This version has no such check yet,
// so the tag changes nothing today.
var (
	buildOnce sync.Once
	buildDir  string
	buildBin  string
	buildErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if buildDir != "" {
		os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

func signalithBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		if buildDir, buildErr = os.MkdirTemp("", "signalith-clustertest-"); buildErr != nil {
			return
		}
		buildBin = filepath.Join(buildDir, "signalith")
		cmd := exec.Command("go", "build", "-tags", "clustertest", "-o", buildBin, "../../cmd/signalith")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("go build: %v\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return buildBin
}

// clusterHarness is one test's OpenSearch, index prefix and servers.
type clusterHarness struct {
	t      *testing.T
	url    string
	prefix string
	root   string
	os     *store.Client
	// keyFile holds the cluster key every server is given.
	keyFile string
	// fake is the in-memory OpenSearch, nil with a real one.
	fake *ostest.Server
}

// newClusterHarness gives a test its own index prefix on the OpenSearch of
// SIGNALITH_TEST_OPENSEARCH, or its own fake OpenSearch, and removes what
// the servers made when it ends.
func newClusterHarness(t *testing.T) *clusterHarness {
	t.Helper()
	// Under signalith*, the indices a secured OpenSearch lets Signalith use.
	h := &clusterHarness{t: t, prefix: "signalithcl" + config.RandomToken(3), root: t.TempDir()}
	h.url = os.Getenv("SIGNALITH_TEST_OPENSEARCH")
	if h.url == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("SIGNALITH_TEST_OPENSEARCH is not set: in CI these tests must run against a real OpenSearch")
		}
		h.fake = ostest.New(t)
		h.url = h.fake.URL
	}
	h.os = store.New(storeConfig(h.url))
	h.keyFile = filepath.Join(h.root, "cluster.key")
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	if err := os.WriteFile(h.keyFile, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if _, err := h.os.Health(ctx); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("OpenSearch not reachable at %s: %v", h.url, err)
		}
		time.Sleep(2 * time.Second)
	}
	if os.Getenv("SIGNALITH_TEST_OPENSEARCH") != "" {
		// Runs after every server of the test was stopped (cleanups run
		// last first).
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			names, err := h.os.ListIndices(ctx, h.prefix+"-*,"+h.prefix+"_*")
			if err != nil {
				t.Logf("could not list the test's indices: %v", err)
			}
			for _, n := range names {
				_ = h.os.DeleteIndex(ctx, n)
			}
			for _, tpl := range []string{h.prefix, h.prefix + "_runtime", h.prefix + "_config"} {
				_ = h.os.Do(ctx, http.MethodDelete, "/_index_template/"+tpl, nil, nil)
			}
		})
	}
	return h
}

// testServer is one `signalith serve` process and its folder, which holds
// its config, its state folder (identity and lock) and its lookups.
type testServer struct {
	h    *clusterHarness
	name string
	dir  string
	port int
	cmd  *exec.Cmd
	done chan struct{}
	// api calls the server over HTTPS, trusting its own CA.
	api  *http.Client
	opts serverOptions
}

// serverOptions are what a server is started with.
type serverOptions struct {
	// noJobs turns detections.scheduler off: the server never runs the
	// background jobs.
	noJobs bool
	// retention is written to lookups/retention.yaml, as the Data
	// retention page saves it.
	retention string
	// noKey starts the server without the cluster key, so it does not
	// join the cluster by itself.
	noKey bool
	// yaml is added to signalith.yaml.
	yaml string
	// opensearch is the OpenSearch address in place of the harness's.
	opensearch string
}

// add makes a server's folder and config, without starting it.
func (h *clusterHarness) add(name string, o serverOptions) *testServer {
	t := h.t
	t.Helper()
	s := &testServer{h: h, name: name, dir: filepath.Join(h.root, name), port: freePort(t), opts: o}
	if err := os.MkdirAll(filepath.Join(s.dir, "lookups"), 0o755); err != nil {
		t.Fatal(err)
	}
	osURL := h.url
	if o.opensearch != "" {
		osURL = o.opensearch
	}
	cfg := fmt.Sprintf("server:\n  listen: 127.0.0.1:%d\nopensearch:\n  url: %q\n  index_prefix: %s\ncluster:\n  node_name: %s\n",
		s.port, osURL, h.prefix, name)
	tlsFiles := storeConfig(h.url)
	for _, f := range []struct{ key, file string }{{"ca_file", tlsFiles.CAFile}, {"cert_file", tlsFiles.CertFile}, {"key_file", tlsFiles.KeyFile}} {
		if f.file != "" {
			cfg = strings.Replace(cfg, "opensearch:\n", fmt.Sprintf("opensearch:\n  %s: %q\n", f.key, f.file), 1)
		}
	}
	if o.noJobs {
		cfg += "detections:\n  scheduler: false\n"
	}
	cfg += o.yaml
	if err := os.WriteFile(filepath.Join(s.dir, "signalith.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if o.retention != "" {
		if err := os.WriteFile(filepath.Join(s.dir, "lookups", "retention.yaml"), []byte(o.retention), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// start adds a server and starts it.
func (h *clusterHarness) start(name string, o serverOptions) *testServer {
	h.t.Helper()
	s := h.add(name, o)
	s.start()
	return s
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// start runs the server and waits until it answers /readyz with 200.
func (s *testServer) start() {
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
		_ = cmd.Process.Signal(syscall.SIGCONT)
		_ = cmd.Process.Kill()
		<-done
		if t.Failed() {
			t.Logf("log of %s:\n%s", s.name, s.logTail(60))
		}
	})
	waitUntil(t, 60*time.Second, s.name+" ready", func() bool {
		select {
		case <-done:
			t.Fatalf("%s exited at start:\n%s", s.name, s.logTail(40))
		default:
		}
		return s.readyz() == http.StatusOK
	})
	s.api = s.httpsClient()
}

// env is the server's environment, for serve and the command line.
func (s *testServer) env() []string {
	env := append(os.Environ(), "SIGNALITH_ADMIN_PASSWORD="+clusterPassword, "SIGNALITH_STATE_DIR="+s.dir)
	if !s.opts.noKey {
		env = append(env, "SIGNALITH_CLUSTER_KEY_FILE="+s.h.keyFile)
	}
	return env
}

// httpsClient is a client that trusts the server's own certificate
// authority, which it made in its state folder.
func (s *testServer) httpsClient() *http.Client {
	t := s.h.t
	t.Helper()
	pem, err := os.ReadFile(filepath.Join(s.dir, "tls", "ca.pem"))
	if err != nil {
		t.Fatalf("%s has no certificate authority in its state folder: %v", s.name, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("%s: no certificate in tls/ca.pem", s.name)
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
}

func (s *testServer) logPath() string { return filepath.Join(s.dir, "signalith.log") }

func (s *testServer) logTail(lines int) string {
	b, _ := os.ReadFile(s.logPath())
	all := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return strings.Join(all, "\n")
}

// kill9 kills the process the way a crash or a power cut stops it: no
// release of the job lease, no last heartbeat.
func (s *testServer) kill9() {
	s.h.t.Helper()
	if err := s.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		s.h.t.Fatal(err)
	}
	<-s.done
}

// pause stops the process without ending it (SIGSTOP), as a stalled
// virtual machine does; resume lets it run again.
func (s *testServer) pause() {
	s.h.t.Helper()
	if err := s.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		s.h.t.Fatal(err)
	}
}

func (s *testServer) resume() {
	s.h.t.Helper()
	if err := s.cmd.Process.Signal(syscall.SIGCONT); err != nil {
		s.h.t.Fatal(err)
	}
}

var clusterHTTP = &http.Client{Timeout: 5 * time.Second}

// readyz asks /readyz over plain HTTP, which answers it on the HTTPS port
// as a load balancer's check needs.
func (s *testServer) readyz() int {
	resp, err := clusterHTTP.Get(fmt.Sprintf("http://127.0.0.1:%d/readyz", s.port))
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// clusterView is GET /api/cluster as an admin sees it.
type clusterView struct {
	Self  string `json:"self"`
	Lease struct {
		Holder     string `json:"holder"`
		HolderName string `json:"holder_name"`
		Epoch      int64  `json:"epoch"`
		Mine       bool   `json:"mine"`
	} `json:"lease"`
	Servers []struct {
		Name           string `json:"name"`
		NodeID         string `json:"node_id"`
		Self           bool   `json:"self"`
		State          string `json:"state"`
		Jobs           string `json:"jobs"`
		CannotTakeOver string `json:"cannot_take_over"`
		NotEligible    string `json:"not_eligible"`
		Shared         *struct {
			Mode string `json:"mode"`
		} `json:"shared"`
	} `json:"servers"`
	Warnings []struct {
		Level string `json:"level"`
		Text  string `json:"text"`
	} `json:"warnings"`
}

// view reads the server's GET /api/cluster; ok is false when it did not
// answer.
func (s *testServer) view() (v clusterView, ok bool) {
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/api/cluster", s.port), nil)
	req.SetBasicAuth("admin", clusterPassword)
	client := s.api
	if client == nil {
		return v, false
	}
	resp, err := client.Do(req)
	if err != nil {
		return v, false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || json.Unmarshal(b, &v) != nil {
		return v, false
	}
	return v, true
}

// runners lists the servers that run the jobs, as v shows them.
func (v clusterView) runners() []string {
	var out []string
	for _, s := range v.Servers {
		if s.Jobs == "runs" {
			out = append(out, s.Name)
		}
	}
	return out
}

func (v clusterView) server(name string) (state, jobs, cannot string) {
	for _, s := range v.Servers {
		if s.Name == name {
			return s.State, s.Jobs, s.CannotTakeOver
		}
	}
	return "", "", ""
}

// leaseHolder reads lease:jobs from OpenSearch itself.
func (h *clusterHarness) leaseHolder() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	src, _, found, err := h.os.Get(ctx, h.prefix+"_runtime", "lease:jobs")
	if err != nil || !found {
		return ""
	}
	var d struct {
		HolderName string `json:"holder_name"`
	}
	_ = json.Unmarshal(src, &d)
	return d.HolderName
}

func waitUntil(t *testing.T, within time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, within)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// startLeader starts a server and waits until it runs the jobs, so the
// test knows which server leads.
func (h *clusterHarness) startLeader(name string, o serverOptions) *testServer {
	h.t.Helper()
	s := h.start(name, o)
	waitUntil(h.t, 30*time.Second, name+" runs the jobs", func() bool {
		v, ok := s.view()
		return ok && v.Lease.Mine
	})
	return s
}

// waitStandby waits until both servers list each other as ready, with
// leader running the jobs and other on standby.
func waitStandby(t *testing.T, leader, other *testServer) {
	t.Helper()
	waitUntil(t, 45*time.Second, other.name+" on standby behind "+leader.name, func() bool {
		for _, s := range []*testServer{leader, other} {
			v, ok := s.view()
			if !ok || len(v.Servers) != 2 || strings.Join(v.runners(), ",") != leader.name {
				return false
			}
			if st, _, _ := v.server(other.name); st != "ready" {
				return false
			}
		}
		return true
	})
}

func TestClusterTwoServersOneRunsTheJobs(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := h.start("siem-a", serverOptions{})
	b := h.start("siem-b", serverOptions{})
	// Both may run the jobs; exactly one does, and both agree which.
	var holder string
	waitUntil(t, 45*time.Second, "one server runs the jobs", func() bool {
		va, ok1 := a.view()
		vb, ok2 := b.view()
		if !ok1 || !ok2 || len(va.Servers) != 2 || len(vb.Servers) != 2 {
			return false
		}
		ra, rb := va.runners(), vb.runners()
		if len(ra) != 1 || len(rb) != 1 || ra[0] != rb[0] || va.Lease.Mine == vb.Lease.Mine {
			return false
		}
		holder = ra[0]
		return true
	})
	// It stays that way across several renewals.
	for i := 0; i < 4; i++ {
		time.Sleep(5 * time.Second)
		for _, s := range []*testServer{a, b} {
			v, ok := s.view()
			if !ok {
				t.Fatalf("%s did not answer", s.name)
			}
			if r := v.runners(); len(r) != 1 || r[0] != holder || v.Lease.HolderName != holder {
				t.Fatalf("%s sees %v running the jobs, lease %+v; want only %s", s.name, r, v.Lease, holder)
			}
		}
	}
	if got := h.leaseHolder(); got != holder {
		t.Errorf("lease:jobs names %q, want %q", got, holder)
	}
}

func TestClusterTakeoverAfterKill(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := h.startLeader("siem-a", serverOptions{})
	b := h.start("siem-b", serverOptions{})
	waitStandby(t, a, b)
	killed := time.Now()
	a.kill9()
	waitUntil(t, 45*time.Second, "siem-b takes the jobs over", func() bool {
		v, ok := b.view()
		return ok && v.Lease.Mine && strings.Join(v.runners(), ",") == "siem-b"
	})
	t.Logf("siem-b took the jobs over %v after siem-a was killed", time.Since(killed).Round(time.Second))
	waitUntil(t, 15*time.Second, "siem-a shown offline", func() bool {
		v, _ := b.view()
		st, _, _ := v.server("siem-a")
		return st == "offline"
	})
	if got := h.leaseHolder(); got != "siem-b" {
		t.Errorf("lease:jobs names %q", got)
	}
}

// refusesTakeover checks that standby, whose files differ from leader's
// in what, does not take the jobs over when leader dies, and says why.
func refusesTakeover(t *testing.T, h *clusterHarness, leader, standby *testServer, what string) {
	t.Helper()
	waitStandby(t, leader, standby)
	// Both servers' lists say that standby would not take over.
	for _, s := range []*testServer{leader, standby} {
		waitUntil(t, 90*time.Second, s.name+" shows that "+standby.name+" would not take over", func() bool {
			v, ok := s.view()
			_, jobs, cannot := v.server(standby.name)
			return ok && jobs == "standby" && strings.Contains(cannot, what)
		})
	}
	killed := time.Now()
	leader.kill9()
	waitUntil(t, 45*time.Second, standby.name+" says that nobody runs the jobs", func() bool {
		v, ok := standby.view()
		if !ok || len(v.Warnings) == 0 {
			return false
		}
		w := v.Warnings[0]
		st, _, _ := v.server(leader.name)
		return st == "offline" && w.Level == "red" && strings.HasPrefix(w.Text, "No server is running detections") && strings.Contains(w.Text, what)
	})
	// Well past the time a takeover takes, it still has not taken over.
	for time.Since(killed) < 50*time.Second {
		if v, ok := standby.view(); ok && (v.Lease.Mine || len(v.runners()) > 0) {
			t.Fatalf("%s took the jobs over although its %s differ: %+v", standby.name, what, v.Lease)
		}
		time.Sleep(time.Second)
	}
	if got := h.leaseHolder(); got != leader.name {
		t.Errorf("lease:jobs names %q, want %q", got, leader.name)
	}
}

// Retention policies are shared once the servers are a cluster, so a
// server whose own retention.yaml differs takes the jobs over, and
// enforces the shared policies, the founder's.
func TestClusterTakeoverWhenRetentionFilesDiffer(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := h.startLeader("siem-a", serverOptions{retention: "default:\n  keep_days: 30\n"})
	b := h.start("siem-b", serverOptions{retention: "default:\n  keep_days: 60\n"})
	waitStandby(t, a, b)
	a.kill9()
	waitUntil(t, 45*time.Second, "siem-b takes the jobs over", func() bool {
		v, ok := b.view()
		return ok && v.Lease.Mine
	})
	var ov struct {
		Default struct {
			Policy struct {
				KeepDays int `json:"keep_days"`
			} `json:"policy"`
		} `json:"default"`
	}
	if code := b.call(http.MethodGet, "/api/retention", nil, &ov); code != http.StatusOK || ov.Default.Policy.KeepDays != 30 {
		t.Errorf("siem-b enforces keep_days %d (%d), want the shared 30", ov.Default.Policy.KeepDays, code)
	}
}

// A server without the cluster key is not part of the cluster, so it
// never takes the jobs over, whatever its files say.
func TestClusterNoTakeoverWithoutTheClusterKey(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := h.startLeader("siem-a", serverOptions{})
	b := h.start("siem-b", serverOptions{noKey: true})
	waitUntil(t, 45*time.Second, "siem-a lists siem-b as not part of the cluster", func() bool {
		v, ok := a.view()
		for _, s := range v.Servers {
			if ok && s.Name == "siem-b" && s.State == "ready" && strings.Contains(s.NotEligible, "not part of the cluster") {
				return true
			}
		}
		return false
	})
	killed := time.Now()
	a.kill9()
	for time.Since(killed) < 50*time.Second {
		if v, ok := b.view(); ok && (v.Lease.Mine || strings.Contains(strings.Join(v.runners(), ","), "siem-b")) {
			t.Fatalf("siem-b took the jobs over without the cluster key: %+v", v.Lease)
		}
		time.Sleep(time.Second)
	}
}

func TestClusterNoTakeoverWhenArchiveFoldersDiffer(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	// Same policies, which archive, but each server keeps archives in its
	// own folder (the default, next to its lookups) instead of one shared
	// folder.
	policy := "default:\n  keep_days: 30\n  archive: true\n"
	a := h.startLeader("siem-a", serverOptions{retention: policy})
	b := h.start("siem-b", serverOptions{retention: policy})
	refusesTakeover(t, h, a, b, "archive folder")
}

// A server that crashed and is started again at once, with the same state
// folder, passes the identity check, and takes its own job lease back.
func TestClusterFastRestart(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := h.startLeader("siem-a", serverOptions{})
	// siem-b never runs the jobs, so only siem-a can take them back.
	b := h.start("siem-b", serverOptions{noJobs: true})
	waitStandby(t, a, b)
	va, _ := a.view()
	a.kill9()
	restarted := time.Now()
	a.start()
	t.Logf("siem-a was ready again %v after it was killed", time.Since(restarted).Round(100*time.Millisecond))
	waitUntil(t, 45*time.Second, "siem-a runs the jobs again", func() bool {
		v, ok := a.view()
		return ok && v.Lease.Mine
	})
	vb, _ := b.view()
	if len(vb.Servers) != 2 || vb.Servers[0].NodeID != va.Self {
		t.Errorf("after the restart siem-b lists %+v; want siem-a once, as %s", vb.Servers, va.Self)
	}
	if log := a.logTail(200); strings.Contains(log, "is using this server's identity") {
		t.Errorf("the restart was taken for another server using the identity:\n%s", log)
	}
}

// A leader that stops running without exiting (SIGSTOP, as a stalled VM)
// loses the jobs to the other server, and when it runs again it finds
// that out and leaves them there.
func TestClusterPausedLeaderGivesWay(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := h.startLeader("siem-a", serverOptions{})
	b := h.start("siem-b", serverOptions{})
	waitStandby(t, a, b)
	a.pause()
	waitUntil(t, 45*time.Second, "siem-b takes the jobs over from the paused siem-a", func() bool {
		v, ok := b.view()
		return ok && v.Lease.Mine
	})
	a.resume()
	waitUntil(t, 30*time.Second, "siem-a gives way after it resumed", func() bool {
		va, ok1 := a.view()
		vb, ok2 := b.view()
		return ok1 && ok2 && !va.Lease.Mine && va.Lease.HolderName == "siem-b" &&
			strings.Join(va.runners(), ",") == "siem-b" && strings.Join(vb.runners(), ",") == "siem-b"
	})
	if got := h.leaseHolder(); got != "siem-b" {
		t.Errorf("lease:jobs names %q", got)
	}
}
