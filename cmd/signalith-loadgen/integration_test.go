//go:build integration && linux

package main

// The scenarios in loadtest/ run against real `signalith serve` processes
// that share one OpenSearch, as the nightly load job runs them. The
// servers are started here, the way internal/integration starts its
// cluster tests: built with the clustertest tag, each with its own state
// folder, one cluster key, HTTPS on.
//
// With SIGNALITH_TEST_OPENSEARCH (and _CA, _CERT, _KEY) they use that
// OpenSearch, and verify reads it; without it they use the in-memory fake
// and only on a laptop (in CI that is an error). LOADGEN_SHORT=1 cuts every
// phase to a few seconds, for a quick check of the tool itself.
// LOADGEN_REPORT_DIR, when set, receives each run's JSON report.
//
//	go test -tags integration -run '^TestLoadgen' ./cmd/signalith-loadgen/

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

const (
	itPassword = "loadgen-test-password"
	itToken    = "loadgen-test-ingest-token-0123456789"
)

var (
	itBuildOnce sync.Once
	itBin       string
	itBuildErr  error
)

func itBinary(t *testing.T) string {
	t.Helper()
	itBuildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "signalith-loadgen-it-")
		if err != nil {
			itBuildErr = err
			return
		}
		itBin = filepath.Join(dir, "signalith")
		cmd := exec.Command("go", "build", "-tags", "clustertest", "-o", itBin, "../signalith")
		if out, err := cmd.CombinedOutput(); err != nil {
			itBuildErr = fmt.Errorf("go build: %v\n%s", err, out)
		}
	})
	if itBuildErr != nil {
		t.Fatal(itBuildErr)
	}
	return itBin
}

// itCluster is the servers of one test and the files a scenario needs.
type itCluster struct {
	t       *testing.T
	root    string
	osURL   string
	prefix  string
	keyFile string
	servers []*itServer
	// fake is the in-memory OpenSearch, nil with a real one.
	fake *ostest.Server
}

type itServer struct {
	name string
	dir  string
	port int
	cmd  *exec.Cmd
	done chan struct{}
}

func newITCluster(t *testing.T, names ...string) *itCluster {
	t.Helper()
	c := &itCluster{t: t, root: t.TempDir(), prefix: "signalithlg" + strings.ToLower(newRunID()[:6])}
	c.osURL = os.Getenv("SIGNALITH_TEST_OPENSEARCH")
	if c.osURL == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("SIGNALITH_TEST_OPENSEARCH is not set: in CI the load scenarios run against a real OpenSearch")
		}
		c.fake = ostest.New(t)
		c.osURL = c.fake.URL
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	c.keyFile = filepath.Join(c.root, "cluster.key")
	must(t, os.WriteFile(c.keyFile, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(c.root, "admin.txt"), []byte("admin:"+itPassword+"\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(c.root, "token.txt"), []byte(itToken+"\n"), 0o600))
	for _, n := range names {
		c.start(n)
	}
	c.waitReady(len(names))
	return c
}

// waitReady waits until the first server lists n servers as ready.
func (c *itCluster) waitReady(n int) {
	t := c.t
	t.Helper()
	s := c.scenario("s3-idle.yaml")
	tc, err := tlsConfig(s.CAFiles)
	must(t, err)
	user, pass, err := readLogin(s.Credentials.AdminFile)
	must(t, err)
	sess := newSession(s.Targets[0], newTransport(tc, nil), user, pass)
	deadline := time.Now().Add(90 * time.Second)
	for {
		var v clusterView
		if sess.Do(context.Background(), http.MethodGet, "/api/cluster", nil, &v) == nil && len(v.live()) >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d servers not ready", n)
		}
		time.Sleep(time.Second)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func (c *itCluster) start(name string) *itServer {
	t := c.t
	t.Helper()
	s := &itServer{name: name, dir: filepath.Join(c.root, name), port: freePort(t)}
	must(t, os.MkdirAll(filepath.Join(s.dir, "lookups"), 0o755))
	cfg := fmt.Sprintf("server:\n  listen: 127.0.0.1:%d\nopensearch:\n  url: %q\n  index_prefix: %s\ncluster:\n  node_name: %s\n",
		s.port, c.osURL, c.prefix, name)
	for _, f := range []struct{ key, env string }{{"ca_file", "SIGNALITH_TEST_OPENSEARCH_CA"}, {"cert_file", "SIGNALITH_TEST_OPENSEARCH_CERT"}, {"key_file", "SIGNALITH_TEST_OPENSEARCH_KEY"}} {
		if v := os.Getenv(f.env); v != "" {
			cfg = strings.Replace(cfg, "opensearch:\n", fmt.Sprintf("opensearch:\n  %s: %q\n", f.key, v), 1)
		}
	}
	must(t, os.WriteFile(filepath.Join(s.dir, "signalith.yaml"), []byte(cfg), 0o600))
	logf, err := os.OpenFile(filepath.Join(s.dir, "signalith.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	must(t, err)
	cmd := exec.Command(itBinary(t), "serve", "-c", filepath.Join(s.dir, "signalith.yaml"))
	cmd.Env = append(os.Environ(), "SIGNALITH_ADMIN_PASSWORD="+itPassword, "SIGNALITH_STATE_DIR="+s.dir,
		"SIGNALITH_CLUSTER_KEY_FILE="+c.keyFile, "SIGNALITH_INGEST_TOKEN="+itToken)
	cmd.Stdout, cmd.Stderr = logf, logf
	must(t, cmd.Start())
	s.cmd, s.done = cmd, make(chan struct{})
	go func() {
		_ = cmd.Wait()
		logf.Close()
		close(s.done)
	}()
	// Faults find the process by its name, as a lab finds a VM.
	must(t, os.WriteFile(filepath.Join(c.root, name+".pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600))
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGCONT)
		_ = cmd.Process.Kill()
		<-s.done
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(s.dir, "signalith.log"))
			lines := strings.Split(strings.TrimSpace(string(b)), "\n")
			t.Logf("log of %s:\n%s", name, strings.Join(lines[max(0, len(lines)-40):], "\n"))
		}
	})
	deadline := time.Now().Add(90 * time.Second)
	for {
		select {
		case <-s.done:
			t.Fatalf("%s exited at start", name)
		default:
		}
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/readyz", s.port))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not ready", name)
		}
		time.Sleep(500 * time.Millisecond)
	}
	c.servers = append(c.servers, s)
	return s
}

// scenario loads a file from loadtest/ and points it at this cluster.
func (c *itCluster) scenario(file string) *Scenario {
	t := c.t
	t.Helper()
	s, err := loadScenario(filepath.Join("..", "..", "loadtest", file))
	must(t, err)
	s.Targets, s.CAFile, s.CAFiles = nil, "", nil
	for _, sv := range c.servers {
		s.Targets = append(s.Targets, fmt.Sprintf("https://127.0.0.1:%d", sv.port))
		s.CAFiles = append(s.CAFiles, filepath.Join(sv.dir, "tls", "ca.pem"))
	}
	s.Credentials = Credentials{AdminFile: filepath.Join(c.root, "admin.txt"), TokenFile: filepath.Join(c.root, "token.txt")}
	s.OpenSearch = OpenSearch{URL: c.osURL, CA: os.Getenv("SIGNALITH_TEST_OPENSEARCH_CA"),
		Cert: os.Getenv("SIGNALITH_TEST_OPENSEARCH_CERT"), Key: os.Getenv("SIGNALITH_TEST_OPENSEARCH_KEY"), Prefix: c.prefix}
	for i := range s.Faults {
		f := &s.Faults[i]
		pid := filepath.Join(c.root, "{server}.pid")
		switch f.Kind {
		case "kill9":
			f.Cmd = "kill -KILL $(cat " + pid + ")"
		case "stop":
			f.Cmd, f.Undo = "kill -STOP $(cat "+pid+")", "kill -CONT $(cat "+pid+")"
		}
	}
	if os.Getenv("LOADGEN_SHORT") != "" && len(s.Faults) == 0 {
		shorten(s, 6*time.Second)
	}
	return s
}

// shorten cuts every phase to at most d.
func shorten(s *Scenario, d time.Duration) {
	for i := range s.Phases {
		s.Phases[i].For = Duration(min(s.Phases[i].For.D(), d))
	}
	s.Drain, s.Settle = Duration(30*time.Second), Duration(20*time.Second)
}

func (c *itCluster) run(s *Scenario) *Report {
	t := c.t
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	rep, err := runScenario(ctx, s, runOptions{Log: testWriter{t}})
	must(t, err)
	var b strings.Builder
	rep.WriteText(&b)
	t.Log(b.String())
	if dir := os.Getenv("LOADGEN_REPORT_DIR"); dir != "" {
		must(t, os.MkdirAll(dir, 0o755))
		must(t, rep.WriteJSON(filepath.Join(dir, s.Name+".json")))
	}
	return rep
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func requirePass(t *testing.T, rep *Report) {
	t.Helper()
	if !rep.Pass {
		t.Errorf("scenario %s failed", rep.Scenario)
	}
}

// One server alone is the baseline every other result is compared with.
func TestLoadgenIngestOneServer(t *testing.T) {
	c := newITCluster(t, "a")
	rep := c.run(c.scenario("s1-small.yaml"))
	requirePass(t, rep)
	if rep.Cluster {
		t.Error("one server reported as a cluster")
	}
	if rep.Verify == nil || rep.Verify.Acked == 0 {
		t.Errorf("nothing verified: %+v", rep.Verify)
	}
}

func TestLoadgenIdleCluster(t *testing.T) {
	c := newITCluster(t, "a", "b")
	if c.fake != nil {
		c.fake.Requests() // from now on
	}
	start := time.Now()
	requirePass(t, c.run(c.scenario("s3-idle.yaml")))
	if c.fake != nil {
		// The fake counts requests rather than operations; this shows the
		// idle cost when no real OpenSearch is at hand.
		n := len(c.fake.Requests())
		t.Logf("in-memory OpenSearch: %d requests in %s, %.2f per second per server", n, time.Since(start).Round(time.Second),
			float64(n)/time.Since(start).Seconds()/2)
	}
}

func TestLoadgenLeaderKilled(t *testing.T) {
	c := newITCluster(t, "a", "b")
	rep := c.run(c.scenario("s4-small.yaml"))
	requirePass(t, rep)
	took := false
	for _, f := range rep.Faults {
		took = took || f.TakeoverSeconds != nil
	}
	if !took {
		t.Errorf("no takeover measured: %+v", rep.Faults)
	}
}

func TestLoadgenBrowsers(t *testing.T) {
	c := newITCluster(t, "a", "b")
	requirePass(t, c.run(c.scenario("s2-browsers-small.yaml")))
}

func TestLoadgenBrute(t *testing.T) {
	c := newITCluster(t, "a", "b")
	requirePass(t, c.run(c.scenario("s6-brute.yaml")))
}
