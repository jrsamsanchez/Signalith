// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

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
	// bin is the server binary, itBinary's when empty.
	bin string
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
	return newITClusterBin(t, "", names...)
}

// newITClusterBin starts the servers from bin (itBinary's when empty).
func newITClusterBin(t *testing.T, bin string, names ...string) *itCluster {
	t.Helper()
	c := &itCluster{t: t, root: t.TempDir(), prefix: "signalithlg" + strings.ToLower(newRunID()[:6]), bin: bin}
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
	if urls := itNodeURLs(); len(urls) > 0 {
		quoted := make([]string, len(urls))
		for i, u := range urls {
			quoted[i] = strconv.Quote(u)
		}
		cfg = strings.Replace(cfg, "opensearch:\n", "opensearch:\n  urls: ["+strings.Join(quoted, ", ")+"]\n", 1)
	}
	for _, f := range []struct{ key, env string }{{"ca_file", "SIGNALITH_TEST_OPENSEARCH_CA"}, {"cert_file", "SIGNALITH_TEST_OPENSEARCH_CERT"}, {"key_file", "SIGNALITH_TEST_OPENSEARCH_KEY"}} {
		if v := os.Getenv(f.env); v != "" {
			cfg = strings.Replace(cfg, "opensearch:\n", fmt.Sprintf("opensearch:\n  %s: %q\n", f.key, v), 1)
		}
	}
	must(t, os.WriteFile(filepath.Join(s.dir, "signalith.yaml"), []byte(cfg), 0o600))
	logf, err := os.OpenFile(filepath.Join(s.dir, "signalith.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	must(t, err)
	bin := c.bin
	if bin == "" {
		bin = itBinary(t)
	}
	cmd := exec.Command(bin, "serve", "-c", filepath.Join(s.dir, "signalith.yaml"))
	cmd.Env = append(os.Environ(), c.env(s)...)
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

// env is what a server needs in its environment besides the test's own.
func (c *itCluster) env(s *itServer) []string {
	return []string{"SIGNALITH_ADMIN_PASSWORD=" + itPassword, "SIGNALITH_STATE_DIR=" + s.dir,
		"SIGNALITH_CLUSTER_KEY_FILE=" + c.keyFile, "SIGNALITH_INGEST_TOKEN=" + itToken}
}

// itNodeURLs are the other nodes of the test OpenSearch, from
// SIGNALITH_TEST_OPENSEARCH_URLS (comma separated), when it has several.
func itNodeURLs() []string {
	return splitComma(os.Getenv("SIGNALITH_TEST_OPENSEARCH_URLS"))
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
	s.OpenSearch = OpenSearch{URL: c.osURL, URLs: itNodeURLs(), CA: os.Getenv("SIGNALITH_TEST_OPENSEARCH_CA"),
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
	return c.runWith(s, runOptions{}, s.Name)
}

// runWith runs s with opts and saves its report as name.json.
func (c *itCluster) runWith(s *Scenario, opts runOptions, name string) *Report {
	t := c.t
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	opts.Log = testWriter{t}
	rep, err := runScenario(ctx, s, opts)
	must(t, err)
	var b strings.Builder
	rep.WriteText(&b)
	t.Log(b.String())
	if dir := os.Getenv("LOADGEN_REPORT_DIR"); dir != "" {
		must(t, os.MkdirAll(dir, 0o755))
		must(t, rep.WriteJSON(filepath.Join(dir, name+".json")))
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

// versionedBinary builds the server with the clustertest tag as version
// v, as internal/integration's rolling-upgrade test does.
func versionedBinary(t *testing.T, v string) string {
	t.Helper()
	bin := filepath.Join(filepath.Dir(itBinary(t)), "signalith-"+v)
	if _, err := os.Stat(bin); err == nil {
		return bin
	}
	cmd := exec.Command("go", "build", "-tags", "clustertest", "-ldflags", "-X main.version="+v, "-o", bin, "../signalith")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", v, err, out)
	}
	return bin
}

// upgradeCmd writes, for each server, a script that upgrades it to bin as
// a package upgrade does: stop the server (SIGTERM, as systemd stops it)
// and start bin on the same files and port. It returns the fault's
// command, and kills the new processes when the test ends.
func (c *itCluster) upgradeCmd(bin string) string {
	t := c.t
	t.Helper()
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	for _, sv := range c.servers {
		pidFile := filepath.Join(c.root, sv.name+".pid")
		var env strings.Builder
		for _, kv := range c.env(sv) {
			k, v, _ := strings.Cut(kv, "=")
			fmt.Fprintf(&env, "%s=%s ", k, q(v))
		}
		script := fmt.Sprintf(`set -e
pid=$(cat %[1]s)
kill -TERM "$pid"
i=0
while kill -0 "$pid" 2>/dev/null; do
  i=$((i+1))
  if [ "$i" -gt 600 ]; then kill -KILL "$pid"; fi
  sleep 0.1
done
%[2]s nohup %[3]s serve -c %[4]s >>%[5]s 2>&1 </dev/null &
echo $! >%[1]s
`, q(pidFile), env.String(), q(bin), q(filepath.Join(sv.dir, "signalith.yaml")), q(filepath.Join(sv.dir, "signalith.log")))
		must(t, os.WriteFile(filepath.Join(c.root, "upgrade-"+sv.name+".sh"), []byte(script), 0o700))
		first := sv.cmd.Process.Pid
		t.Cleanup(func() {
			b, err := os.ReadFile(pidFile)
			pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
			if err != nil || pid == first || pid <= 0 {
				return
			}
			_ = syscall.Kill(pid, syscall.SIGKILL)
			for range 100 {
				if syscall.Kill(pid, 0) != nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		})
	}
	return "sh " + filepath.Join(c.root, "upgrade-{server}.sh")
}

// TestLoadgenRollingUpgrade is S7 at CI size: two servers that run 9.9.0
// are upgraded to 9.9.1 one at a time while agents send and analysts keep
// their pages open. The jobs move once, to the upgraded server, and
// nothing is lost.
func TestLoadgenRollingUpgrade(t *testing.T) {
	// The upgraded server takes the jobs 5 s after it is ready, not a
	// minute, so the run stays short.
	t.Setenv("SIGNALITH_TEST_YIELD_SETTLE", "5s")
	older, newer := versionedBinary(t, "9.9.0"), versionedBinary(t, "9.9.1")
	c := newITClusterBin(t, older, "a", "b")
	s := c.scenario("s7-small.yaml")
	for i := range s.Faults {
		if s.Faults[i].Kind == "upgrade" {
			s.Faults[i].Cmd = c.upgradeCmd(newer)
		}
	}
	rep := c.run(s)
	requirePass(t, rep)
	var steps []UpgradeStep
	for _, f := range rep.Faults {
		steps = append(steps, f.Upgrades...)
	}
	if len(steps) != 2 {
		t.Fatalf("upgrades %+v", steps)
	}
	for _, st := range steps {
		if st.From != "9.9.0" || st.To != "9.9.1" || !st.Drained {
			t.Errorf("%+v", st)
		}
	}
}

// TestLoadgenOpenSearchNodeLoss is S9 at CI size: two servers that list
// all three nodes of the test OpenSearch carry on while the second node is
// stopped (loadtest/s9-small.yaml stops its container). It needs an
// OpenSearch of three nodes: SIGNALITH_TEST_OPENSEARCH and
// SIGNALITH_TEST_OPENSEARCH_URLS, as the nightly job's opensearch-node-loss
// step sets them.
func TestLoadgenOpenSearchNodeLoss(t *testing.T) {
	if len(itNodeURLs()) == 0 || os.Getenv("SIGNALITH_TEST_OPENSEARCH") == "" {
		t.Skip("needs an OpenSearch of several nodes: set SIGNALITH_TEST_OPENSEARCH and SIGNALITH_TEST_OPENSEARCH_URLS")
	}
	c := newITCluster(t, "a", "b")
	rep := c.run(c.scenario("s9-small.yaml"))
	requirePass(t, rep)
	if rep.Skipped != "" {
		t.Fatalf("skipped: %s", rep.Skipped)
	}
	if len(rep.Faults) != 1 || rep.Faults[0].Error != "" || rep.Faults[0].Undone == nil {
		t.Errorf("the node was not stopped and started again: %+v", rep.Faults)
	}
}

func TestLoadgenBrute(t *testing.T) {
	c := newITCluster(t, "a", "b")
	requirePass(t, c.run(c.scenario("s6-brute.yaml")))
}

// TestLoadgenSizing measures what docs/performance.md's sizing table
// shows: loadtest/sizing-small.yaml against one server, then two (the
// second compared with the first), with each server's CPU and memory
// read from /proc. It takes about a quarter of an hour, so it runs only
// with LOADGEN_SIZING=1 (the nightly job's sizing step). The table is
// logged and, with LOADGEN_REPORT_DIR, saved as sizing.md.
func TestLoadgenSizing(t *testing.T) {
	if os.Getenv("LOADGEN_SIZING") == "" {
		t.Skip("set LOADGEN_SIZING=1 to measure the sizing table")
	}
	var reports []*Report
	for _, names := range [][]string{{"a"}, {"a", "b"}} {
		c := newITCluster(t, names...)
		opts := runOptions{PIDs: map[string]int{}}
		for _, sv := range c.servers {
			opts.PIDs[sv.name] = sv.cmd.Process.Pid
		}
		if len(reports) > 0 {
			opts.Baseline = reports[0]
		}
		s := c.scenario("sizing-small.yaml")
		// Not verified event by event: reading millions back takes longer
		// than the run (s1-small checks that).
		s.OpenSearch = OpenSearch{}
		rep := c.runWith(s, opts, fmt.Sprintf("sizing-small-%d", len(names)))
		requirePass(t, rep)
		reports = append(reports, rep)
	}
	table := sizingTable(reports)
	t.Log("\n" + table)
	if dir := os.Getenv("LOADGEN_REPORT_DIR"); dir != "" {
		must(t, os.WriteFile(filepath.Join(dir, "sizing.md"), []byte(table), 0o644))
	}
}
