package agentd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
)

// The test program stands in for Fluent Bit when AGENTD_FAKE_FLUENTBIT
// says how it should behave: "run" keeps running, "exit" stops at once.
func TestMain(m *testing.M) {
	if strings.HasPrefix(filepath.Base(os.Args[0]), "osqueryd") {
		fakeOsqueryd()
		return
	}
	if v := os.Getenv("AGENTD_FAKE_AGENT_VERSION"); v != "" && len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(v)
		return
	}
	if mode := os.Getenv("AGENTD_FAKE_FLUENTBIT"); mode != "" {
		fakeFluentBit(mode)
		return
	}
	upAfter, quickExit, firstBackoff, maxBackoff = 100*time.Millisecond, time.Second, 20*time.Millisecond, 100*time.Millisecond
	stopWait, missingWait, reportDelay, retry = 2*time.Second, 50*time.Millisecond, 10*time.Millisecond, 50*time.Millisecond
	os.Exit(m.Run())
}

func fakeFluentBit(mode string) {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("Fluent Bit v4.0.3")
		return
	}
	fmt.Println("fake fluent-bit starting")
	if len(os.Args) != 3 || os.Args[1] != "-c" {
		fmt.Println("bad arguments:", os.Args[1:])
		os.Exit(2)
	}
	conf, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	seen := fmt.Sprintf("token=%s host=%s conf=%s", os.Getenv("SIGNALITH_TOKEN"), os.Getenv("HOSTNAME"), conf)
	if out := os.Getenv("AGENTD_FAKE_OUT"); out != "" {
		_ = os.WriteFile(out, []byte(seen), 0o600)
	}
	if mode == "exit" {
		fmt.Println("error: something is wrong")
		os.Exit(1)
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}

func testPaths(t *testing.T) Paths {
	dir := t.TempDir()
	p := Paths{Conf: filepath.Join(dir, "conf"), State: filepath.Join(dir, "state")}
	for _, d := range []string{p.Conf, p.State} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p.FluentBit = exe
	return p
}

// fakeServer is Signalith's side of the agent's routes.
type fakeServer struct {
	mu       sync.Mutex
	cfg      agentproto.Config
	statuses []agentproto.Status
	asks     []*http.Request
	notMod   int
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asks = append(f.asks, r)
	if r.Header.Get("Authorization") != "Bearer sgl_test" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"bad token"}`)
		return
	}
	switch r.URL.Path {
	case agentproto.RouteConfig:
		cfg := f.cfg
		cfg.Revision = agentproto.RevisionOf(cfg)
		if r.Header.Get("If-None-Match") == `"`+cfg.Revision+`"` {
			f.notMod++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_ = json.NewEncoder(w).Encode(cfg)
	case agentproto.RouteStatus:
		var st agentproto.Status
		if err := json.NewDecoder(r.Body).Decode(&st); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.statuses = append(f.statuses, st)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeServer) lastStatus() (agentproto.Status, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.statuses) == 0 {
		return agentproto.Status{}, false
	}
	return f.statuses[len(f.statuses)-1], true
}

func newAgent(t *testing.T, srv *httptest.Server, p Paths) *Agent {
	return &Agent{Paths: p, Settings: Settings{Server: srv.URL, Token: "sgl_test"}, Version: "1.2.3", Name: "web-01",
		Client: srv.Client(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Facts: func() facts { return facts{Source: "journal"} }}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAgentRunsFluentBitAndReports(t *testing.T) {
	t.Setenv("AGENTD_FAKE_FLUENTBIT", "run")
	p := testPaths(t)
	out := filepath.Join(t.TempDir(), "seen")
	t.Setenv("AGENTD_FAKE_OUT", out)
	fs := &fakeServer{cfg: agentproto.Config{PollSeconds: 300, FluentBit: &agentproto.FluentBit{Config: "[SERVICE]\n    flush 1\n"}}}
	srv := httptest.NewTLSServer(fs)
	defer srv.Close()
	a := newAgent(t, srv, p)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	waitFor(t, "a status saying Fluent Bit runs", func() bool {
		st, ok := fs.lastStatus()
		return ok && len(st.Components) == 1 && st.Components[0].State == agentproto.StateRunning
	})
	st, _ := fs.lastStatus()
	if st.Version != "1.2.3" || st.Revision == "" || st.ConfigError != "" || st.Components[0].Version != "4.0.3" {
		t.Errorf("status = %+v", st)
	}
	waitFor(t, "the health file", func() bool {
		h, _ := os.ReadFile(p.HealthFile())
		return string(h) == "config=ok\nfluentbit=running\nreported=yes\n"
	})
	seen, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if want := "token=sgl_test host=web-01 conf=[SERVICE]\n    flush 1\n"; string(seen) != want {
		t.Errorf("Fluent Bit saw %q, want %q", seen, want)
	}
	if fi, err := os.Stat(p.fluentBitConf()); err != nil || (fi.Mode().Perm()&0o077 != 0 && runtime.GOOS != "windows") {
		t.Errorf("fluent-bit.conf: %v %v", fi, err)
	}
	fs.mu.Lock()
	first := fs.asks[0]
	fs.mu.Unlock()
	if first.Header.Get(agentproto.HeaderName) != "web-01" || first.URL.Query().Get("source") != "journal" || first.URL.Query().Get("os") == "" {
		t.Errorf("first request: %v %v", first.Header, first.URL)
	}

	// The same configuration again is not applied again.
	if err := a.sync(ctx); err != nil {
		t.Fatal(err)
	}
	fs.mu.Lock()
	notMod := fs.notMod
	fs.mu.Unlock()
	if notMod != 1 {
		t.Errorf("not-modified answers = %d, want 1", notMod)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if c := a.fluentBit.component(); c.Restarts != 0 {
		t.Errorf("Fluent Bit restarted: %+v", c)
	}
}

func TestAgentKeepsLastConfigWhenServerIsDown(t *testing.T) {
	t.Setenv("AGENTD_FAKE_FLUENTBIT", "run")
	p := testPaths(t)
	cfg := agentproto.Config{Revision: "abc", FluentBit: &agentproto.FluentBit{Config: "old"}}
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(p.configFile(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.fluentBitConf(), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	srv.Close() // nothing answers
	a := newAgent(t, srv, p)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitFor(t, "the health file", func() bool {
		h, _ := os.ReadFile(p.HealthFile())
		s := string(h)
		return strings.Contains(s, "fluentbit=running") && strings.Contains(s, "reported=no") && !strings.Contains(s, "config=ok")
	})
	cancel()
	<-done
}

func TestCollectorRestartsWhenItStops(t *testing.T) {
	t.Setenv("AGENTD_FAKE_FLUENTBIT", "exit")
	p := testPaths(t)
	if err := os.WriteFile(p.fluentBitConf(), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pr := newProc("fluentbit", slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { pr.run(ctx); close(done) }()
	pr.set(&procSpec{Path: p.FluentBit, Args: []string{"-c", p.fluentBitConf()}, Env: os.Environ()})
	waitFor(t, "restarts", func() bool { return pr.component().Restarts >= 2 })
	c := pr.component()
	if c.State != agentproto.StateFailed && c.State != agentproto.StateStarting {
		t.Errorf("state = %q", c.State)
	}
	if !strings.Contains(pr.tail.String(), "something is wrong") {
		t.Errorf("tail = %q", pr.tail.String())
	}
	cancel()
	<-done
}

func TestCollectorMissing(t *testing.T) {
	pr := newProc("fluentbit", slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { pr.run(ctx); close(done) }()
	pr.set(&procSpec{Path: filepath.Join(t.TempDir(), "no-such-program")})
	waitFor(t, "missing", func() bool { return pr.stateNow() == agentproto.StateMissing })
	pr.set(nil)
	waitFor(t, "off", func() bool { return pr.stateNow() == agentproto.StateOff })
	cancel()
	<-done
}

func TestWriteCARefusesAuthorityThatDoesNotVouchForServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	p := testPaths(t)
	a := newAgent(t, srv, p)
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	other := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: selfSigned(t)})
	if err := a.writeCA(string(other), resp.TLS); err == nil || !strings.Contains(err.Error(), "does not vouch") {
		t.Fatalf("other authority: %v", err)
	}
	if _, err := os.Stat(p.caFile()); !os.IsNotExist(err) {
		t.Fatalf("ca.pem written: %v", err)
	}
	good := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := a.writeCA(string(other)+string(good), resp.TLS); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p.caFile()); string(b) != string(other)+string(good) {
		t.Fatal("ca.pem not written")
	}
	if err := a.writeCA("not a certificate", resp.TLS); err == nil {
		t.Fatal("garbage accepted")
	}
}

func selfSigned(t *testing.T) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other"}, IsCA: true,
		BasicConstraintsValid: true, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestReadSettings(t *testing.T) {
	p := testPaths(t)
	if _, err := ReadSettings(p); err == nil {
		t.Fatal("no agent.conf accepted")
	}
	_ = os.WriteFile(p.settingsFile(), []byte("# made by install.sh\nSERVER='https://siem.example:9000'\nSIGNALITH_VERSION=0.4.0\n"), 0o644)
	if _, err := ReadSettings(p); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("no token: %v", err)
	}
	_ = os.WriteFile(p.tokenFile(), []byte("sgl_abc\n"), 0o600)
	s, err := ReadSettings(p)
	if err != nil || s.Server != "https://siem.example:9000" || s.Token != "sgl_abc" {
		t.Fatalf("settings = %+v, %v", s, err)
	}
	_ = os.WriteFile(p.settingsFile(), []byte("SERVER=https://siem.example:9000\nOSQUERY=yes\n"), 0o644)
	if s, err := ReadSettings(p); err != nil || !s.Osquery {
		t.Fatalf("OSQUERY=yes: %+v, %v", s, err)
	}
	_ = os.WriteFile(p.settingsFile(), []byte("SERVER=http://siem.example:9000\n"), 0o644)
	if _, err := ReadSettings(p); err == nil {
		t.Fatal("plain http accepted")
	}
}

func TestAgentPoll(t *testing.T) {
	for _, c := range []struct{ in, want int }{{0, 300}, {5, 30}, {600, 600}, {99999, 3600}} {
		if got := agentPoll(&agentproto.Config{PollSeconds: c.in}); got != c.want {
			t.Errorf("agentPoll(%d) = %d, want %d", c.in, got, c.want)
		}
	}
	if agentPoll(nil) != 300 {
		t.Error("nil config")
	}
}

func TestOSReleaseName(t *testing.T) {
	f := filepath.Join(t.TempDir(), "os-release")
	_ = os.WriteFile(f, []byte("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n"), 0o644)
	if got := osReleaseName(f); got != "Ubuntu 24.04.1 LTS" {
		t.Errorf("got %q", got)
	}
}
