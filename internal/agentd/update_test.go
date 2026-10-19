// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
)

// The test program stands in for the agent's own program: with
// AGENTD_FAKE_AGENT_VERSION set, "version" prints it. Programs of
// different versions are the test program with different bytes after it,
// which it runs the same.

func releaseKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := agentproto.ReleaseKeys
	agentproto.ReleaseKeys = []ed25519.PublicKey{pub}
	t.Cleanup(func() { agentproto.ReleaseKeys = old })
	return priv
}

func quickUpdates(t *testing.T) {
	old := [...]time.Duration{healthWait, stableWait, pollEvery, updateRetry}
	healthWait, stableWait, pollEvery, updateRetry = 2*time.Second, 50*time.Millisecond, 10*time.Millisecond, time.Hour
	t.Cleanup(func() { healthWait, stableWait, pollEvery, updateRetry = old[0], old[1], old[2], old[3] })
}

// fakeProgram is the test program with trailer after it, and its SHA-256.
func fakeProgram(t *testing.T, trailer string) ([]byte, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, []byte("\x00signalith-test-"+trailer)...)
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:])
}

func signedManifest(t *testing.T, priv ed25519.PrivateKey, version, sum string) ([]byte, []byte) {
	t.Helper()
	data, err := json.Marshal(agentproto.Manifest{Format: agentproto.ManifestFormat, Version: version,
		Programs: map[string]string{runtime.GOOS + "-" + runtime.GOARCH: sum}})
	if err != nil {
		t.Fatal(err)
	}
	return data, agentproto.SignManifest(priv, data)
}

// updateServer hands out a manifest and a program besides what
// fakeServer answers.
type updateServer struct {
	*fakeServer
	mu       sync.Mutex
	manifest agentproto.ManifestAnswer
	program  []byte
	gets     int
}

func (u *updateServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer sgl_test" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	switch r.URL.Path {
	case agentproto.RouteManifest:
		_ = json.NewEncoder(w).Encode(u.manifest)
	case agentproto.RouteProgram:
		if r.URL.Query().Get("os") != runtime.GOOS || r.URL.Query().Get("arch") != runtime.GOARCH {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		u.gets++
		_, _ = w.Write(u.program)
	default:
		u.fakeServer.ServeHTTP(w, r)
	}
}

type stageCase struct {
	srv     *updateServer
	agent   *Agent
	started int
}

func newStageCase(t *testing.T, offer agentproto.Update, served []byte, data, sig []byte) *stageCase {
	t.Helper()
	us := &updateServer{fakeServer: &fakeServer{}, manifest: agentproto.ManifestAnswer{Manifest: string(data), Signature: string(sig)}, program: served}
	srv := httptest.NewServer(us)
	t.Cleanup(srv.Close)
	c := &stageCase{srv: us}
	c.agent = newAgent(t, srv, testPaths(t))
	c.agent.now = time.Now
	c.agent.cfg = &agentproto.Config{Update: &offer}
	c.agent.runUpdater = func() error { c.started++; return nil }
	return c
}

func (c *stageCase) component() *agentproto.Component {
	c.agent.mu.Lock()
	defer c.agent.mu.Unlock()
	return c.agent.update
}

func TestAgentGetsUpdateReady(t *testing.T) {
	priv := releaseKey(t)
	t.Setenv("AGENTD_FAKE_AGENT_VERSION", "2.0.0")
	prog, sum := fakeProgram(t, "2.0.0")
	data, sig := signedManifest(t, priv, "2.0.0", sum)
	c := newStageCase(t, agentproto.Update{Version: "2.0.0", SHA256: sum}, prog, data, sig)
	c.agent.checkUpdate(context.Background())

	comp := c.component()
	if comp == nil || comp.State != agentproto.StateStarting || comp.Version != "2.0.0" {
		t.Fatalf("component = %+v, want starting 2.0.0", comp)
	}
	if c.started != 1 {
		t.Fatalf("updater started %d times, want 1", c.started)
	}
	p := c.agent.Paths
	if b, err := os.ReadFile(p.readyFile()); err != nil || string(b) != "2.0.0\n" {
		t.Fatalf("ready file = %q, %v", b, err)
	}
	if b, _ := os.ReadFile(p.stagedProgram()); !bytes.Equal(b, prog) {
		t.Fatal("the staged program is not the one served")
	}
	if b, _ := os.ReadFile(p.stagedManifest()); !bytes.Equal(b, data) {
		t.Fatal("the staged manifest is not the one served")
	}
	// While the update waits, the agent does not fetch it again.
	c.agent.checkUpdate(context.Background())
	if c.srv.gets != 1 || c.started != 1 {
		t.Fatalf("fetched %d times and started the updater %d times, want once each", c.srv.gets, c.started)
	}
}

func TestAgentRefusesUpdatesItCannotTrust(t *testing.T) {
	priv := releaseKey(t)
	t.Setenv("AGENTD_FAKE_AGENT_VERSION", "2.0.0")
	prog, sum := fakeProgram(t, "2.0.0")
	other, otherSum := fakeProgram(t, "someone else's")
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	data, sig := signedManifest(t, priv, "2.0.0", sum)
	for name, tc := range map[string]struct {
		offer     agentproto.Update
		served    []byte
		data, sig []byte
		version   string
		want      string
	}{
		"program changed": {offer: agentproto.Update{Version: "2.0.0", SHA256: sum}, served: other, data: data, sig: sig,
			want: "not the one the signed manifest lists"},
		"offer not in manifest": {offer: agentproto.Update{Version: "2.0.0", SHA256: otherSum}, served: other, data: data, sig: sig,
			want: "does not list the update"},
		"manifest changed": {offer: agentproto.Update{Version: "2.0.0", SHA256: sum}, served: prog,
			data: bytes.Replace(data, []byte("2.0.0"), []byte("2.0.1"), 1), sig: sig, want: "signature does not match"},
		"signed by another key": {offer: agentproto.Update{Version: "2.0.0", SHA256: sum}, served: prog,
			data: data, sig: agentproto.SignManifest(stranger, data), want: "signature does not match"},
		"says another version": {offer: agentproto.Update{Version: "2.0.0", SHA256: sum}, served: prog, data: data, sig: sig,
			version: "1.9.9", want: "says it is version"},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.version != "" {
				t.Setenv("AGENTD_FAKE_AGENT_VERSION", tc.version)
			}
			c := newStageCase(t, tc.offer, tc.served, tc.data, tc.sig)
			c.agent.checkUpdate(context.Background())
			comp := c.component()
			if comp == nil || comp.State != agentproto.StateFailed || !strings.Contains(comp.Error, tc.want) {
				t.Fatalf("component = %+v, want failed with %q", comp, tc.want)
			}
			p := c.agent.Paths
			for _, f := range []string{p.readyFile(), p.stagedProgram()} {
				if _, err := os.Stat(f); err == nil {
					t.Fatalf("%s left behind", filepath.Base(f))
				}
			}
			if c.started != 0 {
				t.Fatal("the updater was started")
			}
			// Not again until updateRetry has passed.
			gets := c.srv.gets
			c.agent.checkUpdate(context.Background())
			if c.srv.gets != gets {
				t.Fatal("tried the same update again at once")
			}
		})
	}
}

func TestAgentReportsUndoneUpdate(t *testing.T) {
	c := newStageCase(t, agentproto.Update{Version: "2.0.0", SHA256: strings.Repeat("a", 64)}, nil, nil, nil)
	p := c.agent.Paths
	if err := os.MkdirAll(p.updateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(updateResult{Version: "2.0.0", Error: "version 2.0.0 did not report within 3m0s", At: time.Now()})
	if err := os.WriteFile(p.resultFile(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	c.agent.checkUpdate(context.Background())
	comp := c.component()
	if comp == nil || comp.State != agentproto.StateFailed || !strings.Contains(comp.Error, "was undone: version 2.0.0 did not report") {
		t.Fatalf("component = %+v", comp)
	}
	if c.srv.gets != 0 {
		t.Fatal("tried an update that was undone again")
	}
	// Once the server no longer offers it, there is nothing to say.
	c.agent.cfg.Update = nil
	c.agent.checkUpdate(context.Background())
	if comp := c.component(); comp != nil {
		t.Fatalf("component = %+v, want none", comp)
	}
}

func TestStatusIncludesUpdate(t *testing.T) {
	c := newStageCase(t, agentproto.Update{}, nil, nil, nil)
	c.agent.fluentBit = newProc("fluentbit", c.agent.Log, c.agent.now, func() {})
	c.agent.setUpdate(&agentproto.Component{Name: "update", Version: "2.0.0", State: agentproto.StateStarting})
	found := false
	for _, comp := range c.agent.Status().Components {
		found = found || comp.Name == "update"
	}
	if !found {
		t.Fatal("the status does not report the update")
	}
}

// fakeService is the agent's service as the updater sees it: Restart
// starts what Program is, which writes its status as its version unless
// broken says otherwise.
type fakeService struct {
	t        *testing.T
	p        Paths
	versions map[string]string // SHA-256 of a program: its version
	// broken is how the new version fails: "silent" never reports,
	// "crash" reports and then restarts.
	broken   string
	newSum   string
	mu       sync.Mutex
	run      int
	restarts []string
	stops    int
}

func (s *fakeService) Stop(context.Context) error {
	s.mu.Lock()
	s.stops++
	s.mu.Unlock()
	return nil
}

func (s *fakeService) Restart(context.Context) error {
	b, err := os.ReadFile(s.p.Program)
	if err != nil {
		return err
	}
	h := sha256.Sum256(b)
	sum := hex.EncodeToString(h[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	s.run++
	s.restarts = append(s.restarts, s.versions[sum])
	if sum == s.newSum && s.broken == "silent" {
		return nil
	}
	st, _ := json.Marshal(agentproto.Status{Version: s.versions[sum], Started: time.Now().UTC().Format(time.RFC3339)})
	return os.WriteFile(s.p.StatusFile(), st, 0o600)
}

func (s *fakeService) State(context.Context) (bool, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken == "crash" && s.run > 0 && len(s.restarts) > 0 && s.restarts[len(s.restarts)-1] == "2.0.0" {
		// It keeps restarting.
		s.run++
	}
	return true, string(rune('0' + s.run%10)), nil
}

type updaterCase struct {
	u        *Updater
	svc      *fakeService
	old, new []byte
}

// newUpdaterCase sets up version 1.2.3 installed and version (whose
// program is newProg) waiting in the update folder.
func newUpdaterCase(t *testing.T, priv ed25519.PrivateKey, version string) *updaterCase {
	t.Helper()
	quickUpdates(t)
	t.Setenv("AGENTD_FAKE_AGENT_VERSION", version)
	p := testPaths(t)
	dir := t.TempDir()
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	p.Program = filepath.Join(dir, "bin", "signalith-agent"+exe)
	p.Prev = filepath.Join(dir, "lib", "signalith-agent.prev"+exe)
	oldProg, oldSum := fakeProgram(t, "1.2.3")
	newProg, newSum := fakeProgram(t, version)
	if err := os.MkdirAll(filepath.Dir(p.Program), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Program, oldProg, 0o755); err != nil {
		t.Fatal(err)
	}
	data, sig := signedManifest(t, priv, version, newSum)
	if err := os.MkdirAll(p.updateDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	for f, b := range map[string][]byte{p.stagedProgram(): newProg, p.stagedManifest(): data, p.stagedSignature(): sig, p.readyFile(): []byte(version + "\n")} {
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	svc := &fakeService{t: t, p: p, versions: map[string]string{oldSum: "1.2.3", newSum: version}, newSum: newSum}
	u := &Updater{Paths: p, Version: "1.2.3", Service: svc, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return &updaterCase{u: u, svc: svc, old: oldProg, new: newProg}
}

func (c *updaterCase) installed(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(c.u.Paths.Program)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (c *updaterCase) result(t *testing.T) updateResult {
	t.Helper()
	b, err := os.ReadFile(c.u.Paths.resultFile())
	if err != nil {
		t.Fatal(err)
	}
	var r updateResult
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestUpdaterInstallsUpdate(t *testing.T) {
	c := newUpdaterCase(t, releaseKey(t), "2.0.0")
	if err := c.u.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.installed(t), c.new) {
		t.Fatal("the new program is not in place")
	}
	if b, _ := os.ReadFile(c.u.Paths.Prev); !bytes.Equal(b, c.old) {
		t.Fatal("the version before was not kept")
	}
	if r := c.result(t); !r.OK || r.Version != "2.0.0" {
		t.Fatalf("result = %+v", r)
	}
	p := c.u.Paths
	for _, f := range []string{p.readyFile(), p.stagedProgram(), p.nextProgram()} {
		if _, err := os.Stat(f); err == nil {
			t.Fatalf("%s left behind", filepath.Base(f))
		}
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(p.Program); st.Mode().Perm() != 0o755 {
			t.Fatalf("program mode = %v", st.Mode().Perm())
		}
	}
	// Run again, there is nothing to do.
	if err := c.u.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.svc.restarts) != 1 {
		t.Fatalf("restarts = %v", c.svc.restarts)
	}
}

func TestUpdaterGoesBackWhenNewVersionFails(t *testing.T) {
	for broken, want := range map[string]string{"silent": "did not report", "crash": "stopped and was restarted"} {
		t.Run(broken, func(t *testing.T) {
			c := newUpdaterCase(t, releaseKey(t), "2.0.0")
			c.svc.broken = broken
			err := c.u.Install(context.Background())
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want %q", err, want)
			}
			if !bytes.Equal(c.installed(t), c.old) {
				t.Fatal("the version before is not back in place")
			}
			if r := c.result(t); r.OK || r.Version != "2.0.0" || !strings.Contains(r.Error, want) {
				t.Fatalf("result = %+v", r)
			}
			if got := strings.Join(c.svc.restarts, ","); got != "2.0.0,1.2.3" {
				t.Fatalf("restarts = %s, want 2.0.0 then 1.2.3", got)
			}
		})
	}
}

func TestUpdaterRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		version string
		change  func(t *testing.T, c *updaterCase)
		want    string
	}{
		"not newer": {version: "1.2.3", want: "not newer"},
		"older":     {version: "1.0.0", want: "not newer"},
		"program changed after the agent checked it": {version: "2.0.0", want: "not the one the signed manifest lists",
			change: func(t *testing.T, c *updaterCase) {
				other, _ := fakeProgram(t, "evil")
				if err := os.WriteFile(c.u.Paths.stagedProgram(), other, 0o600); err != nil {
					t.Fatal(err)
				}
			}},
		"manifest changed": {version: "2.0.0", want: "signature does not match",
			change: func(t *testing.T, c *updaterCase) {
				b, _ := os.ReadFile(c.u.Paths.stagedManifest())
				if err := os.WriteFile(c.u.Paths.stagedManifest(), bytes.Replace(b, []byte("2.0.0"), []byte("9.0.0"), 1), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
		"program does not run as its version": {version: "2.0.0", want: "says it is version",
			change: func(t *testing.T, c *updaterCase) { t.Setenv("AGENTD_FAKE_AGENT_VERSION", "1.9.9") }},
	} {
		t.Run(name, func(t *testing.T) {
			c := newUpdaterCase(t, releaseKey(t), tc.version)
			if tc.change != nil {
				tc.change(t, c)
			}
			err := c.u.Install(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if !bytes.Equal(c.installed(t), c.old) {
				t.Fatal("the program was replaced")
			}
			if len(c.svc.restarts) != 0 || c.svc.stops != 0 {
				t.Fatal("the agent was stopped or restarted")
			}
			if r := c.result(t); r.OK {
				t.Fatalf("result = %+v", r)
			}
			if _, err := os.Stat(c.u.Paths.readyFile()); err == nil {
				t.Fatal("the ready file is still there, so the updater would run again and again")
			}
		})
	}
}

func TestUpdaterRefusesLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	c := newUpdaterCase(t, releaseKey(t), "2.0.0")
	p := c.u.Paths
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p.stagedManifest()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, p.stagedManifest()); err != nil {
		t.Fatal(err)
	}
	// The result file through a link must not overwrite what it points at.
	if err := os.Symlink(secret, p.resultFile()); err != nil {
		t.Fatal(err)
	}
	if err := c.u.Install(context.Background()); err == nil {
		t.Fatal("installed from a linked manifest")
	}
	if b, _ := os.ReadFile(secret); string(b) != "{}" {
		t.Fatalf("the linked file was written: %q", b)
	}
	if !bytes.Equal(c.installed(t), c.old) {
		t.Fatal("the program was replaced")
	}
}

// The agent's sandbox can write the update folder and the one it is in,
// so a link put in place of either must not lead the updater to write or
// delete anything elsewhere.
func TestUpdaterRefusesLinkedFolders(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need privileges on Windows")
	}
	for _, which := range []string{"update", "state", "writable"} {
		t.Run(which, func(t *testing.T) {
			c := newUpdaterCase(t, releaseKey(t), "2.0.0")
			p := c.u.Paths
			// target is where the link leads, set up as an update would be.
			target := filepath.Join(t.TempDir(), "target")
			switch which {
			case "update":
				if err := os.Rename(p.updateDir(), target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, p.updateDir()); err != nil {
					t.Fatal(err)
				}
			case "state":
				if err := os.Rename(p.State, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, p.State); err != nil {
					t.Fatal(err)
				}
				target = filepath.Join(target, "update")
			case "writable":
				target = p.updateDir()
				if err := os.Chmod(target, 0o777); err != nil {
					t.Fatal(err)
				}
			}
			before := listDir(t, target)
			err := c.u.Install(context.Background())
			if err == nil || !strings.Contains(err.Error(), "refusing the update folder") {
				t.Fatalf("err = %v", err)
			}
			if after := listDir(t, target); after != before {
				t.Fatalf("the folder changed:\nbefore %s\nafter  %s", before, after)
			}
			if !bytes.Equal(c.installed(t), c.old) || len(c.svc.restarts) != 0 {
				t.Fatal("the program was replaced or the agent restarted")
			}
		})
	}
}

func listDir(t *testing.T, dir string) string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return strings.Join(names, " ")
}
