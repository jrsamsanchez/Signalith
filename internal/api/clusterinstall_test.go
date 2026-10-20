// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/deploy"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clusterinstall"
	"github.com/jrsamsanchez/signalith/internal/clustertls"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/users"
)

func installServer(t *testing.T, exe string, change func(*Server)) *httptest.Server {
	t.Helper()
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Install = &ClusterInstall{
			Files:      &clusterinstall.Files{Exe: exe, GOOS: "linux", GOARCH: "amd64"},
			Gate:       &clusterinstall.Gate{PerHour: 2},
			ScriptGate: &clusterinstall.Gate{PerHour: 4},
		}
		if change != nil {
			change(s)
		}
	})
	return ts
}

func fetch(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

// A new server downloads the scripts and the program without signing in,
// and each carries its SHA-256.
func TestInstallFilesArePublic(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "signalith")
	program := []byte("the program")
	if err := os.WriteFile(exe, program, 0o666); err != nil {
		t.Fatal(err)
	}
	ts := installServer(t, exe, nil)

	for name, want := range map[string][]byte{"install.sh": deploy.InstallSH, "install.ps1": deploy.InstallPS1} {
		resp, body := fetch(t, ts.URL+"/api/cluster/join/"+name)
		sum := sha256.Sum256(want)
		if resp.StatusCode != 200 || string(body) != string(want) || resp.Header.Get("X-Signalith-SHA256") != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: %d sha %q", name, resp.StatusCode, resp.Header.Get("X-Signalith-SHA256"))
		}
		if resp.Header.Get("Cache-Control") != "no-store" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
			t.Errorf("%s headers %v", name, resp.Header)
		}
	}

	resp, body := fetch(t, ts.URL+"/api/cluster/join/binary?os=linux&arch=amd64")
	sum := sha256.Sum256(program)
	if resp.StatusCode != 200 || string(body) != string(program) || resp.Header.Get("X-Signalith-SHA256") != hex.EncodeToString(sum[:]) {
		t.Errorf("binary: %d %q %q", resp.StatusCode, body, resp.Header.Get("X-Signalith-SHA256"))
	}
	// Only its own kind of machine.
	if resp, _ := fetch(t, ts.URL+"/api/cluster/join/binary?os=windows&arch=amd64"); resp.StatusCode != 404 {
		t.Errorf("windows from a linux server: %d", resp.StatusCode)
	}
	// Two downloads an hour from one address here (PerHour: 2).
	fetch(t, ts.URL+"/api/cluster/join/binary?os=linux&arch=amd64")
	if resp, _ := fetch(t, ts.URL+"/api/cluster/join/binary?os=linux&arch=amd64"); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("third download in an hour: %d", resp.StatusCode)
	}
	// The scripts have a limit of their own (PerHour: 4 here), shared by
	// Add a server's and the sensor's: two were taken above.
	fetch(t, ts.URL+"/api/sensor/install.sh")
	fetch(t, ts.URL+"/api/cluster/join/install.sh")
	if resp, _ := fetch(t, ts.URL+"/api/sensor/install.sh"); resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Errorf("fifth script download in an hour: %d", resp.StatusCode)
	}
}

// Without Install the routes answer 404, and the program is never
// handed out.
func TestInstallFilesOff(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, p := range []string{"install.sh", "install.ps1", "binary?os=" + runtime.GOOS + "&arch=" + runtime.GOARCH} {
		if resp, _ := fetch(t, ts.URL+"/api/cluster/join/"+p); resp.StatusCode != 404 {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
}

// The dialog's checklist says what keeps a new server from using
// OpenSearch as this one does.
func TestJoinPrepare(t *testing.T) {
	cases := []struct {
		name  string
		set   func(c *config.Config)
		dep   string
		codes string
	}{
		{"loopback http", func(c *config.Config) { c.OpenSearch.URL = "http://127.0.0.1:9200" }, "", "local,http,no_auth"},
		{"docker name", func(c *config.Config) {
			c.OpenSearch.URL, c.OpenSearch.CertFile, c.OpenSearch.KeyFile = "https://opensearch:9200", "c.pem", "k.pem"
		}, "docker", "docker"},
		{"docker with an address for new servers", func(c *config.Config) {
			c.OpenSearch.URL, c.OpenSearch.CertFile, c.OpenSearch.KeyFile = "https://opensearch:9200", "c.pem", "k.pem"
			c.Cluster.OpenSearchURL = "https://10.0.0.9:9200"
		}, "docker", ""},
		{"ready", func(c *config.Config) {
			c.OpenSearch.URL, c.OpenSearch.Username, c.OpenSearch.Password = "https://os1.example.com:9200", "signalith", "pw"
		}, "systemd", ""},
		{"skip verify", func(c *config.Config) {
			c.OpenSearch.URL, c.OpenSearch.Username, c.OpenSearch.Password, c.OpenSearch.TLSSkipVerify = "https://os1.example.com:9200", "signalith", "pw", true
		}, "", "skip_verify"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := installServer(t, "", func(s *Server) {
				tc.set(s.Config)
				s.Install.Deployment = tc.dep
			})
			code, out := do(t, ts, "GET", "/api/cluster/join/prepare", "", true)
			if code != 200 {
				t.Fatalf("%d %v", code, out)
			}
			o := out["opensearch"].(map[string]any)
			var codes []string
			for _, p := range o["problems"].([]any) {
				codes = append(codes, p.(map[string]any)["code"].(string))
			}
			if got := strings.Join(codes, ","); got != tc.codes {
				t.Errorf("problems %q, want %q (%v)", got, tc.codes, o)
			}
			if strings.Contains(o["own"].(string), "pw") {
				t.Errorf("password in %v", o)
			}
		})
	}
	ts := installServer(t, "", func(s *Server) {
		s.Users = users.NewMemory()
		s.Users.Create(t.Context(), users.NewUser{Username: "ana", Role: users.Analyst, Password: "role-password"})
	})
	if code, _ := doAs(t, ts, "ana", "role-password", "GET", "/api/cluster/join/prepare", ""); code != http.StatusForbidden {
		t.Errorf("analyst: %d", code)
	}
}

// checkCluster is one other server, at url.
type checkCluster struct {
	fakeCluster
	url string
}

func (c *checkCluster) Status() cluster.Status {
	hb := &cluster.Heartbeat{NodeID: "n_c", Name: "siem-c", Version: "1.5.0", NodeURL: c.url}
	return cluster.Status{Self: "n_a", Servers: []cluster.ServerStatus{
		{NodeID: "n_a", Name: "siem-a", Self: true, State: cluster.StateReady},
		{NodeID: "n_c", Name: "siem-c", State: cluster.StateStarting, Version: "1.5.0", HeartbeatAt: time.Now(), Detail: hb},
	}}
}

// The check reaches the new server at its node_url and trusts only the
// cluster's certificate authority.
func TestServerCheck(t *testing.T) {
	ready := true
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" || !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer peer.Close()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peer.Certificate().Raw}))
	cl := &checkCluster{url: peer.URL}
	ctls := &fakeClusterTLS{}
	ts := installServer(t, "", func(s *Server) { s.Cluster, s.ClusterTLS = cl, ctls })

	check := func() map[string]any {
		t.Helper()
		code, out := do(t, ts, "GET", "/api/cluster/servers/n_c/check", "", true)
		if code != 200 {
			t.Fatalf("%d %v", code, out)
		}
		return out
	}
	// Not the cluster's CA.
	if out := check(); out["result"] != "certificate" {
		t.Errorf("unknown certificate: %v", out)
	}
	ctls.body = &clustertls.Body{CACertPEM: caPEM}
	if out := check(); out["result"] != "ready" || out["name"] != "siem-c" {
		t.Errorf("ready: %v", out)
	}
	ready = false
	if out := check(); out["result"] != "not_ready" {
		t.Errorf("not ready: %v", out)
	}
	peer.Close()
	if out := check(); out["result"] != "unreachable" || !strings.Contains(out["detail"].(string), "Open TCP port") {
		t.Errorf("unreachable: %v", out)
	}
	cl.url = ""
	if out := check(); out["result"] != "no_address" {
		t.Errorf("no address: %v", out)
	}
	if code, _ := do(t, ts, "GET", "/api/cluster/servers/n_x/check", "", true); code != 404 {
		t.Errorf("unknown server: %d", code)
	}
}

// A join token's answer carries the one-line installs, with the SHA-256
// of the scripts and of this server's program they check.
func TestInstallLines(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "signalith")
	if err := os.WriteFile(exe, []byte("program"), 0o755); err != nil {
		t.Fatal(err)
	}
	ci := &ClusterInstall{Files: &clusterinstall.Files{Exe: exe, GOOS: "linux", GOARCH: "amd64"}}
	const tok = "SJ1.eyJ1IjoiaHR0cHM6Ly9zaWVtLWE6ODA4MCJ9"
	c, sums, err := ci.lines("https://siem-a:8080", tok, "1.5.0")
	if err != nil {
		t.Fatal(err)
	}
	sha := clusterinstall.ScriptSHA256()
	bin := ci.Files.BinarySHA256()
	if sums["install.sh"] != sha.SH || sums["install.ps1"] != sha.PS1 || sums["linux/amd64"] != bin || bin == "" {
		t.Errorf("sums = %v", sums)
	}
	if !strings.Contains(c.Linux, "echo '"+tok+"' | sudo sh") || !strings.Contains(c.Linux, "--sha256 "+bin) || c.LinuxNote != "" {
		t.Errorf("linux = %q (%q)", c.Linux, c.LinuxNote)
	}
	if !strings.Contains(c.Windows, "-Join '"+tok+"'") || c.WindowsNote == "" || c.DockerRun == "" || !strings.Contains(c.Docker, "SIGNALITH_JOIN="+tok) {
		t.Errorf("windows = %q (%q), docker = %q %q", c.Windows, c.WindowsNote, c.Docker, c.DockerRun)
	}
	// Without install files, or for an address a line cannot carry, there
	// are none: the answer keeps the plain join lines.
	if _, _, err := (*ClusterInstall)(nil).lines("https://siem-a:8080", tok, "1.5.0"); err == nil {
		t.Error("lines without install files")
	}
	if _, _, err := ci.lines("https://siem-a:8080/x;rm", tok, "1.5.0"); err == nil {
		t.Error("lines for a bad address")
	}
}
