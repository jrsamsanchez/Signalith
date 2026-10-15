//go:build integration && linux

package integration

// Servers > Add a server, end to end: a member makes a join token whose
// answer carries the one-line installs; a new server downloads the
// install script and the program they name and finds the SHA-256 the
// lines check; it joins as the Docker server file starts it
// (SIGNALITH_JOIN, SIGNALITH_LISTEN, SIGNALITH_NODE_URL); and the member
// then reaches it at its node address (the dialog's last step).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// adminGet GETs path on s as the admin and decodes its JSON answer.
func (s *testServer) adminGet(path string, v any) (int, error) {
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d%s", s.port, path), nil)
	req.SetBasicAuth("admin", clusterPassword)
	resp, err := s.api.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if v != nil && resp.StatusCode == http.StatusOK {
		return resp.StatusCode, json.Unmarshal(b, v)
	}
	return resp.StatusCode, nil
}

// publicSHA256 downloads path from s without signing in and returns its
// SHA-256.
func (s *testServer) publicSHA256(t *testing.T, path string) string {
	t.Helper()
	resp, err := s.api.Get(fmt.Sprintf("https://127.0.0.1:%d%s", s.port, path))
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	h := sha256.New()
	if _, err := io.Copy(h, resp.Body); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, %v", path, resp.StatusCode, err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestClusterAddServer(t *testing.T) {
	h, o := newJoinHarness(t)
	a := addJoinServer(h, o, "siem-a", true)
	a.start()

	// The token, with the lines the dialog shows.
	var out string
	var code int
	waitUntil(t, 60*time.Second, "siem-a makes a join token", func() bool {
		out, code = a.runCode("cluster", "token", "-url", fmt.Sprintf("https://127.0.0.1:%d", a.port), "-json")
		return code == 0
	})
	var ans struct {
		Token    string            `json:"token"`
		Commands map[string]string `json:"commands"`
	}
	if err := json.Unmarshal([]byte(out[strings.Index(out, "{"):strings.LastIndex(out, "}")+1]), &ans); err != nil {
		t.Fatalf("token -json: %v\n%s", err, out)
	}
	linux := ans.Commands["linux"]
	if !strings.Contains(linux, "echo '"+ans.Token+"' | sudo sh") || !strings.HasSuffix(linux, "--join -") ||
		!strings.Contains(ans.Commands["docker"], "SIGNALITH_JOIN="+ans.Token) || ans.Commands["docker_run"] == "" {
		t.Fatalf("the lines:\n%v", ans.Commands)
	}

	// What the Linux line checks is what siem-a hands out.
	script := regexp.MustCompile(`echo "([0-9a-f]{64})  \$f"`).FindStringSubmatch(linux)
	if script == nil || a.publicSHA256(t, "/api/cluster/join/install.sh") != script[1] {
		t.Errorf("install.sh is not the one the line names: %s", linux)
	}
	bin := regexp.MustCompile(`--sha256 ([0-9a-f]{64})`).FindStringSubmatch(linux)
	if bin == nil || a.publicSHA256(t, "/api/cluster/join/binary?os=linux&arch="+runtime.GOARCH) != bin[1] {
		t.Errorf("the program is not the one the line names: %s", linux)
	}

	// The new server, started as docker-compose.server.yml starts it.
	b := addJoinServer(h, o, "siem-b", false)
	nodeURL := fmt.Sprintf("https://127.0.0.1:%d", b.port)
	for k, v := range map[string]string{"SIGNALITH_JOIN": ans.Token, "SIGNALITH_LISTEN": fmt.Sprintf("127.0.0.1:%d", b.port), "SIGNALITH_NODE_URL": nodeURL} {
		t.Setenv(k, v)
	}
	b.start()
	for _, k := range []string{"SIGNALITH_JOIN", "SIGNALITH_LISTEN", "SIGNALITH_NODE_URL"} {
		os.Unsetenv(k)
	}
	if strings.Contains(b.logTail(400), ans.Token) {
		t.Error("the token is in the new server's log")
	}
	waitUntil(t, 60*time.Second, "siem-b is a member", func() bool {
		st, ok := b.clusterStatus()
		return ok && st.Shared.Mode == "member"
	})

	// The dialog follows the token to the server that used it, then
	// checks that siem-a reaches it.
	var id string
	waitUntil(t, 60*time.Second, "siem-a lists the token as used by siem-b", func() bool {
		var v struct {
			Tokens []struct {
				UsedBy *struct {
					NodeID string `json:"node_id"`
					Name   string `json:"name"`
				} `json:"used_by"`
			} `json:"tokens"`
		}
		if c, err := a.adminGet("/api/cluster", &v); c != http.StatusOK || err != nil {
			return false
		}
		for _, tk := range v.Tokens {
			if tk.UsedBy != nil && tk.UsedBy.Name == "siem-b" {
				id = tk.UsedBy.NodeID
				return true
			}
		}
		return false
	})
	var check struct {
		Result  string `json:"result"`
		NodeURL string `json:"node_url"`
	}
	waitUntil(t, 60*time.Second, "siem-a reaches siem-b", func() bool {
		c, err := a.adminGet("/api/cluster/servers/"+id+"/check", &check)
		return c == http.StatusOK && err == nil && check.Result == "ready"
	})
	if check.NodeURL != nodeURL {
		t.Errorf("siem-b's address = %q, want %q", check.NodeURL, nodeURL)
	}

	// A restart keeps the server joined and ignores the used token.
	b.kill9()
	t.Setenv("SIGNALITH_JOIN", ans.Token)
	b.start()
	os.Unsetenv("SIGNALITH_JOIN")
	if !strings.Contains(b.logTail(200), "SIGNALITH_JOIN is ignored") {
		t.Errorf("a restart did not ignore the token:\n%s", b.logTail(40))
	}
}
