//go:build integration && linux

package integration

// Servers behind a load balancer that writes a PROXY protocol header: an
// in-test forwarder stands in for HAProxy, connecting from 127.0.0.2 (the
// one trusted proxy) and naming a client in a version 2 header. Signalith
// must count and log that client, not the balancer, and refuse a header
// from anyone else.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/proxyproto"
)

const (
	balancerAddr = "127.0.0.2"
	proxyToken   = "proxy-test-ingest-token-0123456789abcdef"
)

// proxyYAML turns PROXY protocol on with 127.0.0.2 trusted, and gives agents
// a token.
func proxyYAML(syslogPort int) string {
	y := "  trusted_proxies: [\"" + balancerAddr + "\"]\n  proxy_protocol: true\ningest:\n  tokens: [\"" + proxyToken + "\"]\n"
	if syslogPort > 0 {
		y += fmt.Sprintf("syslog:\n  tcp: 127.0.0.1:%d\n  proxy_protocol: true\n", syslogPort)
	}
	return y
}

// startProxied starts a server with proxyYAML, which goes under server:.
func startProxied(t *testing.T, h *clusterHarness, name string, syslogPort int) *testServer {
	t.Helper()
	s := h.add(name, serverOptions{})
	cfgPath := filepath.Join(s.dir, "signalith.yaml")
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(b), "server:\n", "server:\n"+strings.SplitN(proxyYAML(syslogPort), "ingest:", 2)[0], 1)
	cfg += "ingest:" + strings.SplitN(proxyYAML(syslogPort), "ingest:", 2)[1]
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	s.start()
	return s
}

// viaBalancer connects to port from the balancer's address and writes a
// PROXY v2 header naming client.
func viaBalancer(t *testing.T, port int, client string) net.Conn {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(balancerAddr)}, Timeout: 5 * time.Second}
	c, err := d.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Skipf("cannot connect from %s: %v", balancerAddr, err)
	}
	h := proxyproto.Header{Src: netip.MustParseAddrPort(client + ":40000"), Dst: netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port))}
	if _, err := c.Write(proxyproto.AppendV2(nil, h)); err != nil {
		t.Fatal(err)
	}
	return c
}

// clientVia is an HTTPS client whose every connection goes through the
// balancer as client.
func (s *testServer) clientVia(t *testing.T, client string) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join(s.dir, "tls", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return viaBalancer(t, s.port, client), nil
		},
	}}
}

func (s *testServer) health(t *testing.T, query string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/api/health%s", s.port, query), nil)
	req.SetBasicAuth("admin", clusterPassword)
	resp, err := s.api.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// sendBatch sends one agent batch through client c.
func sendBatch(t *testing.T, c *http.Client, port int) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://127.0.0.1:%d/api/ingest?tag=linux_secure", port),
		strings.NewReader(`[{"log":"Oct 14 20:30:00 web1 sshd[1]: Failed password for bob from 10.9.9.9 port 22 ssh2"}]`))
	req.Header.Set("Authorization", "Bearer "+proxyToken)
	req.Header.Set("X-Signalith-Agent", "web1")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ingest: %d %s", resp.StatusCode, b)
	}
}

func TestClusterProxySyslog(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	port := freePort(t)
	s := startProxied(t, h, "siem-a", port)

	c := viaBalancer(t, port, "203.0.113.7")
	fmt.Fprint(c, "<13>Oct 14 20:30:00 fw1 app: through the balancer\n")
	defer c.Close()
	waitUntil(t, 20*time.Second, "the device listed as a syslog sender", func() bool {
		sl, _ := s.health(t, "")["syslog"].(map[string]any)
		senders, _ := sl["senders"].([]any)
		return len(senders) == 1 && senders[0].(map[string]any)["address"] == "203.0.113.7"
	})

	// A header from anyone else is refused and counted.
	bad, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	bad.Write(proxyproto.AppendV2(nil, proxyproto.Header{Src: netip.MustParseAddrPort("198.51.100.1:1"), Dst: netip.MustParseAddrPort("127.0.0.1:1")}))
	fmt.Fprint(bad, "<13>Oct 14 20:30:00 forged app: hi\n")
	waitUntil(t, 20*time.Second, "the forged header counted", func() bool {
		sl, _ := s.health(t, "")["syslog"].(map[string]any)
		rb, _ := sl["rejected_by"].(map[string]any)
		return rb["proxy_untrusted"] == float64(1)
	})
}

func TestClusterProxyWeb(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	s := startProxied(t, h, "siem-a", 0)
	sendBatch(t, s.clientVia(t, "203.0.113.9"), s.port)
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/api/agents", s.port), nil)
	req.SetBasicAuth("admin", clusterPassword)
	resp, err := s.api.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), `"203.0.113.9"`) || strings.Contains(string(b), balancerAddr) {
		t.Errorf("agents: %s", b)
	}

	// A header from an address that is not a trusted proxy closes the
	// connection before TLS.
	raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.Write(proxyproto.AppendV2(nil, proxyproto.Header{Src: netip.MustParseAddrPort("198.51.100.1:1"), Dst: netip.MustParseAddrPort("127.0.0.1:1")}))
	raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := raw.Read(make([]byte, 1)); err == nil {
		t.Error("a PROXY header from an untrusted peer got an answer")
	}
	if !strings.Contains(s.logTail(200), "PROXY header from a peer that is not a trusted proxy") {
		t.Error("the refusal is not logged")
	}
}

func TestClusterHealthTotals(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	a := startProxied(t, h, "siem-a", 0)
	b := startProxied(t, h, "siem-b", 0)
	ca, cb := a.clientVia(t, "203.0.113.11"), b.clientVia(t, "203.0.113.12")
	// Heartbeats carry the figures, so each server totals both. A server
	// that restarts in place as it joins the cluster starts counting
	// again, so batches keep coming until both servers report some, and
	// the totals must equal the sum of the servers' figures.
	var last map[string]any
	defer func() {
		if t.Failed() {
			t.Logf("last cluster block: %v", last)
		}
	}()
	for _, s := range []*testServer{a, b} {
		waitUntil(t, 60*time.Second, s.name+" totals both servers", func() bool {
			sendBatch(t, ca, a.port)
			sendBatch(t, cb, b.port)
			c, _ := s.health(t, "?scope=cluster")["cluster"].(map[string]any)
			last = c
			tot, _ := c["totals"].(map[string]any)
			ing, _ := tot["ingest"].(map[string]any)
			rows, _ := c["servers"].([]any)
			if tot["servers"] != float64(2) || len(rows) != 2 {
				return false
			}
			sum := 0.0
			for _, r := range rows {
				n, _ := r.(map[string]any)["ingest"].(map[string]any)["batches"].(float64)
				if n == 0 {
					return false
				}
				sum += n
			}
			return ing["batches"] == sum
		})
	}
	if _, ok := a.health(t, "")["cluster"]; ok {
		t.Error("Health without scope=cluster has a cluster block")
	}
}
