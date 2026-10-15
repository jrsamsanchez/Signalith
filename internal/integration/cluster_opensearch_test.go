//go:build integration && linux

package integration

// Servers with two addresses for one OpenSearch keep working when one
// address stops answering: events keep being stored, the server running
// the background jobs keeps them, and the Servers page shows the address
// as down. Each address is a TCP relay to the test's OpenSearch (real or
// fake), so taking one down is closing it.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// relay forwards TCP connections to an OpenSearch address until it is
// taken down.
type relay struct {
	l     net.Listener
	mu    sync.Mutex
	conns map[net.Conn]bool
	down  bool
}

func newRelay(t *testing.T, target string) *relay {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{l: l, conns: map[net.Conn]bool{}}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go r.pipe(c, target)
		}
	}()
	t.Cleanup(r.Down)
	return r
}

func (r *relay) pipe(c net.Conn, target string) {
	up, err := net.Dial("tcp", target)
	if err != nil {
		c.Close()
		return
	}
	r.mu.Lock()
	if r.down {
		r.mu.Unlock()
		c.Close()
		up.Close()
		return
	}
	r.conns[c], r.conns[up] = true, true
	r.mu.Unlock()
	go func() { _, _ = io.Copy(up, c); up.Close() }()
	_, _ = io.Copy(c, up)
	c.Close()
}

// Down stops taking connections and cuts those open, as when an
// OpenSearch node's machine goes away.
func (r *relay) Down() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.down = true
	r.l.Close()
	for c := range r.conns {
		c.Close()
	}
}

// url is the relay's address in place of target's host and port.
func (r *relay) url(t *testing.T, target *url.URL) string {
	host := "127.0.0.1"
	if target.Scheme == "https" {
		// The name in the test OpenSearch's certificate.
		host = "localhost"
	}
	_, port, _ := net.SplitHostPort(r.l.Addr().String())
	return target.Scheme + "://" + net.JoinHostPort(host, port)
}

const failoverToken = "failover-ingest-token-0123456789"

func TestClusterOpenSearchFailover(t *testing.T) {
	t.Parallel()
	h := newClusterHarness(t)
	target, err := url.Parse(h.url)
	if err != nil {
		t.Fatal(err)
	}
	port := target.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[target.Scheme]
	}
	hostPort := net.JoinHostPort(target.Hostname(), port)
	first, second := newRelay(t, hostPort), newRelay(t, hostPort)
	firstURL, secondURL := first.url(t, target), second.url(t, target)

	servers := map[string]*testServer{}
	for _, name := range []string{"siem-a", "siem-b"} {
		s := h.add(name, serverOptions{opensearch: firstURL, yaml: "ingest:\n  tokens: [" + failoverToken + "]\n"})
		cfgPath := filepath.Join(s.dir, "signalith.yaml")
		raw, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		raw = []byte(strings.Replace(string(raw), "opensearch:\n", fmt.Sprintf("opensearch:\n  urls: [%q]\n", secondURL), 1))
		if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		s.start()
		servers[name] = s
	}
	a, b := servers["siem-a"], servers["siem-b"]
	var holder string
	var epoch int64
	waitUntil(t, 45*time.Second, "one server runs the jobs", func() bool {
		v, ok := a.view()
		if !ok || len(v.Servers) != 2 || len(v.runners()) != 1 {
			return false
		}
		holder, epoch = v.Lease.HolderName, v.Lease.Epoch
		return holder != "" && epoch > 0
	})

	sent := 0
	send := func(s *testServer, what string) {
		t.Helper()
		body := fmt.Sprintf(`[{"log":%q}]`, syslogTime(time.Now().Add(-time.Minute))+
			fmt.Sprintf(" web1 sshd[%d]: Failed password for failover from 192.0.2.77 port 1 ssh2", sent))
		req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://127.0.0.1:%d/api/ingest", s.port), strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+failoverToken)
		req.Header.Set("X-Signalith-Tag", "linux.auth")
		resp, err := s.api.Do(req)
		if err != nil {
			t.Fatalf("%s through %s: %v", what, s.name, err)
		}
		out, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s through %s: %d %s", what, s.name, resp.StatusCode, out)
		}
		sent++
	}
	for range 3 {
		send(a, "before")
		send(b, "before")
	}

	first.Down()
	for range 10 {
		send(a, "with one address down")
		send(b, "with one address down")
		time.Sleep(500 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	events := h.prefix + "-*"
	if err := h.os.Do(ctx, http.MethodPost, "/"+events+"/_refresh", nil, nil); err != nil {
		t.Fatal(err)
	}
	var count struct {
		Count int `json:"count"`
	}
	if err := h.os.Do(ctx, http.MethodGet, "/"+events+"/_count", nil, &count); err != nil {
		t.Fatal(err)
	}
	if count.Count < sent {
		t.Errorf("%d events stored, %d sent", count.Count, sent)
	}

	// The same server runs the jobs, with the same lease.
	v, ok := b.view()
	if !ok || v.Lease.HolderName != holder || v.Lease.Epoch != epoch {
		t.Errorf("lease moved: %+v, was %s epoch %d", v.Lease, holder, epoch)
	}

	// The Servers page shows the first address as down.
	waitUntil(t, 15*time.Second, "the card shows the address down", func() bool {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/api/cluster/opensearch", a.port), nil)
		req.SetBasicAuth("admin", clusterPassword)
		resp, err := a.api.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		var card struct {
			Endpoints []struct {
				URL  string `json:"url"`
				Down bool   `json:"down"`
			} `json:"endpoints"`
		}
		if json.NewDecoder(resp.Body).Decode(&card) != nil || len(card.Endpoints) != 2 {
			return false
		}
		return card.Endpoints[0].URL == firstURL && card.Endpoints[0].Down && !card.Endpoints[1].Down
	})
}
