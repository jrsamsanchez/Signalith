// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/store"
)

func osAnswer(t *testing.T, status int, body string) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

func TestProbeAnonymousAnswers(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name      string
		status    int
		body      string
		state     string
		why       string
		notLoaded bool
	}{
		{"open", 200, `{"count":3}`, "open", "", false},
		{"closed", 401, "", "closed", "", false},
		{"forbidden", 403, "", "closed", "", false},
		{"odd status", 500, "boom", "unknown", "status 500", false},
		{"security not loaded", 503, "OpenSearch Security not initialized.", "unknown", "status 503", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			u := osAnswer(t, c.status, c.body)
			r := probeAnonymous(ctx, store.Config{URL: u}, "")
			if r.state != c.state || r.why != c.why || r.notLoaded != c.notLoaded || r.demo {
				t.Errorf("%+v", r)
			}
		})
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	if r := probeAnonymous(ctx, store.Config{URL: "http://" + closed}, "x"); r.state != "unknown" || r.why == "" || strings.Contains(r.why, closed+"/x-") {
		t.Errorf("unreachable: %+v", r)
	}
}

func TestProbeAuthInfoAnswers(t *testing.T) {
	ctx := context.Background()
	info, noPlugin, why, _ := probeAuthInfo(ctx, store.Config{URL: osAnswer(t, 200, `{"user_name":"signalith","roles":["r1"],"backend_roles":["b"]}`)})
	if noPlugin || why != "" || info.User != "signalith" || len(info.Roles) != 1 {
		t.Errorf("ok: %+v %v %q", info, noPlugin, why)
	}
	if _, noPlugin, _, _ := probeAuthInfo(ctx, store.Config{URL: osAnswer(t, 400, "no handler found for uri")}); !noPlugin {
		t.Error("no plugin not seen")
	}
	if _, noPlugin, why, _ := probeAuthInfo(ctx, store.Config{URL: osAnswer(t, 403, `{"error":"no"}`)}); noPlugin || why != "status 403" {
		t.Errorf("refused: %v %q", noPlugin, why)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	if _, _, why, _ := probeAuthInfo(ctx, store.Config{URL: "http://" + closed}); why == "" {
		t.Error("unreachable: no reason")
	}
}

func TestProbeDataPathsAnswers(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name string
		body string
		want string
		fail bool
	}{
		{"one folder", `{"nodes":{"n":{"settings":{"path":{"data":"/var/lib/os","home":"/usr/share/os"}}}}}`, "/var/lib/os", false},
		{"a list, relative", `{"nodes":{"n":{"settings":{"path":{"data":["d1","/abs"],"home":"/os"}}}}}`, "/os/d1,/abs", false},
		{"home only", `{"nodes":{"n":{"settings":{"path":{"home":"/os"}}}}}`, "/os/data", false},
		{"windows", `{"nodes":{"n":{"settings":{"path":{"data":"C:\\os\\data","home":"C:\\os"}}}}}`, `C:\os\data`, false},
		{"nothing said", `{"nodes":{"n":{"settings":{"path":{}}}}}`, "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := probeDataPaths(ctx, store.Config{URL: osAnswer(t, 200, c.body)})
			if (err != nil) != c.fail || strings.Join(got, ",") != c.want {
				t.Errorf("%v %v", got, err)
			}
		})
	}
	if _, err := probeDataPaths(ctx, store.Config{URL: osAnswer(t, 403, "no")}); err == nil || err.Error() != "status 403" {
		t.Errorf("refused: %v", err)
	}
}

func TestListensOnNetworkAndPorts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	lo := netip.MustParseAddr("127.0.0.1")
	if !listensOnNetwork(context.Background(), []netip.Addr{lo, netip.MustParseAddr("127.0.0.2")}, port) {
		t.Error("a listening port not found")
	}
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	_, closed, _ := net.SplitHostPort(ln2.Addr().String())
	ln2.Close()
	if listensOnNetwork(context.Background(), []netip.Addr{lo}, closed) {
		t.Error("a closed port found")
	}
	for raw, want := range map[string]string{"https://os": "443", "http://os": "80", "http://os:9200": "9200", "http://[::1": ""} {
		if got := urlPort(raw); got != want {
			t.Errorf("urlPort(%s) = %q", raw, got)
		}
	}
	if cleanNetError(context.DeadlineExceeded) != "no answer in time" {
		t.Error("cleanNetError timeout")
	}
}
