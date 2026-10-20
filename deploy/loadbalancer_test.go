// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every HAProxy backend in the load balancer sample checks /readyz, so a
// server that is not ready gets no traffic on any port, syslog included,
// and sends the checks with a PROXY header like the traffic.
func TestHAProxyBackendsCheckReadyz(t *testing.T) {
	b, err := os.ReadFile("loadbalancer/haproxy.cfg")
	if err != nil {
		t.Fatal(err)
	}
	backends := map[string][]string{}
	name := ""
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 0 || strings.HasPrefix(f[0], "#"):
		case !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t"):
			name = ""
			if f[0] == "backend" && len(f) > 1 {
				name = f[1]
				backends[name] = nil
			}
		case name != "":
			backends[name] = append(backends[name], strings.Join(f, " "))
		}
	}
	for _, want := range []string{"signalith_web", "signalith_agents", "signalith_syslog_tls", "signalith_syslog_tcp"} {
		if _, ok := backends[want]; !ok {
			t.Errorf("no backend %s", want)
		}
	}
	for name, lines := range backends {
		has := func(s string) bool {
			for _, l := range lines {
				if l == s || strings.HasPrefix(l, "default-server ") && strings.Contains(" "+l+" ", " "+s+" ") {
					return true
				}
			}
			return false
		}
		for _, want := range []string{"option httpchk GET /readyz", "http-check expect status 200", "check", "send-proxy-v2", "check-send-proxy"} {
			if !has(want) {
				t.Errorf("backend %s lacks %q", name, want)
			}
		}
		// The syslog ports have no /readyz: their checks go to the web port.
		if strings.Contains(name, "syslog") && !has("port 9000") {
			t.Errorf("backend %s does not check the web port (check port 9000)", name)
		}
	}
}

// Every keepalived real server is checked with /readyz on its web port,
// not with a bare TCP connect.
func TestKeepalivedChecksReadyz(t *testing.T) {
	b, err := os.ReadFile("loadbalancer/keepalived.conf")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "TCP_CHECK") {
		t.Error("keepalived.conf still has a TCP_CHECK")
	}
	servers := regexp.MustCompile(`real_server (\S+) \d+ \{`).FindAllStringSubmatchIndex(s, -1)
	if len(servers) == 0 {
		t.Fatal("no real_server in keepalived.conf")
	}
	for i, m := range servers {
		addr, end := s[m[2]:m[3]], len(s)
		if i+1 < len(servers) {
			end = servers[i+1][0]
		}
		block := s[m[1]:end]
		if !strings.Contains(block, "MISC_CHECK") || !strings.Contains(block, "http://"+addr+":9000/readyz") {
			t.Errorf("real_server %s is not checked with /readyz on its own web port:\n%s", addr, block)
		}
	}
}
