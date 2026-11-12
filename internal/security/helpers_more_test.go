// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/intel"
)

func TestWordsAndNumbers(t *testing.T) {
	for s, want := range map[State]string{Risk: "At risk", Attention: "Needs attention", Unknown: "Can't tell", Good: "Good"} {
		if got := s.Word(); got != want {
			t.Errorf("%s.Word() = %q", s, got)
		}
	}
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 1234567: "1,234,567"} {
		if got := thousands(n); got != want {
			t.Errorf("thousands(%d) = %q", n, got)
		}
	}
	long := strings.Repeat("é", 100) // 200 bytes
	for in, want := range map[string]string{
		"one line":               "one line",
		"first\nsecond":          "first",
		long:                     strings.Repeat("é", 80) + "...",
		"x" + long[:199]:         "x" + strings.Repeat("é", 79) + "...",
		strings.Repeat("a", 160): strings.Repeat("a", 160),
	} {
		if got := short(in); got != want {
			t.Errorf("short(%.20q...) = %.30q..., len %d", in, got, len(got))
		}
	}
	now := time.Now()
	for d, want := range map[time.Duration]string{
		30 * time.Second: "just now", 10 * time.Minute: "10 minutes ago", 90 * time.Minute: "an hour ago",
		5 * time.Hour: "5 hours ago", 72 * time.Hour: "3 days ago",
	} {
		if got := ago(now, now.Add(-d)); got != want {
			t.Errorf("ago(%v) = %q", d, got)
		}
	}
	for _, c := range []struct {
		items []string
		want  string
	}{
		{nil, ""},
		{[]string{"a"}, "a"},
		{[]string{"a", "b", "c"}, "a, b or c"},
		{[]string{"a", "b", "c", "d", "e"}, "a, b, c or 2 more"},
	} {
		if got := orList(c.items, 3); got != c.want {
			t.Errorf("orList(%v) = %q", c.items, got)
		}
	}
	for b, want := range map[int64]string{
		10: "1 KB", 5 << 20: "5 MB", 3 << 30: "3 GB", 3<<30 + 512<<20: "3.5 GB", 12<<30 + 512<<20: "12 GB",
	} {
		if got := sizeOf(b); got != want {
			t.Errorf("sizeOf(%d) = %q", b, got)
		}
	}
	for n, want := range map[int]string{0: "in less than a day", 1: "in 1 day", 9: "in 9 days"} {
		if got := inDays(n); got != want {
			t.Errorf("inDays(%d) = %q", n, got)
		}
	}
	if h, p := listenHost("0.0.0.0:8080"); h != "0.0.0.0" || p != "8080" {
		t.Errorf("listenHost %q %q", h, p)
	}
	if h, p := listenHost("no port"); h != "" || p != "" {
		t.Errorf("listenHost bad %q %q", h, p)
	}
	if s, h, hp := urlParts("HTTPS://os.example:9200/x"); s != "https" || h != "os.example" || hp != "os.example:9200" {
		t.Errorf("urlParts %q %q %q", s, h, hp)
	}
	if s, h, hp := urlParts("http://[::1"); s != "" || h != "" || hp != "" {
		t.Errorf("urlParts bad %q %q %q", s, h, hp)
	}
	if groupIndex("no such group") != len(Groups) || groupIndex(Groups[0].ID) != 0 {
		t.Error("groupIndex")
	}
	if processWhy(ProcessFacts{Why: "denied"}) != "denied" || !strings.Contains(processWhy(ProcessFacts{}), "couldn't read") {
		t.Error("processWhy")
	}
}

func TestFeedsFrom(t *testing.T) {
	views := []intel.FeedView{
		{Name: "off", URL: "https://a.example", Enabled: false},
		{Name: "open", URL: "https://b.example", Enabled: true},
		{Name: "user", URL: "https://c.example", Enabled: true, Username: "svc"},
		{Name: "pass", URL: "https://d.example", Enabled: true, Password: intel.SecretView{Set: true}},
		{Name: "hdr", URL: "https://e.example", Enabled: true, HasHeaders: true},
	}
	got := FeedsFrom(views)
	want := []Feed{{"open", "https://b.example", false}, {"user", "https://c.example", true}, {"pass", "https://d.example", true}, {"hdr", "https://e.example", true}}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %+v, want %+v", i, got[i], want[i])
		}
	}
	if FeedsFrom(nil) != nil {
		t.Error("no feeds")
	}
}

func TestServerHostAndInfo(t *testing.T) {
	c := loadConfig(t, httpsAuto)
	h := ServerHost(c, false)
	if h.GOOS != runtime.GOOS || h.PID != "self" || h.Docker || h.Config != c {
		t.Errorf("host %+v", h)
	}
	if DockerQuickStart(func(string) string { return "" }) {
		t.Error("an empty environment is the Docker quick start")
	}
	info := ServerInfoFor(Host{GOOS: "linux", Systemd: true}, "siem-1", "v1.2.3")
	if info.Name != "siem-1" || info.Version != "v1.2.3" || info.OS != "linux" || info.Go != runtime.Version() || info.Deployment != DeployLinuxSystemd {
		t.Errorf("info %+v", info)
	}
	dock := ServerInfoFor(Host{GOOS: "linux", Docker: true, InContainer: true}, "s", "v")
	if dock.Deployment != DeployDocker || dock.DeploymentLabel != "Docker container" {
		t.Errorf("docker %+v", dock)
	}
}

func TestDenyAndRun(t *testing.T) {
	f := goodFacts(t, "")
	f.Deny("transit.https", "host.files")
	f.Deny("host.service")
	r := Run(context.Background(), f, []Collector{{Name: "noop", Checks: []string{"x"}, Run: func(context.Context) func(*Facts) {
		return func(f *Facts) { f.Uptime = 72 * time.Hour }
	}}})
	if f.Uptime != 72*time.Hour {
		t.Error("collector not applied")
	}
	for _, id := range []string{"transit.https", "host.service"} {
		c := r.Find(id)
		if c == nil || c.State != Unknown || c.Line != DeniedLine("linux") {
			t.Errorf("%s: %+v", id, c)
		}
	}
	if c := r.Find("rest.master_key"); c != nil && c.State == Unknown && c.Line == DeniedLine("linux") {
		t.Errorf("a check not denied was: %+v", c)
	}
}

func TestSameNetwork(t *testing.T) {
	ctx := context.Background()
	// Loopback addresses are never "the same network".
	if sameNetwork(ctx, "127.0.0.1") {
		t.Error("loopback counted as the same network")
	}
	if sameNetwork(ctx, "host.invalid") {
		t.Error("a name that does not resolve is on the same network")
	}
	// This computer's own non-loopback address is on its network.
	list, _ := net.InterfaceAddrs()
	for _, a := range list {
		p, err := netip.ParsePrefix(a.String())
		if err != nil || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
			continue
		}
		if !sameNetwork(ctx, p.Addr().String()) {
			t.Errorf("own address %s is not on the same network", p.Addr())
		}
		break
	}
}
