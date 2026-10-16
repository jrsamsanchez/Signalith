package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A server added with docker-compose.server.yml runs Signalith alone,
// hardened as the quick start's, joins with SIGNALITH_JOIN, and keeps
// everything in its one volume.
func TestDockerComposeServer(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(dockerDir, "docker-compose.server.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Services map[string]composeService `yaml:"services"`
		Volumes  map[string]any            `yaml:"volumes"`
	}
	if err := yaml.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Services) != 1 {
		t.Fatalf("services %v, want signalith only", f.Services)
	}
	s, ok := f.Services["signalith"]
	if !ok {
		t.Fatal("no signalith service")
	}
	quick, _, _ := readCompose(t)
	q := quick["signalith"]
	if s.Image != q.Image || !s.ReadOnly || !slices.Equal(s.CapDrop, q.CapDrop) || !slices.Equal(s.SecurityOpt, q.SecurityOpt) || !slices.Equal(s.Tmpfs, q.Tmpfs) {
		t.Errorf("not hardened like the quick start: %+v", s)
	}
	for _, env := range []string{"SIGNALITH_JOIN=${SIGNALITH_JOIN:-}", "SIGNALITH_NODE_NAME=${SIGNALITH_NODE_NAME:-signalith-2}", "SIGNALITH_NODE_URL=${SIGNALITH_NODE_URL:-}"} {
		if !slices.Contains(s.Environment, env) {
			t.Errorf("environment %v lacks %s", s.Environment, env)
		}
	}
	if s.Hostname != "${SIGNALITH_NODE_NAME:-signalith-2}" {
		t.Errorf("hostname %q", s.Hostname)
	}
	if !slices.Equal(s.Volumes, []string{"signalith-data:/var/lib/signalith"}) || !slices.Equal(s.Command, []string{"serve", "-c", "/var/lib/signalith/signalith.yaml"}) {
		t.Errorf("volumes %v command %v", s.Volumes, s.Command)
	}
	if _, ok := f.Volumes["signalith-data"]; !ok || len(f.Volumes) != 1 {
		t.Errorf("volumes %v", f.Volumes)
	}
	// The container cannot open ports below 1024.
	for _, env := range []string{"SIGNALITH_LISTEN=0.0.0.0:9000", "SIGNALITH_AGENT_LISTEN=0.0.0.0:7779", "SIGNALITH_SYSLOG_UDP=0.0.0.0:5514", "SIGNALITH_SYSLOG_TCP=0.0.0.0:5514"} {
		if !slices.Contains(s.Environment, env) {
			t.Errorf("environment %v lacks %s", s.Environment, env)
		}
	}
	for _, port := range []string{"9000:9000", "7779:7779", "514:5514/udp", "514:5514/tcp", "6514:6514"} {
		if !slices.Contains(s.Ports, port) {
			t.Errorf("ports %v lack %s", s.Ports, port)
		}
	}
}

// The quick start opens OpenSearch's port to other servers only with the
// cluster profile, passing connections on as they are.
func TestDockerComposeClusterProfile(t *testing.T) {
	_, _, raw := readCompose(t)
	var f struct {
		Services map[string]struct {
			composeService `yaml:",inline"`
			Profiles       []string `yaml:"profiles"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(raw), &f); err != nil {
		t.Fatal(err)
	}
	p, ok := f.Services["opensearch-port"]
	if !ok {
		t.Fatal("no opensearch-port service")
	}
	if !slices.Equal(p.Profiles, []string{"cluster"}) || flagValue(p.Command, "-to") != "opensearch:9200" || p.Command[0] != "tcp-forward" || !p.ReadOnly {
		t.Errorf("opensearch-port %+v", p)
	}
	for name, s := range f.Services {
		if name != "opensearch-port" && slices.ContainsFunc(s.Ports, func(p string) bool { return strings.HasSuffix(p, ":9200") }) {
			t.Errorf("%s publishes OpenSearch's port without the profile", name)
		}
	}
	if f.Services["signalith"].Hostname != "${SIGNALITH_NODE_NAME:-signalith}" {
		t.Errorf("hostname %q", f.Services["signalith"].Hostname)
	}
}
