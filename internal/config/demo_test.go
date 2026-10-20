// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Demo mode is off by default, set in the file or the environment only,
// and its admin networks are checked.
func TestDemoSettings(t *testing.T) {
	if Default().DemoOn() {
		t.Fatal("demo mode is on by default")
	}
	for _, key := range []string{"demo.enabled", "demo.admin_networks"} {
		if _, ok := Lookup(key); ok {
			t.Errorf("%s is on the Settings page; only signalith.yaml and the environment may set it", key)
		}
		if ScopeOf(key) != ScopeServer {
			t.Errorf("%s has scope %q", key, ScopeOf(key))
		}
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "demo.yaml")
	os.WriteFile(path, []byte("demo:\n  enabled: true\n  admin_networks: [198.51.100.7, 2001:db8::/48]\n"), 0o600)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.DemoOn() {
		t.Error("demo.enabled in the file is not on")
	}
	want := []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32"), netip.MustParsePrefix("2001:db8::/48")}
	if got := c.DemoAdminNetworks(); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("admin networks = %v, want %v", got, want)
	}

	os.WriteFile(path, []byte("demo:\n  admin_networks: [not-an-address]\n"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "demo.admin_networks[0]") {
		t.Errorf("a bad admin network: %v", err)
	}

	os.WriteFile(path, []byte("search:\n  max_events: 500\n"), 0o600)
	t.Setenv("SIGNALITH_DEMO", "true")
	t.Setenv("SIGNALITH_DEMO_ADMIN_NETWORKS", "203.0.113.0/24, 198.51.100.9")
	if c, err = Load(path); err != nil {
		t.Fatal(err)
	}
	if !c.DemoOn() || len(c.DemoAdminNetworks()) != 2 {
		t.Errorf("from the environment: on=%v networks=%v", c.DemoOn(), c.DemoAdminNetworks())
	}
	t.Setenv("SIGNALITH_DEMO", "maybe")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "SIGNALITH_DEMO") {
		t.Errorf("SIGNALITH_DEMO=maybe: %v", err)
	}
}

// The demo's deploy recipe starts in demo mode, behind its reverse proxy,
// with no agent or syslog port.
func TestDemoDeployConfig(t *testing.T) {
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	for _, name := range []string{"SIGNALITH_DEMO", "SIGNALITH_DEMO_ADMIN_NETWORKS", "SIGNALITH_AGENT_LISTEN", "SIGNALITH_LISTEN",
		"SIGNALITH_PUBLIC_URL", "SIGNALITH_SYSLOG_UDP", "SIGNALITH_SYSLOG_TCP"} {
		t.Setenv(name, "")
	}
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	t.Setenv("SIGNALITH_PUBLIC_URL", "https://demo.example.com")
	b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "demo", "signalith.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// The OpenSearch files are the setup service's, in the container.
	var lines []string
	for _, l := range strings.Split(string(b), "\n") {
		if !strings.Contains(l, "/run/signalith-secrets/") {
			lines = append(lines, l)
		}
	}
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600)
	c, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.DemoOn() || len(c.DemoAdminNetworks()) != 0 || c.Server.AgentAddr() != "" || c.Syslog.Enabled() || c.Server.HTTPS() ||
		len(c.Server.TrustedProxyList()) != 1 || c.Server.ClientAddressHeader() != "X-Forwarded-For" {
		t.Errorf("deploy/demo/signalith.yaml: demo=%v networks=%v agents=%q syslog=%v https=%v proxies=%v header=%q",
			c.DemoOn(), c.DemoAdminNetworks(), c.Server.AgentAddr(), c.Syslog.Enabled(), c.Server.HTTPS(),
			c.Server.TrustedProxyList(), c.Server.ClientAddressHeader())
	}
}

// In demo mode everything that reaches other systems through the
// configuration is off, whatever else is set.
func TestDemoTurnsIntegrationsOff(t *testing.T) {
	c := Default()
	c.Auth.OIDC.Enabled = true
	c.Auth.SAML.Enabled = true
	c.Auth.SCIM.Enabled = true
	c.Auth.SCIM.TokenSHA256 = strings.Repeat("a", 64)
	c.M365 = M365{TenantID: "t", ClientID: "c", ClientSecret: "s"}
	c.Okta = Okta{Domain: "example.okta.com", APIToken: "x"}
	c.Assistant = Assistant{Provider: "anthropic", APIKey: "k", Model: "m"}
	if !c.OIDCOn() || !c.SAMLOn() || !c.SCIMOn() || !c.M365On() || !c.OktaOn() || c.AssistantClient() == nil {
		t.Fatal("the integrations should be on without demo mode")
	}
	c.Demo.Enabled = true
	if c.OIDCOn() || c.SAMLOn() || c.SCIMOn() || c.M365On() || c.OktaOn() || c.AssistantClient() != nil {
		t.Errorf("demo mode leaves on: oidc=%v saml=%v scim=%v m365=%v okta=%v assistant=%v",
			c.OIDCOn(), c.SAMLOn(), c.SCIMOn(), c.M365On(), c.OktaOn(), c.AssistantClient() != nil)
	}
}
