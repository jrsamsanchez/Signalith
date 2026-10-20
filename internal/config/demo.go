// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net/netip"
)

// Demo turns a server into a public, read-only demo filled with the
// sample data (see docs/demo.md). It is off by default. Only
// signalith.yaml and the environment set it, never a page: a page that
// could turn it off could undo every restriction it makes.
//
// While it is on, visitors sign in with one click as a built-in viewer,
// password sign-in works only from AdminNetworks, and everything that
// takes events in or reaches out to other systems is off whatever the
// other settings say: agents, syslog, HEC and OTLP intake, the AI
// assistant, notifications, ticketing, chat buttons, response actions,
// playbooks, vulnerability scans, threat intel downloads, Microsoft 365
// and Okta, single sign-on and SCIM. The sample data is loaded again
// every day, so it stays within the last week.
type Demo struct {
	// Enabled turns demo mode on. SIGNALITH_DEMO overrides it.
	Enabled bool `yaml:"enabled,omitempty"`
	// AdminNetworks lists the IP addresses or CIDRs password sign-in
	// (the web page, HTTP Basic and API tokens) still works from, such as
	// the admin's own address or a VPN. Empty allows it from nowhere, so
	// the server is managed only from its own shell.
	// SIGNALITH_DEMO_ADMIN_NETWORKS overrides it.
	AdminNetworks []string `yaml:"admin_networks,omitempty"`
}

// DemoOn reports whether the server is a public demo (demo.enabled).
func (c *Config) DemoOn() bool { return c != nil && c.Demo.Enabled }

// DemoAdminNetworks returns demo.admin_networks as prefixes; invalid
// entries are left out (Validate reports them).
func (c *Config) DemoAdminNetworks() []netip.Prefix {
	var out []netip.Prefix
	for _, a := range c.Demo.AdminNetworks {
		if p, err := parseAllow(a); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func (d *Demo) problems() []string {
	var p []string
	for i, a := range d.AdminNetworks {
		if _, err := parseAllow(a); err != nil {
			p = append(p, fmt.Sprintf("demo.admin_networks[%d] %q must be an IP address or a CIDR such as 198.51.100.7/32", i, a))
		}
	}
	return p
}
