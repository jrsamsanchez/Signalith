// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/oidc"
)

// OIDC is single sign-on with an OpenID Connect identity provider, set
// on the Single sign-on tab of Settings or in signalith.yaml (auth.oidc).
// It works alongside the built-in admin, local users and directory
// sign-in. See docs/sso.md.
type OIDC struct {
	// Enabled turns single sign-on on. Settings can be saved half
	// finished while it is off.
	Enabled bool `yaml:"enabled,omitempty"`
	// Provider is entra, okta, google, keycloak or other. It picks the
	// defaults of the claims and scopes.
	Provider string `yaml:"provider,omitempty"`
	// Issuer is the provider's issuer address, as its discovery document
	// names it. Google's is filled in.
	Issuer       string `yaml:"issuer,omitempty"`
	ClientID     string `yaml:"client_id,omitempty"`
	ClientSecret string `yaml:"client_secret,omitempty"`
	// Scopes are asked for besides openid; empty asks for the provider's
	// usual ones.
	Scopes []string `yaml:"scopes,omitempty"`
	// UsernameClaim names the claim that becomes the Signalith username,
	// and GroupsClaim the one listing the user's groups or roles (a dotted
	// name such as realm_access.roles looks inside nested claims).
	UsernameClaim string `yaml:"username_claim,omitempty"`
	GroupsClaim   string `yaml:"groups_claim,omitempty"`
	// Groups (or verified email addresses) whose members get each role.
	// Someone in several gets the highest.
	AdminGroups   []string `yaml:"admin_groups,omitempty"`
	AnalystGroups []string `yaml:"analyst_groups,omitempty"`
	ViewerGroups  []string `yaml:"viewer_groups,omitempty"`
	// DefaultRole is for people in no mapped group: none (refused, the
	// default) or viewer.
	DefaultRole string `yaml:"default_role,omitempty"`
	// AllowedDomains, when set, lets in only people whose verified email
	// address is in one of these domains.
	AllowedDomains []string `yaml:"allowed_domains,omitempty"`
	// CreateUsers adds people as users on their first sign-in (the
	// default); off, only users who signed in before can.
	CreateUsers *bool `yaml:"create_users,omitempty"`
	// ButtonLabel is the sign-in page's button; empty is "Sign in with"
	// and the provider's name.
	ButtonLabel string `yaml:"button_label,omitempty"`
}

// OIDCOn reports whether single sign-on is set up and on: never in demo
// mode.
func (c *Config) OIDCOn() bool { return c.Auth.OIDC.Enabled && !c.DemoOn() }

// OIDCIssuer returns the issuer in use: the one set, or Google's.
func (c *Config) OIDCIssuer() string {
	o := c.Auth.OIDC
	if strings.TrimSpace(o.Issuer) == "" && o.Provider == oidc.Google {
		return oidc.GoogleIssuer
	}
	return strings.TrimSpace(o.Issuer)
}

// OIDCSettings is the single sign-on setting with every empty value
// filled in from the provider's preset.
type OIDCSettings struct {
	OIDC
	Preset oidc.Preset
}

// OIDCSettings returns the single sign-on settings in use.
func (c *Config) OIDCSettings() OIDCSettings {
	o := c.Auth.OIDC
	p := oidc.PresetFor(o.Provider)
	o.Issuer = c.OIDCIssuer()
	o.ClientID = strings.TrimSpace(o.ClientID)
	if len(o.Scopes) == 0 {
		o.Scopes = p.Scopes
	}
	if o.UsernameClaim == "" {
		o.UsernameClaim = p.UsernameClaim
	}
	if o.GroupsClaim == "" {
		o.GroupsClaim = p.GroupsClaim
	}
	if o.DefaultRole == "" {
		o.DefaultRole = "none"
	}
	if o.ButtonLabel == "" {
		o.ButtonLabel = "Sign in with " + strings.TrimPrefix(p.Label, "Microsoft ")
		if o.Provider == oidc.Other {
			o.ButtonLabel = "Sign in with single sign-on"
		}
	}
	return OIDCSettings{OIDC: o, Preset: p}
}

// NewUsers reports whether people are added as users on their first
// sign-in.
func (s OIDCSettings) NewUsers() bool { return s.CreateUsers == nil || *s.CreateUsers }

var (
	claimPattern  = regexp.MustCompile(`^[A-Za-z0-9_:/.\-]{1,200}$`)
	domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

// oidcProblems checks auth.oidc. Values that are empty are only required
// while single sign-on is on.
func (c *Config) oidcProblems() []string {
	o := c.Auth.OIDC
	var p []string
	add := func(key, format string, args ...any) {
		p = append(p, "auth.oidc."+key+": "+fmt.Sprintf(format, args...))
	}
	on := o.Enabled
	switch o.Provider {
	case oidc.Entra, oidc.Okta, oidc.Google, oidc.Keycloak, oidc.Other:
	case "":
		if on {
			add("provider", "choose the identity provider: entra, okta, google, keycloak or other")
		}
	default:
		add("provider", "%q must be entra, okta, google, keycloak or other", o.Provider)
	}
	if issuer := c.OIDCIssuer(); issuer != "" {
		if msg := oidc.CheckIssuer(issuer); msg != "" {
			add("issuer", "%s", msg)
		}
	} else if on {
		add("issuer", "enter the issuer address, like %s", oidc.PresetFor(o.Provider).IssuerExample)
	}
	if on && strings.TrimSpace(o.ClientID) == "" {
		add("client_id", "enter the client ID (application ID) the identity provider gave Signalith")
	}
	for _, k := range []struct{ key, v string }{{"username_claim", o.UsernameClaim}, {"groups_claim", o.GroupsClaim}} {
		if k.v != "" && !claimPattern.MatchString(k.v) {
			add(k.key, "%q is not a claim name, like groups or realm_access.roles", k.v)
		}
	}
	for _, s := range o.Scopes {
		if strings.ContainsAny(s, " \t\"\\") || s == "" {
			add("scopes", "%q is not a scope; list one per line, like email", s)
		}
	}
	switch o.DefaultRole {
	case "", "none", "viewer":
	default:
		add("default_role", "%q must be none or viewer", o.DefaultRole)
	}
	for _, d := range o.AllowedDomains {
		if !domainPattern.MatchString(strings.ToLower(strings.TrimSpace(d))) {
			add("allowed_domains", "%q is not a domain, like example.com", d)
		}
	}
	if len(o.ButtonLabel) > 60 {
		add("button_label", "keep the button label to 60 characters")
	}
	if on && o.DefaultRole != "viewer" && len(o.AdminGroups)+len(o.AnalystGroups)+len(o.ViewerGroups) == 0 {
		add("admin_groups", "map at least one group to a role, or let people in no mapped group in as viewers; otherwise nobody can sign in")
	}
	if on && o.Provider == oidc.Google && o.DefaultRole == "viewer" && len(o.AllowedDomains) == 0 {
		add("allowed_domains", "with Google, list your domain here, or anyone with a Google account could sign in as a viewer")
	}
	return p
}

// OIDCRole returns the role groups (and a verified email address) give
// with s: the highest that matches, the default role when none does, or
// "" when someone may not sign in. It also returns what matched.
func (s OIDCSettings) OIDCRole(groups []string, email string) (string, []string) {
	return mapRole(s.AdminGroups, s.AnalystGroups, s.ViewerGroups, s.DefaultRole, groups, email)
}

// mapRole returns the role groups (and an email address) give with the
// group lists of each role: the highest that matches, defaultRole
// (viewer) when none does, or "" when someone may not sign in. It also
// returns what matched.
func mapRole(admins, analysts, viewers []string, defaultRole string, groups []string, email string) (string, []string) {
	role := ""
	var matched []string
	rank := map[string]int{"viewer": 1, "analyst": 2, "admin": 3}
	try := func(v string) {
		hit := false
		for _, m := range []struct {
			role string
			list []string
		}{{"admin", admins}, {"analyst", analysts}, {"viewer", viewers}} {
			if slices.ContainsFunc(m.list, func(g string) bool { return strings.EqualFold(strings.TrimSpace(g), v) }) {
				hit = true
				if rank[m.role] > rank[role] {
					role = m.role
				}
			}
		}
		if hit && !slices.Contains(matched, v) {
			matched = append(matched, v)
		}
	}
	for _, g := range groups {
		try(g)
	}
	if email != "" {
		try(email)
	}
	if role == "" && defaultRole == "viewer" {
		role = "viewer"
	}
	return role, matched
}

// DomainAllowed reports whether a verified email address may sign in
// with s: always when no domains are listed.
func (s OIDCSettings) DomainAllowed(email string) bool {
	if len(s.AllowedDomains) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	return slices.ContainsFunc(s.AllowedDomains, func(d string) bool { return strings.EqualFold(strings.TrimSpace(d), domain) })
}
