// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/saml"
)

// SAML is single sign-on with a SAML 2.0 identity provider, such as AD
// FS, Okta or Microsoft Entra ID, set on the Single sign-on tab of
// Settings or in signalith.yaml (auth.saml). It works alongside OpenID
// Connect, local users, directory sign-in and the built-in admin. See
// docs/sso.md.
type SAML struct {
	Enabled bool `yaml:"enabled,omitempty"`
	// Provider is adfs, entra, okta or other. It picks the usual
	// attributes.
	Provider string `yaml:"provider,omitempty"`
	// MetadataURL is where the provider publishes its metadata (entity
	// ID, sign-in address and signing certificates); it is read again
	// every hour, so a new certificate is picked up. MetadataXML is the
	// metadata itself, for a provider Signalith cannot reach. Set one.
	MetadataURL string `yaml:"metadata_url,omitempty"`
	MetadataXML string `yaml:"metadata_xml,omitempty"`
	// UsernameAttribute names the attribute that becomes the Signalith
	// username (NameID for the subject's NameID), and GroupsAttribute
	// the one listing the user's groups.
	UsernameAttribute string `yaml:"username_attribute,omitempty"`
	GroupsAttribute   string `yaml:"groups_attribute,omitempty"`
	// Groups (or email addresses) whose members get each role. Someone
	// in several gets the highest.
	AdminGroups   []string `yaml:"admin_groups,omitempty"`
	AnalystGroups []string `yaml:"analyst_groups,omitempty"`
	ViewerGroups  []string `yaml:"viewer_groups,omitempty"`
	// DefaultRole is for people in no mapped group: none (refused, the
	// default) or viewer.
	DefaultRole string `yaml:"default_role,omitempty"`
	// CreateUsers adds people as users on their first sign-in (the
	// default); off, only users who signed in before can.
	CreateUsers *bool `yaml:"create_users,omitempty"`
	// ButtonLabel is the sign-in page's button.
	ButtonLabel string `yaml:"button_label,omitempty"`
}

// MaxSAMLMetadataXML is the most metadata that can be pasted.
const MaxSAMLMetadataXML = 256 << 10

// SAMLOn reports whether SAML single sign-on is on: never in demo mode.
func (c *Config) SAMLOn() bool { return c.Auth.SAML.Enabled && !c.DemoOn() }

// SAMLSettings is the SAML setting with every empty value filled in from
// the provider's preset.
type SAMLSettings struct {
	SAML
	Preset saml.Preset
}

// SAMLSettings returns the SAML settings in use.
func (c *Config) SAMLSettings() SAMLSettings {
	s := c.Auth.SAML
	p := saml.PresetFor(s.Provider)
	s.MetadataURL = strings.TrimSpace(s.MetadataURL)
	s.MetadataXML = strings.TrimSpace(s.MetadataXML)
	if s.UsernameAttribute == "" {
		s.UsernameAttribute = p.UsernameAttribute
	}
	if s.GroupsAttribute == "" {
		s.GroupsAttribute = p.GroupsAttribute
	}
	if s.DefaultRole == "" {
		s.DefaultRole = "none"
	}
	if s.ButtonLabel == "" {
		s.ButtonLabel = "Sign in with " + strings.TrimPrefix(p.Label, "Microsoft ")
		if s.Provider == saml.Other || s.Provider == "" {
			s.ButtonLabel = "Sign in with SAML single sign-on"
		}
	}
	return SAMLSettings{SAML: s, Preset: p}
}

// NewUsers reports whether people are added as users on their first
// sign-in.
func (s SAMLSettings) NewUsers() bool { return s.CreateUsers == nil || *s.CreateUsers }

// SAMLRole returns the role groups (and an email address) give with s:
// the highest that matches, the default role when none does, or "" when
// someone may not sign in. It also returns what matched.
func (s SAMLSettings) SAMLRole(groups []string, email string) (string, []string) {
	return mapRole(s.AdminGroups, s.AnalystGroups, s.ViewerGroups, s.DefaultRole, groups, email)
}

// SAMLEntityPrefix marks the users of a SAML provider in their Subject,
// apart from those of an OpenID Connect issuer.
const SAMLEntityPrefix = "saml:"

// attributePattern is an attribute name: a word or a URI.
var attributePattern = regexp.MustCompile(`^[A-Za-z0-9_:/.#?=&%~+\-]{1,256}$`)

// CheckSAMLMetadataURL says what is wrong with a metadata address, or "".
func CheckSAMLMetadataURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" {
		return "enter the metadata address, like " + saml.PresetFor("").MetadataExample
	}
	switch u.Scheme {
	case "https":
	case "http":
		h := u.Hostname()
		if ip := net.ParseIP(h); !strings.EqualFold(h, "localhost") && (ip == nil || !ip.IsLoopback()) {
			return "the metadata address must start with https://, so nobody on the way can swap in their own signing certificate"
		}
	default:
		return "the metadata address must start with https://"
	}
	return ""
}

// samlProblems checks auth.saml. Values that are empty are only required
// while SAML is on.
func (c *Config) samlProblems() []string {
	s := c.Auth.SAML
	var p []string
	add := func(key, format string, args ...any) {
		p = append(p, "auth.saml."+key+": "+fmt.Sprintf(format, args...))
	}
	on := s.Enabled
	switch s.Provider {
	case saml.ADFS, saml.Entra, saml.Okta, saml.Other:
	case "":
		if on {
			add("provider", "choose the identity provider: adfs, entra, okta or other")
		}
	default:
		add("provider", "%q must be adfs, entra, okta or other", s.Provider)
	}
	murl, mxml := strings.TrimSpace(s.MetadataURL), strings.TrimSpace(s.MetadataXML)
	switch {
	case murl != "" && mxml != "":
		add("metadata_xml", "set the metadata address or paste the metadata, not both")
	case murl != "":
		if msg := CheckSAMLMetadataURL(murl); msg != "" {
			add("metadata_url", "%s", msg)
		}
	case mxml != "":
		if err := checkSAMLMetadataXML(mxml); err != nil {
			add("metadata_xml", "%s", err)
		}
	case on:
		add("metadata_url", "enter the identity provider's metadata address, or paste its metadata")
	}
	for _, k := range []struct{ key, v string }{{"username_attribute", s.UsernameAttribute}, {"groups_attribute", s.GroupsAttribute}} {
		if k.v != "" && !attributePattern.MatchString(k.v) {
			add(k.key, "%q is not an attribute name, like groups or http://schemas.xmlsoap.org/claims/Group", k.v)
		}
	}
	switch s.DefaultRole {
	case "", "none", "viewer":
	default:
		add("default_role", "%q must be none or viewer", s.DefaultRole)
	}
	if len(s.ButtonLabel) > 60 {
		add("button_label", "keep the button label to 60 characters")
	}
	if on && s.DefaultRole != "viewer" && len(s.AdminGroups)+len(s.AnalystGroups)+len(s.ViewerGroups) == 0 {
		add("admin_groups", "map at least one group to a role, or let people in no mapped group in as viewers; otherwise nobody can sign in")
	}
	return p
}

// checkSAMLMetadataXML checks pasted metadata.
func checkSAMLMetadataXML(v string) error {
	if len(v) > MaxSAMLMetadataXML {
		return fmt.Errorf("the metadata is larger than %d KB; use its address instead", MaxSAMLMetadataXML>>10)
	}
	if _, err := saml.ParseMetadataCached([]byte(v)); err != nil {
		return err
	}
	return nil
}

// samlMetadataXML checks the page's value of auth.saml.metadata_xml.
func samlMetadataXML(v any) error {
	if s, _ := v.(string); s != "" {
		return checkSAMLMetadataXML(s)
	}
	return nil
}

// samlMetadataURL checks the page's value of auth.saml.metadata_url.
func samlMetadataURL(v any) error {
	if s, _ := v.(string); s != "" {
		if msg := CheckSAMLMetadataURL(s); msg != "" {
			return errors.New(msg)
		}
	}
	return nil
}
