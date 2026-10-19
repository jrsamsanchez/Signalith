// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package saml

// The identity providers the Single sign-on tab knows.
const (
	ADFS  = "adfs"
	Entra = "entra"
	Okta  = "okta"
	Other = "other"
)

// NameIDAttribute, as the username attribute, takes the username from the
// subject's NameID.
const NameIDAttribute = "NameID"

// Claim types Microsoft's providers send.
const (
	claimUPN      = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
	claimName     = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
	claimEmail    = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
	claimGiven    = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
	claimSurname  = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
	claimDisplay  = "http://schemas.microsoft.com/identity/claims/displayname"
	claimADFSGrp  = "http://schemas.xmlsoap.org/claims/Group"
	claimGroups   = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
	ClaimObjectID = "http://schemas.microsoft.com/identity/claims/objectidentifier"
	// ClaimGroupsLink is what Entra ID sends instead of the groups when
	// someone is in too many (more than 150 in SAML).
	ClaimGroupsLink = "http://schemas.microsoft.com/claims/groups.link"
)

// EmailAttributes are the attributes an email address may come in, in
// order.
var EmailAttributes = []string{"email", "mail", "emailaddress", claimEmail}

// NameAttributes are the attributes a display name may come in, in
// order; FirstLast are first and last names to join when none is sent.
var (
	NameAttributes = []string{claimDisplay, "displayName", "displayname", "name"}
	FirstLast      = [][2]string{{"firstName", "lastName"}, {"givenName", "sn"}, {claimGiven, claimSurname}}
)

// Preset is what a provider usually sends.
type Preset struct {
	ID              string `json:"id"`
	Label           string `json:"label"`
	MetadataExample string `json:"metadata_example"`
	// UsernameAttribute is the attribute that becomes the username
	// (NameID for the subject's NameID), and GroupsAttribute the one that
	// lists groups.
	UsernameAttribute string `json:"username_attribute"`
	GroupsAttribute   string `json:"groups_attribute"`
}

// Presets lists the providers, in the order the page offers them.
var Presets = []Preset{
	{ID: ADFS, Label: "AD FS", MetadataExample: "https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml",
		UsernameAttribute: claimUPN, GroupsAttribute: claimADFSGrp},
	{ID: Entra, Label: "Microsoft Entra ID", MetadataExample: "https://login.microsoftonline.com/<tenant ID>/federationmetadata/2007-06/federationmetadata.xml?appid=<application ID>",
		UsernameAttribute: claimName, GroupsAttribute: claimGroups},
	{ID: Okta, Label: "Okta", MetadataExample: "https://<your org>.okta.com/app/<app ID>/sso/saml/metadata",
		UsernameAttribute: NameIDAttribute, GroupsAttribute: "groups"},
	{ID: Other, Label: "Other SAML 2.0 provider", MetadataExample: "https://idp.example.com/metadata",
		UsernameAttribute: NameIDAttribute, GroupsAttribute: "groups"},
}

// PresetFor returns the preset of a provider, or Other's.
func PresetFor(id string) Preset {
	for _, p := range Presets {
		if p.ID == id {
			return p
		}
	}
	return Presets[len(Presets)-1]
}
