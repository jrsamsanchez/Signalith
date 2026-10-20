// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ldaptest

// Sample directories for tests and demos. Every person's password is
// Password, and the service account's is ServicePassword.
const (
	Password        = "Passw0rd!"
	ServicePassword = "svc-Passw0rd!"
)

// Active Directory sample names.
const (
	ADBase         = "DC=corp,DC=example,DC=com"
	ADService      = "CN=svc-signalith,OU=Service Accounts,DC=corp,DC=example,DC=com"
	ADAdmins       = "CN=Signalith Admins,OU=Groups,DC=corp,DC=example,DC=com"
	ADITLeads      = "CN=IT Leads,OU=Groups,DC=corp,DC=example,DC=com" // inside ADAdmins
	ADAnalysts     = "CN=SOC Analysts,OU=Groups,DC=corp,DC=example,DC=com"
	ADViewers      = "CN=SOC Viewers,OU=Groups,DC=corp,DC=example,DC=com"
	ADEveryone     = "CN=All Staff,OU=Groups,DC=corp,DC=example,DC=com"
	ADAliceDN      = "CN=Alice Admin,OU=Staff,DC=corp,DC=example,DC=com"
	ADBobDN        = "CN=Bob Analyst,OU=Staff,DC=corp,DC=example,DC=com"
	ADCarolDN      = "CN=Carol Viewer,OU=Staff,DC=corp,DC=example,DC=com"
	ADDaveDN       = "CN=Dave Nogroup,OU=Staff,DC=corp,DC=example,DC=com"
	ADEveDN        = "CN=Eve Disabled,OU=Staff,DC=corp,DC=example,DC=com"
	ADSmithDN      = `CN=Smith\, John,OU=Staff,DC=corp,DC=example,DC=com`
	ADDuplicateOne = "CN=Pat One,OU=Staff,DC=corp,DC=example,DC=com"
	ADDuplicateTwo = "CN=Pat Two,OU=Contractors,DC=corp,DC=example,DC=com"
	ADFrankDN      = "CN=Frank Reset,OU=Staff,DC=corp,DC=example,DC=com"
)

// LoadActiveDirectory fills the server with a small Active Directory:
//
//	alice  in IT Leads, which is inside Signalith Admins (nested)
//	bob    in SOC Analysts
//	carol  in SOC Viewers
//	dave   only in All Staff, which no role maps
//	eve    disabled (userAccountControl 514)
//	jsmith a CN with a comma, to check escaping
//	pat    two accounts with the same sAMAccountName, to check that
//	       ambiguous matches are refused
//	frank  in SOC Analysts, but must change his password first
func LoadActiveDirectory(s *Server) {
	ou := func(dn string) { s.Add(dn, map[string][]string{"objectClass": {"top", "organizationalUnit"}}) }
	s.Add(ADBase, map[string][]string{"objectClass": {"top", "domain"}})
	for _, dn := range []string{"OU=Staff," + ADBase, "OU=Groups," + ADBase, "OU=Service Accounts," + ADBase, "OU=Contractors," + ADBase} {
		ou(dn)
	}
	user := func(dn, sam, name, uac string) {
		s.Add(dn, map[string][]string{
			"objectClass": {"top", "person", "organizationalPerson", "user"}, "objectCategory": {"CN=Person,CN=Schema,CN=Configuration," + ADBase},
			"sAMAccountName": {sam}, "userPrincipalName": {sam + "@corp.example.com"}, "displayName": {name},
			"mail": {sam + "@corp.example.com"}, "userAccountControl": {uac},
		})
		s.SetPassword(dn, Password)
	}
	user(ADAliceDN, "alice", "Alice Admin", "512")
	user(ADBobDN, "bob", "Bob Analyst", "512")
	user(ADCarolDN, "carol", "Carol Viewer", "512")
	user(ADDaveDN, "dave", "Dave Nogroup", "512")
	user(ADEveDN, "eve", "Eve Disabled", "514")
	user(ADSmithDN, "jsmith", "John Smith", "512")
	user(ADDuplicateOne, "pat", "Pat One", "512")
	user(ADDuplicateTwo, "pat", "Pat Two", "512")
	user(ADFrankDN, "frank", "Frank Reset", "512")
	s.MustChangePassword(ADFrankDN)
	s.Add(ADService, map[string][]string{"objectClass": {"top", "person", "user"}, "sAMAccountName": {"svc-signalith"}, "userAccountControl": {"66048"}})
	s.SetPassword(ADService, ServicePassword)
	group := func(dn string, members ...string) {
		s.Add(dn, map[string][]string{"objectClass": {"top", "group"}, "member": members})
	}
	group(ADAdmins, ADITLeads)
	group(ADITLeads, ADAliceDN)
	group(ADAnalysts, ADBobDN, ADSmithDN, ADFrankDN)
	group(ADViewers, ADCarolDN)
	group(ADEveryone, ADAliceDN, ADBobDN, ADCarolDN, ADDaveDN, ADEveDN, ADSmithDN)
}

// OpenLDAP sample names.
const (
	OLBase     = "dc=example,dc=org"
	OLService  = "cn=signalith,ou=services,dc=example,dc=org"
	OLAdmins   = "cn=signalith-admins,ou=groups,dc=example,dc=org" // groupOfNames
	OLAnalysts = "cn=soc,ou=groups,dc=example,dc=org"              // posixGroup
	OLViewers  = "cn=auditors,ou=groups,dc=example,dc=org"         // groupOfUniqueNames
	OLAliceDN  = "uid=alice,ou=people,dc=example,dc=org"
	OLBobDN    = "uid=bob,ou=people,dc=example,dc=org"
	OLCarolDN  = "uid=carol,ou=people,dc=example,dc=org"
	OLDaveDN   = "uid=dave,ou=people,dc=example,dc=org"
)

// LoadOpenLDAP fills the server with a small OpenLDAP directory:
//
//	alice in signalith-admins (groupOfNames, member)
//	bob   in soc (posixGroup, memberUid)
//	carol in auditors (groupOfUniqueNames, uniqueMember)
//	dave  in no group
func LoadOpenLDAP(s *Server) {
	s.Add(OLBase, map[string][]string{"objectClass": {"top", "dcObject", "organization"}})
	for _, ou := range []string{"ou=people", "ou=groups", "ou=services"} {
		s.Add(ou+","+OLBase, map[string][]string{"objectClass": {"top", "organizationalUnit"}})
	}
	person := func(dn, uid, cn string) {
		s.Add(dn, map[string][]string{
			"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson", "posixAccount"},
			"uid":         {uid}, "cn": {cn}, "sn": {cn}, "mail": {uid + "@example.org"},
		})
		s.SetPassword(dn, Password)
	}
	person(OLAliceDN, "alice", "Alice Admin")
	person(OLBobDN, "bob", "Bob Analyst")
	person(OLCarolDN, "carol", "Carol Viewer")
	person(OLDaveDN, "dave", "Dave Nogroup")
	s.Add(OLService, map[string][]string{"objectClass": {"top", "organizationalRole", "simpleSecurityObject"}, "cn": {"signalith"}})
	s.SetPassword(OLService, ServicePassword)
	s.Add(OLAdmins, map[string][]string{"objectClass": {"top", "groupOfNames"}, "cn": {"signalith-admins"}, "member": {OLAliceDN}})
	s.Add(OLAnalysts, map[string][]string{"objectClass": {"top", "posixGroup"}, "cn": {"soc"}, "gidNumber": {"5000"}, "memberUid": {"bob"}})
	s.Add(OLViewers, map[string][]string{"objectClass": {"top", "groupOfUniqueNames"}, "cn": {"auditors"}, "uniqueMember": {OLCarolDN}})
}
