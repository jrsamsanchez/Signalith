package security

import (
	"regexp"
)

// docsBase is where the docs are published.
const docsBase = "https://github.com/jrsamsanchez/signalith/blob/"

var releaseTag = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

// DocsURL links to a section of the docs for this version: the release's
// tag for a release, else main.
func DocsURL(version, file, anchor string) string {
	ref := "main"
	if releaseTag.MatchString(version) {
		ref = version
	}
	dir := "docs/"
	if file == "README.md" {
		dir = ""
	}
	u := docsBase + ref + "/" + dir + file
	if anchor != "" {
		u += "#" + anchor
	}
	return u
}

// The sections of the docs the report links to. Every link the checks
// make is one of these, so a test can check that each still exists.
var (
	docHTTPSUpgrade    = DocLink{File: "https.md", Anchor: "upgrading-from-plain-http"}
	docHTTPSProxy      = DocLink{File: "https.md", Anchor: "behind-a-reverse-proxy"}
	docHTTPSOwn        = DocLink{File: "https.md", Anchor: "use-your-own-certificate"}
	docHTTPSNames      = DocLink{File: "https.md", Anchor: "names-the-certificate-can-cover"}
	docHTTPSSwitch     = DocLink{File: "https.md", Anchor: "switching-to-a-new-certificate-authority"}
	docHTTPSReach      = DocLink{File: "https.md", Anchor: "how-far-the-certificate-authority-reaches"}
	docHTTPSAgents     = DocLink{File: "https.md", Anchor: "agents-and-syslog"}
	docHTTPSTrust      = DocLink{File: "https.md", Anchor: "trust-the-certificate"}
	docHTTPSOldToken   = DocLink{File: "https.md", Anchor: "the-docker-quick-starts-old-example-token"}
	docOSPoint         = DocLink{File: "opensearch-security.md", Anchor: "4-point-signalith-at-it"}
	docOSLinux         = DocLink{File: "opensearch-security.md", Anchor: "opensearch-on-linux-or-windows"}
	docOSCerts         = DocLink{File: "opensearch-security.md", Anchor: "1-make-the-certificates"}
	docOSDocker        = DocLink{File: "opensearch-security.md", Anchor: "docker-quick-start"}
	docOSRoles         = DocLink{File: "opensearch-security.md", Anchor: "3-load-the-security-settings"}
	docEncDocker       = DocLink{File: "encryption.md", Anchor: "docker"}
	docEncElsewhere    = DocLink{File: "encryption.md", Anchor: "keeping-the-key-elsewhere"}
	docEncKey          = DocLink{File: "encryption.md", Anchor: "the-master-key"}
	docEncChange       = DocLink{File: "encryption.md", Anchor: "changing-the-key"}
	docEncBackup       = DocLink{File: "encryption.md", Anchor: "backing-up-the-key"}
	docEncWhat         = DocLink{File: "encryption.md", Anchor: "what-signalith-encrypts"}
	docEncNot          = DocLink{File: "encryption.md", Anchor: "not-encrypted-by-the-master-key"}
	docEncLosing       = DocLink{File: "encryption.md", Anchor: "losing-the-key"}
	docEncDisk         = DocLink{File: "encryption.md", Anchor: "disk-encryption"}
	docEncInUse        = DocLink{File: "encryption.md", Anchor: "in-use"}
	docEncCommands     = DocLink{File: "encryption.md", Anchor: "commands"}
	docRetArchives     = DocLink{File: "retention.md", Anchor: "archives"}
	docUsersBuiltin    = DocLink{File: "users.md", Anchor: "the-built-in-admin"}
	docUsersLocal      = DocLink{File: "users.md", Anchor: "managing-local-users"}
	docUsersDirectory  = DocLink{File: "users.md", Anchor: "set-it-up"}
	docReadmeLinux     = DocLink{File: "README.md", Anchor: "linux"}
	docReadmeWindows   = DocLink{File: "README.md", Anchor: "windows"}
	docReadmeDocker    = DocLink{File: "README.md", Anchor: "docker-evaluation"}
	docServersIdentity = DocLink{File: "servers.md", Anchor: "identity"}
	docSecSyslog       = DocLink{File: "security.md", Anchor: "syslog"}
	docSecDisk         = DocLink{File: "security.md", Anchor: "disk-encryption"}
	docSecOSDisk       = DocLink{File: "security.md", Anchor: "where-opensearch-keeps-events"}
	docSecFiles        = DocLink{File: "security.md", Anchor: "file-permissions"}
	docSecNotChecked   = DocLink{File: "security.md", Anchor: "not-checked-here"}
)

// AllDocs lists every section of the docs the report may link to.
func AllDocs() []DocLink {
	return []DocLink{docHTTPSUpgrade, docHTTPSProxy, docHTTPSOwn, docHTTPSNames, docHTTPSSwitch, docHTTPSReach,
		docHTTPSAgents, docHTTPSTrust, docHTTPSOldToken, docOSPoint, docOSLinux, docOSCerts, docOSDocker, docOSRoles, docEncDocker,
		docEncElsewhere, docEncKey, docEncChange, docEncBackup, docEncWhat, docEncNot, docEncLosing, docEncDisk,
		docEncInUse, docEncCommands, docRetArchives, docUsersBuiltin, docUsersLocal, docUsersDirectory, docReadmeLinux,
		docReadmeWindows, docReadmeDocker, docServersIdentity, docSecSyslog, docSecDisk, docSecOSDisk, docSecFiles,
		docSecNotChecked}
}

// NotCheckedDocs is the section that says how to check by hand what the
// report leaves out.
func NotCheckedDocs(version string) DocLink {
	d := docSecNotChecked
	d.URL = DocsURL(version, d.File, d.Anchor)
	return d
}

// doc returns a copy of a docs section for a Fix.
func doc(d DocLink) *DocLink { return &d }
