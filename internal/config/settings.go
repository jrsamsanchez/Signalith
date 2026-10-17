package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/oidc"
	"github.com/jrsamsanchez/signalith/internal/redact"
	"github.com/jrsamsanchez/signalith/internal/saml"
	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// The Settings page shows the settings in Registry. Each one names its
// key in signalith.yaml, so a value saved on the page, one in the file and
// one from the environment all mean the same thing. Every setting of
// Config is either in Registry or in Excluded with the reason it is not on
// the page; a test fails when a new one is in neither, or has no Scope.

// Scope says which servers a setting is for, once several servers share
// one OpenSearch.
type Scope string

const (
	// ScopeCluster settings are the same on every server, such as the
	// retention policies or the search defaults.
	ScopeCluster Scope = "cluster"
	// ScopeServer settings belong to one server, such as the address it
	// listens on or whether it may run the background jobs.
	ScopeServer Scope = "server"
	// ScopeBootstrap settings are what a server needs before it can reach
	// anything shared: how to connect to OpenSearch, its own name and its
	// folders. They are only ever set on that server.
	ScopeBootstrap Scope = "bootstrap"
)

// Setting types, which decide how the page shows a setting and how a
// value from the page is read.
const (
	TypeText     = "text"
	TypeNumber   = "number"
	TypeDuration = "duration" // such as 30m, 12h or 7d
	TypeBool     = "bool"
	TypeChoice   = "choice"
	TypeList     = "list"   // a list of strings
	TypeSecret   = "secret" // never shown; only whether one is set
	TypeURL      = "url"
	TypeAddress  = "address" // host:port to listen on
)

// Section is a group of settings on the page.
type Section struct {
	ID    string
	Title string
	Help  string
	// Tab, when set, is the Settings tab (a page of its own) that shows
	// the section, in place of the Server tab.
	Tab string
}

// Choice is one value a choice setting can take.
type Choice struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Setting describes one setting on the Settings page.
type Setting struct {
	Key     string // the key in signalith.yaml, such as "syslog.udp"
	Scope   Scope
	Section string
	Label   string
	Help    string
	Type    string
	Choices []Choice
	// Min and Max bound a number.
	Min, Max *int
	// Placeholder is an example value for an empty field.
	Placeholder string
	// EmptyMeans says what an empty value does, such as "off".
	EmptyMeans string
	// File is true for the full path of a file on this server.
	File bool
	// Env is the environment variable that overrides the setting; the
	// page shows such a setting read-only.
	Env string
	// Restart is true when a change applies only after a restart;
	// otherwise it applies as soon as it is saved.
	Restart bool
	// Confirm, when set, is what the page asks before saving a change,
	// naming its consequence. ConfirmWhen limits it to a bool turned "on"
	// or "off".
	Confirm     string
	ConfirmWhen string
	// For a secret: SentWith lists the settings that decide where it is
	// sent, and sentTo returns that address. A saved secret is only sent
	// to the address it was entered for.
	SentWith []string
	sentTo   func(*Config) string
	// WaitsFor lists settings that, while they wait for a restart, make
	// this live setting wait too: the public address is worked out from
	// the listen address.
	WaitsFor []string
	// SharedOnly settings are on the page only of a server whose settings
	// are shared with the other servers of its cluster (see Shared), such
	// as the cluster's name; LegacyOnly ones only of a server that keeps
	// its settings to itself, such as detections.scheduler, the old name
	// of cluster.leader_eligible. See OnPage.
	SharedOnly, LegacyOnly bool
	// check checks a value from the page beyond what Validate does.
	check func(any) error
	// problem words what is wrong with the setting in a whole
	// configuration for its field on the page, in place of Validate's
	// wording (which names settings by their keys), or returns "".
	problem func(*Config) string
}

// Live reports whether a change applies as soon as it is saved.
func (s *Setting) Live() bool { return !s.Restart }

// OnPage reports whether the Settings page shows the setting: on a server
// whose settings are shared with the other servers (shared), or on one
// that keeps them to itself.
func (s *Setting) OnPage(shared bool) bool {
	if shared {
		return !s.LegacyOnly
	}
	return !s.SharedOnly
}

// Check checks a value from ParseValue beyond what Validate does, as a
// save from the page does.
func (s *Setting) Check(v any) error {
	if s.check == nil {
		return nil
	}
	return s.check(v)
}

// Noun returns the label for use inside a sentence: "Password" becomes
// "password", while "API key" and "OpenSearch address" keep their
// capitals.
func (s *Setting) Noun() string {
	first, _, _ := strings.Cut(s.Label, " ")
	r := []rune(first)
	for _, c := range r[min(1, len(r)):] {
		if unicode.IsUpper(c) {
			return s.Label
		}
	}
	if len(r) == 0 {
		return s.Label
	}
	return string(unicode.ToLower(r[0])) + s.Label[len(string(r[0])):]
}

// SentTo returns where a secret setting is sent with c, as
// scheme://host:port, or "" when it is not sent anywhere. A secret sent to
// several addresses (the OpenSearch password, with opensearch.urls) has
// them all, separated by commas.
func (s *Setting) SentTo(c *Config) string {
	if s.sentTo == nil {
		return ""
	}
	var out []string
	for _, a := range strings.Split(s.sentTo(c), ",") {
		if o := Origin(a); o != "" && !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	return strings.Join(out, ",")
}

// checkOpenSearchURLs checks opensearch.urls from the page: each an
// http(s) address without a user name or password. Validate checks the
// rest (the same scheme as opensearch.url).
func checkOpenSearchURLs(v any) error {
	for _, raw := range v.([]string) {
		if hasSecret(raw) {
			return fmt.Errorf("“%s” has a user name or password in it: put them in the Username and Password fields", redact.URL(raw))
		}
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("“%s” isn't an address like https://opensearch-2.example.com:9200", redact.URL(raw))
		}
	}
	return nil
}

func intp(n int) *int { return &n }

// Sections lists the page's sections in order.
var Sections = []Section{
	{ID: "general", Title: "General", Help: "How people and agents reach this server, and how long a sign-in lasts."},
	{ID: "web", Title: "Web server", Help: "Where the web page and the API listen."},
	{ID: "https", Title: "HTTPS", Help: "How the web page, the API, agents and syslog over TLS are kept private on the network: the certificate, and what is still accepted over plain HTTP."},
	{ID: "opensearch", Title: "OpenSearch", Help: "Where events, findings and investigations are stored."},
	{ID: "search", Title: "Search", Help: "What a new search starts with, and when a quiet data source is flagged."},
	{ID: "syslog", Title: "Syslog", Help: "Receive syslog from firewalls, switches and servers that cannot run an agent."},
	{ID: "detections", Title: "Detections", Help: "Whether detections run by themselves, and how many findings one run can raise."},
	{ID: "assistant", Title: "AI assistant", Help: "An optional AI model. Ask sends it only the question and field names, never events. Investigate with AI sends a finding's events, and is off until you turn it on below."},
	{ID: "intel", Title: "Threat intel", Help: "Where threat intel feeds may be downloaded from."},
	{ID: "sso", Title: "Single sign-on", Tab: "sso", Help: "Sign in with an identity provider, over OpenID Connect (Microsoft Entra ID, Okta, Google, Keycloak) or SAML 2.0 (AD FS, Okta, Entra ID), alongside local users and directory sign-in."},
	{ID: "vulns", Title: "Vulnerability scans", Help: "How scans on the Vulnerabilities page look up the known vulnerabilities (CVEs) of the software they find. Only product names are sent, never addresses."},
	{ID: "m365", Title: "Microsoft 365", Help: "Read Microsoft 365's audit log (Entra ID sign-ins and changes, Exchange, SharePoint, OneDrive, Teams and security alerts) with an app registered in Entra ID. One server reads it every 5 minutes. See the Microsoft 365 guide in the docs for how to register the app."},
	{ID: "okta", Title: "Okta", Help: "Read Okta's System Log (sign-ins, MFA, account and admin changes, and Okta's own threat alerts) with an API service app in your Okta organization. One server reads it every minute. See the Okta guide in the docs for how to add the app."},
}

// Registry lists every setting on the page, in page order.
var Registry = []Setting{
	{Key: "server.public_url", Scope: ScopeCluster, Section: "general", Label: "Public address", Type: TypeURL,
		Help:        "The address agents and links use to reach this server. With HTTPS on it starts with https://, and Signalith's own certificate is made to cover its host.",
		Placeholder: "https://siem.example.com:9000", EmptyMeans: "worked out from the listen address",
		Env: "SIGNALITH_PUBLIC_URL", WaitsFor: []string{"server.listen", "server.tls.mode", "server.tls_cert", "server.tls_key"}},
	{Key: "auth.session_timeout", Scope: ScopeCluster, Section: "general", Label: "Sign out after", Type: TypeDuration,
		Help:        "Signs people out of the web page after this long without use, unless they ticked Keep me signed in. At least 5m. NIST SP 800-63B (AAL2) asks for at most 1h.",
		Placeholder: "1h", EmptyMeans: "1h"},
	{Key: "auth.session_max_age", Scope: ScopeCluster, Section: "general", Label: "Sign in again after", Type: TypeDuration,
		Help:        "Ends every session this long after sign-in, also when Keep me signed in was ticked. From 1h to 30d. NIST SP 800-63B (AAL2) asks for at most 24h.",
		Placeholder: "24h", EmptyMeans: "24h"},
	{Key: "auth.mfa_required", Scope: ScopeCluster, Section: "general", Label: "Require two-step sign-in", Type: TypeChoice,
		Help: "Who must enter a code from an authenticator app after their password. Everyone can turn it on for themselves from the account menu either way. " +
			"Someone who has not set it up is asked to right after they sign in. Signing in with a password over the API (HTTP Basic) stops working for them: use an API token instead. " +
			"Single sign-on users get it from their identity provider instead.",
		Choices:    []Choice{{"off", "Not required"}, {"admins", "Admins"}, {"everyone", "Everyone"}},
		EmptyMeans: "Not required"},
	{Key: "cluster.name", Scope: ScopeCluster, Section: "general", Label: "Cluster name", Type: TypeText, SharedOnly: true,
		Help:        "The name of the servers that share this OpenSearch, shown at the top of the Servers page. Every server shows the same name.",
		Placeholder: "SOC", EmptyMeans: "the name the first server gave it"},
	{Key: "ingest.max_event_age", Scope: ScopeCluster, Section: "general", Label: "Oldest event time", Type: TypeDuration,
		Help:        "Events from agents and syslog that say they are older than this are filed under the time they arrived, with their own time kept in device_time. Raise it to load old logs.",
		Placeholder: "30d", EmptyMeans: "7d, or the shortest retention period when that is shorter"},
	{Key: "ingest.url_query", Scope: ScopeCluster, Section: "general", Label: "Query strings in web addresses", Type: TypeChoice,
		Help: "The part of a web address after the ? can carry tokens, session IDs and passwords. As web requests are stored (from a network sensor, a web server's log or an IDS alert), " +
			"Hide values keeps the parameter names (?user=REDACTED&token=REDACTED), and Remove keeps only the address up to the ?, in the url, uri_query and http_referrer fields and the raw event. " +
			"Detections that look at query values (web attacks such as SQL injection) then no longer see them. Events stored before a change keep what they had.",
		Choices:    []Choice{{"keep", "Keep them"}, {"redact", "Hide values"}, {"drop", "Remove them"}},
		EmptyMeans: "Keep them"},

	{Key: "server.listen", Scope: ScopeServer, Section: "web", Label: "Listen address", Type: TypeAddress, Restart: true,
		Help:        "The address and port the web page and API listen on. 0.0.0.0 accepts other computers; 127.0.0.1 only this one.",
		Placeholder: "0.0.0.0:9000", Env: "SIGNALITH_LISTEN",
		Confirm: "After the restart the web page answers only at the new address. Bookmarks that use the old one stop working until they are changed."},
	{Key: "server.agent_listen", Scope: ScopeServer, Section: "web", Label: "Agent address", Type: TypeAddress, Restart: true,
		Help: "The address and port agents send events to, kept apart from the web page: Fluent Bit, the OpenTelemetry Collector, osquery and network sensors. " +
			"off sends agents to the web port, as before Signalith 0.3.",
		Placeholder: "0.0.0.0:7779", EmptyMeans: "the listen address on port 7779; the web port also accepts agents set up before 0.3",
		Env:     "SIGNALITH_AGENT_LISTEN",
		Confirm: "After the restart agents must send to the new address. Agents that use the old one stop sending until they are set up again from Add data."},
	{Key: "server.max_connections", Scope: ScopeServer, Section: "web", Label: "Most connections", Type: TypeNumber, Restart: true, Min: intp(0), Max: intp(1000000),
		Help:       "The most connections open at once from browsers, agents and the API, on the web port and again on the agent port. One computer may use a tenth of them.",
		EmptyMeans: "10000"},
	{Key: "server.shared_addresses", Scope: ScopeServer, Section: "web", Label: "Proxies and gateways", Type: TypeList, Restart: true,
		Help:        "IP addresses or ranges of a reverse proxy, load balancer or NAT gateway that many people and agents reach Signalith through. They are not limited like one computer: wrong passwords from them count against each account, and never pause sign-ins from the whole address.",
		Placeholder: "10.0.0.5", EmptyMeans: "none", check: checkAddressList, problem: listProblem("server.shared_addresses")},
	{Key: "server.proxy_protocol", Scope: ScopeServer, Section: "web", Label: "PROXY protocol from load balancers", Type: TypeBool, Restart: true,
		Help: "Accept a PROXY protocol header (v1 or v2) on the web port from the trusted reverse proxies, as a load balancer that passes connections on sends it, so sign-in limits, the audit log and agent limits see each client's own address. " +
			"Only the trusted reverse proxies may send one; a header from anyone else closes the connection.",
		Env: "SIGNALITH_PROXY_PROTOCOL"},
	{Key: "server.node_url", Scope: ScopeServer, Section: "web", Label: "Address for other servers", Type: TypeURL, SharedOnly: true,
		Help: "The address the other Signalith servers that share this OpenSearch reach this one at, shown on the Servers page. " +
			"In a container set it, since a container cannot know the address it is reached at.",
		Placeholder: "https://10.0.0.5:9000", EmptyMeans: "worked out from the listen address and this computer's name",
		Env: "SIGNALITH_NODE_URL", check: noSecretIn("an address for other servers needs no password")},

	{Key: "server.tls.mode", Scope: ScopeServer, Section: "https", Label: "HTTPS", Type: TypeChoice, Restart: true,
		Help: "Automatic: Signalith makes its own certificate and renews it; browsers warn until its certificate authority is trusted, which the sign-in page offers to download. " +
			"Your own certificate files: a certificate from your organization or a public authority, in the two files below. " +
			"Off: plain HTTP, only behind a reverse proxy that serves HTTPS, since passwords and events would otherwise cross the network unencrypted.",
		Choices: []Choice{{TLSAuto, "Automatic: Signalith's own certificate"}, {TLSFiles, "Your own certificate files"}, {TLSOff, "Off: a reverse proxy serves HTTPS"}},
		problem: tlsModeProblem},
	{Key: "server.tls.names", Scope: ScopeCluster, Section: "https", Label: "Extra certificate names", Type: TypeList, Restart: true,
		Help: "Host names or IP addresses that people and agents also use to reach Signalith, for the automatic certificate: a DNS alias, or the address a NAT or Docker publishes. " +
			"This computer's own names and addresses and the public address are always in it.",
		Placeholder: "siem.corp.local", EmptyMeans: "none besides those", check: checkCertNames, problem: certNamesProblem},
	{Key: "server.tls.ca_scope", Scope: ScopeServer, Section: "https", Label: "Certificate authority reaches", Type: TypeChoice,
		Help: "Only with Automatic HTTPS. Signalith's own certificate authority never vouches for public websites. " +
			"Standard also lets it vouch for private network names and addresses, so a new address for this server works right away. " +
			"Strict limits it to this server's names and addresses as they are now; a new one later means a new certificate authority " +
			"that browsers and agents must trust again. A change takes effect when you switch on the Security page.",
		Choices:    []Choice{{CAScopeStandard, "This server and private network names (standard)"}, {CAScopeStrict, "Only this server's own names and addresses (strict)"}},
		EmptyMeans: CAScopeStandard,
		Confirm:    "Nothing changes for browsers or agents yet. The Security page makes the new certificate authority and helps you switch to it.",
		problem:    caScopeProblem},
	{Key: "server.tls_cert", Scope: ScopeServer, File: true, Section: "https", Label: "Certificate file", Type: TypeText, Restart: true,
		Help:        "Only with your own certificate files: full path of the PEM certificate, followed by any intermediate certificates. Signalith loads it again when the file changes.",
		Placeholder: "/etc/signalith/tls/cert.pem", problem: tlsFileProblem("server.tls_cert")},
	{Key: "server.tls_key", Scope: ScopeServer, File: true, Section: "https", Label: "Key file", Type: TypeText, Restart: true,
		Help:        "Only with your own certificate files: full path of the certificate's PEM private key.",
		Placeholder: "/etc/signalith/tls/key.pem", problem: tlsFileProblem("server.tls_key")},
	{Key: "server.tls.plaintext_ingest", Scope: ScopeCluster, Section: "https", Label: "Agents on plain HTTP", Type: TypeChoice,
		Help: "Agents set up before HTTPS was the default still send to an http:// address. Accept them while you give each one a new configuration from Add data " +
			"(the Health page lists those still on plain HTTP, whose events anyone on the network can read), then refuse them. A refused agent keeps its events and sends them again once it is updated. " +
			"On a Docker quick start upgraded from an older version, refusing them also ends the old example token change-this-ingest-token for good.",
		Choices: []Choice{{"deny", "Refuse them"}, {"allow", "Accept them for now"}}},
	{Key: "server.trusted_proxies", Scope: ScopeCluster, Section: "https", Label: "Trusted reverse proxies", Type: TypeList,
		Help:        "IP addresses or ranges of reverse proxies in front of Signalith. Only from them is X-Forwarded-Proto believed, so a browser that reached the proxy over HTTPS gets the HTTPS-only sign-in cookie and is not sent to https:// again.",
		Placeholder: "10.0.0.5", EmptyMeans: "none", check: checkAddressList, problem: listProblem("server.trusted_proxies")},
	{Key: "server.client_header", Scope: ScopeCluster, Section: "https", Label: "Client address header", Type: TypeChoice,
		Help: "The header your trusted reverse proxies write each person's address into. The sign-in limits and the log then use that address instead of the proxy's. " +
			"Choose one only if the proxy sets the header itself (for nginx: proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;), " +
			"because a proxy that passes on the header from the browser lets anyone pick the address they are counted under. " +
			"With None, everyone reaching Signalith through a trusted proxy counts as one shared address.",
		Choices: []Choice{{"", "None: count everyone behind the proxy together"}, {ClientHeaderXFF, "X-Forwarded-For"}, {ClientHeaderForwarded, "Forwarded"}}},

	{Key: "opensearch.url", Scope: ScopeBootstrap, Section: "opensearch", Label: "Address", Type: TypeURL, Restart: true,
		Help:        "Where OpenSearch answers.",
		Placeholder: "https://opensearch.example.com:9200", Env: "SIGNALITH_OPENSEARCH_URL", check: noSecretIn("put the username and password in their own fields below"),
		Confirm: "Signalith will store and search events in the OpenSearch at the new address. Events stored in the current one stay there and do not show in searches."},
	{Key: "opensearch.urls", Scope: ScopeBootstrap, Section: "opensearch", Label: "More addresses", Type: TypeList, Restart: true,
		Help:        "Other nodes of the same OpenSearch cluster. Signalith spreads requests over all addresses and skips one that is down.",
		Placeholder: "https://opensearch-2.example.com:9200", EmptyMeans: "only the address above", Env: "SIGNALITH_OPENSEARCH_URLS",
		check: checkOpenSearchURLs},
	{Key: "opensearch.username", Scope: ScopeBootstrap, Section: "opensearch", Label: "Username", Type: TypeText, Restart: true,
		Help: "Leave empty if OpenSearch does not ask for a password.", Env: "SIGNALITH_OPENSEARCH_USERNAME"},
	{Key: "opensearch.password", Scope: ScopeBootstrap, Section: "opensearch", Label: "Password", Type: TypeSecret, Restart: true,
		Help: "Only sent to the address it was entered for.", Env: "SIGNALITH_OPENSEARCH_PASSWORD",
		SentWith: []string{"opensearch.url", "opensearch.urls"}, sentTo: func(c *Config) string {
			return strings.Join(append([]string{c.OpenSearch.URL}, c.OpenSearch.URLs...), ",")
		}},
	{Key: "opensearch.ca_file", Scope: ScopeBootstrap, File: true, Section: "opensearch", Label: "CA certificate file", Type: TypeText, Restart: true,
		Help:        "Full path of the PEM certificate of the authority that signed OpenSearch's certificate, for an https address with a private authority.",
		Placeholder: "/etc/signalith/opensearch-ca.pem", EmptyMeans: "only authorities this computer trusts"},
	{Key: "opensearch.cert_file", Scope: ScopeBootstrap, File: true, Section: "opensearch", Label: "Client certificate file", Type: TypeText, Restart: true,
		Help:        "For signing in to OpenSearch with a certificate instead of a password: full path of the PEM certificate Signalith presents.",
		Placeholder: "/etc/signalith/opensearch-client.pem", EmptyMeans: "no certificate sign-in"},
	{Key: "opensearch.key_file", Scope: ScopeBootstrap, File: true, Section: "opensearch", Label: "Client key file", Type: TypeText, Restart: true,
		Help:        "Full path of the client certificate's PEM private key.",
		Placeholder: "/etc/signalith/opensearch-client-key.pem"},
	{Key: "opensearch.crl_file", Scope: ScopeBootstrap, File: true, Section: "opensearch", Label: "Revocation list file", Type: TypeText, Restart: true,
		Help:        "Full path of the revocation list OpenSearch checks client certificates against (plugins.security.ssl.http.crl.file_path). Signalith keeps it, so a removed server's certificate stops working at once.",
		Placeholder: "/etc/opensearch/crl.pem", EmptyMeans: "none: a removed server's certificate works until it expires", Env: "SIGNALITH_OPENSEARCH_CRL_FILE"},
	{Key: "opensearch.proxy", Scope: ScopeBootstrap, Section: "opensearch", Label: "Proxy", Type: TypeText, Restart: true,
		Help:        "A proxy to reach OpenSearch through, such as http://proxy:3128. It sees every event, so use one only when the network needs it.",
		Placeholder: "http://proxy:3128", EmptyMeans: "connect directly", Env: "SIGNALITH_OPENSEARCH_PROXY",
		check: noSecretIn("a proxy that needs a password is set in signalith.yaml or with SIGNALITH_OPENSEARCH_PROXY, where it is not shown")},
	{Key: "opensearch.allow_insecure_http", Scope: ScopeBootstrap, Section: "opensearch", Label: "Allow password over plain http", Type: TypeBool, Restart: true,
		Help:    "Lets the username and password go to OpenSearch on another computer over http:// instead of https://.",
		Confirm: "The OpenSearch username and password will cross the network unencrypted, where anyone on the way can read them. Use an https:// address instead when you can.", ConfirmWhen: "on"},
	{Key: "opensearch.tls_skip_verify", Scope: ScopeBootstrap, Section: "opensearch", Label: "Skip certificate check", Type: TypeBool, Restart: true,
		Help:    "Connects even when OpenSearch's certificate is not trusted, for a test system with a self-signed certificate.",
		Confirm: "Signalith will not check who it is connecting to, so someone on the network could read events and the OpenSearch password. Use this only on a test system.", ConfirmWhen: "on"},
	{Key: "opensearch.index_prefix", Scope: ScopeBootstrap, Section: "opensearch", Label: "Index prefix", Type: TypeText, Restart: true,
		Help:    "The start of every index name, as in signalith-authentication-2026.10.12. Lowercase, no spaces.",
		Confirm: "Signalith will start with empty indices under the new prefix. Events, findings and investigations stored under the current prefix stay in OpenSearch but no longer show in searches or on any page."},
	{Key: "opensearch.replicas", Scope: ScopeCluster, Section: "opensearch", Label: "Replicas", Type: TypeText, Restart: true,
		Help: "Extra copies of each new day's events on other OpenSearch nodes. Automatic (auto) keeps one copy on another node once OpenSearch has more than one node, and none on a single node. " +
			"Or enter a number: 0 for none. Days already stored keep the copies they have.",
		Placeholder: "auto", EmptyMeans: "auto", check: checkReplicas},
	{Key: "opensearch.shards", Scope: ScopeCluster, Section: "opensearch", Label: "Shards", Type: TypeNumber, Restart: true, Min: intp(0), Max: intp(MaxShards),
		Help: "Primary shards for each new day's events, per data model. One, the default, suits a few GB a day. Give more to a system whose busiest data model stores tens of GB a day, " +
			"about one shard per OpenSearch data node, so a day is spread over the nodes and no shard grows past about 50 GB. More shards than data nodes are not used. " +
			"Days already stored keep theirs; a day restored from an archive gets this setting.",
		Placeholder: "1", EmptyMeans: "1"},
	{Key: "cluster.opensearch_url", Scope: ScopeCluster, Section: "opensearch", Label: "Address for new servers", Type: TypeURL, SharedOnly: true,
		Help: "The OpenSearch address a new server is given when it is added to these servers, when it reaches OpenSearch another way than this one does: " +
			"each server's own Address above may be, for one, 127.0.0.1.",
		Placeholder: "https://opensearch.example.com:9200", EmptyMeans: "this server's address", check: noSecretIn("each server keeps its own OpenSearch username and password")},

	{Key: "search.default_earliest", Scope: ScopeCluster, Section: "search", Label: "Default time range", Type: TypeChoice,
		Help: "The time range the Search page starts with until someone picks another, and of a search sent without one, such as from the API.", check: checkEarliest,
		Choices: []Choice{{"-15m", "Last 15 minutes"}, {"-1h", "Last hour"}, {"-4h", "Last 4 hours"},
			{"-24h", "Last 24 hours"}, {"-7d", "Last 7 days"}, {"-30d", "Last 30 days"}}},
	{Key: "search.max_events", Scope: ScopeCluster, Section: "search", Label: "Events per search", Type: TypeNumber, Min: intp(1), Max: intp(100000),
		Help: "The most events a search fetches to sort, filter or count after searching. More uses more memory."},
	{Key: "dashboards.stale_after", Scope: ScopeCluster, Section: "search", Label: "Quiet data source after", Type: TypeDuration,
		Help:        "The Posture dashboard lists a host and source type as stopped when nothing arrives from it for this long, and the detection Data source stopped sending fires for one that sent all day before. At least 5m.",
		Placeholder: "2h"},

	{Key: "syslog.udp", Scope: ScopeServer, Section: "syslog", Label: "UDP address", Type: TypeAddress, Restart: true,
		Help: "Address to receive syslog on over UDP.", Placeholder: "0.0.0.0:514", EmptyMeans: "off",
		Env: "SIGNALITH_SYSLOG_UDP"},
	{Key: "syslog.tcp", Scope: ScopeServer, Section: "syslog", Label: "TCP address", Type: TypeAddress, Restart: true,
		Help: "Address to receive syslog on over TCP.", Placeholder: "0.0.0.0:514", EmptyMeans: "off",
		Env: "SIGNALITH_SYSLOG_TCP"},
	{Key: "syslog.tls", Scope: ScopeServer, Section: "syslog", Label: "TLS address", Type: TypeAddress, Restart: true,
		Help:        "Address for syslog over TLS. It uses the same certificate as HTTPS: Signalith's own, or your own certificate files.",
		Placeholder: "0.0.0.0:6514", EmptyMeans: "off"},
	{Key: "syslog.allow", Scope: ScopeCluster, Section: "syslog", Label: "Allowed senders", Type: TypeList, Restart: true,
		Help:        "IP addresses or ranges, such as 10.0.0.0/8, that may send syslog. Others are dropped and counted.",
		Placeholder: "10.0.0.0/8", EmptyMeans: "any sender", check: checkAddressList, problem: listProblem("syslog.allow")},
	{Key: "syslog.proxy_protocol", Scope: ScopeServer, Section: "syslog", Label: "PROXY protocol from load balancers", Type: TypeBool, Restart: true,
		Help: "Accept a PROXY protocol header (v1 or v2) on the TCP and TLS addresses from the trusted reverse proxies, so a load balancer in front still lets Signalith see each device's address for Allowed senders, limits and the host field. UDP is not affected.",
		Env:  "SIGNALITH_SYSLOG_PROXY_PROTOCOL"},
	{Key: "syslog.public_port", Scope: ScopeCluster, Section: "syslog", Label: "Port devices send to", Type: TypeNumber, Restart: true, Min: intp(0), Max: intp(65535),
		Help:       "When Docker or a firewall forwards another port to the one Signalith listens on, the port devices send to. Add data shows it.",
		EmptyMeans: "the listen port"},

	{Key: "detections.scheduler", Scope: ScopeServer, Section: "detections", Label: "Run detections on schedule", Type: TypeBool, Restart: true, LegacyOnly: true,
		Help:    "Lets this server run detections, threat intel downloads, notifications and retention. Servers that share one OpenSearch take turns automatically; turn it off only on a server that should never run them.",
		Env:     "SIGNALITH_LEADER_ELIGIBLE",
		Confirm: "This server will stop running detections, threat intel downloads, notifications and retention. If no other server shares its OpenSearch, none of them run until this is turned on again.", ConfirmWhen: "off"},
	{Key: "cluster.role", Scope: ScopeServer, Section: "detections", Label: "Server role", Type: TypeChoice, Restart: true, SharedOnly: true,
		Help: "A cluster server shares the work: it can run the background jobs and take over when another server stops. " +
			"A scanner only scans the networks picked for it on the Vulnerabilities page, from inside their zone, and never runs the background jobs. " +
			"Add a server sets it when the server joins; the Servers page shows it.",
		Choices: []Choice{{RoleServer, "Cluster server: shares the work"}, {RoleScanner, "Scanner: scans its network zone only"}},
		Confirm: "As a scanner, this server never runs detections, threat intel downloads, notifications, playbooks or retention; as a cluster server it may take them over. " +
			"If only scanners are left, none of those jobs run."},
	{Key: "cluster.leader_eligible", Scope: ScopeServer, Section: "detections", Label: "May run background jobs", Type: TypeBool, Restart: true, SharedOnly: true,
		Help: "Lets this server run detections, threat intel downloads, notifications, playbooks and retention. The servers take turns automatically, one at a time; " +
			"turn it off only on a server that should never run them. A scanner (Server role) never runs them, whatever this says. Its old name in signalith.yaml, detections.scheduler, still works.",
		Env:     "SIGNALITH_LEADER_ELIGIBLE",
		Confirm: "This server will stop running detections, threat intel downloads, notifications, playbooks and retention. If no other server may run them, none of them run until this is turned on again.", ConfirmWhen: "off"},
	{Key: "detections.max_findings_per_run", Scope: ScopeCluster, Section: "detections", Label: "Most findings per run", Type: TypeNumber, Min: intp(1), Max: intp(10000),
		Help: "The most findings one detection run can raise, so a noisy rule cannot flood the queue."},
	{Key: "detections.catch_up", Scope: ScopeCluster, Section: "detections", Label: "Make up missed runs", Type: TypeDuration,
		Help:        "When detections could not run, for example while every server was stopped, how far back the missed runs are made up once they run again. Older ones are skipped and shown on the Detections page. 0 turns this off.",
		Placeholder: "6h", EmptyMeans: "6h"},
	{Key: "detections.content_updates", Scope: ScopeServer, Section: "detections", Label: "Content pack updates", Type: TypeChoice,
		Help: "Newer SigmaHQ and Splunk rules, tested and signed by the Signalith project, without a new Signalith release. " +
			"Manual: an admin checks for them on the Detections page, or uploads them on a computer without internet access. " +
			"Daily: this server checks once a day and installs them. Rules you turned on stay on, and new rules start off.",
		Choices: []Choice{{ContentManual, "Manual"}, {ContentDaily, "Daily"}}, EmptyMeans: ContentManual},
	{Key: "detections.sync", Scope: ScopeServer, Section: "detections", Label: "Detection and dashboard folders", Type: TypeChoice, SharedOnly: true,
		Help: "The servers of a cluster share one set of detections and dashboards; this server's folders are an inbox for them. " +
			"Inbox: a file added or changed in a folder, such as by a git pull, is shared with every server, and removing a file changes nothing. " +
			"Mirror: removing a file also removes that detection or dashboard from every server.",
		Choices: []Choice{{SyncInbox, "Inbox"}, {SyncMirror, "Mirror"}}, EmptyMeans: SyncInbox},
	{Key: "detections.content_url", Scope: ScopeCluster, Section: "detections", Label: "Content update address", Type: TypeURL,
		Help:        "Where content updates are downloaded from, such as a copy on your own web server. Only bundles signed by the Signalith project are installed, wherever they come from.",
		Placeholder: DefaultContentURL, EmptyMeans: "the Signalith project's GitHub releases"},

	{Key: "assistant.provider", Scope: ScopeCluster, Section: "assistant", Label: "Provider", Type: TypeChoice,
		Help: "Who runs the model. OpenAI or compatible includes Ollama, LM Studio and vLLM on your own hardware.",
		Choices: []Choice{{"", "Off"}, {assistant.Anthropic, "Anthropic"},
			{assistant.OpenAI, "OpenAI or compatible"}}},
	{Key: "assistant.url", Scope: ScopeCluster, Section: "assistant", Label: "Address", Type: TypeURL,
		Help:        "Where the model runs: the provider's own service, a model server on your own hardware such as Ollama, or another compatible service.",
		Placeholder: "http://localhost:11434/v1", EmptyMeans: "the provider's own address", check: noSecretIn("put the key in API key below")},
	{Key: "assistant.model", Scope: ScopeCluster, Section: "assistant", Label: "Model", Type: TypeText,
		Help:        "Which model answers. With an API key saved, the list comes from the provider itself. Required for OpenAI or compatible, such as llama3.1 with Ollama.",
		Placeholder: "llama3.1", EmptyMeans: "the provider's default model", problem: modelProblem},
	{Key: "assistant.api_key", Scope: ScopeCluster, Section: "assistant", Label: "API key", Type: TypeSecret,
		Help: "Only sent to the provider's address it was entered for. Local models often need none.",
		Env:  "SIGNALITH_ASSISTANT_API_KEY", SentWith: []string{"assistant.provider", "assistant.url"},
		sentTo: func(c *Config) string { return c.AssistantURL() }},
	{Key: "assistant.investigate", Scope: ScopeCluster, Section: "assistant", Label: "Investigate with AI", Type: TypeBool,
		Help: "Lets analysts ask the model to investigate a finding. It sends the finding's events, the host and user history, threat intel matches and the results of read-only searches, " +
			"with the fields below masked. Analysts see exactly what is sent before it goes. For data that must stay in-house, use a model on your own hardware, such as Ollama.",
		Confirm: "Event data from findings, such as user names, host names and IP addresses, will be sent to the AI model when an analyst investigates a finding. " +
			"With a cloud provider, it leaves your network.", ConfirmWhen: "on"},
	{Key: "assistant.mask_fields", Scope: ScopeCluster, Section: "assistant", Label: "Fields never sent", Type: TypeList,
		Help: "Fields whose values are replaced with stand-ins such as masked-user-1 wherever they appear, such as user or src. The same value always gets the same stand-in, " +
			"and the real values are put back into the model's searches and its write-up. Add _raw to leave out the original event text. Wildcards * work, and a field covers its subfields: user also masks user.name. " +
			"Passwords, tokens, keys and cookies are always masked.",
		Placeholder: "user, _raw", EmptyMeans: "only passwords, tokens, keys and cookies"},
	{Key: "assistant.request_timeout", Scope: ScopeCluster, Section: "assistant", Label: "Answer time limit", Type: TypeDuration,
		Help: "How long one answer from the model may take, for Test and each turn of Investigate with AI. Ask waits at most 90 seconds, then keeps its own query. " +
			"A local model on a CPU without a GPU can take 5 to 15 minutes for one investigation turn, so give it 15m or more. From 30s to 1h.",
		Placeholder: "15m", EmptyMeans: "3m"},
	{Key: "assistant.investigate_timeout", Scope: ScopeCluster, Section: "assistant", Label: "Investigation time limit", Type: TypeDuration,
		Help: "How long one Investigate with AI may take in all, every model turn and search included. " +
			"The model may take up to 4 turns, so with a slow local model allow about 3 times the answer time limit, such as 45m. From 30s to 2h.",
		Placeholder: "45m", EmptyMeans: "6m"},

	{Key: "auth.oidc.enabled", Scope: ScopeCluster, Section: "sso", Label: "Single sign-on", Type: TypeBool,
		Help: "Shows a sign-in button for the identity provider on the sign-in page. Local users, directory sign-in and the built-in admin keep working."},
	{Key: "auth.oidc.provider", Scope: ScopeCluster, Section: "sso", Label: "Identity provider", Type: TypeChoice,
		Help: "Picks the usual claims and scopes of the provider. Other works with any OpenID Connect provider.",
		Choices: []Choice{{"", "Not chosen"}, {oidc.Entra, "Microsoft Entra ID"}, {oidc.Okta, "Okta"}, {oidc.Google, "Google"},
			{oidc.Keycloak, "Keycloak"}, {oidc.Other, "Other OpenID Connect provider"}}},
	{Key: "auth.oidc.issuer", Scope: ScopeCluster, Section: "sso", Label: "Issuer", Type: TypeURL,
		Help:        "The provider's issuer address, exactly as its discovery document names it.",
		Placeholder: "https://login.microsoftonline.com/<tenant ID>/v2.0", EmptyMeans: "Google's, https://accounts.google.com, with Google",
		check: noSecretIn("put the client secret in its own field")},
	{Key: "auth.oidc.client_id", Scope: ScopeCluster, Section: "sso", Label: "Client ID", Type: TypeText,
		Help: "The client (application) ID the identity provider gave Signalith."},
	{Key: "auth.oidc.client_secret", Scope: ScopeCluster, Section: "sso", Label: "Client secret", Type: TypeSecret,
		Help: "Kept encrypted, and only sent to the issuer it was entered for. Leave it empty for a public client that uses PKCE alone.",
		Env:  "SIGNALITH_OIDC_CLIENT_SECRET", SentWith: []string{"auth.oidc.provider", "auth.oidc.issuer"},
		sentTo: func(c *Config) string { return c.OIDCIssuer() }},
	{Key: "auth.oidc.scopes", Scope: ScopeCluster, Section: "sso", Label: "Scopes", Type: TypeList,
		Help:        "Asked for besides openid.",
		Placeholder: "email", EmptyMeans: "the provider's usual ones, such as profile and email"},
	{Key: "auth.oidc.username_claim", Scope: ScopeCluster, Section: "sso", Label: "Username claim", Type: TypeText,
		Help:        "The claim that becomes the Signalith username.",
		Placeholder: "preferred_username", EmptyMeans: "preferred_username, or email with Google"},
	{Key: "auth.oidc.groups_claim", Scope: ScopeCluster, Section: "sso", Label: "Groups claim", Type: TypeText,
		Help:        "The claim listing the user's groups or roles. A dotted name, such as realm_access.roles, looks inside nested claims.",
		Placeholder: "groups", EmptyMeans: "groups (Google sends none)"},
	{Key: "auth.oidc.admin_groups", Scope: ScopeCluster, Section: "sso", Label: "Admins", Type: TypeList,
		Help: "Groups whose members are admins, as the groups claim names them. A verified email address works too. Someone in several lists gets the highest role."},
	{Key: "auth.oidc.analyst_groups", Scope: ScopeCluster, Section: "sso", Label: "Analysts", Type: TypeList,
		Help: "Groups whose members are analysts."},
	{Key: "auth.oidc.viewer_groups", Scope: ScopeCluster, Section: "sso", Label: "Viewers", Type: TypeList,
		Help: "Groups whose members are viewers."},
	{Key: "auth.oidc.default_role", Scope: ScopeCluster, Section: "sso", Label: "Anyone else", Type: TypeChoice,
		Help:    "What people in none of the groups above get.",
		Choices: []Choice{{"none", "Not let in"}, {"viewer", "Viewer"}}, EmptyMeans: "none"},
	{Key: "auth.oidc.allowed_domains", Scope: ScopeCluster, Section: "sso", Label: "Allowed email domains", Type: TypeList,
		Help:        "Lets in only people whose verified email address is in one of these domains. Needed with Google when anyone else is a viewer.",
		Placeholder: "example.com", EmptyMeans: "any"},
	{Key: "auth.oidc.create_users", Scope: ScopeCluster, Section: "sso", Label: "Add users at first sign-in", Type: TypeBool,
		Help: "Adds people to Users the first time they sign in. Turned off, only people who signed in before can."},
	{Key: "auth.oidc.button_label", Scope: ScopeCluster, Section: "sso", Label: "Button label", Type: TypeText,
		Help:        "The sign-in page's button.",
		Placeholder: "Sign in with Okta", EmptyMeans: "Sign in with and the provider's name"},
	{Key: "auth.saml.enabled", Scope: ScopeCluster, Section: "sso", Label: "SAML single sign-on", Type: TypeBool,
		Help: "Shows a sign-in button for the SAML identity provider on the sign-in page. Works alongside OpenID Connect, local users, directory sign-in and the built-in admin."},
	{Key: "auth.saml.provider", Scope: ScopeCluster, Section: "sso", Label: "Identity provider", Type: TypeChoice,
		Help:    "Picks the usual attributes of the provider. Other works with any SAML 2.0 provider.",
		Choices: []Choice{{"", "Not chosen"}, {saml.ADFS, "AD FS"}, {saml.Entra, "Microsoft Entra ID"}, {saml.Okta, "Okta"}, {saml.Other, "Other SAML 2.0 provider"}}},
	{Key: "auth.saml.metadata_url", Scope: ScopeCluster, Section: "sso", Label: "Metadata URL", Type: TypeURL,
		Help:        "Where the provider publishes its SAML metadata. Signalith reads it again every hour, so a new signing certificate is picked up by itself.",
		Placeholder: "https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml", check: samlMetadataURL},
	{Key: "auth.saml.metadata_xml", Scope: ScopeCluster, Section: "sso", Label: "Metadata XML", Type: TypeText,
		Help:       "Only if Signalith cannot reach the metadata URL: paste the provider's metadata file here instead. Paste it again when the provider's signing certificate changes.",
		EmptyMeans: "read from the metadata URL", check: samlMetadataXML},
	{Key: "auth.saml.username_attribute", Scope: ScopeCluster, Section: "sso", Label: "Username attribute", Type: TypeText,
		Help:        "The attribute that becomes the Signalith username. NameID uses the subject's NameID.",
		Placeholder: "NameID", EmptyMeans: "the provider's usual one"},
	{Key: "auth.saml.groups_attribute", Scope: ScopeCluster, Section: "sso", Label: "Groups attribute", Type: TypeText,
		Help:        "The attribute listing the user's groups or roles.",
		Placeholder: "groups", EmptyMeans: "the provider's usual one"},
	{Key: "auth.saml.admin_groups", Scope: ScopeCluster, Section: "sso", Label: "Admins", Type: TypeList,
		Help: "Groups whose members are admins, as the groups attribute names them. An email address works too. Someone in several lists gets the highest role."},
	{Key: "auth.saml.analyst_groups", Scope: ScopeCluster, Section: "sso", Label: "Analysts", Type: TypeList,
		Help: "Groups whose members are analysts."},
	{Key: "auth.saml.viewer_groups", Scope: ScopeCluster, Section: "sso", Label: "Viewers", Type: TypeList,
		Help: "Groups whose members are viewers."},
	{Key: "auth.saml.default_role", Scope: ScopeCluster, Section: "sso", Label: "Anyone else", Type: TypeChoice,
		Help:    "What people in none of the groups above get.",
		Choices: []Choice{{"none", "Not let in"}, {"viewer", "Viewer"}}, EmptyMeans: "none"},
	{Key: "auth.saml.create_users", Scope: ScopeCluster, Section: "sso", Label: "Add users at first sign-in", Type: TypeBool,
		Help: "Adds people to Users the first time they sign in. Turned off, only people who signed in before can."},
	{Key: "auth.saml.button_label", Scope: ScopeCluster, Section: "sso", Label: "Button label", Type: TypeText,
		Help:        "The sign-in page's button.",
		Placeholder: "Sign in with AD FS", EmptyMeans: "Sign in with and the provider's name"},
	{Key: "auth.scim.enabled", Scope: ScopeCluster, Section: "sso", Label: "Provisioning (SCIM)", Type: TypeBool,
		Help: "Lets the identity provider add, update, disable and remove single sign-on users before they sign in, over SCIM 2.0. Roles still come from groups at each sign-in."},
	{Key: "auth.scim.token_sha256", Scope: ScopeCluster, Section: "sso", Label: "SCIM token", Type: TypeText,
		Help:  "The identity provider sends this token with every request. Signalith keeps only its SHA-256 fingerprint, so the token is shown once, when you create it.",
		check: sha256Hex},

	{Key: "intel.allow_loopback_feeds", Scope: ScopeCluster, Section: "intel", Label: "Allow feeds from this computer", Type: TypeBool, Restart: true,
		Help:    "Lets feeds download from 127.0.0.1 or ::1, for a feed server on this computer.",
		Confirm: "Feeds can then reach services on this computer that are not meant to be reachable from outside. Turn this on only if a feed server runs here.", ConfirmWhen: "on"},
	{Key: "vulns.nvd_api_key", Scope: ScopeCluster, Section: "vulns", Label: "NVD API key", Type: TypeSecret,
		Help: "Optional and free from https://nvd.nist.gov/developers/request-an-api-key. Without one, the National Vulnerability Database allows " +
			"5 lookups every 30 seconds, so a first scan that finds a lot of different software takes a few extra minutes; with one, lookups are about ten times faster.",
		Env: "SIGNALITH_NVD_API_KEY", SentWith: []string{"vulns.nvd_url"}, sentTo: func(c *Config) string { return c.NVDURL() }},
	{Key: "vulns.nvd_url", Scope: ScopeCluster, Section: "vulns", Label: "CVE database address", Type: TypeURL,
		Help:        "Only for a copy of the NVD's CVE API 2.0 on your own network.",
		Placeholder: DefaultNVDURL, EmptyMeans: "the National Vulnerability Database", Env: "SIGNALITH_NVD_URL",
		check: noSecretIn("put the key in NVD API key above")},

	{Key: "vulns.kev_url", Scope: ScopeCluster, Section: "vulns", Label: "Known exploited catalog address", Type: TypeText,
		Help: "Only for a copy of CISA's Known Exploited Vulnerabilities catalog (JSON) on your own network, or, with no internet, " +
			"the path of that file on the server that runs the background jobs. Signalith reads it once a day.",
		Placeholder: DefaultKEVURL, EmptyMeans: "CISA's catalog", Env: "SIGNALITH_KEV_URL",
		check: func(v any) error { return FeedSource(v.(string)) }},
	{Key: "vulns.epss_url", Scope: ScopeCluster, Section: "vulns", Label: "EPSS scores address", Type: TypeText,
		Help: "Only for a copy of FIRST's daily EPSS scores (CSV, gzipped or not) on your own network, or, with no internet, " +
			"the path of that file on the server that runs the background jobs. Signalith reads it once a day.",
		Placeholder: DefaultEPSSURL, EmptyMeans: "FIRST's scores", Env: "SIGNALITH_EPSS_URL",
		check: func(v any) error { return FeedSource(v.(string)) }},

	{Key: "m365.tenant_id", Scope: ScopeCluster, Section: "m365", Label: "Tenant ID", Type: TypeText,
		Help:        "Your Microsoft 365 tenant's ID (Directory (tenant) ID on the app's Overview page in Entra ID).",
		Placeholder: "11111111-2222-3333-4444-555555555555", EmptyMeans: "off", check: m365ID("tenant ID")},
	{Key: "m365.client_id", Scope: ScopeCluster, Section: "m365", Label: "Application (client) ID", Type: TypeText,
		Help:        "The ID of the app registered in Entra ID, which has the Office 365 Management APIs permission ActivityFeed.Read.",
		Placeholder: "11111111-2222-3333-4444-555555555555", EmptyMeans: "off", check: m365ID("application ID")},
	{Key: "m365.client_secret", Scope: ScopeCluster, Section: "m365", Label: "Client secret", Type: TypeSecret,
		Help: "A client secret of that app (its Value, not its ID). Only sent to Microsoft's sign-in service, for the tenant and app it was entered for.",
		Env:  "SIGNALITH_M365_CLIENT_SECRET", SentWith: []string{"m365.cloud", "m365.tenant_id", "m365.client_id"},
		sentTo: func(c *Config) string { return c.M365TokenURL() + "#" + c.M365.ClientID }},
	{Key: "m365.cloud", Scope: ScopeCluster, Section: "m365", Label: "Microsoft cloud", Type: TypeChoice,
		Help:       "Which Microsoft cloud the tenant is in. Most are in the commercial cloud; US government tenants are in GCC, GCC High or DoD.",
		Choices:    []Choice{{"commercial", "Commercial"}, {"gcc", "GCC"}, {"gcc_high", "GCC High"}, {"dod", "DoD"}},
		EmptyMeans: "Commercial"},

	{Key: "okta.domain", Scope: ScopeCluster, Section: "okta", Label: "Okta domain", Type: TypeText,
		Help:        "Your Okta organization's domain, as in the address of its sign-in page.",
		Placeholder: "example.okta.com", EmptyMeans: "off", check: checkOktaDomain},
	{Key: "okta.client_id", Scope: ScopeCluster, Section: "okta", Label: "Client ID", Type: TypeText,
		Help:        "The client ID of the API service app, which is granted the okta.logs.read scope.",
		Placeholder: "0oa1b2c3d4e5f6g7h8i9", EmptyMeans: "no app", check: checkOktaClientID},
	{Key: "okta.private_key", Scope: ScopeCluster, Section: "okta", Label: "Private key", Type: TypeSecret,
		Help: "The app's private key, as PEM or as the JWK Okta's admin console shows. Only used to sign in to your Okta organization's token endpoint.",
		Env:  "SIGNALITH_OKTA_PRIVATE_KEY", SentWith: []string{"okta.domain", "okta.client_id"},
		sentTo: func(c *Config) string { return c.OktaTokenURL() }, check: func(v any) error { return CheckOktaPrivateKey(v) }},
	{Key: "okta.key_id", Scope: ScopeCluster, Section: "okta", Label: "Key ID", Type: TypeText,
		Help:       "The ID (kid) of that key on the app's page, needed only when the app has more than one key.",
		EmptyMeans: "the key's own", check: checkOktaKeyID},
	{Key: "okta.api_token", Scope: ScopeCluster, Section: "okta", Label: "API token", Type: TypeSecret,
		Help: "An admin's API token, in place of the app. It has all of that admin's rights, so the app is the better way. Only sent to your Okta organization.",
		Env:  "SIGNALITH_OKTA_API_TOKEN", SentWith: []string{"okta.domain"},
		sentTo: func(c *Config) string { return c.OktaLogsURL() }},
}

// Exclusion is a setting of Config that is not on the Settings page.
type Exclusion struct {
	Scope  Scope
	Reason string // why it is not on the page
}

// Excluded lists the settings of Config that are not on the Settings
// page, and why.
var Excluded = map[string]Exclusion{
	"retention.days":             {ScopeCluster, "Data retention has its own page."},
	"retention.interval":         {ScopeCluster, "Data retention has its own page."},
	"retention.archive_dir":      {ScopeServer, "Data retention has its own page, and archived days are kept in this folder."},
	"retention.encrypt_archives": {ScopeServer, "Archives are encrypted with this server's master key; only signalith.yaml can turn that off, for tools that read the files directly."},
	"retention.default":          {ScopeCluster, "Data retention has its own page."},
	"retention.policies":         {ScopeCluster, "Data retention has its own page."},
	"retention.guard":            {ScopeCluster, "Data retention has its own page."},
	"auth.admin_user":            {ScopeCluster, "The built-in admin is the break-glass account, so no change on a page can lock everyone out. It is set in signalith.yaml, or with signalith cluster apply on servers that share their settings."},
	"auth.admin_password_hash":   {ScopeCluster, "The built-in admin's password is changed on the server with signalith passwd."},
	"auth.users_file":            {ScopeBootstrap, "The Users page keeps its users there, and a page cannot move a file it depends on. Shown under About this server."},
	"auth.ldap":                  {ScopeCluster, "Directory sign-in is set up on the Users page."},
	"ingest.tokens":              {ScopeCluster, "Shared agent tokens from older setups and the Docker quick start: signalith.yaml (ingest.tokens) or SIGNALITH_INGEST_TOKEN(_FILE). New agents get their own token on Add data."},
	"detections.dir":             {ScopeBootstrap, "Pages save detections there, and a page cannot move a folder it saves into. Shown under About this server."},
	"lookups.dir":                {ScopeBootstrap, "It holds this page's own settings file, users and lists, so it cannot move from a page. Shown under About this server."},
	"dashboards.dir":             {ScopeBootstrap, "Pages save dashboards there, and a page cannot move a folder it saves into. Shown under About this server."},
	"intel.feeds":                {ScopeCluster, "Feeds are added and changed on the Threat intel page."},
	"intel.feeds_file":           {ScopeBootstrap, "The Threat intel page keeps its feeds there, and a page cannot move a file it depends on. Shown under About this server."},
	"notify.file":                {ScopeBootstrap, "The Notifications page keeps its channels and rules there, and a page cannot move a file it depends on. Shown under About this server."},
	"response.file":              {ScopeBootstrap, "The Response actions page keeps its actions there, and a page cannot move a file it depends on. Shown under About this server."},
	"playbooks.file":             {ScopeBootstrap, "The Playbooks page keeps its playbooks there, and a page cannot move a file it depends on. Shown under About this server."},
	"response.scripts_dir":       {ScopeServer, "It decides which programs response actions may run, so only signalith.yaml or SIGNALITH_RESPONSE_SCRIPTS_DIR can set it, never a page. Shown under About this server."},
	"vulns.openvas_address":      {ScopeServer, "OpenVAS runs on the scanning server itself, so it is set there: signalith.yaml or SIGNALITH_OPENVAS_*. Settings > Scanners shows each server’s OpenVAS check."},
	"vulns.openvas_username":     {ScopeServer, "OpenVAS runs on the scanning server itself, so it is set there: signalith.yaml or SIGNALITH_OPENVAS_*. Settings > Scanners shows each server’s OpenVAS check."},
	"vulns.openvas_password":     {ScopeServer, "OpenVAS runs on the scanning server itself, so it is set there: signalith.yaml or SIGNALITH_OPENVAS_*. Settings > Scanners shows each server’s OpenVAS check. The password can be kept encrypted with signalith secrets set vulns.openvas_password."},
	"vulns.openvas_ca_file":      {ScopeServer, "OpenVAS runs on the scanning server itself, so it is set there: signalith.yaml or SIGNALITH_OPENVAS_*. Settings > Scanners shows each server’s OpenVAS check."},
	"cluster.node_name":          {ScopeBootstrap, "This server's name is set in signalith.yaml or with SIGNALITH_NODE_NAME, and kept in its state folder once chosen. The Servers page shows it."},
}

// ScopeOf returns the scope of a setting of Config, on the page or not,
// or "" for a key that is neither.
func ScopeOf(key string) Scope {
	if s, ok := Lookup(key); ok {
		return s.Scope
	}
	return Excluded[key].Scope
}

// Lookup returns the setting with a key.
func Lookup(key string) (*Setting, bool) {
	for i := range Registry {
		if Registry[i].Key == key {
			return &Registry[i], true
		}
	}
	return nil, false
}

// LeafKeys lists every setting of Config by its key, such as
// "server.listen". Lists and nested settings, such as intel.feeds and
// auth.ldap, are one key each.
func LeafKeys() []string {
	var out []string
	var walk func(t reflect.Type, prefix string)
	walk = func(t reflect.Type, prefix string) {
		for i := range t.NumField() {
			f := t.Field(i)
			name := yamlName(f)
			if name == "" {
				continue
			}
			if f.Type.Kind() == reflect.Struct && f.Type != reflect.TypeOf(time.Time{}) {
				walk(f.Type, prefix+name+".")
				continue
			}
			if f.Type.Kind() == reflect.Pointer && sectionPointers[f.Type.Elem()] {
				walk(f.Type.Elem(), prefix+name+".")
				continue
			}
			out = append(out, prefix+name)
		}
	}
	walk(reflect.TypeOf(Config{}), "")
	return out
}

// yamlName is a field's key in signalith.yaml, or "" for fields that are
// not in the file.
func yamlName(f reflect.StructField) string {
	if !f.IsExported() {
		return ""
	}
	name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
	if name == "-" || name == "" {
		return ""
	}
	return name
}

// sectionPointers are the sections of signalith.yaml held by a pointer,
// whose settings are on the page one by one: server.tls, which a file
// from before HTTPS was the default does not have. Other pointers, such
// as auth.ldap, are one setting.
var sectionPointers = map[reflect.Type]bool{reflect.TypeOf(ServerTLS{}): true}

// tlsKeys are the settings whose change on the page fills in the
// server.tls section of a file that has none (see Server.materializeTLS).
func tlsKey(key string) bool {
	return strings.HasPrefix(key, "server.tls.") || key == "server.tls_cert" || key == "server.tls_key" || key == "server.public_url"
}

// field returns the value a key names in c, to read. A setting in a
// section c does not have, such as server.tls in a file from before
// HTTPS was the default, reads as its zero value.
func field(c *Config, key string) (reflect.Value, bool) { return walkField(c, key, false) }

// fieldToSet is field for a setting about to be changed. A missing
// server.tls section is filled in as in effect (see Server.materializeTLS)
// and a shared one is copied first, so changing a shallow copy of c, as
// the settings applied at once are, never changes c itself.
func fieldToSet(c *Config, key string) (reflect.Value, bool) {
	if tlsKey(key) {
		c.Server.materializeTLS(c.Server)
		t := *c.Server.TLS
		t.Names = slices.Clone(t.Names)
		c.Server.TLS = &t
	}
	return walkField(c, key, true)
}

func walkField(c *Config, key string, set bool) (reflect.Value, bool) {
	v := reflect.ValueOf(c).Elem()
	for _, part := range strings.Split(key, ".") {
		if v.Kind() == reflect.Pointer && sectionPointers[v.Type().Elem()] {
			switch {
			case !v.IsNil():
				v = v.Elem()
			case set:
				v.Set(reflect.New(v.Type().Elem()))
				v = v.Elem()
			default:
				v = reflect.New(v.Type().Elem()).Elem()
			}
		}
		if v.Kind() != reflect.Struct {
			return reflect.Value{}, false
		}
		found := false
		t := v.Type()
		for i := range t.NumField() {
			if yamlName(t.Field(i)) == part {
				v, found = v.Field(i), true
				break
			}
		}
		if !found {
			return reflect.Value{}, false
		}
	}
	return v, true
}

// Value returns the value of a setting in c: a string, int, bool or
// []string. Lists are never nil.
//
// A public address worked out from the listen address is "", and an
// http:// one read as https:// (see Validate) is the http:// one, as they
// were set: that is what the page shows, compares and saves. The HTTPS
// mode and plain-HTTP ingest are the ones in effect, which for a file
// from before HTTPS was the default follow from its other settings.
func (c *Config) Value(key string) any {
	v, ok := field(c, key)
	if !ok {
		return nil
	}
	switch key {
	case "server.public_url":
		if c.publicURLDerived {
			return ""
		}
		if c.httpPublicURL != "" {
			return c.httpPublicURL
		}
	case "server.agent_listen":
		if c.agentListenDerived {
			return ""
		}
	case "server.tls.mode":
		return c.Server.TLSMode()
	case "server.tls.plaintext_ingest":
		if c.Server.PlaintextIngest() {
			return "allow"
		}
		return "deny"
	case "server.tls.ca_scope":
		return c.Server.CAScope()
	case "cluster.leader_eligible":
		return c.LeaderEligible()
	}
	if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.String {
		out := make([]string, v.Len())
		for i := range out {
			out[i] = v.Index(i).String()
		}
		return out
	}
	return v.Interface()
}

// SetValue sets a setting in c to a value of its type, as ParseValue
// returns it.
func (c *Config) SetValue(key string, val any) error {
	v, ok := field(c, key)
	if !ok {
		return fmt.Errorf("unknown setting %s", key)
	}
	nv := reflect.ValueOf(val)
	if v.Kind() == reflect.Pointer && nv.Type().AssignableTo(v.Type().Elem()) {
		// A setting that may be left unset, such as cluster.leader_eligible,
		// is set to a value of its own.
		p := reflect.New(v.Type().Elem())
		p.Elem().Set(nv)
		nv = p
	}
	if !nv.Type().AssignableTo(v.Type()) {
		return fmt.Errorf("%s takes a %s, not a %s", key, v.Type(), nv.Type())
	}
	v, _ = fieldToSet(c, key)
	v.Set(nv)
	switch key {
	case "server.public_url":
		c.publicURLDerived, c.httpPublicURL = false, ""
	case "server.agent_listen":
		c.agentListenDerived = false
	}
	return nil
}

// CopyValue sets a setting in c to its value in from. The live settings
// saved on the page reach the running server this way. A secret saved on
// the page brings whether it could be decrypted with it, so Warnings and
// the Settings page stop reporting one entered again.
func (c *Config) CopyValue(key string, from *Config) error {
	src, ok := field(from, key)
	if !ok {
		return fmt.Errorf("unknown setting %s", key)
	}
	if key == "server.tls.mode" || key == "server.tls.plaintext_ingest" || key == "server.tls.ca_scope" {
		// The value in effect, which an empty one in the file is not.
		return c.SetValue(key, from.Value(key))
	}
	dst, _ := fieldToSet(c, key)
	dst.Set(src)
	switch key {
	case "server.public_url":
		c.publicURLDerived, c.httpPublicURL = from.publicURLDerived, from.httpPublicURL
	case "server.agent_listen":
		c.agentListenDerived = from.agentListenDerived
	case "cluster.leader_eligible", "detections.scheduler":
		// Two names for one setting (see syncEligible).
		v := from.LeaderEligible()
		c.Cluster.LeaderEligible, c.Detections.Scheduler = &v, v
	}
	c.copyPageProblem(key, from)
	c.copySharedSource(key, from)
	return nil
}

// SameValue reports whether a setting is the same in a and b. An empty
// list and no list are the same.
func SameValue(a, b *Config, key string) bool {
	va, vb := a.Value(key), b.Value(key)
	return reflect.DeepEqual(va, vb)
}

// ParseValue reads a value for a setting from the page, as JSON decoded
// it (a string, float64 or json.Number, bool, or list), and returns it as
// the setting's own type. Text is trimmed.
func ParseValue(s *Setting, raw any) (any, error) {
	v, ok := field(&Config{}, s.Key)
	if !ok {
		return nil, fmt.Errorf("unknown setting %s", s.Key)
	}
	if v.Kind() == reflect.Pointer {
		v = reflect.New(v.Type().Elem()).Elem()
	}
	switch v.Kind() {
	case reflect.String:
		str, ok := raw.(string)
		if raw == nil {
			str, ok = "", true
		}
		if !ok {
			return nil, fmt.Errorf("enter text")
		}
		if s.Type == TypeSecret {
			// Secrets are taken as typed: spaces can be part of one. One
			// that looks encrypted would be kept as it is, not encrypted.
			if secrets.IsSealed(str) {
				return nil, errors.New("the value cannot start with enc:v and a number and a colon, which is how encrypted values look")
			}
			return str, nil
		}
		str = strings.TrimSpace(str)
		if err := noControl(str); err != nil {
			return nil, err
		}
		// As the field's own type, such as Replicas.
		return reflect.ValueOf(str).Convert(v.Type()).Interface(), nil
	case reflect.Int:
		var f float64
		switch n := raw.(type) {
		case float64:
			f = n
		case interface{ Float64() (float64, error) }:
			var err error
			if f, err = n.Float64(); err != nil {
				return nil, fmt.Errorf("enter a whole number")
			}
		case string:
			var err error
			if f, err = strconv.ParseFloat(strings.TrimSpace(n), 64); err != nil || strings.TrimSpace(n) == "" {
				return nil, fmt.Errorf("enter a whole number")
			}
		default:
			return nil, fmt.Errorf("enter a whole number")
		}
		if f != float64(int(f)) {
			return nil, fmt.Errorf("enter a whole number")
		}
		n := int(f)
		if s.Min != nil && n < *s.Min || s.Max != nil && n > *s.Max {
			return nil, fmt.Errorf("enter a number from %d to %d", deref(s.Min, 0), deref(s.Max, 1<<31-1))
		}
		return n, nil
	case reflect.Bool:
		b, ok := raw.(bool)
		if !ok {
			return nil, fmt.Errorf("choose on or off")
		}
		return b, nil
	case reflect.Slice:
		var items []string
		switch l := raw.(type) {
		case nil:
		case []any:
			for _, it := range l {
				str, ok := it.(string)
				if !ok {
					return nil, fmt.Errorf("enter a list of text values")
				}
				items = append(items, str)
			}
		case []string:
			items = l
		case string:
			// One value per line or comma, as typed in a text box.
			items = strings.FieldsFunc(l, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
		default:
			return nil, fmt.Errorf("enter a list of text values")
		}
		out := []string{}
		for _, it := range items {
			if it = strings.TrimSpace(it); it != "" {
				if err := noControl(it); err != nil {
					return nil, err
				}
				out = append(out, it)
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("%s cannot be changed here", s.Key)
}

// noControl refuses line breaks, tabs and other control characters in a
// one-line value, which could pass for more than one value where it is
// printed.
func noControl(s string) error {
	if strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return fmt.Errorf("remove the line break, tab or other control character")
	}
	return nil
}

// checkReplicas takes auto or a whole number of 0 or more.
func checkReplicas(v any) error {
	if r, _ := v.(Replicas); !r.Valid() {
		return errors.New("enter auto, or a whole number of 0 or more")
	}
	return nil
}

// noSecretIn refuses an address with a password or key in it, which
// would be shown on the page and in logs; why says where it goes instead.
func noSecretIn(why string) func(any) error {
	return func(v any) error {
		if hasSecret(v.(string)) {
			return fmt.Errorf("leave passwords and keys out of the address: %s", why)
		}
		return nil
	}
}

// AddressHasSecret reports whether v, a value of setting key, is an
// address with a password or key in it (see hasSecret). The Settings page
// refuses those; the shared settings take none from a server's files
// either, as they are kept unencrypted and shown on every server's page.
func AddressHasSecret(key string, v any) bool {
	s, ok := Lookup(key)
	if !ok || s.Type != TypeURL {
		return false
	}
	str, _ := v.(string)
	return hasSecret(str)
}

// hasSecret reports whether an address holds a user name and password,
// or a query parameter whose name suggests a key or token.
func hasSecret(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		// Validate refuses it; a password in it must still not be kept.
		return strings.Contains(raw, "@")
	}
	if u.User != nil || u.Host == "" && strings.Contains(raw, "@") {
		return true
	}
	for name := range u.Query() {
		if redact.SecretName(name) {
			return true
		}
	}
	return false
}

// badAddresses lists the entries of a list of IP addresses or ranges that
// are not one.
func badAddresses(list []string) []string {
	var bad []string
	for _, a := range list {
		if _, err := parseAllow(a); err != nil {
			bad = append(bad, "“"+a+"”")
		}
	}
	return bad
}

// addressListProblem words the bad entries of an address list, every one
// of them, or returns "".
func addressListProblem(list []string) string {
	bad := badAddresses(list)
	switch len(bad) {
	case 0:
		return ""
	case 1:
		return bad[0] + " isn't an IP address or a range like 10.0.0.0/8."
	}
	return joinWords(bad) + " aren't IP addresses or ranges like 10.0.0.0/8."
}

func checkAddressList(v any) error {
	if p := addressListProblem(v.([]string)); p != "" {
		return errors.New(p)
	}
	return nil
}

func listProblem(key string) func(*Config) string {
	return func(c *Config) string {
		list, _ := c.Value(key).([]string)
		return addressListProblem(list)
	}
}

// tlsModeProblem words what is wrong with the HTTPS mode and the
// certificate files together, for the mode's field.
func tlsModeProblem(c *Config) string {
	s := c.Server
	files := s.TLSCert != "" || s.TLSKey != ""
	switch s.TLSMode() {
	case TLSAuto, TLSOff:
		if files {
			return "The certificate and key files below are used only with your own certificate files. Choose that, or clear them."
		}
	case TLSFiles:
		if !files {
			return "Enter your certificate and key files below, or choose Automatic."
		}
	default:
		return "Choose Automatic, your own certificate files, or Off."
	}
	return ""
}

// tlsFileProblem words what is wrong with server.tls_cert or tls_key
// (key) for its field.
func tlsFileProblem(key string) func(*Config) string {
	return func(c *Config) string {
		s := c.Server
		mine, other := s.TLSCert, s.TLSKey
		what := "your certificate file"
		if key == "server.tls_key" {
			mine, other, what = s.TLSKey, s.TLSCert, "the certificate's key file"
		}
		switch mode := s.TLSMode(); {
		case (mode == TLSAuto || mode == TLSOff) && mine != "":
			return "Used only when HTTPS is set to your own certificate files. Choose that, or clear this."
		case mode == TLSFiles && mine == "":
			return "Enter the full path of " + what + "."
		case mode == TLSFiles && key == "server.tls_cert" && other != "":
			cert, k := c.TLSFiles()
			if _, err := tls.LoadX509KeyPair(cert, k); err != nil {
				return "The certificate and key files can't be used: " + err.Error() + "."
			}
		}
		return ""
	}
}

// badCertNames lists the entries of server.tls.names that cannot go in
// a certificate.
func badCertNames(list []string) string {
	var bad []string
	for _, n := range list {
		if !validCertName(n) {
			bad = append(bad, "“"+n+"”")
		}
	}
	switch len(bad) {
	case 0:
		return ""
	case 1:
		return bad[0] + " isn't a host name or IP address."
	}
	return joinWords(bad) + " aren't host names or IP addresses."
}

func checkCertNames(v any) error {
	if p := badCertNames(v.([]string)); p != "" {
		return errors.New(p)
	}
	return nil
}

func certNamesProblem(c *Config) string { return badCertNames(c.Server.TLSNames()) }

// caScopeProblem asks for one of the two choices.
func caScopeProblem(c *Config) string {
	if c.Server.TLS == nil {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(c.Server.TLS.CAScope)) {
	case "", CAScopeStandard, CAScopeStrict:
		return ""
	}
	return "Choose standard or strict."
}

// modelProblem asks for a model where the provider needs one named.
func modelProblem(c *Config) string {
	if c.Assistant.Provider == assistant.OpenAI && strings.TrimSpace(c.Assistant.Model) == "" {
		return "Enter the model's name: OpenAI or compatible needs one, such as llama3.1 with Ollama or gpt-4.1 with OpenAI."
	}
	return ""
}

// joinWords joins items as "a, b and c".
func joinWords(items []string) string {
	if len(items) <= 1 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

func deref(p *int, d int) int {
	if p == nil {
		return d
	}
	return *p
}

// m365ID checks a Microsoft 365 tenant or application ID: a GUID, or for
// a tenant its domain (contoso.onmicrosoft.com).
func m365ID(what string) func(any) error {
	return func(v any) error {
		s, _ := v.(string)
		if s == "" || m365IDRe.MatchString(s) || what == "tenant ID" && m365DomainRe.MatchString(s) {
			return nil
		}
		if what == "tenant ID" {
			return fmt.Errorf("the %s is a GUID such as 11111111-2222-3333-4444-555555555555, or the tenant's domain such as contoso.onmicrosoft.com", what)
		}
		return fmt.Errorf("the %s is a GUID such as 11111111-2222-3333-4444-555555555555", what)
	}
}

var (
	m365IDRe     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	m365DomainRe = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)
)

// M365On reports whether Microsoft 365's audit log is read: the tenant,
// the app and its secret are set.
func (c *Config) M365On() bool {
	return c.M365.TenantID != "" && c.M365.ClientID != "" && c.M365.ClientSecret != ""
}

// m365Clouds are each Microsoft cloud's sign-in service and Management
// Activity API.
var m365Clouds = map[string][2]string{
	"commercial": {"https://login.microsoftonline.com", "https://manage.office.com"},
	"gcc":        {"https://login.microsoftonline.com", "https://manage-gcc.office.com"},
	"gcc_high":   {"https://login.microsoftonline.us", "https://manage.office365.us"},
	"dod":        {"https://login.microsoftonline.us", "https://manage.protection.apps.mil"},
}

func (c *Config) m365Cloud() [2]string {
	if v, ok := m365Clouds[c.M365.Cloud]; ok {
		return v
	}
	return m365Clouds["commercial"]
}

// M365TokenURL is where the app signs in for the tenant.
func (c *Config) M365TokenURL() string {
	return c.m365Cloud()[0] + "/" + url.PathEscape(c.M365.TenantID) + "/oauth2/v2.0/token"
}

// M365APIURL is the Management Activity API of the tenant's cloud.
func (c *Config) M365APIURL() string { return c.m365Cloud()[1] }

// OktaOn reports whether Okta's System Log is read: the domain, and the
// app and its key or an API token, are set.
func (c *Config) OktaOn() bool {
	return c.OktaDomain() != "" && (c.Okta.ClientID != "" && c.Okta.PrivateKey != "" || c.Okta.APIToken != "")
}

// OktaDomain is the organization's Okta domain, in lower case, without
// https:// or a slash that was typed with it.
func (c *Config) OktaDomain() string { return oktaDomain(c.Okta.Domain) }

func oktaDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "https://")
	return strings.TrimSuffix(s, "/")
}

// OktaTokenURL is where the app signs in.
func (c *Config) OktaTokenURL() string { return "https://" + c.OktaDomain() + "/oauth2/v1/token" }

// OktaLogsURL is the organization's System Log API.
func (c *Config) OktaLogsURL() string { return "https://" + c.OktaDomain() + "/api/v1/logs" }

// oktaDomainRe is a host name of two or more labels.
var oktaDomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// checkOktaDomain checks an Okta domain: a host name, with no port, path
// or address.
func checkOktaDomain(v any) error {
	s, _ := v.(string)
	d := oktaDomain(s)
	if d == "" {
		return nil
	}
	if len(d) > 253 || !oktaDomainRe.MatchString(d) || net.ParseIP(d) != nil || strings.Trim(d, "0123456789.") == "" {
		return errors.New("the Okta domain is a host name such as example.okta.com, with no port or path")
	}
	return nil
}

// oktaIDRe is an Okta client ID or key ID.
var oktaIDRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// checkOktaClientID checks an Okta app's client ID.
func checkOktaClientID(v any) error {
	if s, _ := v.(string); s != "" && !oktaIDRe.MatchString(s) {
		return errors.New("the client ID is letters and digits, such as 0oa1b2c3d4e5f6g7h8i9")
	}
	return nil
}

// checkOktaKeyID checks the ID (kid) of an Okta app's key.
func checkOktaKeyID(v any) error {
	if s, _ := v.(string); s != "" && !oktaIDRe.MatchString(s) {
		return errors.New("the key ID is letters, digits, dashes and underscores")
	}
	return nil
}

// CheckOktaPrivateKey checks that a value looks like an unencrypted
// private key in PEM or JWK form. internal/okta reads the key itself.
func CheckOktaPrivateKey(v any) error {
	s, _ := v.(string)
	s = strings.TrimSpace(s)
	switch {
	case s == "" || secrets.IsSealed(s):
		return nil
	case len(s) > 16<<10:
		return errors.New("the private key is longer than any RSA or EC key Okta makes")
	case strings.Contains(s, "ENCRYPTED"):
		return errors.New("the private key is encrypted with a passphrase: export it without one")
	case strings.Contains(s, "PUBLIC KEY") || strings.Contains(s, "CERTIFICATE"):
		return errors.New("that is the public key or a certificate: enter the private key")
	case strings.HasPrefix(s, "-----BEGIN ") && !strings.Contains(s, "-----END "):
		return errors.New("the private key is cut short: enter all of it, from its BEGIN line to its END line " +
			"(signalith secrets set reads a whole file from a pipe: < key.pem)")
	case strings.HasPrefix(s, "-----BEGIN ") && strings.Contains(s, "PRIVATE KEY-----"):
		return nil
	case strings.HasPrefix(s, "{") && strings.Contains(s, `"kty"`) && strings.Contains(s, `"d"`):
		return nil
	case strings.HasPrefix(s, "{"):
		return errors.New("that JWK has no private part (d): enter the private key Okta showed when it made the key")
	}
	return errors.New("the private key is PEM (-----BEGIN PRIVATE KEY-----) or a JWK ({\"kty\": ...})")
}

// DefaultNVDURL is the NVD's CVE API 2.0.
const DefaultNVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// Where exploit intelligence comes from (internal/vulnscan has the same).
const (
	DefaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultEPSSURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
)

// FeedSource checks a KEV or EPSS source: empty, an http(s) address with
// no password or key in it, or the absolute path of a .json, .csv or .gz
// file (file:///path works too).
func FeedSource(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	// Either system's absolute paths, so a setting saved on one server
	// validates on all of them.
	abs := func(p string) bool {
		return strings.HasPrefix(p, "/") || (len(p) > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/'))
	}
	p, isFile := strings.CutPrefix(v, "file://")
	if !isFile && abs(v) {
		p, isFile = v, true
	}
	if isFile {
		if !abs(p) {
			return errors.New("a feed file must be an absolute path")
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".json", ".csv", ".gz":
			return nil
		}
		return errors.New("a feed file must be a .json, .csv or .gz file")
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("must be http(s)://host/path, or the path of a file")
	}
	if hasSecret(v) {
		return errors.New("leave passwords and keys out of the address")
	}
	return nil
}

// NVDURL returns where CVE lookups go.
func (c *Config) NVDURL() string {
	if c.Vulns.NVDURL != "" {
		return c.Vulns.NVDURL
	}
	return DefaultNVDURL
}

// AssistantURL returns the address the AI assistant sends questions to:
// assistant.url, or the provider's own; "" when the assistant is off.
func (c *Config) AssistantURL() string {
	if c.Assistant.Provider == "" {
		return ""
	}
	if c.Assistant.URL != "" {
		return c.Assistant.URL
	}
	return assistant.DefaultURL[c.Assistant.Provider]
}

// Origin returns scheme://host:port of an http(s) address, with the
// default port filled in, so two ways of writing the same server compare
// equal. It returns "" for anything else.
func Origin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	switch {
	case scheme != "http" && scheme != "https":
		return ""
	case port == "" && scheme == "https":
		port = "443"
	case port == "":
		port = "80"
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// keyPattern finds setting keys in a validation problem.
var keyPattern = func() *regexp.Regexp {
	keys := LeafKeys()
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for i, k := range keys {
		keys[i] = regexp.QuoteMeta(k)
	}
	return regexp.MustCompile(`(?:^|[^a-z0-9_.])(` + strings.Join(keys, "|") + `)(?:[^a-z0-9_]|$)`)
}()

// ProblemKeys returns the settings a validation problem is about, in the
// order it names them. Problems name the settings to fix by their keys,
// such as "server.listen", so the page can show each one at its field.
func ProblemKeys(problem string) []string {
	var out []string
	for _, m := range keyPattern.FindAllStringSubmatch(problem, -1) {
		if k := m[1]; !contains(out, k) {
			out = append(out, k)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// quotedValue is a value in quotes at the start of a problem, after its
// key, which the page shows in the field anyway.
var quotedValue = regexp.MustCompile(`^"(?:[^"\\]|\\.)*"\s+`)

// PlainProblem words a validation problem for the field of key on the
// page: without the key it starts with, and with other settings named by
// their labels.
func PlainProblem(key, problem string) string {
	msg := problem
	if rest, ok := strings.CutPrefix(msg, key); ok && !strings.HasPrefix(rest, " and ") && !strings.HasPrefix(rest, " or ") {
		rest = strings.TrimLeft(rest, " :")
		msg = quotedValue.ReplaceAllString(rest, "")
	}
	msg = keyPattern.ReplaceAllStringFunc(msg, func(m string) string {
		sub := keyPattern.FindStringSubmatch(m)
		s, ok := Lookup(sub[1])
		if !ok {
			return m
		}
		return strings.Replace(m, sub[1], "“"+s.Label+"”", 1)
	})
	if msg == "" {
		return problem
	}
	return upperFirst(msg)
}

// upperFirst starts s with a capital letter.
func upperFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[n:]
}
