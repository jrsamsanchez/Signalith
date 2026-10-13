// Package config loads and validates signalith.yaml. Every setting has a
// working default, so a fresh install needs only the file "signalith init"
// writes, and validation errors say exactly which line to fix.
package config

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agents"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/redact"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// Config is the whole configuration file.
type Config struct {
	Server     Server     `yaml:"server"`
	OpenSearch OpenSearch `yaml:"opensearch"`
	Search     Search     `yaml:"search"`
	Retention  Retention  `yaml:"retention"`
	Auth       Auth       `yaml:"auth"`
	Ingest     Ingest     `yaml:"ingest"`
	Syslog     Syslog     `yaml:"syslog"`
	Detections Detections `yaml:"detections"`
	Lookups    Lookups    `yaml:"lookups"`
	Dashboards Dashboards `yaml:"dashboards"`
	Assistant  Assistant  `yaml:"assistant"`
	Intel      Intel      `yaml:"intel"`
	Cluster    Cluster    `yaml:"cluster,omitempty"`

	// path is where the file was loaded from.
	path string
	// ldapBindPassword comes from SIGNALITH_LDAP_BIND_PASSWORD. It is kept
	// apart from Auth.LDAP so saving the file never writes it out.
	ldapBindPassword string
	// adminHashFile is AdminHashFile when the built-in admin's password
	// came from it.
	adminHashFile string
	// publicAdminPassword is set when SIGNALITH_ADMIN_PASSWORD is the
	// example from an older docker-compose.yml.
	publicAdminPassword bool
	// envAdminVersion stands for the password in SIGNALITH_ADMIN_PASSWORD
	// (see AdminPasswordVersion), and envAdminHash is the hash made from
	// it for this process.
	envAdminVersion, envAdminHash string
	// publicURLFromEnv is set when SIGNALITH_PUBLIC_URL set
	// server.public_url.
	publicURLFromEnv bool
	// httpPublicURL is the http:// public_url Validate read as https://,
	// for Warnings.
	httpPublicURL string
	// sections are the top-level keys in that file.
	sections map[string]bool
	// file is the config as that file has it: no settings from the
	// environment, and passwords and keys as written. Save writes it.
	file *Config
	// plain lists the passwords and keys stored as plain text in the file,
	// and addressWarnings those written into addresses that cannot be
	// encrypted there.
	plain, addressWarnings []string
	// unreadable lists the encrypted ones that cannot be decrypted, with
	// what to do; locked has their fields, and feedLocked their labels by
	// feed. See openSecrets.
	unreadable []string
	locked     map[string]bool
	feedLocked map[string][]string
	// pageUnreadable lists the passwords and keys saved on the Settings
	// page that cannot be decrypted, with what to do, and pageLocked their
	// settings, with what the page says about each. See applyPage. A copy
	// of a Config shares them: they are replaced, never changed in place
	// (see copyPageProblem).
	pageUnreadable []pageProblem
	pageLocked     map[string]string
	// keys holds the master key; see Keyring.
	keys *secrets.Keyring
	// layers records where each setting's value came from.
	layers *layers
	// publicURLDerived is true when server.public_url was empty and
	// Validate worked it out from the listen address.
	publicURLDerived bool
	// quickStart is true in the Docker quick start's container, and
	// dockerUpgrade is whether it was upgraded from a version whose agents
	// send the example ingest token (see OldToken), nil until decided.
	quickStart    bool
	dockerUpgrade *DockerUpgrade
}

// PublicURLDerived reports whether server.public_url was worked out from
// the listen address, because it was empty.
func (c *Config) PublicURLDerived() bool { return c.publicURLDerived }

// layers records where the settings of a loaded config came from: the
// environment, the Settings page (see pagefile.go), signalith.yaml or the
// defaults.
type layers struct {
	file     map[string]bool       // keys set in signalith.yaml, such as "server.listen"
	env      map[string]string     // keys set by an environment variable, and its name
	page     map[string]*PageEntry // settings applied from the Settings page
	refused  map[string]*PageEntry // settings from the page a restart set aside
	pageFile string                // the Settings page's file
	// pageFileEnv is true when SIGNALITH_SETTINGS_FILE named it.
	pageFileEnv bool
	// base is the config without the page's settings.
	base     *Config
	mismatch []secretMismatch
	warnings []string
	// problem says why the page's settings are not in use, problemKeys
	// which of them were to blame (when known), and pageFileErr whether
	// it was that their file could not be read.
	problem     string
	problemKeys []string
	pageFileErr bool
}

// Server controls the web UI and API listener.
type Server struct {
	// Listen is host:port. The default binds to localhost only; use
	// 0.0.0.0:8080 to accept agents from other machines.
	Listen string `yaml:"listen"`
	// PublicURL is the address agents and browsers use to reach this
	// server: scheme, host and optional port, no path. It goes into the
	// agent configs Signalith generates. SIGNALITH_PUBLIC_URL overrides it.
	PublicURL string `yaml:"public_url"`
	// TLSCert and TLSKey are a certificate and key from your own or a
	// public certificate authority, for server.tls.mode files. The
	// certificate file may hold the whole chain.
	TLSCert string `yaml:"tls_cert,omitempty"`
	TLSKey  string `yaml:"tls_key,omitempty"`
	// TLS controls HTTPS. A file without this section (written before
	// HTTPS was the default) gets mode auto with plain-text ingest
	// allowed, so agents set up for http:// keep working until they are
	// updated; see TLSMode and PlaintextIngest.
	TLS *ServerTLS `yaml:"tls,omitempty"`
	// TrustedProxies lists the IP addresses or CIDRs of reverse proxies
	// whose X-Forwarded-Proto header is believed, so a browser that
	// reached the proxy over HTTPS is treated as such (HSTS, secure
	// cookies) and not redirected; and, with ClientHeader, whose
	// X-Forwarded-For or Forwarded header names the client for the
	// sign-in limits and the audit log.
	TrustedProxies []string `yaml:"trusted_proxies,omitempty"`
	// ClientHeader is the header the trusted proxies write the client's
	// address into: x-forwarded-for or forwarded. Empty reads neither,
	// and everyone reaching Signalith through a trusted proxy counts as
	// one shared address. A proxy that passes on a header the client sent
	// instead of writing it would let the client pick its own address,
	// so this is only set for a proxy that writes it (see
	// ClientAddressHeader).
	ClientHeader string `yaml:"client_header,omitempty"`
	// MaxConnections caps open connections to the UI, API and ingest;
	// 0 means 10000. One client (an IPv4 address, or an IPv6 /64 network)
	// may hold a tenth of them; connections from this machine, such as a
	// local reverse proxy, and from SharedAddresses are not limited that
	// way.
	MaxConnections int `yaml:"max_connections,omitempty"`
	// SharedAddresses lists IP addresses or CIDRs that stand for many
	// clients, such as a reverse proxy, load balancer or NAT gateway on
	// another machine. They are not limited to one client's share of
	// connections, requests and ingest memory, only by the totals, and
	// failed sign-ins from them count per account, never locking the
	// address.
	SharedAddresses []string `yaml:"shared_addresses,omitempty"`
	// NodeURL is the address other Signalith servers that share this
	// OpenSearch reach this one at, shown on the Servers page. Empty works
	// it out from the listen address and this computer's name, except in a
	// container, which cannot know it. SIGNALITH_NODE_URL overrides it.
	NodeURL string `yaml:"node_url,omitempty"`

	// proxied is set by Validate for a config written before HTTPS was the
	// default whose public_url is https:// although Signalith had no
	// certificate: a reverse proxy in front adds HTTPS, so mode is off.
	proxied bool
	// legacyFile is set when signalith.yaml was written before HTTPS was
	// the default but a server.tls setting was filled in as it was in
	// effect, because the Settings page changed one (see materializeTLS):
	// what LegacyProxy allows still holds.
	legacyFile bool
	// oldAgents is set on a Docker quick start upgraded from a version
	// whose agents send over plain HTTP with the example token, until
	// agents on plain HTTP are refused (see Config.OldToken).
	oldAgents bool
}

// materializeTLS fills in the server.tls section with the HTTPS settings
// in effect, when the file has none (it was written before HTTPS was the
// default, and the rules for such files decide them). A setting changed
// on the Settings page then changes only itself: for example, an https://
// public address saved on the page does not make such a file's HTTPS
// mode off, as an https:// public_url in the file itself would. eff is
// the config whose settings are in effect (validated); s is changed.
func (s *Server) materializeTLS(eff Server) {
	if s.TLS != nil {
		return
	}
	ingest := "deny"
	if eff.PlaintextIngest() {
		ingest = "allow"
	}
	s.TLS = &ServerTLS{Mode: eff.TLSMode(), PlaintextIngest: ingest}
	s.legacyFile = s.legacyFile || eff.legacyHTTP()
}

// SharedList returns server.shared_addresses as prefixes; single addresses
// become /32 or /128. Invalid entries are skipped (Validate reports them).
func (s Server) SharedList() []netip.Prefix {
	var out []netip.Prefix
	for _, a := range s.SharedAddresses {
		if p, err := parseAllow(a); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// HTTPS modes (server.tls.mode).
const (
	// TLSAuto serves HTTPS with a certificate from Signalith's own small
	// certificate authority, made on first start and renewed by itself.
	TLSAuto = "auto"
	// TLSFiles serves HTTPS with server.tls_cert and server.tls_key.
	TLSFiles = "files"
	// TLSOff serves plain HTTP, for a reverse proxy in front that adds
	// HTTPS.
	TLSOff = "off"
)

// ServerTLS is the server.tls section.
type ServerTLS struct {
	// Mode is auto (the default), files or off.
	Mode string `yaml:"mode,omitempty"`
	// Names are extra DNS names or IP addresses for the auto certificate,
	// such as a DNS alias or the address a NAT or Docker publishes.
	// This machine's own name and addresses are always in it.
	Names []string `yaml:"names,omitempty"`
	// PlaintextIngest is allow or deny: whether agents may still send
	// events over plain HTTP to the HTTPS port.
	PlaintextIngest string `yaml:"plaintext_ingest,omitempty"`
	// CAScope is how far a certificate authority Signalith makes for
	// itself reaches: standard (empty) also lets it vouch for private
	// network names and addresses; strict only for this server's own
	// names and addresses as they are when it is made. It applies to the
	// CA made on first start and to one made on the Security page, never
	// to the one in use.
	CAScope string `yaml:"ca_scope,omitempty"`
}

// CA scopes (server.tls.ca_scope).
const (
	CAScopeStandard = "standard"
	CAScopeStrict   = "strict"
)

// CAScope returns server.tls.ca_scope: CAScopeStrict, or CAScopeStandard
// for an empty one.
func (s Server) CAScope() string {
	if s.TLS != nil && strings.EqualFold(strings.TrimSpace(s.TLS.CAScope), CAScopeStrict) {
		return CAScopeStrict
	}
	return CAScopeStandard
}

// TLSMode returns the HTTPS mode in effect: server.tls.mode, or for a
// config from before the mode existed, files when server.tls_cert is set
// and off when public_url is https:// without one (a reverse proxy adds
// HTTPS), else auto.
func (s Server) TLSMode() string {
	if s.TLS != nil && s.TLS.Mode != "" {
		return strings.ToLower(strings.TrimSpace(s.TLS.Mode))
	}
	if s.TLSCert != "" {
		return TLSFiles
	}
	if s.proxied {
		return TLSOff
	}
	return TLSAuto
}

// HTTPS reports whether Signalith serves HTTPS itself.
func (s Server) HTTPS() bool { return s.TLSMode() != TLSOff }

// PlaintextIngest reports whether agents may send events over plain HTTP
// to the HTTPS port: server.tls.plaintext_ingest, else allowed only where
// agents were set up for http://: for a config written before HTTPS was
// the default (no server.tls section and no tls_cert), and on a Docker
// quick start upgraded from one that served plain HTTP, until agents on
// plain HTTP are first refused (see Config.OldToken).
func (s Server) PlaintextIngest() bool {
	if s.TLS != nil && s.TLS.PlaintextIngest != "" {
		return strings.EqualFold(strings.TrimSpace(s.TLS.PlaintextIngest), "allow")
	}
	return s.legacyHTTP() || s.oldAgents
}

// legacyHTTP reports whether the config was written when Signalith served
// plain HTTP by default: no server.tls section and no certificate.
func (s Server) legacyHTTP() bool { return s.TLS == nil && s.TLSCert == "" }

// TLSNames returns server.tls.names.
func (s Server) TLSNames() []string {
	if s.TLS == nil {
		return nil
	}
	return s.TLS.Names
}

// TrustedProxyList returns server.trusted_proxies as prefixes. Invalid
// entries are skipped (Validate reports them).
func (s Server) TrustedProxyList() []netip.Prefix {
	var out []netip.Prefix
	for _, a := range s.TrustedProxies {
		if p, err := parseAllow(a); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// LegacyProxy reports whether X-Forwarded-Proto from a is believed only
// because the config was written before HTTPS was the default and lists
// no server.trusted_proxies. Such a config may sit behind a reverse proxy
// set up the way older versions described (send X-Forwarded-Proto, keep
// public_url http://), so the header is believed from this machine and
// private networks, where that proxy would be; the Health page then asks
// for server.trusted_proxies.
func (s Server) LegacyProxy(a netip.Addr) bool {
	if !(s.legacyHTTP() || s.legacyFile) || len(s.TrustedProxies) > 0 {
		return false
	}
	a = a.Unmap().WithZone("")
	return a.IsLoopback() || a.IsPrivate()
}

// LegacyProxied reports whether HTTPS is left to a reverse proxy that
// Signalith believes only because the config was written before HTTPS
// was the default (see LegacyProxy): HTTPS is off, and no
// server.trusted_proxies are listed.
func (s Server) LegacyProxied() bool {
	return s.TLSMode() == TLSOff && (s.legacyHTTP() || s.legacyFile) && len(s.TrustedProxies) == 0
}

// Values of server.client_header.
const (
	ClientHeaderXFF       = "x-forwarded-for"
	ClientHeaderForwarded = "forwarded"
)

// ClientAddressHeader returns the header named by server.client_header,
// as it is written in a request ("X-Forwarded-For" or "Forwarded"), or
// "" when the trusted proxies' client addresses are not read.
func (s Server) ClientAddressHeader() string {
	switch strings.ToLower(strings.TrimSpace(s.ClientHeader)) {
	case ClientHeaderXFF:
		return "X-Forwarded-For"
	case ClientHeaderForwarded:
		return "Forwarded"
	}
	return ""
}

// TrustsProxy reports whether a is in server.trusted_proxies.
func (s Server) TrustsProxy(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	for _, p := range s.TrustedProxyList() {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// tlsProblems checks the HTTPS settings. resolve makes file paths
// relative to the config file.
func (s *Server) tlsProblems(resolve func(string) string) []string {
	var p []string
	mode := s.TLSMode()
	switch mode {
	case TLSAuto, TLSFiles, TLSOff:
	default:
		return []string{fmt.Sprintf("server.tls.mode %q must be auto (Signalith makes its own certificate), files (server.tls_cert and tls_key) or off (plain HTTP behind a reverse proxy that adds HTTPS)", s.TLS.Mode)}
	}
	if (s.TLSCert == "") != (s.TLSKey == "") {
		p = append(p, "server.tls_cert and server.tls_key must be set together")
	}
	switch {
	case mode == TLSFiles && s.TLSCert == "" && s.TLSKey == "":
		p = append(p, "server.tls.mode is files, so set server.tls_cert and server.tls_key to your certificate and key files (or use mode auto and Signalith makes its own)")
	case mode == TLSAuto && (s.TLSCert != "" || s.TLSKey != ""):
		p = append(p, "server.tls_cert and server.tls_key are set, but server.tls.mode is auto, which makes its own certificate. Set server.tls.mode: files to use them, or remove them")
	case mode == TLSOff && (s.TLSCert != "" || s.TLSKey != ""):
		// They would be used for nothing but syslog over TLS, which is
		// easy to miss: they belong to mode files.
		p = append(p, "server.tls_cert and server.tls_key are set, but server.tls.mode is off, so Signalith serves plain HTTP and does not use them. Set server.tls.mode: files to use them, or remove them")
	case s.TLSCert != "" && s.TLSKey != "":
		if _, err := tls.LoadX509KeyPair(resolve(s.TLSCert), resolve(s.TLSKey)); err != nil {
			p = append(p, fmt.Sprintf("server.tls_cert and tls_key: %v", err))
		}
	}
	if s.TLS != nil {
		switch strings.ToLower(strings.TrimSpace(s.TLS.PlaintextIngest)) {
		case "", "allow", "deny":
		default:
			p = append(p, fmt.Sprintf("server.tls.plaintext_ingest %q must be allow or deny", s.TLS.PlaintextIngest))
		}
		switch strings.ToLower(strings.TrimSpace(s.TLS.CAScope)) {
		case "", CAScopeStandard, CAScopeStrict:
		default:
			p = append(p, fmt.Sprintf("server.tls.ca_scope %q must be standard (this server and private network names) or strict (only this server's own names and addresses)", s.TLS.CAScope))
		}
		for i, n := range s.TLS.Names {
			if !validCertName(n) {
				p = append(p, fmt.Sprintf("server.tls.names[%d] %q must be a host name or IP address, such as siem.example.com or 192.168.1.20", i, n))
			}
		}
	}
	switch strings.ToLower(strings.TrimSpace(s.ClientHeader)) {
	case "", ClientHeaderXFF, ClientHeaderForwarded:
	default:
		p = append(p, fmt.Sprintf("server.client_header %q must be x-forwarded-for, forwarded, or empty to read neither", s.ClientHeader))
	}
	for i, a := range s.TrustedProxies {
		if _, err := parseAllow(a); err != nil {
			p = append(p, fmt.Sprintf("server.trusted_proxies[%d] %q must be an IP address or a CIDR such as 10.0.0.5 or 10.0.0.0/24", i, a))
		}
	}
	return p
}

// validCertName reports whether n can go in a certificate as a host name
// or IP address: the same rules as the addresses agents send to.
func validCertName(n string) bool {
	n = strings.TrimSpace(n)
	if a, err := netip.ParseAddr(n); err == nil {
		return a.Zone() == ""
	}
	_, err := agents.ParseServerURL("https://" + n)
	return err == nil && !strings.ContainsAny(n, ":/")
}

// OpenSearch is the event store connection.
type OpenSearch struct {
	// URL is http(s)://host:port. A user name and password written into it
	// are moved to Username and Password when the file is loaded, so they
	// are never shown or logged with the URL.
	URL      string `yaml:"url"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	// CAFile is a PEM file with the certificate authority that signed
	// OpenSearch's certificate, for an https url with a private CA (the
	// usual case). The system's trusted authorities are trusted too.
	CAFile string `yaml:"ca_file,omitempty"`
	// CertFile and KeyFile are a client certificate and key Signalith
	// presents to OpenSearch, for certificate sign-in.
	CertFile string `yaml:"cert_file,omitempty"`
	KeyFile  string `yaml:"key_file,omitempty"`
	// TLSSkipVerify turns off OpenSearch certificate checks, so anyone on
	// the network path could read and change events. For a lab only; use
	// CAFile instead.
	TLSSkipVerify bool `yaml:"tls_skip_verify,omitempty"`
	// Proxy is a proxy for OpenSearch traffic, such as
	// http://proxy:3128 (SIGNALITH_OPENSEARCH_PROXY overrides it). Empty
	// connects directly: HTTP_PROXY and HTTPS_PROXY are not used for
	// OpenSearch, since a proxy would see every event and the OpenSearch
	// password.
	Proxy string `yaml:"proxy,omitempty"`
	// AllowInsecureHTTP lets the username and password go to OpenSearch
	// over plain http on another machine, where anyone on the network
	// could read them. Off, that is refused; use https instead.
	AllowInsecureHTTP bool   `yaml:"allow_insecure_http,omitempty"`
	IndexPrefix       string `yaml:"index_prefix"`
	Replicas          int    `yaml:"replicas"`
}

// problems checks the connection settings. resolve makes file paths
// relative to the config file.
func (o *OpenSearch) problems(resolve func(string) string) []string {
	var p []string
	u, err := url.Parse(o.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return []string{fmt.Sprintf("opensearch.url %q must be http(s)://host:port", redact.URL(o.URL))}
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		// Only the scheme and host are repeated: the rest may hold a key.
		p = append(p, fmt.Sprintf("opensearch.url %s://%s must not have a query string (?...) or fragment (#...); "+
			"put credentials in opensearch.username and password instead", u.Scheme, u.Host))
	}
	if u.Scheme == "http" && (o.Username != "" || o.Password != "") && !isLoopback(u.Hostname()) && !o.AllowInsecureHTTP {
		p = append(p, fmt.Sprintf("opensearch.url is plain http to %s, so the OpenSearch username and password would cross the network unencrypted. "+
			"Use https:// (with opensearch.ca_file set to OpenSearch's CA certificate if it is not publicly trusted), "+
			"or, to accept the risk, set opensearch.allow_insecure_http: true (signalith init: -opensearch-allow-insecure-http)", u.Host))
	}
	if u.Scheme == "http" && (o.CAFile != "" || o.CertFile != "") {
		p = append(p, "opensearch.ca_file, cert_file and key_file only apply to an https:// opensearch.url")
	}
	if o.CAFile != "" {
		if pem, err := os.ReadFile(resolve(o.CAFile)); err != nil {
			p = append(p, fmt.Sprintf("opensearch.ca_file: %v", err))
		} else if !x509.NewCertPool().AppendCertsFromPEM(pem) {
			p = append(p, fmt.Sprintf("opensearch.ca_file %s holds no PEM certificates (it should contain -----BEGIN CERTIFICATE-----)", o.CAFile))
		}
	}
	switch {
	case (o.CertFile == "") != (o.KeyFile == ""):
		p = append(p, "opensearch.cert_file and opensearch.key_file must be set together")
	case o.CertFile != "":
		if _, err := tls.LoadX509KeyPair(resolve(o.CertFile), resolve(o.KeyFile)); err != nil {
			p = append(p, fmt.Sprintf("opensearch.cert_file and key_file: %v", err))
		}
	}
	if o.Proxy != "" {
		if pu, err := url.Parse(o.Proxy); err != nil || !slices.Contains([]string{"http", "https", "socks5"}, pu.Scheme) || pu.Host == "" {
			p = append(p, fmt.Sprintf("opensearch.proxy %q must be http://host:port, https://host:port or socks5://host:port", redact.URL(o.Proxy)))
		}
	}
	return p
}

// moveURLCredentials takes a user name and password out of the URL and
// into Username and Password, unless those are set already.
func (o *OpenSearch) moveURLCredentials() {
	stripped, user, pw, ok := redact.Strip(o.URL)
	if !ok {
		return
	}
	o.URL = stripped
	if o.Username == "" && o.Password == "" {
		o.Username, o.Password = user, pw
	}
}

// isLoopback reports whether host is this machine.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Unmap().IsLoopback()
}

// Search tunes the query engine.
type Search struct {
	DefaultEarliest string `yaml:"default_earliest"`
	MaxEvents       int    `yaml:"max_events"`
}

// Retention controls how long data is kept; see docs/retention.md. Most
// installs set policies on the Data retention page instead. Anything set
// here is shown there as "From signalith.yaml" and cannot be changed in
// the page.
type Retention struct {
	// Days keeps event categories without their own policy searchable for
	// this many days (0 keeps them forever), until a default policy is
	// saved on the page.
	Days int `yaml:"days"`
	// Interval is how often policies are enforced. Default 1h.
	Interval string `yaml:"interval,omitempty"`
	// ArchiveDir holds archived days. A relative path is relative to the
	// folder this config file is in. Default: an "archive" folder next to
	// lookups.dir. SIGNALITH_ARCHIVE_DIR overrides it.
	ArchiveDir string `yaml:"archive_dir,omitempty"`
	// Default is the policy for event categories without their own.
	Default *retention.Policy `yaml:"default,omitempty"`
	// Policies sets a policy per category: a data model (authentication,
	// endpoint, network_traffic, change), other, risk, findings or cases.
	Policies map[string]retention.Policy `yaml:"policies,omitempty"`
	// Guard deletes the oldest days when OpenSearch's disk gets too full.
	Guard *retention.Guard `yaml:"guard,omitempty"`
}

// RetentionInterval returns retention.interval as a duration (1h if unset
// or invalid; Validate reports invalid values).
func (c *Config) RetentionInterval() time.Duration {
	if d, err := detect.ParseDuration(c.Retention.Interval); err == nil && d > 0 {
		return d
	}
	return retention.DefaultInterval
}

// ArchiveDir returns the absolute archive folder.
func (c *Config) ArchiveDir() string {
	if c.Retention.ArchiveDir != "" {
		return c.resolve(c.Retention.ArchiveDir)
	}
	return filepath.Join(filepath.Dir(filepath.Clean(c.LookupsDir())), "archive")
}

// RetentionPolicies returns the retention settings for the retention
// package.
func (c *Config) RetentionPolicies() retention.Config {
	return retention.Config{Days: c.Retention.Days, Default: c.Retention.Default,
		Policies: c.Retention.Policies, Guard: c.Retention.Guard}
}

// Auth protects the UI and API.
type Auth struct {
	// AdminUser and AdminPasswordHash are the built-in admin: a break-glass
	// account that always works, whatever happens to other users.
	AdminUser         string `yaml:"admin_user"`
	AdminPasswordHash string `yaml:"admin_password_hash"`
	// SessionTimeout signs the web UI out after this long without use,
	// unless "keep me signed in" was ticked. Default 12h.
	SessionTimeout string `yaml:"session_timeout,omitempty"`
	// UsersFile holds the users added on the Users page. Default
	// users.json in lookups.dir; directory.json (directory sign-in
	// settings from the Users page) goes in the same folder.
	UsersFile string `yaml:"users_file,omitempty"`
	// LDAP sets up directory sign-in here instead of on the Users page,
	// which then shows it read-only.
	LDAP *users.LDAPSettings `yaml:"ldap,omitempty"`
}

// UsersFile returns the absolute path of the users file.
func (c *Config) UsersFile() string {
	if c.Auth.UsersFile != "" {
		return c.resolve(c.Auth.UsersFile)
	}
	return filepath.Join(c.LookupsDir(), "users.json")
}

// DirectoryFile returns where directory sign-in settings from the Users
// page are kept: directory.json next to the users file.
func (c *Config) DirectoryFile() string {
	return filepath.Join(filepath.Dir(c.UsersFile()), "directory.json")
}

// LDAP returns the directory sign-in settings from auth.ldap, with
// defaults filled in and the bind password from the environment if set
// there, or nil when the file has no auth.ldap.
func (c *Config) LDAP() (*users.LDAPSettings, error) {
	if c.Auth.LDAP == nil {
		return nil, nil
	}
	s := c.Auth.LDAP.Clone()
	if s.Enabled == nil {
		on := true
		s.Enabled = &on
	}
	if c.ldapBindPassword != "" {
		s.BindPassword = c.ldapBindPassword
	}
	if s.CACertFile != "" {
		if strings.TrimSpace(s.CACert) != "" {
			return nil, errors.New("auth.ldap: set ca_cert or ca_cert_file, not both")
		}
		b, err := os.ReadFile(c.resolve(s.CACertFile))
		if err != nil {
			return nil, fmt.Errorf("auth.ldap.ca_cert_file: %w", err)
		}
		s.CACert = string(b)
	}
	s.Normalize()
	return &s, nil
}

// SessionIdle returns auth.session_timeout as a duration.
func (c *Config) SessionIdle() time.Duration {
	if d, err := detect.ParseDuration(c.Auth.SessionTimeout); err == nil && d > 0 {
		return d
	}
	return 12 * time.Hour
}

// Ingest controls agent access.
type Ingest struct {
	// Tokens agents present in the Authorization header. Rotate by adding a
	// new token, updating agents, then removing the old one.
	Tokens []string `yaml:"tokens"`
	// MaxEventAge is how old an event's own time (from an agent or syslog)
	// may be and still be its event time, such as 7d. Older events, and
	// ones more than an hour ahead, are filed under the time they arrived,
	// with their own time kept in device_time. Empty means 7 days, or the
	// shortest retention period when that is shorter. Raise it to load old
	// logs.
	MaxEventAge string `yaml:"max_event_age,omitempty"`
}

// MaxEventAge returns ingest.max_event_age as a duration: the setting, or
// a week (keepDays, the shortest retention period, when that is shorter,
// since older events would land in indices about to be deleted). Each day
// in this window can get its own daily indices, so it bounds how many a
// sender can create.
func (c *Config) MaxEventAge(keepDays int) time.Duration {
	if d, err := detect.ParseDuration(c.Ingest.MaxEventAge); err == nil && d > 0 {
		return d
	}
	week := 7 * 24 * time.Hour
	if d := time.Duration(keepDays) * 24 * time.Hour; d > 0 && d < week {
		return d
	}
	return week
}

// Syslog receives syslog from systems that cannot run an agent: firewalls,
// switches, routers, appliances and servers. Off unless an address is set.
type Syslog struct {
	// UDP and TCP are host:port addresses to listen on, such as
	// 0.0.0.0:514. Empty turns that listener off.
	UDP string `yaml:"udp"`
	TCP string `yaml:"tcp"`
	// TLS is a host:port for syslog over TLS (RFC 5425), such as
	// 0.0.0.0:6514. It uses the web UI's certificate: server.tls_cert and
	// tls_key when set, else the one Signalith makes itself.
	TLS string `yaml:"tls"`
	// Allow lists the sender IP addresses or CIDRs that may send syslog.
	// Empty allows any sender.
	Allow []string `yaml:"allow"`
	// PublicPort is the port devices send UDP and TCP syslog to, when it
	// is not the one Signalith listens on: Docker or a firewall forwards
	// 514 to 5514, say. The Add data page puts it in the setup it shows.
	// Zero means the listen port.
	PublicPort int `yaml:"public_port,omitempty"`
}

// Enabled reports whether any syslog listener is set.
func (s Syslog) Enabled() bool { return s.UDP != "" || s.TCP != "" || s.TLS != "" }

// AllowList returns syslog.allow as prefixes; single addresses become /32
// or /128. Invalid entries are skipped (Validate reports them).
func (s Syslog) AllowList() []netip.Prefix {
	var out []netip.Prefix
	for _, a := range s.Allow {
		if p, err := parseAllow(a); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func parseAllow(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func (s *Syslog) problems(server Server) []string {
	var p []string
	for _, l := range []struct{ setting, addr string }{{"syslog.udp", s.UDP}, {"syslog.tcp", s.TCP}, {"syslog.tls", s.TLS}} {
		if l.addr == "" {
			continue
		}
		host, port, err := net.SplitHostPort(l.addr)
		if err != nil {
			p = append(p, fmt.Sprintf("%s %q must be host:port, for example 0.0.0.0:514 (or empty to turn it off)", l.setting, l.addr))
			continue
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			p = append(p, fmt.Sprintf("%s port %q must be 1-65535", l.setting, port))
		}
		if _, err := netip.ParseAddr(host); err != nil && host != "" && host != "localhost" {
			p = append(p, fmt.Sprintf("%s host %q must be an IP address of this server, or 0.0.0.0 for all of them", l.setting, host))
		}
	}
	// TCP listeners cannot share a port with each other or the web server.
	tcp := []struct{ setting, addr string }{{"server.listen", server.Listen}, {"syslog.tcp", s.TCP}, {"syslog.tls", s.TLS}}
	for i := range tcp {
		for j := i + 1; j < len(tcp); j++ {
			if sameListener(tcp[i].addr, tcp[j].addr) {
				p = append(p, fmt.Sprintf("%s and %s both use %s; give them different ports", tcp[i].setting, tcp[j].setting, tcp[j].addr))
			}
		}
	}
	if s.PublicPort < 0 || s.PublicPort > 65535 {
		p = append(p, fmt.Sprintf("syslog.public_port %d must be 1-65535 (or 0 for the port syslog.udp and syslog.tcp listen on)", s.PublicPort))
	}
	for i, a := range s.Allow {
		if _, err := parseAllow(a); err != nil {
			p = append(p, fmt.Sprintf("syslog.allow[%d] %q must be an IP address or a CIDR such as 10.0.0.0/8", i, a))
		}
	}
	return p
}

// sameListener reports whether two listen addresses would take the same
// port: same port, and the same host or either on all interfaces.
func sameListener(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ha, pa, err1 := net.SplitHostPort(a)
	hb, pb, err2 := net.SplitHostPort(b)
	if err1 != nil || err2 != nil || pa != pb {
		return false
	}
	wildcard := func(h string) bool { return h == "" || h == "0.0.0.0" || h == "::" }
	return ha == hb || wildcard(ha) || wildcard(hb)
}

// Detections controls scheduled detections and findings.
type Detections struct {
	// Dir holds custom and edited detections as YAML files. A relative
	// path is relative to the folder this config file is in.
	Dir string `yaml:"dir"`
	// Scheduler runs enabled detections on their schedules. Turn it off on
	// extra servers that share one OpenSearch so rules run once.
	Scheduler bool `yaml:"scheduler"`
	// MaxFindingsPerRun caps findings one run can raise.
	MaxFindingsPerRun int `yaml:"max_findings_per_run"`
}

// Cluster is about this server among the Signalith servers that share
// one OpenSearch.
type Cluster struct {
	// NodeName is this server's name on the Servers page and in the log.
	// Empty uses the name kept in the state folder, else this computer's
	// name. SIGNALITH_NODE_NAME overrides it.
	NodeName string `yaml:"node_name,omitempty"`
}

// Lookups holds the asset and identity lists.
type Lookups struct {
	// Dir holds assets.csv and identities.csv. A relative path is relative
	// to the folder this config file is in.
	Dir string `yaml:"dir"`
}

// Dashboards controls the posture and custom dashboards.
type Dashboards struct {
	// Dir holds custom dashboards as YAML files, one per dashboard. A
	// relative path is relative to the folder this config file is in.
	Dir string `yaml:"dir"`
	// StaleAfter is how long a host and source type can go quiet before
	// the posture dashboard lists it as a data source that stopped sending.
	StaleAfter string `yaml:"stale_after"`
}

// Assistant is an optional AI model for questions the built-in
// plain-English translator cannot fully understand. Off when Provider is
// empty. Only the question and the field list are sent, never events.
type Assistant struct {
	// Provider is "anthropic" or "openai" (any OpenAI-compatible API,
	// including Ollama and LM Studio on your own hardware).
	Provider string `yaml:"provider,omitempty"`
	// URL overrides the endpoint, for example http://localhost:11434/v1.
	URL    string `yaml:"url,omitempty"`
	Model  string `yaml:"model,omitempty"`
	APIKey string `yaml:"api_key,omitempty"`
}

// Intel configures threat intel feeds. Nothing is downloaded until a
// feed is listed here or added on the Threat intel page.
type Intel struct {
	Feeds []IntelFeed `yaml:"feeds"`
	// FeedsFile keeps the feeds added on the Threat intel page. Default:
	// intel_feeds.yaml in lookups.dir. A relative path is relative to the
	// folder this config file is in.
	FeedsFile string `yaml:"feeds_file,omitempty"`
	// AllowLoopbackFeeds lets feeds download from this machine (127.0.0.1
	// or ::1), for a feed server on the same host. Off by default.
	AllowLoopbackFeeds bool `yaml:"allow_loopback_feeds,omitempty"`
}

// IntelFeed is one feed the server downloads on a schedule. Feeds added on
// the Threat intel page use the same settings and rules.
type IntelFeed = intel.FeedSpec

// ParseFeedDuration parses 30m, 12h, 7d or 2w.
func ParseFeedDuration(s string) (time.Duration, error) { return intel.ParseDuration(s) }

func (in *Intel) problems() []string {
	var p []string
	seen := map[string]bool{}
	for i := range in.Feeds {
		f := &in.Feeds[i]
		f.Defaults()
		at := fmt.Sprintf("intel.feeds[%d]", i)
		if f.Name != "" {
			at = fmt.Sprintf("intel.feeds[%d] (%s)", i, f.Name)
		}
		if seen[f.Name] && f.Name != "" {
			p = append(p, at+": name is used by another feed")
		}
		seen[f.Name] = true
		for _, pr := range f.Problems(true) {
			p = append(p, at+": "+pr.Msg)
		}
	}
	return p
}

// IntelFeedsFile returns the file that keeps the feeds added on the
// Threat intel page.
func (c *Config) IntelFeedsFile() string {
	if c.Intel.FeedsFile != "" {
		return c.resolve(c.Intel.FeedsFile)
	}
	return filepath.Join(c.LookupsDir(), "intel_feeds.yaml")
}

// LookupsDir returns the absolute lookups folder.
func (c *Config) LookupsDir() string { return c.resolve(c.Lookups.Dir) }

// TLSDir is where Signalith keeps its own certificate authority and HTTPS
// certificate (server.tls.mode auto).
func (c *Config) TLSDir() string { return filepath.Join(c.StateDir(), "tls") }

// TLSFiles returns server.tls_cert and tls_key, with relative paths made
// relative to the folder this config file is in.
func (c *Config) TLSFiles() (cert, key string) {
	return c.resolve(c.Server.TLSCert), c.resolve(c.Server.TLSKey)
}

func (c *Config) resolve(d string) string {
	if d == "" || filepath.IsAbs(d) || c.path == "" {
		return d
	}
	return filepath.Join(filepath.Dir(c.path), d)
}

// DetectionsDir returns the absolute detections folder.
func (c *Config) DetectionsDir() string { return c.resolve(c.Detections.Dir) }

// DashboardsDir returns the absolute dashboards folder.
func (c *Config) DashboardsDir() string { return c.resolve(c.Dashboards.Dir) }

// StaleAfter returns dashboards.stale_after as a duration (2h if unset or
// invalid; Validate reports invalid values).
func (c *Config) StaleAfter() time.Duration {
	if d, err := detect.ParseDuration(c.Dashboards.StaleAfter); err == nil && d > 0 {
		return d
	}
	return 2 * time.Hour
}

// Default returns a config with every default filled in.
func Default() *Config {
	return &Config{
		Server:     Server{Listen: "127.0.0.1:8080"},
		OpenSearch: OpenSearch{URL: "http://127.0.0.1:9200", IndexPrefix: "signalith"},
		Search:     Search{DefaultEarliest: "-24h", MaxEvents: 10000},
		Retention:  Retention{Days: 90},
		Auth:       Auth{AdminUser: "admin"},
		Detections: Detections{Dir: "detections", Scheduler: true, MaxFindingsPerRun: 100},
		Lookups:    Lookups{Dir: "lookups"},
		Dashboards: Dashboards{Dir: "dashboards", StaleAfter: "2h"},
	}
}

// Path returns the file the config was loaded from.
func (c *Config) Path() string { return c.path }

// HasSection reports whether the file the config was loaded from has the
// top-level section, such as "syslog". Settings for one that is missing
// are added at the end of the file; a second "syslog:" would not load.
func (c *Config) HasSection(name string) bool { return c.sections[name] }

// Load reads a config file, applies the settings changed on the Settings
// page, defaults and environment overrides, decrypts the passwords and keys
// stored encrypted, and validates the result. Settings from the page that
// cannot be used never stop Signalith: it starts with signalith.yaml
// alone, and SettingsProblem says why. A password or key that cannot be
// decrypted is left out and reported by Warnings rather than failing (see
// Unreadable and PageUnreadable).
func Load(path string) (*Config, error) {
	return loadWith(path, nil)
}

// LoadSetAside is Load with the settings keys, changed on the Settings
// page, set aside for reason: they are not used, as after MarkRefused,
// whether or not that could be saved.
func LoadSetAside(path string, keys []string, reason string) (*Config, error) {
	now := time.Now()
	return loadWith(path, func(p *PageSettings) { p.refuse(keys, reason, now) })
}

// SetAsideAlong returns keys and the other settings changed on the
// Settings page that cannot be used once keys are set aside. Setting a
// change aside must not leave the page's settings in a combination that
// does not validate, or the next start would use none of them: setting
// server.tls.mode aside, for one, takes along the certificate files saved
// with it, which the mode in signalith.yaml refuses.
func SetAsideAlong(path string, keys []string) []string {
	out := slices.Clone(keys)
	now := time.Now()
	for range len(Registry) {
		s, err := loadSaved(path, func(p *PageSettings) { p.refuse(out, "set aside", now) })
		if err != nil || s.PageErr != nil || s.Problems == nil {
			return out
		}
		more := false
		for _, p := range s.Problems {
			for _, k := range ProblemKeys(p) {
				if s.Config.Source(k).Kind == FromPage && !slices.Contains(out, k) {
					out, more = append(out, k), true
				}
			}
		}
		if !more {
			return out
		}
	}
	return out
}

func loadWith(path string, adjust func(*PageSettings)) (*Config, error) {
	s, err := loadSaved(path, adjust)
	if err != nil {
		return nil, err
	}
	if s.PageErr == nil && s.Problems == nil {
		return s.Config, nil
	}
	if s.PageErr == nil && len(s.Config.PageKeys()) == 0 {
		// Nothing came from the page: the problems are the file's own.
		return nil, fmt.Errorf("%s: %w", path, &ValidationError{Problems: s.Problems})
	}
	c, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	c.layers.pageFileErr = s.PageErr != nil
	if s.PageErr != nil {
		c.layers.problem = fmt.Sprintf("The settings saved on the Settings page were not used, because %v. Signalith started with signalith.yaml alone. Fix the file, or remove it with: signalith settings reset", s.PageErr)
	} else {
		c.layers.problem = "The settings saved on the Settings page were not used, because with them: " + strings.Join(s.Problems, "; ") +
			". Signalith started with signalith.yaml alone. Fix these settings on the Settings page, or remove them with: signalith settings reset"
		for _, p := range s.Problems {
			for _, k := range ProblemKeys(p) {
				if s.Config.Source(k).Kind == FromPage && !slices.Contains(c.layers.problemKeys, k) {
					c.layers.problemKeys = append(c.layers.problemKeys, k)
				}
			}
		}
	}
	return c, nil
}

// LoadWithoutPage is LoadFile for a server that could not start with the
// settings saved on the Settings page; reason says why, and SettingsProblem
// reports it. keys are the settings to blame, when known.
func LoadWithoutPage(path, reason string, keys []string) (*Config, error) {
	c, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	c.layers.problem = "The settings saved on the Settings page were not used, because " + reason +
		". Signalith started with signalith.yaml alone. Fix these settings on the Settings page, or remove them with: signalith settings reset"
	c.layers.problemKeys = keys
	return c, nil
}

// SettingsProblemKeys lists the settings from the Settings page that kept
// Signalith from starting with them, when SettingsProblem is set and it
// is known which.
func (c *Config) SettingsProblemKeys() []string {
	if c.layers == nil || c.layers.problemKeys == nil {
		return []string{}
	}
	return c.layers.problemKeys
}

// SettingsFileProblem reports whether SettingsProblem is that the
// Settings page's file could not be read.
func (c *Config) SettingsFileProblem() bool {
	return c.layers != nil && c.layers.pageFileErr
}

// LoadFile is Load without the settings changed on the Settings page:
// signalith.yaml, defaults and the environment. Commands that write
// signalith.yaml back load it this way, so the page's settings stay in
// their own file.
func LoadFile(path string) (*Config, error) {
	c, err := build(path, nil)
	if err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// LoadUnchecked reads a config file with defaults and environment
// overrides, but neither decrypts nor checks it, and leaves out the
// settings changed on the Settings page: for commands that look at, or
// repair, a file that may not load.
func LoadUnchecked(path string) (*Config, error) {
	return readAndEnv(path)
}

// Saved is the configuration as saved, whether or not it is valid:
// signalith.yaml, the settings changed on the Settings page, and the
// environment. The Settings page shows it.
type Saved struct {
	*Config
	// Page is the Settings page's file as read; nil when it cannot be.
	Page *PageSettings
	// Problems lists what is wrong, as Validate words it; nil when valid.
	Problems []string
	// PageErr is set when the page's file cannot be read or used; Config
	// is then without it.
	PageErr error
}

// LoadSaved reads the configuration as saved, valid or not.
func LoadSaved(path string) (*Saved, error) {
	return loadSaved(path, nil)
}

func loadSaved(path string, adjust func(*PageSettings)) (*Saved, error) {
	c, err := readAndEnv(path)
	if err != nil {
		return nil, err
	}
	s := &Saved{}
	page, perr := ReadPageSettings(c.SettingsFile())
	if perr == nil {
		if adjust != nil {
			page = page.Clone()
			adjust(page)
		}
		s.Page = page
	}
	cfg, err := build(path, page)
	var pe *PageFileError
	if errors.As(err, &pe) {
		perr = pe
		cfg, err = build(path, nil)
	}
	if err != nil {
		return nil, err
	}
	s.Config, s.PageErr = cfg, perr
	s.Problems = problemsOf(cfg)
	return s, nil
}

// problemsOf validates c and returns its problems, or nil.
func problemsOf(c *Config) []string {
	err := c.Validate()
	if err == nil {
		return nil
	}
	var ve *ValidationError
	if errors.As(err, &ve) {
		return ve.Problems
	}
	return []string{err.Error()}
}

// build reads signalith.yaml and applies the environment, then the
// settings changed on the page, without validating. A page setting that
// cannot be used is a *PageFileError.
func build(path string, page *PageSettings) (*Config, error) {
	c, err := readAndEnv(path)
	if err != nil {
		return nil, err
	}
	base, err := readAndEnv(path)
	if err != nil {
		return nil, err
	}
	// Both use the same master key.
	base.keys = c.Keyring()
	base.openSecrets()
	// Validating fills in worked-out values, such as the public address.
	_ = base.Validate()
	c.layers.base = base
	if !page.Empty() {
		if err := c.applyPage(page, base); err != nil {
			return nil, &PageFileError{Path: c.layers.pageFile, Err: err}
		}
	}
	// The passwords and keys in signalith.yaml are decrypted once the
	// page's settings are in: one the page replaces is not needed, as one
	// an environment variable replaces is not.
	c.openSecrets()
	return c, nil
}

// readAndEnv reads signalith.yaml with defaults and the environment,
// without decrypting it.
func readAndEnv(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("config file %s not found; create one with: signalith init", path)
		}
		return nil, err
	}
	c, err := decodeFile(path, data)
	if err != nil {
		return nil, err
	}
	c.path = path
	c.layers = &layers{file: map[string]bool{}, env: map[string]string{}, page: map[string]*PageEntry{}, refused: map[string]*PageEntry{}}
	var top map[string]any
	if yaml.Unmarshal(data, &top) == nil {
		c.sections = make(map[string]bool, len(top))
		for k := range top {
			c.sections[k] = true
		}
		fileKeys(top, "", c.layers.file)
	}
	// Keep the file's own view, before the environment changes anything.
	if c.file, err = decodeFile(path, data); err != nil {
		return nil, err
	}
	c.plain = plainLabels(c.file.secretRefs())
	inURL, warnings := addressPlain(c.file.addressSecrets())
	c.plain, c.addressWarnings = append(c.plain, inURL...), warnings
	if err := c.applyEnv(); err != nil {
		return nil, err
	}
	if err := c.applyAdminHashFile(); err != nil {
		return nil, err
	}
	c.readDockerUpgrade()
	c.layers.pageFileEnv = strings.TrimSpace(os.Getenv("SIGNALITH_SETTINGS_FILE")) != ""
	c.layers.pageFile = c.SettingsFile()
	return c, nil
}

// decodeFile decodes signalith.yaml over the defaults.
func decodeFile(path string, data []byte) (*Config, error) {
	c := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && err.Error() != "EOF" {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// fileKeys records every key set in the file, nested ones as "a.b".
func fileKeys(m map[string]any, prefix string, out map[string]bool) {
	for k, v := range m {
		out[prefix+k] = true
		if sub, ok := v.(map[string]any); ok {
			fileKeys(sub, prefix+k+".", out)
		}
	}
}

// fromEnv notes that an environment variable set a setting.
func (c *Config) fromEnv(key, name string) {
	if c.layers != nil {
		c.layers.env[key] = name
	}
}

// envSecret returns the secret in the environment variable name, or in
// the file named by name_FILE (how Docker and Kubernetes pass secrets),
// without its trailing newline, and which of the two it came from (both,
// joined by " and ", when both are set). An unreadable or empty file is
// an error, and so is setting both, except for SIGNALITH_INGEST_TOKEN,
// where each adds a token.
func envSecret(name string) ([]string, string, error) {
	var out []string
	var from []string
	if v := os.Getenv(name); v != "" {
		out = append(out, v)
		from = append(from, name)
	}
	file := os.Getenv(name + "_FILE")
	if file == "" {
		return out, strings.Join(from, " and "), nil
	}
	if len(out) > 0 && name != "SIGNALITH_INGEST_TOKEN" {
		return nil, "", fmt.Errorf("%s and %s_FILE are both set; set only one of them", name, name)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, "", fmt.Errorf("%s_FILE is set to %s, which cannot be read: %v", name, file, err)
	}
	v := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if strings.TrimSpace(v) == "" {
		return nil, "", fmt.Errorf("%s_FILE is set to %s, which is empty", name, file)
	}
	return append(out, v), strings.Join(append(from, name+"_FILE"), " and "), nil
}

// AdminHashFile is where signalith passwd keeps the built-in admin's
// password hash when signalith.yaml cannot hold it: the password comes
// from SIGNALITH_ADMIN_PASSWORD or SIGNALITH_ADMIN_PASSWORD_FILE (as in
// Docker, where the first password is generated and signalith.yaml is
// read-only). While the file exists it replaces both.
func (c *Config) AdminHashFile() string { return AdminHashFileIn(c.StateDir()) }

// AdminHashFileIn is AdminHashFile for the state folder dir.
func AdminHashFileIn(dir string) string { return filepath.Join(dir, "admin-password-hash") }

// SignInKeyFile is the key that signs the cookie marking a browser as one
// that signed in to an account before, so that guesses at the account's
// password from elsewhere do not keep it out (see auth.Limiter). The
// server makes it on first start.
func (c *Config) SignInKeyFile() string { return filepath.Join(c.StateDir(), "signin.key") }

// AdminPasswordChanged returns AdminHashFile when the built-in admin's
// password comes from it, else "".
func (c *Config) AdminPasswordChanged() string { return c.adminHashFile }

// PublicAdminPassword reports whether the built-in admin's password in
// use is change-me-please, the example in an older docker-compose.yml,
// which anyone can look up.
func (c *Config) PublicAdminPassword() bool { return c.publicAdminPassword && c.adminHashFile == "" }

// StateDirFor returns StateDir for the config file at path, reading only
// lookups.dir from it, so it works when the rest of the file does not
// load without the server's environment.
func StateDirFor(path string) string {
	c := Default()
	c.path = path
	if data, err := os.ReadFile(path); err == nil {
		var f struct {
			Lookups Lookups `yaml:"lookups"`
		}
		if yaml.Unmarshal(data, &f) == nil && f.Lookups.Dir != "" {
			c.Lookups.Dir = f.Lookups.Dir
		}
	}
	if v := os.Getenv("SIGNALITH_LOOKUPS_DIR"); v != "" {
		c.Lookups.Dir = v
	}
	return c.StateDir()
}

// applyAdminHashFile uses the password hash in AdminHashFile when there
// is one.
func (c *Config) applyAdminHashFile() error {
	path := c.AdminHashFile()
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("the built-in admin's password, as changed with signalith passwd: %w", err)
	}
	h := strings.TrimSpace(string(b))
	if _, err := bcrypt.Cost([]byte(h)); err != nil {
		return fmt.Errorf("%s does not hold a password hash. Set the password again with signalith passwd, "+
			"or delete the file to go back to the password in signalith.yaml or SIGNALITH_ADMIN_PASSWORD(_FILE)", path)
	}
	c.Auth.AdminPasswordHash = h
	c.adminHashFile = path
	return nil
}

// applyEnv lets secrets come from the environment instead of the file,
// either in the variable itself or in a file it names (the variable's name
// with _FILE added).
func (c *Config) applyEnv() error {
	if v := os.Getenv("SIGNALITH_OPENSEARCH_URL"); v != "" {
		c.OpenSearch.URL = v
		c.fromEnv("opensearch.url", "SIGNALITH_OPENSEARCH_URL")
	}
	if v := os.Getenv("SIGNALITH_OPENSEARCH_USERNAME"); v != "" {
		c.OpenSearch.Username = v
		c.fromEnv("opensearch.username", "SIGNALITH_OPENSEARCH_USERNAME")
	}
	if v, from, err := envSecret("SIGNALITH_OPENSEARCH_PASSWORD"); err != nil {
		return err
	} else if len(v) > 0 {
		c.OpenSearch.Password = v[0]
		c.fromEnv("opensearch.password", from)
	}
	if v := strings.TrimSpace(os.Getenv("SIGNALITH_OPENSEARCH_PROXY")); v != "" {
		c.OpenSearch.Proxy = v
		c.fromEnv("opensearch.proxy", "SIGNALITH_OPENSEARCH_PROXY")
	}
	if v := os.Getenv("SIGNALITH_LISTEN"); v != "" {
		c.Server.Listen = v
		c.fromEnv("server.listen", "SIGNALITH_LISTEN")
	}
	if v := strings.TrimSpace(os.Getenv("SIGNALITH_PUBLIC_URL")); v != "" {
		if _, err := agents.ParseServerURL(v); err != nil {
			return fmt.Errorf("SIGNALITH_PUBLIC_URL %q: %v", v, err)
		}
		c.Server.PublicURL = v
		c.publicURLFromEnv = true
		c.fromEnv("server.public_url", "SIGNALITH_PUBLIC_URL")
	}
	if v := strings.TrimSpace(os.Getenv("SIGNALITH_NODE_URL")); v != "" {
		if _, err := agents.ParseServerURL(v); err != nil {
			return fmt.Errorf("SIGNALITH_NODE_URL %q: %v", v, err)
		}
		c.Server.NodeURL = v
		c.fromEnv("server.node_url", "SIGNALITH_NODE_URL")
	}
	if v := strings.TrimSpace(os.Getenv("SIGNALITH_NODE_NAME")); v != "" {
		c.Cluster.NodeName = v
		c.fromEnv("cluster.node_name", "SIGNALITH_NODE_NAME")
	}
	if v, from, err := envSecret("SIGNALITH_ADMIN_PASSWORD"); err != nil {
		return err
	} else if len(v) > 0 {
		h, err := envPasswordHash(v[0])
		if err != nil {
			return fmt.Errorf("SIGNALITH_ADMIN_PASSWORD: %w", err)
		}
		c.Auth.AdminPasswordHash = h
		c.envAdminHash, c.envAdminVersion = h, envPasswordVersion(v[0])
		c.publicAdminPassword = v[0] == publicAdminPassword
		c.fromEnv("auth.admin_password_hash", from)
	}
	if v := os.Getenv("SIGNALITH_USERS_FILE"); v != "" {
		c.Auth.UsersFile = v
		c.fromEnv("auth.users_file", "SIGNALITH_USERS_FILE")
	}
	if v, _, err := envSecret("SIGNALITH_LDAP_BIND_PASSWORD"); err != nil {
		return err
	} else if len(v) > 0 {
		c.ldapBindPassword = v[0]
	}
	if v := os.Getenv("SIGNALITH_DETECTIONS_DIR"); v != "" {
		c.Detections.Dir = v
		c.fromEnv("detections.dir", "SIGNALITH_DETECTIONS_DIR")
	}
	if v := os.Getenv("SIGNALITH_LOOKUPS_DIR"); v != "" {
		c.Lookups.Dir = v
		c.fromEnv("lookups.dir", "SIGNALITH_LOOKUPS_DIR")
	}
	if v := os.Getenv("SIGNALITH_DASHBOARDS_DIR"); v != "" {
		c.Dashboards.Dir = v
		c.fromEnv("dashboards.dir", "SIGNALITH_DASHBOARDS_DIR")
	}
	if v := os.Getenv("SIGNALITH_INTEL_FEEDS_FILE"); v != "" {
		c.Intel.FeedsFile = v
		c.fromEnv("intel.feeds_file", "SIGNALITH_INTEL_FEEDS_FILE")
	}
	if v := os.Getenv("SIGNALITH_ARCHIVE_DIR"); v != "" {
		c.Retention.ArchiveDir = v
		c.fromEnv("retention.archive_dir", "SIGNALITH_ARCHIVE_DIR")
	}
	if v, from, err := envSecret("SIGNALITH_ASSISTANT_API_KEY"); err != nil {
		return err
	} else if len(v) > 0 {
		c.Assistant.APIKey = v[0]
		c.fromEnv("assistant.api_key", from)
	}
	if v, from, err := envSecret("SIGNALITH_INGEST_TOKEN"); err != nil {
		return err
	} else if len(v) > 0 {
		// The file's token comes first, so it is the one the Add data
		// page gives new agents: the variable is how an older token is
		// kept for agents that still use it.
		slices.Reverse(v)
		c.Ingest.Tokens = append(c.Ingest.Tokens, v...)
		c.fromEnv("ingest.tokens", from)
	}
	// "off" turns a syslog listener off, since an empty variable is
	// indistinguishable from an unset one.
	if v := os.Getenv("SIGNALITH_SYSLOG_UDP"); v != "" {
		c.Syslog.UDP = offToEmpty(v)
		c.fromEnv("syslog.udp", "SIGNALITH_SYSLOG_UDP")
	}
	if v := os.Getenv("SIGNALITH_SYSLOG_TCP"); v != "" {
		c.Syslog.TCP = offToEmpty(v)
		c.fromEnv("syslog.tcp", "SIGNALITH_SYSLOG_TCP")
	}
	return nil
}

// AdminPasswordVersion changes when the built-in admin's password does,
// and stays the same while it does not, across restarts too. It is the
// password hash, except for a password from SIGNALITH_ADMIN_PASSWORD(_FILE):
// that is hashed again with a new salt by each process, so its version is
// worked out from the password itself instead. It is never written
// anywhere or shown.
func (c *Config) AdminPasswordVersion() string {
	if c.envAdminVersion != "" && c.Auth.AdminPasswordHash == c.envAdminHash {
		return "env:" + c.envAdminVersion
	}
	return "hash:" + c.Auth.AdminPasswordHash
}

// envPasswordVersion is AdminPasswordVersion for a password from the
// environment: a hash of it made only for this purpose.
func envPasswordVersion(pw string) string {
	sum := sha256.Sum256([]byte("signalith admin password version\x00" + pw))
	return hex.EncodeToString(sum[:])
}

// envHash remembers the hash of SIGNALITH_ADMIN_PASSWORD, which every
// load of the config needs and which is slow to compute on purpose.
var envHash struct {
	sync.Mutex
	password, hash string
}

func envPasswordHash(pw string) (string, error) {
	envHash.Lock()
	defer envHash.Unlock()
	if envHash.hash != "" && envHash.password == pw {
		return envHash.hash, nil
	}
	h, err := HashPassword(pw)
	if err != nil {
		return "", err
	}
	envHash.password, envHash.hash = pw, h
	return h, nil
}

func offToEmpty(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), "off") {
		return ""
	}
	return strings.TrimSpace(v)
}

// ValidationError lists every problem found, not just the first.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid configuration:\n  - " + strings.Join(e.Problems, "\n  - ")
}

// Validate checks the config and fills derived defaults.
func (c *Config) Validate() error {
	var p []string
	if _, port, err := net.SplitHostPort(c.Server.Listen); err != nil {
		p = append(p, fmt.Sprintf("server.listen %q must be host:port, for example 0.0.0.0:8080", c.Server.Listen))
	} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		p = append(p, fmt.Sprintf("server.listen port %q must be 1-65535", port))
	}
	if c.Server.MaxConnections < 0 {
		p = append(p, "server.max_connections cannot be negative (0 uses the default, 10000)")
	}
	for i, a := range c.Server.SharedAddresses {
		if _, err := parseAllow(a); err != nil {
			p = append(p, fmt.Sprintf("server.shared_addresses[%d] %q must be an IP address or a CIDR such as 10.0.0.0/24", i, a))
		}
	}
	// Validating again starts from public_url as it was set: empty when
	// it was worked out from the listen address, or the http:// address
	// read as https:// below.
	if c.publicURLDerived {
		c.Server.PublicURL = ""
	} else if c.httpPublicURL != "" && c.Server.PublicURL == httpsForHTTP(c.httpPublicURL) {
		c.Server.PublicURL = c.httpPublicURL
	}
	c.publicURLDerived, c.httpPublicURL = false, ""
	c.Server.proxied = c.Server.legacyHTTP() && strings.HasPrefix(strings.ToLower(c.Server.PublicURL), "https://")
	p = append(p, c.Server.tlsProblems(c.resolve)...)
	if c.Server.PublicURL == "" {
		c.Server.PublicURL, c.publicURLDerived = defaultPublicURL(c.Server), true
	} else if u, err := agents.ParseServerURL(c.Server.PublicURL); err != nil {
		p = append(p, fmt.Sprintf("server.public_url %q: %v", c.Server.PublicURL, err))
	} else if u.Scheme == "http" && c.Server.HTTPS() {
		// Most likely written when Signalith served plain HTTP (in the
		// file, or in SIGNALITH_PUBLIC_URL as older Docker examples show
		// it). The same port serves HTTPS now, so that is the address;
		// Warnings asks for the setting to be changed. With no port it
		// was port 80, which https:// alone would not mean.
		c.httpPublicURL = c.Server.PublicURL
		c.Server.PublicURL = httpsForHTTP(c.Server.PublicURL)
	}
	if c.Server.NodeURL != "" {
		if _, err := agents.ParseServerURL(c.Server.NodeURL); err != nil {
			p = append(p, fmt.Sprintf("server.node_url %q: %v", c.Server.NodeURL, err))
		}
	}
	if n := c.Cluster.NodeName; n != "" && !ValidNodeName(n) {
		p = append(p, fmt.Sprintf("cluster.node_name %q must be 1 to 63 letters, digits, dots, dashes or underscores, starting with a letter or digit", n))
	}
	c.OpenSearch.moveURLCredentials()
	p = append(p, c.OpenSearch.problems(c.resolve)...)
	if c.OpenSearch.IndexPrefix == "" || strings.ToLower(c.OpenSearch.IndexPrefix) != c.OpenSearch.IndexPrefix || strings.ContainsAny(c.OpenSearch.IndexPrefix, `*?"<>|, /\#`) {
		p = append(p, "opensearch.index_prefix must be lowercase with no spaces or wildcards")
	}
	if c.OpenSearch.Replicas < 0 {
		p = append(p, "opensearch.replicas cannot be negative")
	}
	if c.Search.MaxEvents < 1 || c.Search.MaxEvents > 100000 {
		p = append(p, "search.max_events must be between 1 and 100000")
	}
	if c.Retention.Days < 0 {
		p = append(p, "retention.days cannot be negative (0 keeps data forever)")
	} else if c.Retention.Days > retention.MaxKeepDays {
		p = append(p, fmt.Sprintf("retention.days must be at most %d (0 keeps data forever)", retention.MaxKeepDays))
	}
	if c.Retention.Interval != "" {
		if d, err := detect.ParseDuration(c.Retention.Interval); err != nil || d < 5*time.Minute || d > 24*time.Hour {
			p = append(p, fmt.Sprintf("retention.interval %q must be a duration from 5m to 24h, for example 1h", c.Retention.Interval))
		}
	}
	p = append(p, c.RetentionPolicies().Problems()...)
	if c.Auth.AdminUser == "" {
		p = append(p, "auth.admin_user is required")
	}
	if c.Auth.AdminPasswordHash == "" {
		p = append(p, "auth.admin_password_hash is empty; run signalith passwd, or set SIGNALITH_ADMIN_PASSWORD")
	} else if _, err := bcrypt.Cost([]byte(c.Auth.AdminPasswordHash)); err != nil {
		p = append(p, "auth.admin_password_hash is not a bcrypt hash; generate one with signalith passwd")
	}
	if c.Auth.SessionTimeout != "" {
		if d, err := detect.ParseDuration(c.Auth.SessionTimeout); err != nil || d < 5*time.Minute {
			p = append(p, fmt.Sprintf("auth.session_timeout %q must be a duration of at least 5m, for example 12h or 1d", c.Auth.SessionTimeout))
		}
	}
	if c.Auth.LDAP != nil {
		if s, err := c.LDAP(); err != nil {
			p = append(p, err.Error())
		} else {
			for _, pr := range s.Problems() {
				msg := pr.Message
				if pr.Field == "bind_password" {
					if c.locked["auth.ldap.bind_password"] {
						// Reported by Warnings; directory sign-in fails
						// without trying an empty password.
						continue
					}
					msg = "set auth.ldap.bind_password, or the SIGNALITH_LDAP_BIND_PASSWORD environment variable"
				}
				p = append(p, "auth.ldap."+pr.Field+": "+msg)
			}
		}
	}
	if c.Detections.Dir == "" {
		p = append(p, "detections.dir is required, for example: detections")
	}
	if c.Lookups.Dir == "" {
		p = append(p, "lookups.dir is required, for example: lookups")
	}
	if c.Dashboards.Dir == "" {
		p = append(p, "dashboards.dir is required, for example: dashboards")
	}
	if c.Dashboards.StaleAfter == "" {
		c.Dashboards.StaleAfter = "2h"
	} else if d, err := detect.ParseDuration(c.Dashboards.StaleAfter); err != nil || d < 5*time.Minute {
		p = append(p, fmt.Sprintf("dashboards.stale_after %q must be a duration of at least 5m, for example 2h or 1d", c.Dashboards.StaleAfter))
	}
	switch c.Assistant.Provider {
	case "":
	case "anthropic":
		// A key that cannot be decrypted is reported by Warnings instead.
		if c.Assistant.APIKey == "" && !c.locked["assistant.api_key"] && c.pageLocked["assistant.api_key"] == "" {
			p = append(p, "assistant.api_key is required for anthropic; set it or SIGNALITH_ASSISTANT_API_KEY")
		}
	case "openai":
		if c.Assistant.Model == "" {
			p = append(p, "assistant.model is required for openai, for example gpt-4.1 or, with Ollama, llama3.1")
		}
	default:
		p = append(p, fmt.Sprintf("assistant.provider %q must be anthropic, openai or empty (off)", c.Assistant.Provider))
	}
	if c.Assistant.URL != "" {
		if u, err := url.Parse(c.Assistant.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			p = append(p, fmt.Sprintf("assistant.url %q must be http(s)://host[:port][/path]", redact.URL(c.Assistant.URL)))
		}
	}
	p = append(p, c.Intel.problems()...)
	if c.Detections.MaxFindingsPerRun < 1 || c.Detections.MaxFindingsPerRun > 10000 {
		p = append(p, "detections.max_findings_per_run must be between 1 and 10000")
	}
	for i, t := range c.Ingest.Tokens {
		if len(t) < 16 {
			p = append(p, fmt.Sprintf("ingest.tokens[%d] is shorter than 16 characters", i))
		}
	}
	if c.Ingest.MaxEventAge != "" {
		if d, err := detect.ParseDuration(c.Ingest.MaxEventAge); err != nil || d < time.Hour || d > 3650*24*time.Hour {
			p = append(p, fmt.Sprintf("ingest.max_event_age %q must be a duration from 1h to 3650d, for example 7d or 30d (empty: 7 days)", c.Ingest.MaxEventAge))
		}
	}
	p = append(p, c.Syslog.problems(c.Server)...)
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

// Warnings lists settings that work but put data at risk. validate prints
// them, and the server logs them at startup and shows them on the Health
// page.
func (c *Config) Warnings() []string {
	var w []string
	o := c.OpenSearch
	if o.TLSSkipVerify {
		w = append(w, "opensearch.tls_skip_verify is on, so Signalith does not check OpenSearch's certificate: anyone on the network path "+
			"could read and change events and capture the OpenSearch password. Set opensearch.ca_file to OpenSearch's CA certificate and turn tls_skip_verify off.")
	}
	if u, err := url.Parse(o.URL); err == nil && u.Scheme == "http" && o.AllowInsecureHTTP && (o.Username != "" || o.Password != "") && !isLoopback(u.Hostname()) {
		w = append(w, "opensearch.allow_insecure_http is on, so the OpenSearch username and password cross the network to "+u.Host+" unencrypted. Use an https:// opensearch.url.")
	}
	if u, err := url.Parse(c.Assistant.URL); err == nil && c.Assistant.Provider != "" && u.Scheme == "http" && c.Assistant.APIKey != "" && !isLoopback(u.Hostname()) {
		w = append(w, "assistant.url is plain http to "+u.Host+", so the AI model's API key crosses the network unencrypted. Use https://.")
	}
	if c.PublicAdminPassword() {
		w = append(w, "The built-in admin's password is "+publicAdminPassword+", the example in an older docker-compose.yml, which anyone can look up. "+
			"Remove SIGNALITH_ADMIN_PASSWORD (the Docker quick start now makes a password; from the Signalith folder: "+
			"docker compose -f deploy/docker/docker-compose.yml exec signalith signalith initial-password), or set a new one with signalith passwd.")
	}
	for _, t := range c.Ingest.Tokens {
		if IsPublicIngestToken(t) {
			fix := "Give each agent a new configuration from the Add data page, which has this server's own token, then remove " + t
			if len(c.Ingest.Tokens) == 1 {
				fix = "Add a token of your own under ingest.tokens (signalith init makes one), give each agent a new configuration from the Add data page, then remove " + t
			}
			w = append(w, "ingest.tokens includes "+t+", the example token in an older docker-compose.yml, which anyone can look up and use to send events. "+
				fix+" (in ingest.tokens or SIGNALITH_INGEST_TOKEN).")
		}
	}
	if c.httpPublicURL != "" {
		where, fix := "server.public_url is "+c.httpPublicURL, "Change public_url to "+c.Server.PublicURL+" in signalith.yaml"
		if c.Source("server.public_url").Kind == FromPage {
			fix = "Change it to " + c.Server.PublicURL + " on the Settings page"
		}
		if c.publicURLFromEnv {
			where, fix = "SIGNALITH_PUBLIC_URL is "+c.httpPublicURL, "Change SIGNALITH_PUBLIC_URL to "+c.Server.PublicURL+" (in docker-compose.yml, or wherever it is set)"
		}
		w = append(w, where+", but Signalith serves HTTPS on that port now, so agents are set up with "+c.Server.PublicURL+". "+
			fix+". If a reverse proxy in front adds HTTPS, use the proxy's https:// address instead.")
	}
	if host, _, err := net.SplitHostPort(c.Server.Listen); err == nil && !c.Server.HTTPS() && !isLoopback(host) && len(c.Server.TrustedProxies) == 0 {
		w = append(w, "HTTPS is off (server.tls.mode: off) and server.listen accepts connections from other machines, so passwords, sessions, "+
			"the ingest token and events cross the network unencrypted unless a reverse proxy in front adds HTTPS. Turn it on with server.tls.mode: auto, "+
			"or list the proxy's address under server.trusted_proxies.")
	}
	return append(w, c.secretWarnings()...)
}

// Secrets from older example files, which anyone can look up. Warnings
// names them while they are in use.
const publicAdminPassword = "change-me-please"

var publicIngestTokens = []string{"change-this-ingest-token"}

// IsPublicIngestToken reports whether t is the example ingest token from an
// older docker-compose.yml, which anyone can look up. The Add data page
// never hands it to new agents.
func IsPublicIngestToken(t string) bool { return slices.Contains(publicIngestTokens, t) }

// OpenSearchConnection returns the settings Signalith connects to
// OpenSearch with.
func (c *Config) OpenSearchConnection() store.Config {
	ca, cert, key := c.OpenSearchTLSFiles()
	return store.Config{
		URL: c.OpenSearch.URL, Username: c.OpenSearch.Username, Password: secrets.New("opensearch.password", c.OpenSearch.Password),
		CAFile: ca, CertFile: cert, KeyFile: key,
		TLSSkipVerify: c.OpenSearch.TLSSkipVerify, Proxy: c.OpenSearch.Proxy,
	}
}

// OpenSearchProblems lists what is wrong with the OpenSearch connection
// settings, as Validate words it.
func (c *Config) OpenSearchProblems() []string {
	o := c.OpenSearch
	o.moveURLCredentials()
	return o.problems(c.resolve)
}

// OpenSearchTLSFiles returns opensearch.ca_file, cert_file and key_file,
// with relative paths made relative to the folder this config file is in.
func (c *Config) OpenSearchTLSFiles() (ca, cert, key string) {
	return c.resolve(c.OpenSearch.CAFile), c.resolve(c.OpenSearch.CertFile), c.resolve(c.OpenSearch.KeyFile)
}

// ValidNodeName reports whether name can be a server's name: 1 to 63
// letters, digits, dots, dashes or underscores, starting with a letter or
// digit, as a host name would be.
func ValidNodeName(name string) bool {
	if name == "" || len(name) > 63 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case i > 0 && (r == '.' || r == '-' || r == '_'):
		default:
			return false
		}
	}
	return true
}

// httpsForHTTP is an http:// public_url read as https://, now that the
// same port serves HTTPS: the same host and port, with :80 when it had
// none, which https:// alone would not mean.
func httpsForHTTP(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "80")
	}
	return "https://" + host
}

func defaultPublicURL(s Server) string {
	host, port, err := net.SplitHostPort(s.Listen)
	if err != nil {
		return ""
	}
	scheme := "https"
	if !s.HTTPS() {
		scheme = "http"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
		// The machine's name, if it can go into an agent config as is.
		if h, err := os.Hostname(); err == nil {
			if _, err := agents.ParseServerURL(scheme + "://" + net.JoinHostPort(h, port)); err == nil {
				host = h
			}
		}
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

// HashPassword returns a bcrypt hash for the admin password. Users'
// passwords follow the same rules.
func HashPassword(pw string) (string, error) { return users.HashPassword(pw) }

// CheckPassword reports whether user and pw are the built-in admin's. The
// username ignores case, like every other username.
func (c *Config) CheckPassword(user, pw string) bool {
	if !strings.EqualFold(strings.TrimSpace(user), c.Auth.AdminUser) {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(c.Auth.AdminPasswordHash), []byte(pw)) == nil
}

// RandomToken returns a random hex token.
func RandomToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Save writes the config with a header comment explaining each section,
// with its passwords and keys encrypted. A config from Load is written as
// its file had it: settings from environment variables are never written
// out, and neither are changes made after loading (use SetSecret or
// SetAdminPasswordHash to change one setting in a file). A config with
// settings from the Settings page is refused, so they stay in their own
// file; load it with LoadFile to change signalith.yaml.
func (c *Config) Save(path string) error {
	if len(c.PageKeys()) > 0 {
		return errors.New("this configuration includes settings from the Settings page; load signalith.yaml with LoadFile to save it")
	}
	src := c
	if c.file != nil {
		src = c.file
	}
	if c.path == "" {
		// The master key goes with the file: a keyring made before the
		// config had a file is made again for its folder.
		c.path, c.keys = path, nil
	}
	var doc yaml.Node
	if err := doc.Encode(src); err != nil {
		return err
	}
	for _, n := range secretNodes(&doc) {
		if !isPlain(n.node.Value, n.envRefs) {
			continue
		}
		sealed, err := c.Keyring().Seal(n.field, n.node.Value)
		if err != nil {
			return err
		}
		n.node.Value, n.node.Style = sealed, 0
	}
	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if comment, ok := sectionComments[root.Content[i].Value]; ok {
			root.Content[i].HeadComment = comment
		}
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	return securefile.WriteFile(path, []byte(header+string(out)))
}

// sectionComments are written just above a section of the saved file.
var sectionComments = map[string]string{
	"syslog": `Syslog from systems that cannot run an agent (firewalls, switches, routers,
appliances, servers). Point them at this server on UDP or TCP port 514, or
TLS port 6514 (it uses the web UI's certificate). An empty address turns
that listener off. allow limits who may send, as IPs or CIDRs such as
10.0.0.0/8; empty allows any sender.`,
}

const header = `# Signalith configuration.
# Run "signalith validate" after editing. Secrets can come from environment
# variables instead of this file: SIGNALITH_OPENSEARCH_PASSWORD,
# SIGNALITH_ADMIN_PASSWORD, SIGNALITH_INGEST_TOKEN, SIGNALITH_ASSISTANT_API_KEY,
# SIGNALITH_LDAP_BIND_PASSWORD, or from files named by the same variables with
# _FILE added (such as SIGNALITH_ADMIN_PASSWORD_FILE). Passwords and keys
# below are encrypted (enc:v1:...) with Signalith's master key; a plain value
# pasted in works too, and "signalith secrets encrypt" encrypts it (see
# docs/encryption.md).
#
# server.listen      address the UI/API binds to (0.0.0.0:8080 for all interfaces)
# server.public_url  URL agents use to reach this server (or SIGNALITH_PUBLIC_URL)
# server.tls.mode    auto: HTTPS with a certificate Signalith makes and renews itself
#                    (browsers warn until you trust its CA; see docs/https.md);
#                    files: your own certificate in server.tls_cert and tls_key;
#                    off: plain HTTP, only behind a reverse proxy that adds HTTPS
# server.tls.names   extra host names or IPs for the auto certificate
# server.tls.plaintext_ingest  allow or deny agents sending over plain http://
# server.tls.ca_scope  standard or strict: how far Signalith's own certificate
#                    authority reaches when one is made (see docs/https.md)
# server.trusted_proxies  IPs or CIDRs of reverse proxies whose X-Forwarded-Proto
#                    header is believed
# server.client_header  x-forwarded-for or forwarded: the header those proxies
#                    write each person's address into, for the sign-in limits and
#                    the log; empty counts everyone behind them as one shared address
# server.max_connections  open connections allowed at once (default 10000); one
#                    client may hold a tenth of them
# server.shared_addresses  IPs or CIDRs of a proxy, load balancer or NAT that many
#                    clients reach Signalith through; not limited as one client,
#                    and wrong passwords from them never lock the address
# auth.admin_user    the built-in admin, a break-glass account; add other users on the Users page
# auth.session_timeout  sign the web UI out after this long idle (default 12h)
# auth.users_file    where Users page accounts are kept (default users.json in lookups.dir)
# auth.ldap          optional LDAP / Active Directory sign-in; usually set up on the Users
#                    page instead (see docs/users.md)
# opensearch.*       where events are stored; for https with a private CA set
#                    ca_file (cert_file and key_file for certificate sign-in)
# search.*           default time range and result limits
# retention.days     days of events to keep (0 = forever) until a default is saved on the
#                    Data retention page; per-category policies, the disk guard and
#                    archiving are set there too (or here: see docs/retention.md)
# ingest.tokens      tokens agents send; see the Add data page for agent setup
# ingest.max_event_age  events older than this (default 7d) are filed under the time
#                    they arrived, with their own time in device_time
# syslog.udp, .tcp   receive syslog from devices without an agent, e.g. 0.0.0.0:514
#                    (empty = off; SIGNALITH_SYSLOG_UDP / _TCP override, "off" turns off)
# syslog.tls         syslog over TLS, e.g. 0.0.0.0:6514; uses the web UI's certificate
# syslog.allow       sender IPs or CIDRs allowed to send syslog (empty = any sender)
# syslog.public_port port devices send to, if forwarded to another (Docker: 514 -> 5514)
# detections.dir     folder for custom detections (relative to this file)
# detections.scheduler  lets this server run detections, threat intel downloads and
#                    retention; servers that share one OpenSearch take turns
# lookups.dir        folder for assets.csv and identities.csv (relative to this file)
# dashboards.dir     folder for custom dashboards, one YAML file each (relative to this file)
# dashboards.stale_after  how long a host can go quiet before the posture dashboard flags it
# assistant.*        optional AI model for "Ask in English" (provider: anthropic or openai);
#                    off by default, and only the question and field names are sent
# intel.feeds        threat intel feeds to download (none by default). The easiest way
#                    is the Threat intel page (Add feed), which keeps its feeds in
#                    lookups.dir/intel_feeds.yaml (intel.feeds_file). Or list them here:
#                      - name: feodo-tracker
#                        url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
#                    format: lines, csv (with column:), stix or auto; see docs/threat-intel.md
# cluster.node_name  this server's name on the Servers page (default: this computer's
#                    name; SIGNALITH_NODE_NAME overrides it)
# server.node_url    the address other Signalith servers reach this one at (default:
#                    worked out from server.listen; SIGNALITH_NODE_URL overrides it)

`
