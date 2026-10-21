// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package agentproto is what the Signalith Agent and a Signalith server
// say to each other: the routes on the agent port, and the JSON of the
// configuration the agent fetches and the status it reports.
//
// The Signalith Agent (cmd/signalith-agent) is one program per computer
// that runs the collectors for it: it fetches what to collect from the
// server every few minutes, writes the collectors' configuration, keeps
// them running and says how they are. It holds an agent token made for it
// (purpose "agent") and sends it with every request, as Fluent Bit does
// with its batches. This package imports nothing but the standard
// library, so the agent stays small.
package agentproto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strings"
)

// Routes on the agent port. The install scripts and the program are
// fetched before the agent runs; the agent itself fetches its
// configuration and sends its status.
const (
	// RouteConfig answers the agent's configuration (Config), or 304 when
	// it has not changed since the revision in If-None-Match.
	RouteConfig = "/api/agent/config"
	// RouteStatus takes the agent's Status.
	RouteStatus = "/api/agent/status"
	// RouteProgram answers the agent program for ?os=&arch=, with its
	// SHA-256 in the X-Signalith-SHA256 header.
	RouteProgram = "/api/agent/program"
	// RouteInstallSH is the Linux install script.
	RouteInstallSH = "/api/agent/install.sh"
	// RouteInstallPS1 is the Windows install script.
	RouteInstallPS1 = "/api/agent/install.ps1"
	// RouteInstallMacOS is the macOS install script.
	RouteInstallMacOS = "/api/agent/install-macos.sh"
)

// Headers the agent sends with every request, besides the agent token in
// Authorization. HeaderName is the computer's name, the same one its
// Fluent Bit sends (X-Signalith-Agent), so the Endpoints page shows both
// on one row; it is a label, never used to let anyone in.
const (
	HeaderName    = "X-Signalith-Agent"
	HeaderVersion = "X-Signalith-Agent-Version"
	HeaderSHA256  = "X-Signalith-SHA256"
)

// Config is what the server tells an agent to run.
type Config struct {
	// Revision names this configuration; the agent sends it back in
	// If-None-Match, and in its status as the one it runs.
	Revision string `json:"revision"`
	// PollSeconds is how often the agent asks again.
	PollSeconds int `json:"poll_seconds"`
	// CA is the certificate authority, in PEM, the agent and its
	// collectors check the server's certificate with: Signalith's own, and
	// the next one while it switches. Empty when the server's certificate
	// is from an authority the computer trusts already.
	CA string `json:"ca,omitempty"`
	// FluentBit is the log collector's configuration; nil runs none.
	FluentBit *FluentBit `json:"fluentbit,omitempty"`
	// Osquery is osquery's part, for an agent whose computer has osquery
	// (it says so when it asks); nil runs none.
	Osquery *Osquery `json:"osquery,omitempty"`
	// Update offers the agent a newer version of itself, from the signed
	// manifest of the programs the server hands out; nil offers none.
	Update *Update `json:"update,omitempty"`
}

// FluentBit is Fluent Bit's part of a Config.
type FluentBit struct {
	// Config is fluent-bit.conf. It reads the agent token from the
	// SIGNALITH_TOKEN variable, which the agent sets, so the file holds
	// no secret.
	Config string `json:"config"`
}

// Osquery is osquery's part of a Config: osquery uses Signalith as its
// management server (enrolling with the agent token), and fetches what
// to collect from it.
type Osquery struct {
	// Flags are the flags that point osquery at Signalith, one
	// --name=value a line. The agent adds those that name its own files
	// (the enroll secret, which is the agent token file, the certificate
	// authority and osquery's database), and runs none it does not know
	// (OsqueryFlagAllowed).
	Flags string `json:"flags,omitempty"`
	// Error is why osquery cannot use this server, "" when it can; the
	// agent then runs no osquery and reports the reason.
	Error string `json:"error,omitempty"`
}

// OsqueryDisabledTables are the osquery tables no query may read
// (ASI-12): curl and curl_certificate make the computer fetch any
// address, so a live query to every host could reach anything they can.
// osquery's file carving, the other way to take files off a host, stays
// off as osquery leaves it (--disable_carver).
const OsqueryDisabledTables = "curl,curl_certificate"

// osqueryFlagNames are the flags a server may give osquery. Flags that
// load code (extensions) or name files are not among them: the agent
// names its own files.
var osqueryFlagNames = map[string]bool{
	"tls_hostname": true, "enroll_tls_endpoint": true, "host_identifier": true,
	"config_plugin": true, "config_tls_endpoint": true, "config_refresh": true, "config_accelerated_refresh": true,
	"logger_plugin": true, "logger_tls_endpoint": true, "logger_tls_period": true,
	"disable_distributed": true, "distributed_plugin": true, "distributed_interval": true,
	"distributed_tls_max_attempts": true, "distributed_tls_read_endpoint": true, "distributed_tls_write_endpoint": true,
	"disable_events": true, "enable_file_events": true, "enable_ntfs_event_publisher": true, "utc": true,
	// macOS: program starts from EndpointSecurity.
	"disable_endpointsecurity": true,
	// Tables a live query may not read; the agent adds its own list
	// after the server's, and osquery keeps the last.
	"disable_tables": true,
}

// osqueryFlagValue is what a value of those flags may hold: a host and
// port, a route, a number, true or a list of names; no spaces, which
// could start another flag.
var osqueryFlagValue = regexp.MustCompile(`^[A-Za-z0-9._:/\[\],-]*$`)

// OsqueryFlagAllowed says whether a server may give osquery the flag
// line (--name or --name=value).
func OsqueryFlagAllowed(line string) bool {
	name, ok := strings.CutPrefix(line, "--")
	if !ok {
		return false
	}
	name, value, _ := strings.Cut(name, "=")
	return osqueryFlagNames[name] && osqueryFlagValue.MatchString(value)
}

// Status is what an agent reports: itself and each collector it runs.
type Status struct {
	// Version is the agent's own version.
	Version string `json:"version"`
	// OS and Arch are the computer's (Go's names: linux, windows, darwin;
	// amd64, arm64), and System its distribution and version as the
	// computer says them (Ubuntu 24.04.1 LTS).
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	System string `json:"system,omitempty"`
	// Revision is the configuration it runs, "" before the first.
	Revision string `json:"revision,omitempty"`
	// Started is when the agent started (RFC 3339).
	Started string `json:"started,omitempty"`
	// ConfigError is why the last configuration could not be fetched or
	// applied, "" when it was.
	ConfigError string `json:"config_error,omitempty"`
	// Components are the collectors it runs.
	Components []Component `json:"components"`
	// CAs are the SHA-256 fingerprints (lowercase hex) of the
	// certificate authorities in its ca.pem, at most MaxCAs; none from
	// agents before they reported them.
	CAs []string `json:"ca_sha256,omitempty"`
}

// TooManyCAs stands, last in Status.CAs, for the certificate
// authorities past MaxCAs in an agent's ca.pem: no certificate has this
// fingerprint, so the server never knows it.
var TooManyCAs = strings.Repeat("0", 64)

// Component states.
const (
	StateRunning  = "running"
	StateStarting = "starting"
	StateFailed   = "failed"
	StateMissing  = "missing"
	StateOff      = "off"
)

// Component is one collector the agent runs.
type Component struct {
	// Name is fluentbit or osquery.
	Name string `json:"name"`
	// Version is the collector's version, "" when not known.
	Version string `json:"version,omitempty"`
	// State is one of the State constants.
	State string `json:"state"`
	// Restarts counts the times the agent restarted it since the agent
	// started, other than for a new configuration.
	Restarts int `json:"restarts,omitempty"`
	// Since is when it got into its state (RFC 3339).
	Since string `json:"since,omitempty"`
	// Error is why it is failed or missing, with the last lines it wrote.
	Error string `json:"error,omitempty"`
}

// Limits on what an agent sends, so a broken or hostile one cannot fill
// memory or the inventory.
const (
	MaxStatusBytes  = 64 << 10
	MaxComponents   = 8
	MaxCAs          = 8
	MaxTextLen      = 2000
	maxShortTextLen = 128
)

var (
	shortText   = regexp.MustCompile(`^[A-Za-z0-9 ._:+()/-]*$`)
	revisionHex = regexp.MustCompile(`^[0-9a-f]{0,64}$`)
)

// Clean trims what an agent reported to what the server keeps: short
// fields that are not plain text are dropped, long ones cut, and at most
// MaxComponents components with known states kept.
func (s Status) Clean() Status {
	short := func(v string) string {
		v = strings.TrimSpace(v)
		if len(v) > maxShortTextLen || !shortText.MatchString(v) {
			return ""
		}
		return v
	}
	out := Status{
		Version: short(s.Version), OS: short(s.OS), Arch: short(s.Arch), System: short(s.System),
		Started: short(s.Started), ConfigError: cut(s.ConfigError),
		Components: []Component{},
	}
	if revisionHex.MatchString(s.Revision) {
		out.Revision = s.Revision
	}
	for _, fp := range s.CAs {
		if len(out.CAs) == MaxCAs {
			break
		}
		if fp = strings.ToLower(fp); sha256Hex.MatchString(fp) {
			out.CAs = append(out.CAs, fp)
		}
	}
	for _, c := range s.Components {
		if len(out.Components) == MaxComponents {
			break
		}
		switch c.State {
		case StateRunning, StateStarting, StateFailed, StateMissing, StateOff:
		default:
			continue
		}
		name := short(c.Name)
		if name == "" {
			continue
		}
		restarts := c.Restarts
		if restarts < 0 {
			restarts = 0
		}
		out.Components = append(out.Components, Component{
			Name: name, Version: short(c.Version), State: c.State, Restarts: restarts,
			Since: short(c.Since), Error: cut(c.Error),
		})
	}
	return out
}

// cut keeps at most MaxTextLen bytes of v, ending on a whole character,
// and drops control characters other than new lines and tabs.
func cut(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f || r == 0xfffd {
			return -1
		}
		return r
	}, strings.TrimSpace(v))
	if len(v) <= MaxTextLen {
		return v
	}
	for i := MaxTextLen; i > 0; i-- {
		if v[i]&0xc0 != 0x80 {
			return v[:i]
		}
	}
	return ""
}

// RevisionOf names a configuration by what it holds: revisionSum of the
// JSON the server sends (Encode) with an empty Revision. An agent checks
// it over the bytes it got (RawRevision), so fields it doesn't know yet
// count too.
func RevisionOf(c Config) string {
	c.Revision = ""
	return revisionSum(Encode(c))
}

// Encode is c as the server sends it (its writeJSON, without the final
// new line): compact JSON, with <, > and & as they are.
func Encode(c Config) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(c)
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

// LegacyRevisionOf is how servers before RawRevision named a
// configuration: the sum of json.Marshal with an empty Revision, which
// escapes <, > and & unlike the JSON they sent. An agent accepts it from
// such a server. It matches only while every Config field the server
// doesn't know is empty and omitempty.
func LegacyRevisionOf(c Config) string {
	c.Revision = ""
	b, _ := json.Marshal(c)
	return revisionSum(b)
}

// RawRevision is the revision of b, a configuration's JSON as received:
// revisionSum of b with what follows its top-level "revision" key (the
// colon, any white space and the string) made `:""`, and the white space
// around b trimmed. It is RevisionOf of what the
// server encoded, whatever fields the agent knows. ok is false when b is
// not one JSON object with exactly one top-level "revision" string.
func RawRevision(b []byte) (rev string, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return "", false
	}
	start, end := int64(-1), int64(-1)
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return "", false
		}
		if t == "revision" {
			if start >= 0 {
				return "", false
			}
			// From the end of the key to the end of its value: the
			// colon, any white space and the string.
			start = dec.InputOffset()
			v, err := dec.Token()
			if _, isString := v.(string); err != nil || !isString {
				return "", false
			}
			end = dec.InputOffset()
			continue
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return "", false
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') || start < 0 {
		return "", false
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", false
	}
	blank := make([]byte, 0, len(b))
	blank = append(blank, b[:start]...)
	blank = append(blank, `:""`...)
	blank = append(blank, b[end:]...)
	return revisionSum(bytes.TrimSpace(blank)), true
}

// revisionSum is the first 32 hex digits of the SHA-256 of b.
func revisionSum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

// Platforms are the computers the agent program is built for, as
// os-arch.
var Platforms = []string{"linux-amd64", "linux-arm64", "windows-amd64", "darwin-amd64", "darwin-arm64"}

// ProgramName is the agent program's file name for a platform, as the
// server keeps them (signalith-agent-linux-amd64,
// signalith-agent-windows-amd64.exe).
func ProgramName(goos, goarch string) string {
	name := "signalith-agent-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}
