package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration written as "30s" or "2m" in scenario files.
type Duration time.Duration

// D is the duration as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("line %d: %q is not a duration such as 30s or 2m", n.Line, s)
	}
	if v < 0 {
		return fmt.Errorf("line %d: %q is negative", n.Line, s)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(d.D().String()), nil }

// Scenario is one load test: who sends what, for how long, what breaks
// on the way, and what counts as a pass.
type Scenario struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	// Needs names features the servers must have; a scenario whose
	// features are missing is skipped, not failed.
	Needs []string `yaml:"needs"`
	// Targets are the servers' web addresses, or one load balancer's.
	Targets []string `yaml:"targets"`
	// AgentTargets are the addresses the agents send to, when the servers
	// take agents on a port of their own (server.agent_listen); empty
	// sends them to Targets.
	AgentTargets []string `yaml:"agent_targets"`
	// CAFile and CAFiles are the certificate authorities that sign the
	// targets' HTTPS certificates; empty uses the system's.
	CAFile  string   `yaml:"ca_file"`
	CAFiles []string `yaml:"ca_files"`
	// SyslogTargets are host:port addresses of the syslog listeners.
	SyslogTargets SyslogTargets `yaml:"syslog_targets"`
	Credentials   Credentials   `yaml:"credentials"`
	OpenSearch    OpenSearch    `yaml:"opensearch"`
	Toxiproxy     Toxiproxy     `yaml:"toxiproxy"`
	// Seed runs API requests once, before the first phase.
	Seed []SeedStep `yaml:"seed"`
	// Drain is how long agents keep resending batches after the last
	// phase; default 2m.
	Drain Duration `yaml:"drain"`
	// Settle is how long verify waits for stored counts to stop
	// changing; default 1m.
	Settle Duration `yaml:"settle"`
	Phases []Phase  `yaml:"phases"`
	Faults []Fault  `yaml:"faults"`
	// Checks are commands run once the load has ended; each one that
	// exits non-zero counts toward check_failures.
	Checks   []Check     `yaml:"checks"`
	Criteria []Criterion `yaml:"criteria"`
}

// Check is a command run after the phases, for what only the lab can
// look at, such as who wrote the files on an archive share.
type Check struct {
	Name string `yaml:"name"`
	Cmd  string `yaml:"cmd"`
}

// SyslogTargets are the syslog listeners by protocol.
type SyslogTargets struct {
	UDP []string `yaml:"udp"`
	TCP []string `yaml:"tcp"`
	TLS []string `yaml:"tls"`
}

// Credentials name the files the secrets are read from. Secrets are
// never written in scenario files, flags or reports.
type Credentials struct {
	// AdminFile holds "user:password" (or a password for admin).
	AdminFile string `yaml:"admin_file"`
	// TokenFile holds an agent token.
	TokenFile string `yaml:"token_file"`
	// UsersFile is a CSV of username,password for simulated users who
	// already exist.
	UsersFile string `yaml:"users_file"`
}

// OpenSearch is where verify and the request counts read from. It is
// only ever read.
type OpenSearch struct {
	URL string `yaml:"url"`
	// URLs are further nodes of the same OpenSearch, tried in turn when
	// the one in use does not answer (a node is stopped on purpose in S9).
	URLs     []string `yaml:"urls"`
	CA       string   `yaml:"ca"`
	Cert     string   `yaml:"cert"`
	Key      string   `yaml:"key"`
	UserFile string   `yaml:"user_file"`
	// Prefix is the servers' opensearch.index_prefix; default signalith.
	Prefix string `yaml:"index_prefix"`
}

// Toxiproxy is the proxy between the servers and OpenSearch that the
// cut_opensearch fault turns off and on again.
type Toxiproxy struct {
	URL   string `yaml:"url"`
	Proxy string `yaml:"proxy"`
}

// SeedStep is one API request, repeated Count times. In Path and Body,
// {i} is the repeat number from 1 and {run} the run ID.
type SeedStep struct {
	Name   string `yaml:"name"`
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
	Body   string `yaml:"body"`
	Count  int    `yaml:"count"`
}

// Phase is a stretch of the run with one mix of load.
type Phase struct {
	Name        string       `yaml:"name"`
	For         Duration     `yaml:"for"`
	Agents      *AgentLoad   `yaml:"agents"`
	Syslog      *SyslogLoad  `yaml:"syslog"`
	Users       *UserLoad    `yaml:"users"`
	Brute       *BruteLoad   `yaml:"brute"`
	Churn       *ChurnLoad   `yaml:"churn"`
	CookieFlood *CookieFlood `yaml:"cookie_flood"`
}

// AgentLoad is simulated Fluent Bit agents.
type AgentLoad struct {
	N int `yaml:"n"`
	// Rate is events per second, all agents together.
	Rate float64 `yaml:"rate"`
	// Batch is events per request; default 200.
	Batch int `yaml:"batch"`
	// EventBytes pads each event's message to about this size.
	EventBytes int `yaml:"event_bytes"`
	// SwitchOnError sends a batch that failed to the next target, as an
	// agent behind DNS round robin may; by default an agent keeps its
	// target, as Fluent Bit with one Host does.
	SwitchOnError bool `yaml:"switch_on_error"`
	// BufferMB caps the memory all agents' unsent batches hold together;
	// past it new batches are dropped and counted, as Fluent Bit's
	// Mem_Buf_Limit does. Default 512.
	BufferMB int `yaml:"buffer_mb"`
}

// SyslogLoad is simulated syslog devices.
type SyslogLoad struct {
	// Proto is udp, tcp or tls.
	Proto   string  `yaml:"proto"`
	Sources int     `yaml:"sources"`
	Rate    float64 `yaml:"rate"`
	// Format is 5424 (default) or 3164.
	Format string `yaml:"format"`
	// ProxyV2 starts each connection (or datagram) with a PROXY v2
	// header naming a different source address per device.
	ProxyV2 bool `yaml:"proxy_v2"`
}

// UserLoad is simulated people using the web pages.
type UserLoad struct {
	N int `yaml:"n"`
	// Think is the time between one user's page loads; default 5s.
	Think Duration `yaml:"think"`
	// Search is the query each page load runs; default the run's events.
	Search string `yaml:"search"`
	// Triage has analysts comment on the same findings and the same case.
	Triage bool `yaml:"triage"`
	// Create makes N analyst accounts for the run (and removes them
	// afterwards) instead of reading credentials.users_file.
	Create bool `yaml:"create"`
}

// BruteLoad is wrong passwords tried against accounts made for the run.
type BruteLoad struct {
	Accounts int     `yaml:"accounts"`
	Sources  int     `yaml:"sources"`
	Rate     float64 `yaml:"rate"`
	// ViaProxy sends every attempt with a PROXY v2 header from this
	// address, as if all came through one proxy; needs proxy_protocol.
	ViaProxy string `yaml:"via_proxy"`
}

// ChurnLoad edits one setting over and over.
type ChurnLoad struct {
	Every  Duration `yaml:"every"`
	Key    string   `yaml:"key"`
	Values []any    `yaml:"values"`
}

// CookieFlood is requests with made-up session cookies.
type CookieFlood struct {
	Rate float64 `yaml:"rate"`
}

// Fault is something broken on purpose during the run.
type Fault struct {
	// At is from the start of the first phase.
	At Duration `yaml:"at"`
	// Kind is kill9, stop, cut_opensearch, clock, fill_disk, cmd or
	// upgrade. An upgrade takes every server in turn, as the upgrade
	// check says (upgradeAll), and runs Cmd for each.
	Kind string `yaml:"kind"`
	// Target is leader, standby, windows (a Windows server), or a
	// server name. An upgrade has none: it takes every server.
	Target string `yaml:"target"`
	// For, when set, runs Undo that long after Cmd.
	For Duration `yaml:"for"`
	// Cmd and Undo are shell commands; {server} is the target server's
	// name.
	Cmd  string `yaml:"cmd"`
	Undo string `yaml:"undo"`
	// WindowsCmd and WindowsUndo replace Cmd and Undo when the target
	// is a Windows server, which needs other commands to stop.
	WindowsCmd  string `yaml:"windows_cmd"`
	WindowsUndo string `yaml:"windows_undo"`
	// Version is the version an upgrade installs; when empty, any version
	// other than the one a server ran before counts.
	Version string `yaml:"version"`
}

// Criterion is one pass condition. With neither Max nor Min the value is
// recorded only.
type Criterion struct {
	Name string   `yaml:"name"`
	Max  *float64 `yaml:"max"`
	Min  *float64 `yaml:"min"`
	// Phase limits the measurement to one phase.
	Phase string `yaml:"phase"`
	// Baseline is the phase compared against, for os_ops_per_random_cookie.
	Baseline string `yaml:"baseline"`
	// MinByServers is the minimum by the number of servers in the run,
	// for ingest_scaling: {2: 1.7, 3: 2.4}.
	MinByServers map[int]float64 `yaml:"min_by_servers"`
}

// criteria are the criterion names a scenario may use, and what each
// measures.
var criteria = map[string]string{
	"events_lost":                    "events the agents had stored (2xx) that are not in OpenSearch",
	"events_duplicated":              "events stored more than once",
	"events_undelivered":             "events still unsent when the run ended",
	"events_dropped":                 "events the agents dropped because their buffers were full (buffer_mb)",
	"ingest_error_rate":              "share of agent requests answered other than 2xx",
	"ingest_p99_ms":                  "99th percentile agent request time",
	"syslog_send_errors":             "syslog messages that could not be written",
	"page_p95_ms":                    "95th percentile page request time for users",
	"search_p95_ms":                  "95th percentile search time for users",
	"write_p95_ms":                   "95th percentile triage write time for users",
	"unexpected_signouts":            "users sent back to sign in mid-session",
	"write_conflicts":                "triage writes refused as busy (409)",
	"takeover_seconds":               "time until another server ran the jobs after a fault",
	"leaders_at_once":                "most servers that ran the jobs at the same moment",
	"os_ops_per_server_per_second":   "OpenSearch operations per second, per server",
	"os_ops_per_random_cookie":       "OpenSearch operations caused by each made-up session cookie",
	"brute_checked_per_account":      "most wrong passwords one account had checked (not refused early)",
	"brute_lockouts":                 "sign-ins refused by the limits (429)",
	"settings_converge_seconds":      "longest time until every server used a changed setting",
	"generator_lag_ms":               "how far the load generator fell behind its own schedule",
	"ingest_events_per_second":       "events the servers said they stored, per second",
	"ingest_scaling":                 "events per second stored, divided by the baseline run's (-baseline)",
	"ingest_share_min":               "smallest share of stored events one target took, times the number of targets (1 is even)",
	"servers_ready":                  "servers ready at the end of the run",
	"windows_servers_ready":          "Windows servers ready at the end of the run",
	"windows_led_seconds":            "seconds a Windows server ran the jobs",
	"opensearch_red_samples":         "samples in which the servers' OpenSearch indices were red",
	"opensearch_unreachable_samples": "samples in which no OpenSearch node answered",
	"server_cpu_cores":               "CPU cores the busiest server used, on average over the phase",
	"server_memory_mb":               "largest resident memory of any server",
	"check_failures":                 "checks (commands run after the load) that failed",
	"servers_not_upgraded":           "servers an upgrade fault did not bring to the new version",
	"upgrade_server_seconds":         "longest time one server took to upgrade, from drain to resumed",
	"jobs_moves":                     "times the background jobs moved to another server",
	"page_reloads_per_user":          "most times one user's open page reloaded because a server of another version answered",
}

// clusterOnly are criteria that need several servers; against one server
// they are skipped, never failed.
var clusterOnly = map[string]bool{"takeover_seconds": true, "leaders_at_once": true, "windows_led_seconds": true, "jobs_moves": true}

var faultKinds = []string{"kill9", "stop", "cut_opensearch", "clock", "fill_disk", "cmd", "upgrade"}

// signalFaults need Unix signals, so they are skipped on Windows.
var signalFaults = map[string]bool{"kill9": true, "stop": true}

// loadScenario reads a scenario file. ${VAR} in it is replaced by the
// environment, so one file serves the lab and CI.
func loadScenario(path string) (*Scenario, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseScenario(raw)
}

func parseScenario(raw []byte) (*Scenario, error) {
	expanded := os.Expand(string(raw), func(k string) string {
		if k == "$" {
			return "$"
		}
		return os.Getenv(k)
	})
	dec := yaml.NewDecoder(bytes.NewReader([]byte(expanded)))
	dec.KnownFields(true)
	var s Scenario
	if err := dec.Decode(&s); err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *Scenario) validate() error {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if s.Name == "" {
		bad("name is required")
	}
	if len(s.Phases) == 0 {
		bad("a scenario needs at least one phase")
	}
	names := map[string]bool{}
	var total time.Duration
	for i, p := range s.Phases {
		where := fmt.Sprintf("phase %d", i+1)
		if p.Name != "" {
			where = "phase " + p.Name
		}
		if p.Name == "" {
			bad("%s: name is required", where)
		} else if names[p.Name] {
			bad("%s: name used twice", where)
		}
		names[p.Name] = true
		if p.For <= 0 {
			bad("%s: for is required", where)
		}
		total += p.For.D()
		if a := p.Agents; a != nil {
			if a.N < 0 || a.Rate < 0 || a.Batch < 0 || a.EventBytes < 0 {
				bad("%s: agents: values must not be negative", where)
			}
			if a.N > 0 && a.Rate <= 0 {
				bad("%s: agents: rate is required", where)
			}
		}
		if sl := p.Syslog; sl != nil {
			if !slices.Contains([]string{"udp", "tcp", "tls"}, sl.Proto) {
				bad("%s: syslog: proto must be udp, tcp or tls", where)
			}
			if sl.Format != "" && sl.Format != "5424" && sl.Format != "3164" {
				bad("%s: syslog: format must be 5424 or 3164", where)
			}
			if sl.Sources <= 0 || sl.Rate <= 0 {
				bad("%s: syslog: sources and rate are required", where)
			}
		}
		if u := p.Users; u != nil && u.N <= 0 {
			bad("%s: users: n is required", where)
		}
		if b := p.Brute; b != nil && (b.Accounts <= 0 || b.Rate <= 0) {
			bad("%s: brute: accounts and rate are required", where)
		}
		if c := p.Churn; c != nil {
			if c.Key == "" || c.Every <= 0 || len(c.Values) < 2 {
				bad("%s: churn: key, every and at least two values are required", where)
			}
		}
		if c := p.CookieFlood; c != nil && c.Rate <= 0 {
			bad("%s: cookie_flood: rate is required", where)
		}
	}
	for i, f := range s.Faults {
		where := fmt.Sprintf("fault %d", i+1)
		if !slices.Contains(faultKinds, f.Kind) {
			bad("%s: kind must be one of %s", where, strings.Join(faultKinds, ", "))
		}
		if f.Cmd == "" && !(f.Kind == "cut_opensearch" && s.Toxiproxy.URL != "") {
			bad("%s: cmd is required (cut_opensearch can use toxiproxy instead)", where)
		}
		if f.Target == "" && (f.Kind == "kill9" || f.Kind == "stop") {
			bad("%s: target is required", where)
		}
		if f.Kind == "upgrade" && (f.Target != "" || f.For > 0 || f.Undo != "" || f.WindowsUndo != "") {
			bad("%s: an upgrade takes every server in turn, so it has no target, for or undo", where)
		}
		if f.Version != "" && f.Kind != "upgrade" {
			bad("%s: version is for an upgrade", where)
		}
		if f.At.D() >= total && total > 0 {
			bad("%s: at %s is after the last phase ends (%s)", where, f.At.D(), total)
		}
	}
	for i, c := range s.Criteria {
		where := fmt.Sprintf("criterion %d", i+1)
		if _, ok := criteria[c.Name]; !ok {
			bad("%s: unknown name %q", where, c.Name)
		}
		if c.Phase != "" && !names[c.Phase] {
			bad("%s: no phase %q", where, c.Phase)
		}
		if c.Baseline != "" && !names[c.Baseline] {
			bad("%s: no phase %q", where, c.Baseline)
		}
		if c.Name == "os_ops_per_random_cookie" && (c.Phase == "" || c.Baseline == "") {
			bad("%s: os_ops_per_random_cookie needs phase and baseline", where)
		}
		if len(c.MinByServers) > 0 && c.Name != "ingest_scaling" {
			bad("%s: min_by_servers is only for ingest_scaling", where)
		}
		for n := range c.MinByServers {
			if n < 1 {
				bad("%s: min_by_servers: %d is not a number of servers", where, n)
			}
		}
	}
	for i, ch := range s.Checks {
		if ch.Name == "" || ch.Cmd == "" {
			bad("check %d: name and cmd are required", i+1)
		}
	}
	for i, st := range s.Seed {
		if st.Path == "" || !strings.HasPrefix(st.Path, "/api/") {
			bad("seed %d: path must start with /api/", i+1)
		}
		if st.Method == "" {
			bad("seed %d: method is required", i+1)
		}
	}
	return errors.Join(errs...)
}

// duration is the time from the first phase's start to the last one's
// end.
func (s *Scenario) duration() time.Duration {
	var d time.Duration
	for _, p := range s.Phases {
		d += p.For.D()
	}
	return d
}

// caFiles lists every CA file the scenario names.
func (s *Scenario) caFiles() []string {
	out := slices.Clone(s.CAFiles)
	if s.CAFile != "" {
		out = append(out, s.CAFile)
	}
	return out
}
