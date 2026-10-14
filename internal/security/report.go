// Package security checks how a Signalith server is set up and says what
// to fix first. Every check is a pure function over Facts, so the server
// (GET /api/security, the Security page) and the CLI (signalith security)
// give the same answer for the same facts. Facts are gathered with time
// limits (see Gather), and a check whose facts did not arrive in time says
// so rather than guessing.
//
// A report names settings and files, never the values of passwords or
// keys. The only exceptions are the two public example values
// (change-me-please and change-this-ingest-token), which anyone can
// already look up.
package security

import (
	"sort"
	"strings"
	"time"
)

// State is how a check came out.
type State string

const (
	// Risk: right now someone on the network, or another account on this
	// computer, could read or change Signalith's data, or sign in,
	// without anything special.
	Risk State = "risk"
	// Attention: weaker than it should be, or a step left half done.
	// Nobody gets in because of it today.
	Attention State = "attention"
	// Unknown: Signalith can't see this from where it runs. Never counted
	// as a problem.
	Unknown State = "unknown"
	// Good: set up safely.
	Good State = "good"
)

// order sorts states worst first.
func (s State) order() int {
	switch s {
	case Risk:
		return 0
	case Attention:
		return 1
	case Unknown:
		return 2
	}
	return 3
}

// Word is the state as the page and the text report say it.
func (s State) Word() string {
	switch s {
	case Risk:
		return "At risk"
	case Attention:
		return "Needs attention"
	case Unknown:
		return "Can't tell"
	}
	return "Good"
}

// PageLink points to another page of Signalith.
type PageLink struct {
	ID    string `json:"id"`
	Tab   string `json:"tab,omitempty"`
	Label string `json:"label"`
}

// DocLink points to a section of the docs.
type DocLink struct {
	File   string `json:"file"`
	Anchor string `json:"anchor"`
	URL    string `json:"url"`
	// Label is the link's text when "How it works" would not fit, such
	// as for steps.
	Label string `json:"label,omitempty"`
}

// Fix says how to fix a problem ("How to fix"), how to check by hand
// what Signalith cannot see ("How to check"), or how to make something
// good stronger (a tip).
type Fix struct {
	Label string   `json:"label"`
	Steps []string `json:"steps"`
	// Setting is opened on the Settings page; LockedBy names the
	// environment variable that sets it, when one does, so the page shows
	// that instead of a button.
	Setting  string    `json:"setting"`
	LockedBy string    `json:"locked_by"`
	Page     *PageLink `json:"page"`
	// Action is an action on the Security page itself, such as
	// "ca.prepare".
	Action string   `json:"action"`
	Docs   *DocLink `json:"docs"`
	// Commands are per deployment: linux, windows and docker.
	Commands map[string]string `json:"commands"`
}

// Check is one row of the report.
type Check struct {
	ID      string   `json:"id"`
	Group   string   `json:"group"`
	Title   string   `json:"title"`
	State   State    `json:"state"`
	Rank    int      `json:"rank"`
	Line    string   `json:"line"`
	Details []string `json:"details"`
	Fix     *Fix     `json:"fix"`
	Tip     *Fix     `json:"tip"`
}

// Group is a set of checks on the page.
type Group struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// Groups in page order.
var Groups = []Group{
	{"transit", "In transit", "Whether data is encrypted as it crosses the network."},
	{"rest", "At rest", "Whether stored passwords, keys and events are protected on disk."},
	{"use", "In use", "Whether secrets stay private while Signalith runs."},
	{"accounts", "Accounts and sign-in", "Who can sign in, and how well passwords and tokens are kept."},
	{"host", "This server", "How Signalith runs on this computer."},
}

// Summary counts the checks by state.
type Summary struct {
	Risk      int `json:"risk"`
	Attention int `json:"attention"`
	Unknown   int `json:"unknown"`
	Good      int `json:"good"`
}

// ServerInfo says which server a report is about.
type ServerInfo struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Go              string `json:"go"`
	OS              string `json:"os"`
	Deployment      string `json:"deployment"`
	DeploymentLabel string `json:"deployment_label"`
}

// OtherServer is another server that shares this one's OpenSearch, with
// the summary its heartbeat carries.
type OtherServer struct {
	Name      string     `json:"name"`
	URL       string     `json:"url"`
	Risk      int        `json:"risk"`
	Attention int        `json:"attention"`
	CheckedAt *time.Time `json:"checked_at"`
	CAScope   string     `json:"ca_scope"`
	// NotChecked is set for a server too old to check itself.
	NotChecked bool `json:"not_checked,omitempty"`
}

// Report is the whole answer.
type Report struct {
	CheckedAt  time.Time     `json:"checked_at"`
	Server     ServerInfo    `json:"server"`
	Summary    Summary       `json:"summary"`
	FixFirst   []string      `json:"fix_first"`
	Groups     []Group       `json:"groups"`
	Checks     []Check       `json:"checks"`
	AlwaysOn   []string      `json:"always_on"`
	NotChecked []string      `json:"not_checked"`
	Others     []OtherServer `json:"others,omitempty"`
	CA         *CAReport     `json:"ca,omitempty"`
}

// AtRisk lists the ids of the checks at risk.
func (r *Report) AtRisk() []string {
	var out []string
	for _, c := range r.Checks {
		if c.State == Risk {
			out = append(out, c.ID)
		}
	}
	return out
}

// Find returns the check with id, or nil.
func (r *Report) Find(id string) *Check {
	for i := range r.Checks {
		if r.Checks[i].ID == id {
			return &r.Checks[i]
		}
	}
	return nil
}

// checkFunc is one check: nil means it does not apply here, and is left
// out.
type checkFunc func(f *Facts) *Check

// def is a check in the table.
type def struct {
	id, group, title string
	rank             int
	fn               checkFunc
}

// checks lists every check, in no particular order; rank decides the
// order within a state.
var checks = []def{
	{"transit.https", "transit", "HTTPS", 3, checkHTTPS},
	{"transit.certificate", "transit", "HTTPS certificate", 12, checkCertificate},
	{"transit.ca_scope", "transit", "Certificate authority", 13, checkCAScope},
	{"transit.agents_plain", "transit", "Agents on plain HTTP", 11, checkAgentsPlain},
	{"transit.syslog", "transit", "Syslog", 16, checkSyslog},
	{"transit.opensearch", "transit", "Connection to OpenSearch", 1, checkOpenSearchTransit},
	{"transit.outbound", "transit", "AI assistant and threat intel", 7, checkOutbound},
	{"transit.proxies", "transit", "Trusted reverse proxies", 24, checkProxies},
	{"rest.master_key", "rest", "Master key", 8, checkMasterKey},
	{"rest.stored_secrets", "rest", "Stored passwords and keys", 10, checkStoredSecrets},
	{"rest.disk", "rest", "Disk encryption", 17, checkDisk},
	{"rest.archives", "rest", "Archived days", 19, checkArchives},
	{"rest.opensearch_disk", "rest", "Where OpenSearch keeps events", 18, checkOpenSearchDisk},
	{"rest.opensearch_access", "rest", "Who can read OpenSearch", 2, checkOpenSearchAccess},
	{"use.memory", "use", "Memory", 25, checkMemory},
	{"use.confidential_vm", "use", "Confidential virtual machine", 26, checkConfidentialVM},
	{"accounts.builtin_password", "accounts", "Built-in admin's password", 4, checkBuiltinPassword},
	{"accounts.builtin_use", "accounts", "Everyday sign-in", 21, checkBuiltinUse},
	{"accounts.temp_passwords", "accounts", "Temporary passwords", 22, checkTempPasswords},
	{"accounts.directory", "accounts", "Directory sign-in", 5, checkDirectory},
	{"accounts.sessions", "accounts", "Sign-in sessions", 23, checkSessions},
	{"accounts.agent_tokens", "accounts", "Agent tokens", 6, checkAgentTokens},
	{"accounts.opensearch_role", "accounts", "Signalith's OpenSearch account", 14, checkOpenSearchRole},
	{"host.account", "host", "Account Signalith runs as", 15, checkAccount},
	{"host.service", "host", "Service protections", 20, checkService},
	{"host.files", "host", "File permissions", 9, checkFiles},
}

// CheckIDs lists every check's id.
func CheckIDs() []string {
	out := make([]string, len(checks))
	for i, d := range checks {
		out[i] = d.id
	}
	return out
}

// Titles maps each check's id to its title.
func Titles() map[string]string {
	out := map[string]string{}
	for _, d := range checks {
		out[d.id] = d.title
	}
	return out
}

// TimedOutLine is the line of a check whose facts did not arrive in time.
const TimedOutLine = "Signalith couldn't finish this check in time."

// Evaluate runs every check over f and builds the report.
func Evaluate(f *Facts) *Report {
	r := &Report{CheckedAt: f.Now.UTC(), Server: f.Server, Groups: Groups, Checks: []Check{}, FixFirst: []string{}}
	for _, d := range checks {
		var c *Check
		if f.timedOut(d.id) {
			c = &Check{State: Unknown, Line: TimedOutLine,
				Fix: &Fix{Steps: []string{"Re-check in a minute. If it keeps happening, the server log may say what is slow."}}}
		} else if f.Denied[d.id] {
			c = &Check{State: Unknown, Line: DeniedLine(f.Server.OS)}
		} else {
			c = d.fn(f)
		}
		if c == nil {
			continue
		}
		c.ID, c.Group, c.Title, c.Rank = d.id, d.group, d.title, d.rank
		finish(c, f)
		r.Checks = append(r.Checks, *c)
	}
	sort.SliceStable(r.Checks, func(i, j int) bool {
		a, b := r.Checks[i], r.Checks[j]
		if ga, gb := groupIndex(a.Group), groupIndex(b.Group); ga != gb {
			return ga < gb
		}
		if a.State.order() != b.State.order() {
			return a.State.order() < b.State.order()
		}
		return a.Rank < b.Rank
	})
	for _, c := range r.Checks {
		switch c.State {
		case Risk:
			r.Summary.Risk++
		case Attention:
			r.Summary.Attention++
		case Unknown:
			r.Summary.Unknown++
		default:
			r.Summary.Good++
		}
	}
	r.FixFirst = FixFirst(r.Checks)
	r.AlwaysOn = alwaysOn(f)
	r.NotChecked = notChecked()
	r.CA = caReport(f)
	return r
}

// FixFirst orders the checks at risk, then those that need attention, by
// rank. Can't tell and good are never in it.
func FixFirst(list []Check) []string {
	var probs []Check
	for _, c := range list {
		if c.State == Risk || c.State == Attention {
			probs = append(probs, c)
		}
	}
	sort.SliceStable(probs, func(i, j int) bool {
		if probs[i].State.order() != probs[j].State.order() {
			return probs[i].State.order() < probs[j].State.order()
		}
		return probs[i].Rank < probs[j].Rank
	})
	out := []string{}
	for _, c := range probs {
		out = append(out, c.ID)
	}
	return out
}

func groupIndex(id string) int {
	for i, g := range Groups {
		if g.ID == id {
			return i
		}
	}
	return len(Groups)
}

// finish fills in what every check's fix and tip have in common: the
// label, the docs URL, an empty list instead of nil, and the
// environment variable that sets the setting.
func finish(c *Check, f *Facts) {
	if c.Details == nil {
		c.Details = []string{}
	}
	label := "How to fix"
	if c.State == Unknown {
		label = "How to check"
	}
	if c.State == Good {
		c.Fix = nil
	}
	if c.Fix != nil {
		if c.Fix.Label == "" {
			c.Fix.Label = label
		}
		tidyFix(c.Fix, f)
	}
	if c.Tip != nil {
		if c.Tip.Label == "" {
			c.Tip.Label = "Make it stronger"
		}
		tidyFix(c.Tip, f)
	}
}

func tidyFix(x *Fix, f *Facts) {
	if x.Steps == nil {
		x.Steps = []string{}
	}
	if x.Commands == nil {
		x.Commands = map[string]string{}
	}
	if x.Docs != nil && x.Docs.URL == "" {
		x.Docs.URL = DocsURL(f.Server.Version, x.Docs.File, x.Docs.Anchor)
	}
	if x.Setting != "" && f.SettingEnv != nil {
		x.LockedBy = f.SettingEnv[x.Setting]
	}
}

// alwaysOn lists the protections that are always on, as they apply here.
func alwaysOn(f *Facts) []string {
	https := f.HTTPSOn()
	var out []string
	if https {
		out = append(out, "Passwords, API sign-ins and sessions are refused over plain HTTP, and the sign-in cookie is sent over HTTPS only.",
			"Browsers that reach Signalith by name are told to use HTTPS only (HSTS).")
	}
	out = append(out,
		"Every page has a strict Content Security Policy and can't be shown inside another site.",
		"Guessing passwords is slowed: after 10 wrong tries for one account from one address in 15 minutes, sign-in pauses for 15 minutes. The API is limited the same way.",
		"Sign-ins end after 7 days at most, even with Keep me signed in.",
		"Passwords are stored only as bcrypt hashes.",
		"Logs, pages and the API never show stored passwords or keys.")
	if https {
		out = append(out, "Agents set up from Add data check the server's certificate before sending.")
	}
	return append(out, "Sign-ins, sign-outs and every change to users and settings go to the audit log.")
}

func notChecked() []string {
	return []string{
		"Firewalls: which computers can reach Signalith's ports.",
		"Backups, and whether the master key is kept apart from them.",
		"Updates for Signalith, OpenSearch and the operating system. Signalith doesn't contact the internet to check.",
		"Two-step sign-in. Signalith has none of its own.",
		"The computers agents run on.",
		"Copies of events outside Signalith, such as exports, moved archives and OpenSearch snapshots.",
	}
}

// Typographic returns a copy of r whose words use the typographic
// apostrophe, as the pages do. Commands, settings, paths in commands and
// links keep theirs.
func (r *Report) Typographic() *Report {
	out := *r
	q := func(s string) string { return strings.ReplaceAll(s, "'", "’") }
	qs := func(l []string) []string {
		o := make([]string, len(l))
		for i, s := range l {
			o[i] = q(s)
		}
		return o
	}
	qf := func(x *Fix) *Fix {
		if x == nil {
			return nil
		}
		y := *x
		y.Label, y.Steps = q(x.Label), qs(x.Steps)
		if x.Page != nil {
			p := *x.Page
			p.Label = q(p.Label)
			y.Page = &p
		}
		return &y
	}
	out.Checks = make([]Check, len(r.Checks))
	for i, c := range r.Checks {
		c.Title, c.Line, c.Details = q(c.Title), q(c.Line), qs(c.Details)
		c.Fix, c.Tip = qf(c.Fix), qf(c.Tip)
		out.Checks[i] = c
	}
	out.Groups = make([]Group, len(r.Groups))
	for i, g := range r.Groups {
		g.Title, g.Description = q(g.Title), q(g.Description)
		out.Groups[i] = g
	}
	out.AlwaysOn, out.NotChecked = qs(r.AlwaysOn), qs(r.NotChecked)
	return &out
}
