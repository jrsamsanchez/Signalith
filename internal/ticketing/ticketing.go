// Package ticketing keeps Signalith cases in step with tickets in Jira
// (Cloud or Data Center) and ServiceNow.
//
// Admins set up connections on Settings > Ticketing. They are kept in a
// YAML file in the lookups folder (ticketing.file), with every API token,
// password and client secret encrypted with the master key (package
// secrets), and never sent back to the page.
//
// An analyst opens a ticket from a case, or a connection opens one by
// itself for new cases at or above a severity. From then on the server
// that runs the background jobs keeps the two in step every minute (see
// Service.Pass): the case's status, severity, title and notes go to the
// ticket, and the ticket's comments and status come back to the case.
// It polls the systems' APIs rather than waiting for their webhooks, so it
// works when Signalith cannot be reached from Jira Cloud or ServiceNow,
// and opens no way in.
//
// What a ticket gets is kept to what the people working it need: the
// case's title, severity, status, description, notes and a link back to
// the case; never events or the rows a detection found.
package ticketing

import (
	"crypto/rand"
	"encoding/hex"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

// Connection types.
const (
	TypeJira       = "jira"
	TypeServiceNow = "servicenow"
)

// Types lists the connection types, in the order the page offers them.
var Types = []string{TypeJira, TypeServiceNow}

// TypeLabel names a connection type for people: Jira or ServiceNow.
func TypeLabel(t string) string {
	switch t {
	case TypeJira:
		return "Jira"
	case TypeServiceNow:
		return "ServiceNow"
	}
	return t
}

// How a connection signs in.
const (
	// AuthCloud is Jira Cloud: an Atlassian account's email address and
	// an API token, sent as HTTP Basic auth.
	AuthCloud = "cloud"
	// AuthBearer is Jira Data Center or Server: a personal access token.
	AuthBearer = "bearer"
	// AuthBasic is ServiceNow: a user name and password.
	AuthBasic = "basic"
	// AuthOAuth is ServiceNow: an OAuth application's client ID and
	// secret (the client credentials grant).
	AuthOAuth = "oauth"
)

// Defaults of a new connection.
const (
	DefaultIssueType    = "Task"
	DefaultTable        = "incident"
	DefaultCommentField = "work_notes"
	DefaultCloseCode    = "Solution provided"
	DefaultAutoSeverity = "high"
)

// Case statuses, in workflow order (the statuses of package findings).
var CaseStatuses = findings.Statuses

// Severities, lowest first.
var Severities = findings.Severities

// DefaultPriorities are the Jira priorities each case severity sets:
// those of a new Jira site.
var DefaultPriorities = map[string]string{
	"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "informational": "Lowest",
}

// DefaultStates are the ServiceNow incident states each case status
// sets: 1 New, 2 In Progress, 3 On Hold, 6 Resolved and 7 Closed.
var DefaultStates = map[string]string{
	findings.StatusNew: "1", findings.StatusInProgress: "2", findings.StatusPending: "3",
	findings.StatusResolved: "6", findings.StatusClosed: "7",
}

// stateLabels names ServiceNow's incident states.
var stateLabels = map[string]string{"1": "New", "2": "In Progress", "3": "On Hold", "6": "Resolved", "7": "Closed", "8": "Canceled"}

// canceledState is ServiceNow's Canceled, which no case status sets but
// which closes the case when someone cancels the incident.
const canceledState = "8"

// Connection is one Jira project or ServiceNow table that cases open
// tickets in. The secrets (Token, Password and ClientSecret) are kept
// encrypted in the file and never sent to the page.
type Connection struct {
	// ID never changes, so links and tickets keep pointing at the
	// connection when it is renamed.
	ID   string `yaml:"id" json:"id"`
	Name string `yaml:"name" json:"name"`
	Type string `yaml:"type" json:"type"`
	// URL is the site: https://example.atlassian.net, the Data Center
	// address (with its context path, if any), or
	// https://example.service-now.com.
	URL  string `yaml:"url" json:"url"`
	Auth string `yaml:"auth" json:"auth"`

	// Email and Token sign in to Jira Cloud; Token alone is a Data Center
	// personal access token.
	Email string `yaml:"email,omitempty" json:"email,omitempty"`
	Token string `yaml:"token,omitempty" json:"-"`
	// Username and Password sign in to ServiceNow with basic auth.
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"-"`
	// ClientID and ClientSecret sign in to ServiceNow with OAuth.
	ClientID     string `yaml:"client_id,omitempty" json:"client_id,omitempty"`
	ClientSecret string `yaml:"client_secret,omitempty" json:"-"`

	// Jira: the project tickets go in, their issue type, and whether a
	// case's severity sets the issue's priority (Priorities maps one to
	// the other).
	Project     string            `yaml:"project,omitempty" json:"project,omitempty"`
	IssueType   string            `yaml:"issue_type,omitempty" json:"issue_type,omitempty"`
	SetPriority bool              `yaml:"set_priority,omitempty" json:"set_priority"`
	Priorities  map[string]string `yaml:"priorities,omitempty" json:"priorities,omitempty"`

	// ServiceNow: the table tickets go in, the journal field case notes
	// go to (work_notes, seen only by the people who work the ticket, or
	// comments, which the caller sees too), the close code a resolved
	// case sets, and an optional caller and assignment group for new
	// tickets.
	Table           string `yaml:"table,omitempty" json:"table,omitempty"`
	CommentField    string `yaml:"comment_field,omitempty" json:"comment_field,omitempty"`
	CloseCode       string `yaml:"close_code,omitempty" json:"close_code,omitempty"`
	CallerID        string `yaml:"caller_id,omitempty" json:"caller_id,omitempty"`
	AssignmentGroup string `yaml:"assignment_group,omitempty" json:"assignment_group,omitempty"`

	// Statuses maps each case status to the ticket's: for Jira, status
	// names separated by commas (empty goes by the status category); for
	// ServiceNow, a state number.
	Statuses map[string]string `yaml:"statuses,omitempty" json:"statuses"`
	// SyncNotes sends new case notes to the ticket as comments, and the
	// ticket's new comments to the case as notes.
	SyncNotes bool `yaml:"sync_notes" json:"sync_notes"`
	// SyncStatus moves the ticket when the case's status changes, and the
	// case when the ticket's does.
	SyncStatus bool `yaml:"sync_status" json:"sync_status"`

	// AutoCreate opens a ticket by itself for each case opened since
	// AutoSince (when it was turned on) at AutoMinSeverity or above.
	AutoCreate      bool      `yaml:"auto_create,omitempty" json:"auto_create"`
	AutoMinSeverity string    `yaml:"auto_min_severity,omitempty" json:"auto_min_severity,omitempty"`
	AutoSince       time.Time `yaml:"auto_since,omitempty" json:"auto_since,omitzero"`

	// AllowLoopback lets the connection reach this server's own
	// addresses, over HTTP too, for a test instance on this machine. Off
	// by default.
	AllowLoopback bool `yaml:"allow_loopback,omitempty" json:"allow_loopback,omitempty"`
	// CAPEM holds extra certificate authorities, in PEM, that the
	// system's certificate may come from. The system's trusted ones
	// always count too.
	CAPEM string `yaml:"ca_pem,omitempty" json:"ca_pem,omitempty"`
}

// Settings are the connections.
type Settings struct {
	Connections []Connection `yaml:"connections" json:"connections"`
}

// Connection returns the connection with an ID.
func (s Settings) Connection(id string) (Connection, bool) {
	for _, c := range s.Connections {
		if c.ID == id {
			return c, true
		}
	}
	return Connection{}, false
}

// clone returns a deep copy, so a caller may change it.
func (s Settings) clone() Settings {
	out := Settings{Connections: make([]Connection, len(s.Connections))}
	for i, c := range s.Connections {
		out.Connections[i] = c.clone()
	}
	return out
}

func (c Connection) clone() Connection {
	c.Priorities = maps.Clone(c.Priorities)
	c.Statuses = maps.Clone(c.Statuses)
	return c
}

// Label names a connection with its system, as in "Jira SOC", unless its
// name already says it.
func (c Connection) Label() string {
	t := TypeLabel(c.Type)
	if strings.Contains(strings.ToLower(c.Name), strings.ToLower(t)) {
		return c.Name
	}
	return t + " " + c.Name
}

// cloud reports whether a Jira connection is Jira Cloud, which has API
// version 3 and Atlassian Document Format bodies; Data Center has
// version 2 and plain text.
func (c Connection) cloud() bool { return c.Auth != AuthBearer }

// RemoteStatus is a ticket's status as its system reports it.
type RemoteStatus struct {
	// Name is Jira's status name or ServiceNow's state number.
	Name string `json:"name"`
	// Category is Jira's status category: new, indeterminate or done.
	Category string `json:"category,omitempty"`
}

// Label names the status for people.
func (r RemoteStatus) Label(system string) string {
	if system == TypeServiceNow {
		if l, ok := stateLabels[r.Name]; ok {
			return l
		}
		if r.Name != "" {
			return "State " + r.Name
		}
	}
	return r.Name
}

// jiraCategory is the Jira status category a case status goes to when
// no status names are mapped for it.
func jiraCategory(caseStatus string) string {
	switch caseStatus {
	case findings.StatusNew:
		return "new"
	case findings.StatusResolved, findings.StatusClosed:
		return "done"
	}
	return "indeterminate"
}

// jiraNames returns the Jira status names mapped for a case status, in
// order of preference.
func (c Connection) jiraNames(caseStatus string) []string {
	var out []string
	for _, n := range strings.Split(c.Statuses[caseStatus], ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// state returns the ServiceNow state a case status sets.
func (c Connection) state(caseStatus string) string {
	if v := strings.TrimSpace(c.Statuses[caseStatus]); v != "" {
		return v
	}
	return DefaultStates[caseStatus]
}

// agrees reports whether a ticket's status already says what the case's
// does, so neither needs to move: a resolved case and a ticket in Done,
// or a closed case and a ticket that was resolved and then closed.
func (c Connection) agrees(caseStatus string, r RemoteStatus) bool {
	if r.Name == "" {
		return false
	}
	if c.Type == TypeServiceNow {
		if r.Name == canceledState && caseStatus == findings.StatusClosed {
			return true
		}
		return r.Name == c.state(caseStatus)
	}
	if names := c.jiraNames(caseStatus); len(names) > 0 {
		return slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, r.Name) })
	}
	return r.Category == jiraCategory(caseStatus)
}

// caseStatusFor returns the case status a ticket's status stands for, or
// "" when it stands for none.
func (c Connection) caseStatusFor(r RemoteStatus) string {
	if r.Name == "" {
		return ""
	}
	for _, s := range CaseStatuses {
		if c.Type == TypeServiceNow {
			if c.state(s) == r.Name {
				return s
			}
			continue
		}
		if slices.ContainsFunc(c.jiraNames(s), func(n string) bool { return strings.EqualFold(n, r.Name) }) {
			return s
		}
	}
	if c.Type == TypeServiceNow {
		if r.Name == canceledState {
			return findings.StatusClosed
		}
		return ""
	}
	switch r.Category {
	case "new":
		return findings.StatusNew
	case "indeterminate":
		return findings.StatusInProgress
	case "done":
		return findings.StatusResolved
	}
	return ""
}

// priority returns the Jira priority a case severity sets.
func (c Connection) priority(severity string) string {
	if p := strings.TrimSpace(c.Priorities[severity]); p != "" {
		return p
	}
	return DefaultPriorities[severity]
}

// impactUrgency returns the ServiceNow impact and urgency a case severity
// sets, which make its priority: critical 1 and 1 (priority 1), high 1
// and 2, medium 2 and 2, low 2 and 3, informational 3 and 3 (priority 5).
func impactUrgency(severity string) (string, string) {
	switch severity {
	case "critical":
		return "1", "1"
	case "high":
		return "1", "2"
	case "medium":
		return "2", "2"
	case "low":
		return "2", "3"
	}
	return "3", "3"
}

// AtLeast reports whether severity s is at least min.
func AtLeast(s, min string) bool { return slices.Index(Severities, s) >= slices.Index(Severities, min) }

// newID returns a short random ID for a connection.
func newID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
