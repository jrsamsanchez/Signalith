package ticketing

import (
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// Limits on what the page can save.
const (
	MaxConnections = 20
	maxName        = 80
	maxCAPEM       = 64 << 10
	maxSecret      = 4 << 10
	maxField       = 200
)

// Input is the whole of the connections as the Ticketing page sends
// them. Secrets are write-only: they are never sent back, and an empty
// value keeps the stored one.
type Input struct {
	// Revision is the Revision the page started from; a save over newer
	// settings is refused with ErrChanged. Empty skips the check.
	Revision    string            `json:"revision"`
	Connections []ConnectionInput `json:"connections"`
}

// ConnectionInput is a connection as the page sends it. A connection with
// an ID that is not saved yet is new; one without an ID gets one.
type ConnectionInput struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	URL  string `json:"url"`
	Auth string `json:"auth"`

	Email string `json:"email"`
	// Token, Password and ClientSecret set a secret; empty keeps the
	// stored one.
	Token        string `json:"token"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`

	Project   string `json:"project"`
	IssueType string `json:"issue_type"`
	// SetPriority defaults to true.
	SetPriority *bool             `json:"set_priority"`
	Priorities  map[string]string `json:"priorities"`

	Table           string `json:"table"`
	CommentField    string `json:"comment_field"`
	CloseCode       string `json:"close_code"`
	CallerID        string `json:"caller_id"`
	AssignmentGroup string `json:"assignment_group"`

	Statuses map[string]string `json:"statuses"`
	// SyncNotes and SyncStatus default to true.
	SyncNotes  *bool `json:"sync_notes"`
	SyncStatus *bool `json:"sync_status"`

	AutoCreate      bool   `json:"auto_create"`
	AutoMinSeverity string `json:"auto_min_severity"`

	AllowLoopback bool   `json:"allow_loopback"`
	CAPEM         string `json:"ca_pem"`
}

// Problem is one setting to fix. Where is "connection:<id>" (with the ID
// the page sent, or the place in the list for one sent without an ID, as
// in "connection:#2"); Field is the setting, such as url, for the form to
// mark.
type Problem struct {
	Where string `json:"where"`
	Field string `json:"field,omitempty"`
	Msg   string `json:"message"`
}

// InputError lists the settings to fix.
type InputError struct{ Problems []Problem }

func (e *InputError) Error() string {
	msgs := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		msgs[i] = p.Msg
	}
	return "Please fix these settings: " + strings.Join(msgs, "; ")
}

// looksEncrypted is the problem with a typed value that starts like an
// encrypted one: it would be stored as it is, not encrypted.
const looksEncrypted = "cannot start with enc:v and a number and a colon, which is how encrypted values look"

var (
	idForm      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)
	projectForm = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,49}$`)
	tableForm   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,79}$`)
	stateForm   = regexp.MustCompile(`^-?[0-9]{1,4}$`)
)

// Save checks in, merges its secrets with the stored ones, and writes it
// as the new settings. It returns *InputError for settings to fix,
// ErrChanged when the settings changed since in.Revision, and the file's
// error when it cannot be read.
func (m *Manager) Save(in Input) (Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	if m.fileErr != nil {
		return Settings{}, m.fileErr
	}
	if in.Revision != "" && in.Revision != m.rev {
		return Settings{}, ErrChanged
	}
	s, probs := merge(m.cur, in, m.now)
	if len(probs) > 0 {
		return Settings{}, &InputError{Problems: probs}
	}
	if err := m.save(s); err != nil {
		return Settings{}, err
	}
	return s.clone(), nil
}

// Check merges a single connection as a test would use it, without
// saving: the stored connection with the same ID gives the secrets left
// empty.
func (m *Manager) Check(in ConnectionInput) (Connection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	if m.fileErr != nil {
		return Connection{}, m.fileErr
	}
	var old *Connection
	if c, ok := m.cur.Connection(strings.TrimSpace(in.ID)); ok {
		old = &c
	}
	c, probs := in.connection(old, "connection:"+where(in.ID, 0), m.now)
	if c.ID == "" {
		c.ID = "test"
	}
	if len(probs) > 0 {
		return Connection{}, &InputError{Problems: probs}
	}
	return c, nil
}

func where(id string, i int) string {
	if id = strings.TrimSpace(id); id != "" {
		return id
	}
	return "#" + strconv.Itoa(i+1)
}

// merge builds the new settings from in and the current ones.
func merge(cur Settings, in Input, now func() time.Time) (Settings, []Problem) {
	if len(in.Connections) > MaxConnections {
		return Settings{}, []Problem{{Where: "connections", Msg: fmt.Sprintf("at most %d connections can be set up", MaxConnections)}}
	}
	var out Settings
	var probs []Problem
	ids, names := map[string]bool{}, map[string]bool{}
	for i, ci := range in.Connections {
		w := "connection:" + where(ci.ID, i)
		var old *Connection
		if c, ok := cur.Connection(strings.TrimSpace(ci.ID)); ok {
			old = &c
		}
		c, p := ci.connection(old, w, now)
		probs = append(probs, p...)
		if c.ID == "" {
			c.ID = newID()
		}
		if ids[c.ID] {
			probs = append(probs, Problem{Where: w, Field: "id", Msg: fmt.Sprintf("two connections have the ID %s", c.ID)})
		}
		ids[c.ID] = true
		if key := strings.ToLower(c.Name); c.Name != "" {
			if names[key] {
				probs = append(probs, Problem{Where: w, Field: "name", Msg: fmt.Sprintf("another connection is already named %s; choose another name", c.Name)})
			}
			names[key] = true
		}
		out.Connections = append(out.Connections, c)
	}
	return out, probs
}

// plainText reports the problem with a short setting, or "".
func plainText(v, what string, max int) string {
	switch {
	case len(v) > max:
		return fmt.Sprintf("the %s is too long (at most %d characters)", what, max)
	case strings.IndexFunc(v, unicode.IsControl) >= 0:
		return fmt.Sprintf("the %s cannot hold line breaks or control characters", what)
	}
	return ""
}

// connection turns input into a connection, merging secrets with old's.
func (in ConnectionInput) connection(old *Connection, w string, now func() time.Time) (Connection, []Problem) {
	var probs []Problem
	label := strings.TrimSpace(in.Name)
	if label == "" {
		label = "a connection"
	}
	add := func(field, msg string) {
		probs = append(probs, Problem{Where: w, Field: field, Msg: label + ": " + msg})
	}
	on := func(b *bool) bool { return b == nil || *b }
	c := Connection{
		ID: strings.TrimSpace(in.ID), Name: strings.TrimSpace(in.Name), Type: strings.ToLower(strings.TrimSpace(in.Type)),
		URL: strings.TrimRight(strings.TrimSpace(in.URL), "/"), Auth: strings.ToLower(strings.TrimSpace(in.Auth)),
		SyncNotes: on(in.SyncNotes), SyncStatus: on(in.SyncStatus), AutoCreate: in.AutoCreate,
		AutoMinSeverity: strings.ToLower(strings.TrimSpace(in.AutoMinSeverity)),
		AllowLoopback:   in.AllowLoopback, CAPEM: strings.TrimSpace(in.CAPEM),
	}
	if c.ID != "" && old == nil && !idForm.MatchString(c.ID) {
		add("id", "a new connection's ID may only hold lowercase letters, digits, - and _ (at most 40 characters)")
	}
	switch {
	case c.Name == "":
		add("name", "enter a name for the connection")
	case plainText(c.Name, "name", maxName) != "":
		add("name", plainText(c.Name, "name", maxName))
	}
	if !slices.Contains(Types, c.Type) {
		add("type", "pick the system: Jira or ServiceNow")
		return c, probs
	}
	if old != nil && old.Type != c.Type {
		// A connection's saved secrets belong to its system; a new one
		// starts without them.
		old = nil
	}
	if c.CAPEM != "" {
		if len(c.CAPEM) > maxCAPEM || !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CAPEM)) {
			add("ca_pem", "the certificate authority must be one or more PEM certificates (-----BEGIN CERTIFICATE-----)")
		}
	}
	if c.URL == "" {
		add("url", map[string]string{TypeJira: "enter the address of the Jira site, such as https://example.atlassian.net",
			TypeServiceNow: "enter the address of the ServiceNow instance, such as https://example.service-now.com"}[c.Type])
	} else if msg := CheckURL(c.URL, c.AllowLoopback); msg != "" {
		add("url", msg)
	}
	// Saved secrets are only sent to the server they were entered for:
	// when the address points elsewhere, or the way of signing in
	// changed, each must be entered again.
	keep := old != nil && sameServer(old.URL, c.URL) && old.Auth == c.Auth
	secret := func(field, typed, saved, what string) string {
		switch {
		case typed == "" && keep && saved != "":
			return saved
		case typed == "" && old != nil && saved != "" && !keep:
			add(field, "enter the "+what+" again: the address or the way of signing in changed, and a saved "+what+" is only sent to the server it was entered for")
		case typed == "":
			add(field, "enter the "+what)
		case secrets.IsSealed(typed):
			add(field, "the "+what+" "+looksEncrypted)
		case len(typed) > maxSecret:
			add(field, "the "+what+" is too long")
		case strings.ContainsAny(typed, "\r\n"):
			add(field, "the "+what+" cannot hold line breaks")
		default:
			return typed
		}
		return ""
	}
	saved := func(f func(*Connection) string) string {
		if old == nil {
			return ""
		}
		return f(old)
	}
	text := func(field, v, what string, max int) string {
		v = strings.TrimSpace(v)
		if msg := plainText(v, what, max); msg != "" {
			add(field, msg)
		}
		return v
	}
	switch c.Type {
	case TypeJira:
		if c.Auth == "" {
			c.Auth = AuthCloud
		}
		switch c.Auth {
		case AuthCloud:
			c.Email = text("email", in.Email, "email address", maxField)
			if c.Email == "" || !strings.Contains(c.Email, "@") {
				add("email", "enter the email address of the Atlassian account the API token belongs to")
			}
			c.Token = secret("token", in.Token, saved(func(o *Connection) string { return o.Token }), "API token")
		case AuthBearer:
			c.Token = secret("token", in.Token, saved(func(o *Connection) string { return o.Token }), "personal access token")
		default:
			add("auth", "pick how to sign in: Jira Cloud (email and API token) or Data Center (personal access token)")
		}
		c.Project = strings.ToUpper(strings.TrimSpace(in.Project))
		if !projectForm.MatchString(c.Project) {
			add("project", "enter the project's key, such as SEC: capital letters, digits and _, starting with a letter")
		}
		c.IssueType = text("issue_type", in.IssueType, "issue type", 60)
		if c.IssueType == "" {
			c.IssueType = DefaultIssueType
		}
		c.SetPriority = on(in.SetPriority)
		c.Priorities = map[string]string{}
		for _, sev := range Severities {
			v := text("priorities", in.Priorities[sev], "priority name", 60)
			if v == "" {
				v = DefaultPriorities[sev]
			}
			c.Priorities[sev] = v
		}
		c.Statuses = map[string]string{}
		for _, st := range CaseStatuses {
			var names []string
			for _, n := range strings.Split(in.Statuses[st], ",") {
				if n = strings.TrimSpace(n); n != "" {
					if msg := plainText(n, "status name", 60); msg != "" {
						add("statuses", msg)
					}
					names = append(names, n)
				}
			}
			if len(names) > 10 {
				add("statuses", "at most 10 Jira statuses for each case status")
			}
			if len(names) > 0 {
				c.Statuses[st] = strings.Join(names, ", ")
			}
		}
	case TypeServiceNow:
		if c.Auth == "" {
			c.Auth = AuthBasic
		}
		switch c.Auth {
		case AuthBasic:
			c.Username = text("username", in.Username, "user name", maxField)
			if c.Username == "" {
				add("username", "enter the user name of the ServiceNow account Signalith signs in as")
			}
			c.Password = secret("password", in.Password, saved(func(o *Connection) string { return o.Password }), "password")
		case AuthOAuth:
			c.ClientID = text("client_id", in.ClientID, "client ID", maxField)
			if c.ClientID == "" {
				add("client_id", "enter the client ID of the OAuth application")
			}
			c.ClientSecret = secret("client_secret", in.ClientSecret, saved(func(o *Connection) string { return o.ClientSecret }), "client secret")
		default:
			add("auth", "pick how to sign in: user name and password, or OAuth client credentials")
		}
		c.Table = strings.ToLower(strings.TrimSpace(in.Table))
		if c.Table == "" {
			c.Table = DefaultTable
		}
		if !tableForm.MatchString(c.Table) {
			add("table", "enter the table's name, such as incident: lowercase letters, digits and _")
		}
		c.CommentField = strings.TrimSpace(in.CommentField)
		if c.CommentField == "" {
			c.CommentField = DefaultCommentField
		}
		if c.CommentField != "work_notes" && c.CommentField != "comments" {
			add("comment_field", "pick where notes go: work notes or additional comments")
		}
		c.CloseCode = text("close_code", in.CloseCode, "close code", 80)
		if c.CloseCode == "" {
			c.CloseCode = DefaultCloseCode
		}
		c.CallerID = text("caller_id", in.CallerID, "caller", 100)
		c.AssignmentGroup = text("assignment_group", in.AssignmentGroup, "assignment group", 100)
		c.Statuses = map[string]string{}
		for _, st := range CaseStatuses {
			v := strings.TrimSpace(in.Statuses[st])
			if v == "" {
				v = DefaultStates[st]
			}
			if !stateForm.MatchString(v) {
				add("statuses", fmt.Sprintf("the state for %s must be a number, such as %s", strings.ReplaceAll(st, "_", " "), DefaultStates[st]))
			}
			c.Statuses[st] = v
		}
	}
	if c.AutoMinSeverity == "" {
		c.AutoMinSeverity = DefaultAutoSeverity
	}
	if !slices.Contains(Severities, c.AutoMinSeverity) {
		add("auto_min_severity", "pick the least severity: "+strings.Join(Severities, ", "))
	}
	// Only cases opened from when auto-create is turned on get a ticket by
	// themselves, so turning it on does not flood the system with old
	// cases.
	switch {
	case !c.AutoCreate:
		if old != nil {
			c.AutoSince = old.AutoSince
		}
	case old == nil || !old.AutoCreate:
		c.AutoSince = now().UTC()
	default:
		c.AutoSince = old.AutoSince
	}
	return c, probs
}

// CheckURL checks a connection's address: https (or http to this machine
// with allowLoopback), with a host, no user name, query or fragment, and
// not an address connections may not reach. It returns the problem, or "".
func CheckURL(raw string, allowLoopback bool) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "the address must start with https:// and name a server"
	}
	if u.User != nil {
		return "the address cannot hold a user name or password; enter them below"
	}
	if u.RawQuery != "" || u.Fragment != "" || strings.Contains(raw, "#") {
		return "the address cannot hold a query (?) or fragment (#); enter only the site's address"
	}
	if u.Port() != "" {
		if p, err := strconv.Atoi(u.Port()); err != nil || p < 1 || p > 65535 {
			return "the address's port must be between 1 and 65535"
		}
	}
	host := u.Hostname()
	ip, ipErr := netip.ParseAddr(strings.Trim(host, "[]"))
	if ipErr == nil {
		if err := notify.CheckAddr(ip, allowLoopback); err != nil {
			return blockedText(err)
		}
	} else if isLocalhost(host) && !allowLoopback {
		return blockedText(&notify.BlockedError{Addr: host, Why: "this machine", Loopback: true})
	}
	if u.Scheme == "http" {
		local := isLocalhost(host) || (ipErr == nil && ip.Unmap().IsLoopback())
		if !allowLoopback || !local {
			return "the address must start with https://: tokens and passwords are only sent over HTTPS (http:// is only for a test system on this machine, with \"Allow this server's own addresses\")"
		}
	}
	return ""
}

// blockedText is a refused address in the words of this page.
func blockedText(err error) string {
	var be *notify.BlockedError
	if !errors.As(err, &be) {
		return err.Error()
	}
	msg := fmt.Sprintf("Signalith does not connect to %s, %s.", be.Addr, be.Why)
	if be.Loopback {
		msg += " For a test system on this machine, tick \"Allow this server's own addresses\" on the connection."
	}
	return msg
}

// isLocalhost reports whether h names this machine: localhost or a
// loopback address. A name ending in dots ("localhost.") is the same name.
func isLocalhost(h string) bool {
	h = strings.TrimRight(strings.ToLower(strings.Trim(h, "[]")), ".")
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.Unmap().IsLoopback()
}

// sameServer reports whether two URLs reach the same server: the same
// scheme, host and port.
func sameServer(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil || ua.Host == "" {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && hostPort(ua) == hostPort(ub)
}

// hostPort returns a URL's lowercase host:port, with the scheme's default
// port when it has none.
func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[strings.ToLower(u.Scheme)]
	}
	return strings.ToLower(net.JoinHostPort(strings.TrimSuffix(u.Hostname(), "."), port))
}

// statusesOrDefault returns a connection's status mapping as the page
// shows it: every case status, with the defaults filled in.
func (c Connection) statusesOrDefault() map[string]string {
	out := maps.Clone(c.Statuses)
	if out == nil {
		out = map[string]string{}
	}
	for _, s := range CaseStatuses {
		if out[s] == "" && c.Type == TypeServiceNow {
			out[s] = DefaultStates[s]
		}
	}
	return out
}
