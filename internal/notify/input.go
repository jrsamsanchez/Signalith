package notify

import (
	"crypto/x509"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// Limits on what the page can save.
const (
	MaxChannels   = 50
	MaxRules      = 100
	MaxRecipients = 50
	MaxHeaders    = 20
	maxName       = 80
	maxCAPEM      = 64 << 10
	maxSecret     = 4 << 10
)

// Input is the whole of the channels and rules as the Notifications page
// sends them. Secrets are write-only: they are never sent back, and an
// empty value keeps the stored one.
type Input struct {
	// Revision is the Revision the page started from; a save over newer
	// settings is refused with ErrChanged. Empty skips the check.
	Revision string         `json:"revision"`
	Channels []ChannelInput `json:"channels"`
	Rules    []RuleInput    `json:"rules"`
}

// ChannelInput is a channel as the page sends it. A channel with an ID
// that is not saved yet is new; one without an ID gets one.
type ChannelInput struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	// URL sets the address; empty keeps the stored one.
	URL string `json:"url"`
	// Headers set, keep or clear webhook request headers, as on a feed:
	// one with a value sets it, one without keeps the stored value, one
	// with clear removes it, and stored ones not listed are removed.
	Headers []HeaderInput `json:"headers"`
	// SigningSecret sets the webhook signing secret; empty keeps the
	// stored one and ClearSigningSecret removes it.
	SigningSecret      string `json:"signing_secret"`
	ClearSigningSecret bool   `json:"clear_signing_secret"`

	Host     string `json:"host"`
	Port     int    `json:"port"`
	Security string `json:"security"`
	Username string `json:"username"`
	// Password sets the mail password; empty keeps the stored one and
	// ClearPassword removes it.
	Password      string   `json:"password"`
	ClearPassword bool     `json:"clear_password"`
	From          string   `json:"from"`
	To            []string `json:"to"`

	AllowLoopback bool   `json:"allow_loopback"`
	CAPEM         string `json:"ca_pem"`
}

// HeaderInput sets, keeps or clears one webhook header.
type HeaderInput struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	Clear bool   `json:"clear,omitempty"`
}

// RuleInput is a rule as the page sends it.
type RuleInput struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Enabled defaults to true.
	Enabled       *bool    `json:"enabled"`
	Channels      []string `json:"channels"`
	MinUrgency    string   `json:"min_urgency"`
	Detections    []string `json:"detections"`
	MinRiskScore  float64  `json:"min_risk_score"`
	IncludeSample bool     `json:"include_sample"`
}

// Problem is one setting to fix. Where is "channel:<id>" or
// "rule:<id>" (with the ID the page sent, or the place in the list for
// one sent without an ID, as in "channel:#2"); Field is the setting, such
// as url, for the form to mark.
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
	idForm     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)
	headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$")
	// reservedHeaders are set by Signalith or by the HTTP client.
	reservedHeaders = []string{"host", "content-length", "content-type", "transfer-encoding", "connection", "x-signalith-signature", "user-agent"}
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

// Check merges a single channel as a test would send through it, without
// saving: the stored channel with the same ID gives the secrets left
// empty.
func (m *Manager) Check(in ChannelInput) (Channel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	if m.fileErr != nil {
		return Channel{}, m.fileErr
	}
	var old *Channel
	if c, ok := m.cur.Channel(strings.TrimSpace(in.ID)); ok {
		old = &c
	}
	c, probs := in.channel(old, "channel:"+where(in.ID, 0))
	if c.ID == "" {
		c.ID = "test"
	}
	if len(probs) > 0 {
		return Channel{}, &InputError{Problems: probs}
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
	var probs []Problem
	if len(in.Channels) > MaxChannels {
		probs = append(probs, Problem{Where: "channels", Msg: fmt.Sprintf("at most %d channels can be set up", MaxChannels)})
	}
	if len(in.Rules) > MaxRules {
		probs = append(probs, Problem{Where: "rules", Msg: fmt.Sprintf("at most %d rules can be set up", MaxRules)})
	}
	if len(probs) > 0 {
		return Settings{}, probs
	}
	var out Settings
	ids, names := map[string]bool{}, map[string]bool{}
	for i, ci := range in.Channels {
		w := "channel:" + where(ci.ID, i)
		var old *Channel
		if c, ok := cur.Channel(strings.TrimSpace(ci.ID)); ok {
			old = &c
		}
		c, p := ci.channel(old, w)
		probs = append(probs, p...)
		if c.ID == "" {
			c.ID = newID()
		}
		if ids[c.ID] {
			probs = append(probs, Problem{Where: w, Field: "id", Msg: fmt.Sprintf("two channels have the ID %s", c.ID)})
		}
		ids[c.ID] = true
		if key := strings.ToLower(c.Name); c.Name != "" {
			if names[key] {
				probs = append(probs, Problem{Where: w, Field: "name", Msg: fmt.Sprintf("another channel is already named %s; choose another name", c.Name)})
			}
			names[key] = true
		}
		out.Channels = append(out.Channels, c)
	}
	ruleIDs, ruleNames := map[string]bool{}, map[string]bool{}
	for i, ri := range in.Rules {
		w := "rule:" + where(ri.ID, i)
		var old *Rule
		for _, r := range cur.Rules {
			if r.ID == strings.TrimSpace(ri.ID) {
				old = &r
				break
			}
		}
		r, p := ri.rule(old, w, cur, out, now)
		probs = append(probs, p...)
		if r.ID == "" {
			r.ID = newID()
		}
		if ruleIDs[r.ID] {
			probs = append(probs, Problem{Where: w, Field: "id", Msg: fmt.Sprintf("two rules have the ID %s", r.ID)})
		}
		ruleIDs[r.ID] = true
		if key := strings.ToLower(r.Name); r.Name != "" {
			if ruleNames[key] {
				probs = append(probs, Problem{Where: w, Field: "name", Msg: fmt.Sprintf("another rule is already named %s; choose another name", r.Name)})
			}
			ruleNames[key] = true
		}
		out.Rules = append(out.Rules, r)
	}
	return out, probs
}

// checkName checks a channel or rule name.
func checkName(name, what string) string {
	switch {
	case name == "":
		return "enter a name for the " + what
	case len(name) > maxName:
		return fmt.Sprintf("the %s's name is too long (at most %d characters)", what, maxName)
	case strings.IndexFunc(name, unicode.IsControl) >= 0:
		return fmt.Sprintf("the %s's name cannot hold line breaks or control characters", what)
	}
	return ""
}

// channel turns input into a channel, merging secrets with old's.
func (in ChannelInput) channel(old *Channel, w string) (Channel, []Problem) {
	var probs []Problem
	label := strings.TrimSpace(in.Name)
	if label == "" {
		label = "a channel"
	}
	add := func(field, msg string) {
		probs = append(probs, Problem{Where: w, Field: field, Msg: label + ": " + msg})
	}
	c := Channel{
		ID: strings.TrimSpace(in.ID), Name: strings.TrimSpace(in.Name), Type: strings.ToLower(strings.TrimSpace(in.Type)),
		AllowLoopback: in.AllowLoopback, CAPEM: strings.TrimSpace(in.CAPEM),
	}
	if c.ID != "" && old == nil && !idForm.MatchString(c.ID) {
		add("id", "a new channel's ID may only hold lowercase letters, digits, - and _ (at most 40 characters)")
	}
	if msg := checkName(c.Name, "channel"); msg != "" {
		add("name", msg)
	}
	if !slices.Contains(Types, c.Type) {
		add("type", "pick the kind of channel: Slack, Teams, email or webhook")
		return c, probs
	}
	if old != nil && old.Type != c.Type {
		// A channel's saved secrets belong to its kind; a new kind
		// starts without them.
		old = nil
	}
	if c.CAPEM != "" {
		if len(c.CAPEM) > maxCAPEM || !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CAPEM)) {
			add("ca_pem", "the certificate authority must be one or more PEM certificates (-----BEGIN CERTIFICATE-----)")
		}
	}
	secret := func(field, v string) bool {
		switch {
		case secrets.IsSealed(v):
			add(field, "the value "+looksEncrypted)
		case len(v) > maxSecret:
			add(field, "the value is too long")
		case strings.ContainsAny(v, "\r\n"):
			add(field, "the value cannot hold line breaks")
		default:
			return true
		}
		return false
	}
	if c.Type == TypeEmail {
		probs = append(probs, in.email(&c, old, add, secret)...)
		return c, probs
	}
	// Webhook, Slack and Teams post to a URL.
	newURL := strings.TrimSpace(in.URL)
	switch {
	case newURL != "":
		if secret("url", newURL) {
			c.URL = newURL
		}
	case old != nil:
		c.URL = old.URL
	}
	if c.URL == "" {
		add("url", map[string]string{
			TypeSlack:   "enter the incoming webhook URL from Slack",
			TypeTeams:   "enter the workflow's webhook URL from Teams (Workflows, \"Post to a channel when a webhook request is received\")",
			TypeWebhook: "enter the URL to post to",
		}[c.Type])
	} else if !secrets.IsSealed(c.URL) {
		if msg := checkURL(c.URL, c.AllowLoopback); msg != "" {
			add("url", msg)
		}
	}
	if c.Type != TypeWebhook {
		return c, probs
	}
	// Saved secrets are only sent to the server they were entered for:
	// when the URL points elsewhere, each must be entered again or
	// cleared.
	moved := old != nil && !sameServer(old.URL, c.URL)
	headers := map[string]string{}
	var oldHeaders map[string]string
	if old != nil {
		oldHeaders = old.Headers
	}
	stored := func(name string) (string, string) {
		for k, v := range oldHeaders {
			if strings.EqualFold(k, name) {
				return k, v
			}
		}
		return "", ""
	}
	var again []string
	for _, h := range in.Headers {
		name, value := strings.TrimSpace(h.Name), strings.TrimSpace(h.Value)
		have, haveValue := stored(name)
		switch {
		case name == "" && value == "":
		case name == "":
			add("headers", "a header with a value needs a name")
		case !headerName.MatchString(name):
			add("headers", fmt.Sprintf("%q is not a valid header name", name))
		case slices.Contains(reservedHeaders, strings.ToLower(name)):
			add("headers", fmt.Sprintf("the %s header is set by Signalith", name))
		case h.Clear:
		case value != "":
			if secret("headers", value) {
				headers[name] = value
			}
		case have == "":
			add("headers", fmt.Sprintf("enter a value for header %s", name))
		case moved:
			again = append(again, have)
		default:
			headers[have] = haveValue
		}
	}
	for _, k := range again {
		add("headers", fmt.Sprintf("enter the value of header %s again, or remove it: the URL now points to another server, and saved values are only sent to the server they were entered for", k))
	}
	if len(headers) > MaxHeaders {
		add("headers", fmt.Sprintf("at most %d headers", MaxHeaders))
	}
	if len(headers) > 0 {
		c.Headers = headers
	}
	switch {
	case in.SigningSecret != "":
		if secret("signing_secret", in.SigningSecret) {
			c.SigningSecret = in.SigningSecret
		}
	case in.ClearSigningSecret || old == nil || old.SigningSecret == "":
	case moved:
		add("signing_secret", "enter the signing secret again for the new server, or clear it: a saved secret is only sent to the server it was entered for")
	default:
		c.SigningSecret = old.SigningSecret
	}
	return c, probs
}

// email fills the mail settings of c.
func (in ChannelInput) email(c *Channel, old *Channel, add func(field, msg string), secret func(field, v string) bool) []Problem {
	c.Host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(in.Host)), ".")
	c.Security = strings.ToLower(strings.TrimSpace(in.Security))
	if c.Security == "" {
		c.Security = SecuritySTARTTLS
	}
	c.Username = strings.TrimSpace(in.Username)
	c.Port = in.Port
	switch c.Security {
	case SecuritySTARTTLS, SecurityTLS, SecurityNone:
	default:
		add("security", "pick how to connect: STARTTLS, TLS or none")
	}
	if c.Port == 0 {
		c.Port = map[string]int{SecuritySTARTTLS: 587, SecurityTLS: 465, SecurityNone: 25}[c.Security]
	}
	if c.Port < 1 || c.Port > 65535 {
		add("port", "the port must be between 1 and 65535")
	}
	switch {
	case c.Host == "":
		add("host", "enter the mail server, such as smtp.example.com")
	case !validHost(c.Host):
		add("host", "enter the mail server's name or IP address, without a port or scheme")
	default:
		if ip, err := netip.ParseAddr(strings.Trim(c.Host, "[]")); err == nil {
			if err := CheckAddr(ip, c.AllowLoopback || c.Security == SecurityNone); err != nil {
				add("host", sentenceCase(err.Error()))
			}
		}
	}
	if c.Security == SecurityNone && c.Host != "" && !isLocalhost(c.Host) {
		add("security", "mail is only sent without TLS to a relay on this machine (localhost); pick STARTTLS or TLS for another server")
	}
	moved := old != nil && (old.Host != c.Host || old.Port != c.Port)
	switch {
	case in.Password != "":
		if secret("password", in.Password) {
			c.Password = in.Password
		}
	case in.ClearPassword || old == nil || old.Password == "" || c.Username == "":
	case moved:
		add("password", "enter the password again for the new mail server, or clear it: a saved password is only sent to the server it was entered for")
	default:
		c.Password = old.Password
	}
	if c.Password != "" && c.Username == "" {
		add("username", "enter the user name the password is for")
	}
	if c.Security == SecurityNone && (c.Username != "" || c.Password != "") {
		add("security", "a user name and password are only sent over TLS; pick STARTTLS or TLS, or clear them")
	}
	if strings.ContainsAny(c.Username, "\r\n") {
		add("username", "the user name cannot hold line breaks")
	}
	from := strings.TrimSpace(in.From)
	if from == "" {
		add("from", "enter the address the mail comes from, such as signalith@example.com")
	} else if a, err := parseAddr(from); err != nil {
		add("from", fmt.Sprintf("%q is not a valid email address", from))
	} else {
		c.From = a
	}
	seen := map[string]bool{}
	for _, raw := range in.To {
		for _, t := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == '\n' }) {
			if t = strings.TrimSpace(t); t == "" {
				continue
			}
			a, err := parseAddr(t)
			if err != nil {
				add("to", fmt.Sprintf("%q is not a valid email address", t))
				continue
			}
			if !seen[strings.ToLower(a)] {
				seen[strings.ToLower(a)] = true
				c.To = append(c.To, a)
			}
		}
	}
	switch {
	case len(c.To) == 0:
		add("to", "enter at least one address to send to")
	case len(c.To) > MaxRecipients:
		add("to", fmt.Sprintf("at most %d addresses", MaxRecipients))
	}
	return nil
}

// parseAddr checks one email address and returns it in its usual form.
func parseAddr(s string) (string, error) {
	if strings.ContainsAny(s, "\r\n") {
		return "", fmt.Errorf("line break")
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return "", err
	}
	if a.Name == "" {
		return a.Address, nil
	}
	return a.String(), nil
}

// validHost reports whether h is a host name or IP address, without a
// port.
func validHost(h string) bool {
	if _, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return true
	}
	if len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// isLocalhost reports whether h names this machine: localhost or a
// loopback address.
func isLocalhost(h string) bool {
	h = strings.ToLower(strings.Trim(h, "[]"))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.Unmap().IsLoopback()
}

// checkURL checks a webhook URL: http or https, with a host, and not an
// address channels may not reach.
func checkURL(raw string, allowLoopback bool) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "the URL must start with https:// (or http://) and name a server"
	}
	if u.Port() != "" {
		if p, err := strconv.Atoi(u.Port()); err != nil || p < 1 || p > 65535 {
			return "the URL's port must be between 1 and 65535"
		}
	}
	if ip, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil {
		if err := CheckAddr(ip, allowLoopback); err != nil {
			return sentenceCase(err.Error())
		}
	} else if isLocalhost(u.Hostname()) && !allowLoopback {
		return (&BlockedError{Addr: u.Hostname(), Why: "this machine", Loopback: true}).Error()
	}
	return ""
}

// sameServer reports whether two URLs reach the same server: the same
// scheme, host and port.
func sameServer(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
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

// rule turns input into a rule. old is the saved rule with its ID, cur
// the saved settings, and next the new settings' channels.
func (in RuleInput) rule(old *Rule, w string, cur, next Settings, now func() time.Time) (Rule, []Problem) {
	var probs []Problem
	label := strings.TrimSpace(in.Name)
	if label == "" {
		label = "a rule"
	}
	add := func(field, msg string) {
		probs = append(probs, Problem{Where: w, Field: field, Msg: label + ": " + msg})
	}
	r := Rule{
		ID: strings.TrimSpace(in.ID), Name: strings.TrimSpace(in.Name), Enabled: in.Enabled == nil || *in.Enabled,
		MinUrgency: strings.ToLower(strings.TrimSpace(in.MinUrgency)), MinRiskScore: in.MinRiskScore, IncludeSample: in.IncludeSample,
	}
	if r.ID != "" && old == nil && !idForm.MatchString(r.ID) {
		add("id", "a new rule's ID may only hold lowercase letters, digits, - and _ (at most 40 characters)")
	}
	if msg := checkName(r.Name, "rule"); msg != "" {
		add("name", msg)
	}
	if r.MinUrgency == "" {
		r.MinUrgency = DefaultMinUrgency
	}
	if !slices.Contains(Urgencies, r.MinUrgency) {
		add("min_urgency", "pick the least urgency: "+strings.Join(Urgencies, ", "))
	}
	if r.MinRiskScore < 0 || r.MinRiskScore > 100000 {
		add("min_risk_score", "the least risk score must be between 0 and 100000 (0 means any)")
	}
	for _, d := range in.Detections {
		d = strings.TrimSpace(d)
		switch {
		case d == "" || slices.Contains(r.Detections, d):
		case len(d) > 200 || strings.IndexFunc(d, unicode.IsControl) >= 0:
			add("detections", fmt.Sprintf("%q is not a detection ID", d))
		default:
			r.Detections = append(r.Detections, d)
		}
	}
	if len(r.Detections) > 500 {
		add("detections", "at most 500 detections")
	}
	removed, unknown := false, false
	for _, id := range in.Channels {
		id = strings.TrimSpace(id)
		switch {
		case id == "" || slices.Contains(r.Channels, id):
		case containsChannel(next, id):
			r.Channels = append(r.Channels, id)
		case containsChannel(cur, id):
			// The channel is being removed: the rule no longer sends to it.
			removed = true
		default:
			unknown = true
			add("channels", fmt.Sprintf("there is no channel with the ID %s", id))
		}
	}
	switch {
	case len(r.Channels) > 0 || !r.Enabled || unknown:
	case removed:
		// Every channel it sent to was removed: it is turned off rather
		// than refused, so removing a channel always works.
		r.Enabled = false
	default:
		add("channels", "pick at least one channel to send to")
	}
	// Only findings raised from when a rule is turned on match it.
	switch {
	case !r.Enabled:
		if old != nil {
			r.Since = old.Since
		}
	case old == nil || !old.Enabled:
		r.Since = now().UTC()
	default:
		r.Since = old.Since
	}
	return r, probs
}

func containsChannel(s Settings, id string) bool {
	_, ok := s.Channel(id)
	return ok
}

// sentenceCase lowers the first letter of a sentence that goes after a
// channel's name and a colon.
func sentenceCase(s string) string {
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}
