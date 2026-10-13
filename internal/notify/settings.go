// Package notify sends a message to email, a webhook, Slack or Microsoft
// Teams when a detection raises a finding that matters, so nobody has to
// watch the Findings page to learn of it.
//
// Admins set it up on the Notifications page: channels (where messages
// go) and rules (which findings go to which channels). Both are kept in a
// YAML file in the lookups folder (notify.file), with every password, key
// and webhook address encrypted with the master key (package secrets).
//
// Only the server that runs the background jobs sends (see Dispatcher).
// Each message is claimed first with a document in OpenSearch whose ID
// says which finding and channel it is for, so it goes out at most once,
// even when another server takes the jobs over part way.
package notify

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

// Channel types.
const (
	TypeEmail   = "email"
	TypeWebhook = "webhook"
	TypeSlack   = "slack"
	TypeTeams   = "teams"
)

// Types lists the channel types, in the order the page offers them.
var Types = []string{TypeSlack, TypeTeams, TypeEmail, TypeWebhook}

// typeLabel names each channel type for people.
var typeLabel = map[string]string{TypeEmail: "Email", TypeWebhook: "Webhook", TypeSlack: "Slack", TypeTeams: "Teams"}

// TypeLabel names a channel type for people: Email, Webhook, Slack or
// Teams.
func TypeLabel(t string) string {
	if l, ok := typeLabel[t]; ok {
		return l
	}
	return t
}

// How an email channel protects its connection to the mail server.
const (
	// SecuritySTARTTLS connects in plain text and switches to TLS before
	// anything else is sent (usually port 587). The default; a server
	// that does not offer it is refused.
	SecuritySTARTTLS = "starttls"
	// SecurityTLS uses TLS from the start (usually port 465).
	SecurityTLS = "tls"
	// SecurityNone sends in plain text, only to a mail relay on this
	// machine (localhost), and never with a password.
	SecurityNone = "none"
)

// Channel is one place messages go. The secrets (URL, header values,
// signing secret and password) are kept encrypted in the file and are
// never sent back to the page.
type Channel struct {
	// ID never changes, so rules and deliveries keep pointing at the
	// channel when it is renamed.
	ID   string `yaml:"id" json:"id"`
	Name string `yaml:"name" json:"name"`
	Type string `yaml:"type" json:"type"`

	// URL is where a webhook, Slack or Teams message is posted. It is a
	// secret: these addresses usually carry the token that lets anyone
	// post.
	URL string `yaml:"url,omitempty" json:"-"`
	// Headers are extra request headers for a webhook, such as an
	// Authorization header; their values are secrets.
	Headers map[string]string `yaml:"headers,omitempty" json:"-"`
	// SigningSecret, when set, signs each webhook body: the
	// X-Signalith-Signature header is sha256= and the hex HMAC-SHA256 of
	// the body with it.
	SigningSecret string `yaml:"signing_secret,omitempty" json:"-"`

	// The mail server of an email channel, and who the mail is from and
	// to.
	Host     string   `yaml:"host,omitempty" json:"host,omitempty"`
	Port     int      `yaml:"port,omitempty" json:"port,omitempty"`
	Security string   `yaml:"security,omitempty" json:"security,omitempty"`
	Username string   `yaml:"username,omitempty" json:"username,omitempty"`
	Password string   `yaml:"password,omitempty" json:"-"`
	From     string   `yaml:"from,omitempty" json:"from,omitempty"`
	To       []string `yaml:"to,omitempty" json:"to,omitempty"`

	// AllowLoopback lets the channel reach this server's own addresses
	// (127.0.0.1, ::1) and link-local ones, for a receiver on this
	// machine. Off by default, so a channel cannot be used to reach
	// services that are only meant to be reachable from this machine.
	AllowLoopback bool `yaml:"allow_loopback,omitempty" json:"allow_loopback,omitempty"`
	// CAPEM holds extra certificate authorities, in PEM, that the
	// receiver's HTTPS or mail server certificate may come from, for a
	// private certificate authority. The system's trusted ones always
	// count too.
	CAPEM string `yaml:"ca_pem,omitempty" json:"ca_pem,omitempty"`
}

// Rule sends the findings that match it to its channels.
type Rule struct {
	ID      string `yaml:"id" json:"id"`
	Name    string `yaml:"name" json:"name"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
	// Channels are channel IDs.
	Channels []string `yaml:"channels" json:"channels"`
	// MinUrgency is the least urgency a finding needs; default high.
	MinUrgency string `yaml:"min_urgency" json:"min_urgency"`
	// Detections limits the rule to findings of these detections; empty
	// means every detection.
	Detections []string `yaml:"detections,omitempty" json:"detections"`
	// MinRiskScore, above 0, skips findings whose result carries a
	// risk_score below it. Findings without a risk score are not affected.
	MinRiskScore float64 `yaml:"min_risk_score,omitempty" json:"min_risk_score"`
	// IncludeSample sends findings raised from the one-click sample data
	// too, to try a channel out. Off by default.
	IncludeSample bool `yaml:"include_sample,omitempty" json:"include_sample"`
	// Since is when the rule was added or last turned on: only findings
	// raised from then on match, so a new rule does not send old ones.
	Since time.Time `yaml:"since" json:"since"`
}

// Settings are the channels and rules.
type Settings struct {
	Channels []Channel `yaml:"channels" json:"channels"`
	Rules    []Rule    `yaml:"rules" json:"rules"`
}

// Channel returns the channel with an ID.
func (s Settings) Channel(id string) (Channel, bool) {
	for _, c := range s.Channels {
		if c.ID == id {
			return c, true
		}
	}
	return Channel{}, false
}

// clone returns a deep copy, so a caller may change it.
func (s Settings) clone() Settings {
	out := Settings{Channels: make([]Channel, len(s.Channels)), Rules: make([]Rule, len(s.Rules))}
	for i, c := range s.Channels {
		out.Channels[i] = c.clone()
	}
	for i, r := range s.Rules {
		r.Channels = slices.Clone(r.Channels)
		r.Detections = slices.Clone(r.Detections)
		out.Rules[i] = r
	}
	return out
}

func (c Channel) clone() Channel {
	if c.Headers != nil {
		h := make(map[string]string, len(c.Headers))
		for k, v := range c.Headers {
			h[k] = v
		}
		c.Headers = h
	}
	c.To = slices.Clone(c.To)
	return c
}

// Urgencies lists the urgencies, lowest first (the severities of
// package findings).
var Urgencies = findings.Severities

// urgencyRank orders urgencies; an unknown one ranks lowest.
func urgencyRank(u string) int { return slices.Index(Urgencies, u) }

// DefaultMinUrgency is a new rule's least urgency.
const DefaultMinUrgency = "high"

// Matches reports whether a finding goes to the rule's channels: the
// rule is on, the finding is at least as urgent as the rule asks, from
// one of its detections, raised since the rule was turned on, not sample
// data unless the rule asks for it, and at or above its least risk score
// when it carries one.
func (r Rule) Matches(f *findings.Finding) bool {
	if !r.Enabled || f == nil {
		return false
	}
	if f.Sample != "" && !r.IncludeSample {
		return false
	}
	if f.Created.Before(r.Since) {
		return false
	}
	min := r.MinUrgency
	if min == "" {
		min = DefaultMinUrgency
	}
	if urgencyRank(f.EffectiveUrgency()) < urgencyRank(min) {
		return false
	}
	if len(r.Detections) > 0 && !slices.Contains(r.Detections, f.DetectionID) {
		return false
	}
	if r.MinRiskScore > 0 {
		if score, ok := RiskScore(f); ok && score < r.MinRiskScore {
			return false
		}
	}
	return true
}

// RiskScore returns the risk score a finding's result carries, if any.
// Findings of risk detections carry result["risk_score"].
func RiskScore(f *findings.Finding) (float64, bool) {
	if f == nil || f.Result == nil {
		return 0, false
	}
	switch v := f.Result["risk_score"].(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case string:
		var x float64
		if _, err := fmt.Sscan(strings.TrimSpace(v), &x); err == nil {
			return x, true
		}
	}
	return 0, false
}

// Summary says in plain English what a rule does, as in "High and
// critical findings from any detection go to Slack #soc and SOC email."
func (r Rule) Summary(s Settings) string {
	min := r.MinUrgency
	if min == "" {
		min = DefaultMinUrgency
	}
	what := map[string]string{
		"critical":      "Critical findings",
		"high":          "High and critical findings",
		"medium":        "Medium, high and critical findings",
		"low":           "Findings of low urgency and above",
		"informational": "All findings",
	}[min]
	if what == "" {
		what = "Findings"
	}
	from := "from any detection"
	switch n := len(r.Detections); {
	case n == 1:
		from = "from " + r.Detections[0]
	case n == 2 || n == 3:
		from = "from " + joinAnd(r.Detections)
	case n > 3:
		from = fmt.Sprintf("from %d detections", n)
	}
	parts := []string{what, from}
	if r.MinRiskScore > 0 {
		parts = append(parts, "with a risk score of "+trimFloat(r.MinRiskScore)+" or more (when they have one)")
	}
	if r.IncludeSample {
		parts = append(parts, "including sample data")
	}
	var to []string
	for _, id := range r.Channels {
		if c, ok := s.Channel(id); ok {
			to = append(to, c.Label())
		}
	}
	if len(to) == 0 {
		return strings.Join(parts, " ") + " go nowhere yet: pick a channel."
	}
	return strings.Join(parts, " ") + " go to " + joinAnd(to) + "."
}

// Label names a channel with its type, as in "Slack #soc", unless its
// name already says it, as in "SOC email".
func (c Channel) Label() string {
	t := TypeLabel(c.Type)
	if strings.Contains(strings.ToLower(c.Name), strings.ToLower(t)) {
		return c.Name
	}
	return t + " " + c.Name
}

func joinAnd(list []string) string {
	switch len(list) {
	case 0:
		return ""
	case 1:
		return list[0]
	}
	return strings.Join(list[:len(list)-1], ", ") + " and " + list[len(list)-1]
}

func trimFloat(v float64) string {
	s := fmt.Sprintf("%.2f", v)
	s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	return s
}

// newID returns a short random ID for a channel or rule.
func newID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
