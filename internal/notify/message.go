package notify

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

// Message kinds.
const (
	KindFinding = "finding"
	// KindSummary stands for several findings at once, when one pass
	// would send a channel more than FloodLimit messages.
	KindSummary = "summary"
	KindTest    = "test"
)

// Entities are the entity fields a message names, in order, with their
// labels.
var Entities = []struct{ Field, Label string }{
	{"user", "User"}, {"host", "Host"}, {"src", "Source"}, {"dest", "Destination"},
}

// Message is what a channel is sent about one finding, or about several
// at once. It never holds the event that fired, or the finding's result
// row: only its title, urgency, detection, MITRE techniques, key
// entities, risk score, when it was raised and a link, so a chat channel
// or mailbox never receives raw log data.
type Message struct {
	Kind        string            `json:"kind"`
	FindingID   string            `json:"finding_id,omitempty"`
	Title       string            `json:"title"`
	Urgency     string            `json:"urgency,omitempty"`
	Severity    string            `json:"severity,omitempty"`
	DetectionID string            `json:"detection_id,omitempty"`
	MITRE       []string          `json:"mitre,omitempty"`
	Entities    map[string]string `json:"entities,omitempty"`
	RiskScore   *float64          `json:"risk_score,omitempty"`
	Created     time.Time         `json:"created"`
	// Link opens the Findings page; "" when server.public_url is not
	// known.
	Link   string `json:"link,omitempty"`
	Sample bool   `json:"sample,omitempty"`
	// Count is how many findings a summary stands for.
	Count int `json:"count,omitempty"`
}

// Limits on the text of a message, which comes from the events that
// fired.
const (
	maxTitle  = 300
	maxEntity = 200
	maxMITRE  = 20
)

// FindingsLink returns the link to the Findings page of the Signalith at
// publicURL, or "" when it is not known.
func FindingsLink(publicURL string) string {
	publicURL = strings.TrimRight(strings.TrimSpace(publicURL), "/")
	if publicURL == "" {
		return ""
	}
	return publicURL + "/#findings"
}

// NewMessage returns the message about a finding.
func NewMessage(f *findings.Finding, link string) Message {
	m := Message{
		Kind: KindFinding, FindingID: clean(f.ID, 100), Title: clean(f.Title, maxTitle),
		Urgency: clean(f.EffectiveUrgency(), 20), Severity: clean(f.Severity, 20), DetectionID: clean(f.DetectionID, 200),
		Created: f.Created.UTC(), Link: link, Sample: f.Sample != "",
	}
	if m.Title == "" {
		m.Title = m.DetectionID
	}
	for i, t := range f.MITRE {
		if i == maxMITRE {
			break
		}
		if t = clean(t, 20); t != "" {
			m.MITRE = append(m.MITRE, t)
		}
	}
	for _, e := range Entities {
		v, ok := f.Entities[e.Field]
		if !ok || v == nil {
			continue
		}
		if s := clean(fmt.Sprint(v), maxEntity); s != "" {
			if m.Entities == nil {
				m.Entities = map[string]string{}
			}
			m.Entities[e.Field] = s
		}
	}
	if score, ok := RiskScore(f); ok {
		m.RiskScore = &score
	}
	return m
}

// summaryMessage stands for count findings sent in one message.
func summaryMessage(count int, link string, now time.Time) Message {
	return Message{Kind: KindSummary, Title: fmt.Sprintf("And %d more new %s", count, plural(count, "finding", "findings")),
		Count: count, Link: link, Created: now.UTC()}
}

// TestMessage is what Send test sends: made-up values, marked as a test.
func TestMessage(link string, now time.Time) Message {
	score := 0.0
	return Message{
		Kind: KindTest, FindingID: "test", Title: "Test message from Signalith", Urgency: "informational", Severity: "informational",
		DetectionID: "test", Entities: map[string]string{"user": "test-user", "host": "test-host"}, RiskScore: &score,
		Created: now.UTC(), Link: link,
	}
}

// clean makes text from a finding safe to put in a message: control
// characters (line breaks among them) become spaces, and it is cut to at
// most max characters.
func clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	return cut(s, max)
}

// cut shortens s to at most max characters.
func cut(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max-1]) + "…"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// UrgencyLabel is an urgency as people read it: High.
func UrgencyLabel(u string) string {
	switch u {
	case "":
		return "Unknown"
	case "informational":
		return "Informational"
	}
	return strings.ToUpper(u[:1]) + u[1:]
}

// headline is the first line of a message, as in "High: Brute force from
// 10.0.0.5".
func (m Message) headline() string {
	switch m.Kind {
	case KindSummary:
		return m.Title
	case KindTest:
		return m.Title
	}
	h := UrgencyLabel(m.Urgency) + ": " + m.Title
	if m.Sample {
		h += " (sample data)"
	}
	return h
}

// fact is one labeled value of a message.
type fact struct{ Label, Value string }

// facts are the message's details, in order, without the title.
func (m Message) facts() []fact {
	if m.Kind == KindSummary {
		return []fact{{"Findings", fmt.Sprint(m.Count)}}
	}
	var out []fact
	if m.Urgency != "" {
		u := UrgencyLabel(m.Urgency)
		if m.Severity != "" && m.Severity != m.Urgency {
			u += " (severity " + m.Severity + ")"
		}
		out = append(out, fact{"Urgency", u})
	}
	if m.DetectionID != "" {
		out = append(out, fact{"Detection", m.DetectionID})
	}
	if len(m.MITRE) > 0 {
		out = append(out, fact{"MITRE ATT&CK", strings.Join(m.MITRE, ", ")})
	}
	for _, e := range Entities {
		if v := m.Entities[e.Field]; v != "" {
			out = append(out, fact{e.Label, v})
		}
	}
	if m.RiskScore != nil {
		out = append(out, fact{"Risk score", trimFloat(*m.RiskScore)})
	}
	if !m.Created.IsZero() {
		out = append(out, fact{"Raised", m.Created.UTC().Format("2006-01-02 15:04:05 UTC")})
	}
	return out
}

// text is the message as plain text, for email.
func (m Message) text(channel string) string {
	var b strings.Builder
	switch m.Kind {
	case KindTest:
		b.WriteString("This is a test message from Signalith. If you can read it, Signalith can send notifications to " + channel + ".\n\n")
	case KindSummary:
		fmt.Fprintf(&b, "%s.\n\nThere were too many to send one message each. Open the Findings page to see them all.\n\n", m.Title)
	default:
		b.WriteString(m.headline() + "\n\n")
	}
	if m.Kind != KindSummary {
		facts := m.facts()
		width := 0
		for _, f := range facts {
			width = max(width, utf8.RuneCountInString(f.Label))
		}
		for _, f := range facts {
			fmt.Fprintf(&b, "%-*s %s\n", width+1, f.Label+":", f.Value)
		}
		b.WriteString("\n")
	}
	if m.Link != "" {
		b.WriteString("Open in Signalith: " + m.Link + "\n\n")
	}
	b.WriteString("-- \nSent by Signalith. Admins choose what is sent where on the Notifications page.\n")
	return b.String()
}

// subject is an email's subject line.
func (m Message) subject() string {
	return clean("[Signalith] "+m.headline(), 200)
}

// WebhookVersion is the version of the webhook body's schema. Fields may
// be added within a version; none are removed or changed.
const WebhookVersion = 1

// WebhookBody is the JSON a webhook channel posts.
type WebhookBody struct {
	Version int    `json:"version"`
	Type    string `json:"type"` // finding, summary or test
	// Sent is when the message was sent; a receiver can refuse old ones.
	Sent    time.Time       `json:"sent"`
	Finding *WebhookFinding `json:"finding,omitempty"`
	Summary *WebhookSummary `json:"summary,omitempty"`
}

// WebhookFinding is the finding a webhook message is about.
type WebhookFinding struct {
	ID        string            `json:"id"`
	Title     string            `json:"title"`
	Urgency   string            `json:"urgency"`
	Severity  string            `json:"severity"`
	Detection string            `json:"detection"`
	MITRE     []string          `json:"mitre"`
	Entities  map[string]string `json:"entities"`
	RiskScore *float64          `json:"risk_score"`
	Created   time.Time         `json:"created"`
	Link      string            `json:"link"`
	Sample    bool              `json:"sample"`
}

// WebhookSummary stands for several new findings at once.
type WebhookSummary struct {
	Count int    `json:"count"`
	Text  string `json:"text"`
	Link  string `json:"link"`
}

// webhookBody returns the webhook body of a message.
func (m Message) webhookBody(sent time.Time) WebhookBody {
	b := WebhookBody{Version: WebhookVersion, Type: m.Kind, Sent: sent.UTC()}
	if m.Kind == KindSummary {
		b.Summary = &WebhookSummary{Count: m.Count, Text: m.Title, Link: m.Link}
		return b
	}
	mitre := slices.Clone(m.MITRE)
	if mitre == nil {
		mitre = []string{}
	}
	ent := map[string]string{}
	for k, v := range m.Entities {
		ent[k] = v
	}
	b.Finding = &WebhookFinding{ID: m.FindingID, Title: m.Title, Urgency: m.Urgency, Severity: m.Severity, Detection: m.DetectionID,
		MITRE: mitre, Entities: ent, RiskScore: m.RiskScore, Created: m.Created, Link: m.Link, Sample: m.Sample}
	return b
}

// slackEscape escapes the characters Slack's mrkdwn gives meaning to
// (links and mentions are written <...>).
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// slackBody returns a Slack incoming webhook message in Block Kit. Text
// from the finding goes in plain_text elements, which Slack shows as
// they are, so it cannot add links, mentions or formatting; only the
// fallback text Slack shows in notifications is mrkdwn, escaped.
func (m Message) slackBody(channel string) map[string]any {
	plain := func(s string, max int) map[string]any {
		return map[string]any{"type": "plain_text", "text": cut(s, max), "emoji": false}
	}
	blocks := []any{map[string]any{"type": "header", "text": plain(m.headline(), 150)}}
	switch m.Kind {
	case KindTest:
		blocks = append(blocks, map[string]any{"type": "section", "text": plain("If you can read this, Signalith can send notifications to "+channel+".", 2000)})
	case KindSummary:
		blocks = append(blocks, map[string]any{"type": "section", "text": plain("There were too many to send one message each. Open the Findings page to see them all.", 2000)})
	}
	if m.Kind != KindSummary {
		var fields []any
		for _, f := range m.facts() {
			if len(fields) == 10 {
				break
			}
			fields = append(fields, plain(f.Label+"\n"+f.Value, 2000))
		}
		if len(fields) > 0 {
			blocks = append(blocks, map[string]any{"type": "section", "fields": fields})
		}
	}
	if m.Link != "" {
		blocks = append(blocks, map[string]any{"type": "actions", "elements": []any{map[string]any{
			"type": "button", "text": plain("Open in Signalith", 75), "url": m.Link,
		}}})
	}
	return map[string]any{"text": slackEscape(m.headline()), "blocks": blocks, "unfurl_links": false, "unfurl_media": false}
}

// teamsEscape keeps text from a finding from being read as markdown in an
// Adaptive Card, where it could add links or formatting.
func teamsEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`, "`", "\\`", "~", `\~`, "<", "&lt;", ">", "&gt;").Replace(s)
}

// teamsBody returns a Teams Workflows webhook message: an Adaptive Card in
// the "message" envelope that the "Post to a channel when a webhook
// request is received" workflow expects.
func (m Message) teamsBody(channel string) map[string]any {
	body := []any{map[string]any{"type": "TextBlock", "text": teamsEscape(m.headline()), "weight": "Bolder", "size": "Medium", "wrap": true}}
	switch m.Kind {
	case KindTest:
		body = append(body, map[string]any{"type": "TextBlock", "text": teamsEscape("If you can read this, Signalith can send notifications to " + channel + "."), "wrap": true})
	case KindSummary:
		body = append(body, map[string]any{"type": "TextBlock", "text": "There were too many to send one message each. Open the Findings page to see them all.", "wrap": true})
	}
	if m.Kind != KindSummary {
		var facts []any
		for _, f := range m.facts() {
			facts = append(facts, map[string]any{"title": f.Label, "value": teamsEscape(f.Value)})
		}
		if len(facts) > 0 {
			body = append(body, map[string]any{"type": "FactSet", "facts": facts})
		}
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"body":    body,
	}
	if m.Link != "" {
		card["actions"] = []any{map[string]any{"type": "Action.OpenUrl", "title": "Open in Signalith", "url": m.Link}}
	}
	return map[string]any{
		"type": "message",
		"attachments": []any{map[string]any{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"contentUrl":  nil,
			"content":     card,
		}},
	}
}
