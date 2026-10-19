package notify

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

func mailInput() ChannelInput {
	return ChannelInput{ID: "mail", Name: "SOC email", Type: TypeEmail, Host: "smtp.example.com", Port: 587, Security: "starttls",
		From: "signalith@example.com", To: []string{"soc@example.com"}}
}

func problemsOf(t *testing.T, err error) []Problem {
	t.Helper()
	var ie *InputError
	if !errors.As(err, &ie) {
		t.Fatalf("not an input error: %v", err)
	}
	return ie.Problems
}

func hasProblem(ps []Problem, field, msg string) bool {
	for _, p := range ps {
		if p.Field == field && strings.Contains(p.Msg, msg) {
			return true
		}
	}
	return false
}

func TestMoreInputProblems(t *testing.T) {
	long := strings.Repeat("n", maxName+1)
	for _, c := range []struct {
		field, msg string
		ch         func(*ChannelInput)
	}{
		{"name", "too long", func(c *ChannelInput) { c.Name = long }},
		{"name", "control characters", func(c *ChannelInput) { c.Name = "a\tb" }},
		{"security", "pick how to connect", func(c *ChannelInput) { c.Security = "ssl3" }},
		{"port", "between 1 and 65535", func(c *ChannelInput) { c.Port = 70000 }},
		{"host", "without a port or scheme", func(c *ChannelInput) { c.Host = "smtp://mail" }},
		{"host", "without a port or scheme", func(c *ChannelInput) { c.Host = strings.Repeat("a", 254) }},
		{"host", "without a port or scheme", func(c *ChannelInput) { c.Host = "-bad.example.com" }},
		{"host", "", func(c *ChannelInput) { c.Host = "169.254.169.254" }},
		{"username", "the password is for", func(c *ChannelInput) { c.Password = "pw" }},
		{"username", "line breaks", func(c *ChannelInput) { c.Username = "a\nb"; c.Password = "pw" }},
		{"password", "too long", func(c *ChannelInput) { c.Username = "u"; c.Password = strings.Repeat("p", maxSecret+1) }},
		{"from", "enter the address", func(c *ChannelInput) { c.From = "" }},
		{"to", "is not a valid email address", func(c *ChannelInput) { c.To = []string{"soc@example.com, , not an address"} }},
		{"to", "at most 50 addresses", func(c *ChannelInput) {
			c.To = nil
			for i := range MaxRecipients + 1 {
				c.To = append(c.To, fmt.Sprintf("a%d@example.com", i))
			}
		}},
	} {
		in := mailInput()
		c.ch(&in)
		_, err := newManager(t).Save(Input{Channels: []ChannelInput{in}})
		if ps := problemsOf(t, err); !hasProblem(ps, c.field, c.msg) {
			t.Errorf("%s %q: %v", c.field, c.msg, ps)
		}
	}

	hook := func(h ...HeaderInput) ChannelInput {
		return ChannelInput{ID: "hook", Name: "SOAR", Type: TypeWebhook, URL: "https://soar.example.com/hook", Headers: h}
	}
	for msg, in := range map[string]ChannelInput{
		"needs a name":            hook(HeaderInput{Value: "v"}),
		"is not a valid header":   hook(HeaderInput{Name: "bad header", Value: "v"}),
		"enter a value for":       hook(HeaderInput{Name: "X-New"}),
		"at most 20 headers":      hook(manyHeaders()...),
		"port must be between":    {ID: "hook", Name: "SOAR", Type: TypeWebhook, URL: "https://soar.example.com:0/hook"},
		"is not a valid header n": hook(HeaderInput{}, HeaderInput{Name: "a:b", Value: "v"}),
	} {
		_, err := newManager(t).Save(Input{Channels: []ChannelInput{in}})
		if ps := problemsOf(t, err); !hasProblem(ps, fieldFor(msg), msg) {
			t.Errorf("%q: %v", msg, ps)
		}
	}

	// Lists that are too long, and repeated IDs.
	var chans []ChannelInput
	for i := range MaxChannels + 1 {
		chans = append(chans, slackInput(fmt.Sprintf("s%d", i), "https://hooks.slack.com/services/T0/B0/x"))
	}
	if ps := problemsOf(t, second(newManager(t).Save(Input{Channels: chans}))); ps[0].Where != "channels" {
		t.Errorf("too many channels: %v", ps)
	}
	if ps := problemsOf(t, second(newManager(t).Save(Input{Rules: make([]RuleInput, MaxRules+1)}))); ps[0].Where != "rules" {
		t.Errorf("too many rules: %v", ps)
	}
	twice := slackInput("dup", "https://hooks.slack.com/services/T0/B0/x")
	if ps := problemsOf(t, second(newManager(t).Save(Input{Channels: []ChannelInput{twice, twice}}))); !hasProblem(ps, "id", "two channels have the ID dup") {
		t.Errorf("repeated channel: %v", ps)
	}
	r := RuleInput{ID: "r1", Name: "R", Channels: []string{"dup"}, MinUrgency: "high"}
	if ps := problemsOf(t, second(newManager(t).Save(Input{Channels: []ChannelInput{twice}, Rules: []RuleInput{r, r}}))); !hasProblem(ps, "id", "two rules have the ID r1") {
		t.Errorf("repeated rule: %v", ps)
	}

	// Rules.
	for _, c := range []struct {
		field, msg string
		r          RuleInput
	}{
		{"id", "a new rule's ID", RuleInput{ID: "Bad ID", Name: "R", MinUrgency: "high"}},
		{"name", "too long", RuleInput{ID: "r", Name: long, MinUrgency: "high"}},
		{"min_urgency", "pick the least urgency", RuleInput{ID: "r", Name: "R", MinUrgency: "panic"}},
		{"min_risk_score", "between 0 and 100000", RuleInput{ID: "r", Name: "R", MinUrgency: "high", MinRiskScore: -1}},
		{"detections", "is not a detection ID", RuleInput{ID: "r", Name: "R", MinUrgency: "high", Detections: []string{"ok", "", "ok", "a\x01"}}},
		{"detections", "at most 500", RuleInput{ID: "r", Name: "R", MinUrgency: "high", Detections: manyDetections()}},
	} {
		_, err := newManager(t).Save(Input{Rules: []RuleInput{c.r}})
		if ps := problemsOf(t, err); !hasProblem(ps, c.field, c.msg) {
			t.Errorf("rule %s %q: %v", c.field, c.msg, ps)
		}
	}
}

func second[T any](_ T, err error) error { return err }

func fieldFor(msg string) string {
	if strings.Contains(msg, "port") {
		return "url"
	}
	return "headers"
}

func manyHeaders() []HeaderInput {
	var h []HeaderInput
	for i := range MaxHeaders + 1 {
		h = append(h, HeaderInput{Name: fmt.Sprintf("X-H%d", i), Value: "v"})
	}
	return h
}

func manyDetections() []string {
	var d []string
	for i := range 501 {
		d = append(d, fmt.Sprintf("det-%d", i))
	}
	return d
}

func TestCheckChannel(t *testing.T) {
	m := newManager(t)
	saved := slackInput("slack-soc", "https://hooks.slack.com/services/T0/B0/slack-token-123")
	if _, err := m.Save(Input{Channels: []ChannelInput{saved}}); err != nil {
		t.Fatal(err)
	}
	// A saved channel is checked with its stored address.
	c, err := m.Check(ChannelInput{ID: "slack-soc", Name: "#soc", Type: TypeSlack})
	if err != nil || c.ID != "slack-soc" || c.URL == "" {
		t.Errorf("saved = %+v, %v", c, err)
	}
	// A new one gets a stand-in ID.
	c, err = m.Check(ChannelInput{Name: "#new", Type: TypeSlack, URL: "https://hooks.slack.com/services/T0/B0/other"})
	if err != nil || c.ID == "" {
		t.Errorf("new = %+v, %v", c, err)
	}
	if _, err := m.Check(ChannelInput{Name: "#new", Type: TypeSlack}); !hasProblem(problemsOf(t, err), "url", "") {
		t.Errorf("no URL = %v", err)
	}
	// A saved channel whose kind changes loses its secrets.
	if _, err := m.Check(ChannelInput{ID: "slack-soc", Name: "#soc", Type: TypeWebhook}); err == nil {
		t.Error("a webhook without an address passed")
	}

	data, err := os.ReadFile(m.File)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.File, []byte("channels: [unclosed"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := &Manager{File: m.File, Now: m.Now}
	if _, err := broken.Check(saved); err == nil {
		t.Error("a damaged file was ignored")
	}

	// A file that cannot be read says which, and how to fix it.
	dir := t.TempDir()
	unreadable := &Manager{File: dir, Now: m.Now}
	_, err = unreadable.Save(Input{})
	var fe *FileError
	if !errors.As(err, &fe) || fe.Path != dir || !strings.Contains(err.Error(), "could not be read") || errors.Unwrap(err) == nil {
		t.Errorf("unreadable = %v", err)
	}
	if _, _, err := Reseal([]byte("channels: [unclosed"), nil); err == nil || !strings.Contains(err.Error(), "not valid YAML") {
		t.Errorf("reseal damaged = %v", err)
	}
	boom := errors.New("no key")
	if _, _, err := Reseal(data, func(secrets.Stored) (string, error) { return "", boom }); !errors.Is(err, boom) {
		t.Errorf("reseal failure = %v", err)
	}
}
