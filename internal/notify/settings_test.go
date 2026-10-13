package notify

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/secrets"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "signalith-test-keys-")
	if err != nil {
		panic(err)
	}
	secrets.SetDefault(secrets.NewKeyring(dir))
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

var t0 = time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)

func finding(id, urgency, detection string, created time.Time) *findings.Finding {
	return &findings.Finding{ID: id, Title: "Finding " + id, DetectionID: detection, Severity: urgency, Urgency: urgency,
		Status: findings.StatusNew, Created: created, Updated: created}
}

func TestRuleMatches(t *testing.T) {
	r := Rule{Enabled: true, Channels: []string{"c"}, MinUrgency: "high", Since: t0}
	at := t0.Add(time.Minute)
	cases := []struct {
		name string
		rule func(Rule) Rule
		f    *findings.Finding
		want bool
	}{
		{"high matches high", nil, finding("a", "high", "d1", at), true},
		{"critical matches high", nil, finding("a", "critical", "d1", at), true},
		{"medium is below high", nil, finding("a", "medium", "d1", at), false},
		{"default least urgency is high", func(r Rule) Rule { r.MinUrgency = ""; return r }, finding("a", "medium", "d1", at), false},
		{"off", func(r Rule) Rule { r.Enabled = false; return r }, finding("a", "critical", "d1", at), false},
		{"raised before the rule was turned on", nil, finding("a", "critical", "d1", t0.Add(-time.Second)), false},
		{"other detection", func(r Rule) Rule { r.Detections = []string{"d2"}; return r }, finding("a", "high", "d1", at), false},
		{"listed detection", func(r Rule) Rule { r.Detections = []string{"d2", "d1"}; return r }, finding("a", "high", "d1", at), true},
		{"sample data is skipped", nil, func() *findings.Finding { f := finding("a", "high", "d1", at); f.Sample = "load1"; return f }(), false},
		{"sample data when asked for", func(r Rule) Rule { r.IncludeSample = true; return r },
			func() *findings.Finding { f := finding("a", "high", "d1", at); f.Sample = "load1"; return f }(), true},
		{"urgency falls back to severity", nil, func() *findings.Finding { f := finding("a", "", "d1", at); f.Severity = "critical"; return f }(), true},
		{"risk score below", func(r Rule) Rule { r.MinRiskScore = 80; return r },
			func() *findings.Finding {
				f := finding("a", "high", "d1", at)
				f.Result = map[string]any{"risk_score": 60.0}
				return f
			}(), false},
		{"risk score at", func(r Rule) Rule { r.MinRiskScore = 80; return r },
			func() *findings.Finding {
				f := finding("a", "high", "d1", at)
				f.Result = map[string]any{"risk_score": 80}
				return f
			}(), true},
		{"no risk score is not affected", func(r Rule) Rule { r.MinRiskScore = 80; return r }, finding("a", "high", "d1", at), true},
	}
	for _, c := range cases {
		rr := r
		if c.rule != nil {
			rr = c.rule(r)
		}
		if got := rr.Matches(c.f); got != c.want {
			t.Errorf("%s: Matches = %v", c.name, got)
		}
	}
}

func TestRuleSummary(t *testing.T) {
	s := Settings{Channels: []Channel{{ID: "s", Name: "#soc", Type: TypeSlack}, {ID: "e", Name: "SOC email", Type: TypeEmail}}}
	r := Rule{Name: "r", Enabled: true, Channels: []string{"s", "e"}, MinUrgency: "high"}
	if got := r.Summary(s); got != "High and critical findings from any detection go to Slack #soc and SOC email." {
		t.Errorf("summary %q", got)
	}
	r = Rule{MinUrgency: "critical", Detections: []string{"brute-force"}, Channels: []string{"e"}, MinRiskScore: 75.5, IncludeSample: true}
	if got := r.Summary(s); got != "Critical findings from brute-force with a risk score of 75.5 or more (when they have one) including sample data go to SOC email." {
		t.Errorf("summary %q", got)
	}
	r = Rule{MinUrgency: "medium", Detections: []string{"a", "b", "c", "d"}}
	if got := r.Summary(s); got != "Medium, high and critical findings from 4 detections go nowhere yet: pick a channel." {
		t.Errorf("summary %q", got)
	}
}

func newManager(t *testing.T) *Manager {
	t.Helper()
	return &Manager{File: filepath.Join(t.TempDir(), "notifications.yaml"), Now: func() time.Time { return t0 }}
}

func slackInput(id, url string) ChannelInput {
	return ChannelInput{ID: id, Name: "#soc", Type: TypeSlack, URL: url}
}

func TestSaveKeepsSecretsAndSealsThem(t *testing.T) {
	m := newManager(t)
	on := true
	in := Input{
		Channels: []ChannelInput{
			slackInput("slack-soc", "https://hooks.slack.com/services/T0/B0/slack-token-123"),
			{ID: "hook", Name: "SOAR", Type: TypeWebhook, URL: "https://soar.example.com/hook?token=query-secret-1",
				Headers: []HeaderInput{{Name: "Authorization", Value: "Bearer header-secret-1"}}, SigningSecret: "signing-secret-1"},
			{ID: "mail", Name: "SOC email", Type: TypeEmail, Host: "smtp.example.com", Username: "svc", Password: "mail-pass-1",
				From: "Signalith <signalith@example.com>", To: []string{"soc@example.com, lead@example.com"}},
		},
		Rules: []RuleInput{{ID: "r1", Name: "Urgent", Enabled: &on, Channels: []string{"slack-soc", "mail"}}},
	}
	s, err := m.Save(in)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := s.Channel("mail"); c.Port != 587 || c.Security != SecuritySTARTTLS || len(c.To) != 2 || c.From != `"Signalith" <signalith@example.com>` {
		t.Errorf("mail defaults %+v", c)
	}
	if s.Rules[0].Since != t0 || s.Rules[0].MinUrgency != "high" {
		t.Errorf("rule %+v", s.Rules[0])
	}
	raw, _ := os.ReadFile(m.File)
	for _, secret := range []string{"slack-token-123", "query-secret-1", "header-secret-1", "signing-secret-1", "mail-pass-1"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("file holds %s in plain text:\n%s", secret, raw)
		}
	}
	if n := strings.Count(string(raw), "enc:v1:"); n != 5 {
		t.Errorf("%d encrypted values:\n%s", n, raw)
	}

	// Read back by another manager: the secrets decrypt.
	m2 := &Manager{File: m.File}
	s2, err := m2.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := s2.Channel("hook"); c.URL != "https://soar.example.com/hook?token=query-secret-1" || c.Headers["Authorization"] != "Bearer header-secret-1" || c.SigningSecret != "signing-secret-1" {
		t.Errorf("read back %+v", c)
	}

	// Empty secrets keep the saved ones; renaming keeps the ID.
	rev := m2.Revision()
	in.Revision = rev
	in.Channels[0] = slackInput("slack-soc", "")
	in.Channels[0].Name = "SOC channel"
	in.Channels[1] = ChannelInput{ID: "hook", Name: "SOAR", Type: TypeWebhook, Headers: []HeaderInput{{Name: "Authorization"}}}
	in.Channels[2].Password = ""
	s3, err := m2.Save(in)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := s3.Channel("slack-soc"); c.URL != "https://hooks.slack.com/services/T0/B0/slack-token-123" || c.Name != "SOC channel" {
		t.Errorf("kept url %+v", c)
	}
	if c, _ := s3.Channel("hook"); c.Headers["Authorization"] != "Bearer header-secret-1" || c.SigningSecret != "signing-secret-1" {
		t.Errorf("kept webhook secrets %+v", c)
	}
	if c, _ := s3.Channel("mail"); c.Password != "mail-pass-1" {
		t.Errorf("kept password %+v", c)
	}
	// The old revision is refused now.
	if _, err := m2.Save(in); !errors.Is(err, ErrChanged) {
		t.Errorf("stale save: %v", err)
	}
}

func TestSecretsStayWithTheirServer(t *testing.T) {
	m := newManager(t)
	_, err := m.Save(Input{Channels: []ChannelInput{
		{ID: "hook", Name: "SOAR", Type: TypeWebhook, URL: "https://soar.example.com/hook",
			Headers: []HeaderInput{{Name: "X-Key", Value: "k3y-value"}}, SigningSecret: "sig-secret"},
		{ID: "mail", Name: "Mail", Type: TypeEmail, Host: "smtp.example.com", Username: "svc", Password: "pw-123456", From: "a@example.com", To: []string{"b@example.com"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Save(Input{Channels: []ChannelInput{
		{ID: "hook", Name: "SOAR", Type: TypeWebhook, URL: "https://elsewhere.example.net/hook", Headers: []HeaderInput{{Name: "X-Key"}}},
		{ID: "mail", Name: "Mail", Type: TypeEmail, Host: "smtp.other.example", Username: "svc", From: "a@example.com", To: []string{"b@example.com"}},
	}})
	var ie *InputError
	if !errors.As(err, &ie) {
		t.Fatalf("moved secrets: %v", err)
	}
	fields := map[string]bool{}
	for _, p := range ie.Problems {
		fields[p.Where+"."+p.Field] = true
	}
	for _, f := range []string{"channel:hook.headers", "channel:hook.signing_secret", "channel:mail.password"} {
		if !fields[f] {
			t.Errorf("no problem for %s: %v", f, ie.Problems)
		}
	}
}

func TestInputProblems(t *testing.T) {
	m := newManager(t)
	bad := []struct {
		name  string
		in    ChannelInput
		field string
	}{
		{"no name", ChannelInput{Type: TypeSlack, URL: "https://hooks.slack.com/x"}, "name"},
		{"bad type", ChannelInput{Name: "x", Type: "pager"}, "type"},
		{"no url", ChannelInput{Name: "x", Type: TypeTeams}, "url"},
		{"ftp url", ChannelInput{Name: "x", Type: TypeWebhook, URL: "ftp://example.com/"}, "url"},
		{"loopback url", ChannelInput{Name: "x", Type: TypeWebhook, URL: "http://127.0.0.1:9000/"}, "url"},
		{"localhost url", ChannelInput{Name: "x", Type: TypeWebhook, URL: "http://localhost:9000/"}, "url"},
		{"metadata url", ChannelInput{Name: "x", Type: TypeWebhook, URL: "http://169.254.169.254/latest", AllowLoopback: true}, "url"},
		{"looks encrypted", ChannelInput{Name: "x", Type: TypeWebhook, URL: "enc:v1:abc:def"}, "url"},
		{"reserved header", ChannelInput{Name: "x", Type: TypeWebhook, URL: "https://e.example/", Headers: []HeaderInput{{Name: "Host", Value: "v"}}}, "headers"},
		{"header line break", ChannelInput{Name: "x", Type: TypeWebhook, URL: "https://e.example/", Headers: []HeaderInput{{Name: "X-A", Value: "a\r\nX-B: b"}}}, "headers"},
		{"bad ca", ChannelInput{Name: "x", Type: TypeSlack, URL: "https://e.example/", CAPEM: "not a cert"}, "ca_pem"},
		{"no mail host", ChannelInput{Name: "x", Type: TypeEmail, From: "a@example.com", To: []string{"b@example.com"}}, "host"},
		{"plain to remote", ChannelInput{Name: "x", Type: TypeEmail, Host: "smtp.example.com", Security: SecurityNone, From: "a@example.com", To: []string{"b@example.com"}}, "security"},
		{"password without tls", ChannelInput{Name: "x", Type: TypeEmail, Host: "localhost", Security: SecurityNone, Username: "u", Password: "p", From: "a@example.com", To: []string{"b@example.com"}}, "security"},
		{"bad from", ChannelInput{Name: "x", Type: TypeEmail, Host: "smtp.example.com", From: "not an address", To: []string{"b@example.com"}}, "from"},
		{"injected from", ChannelInput{Name: "x", Type: TypeEmail, Host: "smtp.example.com", From: "a@example.com\r\nBcc: x@evil.example", To: []string{"b@example.com"}}, "from"},
		{"no to", ChannelInput{Name: "x", Type: TypeEmail, Host: "smtp.example.com", From: "a@example.com"}, "to"},
		{"bad id", ChannelInput{ID: "Bad ID!", Name: "x", Type: TypeSlack, URL: "https://e.example/"}, "id"},
	}
	for _, c := range bad {
		_, err := m.Save(Input{Channels: []ChannelInput{c.in}})
		var ie *InputError
		if !errors.As(err, &ie) {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		found := false
		for _, p := range ie.Problems {
			found = found || p.Field == c.field
		}
		if !found {
			t.Errorf("%s: problems %+v, want field %s", c.name, ie.Problems, c.field)
		}
	}
	// A plain relay on this machine is fine.
	if _, err := m.Save(Input{Channels: []ChannelInput{{Name: "relay", Type: TypeEmail, Host: "localhost", Security: SecurityNone, From: "a@example.com", To: []string{"b@example.com"}}}}); err != nil {
		t.Errorf("localhost relay: %v", err)
	}
	// Names are unique; rules need a channel that exists.
	on := true
	_, err := m.Save(Input{
		Channels: []ChannelInput{slackInput("aaa", "https://e.example/1"), slackInput("bbb", "https://e.example/2")},
		Rules:    []RuleInput{{Name: "r", Enabled: &on, Channels: []string{"nope"}}, {Name: "r", Enabled: &on}},
	})
	var ie *InputError
	if !errors.As(err, &ie) || len(ie.Problems) != 4 {
		t.Errorf("names and channels: %v", err)
	}
}

func TestRemovingAChannelTurnsItsOnlyRuleOff(t *testing.T) {
	m := newManager(t)
	on := true
	if _, err := m.Save(Input{
		Channels: []ChannelInput{slackInput("aaa", "https://e.example/1"), {ID: "bbb", Name: "other", Type: TypeSlack, URL: "https://e.example/2"}},
		Rules:    []RuleInput{{ID: "r1", Name: "only a", Enabled: &on, Channels: []string{"aaa"}}, {ID: "r2", Name: "both", Enabled: &on, Channels: []string{"aaa", "bbb"}}},
	}); err != nil {
		t.Fatal(err)
	}
	s, err := m.Save(Input{
		Channels: []ChannelInput{{ID: "bbb", Name: "other", Type: TypeSlack}},
		Rules:    []RuleInput{{ID: "r1", Name: "only a", Enabled: &on, Channels: []string{"aaa"}}, {ID: "r2", Name: "both", Enabled: &on, Channels: []string{"aaa", "bbb"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Rules[0].Enabled || len(s.Rules[0].Channels) != 0 || !s.Rules[1].Enabled || len(s.Rules[1].Channels) != 1 {
		t.Errorf("rules %+v", s.Rules)
	}
}

func TestRuleSinceMovesWhenTurnedOn(t *testing.T) {
	now := t0
	m := &Manager{File: filepath.Join(t.TempDir(), "n.yaml"), Now: func() time.Time { return now }}
	on, off := true, false
	ch := []ChannelInput{slackInput("aaa", "https://e.example/1")}
	s, _ := m.Save(Input{Channels: ch, Rules: []RuleInput{{ID: "r1", Name: "r", Enabled: &on, Channels: []string{"aaa"}}}})
	if !s.Rules[0].Since.Equal(t0) {
		t.Fatalf("since %v", s.Rules[0].Since)
	}
	now = t0.Add(time.Hour)
	s, _ = m.Save(Input{Channels: ch, Rules: []RuleInput{{ID: "r1", Name: "renamed", Enabled: &on, Channels: []string{"aaa"}}}})
	if !s.Rules[0].Since.Equal(t0) {
		t.Errorf("a change while on keeps since: %v", s.Rules[0].Since)
	}
	s, _ = m.Save(Input{Channels: ch, Rules: []RuleInput{{ID: "r1", Name: "renamed", Enabled: &off, Channels: []string{"aaa"}}}})
	now = t0.Add(2 * time.Hour)
	s, _ = m.Save(Input{Channels: ch, Rules: []RuleInput{{ID: "r1", Name: "renamed", Enabled: &on, Channels: []string{"aaa"}}}})
	if !s.Rules[0].Since.Equal(t0.Add(2 * time.Hour)) {
		t.Errorf("turned on again: since %v", s.Rules[0].Since)
	}
}

const plainFile = `channels:
  - id: hook
    name: SOAR
    type: webhook
    url: https://soar.example.com/hook
    headers:
      Authorization: Bearer plain-token
    signing_secret: plain-signing
  - id: mail
    name: Mail
    type: email
    host: smtp.example.com
    port: 587
    security: starttls
    username: svc
    password: plain-password
    from: a@example.com
    to: [b@example.com]
rules: []
`

// TestResealFile checks that Reseal encrypts every secret (and nothing
// else), that the server still reads plain values, and that a value that
// cannot be decrypted makes only its channel show a problem.
func TestResealFile(t *testing.T) {
	m := newManager(t)
	if err := os.WriteFile(m.File, []byte(plainFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := m.Settings(); err != nil || s.Channels[1].Password != "plain-password" {
		t.Fatalf("plain file: %v %+v", err, s)
	}
	var labels []string
	seal := func(s secrets.Stored) (string, error) { return secrets.Seal(s.Field, s.Value) }
	out, n, err := Reseal([]byte(plainFile), func(s secrets.Stored) (string, error) {
		labels = append(labels, s.Label+" as "+s.Field)
		return seal(s)
	})
	if err != nil || n != 4 {
		t.Fatalf("reseal: n=%d err=%v", n, err)
	}
	want := "channels[SOAR] URL as notify_channels[hook].url|channels[SOAR] signing secret as notify_channels[hook].signing_secret|" +
		"channels[SOAR] header Authorization as notify_channels[hook].headers.Authorization|channels[Mail] password as notify_channels[mail].password"
	if strings.Join(labels, "|") != want {
		t.Errorf("labels %q", labels)
	}
	if strings.Contains(string(out), "plain-") || !strings.HasPrefix(string(out), "# Notification channels") {
		t.Errorf("resealed:\n%s", out)
	}
	if again, n, _ := Reseal(out, seal); n != 0 || string(again) != string(out) {
		t.Error("resealing an encrypted file should change nothing")
	}
	if err := os.WriteFile(m.File, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := (&Manager{File: m.File}).Settings(); err != nil || s.Channels[0].Headers["Authorization"] != "Bearer plain-token" {
		t.Fatalf("encrypted file: %v %+v", err, s)
	}

	// Another master key: the secrets stay encrypted, and the channel
	// says what to do; saving keeps them as they are.
	other := secrets.NewKeyring(t.TempDir())
	if _, err := other.Seal("x", "make a key"); err != nil {
		t.Fatal(err)
	}
	prev := secrets.Default()
	secrets.SetDefault(other)
	defer secrets.SetDefault(prev)
	m3 := &Manager{File: m.File}
	s, err := m3.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if bad := s.Channels[1].Undecrypted(); len(bad) != 1 || bad[0] != "password" {
		t.Errorf("undecrypted %v", bad)
	}
	err = (&Senders{}).Send(t.Context(), s.Channels[1], TestMessage("", t0))
	if err == nil || !strings.Contains(err.Error(), "cannot be decrypted") {
		t.Errorf("send with an undecrypted secret: %v", err)
	}
}

func TestFileErrorBlocksSaving(t *testing.T) {
	m := newManager(t)
	if err := os.WriteFile(m.File, []byte("channels: [unclosed"), 0o600); err != nil {
		t.Fatal(err)
	}
	var fe *FileError
	if err := m.Load(); !errors.As(err, &fe) {
		t.Fatalf("load %v", err)
	}
	if _, err := m.Save(Input{}); !errors.As(err, &fe) {
		t.Errorf("save over a broken file: %v", err)
	}
	if m.Fingerprint() == "" {
		t.Error("a broken file has a fingerprint")
	}
	// Fixed by hand: picked up without a restart.
	os.WriteFile(m.File, []byte("channels: []\n"), 0o600)
	if err := m.Load(); err != nil {
		t.Errorf("fixed file: %v", err)
	}
	if m.Fingerprint() != "" {
		t.Error("an empty file has a fingerprint")
	}
}

func TestFingerprintLeavesSecretsOut(t *testing.T) {
	a, b := newManager(t), newManager(t)
	for i, m := range []*Manager{a, b} {
		url := "https://hooks.example.com/" + []string{"one-secret", "two-secret"}[i]
		if _, err := m.Save(Input{Channels: []ChannelInput{slackInput("aaa", url)}}); err != nil {
			t.Fatal(err)
		}
	}
	if a.Fingerprint() == "" || a.Fingerprint() != b.Fingerprint() {
		t.Error("fingerprints differ by secret value only")
	}
	if _, err := b.Save(Input{Channels: []ChannelInput{{ID: "aaa", Name: "renamed", Type: TypeSlack}}}); err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("a rename does not change the fingerprint")
	}
}
