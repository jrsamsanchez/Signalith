package ticketing

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

func jiraInput() ConnectionInput {
	return ConnectionInput{ID: "soc", Name: "SOC", Type: "jira", URL: "https://example.atlassian.net/", Auth: "cloud",
		Email: "bot@example.com", Token: "atlassian-token-0001", Project: "sec"}
}

func snInput() ConnectionInput {
	return ConnectionInput{Name: "Desk", Type: "servicenow", URL: "https://example.service-now.com", Auth: "oauth",
		ClientID: "cid", ClientSecret: "oauth-secret-0001"}
}

func TestSaveEncryptsSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tickets.yaml")
	m := &Manager{File: path}
	s, err := m.Save(Input{Connections: []ConnectionInput{jiraInput(), snInput()}})
	if err != nil {
		t.Fatal(err)
	}
	jc, sn := s.Connections[0], s.Connections[1]
	if jc.Project != "SEC" || jc.URL != "https://example.atlassian.net" || jc.IssueType != DefaultIssueType || !jc.SetPriority || !jc.SyncNotes || !jc.SyncStatus || jc.Priorities["critical"] != "Highest" {
		t.Errorf("jira defaults %+v", jc)
	}
	if sn.ID == "" || sn.Table != DefaultTable || sn.CommentField != DefaultCommentField || sn.CloseCode != DefaultCloseCode || sn.Statuses["resolved"] != "6" {
		t.Errorf("servicenow defaults %+v", sn)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "atlassian-token-0001") || strings.Contains(text, "oauth-secret-0001") || strings.Count(text, "enc:v") != 2 {
		t.Errorf("file holds plain secrets:\n%s", text)
	}
	// The page never gets them.
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), "atlassian-token-0001") || strings.Contains(string(b), "oauth-secret-0001") {
		t.Errorf("JSON holds secrets: %s", b)
	}

	// Read back by another manager, decrypted.
	m2 := &Manager{File: path}
	s2, err := m2.Settings()
	if err != nil || s2.Connections[0].Token != "atlassian-token-0001" || s2.Connections[1].ClientSecret != "oauth-secret-0001" {
		t.Fatalf("read back: %+v %v", s2, err)
	}
	if m2.Revision() != m.Revision() || m2.Fingerprint() != m.Fingerprint() || strings.Contains(m.Fingerprint(), "atlassian") {
		t.Error("revision or fingerprint differs after reading back")
	}

	// An empty secret keeps the saved one; the revision guards the save.
	rev := m.Revision()
	in := jiraInput()
	in.Token, in.Name = "", "SOC 2"
	s3, err := m.Save(Input{Revision: rev, Connections: []ConnectionInput{in, {ID: sn.ID, Name: "Desk", Type: "servicenow", URL: sn.URL, Auth: "oauth", ClientID: "cid"}}})
	if err != nil || s3.Connections[0].Token != "atlassian-token-0001" || s3.Connections[1].ClientSecret != "oauth-secret-0001" {
		t.Fatalf("keep secrets: %+v %v", s3, err)
	}
	if _, err := m.Save(Input{Revision: rev}); !errors.Is(err, ErrChanged) {
		t.Errorf("stale revision: %v", err)
	}
	if fp := m.Fingerprint(); fp == m2.Fingerprint() {
		t.Error("fingerprint did not change with the settings")
	}

	// A saved secret is not sent to another server.
	in.URL = "https://evil.example.com"
	_, err = m.Save(Input{Connections: []ConnectionInput{in}})
	var ie *InputError
	if !errors.As(err, &ie) || ie.Problems[0].Field != "token" || !strings.Contains(ie.Problems[0].Msg, "again") {
		t.Errorf("moved connection: %v", err)
	}
	// Nor with another way of signing in.
	in.URL, in.Auth = "https://example.atlassian.net", "bearer"
	if _, err := m.Save(Input{Connections: []ConnectionInput{in}}); !errors.As(err, &ie) {
		t.Errorf("changed auth kept the token: %v", err)
	}
}

func TestEmptyFingerprint(t *testing.T) {
	m := &Manager{File: filepath.Join(t.TempDir(), "none.yaml")}
	if fp := m.Fingerprint(); fp != "" {
		t.Errorf("fingerprint with no connections: %q", fp)
	}
}

func TestSaveChecksInput(t *testing.T) {
	m := &Manager{}
	for name, c := range map[string]struct {
		in    ConnectionInput
		field string
	}{
		"http":           {func() ConnectionInput { c := jiraInput(); c.URL = "http://example.atlassian.net"; return c }(), "url"},
		"metadata":       {func() ConnectionInput { c := jiraInput(); c.URL = "https://169.254.169.254"; return c }(), "url"},
		"no token":       {func() ConnectionInput { c := jiraInput(); c.Token = ""; return c }(), "token"},
		"sealed token":   {func() ConnectionInput { c := jiraInput(); c.Token = "enc:v1:abc"; return c }(), "token"},
		"token newline":  {func() ConnectionInput { c := jiraInput(); c.Token = "a\nb"; return c }(), "token"},
		"project":        {func() ConnectionInput { c := jiraInput(); c.Project = "1SEC"; return c }(), "project"},
		"no email":       {func() ConnectionInput { c := jiraInput(); c.Email = ""; return c }(), "email"},
		"type":           {func() ConnectionInput { c := jiraInput(); c.Type = "github"; return c }(), "type"},
		"auth":           {func() ConnectionInput { c := jiraInput(); c.Auth = "basic"; return c }(), "auth"},
		"name":           {func() ConnectionInput { c := jiraInput(); c.Name = ""; return c }(), "name"},
		"ca":             {func() ConnectionInput { c := jiraInput(); c.CAPEM = "not a cert"; return c }(), "ca_pem"},
		"table":          {func() ConnectionInput { c := snInput(); c.Table = "incident; drop"; return c }(), "table"},
		"state":          {func() ConnectionInput { c := snInput(); c.Statuses = map[string]string{"new": "one"}; return c }(), "statuses"},
		"comment field":  {func() ConnectionInput { c := snInput(); c.CommentField = "description"; return c }(), "comment_field"},
		"severity":       {func() ConnectionInput { c := snInput(); c.AutoMinSeverity = "huge"; return c }(), "auto_min_severity"},
		"no client id":   {func() ConnectionInput { c := snInput(); c.ClientID = ""; return c }(), "client_id"},
		"status control": {func() ConnectionInput { c := jiraInput(); c.Statuses = map[string]string{"new": "To\x00Do"}; return c }(), "statuses"},
	} {
		_, err := m.Save(Input{Connections: []ConnectionInput{c.in}})
		var ie *InputError
		if !errors.As(err, &ie) {
			t.Errorf("%s: saved (%v)", name, err)
			continue
		}
		found := false
		for _, p := range ie.Problems {
			found = found || p.Field == c.field
		}
		if !found {
			t.Errorf("%s: problems %+v, want field %s", name, ie.Problems, c.field)
		}
	}
	if _, err := m.Save(Input{Connections: []ConnectionInput{jiraInput(), jiraInput()}}); err == nil {
		t.Error("two connections with one ID are saved")
	}
}

func TestAutoSince(t *testing.T) {
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	m := &Manager{Now: func() time.Time { return now }}
	in := jiraInput()
	in.AutoCreate = true
	s, err := m.Save(Input{Connections: []ConnectionInput{in}})
	if err != nil || !s.Connections[0].AutoSince.Equal(now) {
		t.Fatalf("auto since %v %v", s.Connections[0].AutoSince, err)
	}
	now = now.Add(time.Hour)
	in.Token = ""
	s, err = m.Save(Input{Connections: []ConnectionInput{in}})
	if err != nil || !s.Connections[0].AutoSince.Equal(now.Add(-time.Hour)) {
		t.Errorf("auto since moved on a save: %v %v", s.Connections[0].AutoSince, err)
	}
}

func TestCheckUsesSavedSecret(t *testing.T) {
	m := &Manager{}
	if _, err := m.Save(Input{Connections: []ConnectionInput{jiraInput()}}); err != nil {
		t.Fatal(err)
	}
	in := jiraInput()
	in.Token = ""
	c, err := m.Check(in)
	if err != nil || c.Token != "atlassian-token-0001" {
		t.Errorf("check: %+v %v", c, err)
	}
	in.ID = ""
	if _, err := m.Check(in); err == nil {
		t.Error("a new connection is tested without a token")
	}
}

func TestBrokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tickets.yaml")
	if err := os.WriteFile(path, []byte("connections: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{File: path}
	var fe *FileError
	if _, err := m.Settings(); !errors.As(err, &fe) {
		t.Errorf("broken file: %v", err)
	}
	if _, err := m.Save(Input{Connections: []ConnectionInput{jiraInput()}}); !errors.As(err, &fe) {
		t.Errorf("save over a broken file: %v", err)
	}
	if m.Fingerprint() == "" {
		t.Error("a broken file has the fingerprint of none")
	}
	if err := os.WriteFile(path, []byte("connections: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Settings(); err != nil {
		t.Errorf("fixed file: %v", err)
	}
}

func TestResealAndOtherKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tickets.yaml")
	m := &Manager{File: path}
	if _, err := m.Save(Input{Connections: []ConnectionInput{jiraInput()}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fields []string
	out, n, err := Reseal(data, func(s secrets.Stored) (string, error) {
		fields = append(fields, s.Field)
		plain, err := secrets.Open(s.Field, s.Value)
		return "plain:" + plain, err
	})
	if err != nil || n != 1 || len(fields) != 1 || fields[0] != "ticketing_connections[soc].token" || !strings.Contains(string(out), "plain:atlassian-token-0001") || !strings.HasPrefix(string(out), "# Jira and ServiceNow") {
		t.Errorf("reseal %d %v %v:\n%s", n, fields, err, out)
	}

	// Another master key: the token stays encrypted, the connection says
	// so, and saving keeps the value as it was.
	prev := secrets.Default()
	secrets.SetDefault(secrets.NewKeyring(t.TempDir()))
	defer secrets.SetDefault(prev)
	m2 := &Manager{File: path}
	s, err := m2.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if bad := s.Connections[0].Undecrypted(); len(bad) != 1 {
		t.Errorf("undecrypted %v", bad)
	}
	in := jiraInput()
	in.Token, in.Name = "", "Renamed"
	if _, err := m2.Save(Input{Connections: []ConnectionInput{in}}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !strings.Contains(string(after), strings.TrimSpace(sealedToken(t, data))) {
		t.Error("an undecryptable token was not kept as it was")
	}
}

// sealedToken returns the token line's value in a ticketing file.
func sealedToken(t *testing.T, data []byte) string {
	t.Helper()
	for _, l := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "token: "); ok {
			return v
		}
	}
	t.Fatal("no token in the file")
	return ""
}
