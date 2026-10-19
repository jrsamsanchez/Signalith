package ticketing

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

func TestADFTextNodes(t *testing.T) {
	var doc any
	raw := `{"type":"doc","content":[
		{"type":"paragraph","content":[{"type":"text","text":"See "},{"type":"emoji","attrs":{"text":"🔥"}},{"type":"emoji","attrs":{"shortName":":ok:"}},
			{"type":"emoji","attrs":{}},{"type":"inlineCard","attrs":{"url":"https://example.com/a"}},{"type":"blockCard","attrs":{}}]},
		{"type":"bulletList","content":[{"type":"listItem","content":[{"type":"text","text":"one"}]},{"type":"listItem","content":[{"type":"text","text":"two"}]}]},
		{"type":"rule"}]}`
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	got := adfText(doc)
	for _, want := range []string{"See 🔥:ok:https://example.com/a", "one\n", "two"} {
		if !strings.Contains(got, want) {
			t.Errorf("text %q lacks %q", got, want)
		}
	}
	if CaseLink(" ", "c1") != "" || label("") != "none" || authorName("jira", " ") != "jira:someone" || truncateRunes("abcdef", 4) != "abc…" {
		t.Error("helpers")
	}
}

func TestTicketingFileErrors(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{File: dir}
	err := m.Load()
	var fe *FileError
	if !errors.As(err, &fe) || !strings.Contains(err.Error(), "could not be read") || errors.Unwrap(err) == nil {
		t.Errorf("unreadable = %v", err)
	}
	if _, _, err := Reseal([]byte("connections: [unclosed"), nil); err == nil || !strings.Contains(err.Error(), "not valid YAML") {
		t.Errorf("damaged = %v", err)
	}

	good := &Manager{File: filepath.Join(dir, "tickets.yaml")}
	if _, err := good.Save(Input{Connections: []ConnectionInput{jiraInput()}}); err != nil {
		t.Fatal(err)
	}
	if err := good.Load(); err != nil {
		t.Errorf("load = %v", err)
	}
	data, err := os.ReadFile(good.File)
	if err != nil {
		t.Fatal(err)
	}
	same := func(s secrets.Stored) (string, error) { return s.Value, nil }
	if out, n, err := Reseal(data, same); err != nil || n != 0 || string(out) != string(data) {
		t.Errorf("unchanged = %d %v", n, err)
	}
	boom := errors.New("no key")
	if _, _, err := Reseal(data, func(secrets.Stored) (string, error) { return "", boom }); !errors.Is(err, boom) {
		t.Errorf("failing = %v", err)
	}
}
