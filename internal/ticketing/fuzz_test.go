package ticketing

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/cases"
)

// The fuzz targets cover what reads answers from Jira and ServiceNow:
// error bodies, rich text and comments become messages and case notes.

func FuzzAPIMessage(f *testing.F) {
	for _, s := range []string{
		`{"errorMessages":["Issue does not exist"],"errors":{"priority":"cannot be set"}}`,
		`{"error":{"message":"No Record found","detail":"ACL"},"status":"failure"}`,
		`{"error":"access_denied"}`, `<html>Bad gateway</html>`, `plain text`, "\xff\xfe", `{"message":1}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		msg, _ := apiMessage(b)
		if strings.ContainsAny(msg, "\n\r") || utf8.RuneCountInString(msg) > 300 {
			t.Errorf("message %q", msg)
		}
	})
}

func FuzzBodyText(f *testing.F) {
	doc, _ := json.Marshal(adfDoc([]string{"Hello", "See https://siem.example.com/#cases?id=1", ""}))
	for _, s := range []string{string(doc), `"plain"`, `{"type":"doc","content":[{"type":"mention","attrs":{"text":"@dana"}}]}`,
		`{"type":"doc","content":[[[[[[]]]]]]}`, `null`, `42`, `{"content":{"x":1}}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = bodyText(b)
	})
}

func FuzzNoteText(f *testing.F) {
	for _, s := range []string{"hello\r\nworld", "\x00\x1b[31mred", "\xff", strings.Repeat("é", cases.MaxTextLen)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n := noteText(s)
		if !utf8.ValidString(n) || len(n) > cases.MaxTextLen || strings.ContainsRune(n, '\r') {
			t.Errorf("note %q", n)
		}
		_ = ours(s)
		_ = authorName(TypeJira, s)
	})
}

func TestADFRoundTrip(t *testing.T) {
	lines := []string{"Opened from Signalith case c1.", "Case: https://siem.example.com/#cases?id=c1", "", "two  spaces"}
	raw, _ := json.Marshal(adfDoc(lines))
	if got := bodyText(raw); got != strings.Join(lines, "\n") {
		t.Errorf("round trip %q", got)
	}
	if !strings.Contains(string(raw), `"type":"link"`) {
		t.Errorf("no link mark: %s", raw)
	}
}

func TestEchoMarkers(t *testing.T) {
	if !ours("  [Signalith] ann: x") || ours("Re: [Signalith] x") {
		t.Error("ours")
	}
	if !imported("jira:Dana") || !imported("servicenow:beth") || imported("ann") {
		t.Error("imported")
	}
	if got := noteComment(cases.Entry{Author: "ann", Text: "hi"}); got != "[Signalith] ann: hi" {
		t.Errorf("note comment %q", got)
	}
}

func TestStatusMapping(t *testing.T) {
	sn := Connection{Type: TypeServiceNow, Statuses: map[string]string{"pending": "-5"}}
	for st, want := range map[string]string{"new": "1", "in_progress": "2", "pending": "-5", "resolved": "6", "closed": "7"} {
		if got := sn.state(st); got != want {
			t.Errorf("state(%s) %s, want %s", st, got, want)
		}
		if back := sn.caseStatusFor(RemoteStatus{Name: want}); back != st {
			t.Errorf("caseStatusFor(%s) %s, want %s", want, back, st)
		}
	}
	if sn.caseStatusFor(RemoteStatus{Name: "8"}) != "closed" || !sn.agrees("closed", RemoteStatus{Name: "8"}) || sn.caseStatusFor(RemoteStatus{Name: "3"}) != "" {
		t.Error("canceled or unknown state")
	}
	j := Connection{Type: TypeJira, Statuses: map[string]string{"pending": "Blocked, Waiting"}}
	for _, c := range []struct {
		rs   RemoteStatus
		want string
	}{
		{RemoteStatus{"To Do", "new"}, "new"}, {RemoteStatus{"Doing", "indeterminate"}, "in_progress"},
		{RemoteStatus{"waiting", "indeterminate"}, "pending"}, {RemoteStatus{"Done", "done"}, "resolved"}, {RemoteStatus{"Odd", ""}, ""},
	} {
		if got := j.caseStatusFor(c.rs); got != c.want {
			t.Errorf("jira %v: %s, want %s", c.rs, got, c.want)
		}
	}
	if !j.agrees("closed", RemoteStatus{"Done", "done"}) || j.agrees("pending", RemoteStatus{"Doing", "indeterminate"}) {
		t.Error("jira agrees")
	}
	if i, u := impactUrgency("critical"); i != "1" || u != "1" {
		t.Error("impact")
	}
}
