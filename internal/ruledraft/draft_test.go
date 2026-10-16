package ruledraft

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/detect"
)

func builtins(t testing.TB) []*detect.Detection {
	t.Helper()
	ds, err := detect.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

func TestOfflineDraftsAWholeRule(t *testing.T) {
	dr, err := Offline("Alert me when more than 10 failed logins come from the same source in 5 minutes", nil, builtins(t))
	if err != nil {
		t.Fatal(err)
	}
	d := dr.Detection
	want := "datamodel=Authentication action=failure\n| stats count by src\n| where count>10\n| sort -count"
	if d.Query != want {
		t.Errorf("query %q, want %q", d.Query, want)
	}
	if d.Lookback != "5m" || d.Schedule != "5m" || d.Severity != "medium" || d.Enabled {
		t.Errorf("lookback %s schedule %s severity %s enabled %v", d.Lookback, d.Schedule, d.Severity, d.Enabled)
	}
	if len(d.MITRE) != 1 || d.MITRE[0] != "T1110" {
		t.Errorf("mitre %v", d.MITRE)
	}
	if d.Risk == nil || d.Risk.Score != 30 || len(d.Risk.Objects) != 1 || d.Risk.Objects[0] != (detect.RiskObject{Field: "src", Type: "system"}) {
		t.Errorf("risk %+v", d.Risk)
	}
	if strings.Join(d.Throttle.Fields, ",") != "src" || d.Throttle.Window != "1h" {
		t.Errorf("throttle %+v", d.Throttle)
	}
	if d.Title != "Password guessing from $src$" || d.ID != "password-guessing" {
		t.Errorf("title %q id %q", d.Title, d.ID)
	}
	if dr.Source != "rules" || len(dr.Steps) < 4 {
		t.Errorf("source %s steps %v", dr.Source, dr.Steps)
	}
	if len(dr.Similar) == 0 || dr.Similar[0].ID != "auth-brute-force" && dr.Similar[0].ID != "auth-brute-force-success" {
		t.Errorf("similar %+v", dr.Similar)
	}
}

func TestOfflineSeverityAndTechniques(t *testing.T) {
	for _, tc := range []struct {
		desc, severity string
		mitre          []string
		lookback       string
	}{
		{"encoded powershell on any host", "high", []string{"T1059.001", "T1027"}, "10m"},
		{"someone added to the domain admins group", "high", []string{"T1098"}, "10m"},
		{"rundll32 running from a temp folder, low severity", "low", []string{"T1218.011"}, "10m"},
		{"a user logging on to more than 5 hosts within an hour", "medium", nil, "1h"},
		{"failed logins in the last 24 hours by user over 20, priority critical", "critical", []string{"T1110"}, "24h"},
	} {
		dr, err := Offline(tc.desc, nil, nil)
		if err != nil {
			t.Errorf("%s: %v", tc.desc, err)
			continue
		}
		d := dr.Detection
		if d.Severity != tc.severity || strings.Join(d.MITRE, ",") != strings.Join(tc.mitre, ",") || d.Lookback != tc.lookback {
			t.Errorf("%s: severity %s mitre %v lookback %s; want %s %v %s", tc.desc, d.Severity, d.MITRE, d.Lookback, tc.severity, tc.mitre, tc.lookback)
		}
		if strings.Contains(d.Query, "earliest") || strings.Contains(d.Query, "severity") || strings.Contains(d.Query, "priority") {
			t.Errorf("%s: query %q", tc.desc, d.Query)
		}
	}
}

func TestOfflineCopiesTheLibraryWhenItUnderstandsLittle(t *testing.T) {
	lib := append(builtins(t), &detect.Detection{ID: "win-log-cleared", Title: "Security event log cleared on $dest$", Query: "datamodel=Change signature_id=1102",
		Schedule: "5m", Lookback: "10m", Severity: "high", MITRE: []string{"T1070.001"}, Source: "pack", Exceptions: []detect.Exception{{ID: "e1"}}})
	dr, err := Offline("security log cleared", nil, lib)
	if err != nil {
		t.Fatal(err)
	}
	d := dr.Detection
	if dr.Source != "library" || dr.BasedOn != "win-log-cleared" || d.Query != "datamodel=Change signature_id=1102" {
		t.Fatalf("source %s based on %s query %q", dr.Source, dr.BasedOn, d.Query)
	}
	if d.ID != "security-event-log-cleared-custom" || d.Enabled || len(d.Exceptions) != 0 || len(dr.Warnings) == 0 {
		t.Errorf("copy: id %s enabled %v exceptions %v warnings %v", d.ID, d.Enabled, d.Exceptions, dr.Warnings)
	}
	// The library's own detection is untouched.
	if lib[len(lib)-1].ID != "win-log-cleared" || len(lib[len(lib)-1].Exceptions) != 1 {
		t.Error("the library detection changed")
	}
}

func TestOfflineAlwaysValidates(t *testing.T) {
	lib := builtins(t)
	for _, desc := range []string{
		"x", "$dest$ $user$", "detect", "alert me", "in 5 minutes", "within 0 minutes", "over 999999 days",
		"powershell in 30 seconds", strings.Repeat("failed logins ", 60), "top 10 users with failed logins",
		"processes containing \"invoke-mimikatz\"", "connections to port 4444 over time", "ПАРОЛЬ 漢字 🚨",
	} {
		dr, err := Offline(desc, nil, lib)
		if err != nil {
			t.Errorf("%.40q: %v", desc, err)
			continue
		}
		if err := dr.Detection.Validate(); err != nil || dr.Detection.Enabled {
			t.Errorf("%.40q: %v enabled %v", desc, err, dr.Detection.Enabled)
		}
	}
	if _, err := Offline("  ", nil, lib); err == nil {
		t.Error("empty description accepted")
	}
	if _, err := Offline(strings.Repeat("a", MaxDescription+1), nil, lib); err == nil {
		t.Error("long description accepted")
	}
}

func TestCutWindow(t *testing.T) {
	for in, want := range map[string]string{
		"10 failures in 5 minutes":      "5m",
		"logons within an hour":         "1h",
		"over 2 days":                   "2d",
		"in 30 seconds":                 "1m",
		"in 90 sec":                     "2m",
		"in the morning":                "",
		"over 1000 days":                "",
		"in 0 minutes":                  "",
		"spikes within a 10 min window": "",
	} {
		if _, got, _ := cutWindow(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if text, _, _ := cutWindow("10 failures in 5 minutes from the same source"); text != "10 failures from the same source" {
		t.Errorf("text %q", text)
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{
		"Password guessing from $src$": "password-guessing",
		"$dest$":                       "dest",
		"!!":                           "custom-detection",
		"A very long title that goes on and on and on past the limit of an id": "a-very-long-title-that-goes-on-and-on-and-on",
	} {
		if got := Slug(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

type fakeModel struct {
	replies []string
	got     []string
}

func (f *fakeModel) Name() string { return "fake" }

func (f *fakeModel) Chat(ctx context.Context, system string, msgs []assistant.Message, maxTokens int) (string, error) {
	f.got = append(f.got, msgs[len(msgs)-1].Content)
	if len(f.replies) == 0 {
		return "", errors.New("no more replies")
	}
	r := f.replies[0]
	f.replies = f.replies[1:]
	return r, nil
}

func TestAIDraft(t *testing.T) {
	offline, _ := Offline("kerberoasting", nil, builtins(t))
	m := &fakeModel{replies: []string{
		`{"title": "Kerberoasting", "query": "| bad"}`,
		"Here it is:\n```json\n" + `{"title": "Kerberoasting by $user$", "description": "RC4 service tickets.", "query": "datamodel=Authentication signature_id=4769 ticket_encryption=0x17 earliest=-1h | stats dc(service) as services by user | where services > 5",
		 "schedule": "15m", "lookback": "1h", "severity": "HIGH", "mitre": ["T1558.003", "T9999"], "risk_score": 50,
		 "risk_objects": [{"field": "user", "type": "user"}], "group_by": ["user"], "guidance": "Check the user.", "notes": "Needs 4769 events."}` + "\n```",
	}}
	dr, err := AI(context.Background(), m, "kerberoasting", offline)
	if err != nil {
		t.Fatal(err)
	}
	d := dr.Detection
	if dr.Source != "ai" || d.Severity != "high" || d.Lookback != "1h" || strings.Contains(d.Query, "earliest") || d.Enabled {
		t.Errorf("draft %+v", d)
	}
	if strings.Join(d.MITRE, ",") != "T1558.003" || d.Risk == nil || d.Risk.Score != 50 || d.ID != "kerberoasting" {
		t.Errorf("mitre %v risk %+v id %s", d.MITRE, d.Risk, d.ID)
	}
	if len(dr.Warnings) != 2 {
		t.Errorf("warnings %v", dr.Warnings)
	}
	if len(m.got) != 2 || !strings.Contains(m.got[1], "problems") {
		t.Errorf("the bad reply was not sent back: %v", m.got)
	}
	if !strings.Contains(m.got[0], "Detect: kerberoasting") {
		t.Errorf("prompt %q", m.got[0])
	}

	m = &fakeModel{replies: []string{`not json`, `{"title": "", "query": "x"}`}}
	if _, err := AI(context.Background(), m, "x", nil); err == nil {
		t.Error("an invalid rule was accepted")
	}
}

func FuzzOffline(f *testing.F) {
	for _, s := range []string{"more than 10 failed logins from the same source in 5 minutes", "encoded powershell, high severity", "in 5 minutes", "$x$"} {
		f.Add(s)
	}
	lib := builtins(f)
	f.Fuzz(func(t *testing.T, desc string) {
		dr, err := Offline(desc, nil, lib)
		if err != nil || dr == nil {
			return
		}
		if err := dr.Detection.Validate(); err != nil {
			t.Fatalf("%q: draft does not validate: %v", desc, err)
		}
	})
}
