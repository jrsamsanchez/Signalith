package endpoint

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint/checks"
)

func lines(t *testing.T, ls ...string) []json.RawMessage {
	t.Helper()
	out := make([]json.RawMessage, len(ls))
	for i, l := range ls {
		out[i] = json.RawMessage(l)
	}
	return out
}

func TestParseResultsInventoryAndAddresses(t *testing.T) {
	n := &Node{ID: "n1", Hostname: "web1", Platform: Linux}
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	b := ParseResults(n, lines(t,
		`{"name":"signalith_software","unixTime":1760356800,"decorations":{"hostname":"web1.corp"},`+
			`"diffResults":{"added":[{"name":"openssl","version":"3.0.2","vendor":"Ubuntu","package_type":"deb"}],"removed":[{"name":"telnet","version":"0.17"}]}}`,
		`{"name":"signalith_ports","unixTime":"1760356800","action":"added","columns":{"port":"22","transport":"tcp","process_name":"sshd"}}`,
		`{"name":"signalith_addresses","snapshot":[{"address":"192.0.2.10"},{"address":"2001:db8::1"}]}`,
		`"{\"name\":\"signalith_users\",\"action\":\"removed\",\"columns\":{\"username\":\"bob\"}}"`,
		`{"name":"pack_other_query","columns":{}}`,
		`not json`,
	), now)
	if b.Skipped != 2 {
		t.Errorf("Skipped = %d, want 2", b.Skipped)
	}
	if strings.Join(b.IPs, ",") != "192.0.2.10,2001:db8::1" {
		t.Errorf("IPs = %v", b.IPs)
	}
	if len(b.Events) != 4 {
		t.Fatalf("events = %d: %+v", len(b.Events), b.Events)
	}
	sw := b.Events[0]
	if sw.Model != "Inventory" || sw.Fields["inventory_type"] != "software" || sw.Fields["action"] != "added" ||
		sw.Fields["name"] != "openssl" || sw.Fields["dest"] != "web1.corp" || sw.Fields["signature"] != "Software installed" {
		t.Errorf("software = %+v", sw.Fields)
	}
	if !sw.Time.Equal(time.Unix(1760356800, 0)) {
		t.Errorf("time = %v", sw.Time)
	}
	if b.Events[1].Fields["signature"] != "Software removed" {
		t.Errorf("removed = %+v", b.Events[1].Fields)
	}
	port := b.Events[2]
	if port.Fields["dest_port"] != int64(22) || port.Fields["transport"] != "tcp" || port.Fields["signature"] != "Listening port opened" {
		t.Errorf("port = %+v", port.Fields)
	}
	if u := b.Events[3]; u.Fields["user"] != "bob" || u.Fields["action"] != "removed" || !u.Time.Equal(now) {
		t.Errorf("user = %+v %v", u.Fields, u.Time)
	}
}

func TestParseResultsFIM(t *testing.T) {
	linux := &Node{ID: "n1", Hostname: "web1", Platform: Linux}
	b := ParseResults(linux, lines(t,
		`{"name":"signalith_fim","action":"added","columns":{"target_path":"/etc/passwd","action":"UPDATED","sha256":"ABCD","size":"1024","uid":"0","time":"1760356801"}}`,
		`{"name":"signalith_fim","action":"added","columns":{"target_path":"/etc/cron.d/x","action":"DELETED","size":"0"}}`,
	), time.Now())
	if len(b.Events) != 2 {
		t.Fatalf("events = %+v", b.Events)
	}
	f := b.Events[0]
	if f.Model != "Filesystem" || f.Fields["file_path"] != "/etc/passwd" || f.Fields["file_name"] != "passwd" ||
		f.Fields["action"] != "modified" || f.Fields["file_hash"] != "abcd" || f.Fields["file_size"] != int64(1024) || f.Fields["user_id"] != "0" {
		t.Errorf("fim = %+v", f.Fields)
	}
	if !f.Time.Equal(time.Unix(1760356801, 0)) {
		t.Errorf("fim time = %v", f.Time)
	}
	if d := b.Events[1]; d.Fields["action"] != "deleted" || d.Fields["file_size"] != nil {
		t.Errorf("deleted = %+v", d.Fields)
	}

	win := &Node{ID: "n2", Hostname: "pc1", Platform: Windows}
	b = ParseResults(win, lines(t,
		`{"name":"signalith_fim","action":"added","columns":{"path":"C:\\Windows\\System32\\Tasks\\evil","old_path":"C:\\tmp\\evil","action":"FileRename_NewName"}}`,
	), time.Now())
	if len(b.Events) != 1 || b.Events[0].Fields["file_name"] != "evil" || b.Events[0].Fields["file_old_path"] != `C:\tmp\evil` {
		t.Fatalf("windows fim = %+v", b.Events)
	}
}

func TestFIMAction(t *testing.T) {
	for in, want := range map[string]string{
		"CREATED": "created", "MOVED_TO": "created", "FileCreation": "created",
		"DELETED": "deleted", "MOVED_FROM": "deleted", "FileDelete": "deleted",
		"FileRename_OldName": "renamed", "UPDATED": "modified", "ATTRIBUTES_MODIFIED": "modified",
	} {
		if got := fimAction(in); got != want {
			t.Errorf("fimAction(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseResultsChecks(t *testing.T) {
	c := checks.For(Linux)[0]
	n := &Node{ID: "n1", Hostname: "web1", Platform: Linux}
	b := ParseResults(n, lines(t,
		`{"name":"signalith_check_`+c.ID+`","unixTime":1760356800,"diffResults":{"added":[{"result":"fail","detail":"PermitRootLogin yes"}],"removed":[{"result":"pass","detail":""}]}}`,
		`{"name":"signalith_check_no-such-check","diffResults":{"added":[{"result":"pass"}]}}`,
		`{"name":"signalith_check_`+c.ID+`","diffResults":{"added":[{"result":"weird"}]}}`,
	), time.Now())
	if len(b.Checks) != 2 || len(b.Events) != 2 {
		t.Fatalf("checks = %+v events = %d", b.Checks, len(b.Events))
	}
	r := b.Checks[0]
	if r.ID != c.ID || r.Result != "fail" || r.Detail != "PermitRootLogin yes" {
		t.Errorf("check = %+v", r)
	}
	ev := b.Events[0]
	if ev.Model != "Configuration_Check" || ev.Fields["check_id"] != c.ID || ev.Fields["result"] != "fail" || ev.Fields["severity"] != c.Severity {
		t.Errorf("event = %+v", ev.Fields)
	}
	if c.RuleID != "" && (ev.Fields["rule_id"] != c.RuleID || ev.Fields["benchmark"] != "SCAP Security Guide") {
		t.Errorf("rule = %+v", ev.Fields)
	}
	if b.Checks[1].Result != "error" {
		t.Errorf("unknown result = %+v", b.Checks[1])
	}
}

func TestConfigSchedule(t *testing.T) {
	set := DefaultSettings()
	for _, p := range Platforms {
		raw, hash := Config(p, set)
		var cfg struct {
			Schedule  map[string]map[string]any `json:"schedule"`
			FilePaths map[string][]string       `json:"file_paths"`
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{"os", "users", "ports", "startup", "addresses", "software", "services", "fim"} {
			if _, ok := cfg.Schedule[QueryPrefix+q]; !ok {
				t.Errorf("%s: no %s query", p, q)
			}
		}
		if len(cfg.FilePaths["signalith"]) == 0 {
			t.Errorf("%s: no watched paths", p)
		}
		nchecks := 0
		for name := range cfg.Schedule {
			if strings.HasPrefix(name, QueryPrefix+qCheck) {
				nchecks++
			}
		}
		if nchecks != len(checks.For(p)) || nchecks == 0 {
			t.Errorf("%s: %d check queries, want %d", p, nchecks, len(checks.For(p)))
		}
		if _, h2 := Config(p, set); h2 != hash {
			t.Errorf("%s: hash not stable", p)
		}
	}

	off := DefaultSettings()
	off.FIM, off.Checks = false, false
	raw, h := Config(Linux, off)
	if _, h0 := Config(Linux, set); h0 == h {
		t.Error("hash did not change with the settings")
	}
	if strings.Contains(string(raw), "file_events") || strings.Contains(string(raw), "file_paths") || strings.Contains(string(raw), QueryPrefix+qCheck) {
		t.Errorf("FIM or checks still configured: %s", raw)
	}
}

func TestNormalizePlatform(t *testing.T) {
	for _, c := range [][3]string{
		{"ubuntu", "debian", Linux}, {"rhel", "", Linux}, {"windows", "", Windows},
		{"darwin", "", Darwin}, {"", "windows", Windows},
	} {
		if got := NormalizePlatform(c[0], c[1]); got != c[2] {
			t.Errorf("NormalizePlatform(%q, %q) = %q", c[0], c[1], got)
		}
	}
}

func TestSettingsValidate(t *testing.T) {
	s := DefaultSettings()
	s.FilePaths[Linux] = append(s.FilePaths[Linux], " /etc/%% ", "", "/opt/app/%%")
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.Join(s.FilePaths[Linux], "\n"), "/etc/%%"); n != 1 {
		t.Errorf("duplicates kept: %v", s.FilePaths[Linux])
	}
	for _, bad := range []map[string][]string{
		{Linux: {"etc/passwd"}},
		{Windows: {`Windows\System32`}},
		{"solaris": {"/etc"}},
		{Linux: {"/etc/\"x"}},
	} {
		s := DefaultSettings()
		s.FilePaths = bad
		if err := s.Validate(); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}
