package detect

import (
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func TestSplunkDetection(t *testing.T) {
	src := []byte(`name: Windows Test Thing
id: 11111111-2222-3333-4444-555555555555
author: Some Author, Splunk
type: TTP
status: production
description: A test.
known_false_positives: Admins.
mitre_attack_id:
  - T1562.001
finding:
  entity:
    field: user
    score: 70
search: |
  | tstats count from datamodel=Endpoint.Processes where Processes.process_name=reg.exe Processes.user!=SYSTEM by Processes.dest
  | ` + "`windows_test_thing_filter`\n")
	p := &Pack{Name: "splunk", Title: "Splunk Security Content", Format: "splunk", Source: "https://github.com/splunk/security_content", Version: "abc", License: "Apache-2.0", LicenseURL: "https://www.apache.org/licenses/LICENSE-2.0"}
	d, err := PackDetection(p, PackRule{ID: "splunk-windows-test-thing", File: "windows_test_thing.yml", Path: "detections/endpoint/windows_test_thing.yml"}, src)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"datamodel=Endpoint", "signature_id IN (1, 4688)", "process_name=reg.exe", "user=*", `user=*\SYSTEM`} {
		if !strings.Contains(d.Query, want) {
			t.Errorf("query %s lacks %s", d.Query, want)
		}
	}
	if d.Severity != "high" || d.Risk.Only || d.Risk.Score != 70 || d.Enabled || len(d.MITRE) != 1 || d.Origin.Author != "Some Author, Splunk" ||
		d.Origin.URL != "https://github.com/splunk/security_content/blob/abc/detections/endpoint/windows_test_thing.yml" || !strings.Contains(d.Guidance, "Admins") {
		t.Errorf("detection = %+v %+v", d, d.Origin)
	}

	// Anomalies only add risk.
	anomaly := []byte(strings.Replace(string(src), "type: TTP", "type: Anomaly", 1))
	if d, err := PackDetection(p, PackRule{ID: "splunk-x"}, anomaly); err != nil || !d.Risk.Only || d.Severity != "low" {
		t.Errorf("anomaly = %v %+v", err, d)
	}
	// A ? is literal in Splunk, so it is searched as a regular
	// expression.
	q := []byte(strings.Replace(string(src), "reg.exe", "re?.exe", 1))
	if d, err := PackDetection(p, PackRule{ID: "splunk-x"}, q); err != nil || !strings.Contains(d.Query, `process_name=~"(?is)^re\\?\\.exe$"`) {
		t.Errorf("? = %v %+v", err, d)
	}
	// regex and where match() stages keep the events they match.
	stages := map[string]string{
		`| regex process="(?i)reg\\.exe\\s+add"`:                            `process=~"(?i)reg\\.exe\\s+add"`,
		`| where match(process, "a\\d") AND match(process_path, "^C:\\\\")`: `process=~a\d AND process_path=~^C:\\`,
	}
	for stage, want := range stages {
		r := []byte(strings.Replace(string(src), "by Processes.dest\n", "by Processes.dest\n  | `drop_dm_object_name(Processes)`\n  "+stage+"\n", 1))
		d, err := PackDetection(p, PackRule{ID: "splunk-x"}, r)
		if err != nil || !strings.Contains(d.Query, want) {
			t.Errorf("%s: %v %+v", stage, err, d)
			continue
		}
		if q, err := query.Parse(d.Query); err != nil || q.String() != d.Query {
			t.Errorf("%s: does not parse back: %v", d.Query, err)
		}
	}
	// Lookarounds are not RE2, so such a rule is refused.
	r := []byte(strings.Replace(string(src), "by Processes.dest\n", "by Processes.dest\n  | regex process=\"(?<!x)y\"\n", 1))
	if _, err := PackDetection(p, PackRule{ID: "splunk-x"}, r); err == nil {
		t.Error("lookbehind accepted")
	}

	// A count with a limit counts each group over its span and the time
	// since the last run, and finds each group once a day.
	r = []byte(strings.Replace(string(src), "by Processes.dest\n", "by Processes.dest Processes.user _time span=1m\n  | where count >= 10\n", 1))
	d, err = PackDetection(p, PackRule{ID: "splunk-x"}, r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(d.Query, "\n| stats count by dest, user\n| where count>=10") || d.Schedule != "1m" || d.Lookback != "2m" ||
		d.Title != "Windows Test Thing on $dest$" || strings.Join(d.Throttle.Fields, ",") != "dest,user" || d.Throttle.Window != "24h" {
		t.Errorf("count = %s %+v", d.Query, d)
	}
	if q, err := query.Parse(d.Query); err != nil || q.String() != d.Query {
		t.Errorf("%s: does not parse back: %v %v", d.Query, err, q)
	}
	r = []byte(strings.Replace(string(src), "| tstats count from", "| tstats dc(Processes.process) as n from", 1))
	r = []byte(strings.Replace(string(r), "by Processes.dest\n", "by Processes.dest _time span=20m\n  | where n > 37\n", 1))
	if d, err := PackDetection(p, PackRule{ID: "splunk-x"}, r); err != nil || !strings.Contains(d.Query, "| stats count, dc(process) as n by dest\n| where n>37") ||
		d.Schedule != "5m" || d.Lookback != "25m" {
		t.Errorf("distinct count = %v %+v", err, d)
	}
}
