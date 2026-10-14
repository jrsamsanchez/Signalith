package detect

import (
	"strings"
	"testing"
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
	// A ? is literal in Splunk, so such a rule is refused.
	q := []byte(strings.Replace(string(src), "reg.exe", "re?.exe", 1))
	if _, err := PackDetection(p, PackRule{ID: "splunk-x"}, q); err == nil {
		t.Error("? accepted")
	}
}
