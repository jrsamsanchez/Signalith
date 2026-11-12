// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestExportThenImportDetections: Export gives every detection written
// here, turned off and without its exceptions, in a file that Import rule
// reads back; built-ins are left out, and reading saves nothing.
func TestExportThenImportDetections(t *testing.T) {
	ts, _ := newTestServer(t)
	mine := `{"id":"my-shared-rule","title":"Shared rule","query":"datamodel=Authentication action=failure | stats count by src","schedule":"5m","severity":"high","enabled":true,
		"exceptions":[{"id":"x1","match":{"src":"10.9.9.9"},"comment":"our scanner"}]}`
	if code, body := do(t, ts, "POST", "/api/detections", mine, true); code != 201 {
		t.Fatalf("create = %d %v", code, body)
	}

	get := func(path string) string {
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		req.SetBasicAuth("admin", "s3cret-pass")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Disposition"), "signalith-detections-") {
			t.Fatalf("export = %d %q %s", resp.StatusCode, resp.Header.Get("Content-Disposition"), b)
		}
		return string(b)
	}
	file := get("/api/detections?format=yaml")
	if !strings.Contains(file, "id: my-shared-rule") || !strings.Contains(file, "enabled: false") {
		t.Fatalf("export lacks the rule, turned off:\n%s", file)
	}
	if strings.Contains(file, "10.9.9.9") {
		t.Errorf("export kept an exception without being asked:\n%s", file)
	}
	if strings.Contains(file, "id: data-source-stopped") {
		t.Errorf("export holds a built-in detection")
	}
	if with := get("/api/detections?format=yaml&exceptions=true"); !strings.Contains(with, "10.9.9.9") {
		t.Errorf("exceptions=true dropped the exception:\n%s", with)
	}

	// The file read back: the rule is found, turned off and taken; a
	// second, new rule after it is free to add. A Sigma rule in the same
	// file is converted.
	file += "---\nid: another-rule\ntitle: Another\nquery: datamodel=Endpoint process_name=whoami.exe\nenabled: true\n" +
		"---\ntitle: Whoami\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    Image|endswith: '\\whoami.exe'\n  condition: sel\n"
	code, body := do(t, ts, "POST", "/api/detections/convert", file, true)
	rules, _ := body["rules"].([]any)
	if code != 200 || len(rules) != 3 {
		t.Fatalf("convert = %d %v", code, body)
	}
	first, second, third := rules[0].(map[string]any), rules[1].(map[string]any), rules[2].(map[string]any)
	if first["exists"] != true || first["format"] != "signalith" {
		t.Errorf("first rule = %v", first)
	}
	if second["exists"] == true || second["problems"] != nil || second["detection"].(map[string]any)["enabled"] != false {
		t.Errorf("second rule = %v", second)
	}
	if third["format"] != "sigma" {
		t.Errorf("third rule = %v", third)
	}
	if code, _ := do(t, ts, "GET", "/api/detections/another-rule", "", true); code != 404 {
		t.Errorf("reading the file saved a rule: %d", code)
	}

	// A rule with a problem says so; something that is no rule fails.
	_, body = do(t, ts, "POST", "/api/detections/convert", "id: X\ntitle: Bad\nquery: '*'\n", true)
	if rules, _ := body["rules"].([]any); len(rules) != 1 || rules[0].(map[string]any)["problems"] == nil {
		t.Errorf("bad id not reported: %v", body)
	}
	for _, bad := range []string{"", "hello: world\n", "- a\n- b\n", "id: x\nquery: '*'\nsurprise: 1\n"} {
		if code, body := do(t, ts, "POST", "/api/detections/convert", bad, true); code != 400 {
			t.Errorf("convert(%q) = %d %v", bad, code, body)
		}
	}
}
