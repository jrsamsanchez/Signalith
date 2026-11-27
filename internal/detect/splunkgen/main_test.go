// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
	"github.com/jrsamsanchez/signalith/internal/splcheck"
)

// shipped is the pack splunkgen last wrote, the fixture the tests build a
// small security_content checkout from.
var shipped = filepath.Join("..", "packs", "splunk")

func TestWindowsSource(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"Sysmon EventID 1", true},
		{"Windows Event Log Security 4688", true},
		{"Sysmon EventID 1 AND Sysmon EventID 11", true},
		{"Sysmon EventID 1 AND  Sysmon EventID 11 ", true},
		{"Linux Auditd Execve", true},
		{"Sysmon EventID 1 AND CrowdStrike ProcessRollup2", false},
		{"Cisco NVM Flowdata", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := windowsSource(tc.in); got != tc.want {
			t.Errorf("windowsSource(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestShort(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain reason", "plain reason"},
		{`value "abc" is not supported`, "value … is not supported"},
		{"field Processes.process is unknown", "field … is unknown"},
		{strings.Repeat("x", 200), strings.Repeat("x", 90)},
	}
	for _, tc := range tests {
		if got := short(errors.New(tc.in)); got != tc.want {
			t.Errorf("short(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// A cut through a multi-byte character drops the broken piece.
	s := short(errors.New(strings.Repeat("x", 89) + "éééé"))
	if !strings.HasPrefix(s, strings.Repeat("x", 89)) || len(s) > 90 || strings.ContainsRune(s, '\uFFFD') {
		t.Errorf("short cut through a character: %q", s)
	}
}

func TestNewID(t *testing.T) {
	tests := []struct {
		name, stem, ruleID string
		used               map[string]bool
		want               string
	}{
		{"plain", "some_rule", "x", nil, "splunk-some-rule"},
		{"symbols", "Some.Rule--Name_", "x", nil, "splunk-some-rule-name"},
		{"taken", "some_rule", "abc-def-123", map[string]bool{"splunk-some-rule": true}, "splunk-some-rule-abcdef"},
	}
	for _, tc := range tests {
		used := tc.used
		if used == nil {
			used = map[string]bool{}
		}
		if got := newID(tc.stem, tc.ruleID, used); got != tc.want {
			t.Errorf("%s: newID = %q, want %q", tc.name, got, tc.want)
		}
	}
	long := strings.Repeat("abcdefghi_", 10)
	id := newID(long, "x", map[string]bool{})
	if len(id) > 64 || strings.HasSuffix(id, "-") || !strings.HasPrefix(id, "splunk-abcdefghi") {
		t.Errorf("long stem gives %q", id)
	}
	taken := newID(long, "0123456789", map[string]bool{id: true})
	if len(taken) > 64 || !strings.HasSuffix(taken, "-012345") {
		t.Errorf("long taken stem gives %q", taken)
	}
}

func TestClauseNote(t *testing.T) {
	if got := clauseNote("r.yml", 2000, nil); got != "r.yml: about 2000" {
		t.Errorf("clauseNote = %q", got)
	}
	if got := clauseNote("r.yml", 0, errors.New("boom")); got != "r.yml: boom" {
		t.Errorf("clauseNote with error = %q", got)
	}
}

func TestMarkMacros(t *testing.T) {
	macros := map[string]*splcheck.Macro{
		"a":                              {Name: "a", Definition: "x `b` y `missing`"},
		"b":                              {Name: "b", Definition: "`a` z"},
		"c":                              {Name: "c", Definition: "c"},
		"rule_filter":                    {Name: "rule_filter", Definition: "search *"},
		"security_content_summariesonly": {Name: "security_content_summariesonly", Definition: "summariesonly=true"},
	}
	used := map[string]bool{}
	markMacros("`a` | `security_content_summariesonly` | `rule_filter` | `unknown`", macros, used)
	if !used["a"] || !used["b"] || used["c"] || used["rule_filter"] || used["security_content_summariesonly"] || used["missing"] || len(used) != 2 {
		t.Errorf("used macros %v, want a and b", used)
	}
}

func TestReadLookups(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "lookups", "csv")
	if err := os.MkdirAll(csv, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"good.yml":     "name: good\nlookup_type: csv\nmatch_type:\n  - WILDCARD(domain)\n",
		"good.csv":     "domain,flag\n*.evil.example,1\n",
		"kv.yml":       "name: kv\nlookup_type: kvstore\n",
		"nocsv.yml":    "name: nocsv\nlookup_type: csv\n",
		"noname.yml":   "lookup_type: csv\n",
		"invalid.yml":  ": [\n",
		"badcsv.yml":   "name: badcsv\nlookup_type: csv\n",
		"badcsv.csv":   "",
		"ignored.txt":  "not a lookup",
		"another.yaml": "name: other\n",
	} {
		if err := os.WriteFile(filepath.Join(csv, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	lookups, errs, files := readLookups(dir)
	if lookups["good"] == nil || files["good"] != filepath.Join(csv, "good.yml") {
		t.Errorf("good lookup not read: %v %v", lookups, files)
	}
	if len(lookups) != 1 || len(files) != 1 {
		t.Errorf("lookups %v, want only good", lookups)
	}
	if err := errs["kv"]; err == nil || !strings.Contains(err.Error(), "kvstore") {
		t.Errorf("kv store lookup error %v", err)
	}
	if err := errs["nocsv"]; err == nil || !strings.Contains(err.Error(), "no CSV") {
		t.Errorf("lookup without a CSV: %v", err)
	}
	if errs["badcsv"] == nil {
		t.Error("empty CSV gives no error")
	}
	if _, ok := errs[""]; ok {
		t.Error("lookup without a name recorded")
	}
}

// copyFile copies src to dst, making dst's folder.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dst, data)
}

func writeFile(t *testing.T, dst string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestMain builds a small security_content checkout from rules of the
// shipped pack, of every category, and rules each skipped for a reason,
// runs the generator over it and checks the pack it writes.
func TestMainGeneratesPack(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	data, err := os.ReadFile(filepath.Join(shipped, "pack.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var p detect.Pack
	if err := yaml.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	// A few rules of each category, and every rule reading a lookup.
	root := t.TempDir()
	lookupFiles, _ := filepath.Glob(filepath.Join(shipped, "lookups", "*"))
	for _, f := range lookupFiles {
		copyFile(t, f, filepath.Join(root, "lookups", "csv", filepath.Base(f)))
	}
	fixLookups, fixLookupErrs, _ := readLookups(root)
	fixMacros := map[string]*splcheck.Macro{}
	macroFiles, _ := filepath.Glob(filepath.Join(shipped, "macros", "*.yml"))
	for _, f := range macroFiles {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m, err := splcheck.ParseMacro(src); err == nil {
			fixMacros[m.Name] = m
		}
	}
	perCategory, lookupRules := map[string]int{}, 0
	var picked []detect.PackRule
	for _, r := range p.Rules {
		cat := strings.Split(r.Path, "/")[1]
		src, err := os.ReadFile(filepath.Join(shipped, "rules", r.File))
		if err != nil {
			t.Fatal(err)
		}
		// Rules that count events take long to synthesize test events
		// for; the others cover the same paths.
		rule, err := splcheck.ParseWith(src, fixMacros, splcheck.ParseOptions{Network: detect.SplunkNetworkRule(r.Path), Lookups: fixLookups, LookupErrors: fixLookupErrs})
		if err != nil || rule.Threshold != nil || rule.Post != "" && len(rule.Lookups) == 0 {
			continue
		}
		if len(rule.Lookups) > 0 && lookupRules < 3 || len(rule.Lookups) == 0 && perCategory[cat] < 3 {
			perCategory[cat]++
			if len(rule.Lookups) > 0 {
				lookupRules++
			}
			picked = append(picked, r)
		}
	}
	for _, r := range picked {
		copyFile(t, filepath.Join(shipped, "rules", r.File), filepath.Join(root, filepath.FromSlash(r.Path)))
	}
	for _, f := range macroFiles {
		copyFile(t, f, filepath.Join(root, "macros", filepath.Base(f)))
	}
	writeFile(t, filepath.Join(root, "macros", "broken.yml"), []byte("definition: x\n"))
	writeFile(t, filepath.Join(root, "LICENSE"), []byte("Apache License\n"))

	// Rules left out, one for each reason the fixture can give.
	endpoint := filepath.Join(root, "detections", "endpoint")
	lsass, err := os.ReadFile(filepath.Join(shipped, "rules", "access_lsass_memory_for_dump_creation.yml"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(endpoint, "zz_invalid.yml"), []byte("name: [\n"))
	writeFile(t, filepath.Join(endpoint, "zz_experimental.yml"), []byte(strings.Replace(string(lsass), "status: production", "status: experimental", 1)))
	writeFile(t, filepath.Join(endpoint, "zz_hunting.yml"), []byte(strings.Replace(string(lsass), "type: TTP", "type: Hunting", 1)))
	writeFile(t, filepath.Join(endpoint, "zz_other_source.yml"), []byte(strings.Replace(string(lsass), "- Sysmon EventID 10", "- CrowdStrike ProcessRollup2", 1)))
	writeFile(t, filepath.Join(endpoint, "zz_unconvertible.yml"), []byte(strings.Replace(string(lsass), "EventCode=10 ", "EventCode=10 | transaction dest | search ", 1)))
	// A Sysmon search among the network rules is endpoint content.
	writeFile(t, filepath.Join(root, "detections", "network", "zz_sysmon.yml"), lsass)
	// A cloud rule over a log the pack does not read is not looked at.
	writeFile(t, filepath.Join(root, "detections", "cloud", "zz_gcp.yml"), []byte("name: x\nsearch: '`google_gcp_pubsub_message` x=1'\n"))

	for _, args := range [][]string{
		{"init", "-q"},
		{"-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "x"},
	} {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v: %v: %s", args, err, out)
		}
	}

	out := t.TempDir()
	keep := picked[0]
	prev := detect.Pack{Name: "splunk", Rules: []detect.PackRule{{ID: "splunk-kept-id", RuleID: keep.RuleID, File: keep.File, Path: keep.Path}}}
	pb, err := yaml.Marshal(prev)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(out, "pack.yaml"), pb)
	writeFile(t, filepath.Join(out, "rules", "stale.yml"), []byte("x"))
	// Recorded events of the earlier tests are kept.
	var withRecorded string
	for _, r := range picked {
		stem := strings.TrimSuffix(r.File, ".yml")
		tdata, err := os.ReadFile(filepath.Join(shipped, "tests", stem+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if withRecorded == "" && strings.Contains(string(tdata), `"source":"attack_data"`) {
			withRecorded = stem
			writeFile(t, filepath.Join(out, "tests", stem+".json"), tdata)
		}
	}

	oldSplunk, oldOut := *splunkDir, *outDir
	*splunkDir, *outDir = root, out
	defer func() { *splunkDir, *outDir = oldSplunk, oldOut }()
	main()

	data, err = os.ReadFile(filepath.Join(out, "pack.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "# Generated by go run ./internal/detect/splunkgen") {
		t.Error("pack.yaml has no generated header")
	}
	var got detect.Pack
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "splunk" || got.Format != "splunk" || got.License != "Apache-2.0" || len(got.Version) != 40 || got.Date == "" {
		t.Errorf("pack header %+v", got)
	}
	if len(got.Rules) < len(picked)*9/10 || len(got.Rules) > len(picked) {
		t.Errorf("%d rules shipped of the %d picked", len(got.Rules), len(picked))
	}
	byRule := map[string]detect.PackRule{}
	for i, r := range got.Rules {
		byRule[r.RuleID] = r
		if i > 0 && got.Rules[i-1].ID >= r.ID {
			t.Errorf("rules not sorted by ID: %s before %s", got.Rules[i-1].ID, r.ID)
		}
		if _, err := os.Stat(filepath.Join(out, "rules", r.File)); err != nil {
			t.Errorf("rule file: %v", err)
		}
		if _, err := os.Stat(filepath.Join(out, "tests", strings.TrimSuffix(r.File, ".yml")+".json")); err != nil {
			t.Errorf("test file: %v", err)
		}
	}
	if r := byRule[keep.RuleID]; r.ID != "splunk-kept-id" {
		t.Errorf("earlier rule ID not kept: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(out, "rules", "stale.yml")); !os.IsNotExist(err) {
		t.Errorf("stale rule file left: %v", err)
	}
	if withRecorded != "" {
		tdata, err := os.ReadFile(filepath.Join(out, "tests", withRecorded+".json"))
		if err != nil {
			t.Fatal(err)
		}
		tf, err := sigmacheck.DecodeTestFile(tdata)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, c := range tf.Cases {
			if c.Source == splcheck.AttackDataSource {
				n++
			}
		}
		if n == 0 {
			t.Errorf("%s: recorded events not kept", withRecorded)
		}
	}
	if lic, err := os.ReadFile(filepath.Join(out, "LICENSE")); err != nil || string(lic) != "Apache License\n" {
		t.Errorf("LICENSE %q, %v", lic, err)
	}
	if ms, _ := filepath.Glob(filepath.Join(out, "macros", "*.yml")); len(ms) == 0 {
		t.Error("no macros written")
	}
	if ls, _ := filepath.Glob(filepath.Join(out, "lookups", "*.csv")); len(ls) == 0 {
		t.Error("no lookups written")
	}
	report, err := os.ReadFile(filepath.Join(out, "REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"# Splunk Security Content pack report",
		"rules shipped",
		"## not valid YAML\n\n- detections/endpoint/zz_invalid.yml",
		"## status experimental",
		"## type Hunting (not TTP or Anomaly)",
		"## no Windows Sysmon or Security log data source\n\n- detections/endpoint/zz_other_source.yml",
		"detections/endpoint/zz_unconvertible.yml",
		"## network detection that is not a tstats search of connections or DNS lookups\n\n- detections/network/zz_sysmon.yml",
	} {
		if !strings.Contains(string(report), want) {
			t.Errorf("REPORT.md lacks %q:\n%s", want, report)
		}
	}
	if strings.Contains(string(report), "zz_gcp") {
		t.Error("a cloud rule over another log is in the report")
	}
}

func TestWriteReport(t *testing.T) {
	out := t.TempDir()
	old := *outDir
	*outDir = out
	defer func() { *outDir = old }()
	p := &detect.Pack{Version: "abc", Date: "d", Rules: []detect.PackRule{{ID: "x"}}}
	writeReport(p, map[string][]string{
		"b reason":      {"z.yml", "a.yml"},
		"a reason":      {"c.yml"},
		"pipe | reason": {"p.yml"},
		"most":          {"1.yml", "2.yml", "3.yml"},
	})
	data, err := os.ReadFile(filepath.Join(out, "REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, "commit `abc` on d") || !strings.Contains(s, "1 rules shipped. 7 endpoint") {
		t.Errorf("report header:\n%s", s)
	}
	// Reasons by count, then name; files sorted; pipes escaped.
	order := []string{"| 3 | most |", "| 2 | b reason |", "| 1 | a reason |", `| 1 | pipe \| reason |`, "## b reason\n\n- a.yml\n- z.yml"}
	last := -1
	for _, o := range order {
		i := strings.Index(s, o)
		if i < 0 || i < last {
			t.Errorf("report lacks %q in order:\n%s", o, s)
		}
		last = i
	}
}
