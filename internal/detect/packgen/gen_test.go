// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

func TestNewID(t *testing.T) {
	long := strings.Repeat("abcdefghij_", 10)
	tests := []struct {
		name, stem, ruleID string
		used               map[string]bool
		want               string
	}{
		{"generic", "some_rule", "x", nil, "sigma-some-rule"},
		{"windows process", "proc_creation_win_7zip_exfil", "x", nil, "sigma-proc-7zip-exfil"},
		{"linux process", "proc_creation_lnx_curl", "x", nil, "sigma-lnx-proc-curl"},
		{"registry set", "registry_set_run_key", "x", nil, "sigma-reg-set-run-key"},
		{"zeek", "zeek_dns_txt", "x", nil, "sigma-zeek-dns-txt"},
		{"upper case and symbols", "Some.Rule--Name", "x", nil, "sigma-some-rule-name"},
		{"taken", "some_rule", "abc-def-123", map[string]bool{"sigma-some-rule": true}, "sigma-some-rule-abcdef"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			used := tc.used
			if used == nil {
				used = map[string]bool{}
			}
			if got := newID(tc.stem, tc.ruleID, used); got != tc.want {
				t.Errorf("newID(%q) = %q, want %q", tc.stem, got, tc.want)
			}
		})
	}
	id := newID(long, "x", map[string]bool{})
	if len(id) > 64 || strings.HasSuffix(id, "-") || !strings.HasPrefix(id, "sigma-abcdefghij") {
		t.Errorf("long stem gives %q (%d chars)", id, len(id))
	}
	taken := newID(long, "0123456789", map[string]bool{id: true})
	if len(taken) > 64 || !strings.HasSuffix(taken, "-012345") || taken == id {
		t.Errorf("long taken stem gives %q (%d chars)", taken, len(taken))
	}
}

func TestShort(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain reason", "plain reason"},
		{`value "abc" is bad (in rule x)`, "value … is bad"},
		{`modifier 'x' unknown`, "modifier … unknown"},
		{"CommandLine|re: has a regular expression", "has a regular expression"},
		{"field Image has no value", "a field has no value"},
		{strings.Repeat("x", 200), strings.Repeat("x", 90)},
	}
	for _, tc := range tests {
		if got := short(errors.New(tc.in)); got != tc.want {
			t.Errorf("short(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSeed(t *testing.T) {
	a, b := seed("rule-a"), seed("rule-b")
	if a != seed("rule-a") {
		t.Error("seed is not stable")
	}
	if a == b {
		t.Error("different rules have the same seed")
	}
	if a < 0 || b < 0 {
		t.Errorf("seeds %d, %d are negative", a, b)
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

func TestNetworkCategory(t *testing.T) {
	tests := []struct {
		name string
		ls   map[string]string
		cat  string
		want string
	}{
		{"zeek service", map[string]string{"product": "zeek", "service": "DNS"}, "zeek", sigmacheck.ZeekCategoryPrefix + "dns"},
		{"zeek without service", map[string]string{"product": "zeek"}, "zeek", ""},
		{"zeek with category", map[string]string{"product": "zeek", "service": "dns", "category": "dns"}, "zeek", ""},
		{"not zeek in zeek folder", map[string]string{"product": "windows", "service": "dns"}, "zeek", ""},
		{"generic dns", map[string]string{"category": "dns"}, "dns", "dns"},
		{"dns from zeek", map[string]string{"category": "dns", "product": "zeek"}, "dns", "dns"},
		{"dns from another product", map[string]string{"category": "dns", "product": "windows"}, "dns", ""},
		{"dns with service", map[string]string{"category": "dns", "service": "x"}, "dns", ""},
		{"other category", map[string]string{"category": "proxy"}, "firewall", ""},
	}
	for _, tc := range tests {
		if got := networkCategory(tc.ls, tc.cat); got != tc.want {
			t.Errorf("%s: networkCategory = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestUnreadFoldersMissingRoot(t *testing.T) {
	if _, _, err := unreadFolders(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Error("a missing checkout gives no error")
	}
}

func TestRegression(t *testing.T) {
	root := t.TempDir()
	src, err := os.ReadFile(filepath.Join("..", "packs", "sigmahq", "rules", "proc_creation_win_7zip_exfil_dmp_files.yml"))
	if err != nil {
		t.Fatal(err)
	}
	rule, err := sigmacheck.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	rel := "rules/windows/process_creation/proc_creation_win_7zip_exfil_dmp_files.yml"
	writeRegression(t, root, rel)
	got := regression(root, rel, rule, "process_creation")
	if len(got) != 2 {
		t.Fatalf("%d regression cases, want 2: %+v", len(got), got)
	}
	for _, c := range got {
		if !c.Expect || c.Source != "sigmahq" || c.EventID != "1" || c.Channel != sigmacheck.Channel("process_creation") {
			t.Errorf("case %+v", c)
		}
		if c.Data["ProcessId"] != "42" {
			t.Errorf("numeric field = %q, want 42", c.Data["ProcessId"])
		}
		if _, ok := c.Data["Empty"]; ok {
			t.Error("null field kept")
		}
	}
	if got[1].Data["Extra"] != `{"a":1}` {
		t.Errorf("object field = %q", got[1].Data["Extra"])
	}
	if none := regression(root, "rules/windows/process_creation/other.yml", rule, "process_creation"); len(none) != 0 {
		t.Errorf("a rule without recordings has %d cases", len(none))
	}
}

// writeRegression writes SigmaHQ-style recorded events for the 7-Zip rule:
// two it matches (one with an XML-style event ID), one it does not, one
// from another channel, and one event ID Sysmon does not use for process
// starts.
func writeRegression(t *testing.T, root, rel string) {
	t.Helper()
	dir := filepath.Join(root, "regression_data", filepath.FromSlash(strings.TrimSuffix(rel, ".yml")))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	ch := sigmacheck.Channel("process_creation")
	ev := func(channel string, id any, data map[string]any) string {
		b, err := json.Marshal(map[string]any{"Event": map[string]any{
			"System":    map[string]any{"Channel": channel, "EventID": id},
			"EventData": data,
		}})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	lines := []string{
		ev(ch, 1.0, map[string]any{"Image": `C:\Tools\7z.exe`, "CommandLine": `7z a out.7z lsass.dmp`, "ProcessId": 42.0, "Empty": nil}),
		ev(ch, map[string]any{"#text": "1"}, map[string]any{"Image": `C:\Tools\7za.exe`, "CommandLine": `7za a x.dump`, "ProcessId": 42.0, "Extra": map[string]any{"a": 1}}),
		ev(ch, 1.0, map[string]any{"Image": `C:\Tools\7z.exe`, "CommandLine": `7z a out.7z notes.txt`}),
		ev("Application", 1.0, map[string]any{"Image": `C:\Tools\7z.exe`, "CommandLine": `7z a x.dmp`}),
		ev(ch, 3.0, map[string]any{"Image": `C:\Tools\7z.exe`, "CommandLine": `7z a x.dmp`}),
	}
	if err := os.WriteFile(filepath.Join(dir, "events.json"), []byte(strings.Join(lines, "\n")+"\nnot json"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestMainBuildsPack runs packgen end to end on a small checkout made of
// one shipped rule from each folder of the SigmaHQ pack, plus rules it
// must leave out, and checks the pack, its tests and its report.
func TestMainBuildsPack(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	packDir := filepath.Join("..", "packs", "sigmahq")
	data, err := os.ReadFile(filepath.Join(packDir, "pack.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var real detect.Pack
	if err := yaml.Unmarshal(data, &real); err != nil {
		t.Fatal(err)
	}
	sort.Slice(real.Rules, func(i, j int) bool { return real.Rules[i].Path < real.Rules[j].Path })
	root := t.TempDir()
	write := func(rel string, b []byte) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// One shipped rule per folder.
	var picked []detect.PackRule
	seen := map[string]bool{}
	for _, r := range real.Rules {
		d := path.Dir(r.Path)
		if seen[d] {
			continue
		}
		seen[d] = true
		src, err := os.ReadFile(filepath.Join(packDir, "rules", r.File))
		if err != nil {
			t.Fatal(err)
		}
		write(r.Path, src)
		picked = append(picked, r)
	}
	var sevenZip string
	for _, r := range real.Rules {
		if r.File == "proc_creation_win_7zip_exfil_dmp_files.yml" {
			src, err := os.ReadFile(filepath.Join(packDir, "rules", r.File))
			if err != nil {
				t.Fatal(err)
			}
			write(r.Path, src)
			writeRegression(t, root, r.Path)
			if !seen[r.Path] {
				picked = append(picked, r)
			}
			sevenZip = r.ID
		}
	}
	if sevenZip == "" {
		t.Fatal("the 7-Zip rule is not in the pack")
	}
	// Rules to leave out, each for its own reason.
	rule := func(id, status, level, product, detection string) []byte {
		return []byte("title: t\nid: " + id + "\nstatus: " + status + "\nlevel: " + level +
			"\nlogsource:\n    category: process_creation\n    product: " + product + "\ndetection:\n" + detection)
	}
	sel := "    sel:\n        Image|endswith: '\\x.exe'\n    condition: sel\n"
	proc := "rules/windows/process_creation/"
	write(proc+"zz_bad_yaml.yml", []byte("title: [unclosed\n"))
	write(proc+"zz_no_detection.yml", []byte("title: t\nid: 1\n"))
	write(proc+"zz_deprecated.yml", rule("00000000-0000-0000-0000-000000000001", "deprecated", "high", "windows", sel))
	write(proc+"zz_informational.yml", rule("00000000-0000-0000-0000-000000000002", "test", "informational", "windows", sel))
	write(proc+"zz_linux.yml", rule("00000000-0000-0000-0000-000000000003", "test", "high", "linux", sel))
	// A folder packgen does not read, with a note, and one without.
	write("rules/linux/builtin/syslog_rule.yml", []byte("title: t\n"))
	write("rules-threat-hunting/windows/hunt.yml", []byte("title: t\n"))

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
	// An earlier manifest whose rule IDs must be kept: the first rule
	// picked, under a new ID.
	keep := picked[0]
	prev := detect.Pack{Name: "sigmahq", Rules: []detect.PackRule{{ID: "sigma-kept-id", RuleID: keep.RuleID, File: keep.File, Path: keep.Path}}}
	pb, err := yaml.Marshal(prev)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "pack.yaml"), pb, 0o644); err != nil {
		t.Fatal(err)
	}
	// Stale files from an earlier run are removed.
	if err := os.MkdirAll(filepath.Join(out, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "rules", "stale.yml"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldSigma, oldOut := *sigmaDir, *outDir
	*sigmaDir, *outDir = root, out
	defer func() { *sigmaDir, *outDir = oldSigma, oldOut }()
	main()

	data, err = os.ReadFile(filepath.Join(out, "pack.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var got detect.Pack
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "sigmahq" || got.License != "DRL-1.1" || got.Version == "" || got.Date == "" {
		t.Errorf("pack header %+v", got)
	}
	byRule := map[string]detect.PackRule{}
	for _, r := range got.Rules {
		byRule[r.RuleID] = r
	}
	if len(got.Rules) < len(picked)*9/10 {
		t.Errorf("%d of %d shipped rules shipped again", len(got.Rules), len(picked))
	}
	if r := byRule[keep.RuleID]; r.ID != "sigma-kept-id" {
		t.Errorf("earlier rule ID not kept: %+v", r)
	}
	for _, r := range got.Rules {
		if _, err := os.Stat(filepath.Join(out, "rules", r.File)); err != nil {
			t.Errorf("rule file: %v", err)
		}
		stem := strings.TrimSuffix(r.File, ".yml")
		if _, err := os.Stat(filepath.Join(out, "tests", stem+".json")); err != nil {
			t.Errorf("test file: %v", err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "rules", "stale.yml")); !os.IsNotExist(err) {
		t.Errorf("stale rule file kept: %v", err)
	}
	for _, id := range []string{"00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000003"} {
		if _, ok := byRule[id]; ok {
			t.Errorf("rule %s shipped, want it left out", id)
		}
	}
	// The 7-Zip rule's tests carry the recorded events it matches.
	tf, err := os.ReadFile(filepath.Join(out, "tests", "proc_creation_win_7zip_exfil_dmp_files.json"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(tf), `"sigmahq"`); n != 2 {
		t.Errorf("7-Zip tests have %d recorded events, want 2", n)
	}
	rep, err := os.ReadFile(filepath.Join(out, "REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	report := string(rep)
	for _, want := range []string{
		"# SigmaHQ pack report",
		"status deprecated",
		"level informational",
		"log source is not plain windows process_creation",
		"Sigma checker cannot read it",
		"rules/windows/process_creation/zz_linux.yml",
		unreadHeading,
		"| 1 | rules/linux/builtin | syslog",
		"| 1 | rules-threat-hunting/windows | not read yet |",
		"## Shipped network rules unlikely",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q", want)
		}
	}
}
