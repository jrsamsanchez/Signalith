package detect

import (
	"io/fs"
	"path"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/splcheck"
)

// fuzzPack reads one built-in pack's manifest, with its macros for a
// splunk pack, and a spread of its rules as fuzz seeds: about every
// n-th rule, plus the first rule that uses each of the given strings.
func fuzzPack(f *testing.F, dir string, n int, uses ...string) (*Pack, [][]byte) {
	f.Helper()
	data, err := packFS.ReadFile(path.Join(dir, "pack.yaml"))
	if err != nil {
		f.Fatal(err)
	}
	var p Pack
	if err := yaml.Unmarshal(data, &p); err != nil {
		f.Fatal(err)
	}
	if p.Format == "splunk" {
		if p.macros, err = loadMacros(packFS, dir); err != nil {
			f.Fatal(err)
		}
	}
	files, err := fs.Glob(packFS, path.Join(dir, "rules", "*.yml"))
	if err != nil || len(files) == 0 {
		f.Fatalf("no rules in %s: %v", dir, err)
	}
	slices.Sort(files)
	var seeds [][]byte
	for i, file := range files {
		src, err := packFS.ReadFile(file)
		if err != nil {
			f.Fatal(err)
		}
		pick := i%max(len(files)/n, 1) == 0
		for j, u := range uses {
			if u != "" && strings.Contains(string(src), u) {
				pick, uses[j] = true, ""
			}
		}
		if pick {
			seeds = append(seeds, src)
		}
	}
	p.Rules = nil
	return &p, seeds
}

var fuzzPackRule = PackRule{ID: "fuzz-rule", RuleID: "fuzz", File: "fuzz.yml", Path: "rules/fuzz.yml"}

// checkFuzzDetection checks a converted detection's query: it parses,
// prints back as the same text, and compiles to a search.
func checkFuzzDetection(t *testing.T, d *Detection) {
	t.Helper()
	q, err := query.Parse(d.Query)
	if err != nil {
		t.Fatalf("query %q does not parse: %v", d.Query, err)
	}
	if got := q.String(); got != d.Query {
		t.Fatalf("query does not round trip:\n%s\n---\n%s", d.Query, got)
	}
	_, _ = (&search.Engine{}).Compile(q)
}

// FuzzConvertSigma converts Sigma rules leniently (ConvertSigma, as an
// imported rule) and strictly as a pack rule (PackDetection), which must
// not panic and must give a query that parses back to itself.
func FuzzConvertSigma(f *testing.F) {
	pack, seeds := fuzzPack(f, "packs/sigmahq", 20,
		"|re:", "|re|i:", "|cidr:", "|base64offset", "|windash", "|contains|all:", "|startswith:",
		"keywords:", "1 of ", "all of them", "service: security", "service: system", "auditd", "product: linux",
		"|expand", "|utf16", "|wide", "|fieldref", "|exists", "|gt", "|cased", "null")
	for _, s := range seeds {
		f.Add(s)
	}
	f.Add([]byte(sigmaEncoded))
	f.Add([]byte("title: R\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    CommandLine|re|i: 'curl .*://[0-9]{1,3}\\.'\n  condition: sel\n"))
	f.Add([]byte("title: Failed logons\nlogsource:\n  product: windows\n  service: security\ndetection:\n  sel:\n    EventID: 4625\n  keywords:\n    - 'bad stuff'\n  condition: sel or keywords\n"))
	f.Add([]byte("title: x\ndetection:\n  sel:\n    EventID: 4625\n  condition: sel | count() by IpAddress > 10\n"))
	f.Add([]byte("title: x\ndetection:\n  a: [1, 2]\n  b:\n    - x|endswith: [a, '*', '\\\\?']\n  condition: not (a or 1 of b*) and all of them\n"))
	f.Fuzz(func(t *testing.T, src []byte) {
		if res, err := ConvertSigma(src); err == nil {
			checkFuzzDetection(t, res.Detection)
		}
		if d, err := PackDetection(pack, fuzzPackRule, src); err == nil {
			checkFuzzDetection(t, d)
		}
	})
}

// FuzzSplunkDetection converts Splunk security_content detections as
// the splunk pack does (PackDetection, with the pack's macros).
func FuzzSplunkDetection(f *testing.F) {
	pack, seeds := fuzzPack(f, "packs/splunk", 20,
		"| where ", "| stats ", "match(", "| regex ", "isnotnull", "`sysmon`", "`wineventlog_security`",
		"`linux_auditd`", "Registry.", "Filesystem.", "All_Traffic", "cidrmatch", "Sysmon for Linux", " IN (")
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		if d, err := PackDetection(pack, fuzzPackRule, src); err == nil {
			checkFuzzDetection(t, d)
		}
	})
}

// FuzzSplunkSearch is FuzzSplunkDetection with the fuzzer working on the
// search itself, in an otherwise well-formed rule.
func FuzzSplunkSearch(f *testing.F) {
	pack, seeds := fuzzPack(f, "packs/splunk", 20,
		"| where ", "| stats ", "match(", "| regex ", "isnotnull", "`sysmon`", "`wineventlog_security`",
		"`linux_auditd`", "Registry.", "Filesystem.", "All_Traffic", "cidrmatch", "Sysmon for Linux", " IN (")
	for _, s := range seeds {
		var r splcheck.Rule
		if err := yaml.Unmarshal(s, &r); err != nil {
			f.Fatal(err)
		}
		f.Add(r.Search, slices.ContainsFunc(r.DataSource, func(s string) bool { return strings.HasPrefix(s, "Sysmon for Linux ") }))
	}
	f.Fuzz(func(t *testing.T, search string, linux bool) {
		rule := map[string]any{
			"name": "Fuzz rule", "id": "11111111-2222-3333-4444-555555555555", "type": "TTP",
			"status": "production", "search": search,
		}
		if linux {
			rule["data_source"] = []string{"Sysmon for Linux EventID 1"}
		}
		src, err := yaml.Marshal(rule)
		if err != nil {
			return
		}
		if d, err := PackDetection(pack, fuzzPackRule, src); err == nil {
			checkFuzzDetection(t, d)
		}
	})
}
