// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
	"github.com/jrsamsanchez/signalith/internal/splcheck"
)

// readManifests returns every pack manifest with its rules listed (Packs
// drops the list once the rules are loaded).
func readManifests(t *testing.T) map[string]*Pack {
	t.Helper()
	files, err := fs.Glob(packFS, "packs/*/pack.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no pack manifests: %v", err)
	}
	out := map[string]*Pack{}
	for _, f := range files {
		data, err := packFS.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var p Pack
		if err := yaml.Unmarshal(data, &p); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out[path.Dir(f)] = &p
	}
	return out
}

// TestPackRulesFireOnTheirTests is the content check CI runs on every
// change: each shipped Sigma rule converts strictly, and on every one of
// its test events (synthesized from the rule, and SigmaHQ's recorded
// events where it has them) the converted detection, reading the event
// as the real Windows parser stores it, agrees with the Sigma rule: it
// fires on the positives and stays quiet on the exclusions and near
// misses. A rule that stops firing, or starts firing where it should not,
// fails here by name.
func TestPackRulesFireOnTheirTests(t *testing.T) {
	eng := &search.Engine{Intel: intel.NewStore(intel.NewMemory())}
	total := 0
	for dir, p := range readManifests(t) {
		if p.Format == "splunk" {
			var err error
			if p.macros, err = loadMacros(packFS, dir); err != nil {
				t.Fatal(err)
			}
			if p.lookups, err = loadLookups(packFS, dir); err != nil {
				t.Fatal(err)
			}
		}
		listed := map[string]bool{}
		for _, r := range p.Rules {
			listed[r.File] = true
			src, err := packFS.ReadFile(path.Join(dir, "rules", r.File))
			if err != nil {
				t.Errorf("%s: %v", r.ID, err)
				continue
			}
			d, err := PackDetection(p, r, src)
			if err != nil {
				t.Errorf("%s (%s): does not convert: %v", r.ID, r.Path, err)
				continue
			}
			q, err := query.Parse(d.Query)
			if err != nil {
				t.Errorf("%s: query does not parse: %v", r.ID, err)
				continue
			}
			if _, err := eng.Compile(q); err != nil {
				t.Errorf("%s: query does not compile: %v", r.ID, err)
			}
			// verify checks the converted detection against the rule as its
			// own project reads it.
			var ruleID string
			var verify func(tf *sigmacheck.TestFile) []error
			if p.Format == "splunk" {
				rule, err := splcheck.ParseWith(src, p.macros, splcheck.ParseOptions{Network: SplunkNetworkRule(r.Path), Lookups: p.lookups})
				if err != nil {
					t.Errorf("%s: %v", r.ID, err)
					continue
				}
				ruleID = rule.ID
				verify = func(tf *sigmacheck.TestFile) []error { return splcheck.Verify(rule, q, tf) }
			} else {
				rule, err := sigmacheck.Parse(src)
				if err != nil {
					t.Errorf("%s: %v", r.ID, err)
					continue
				}
				ruleID = rule.ID
				verify = func(tf *sigmacheck.TestFile) []error { return sigmacheck.Verify(rule, q.Datamodel, q.Search, tf) }
			}
			if ruleID != r.RuleID {
				t.Errorf("%s: manifest says rule %s, file has %s", r.ID, r.RuleID, ruleID)
			}
			data, err := os.ReadFile(path.Join(dir, "tests", strings.TrimSuffix(r.File, ".yml")+".json"))
			if err != nil {
				t.Errorf("%s: no test events: %v", r.ID, err)
				continue
			}
			tf, err := sigmacheck.DecodeTestFile(data)
			if err != nil {
				t.Errorf("%s: %v", r.ID, err)
				continue
			}
			if tf.Rule != r.RuleID {
				t.Errorf("%s: test file is for rule %s", r.ID, tf.Rule)
			}
			positives := 0
			for _, c := range tf.Cases {
				if c.Expect {
					positives++
				}
			}
			if positives == 0 {
				t.Errorf("%s: no positive test event", r.ID)
			}
			for _, err := range verify(tf) {
				t.Errorf("%s (%s): %v", r.ID, r.Path, err)
			}
			total++
		}
		// Nothing ships without a test: every rule file is in the manifest.
		files, _ := fs.Glob(packFS, path.Join(dir, "rules", "*.yml"))
		for _, f := range files {
			if !listed[path.Base(f)] {
				t.Errorf("%s is not in %s/pack.yaml", f, dir)
			}
		}
	}
	if total < 1500 {
		t.Errorf("only %d pack rules checked", total)
	}
}

func TestPackDetections(t *testing.T) {
	ps, ds, err := Packs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) == 0 || len(ds) < 500 {
		t.Fatalf("%d packs, %d detections", len(ps), len(ds))
	}
	for _, d := range ds {
		if d.Enabled {
			t.Errorf("%s is on by default", d.ID)
		}
		o := d.Origin
		if o == nil {
			t.Errorf("%s: no origin", d.ID)
			continue
		}
		license, url := "DRL-1.1", "https://github.com/SigmaHQ/sigma/blob/"
		if o.Pack == "splunk" {
			license, url = "Apache-2.0", "https://github.com/splunk/security_content/blob/"
		}
		if o.Rule == "" || o.License != license || !strings.HasPrefix(o.URL, url) || o.LicenseURL == "" {
			t.Errorf("%s: origin %+v", d.ID, o)
			continue
		}
		// DRL 1.1 requires findings to name the rule's author; Splunk's
		// rules are credited the same way.
		if o.Author == "" || !strings.Contains(o.Credit(), o.Author) {
			t.Errorf("%s: credit %q", d.ID, o.Credit())
		}
		// Its ATT&CK techniques are in the matrix, or retired ones that
		// were replaced (T1035.009 is a Splunk rule's typo).
		for _, id := range d.MITRE {
			if _, ok := ATTACK().Technique(id); !ok && id != "T1035.009" {
				t.Errorf("%s: technique %s is not in ATT&CK %s", d.ID, id, ATTACK().Version)
			}
		}
		// Each rule reads only its own system's events: a network rule
		// its Zeek log's, or its data model's (a DNS lookup, a web request
		// or a connection from any source); a web server rule the Web
		// data model's; an antivirus rule (category: antivirus, which
		// names no product) the Malware data model's, any antivirus
		// product's alerts.
		if strings.Contains(d.Query, "sourcetype=zeek:") || networkPackRule(d) ||
			slices.Contains(d.Tags, "antivirus") && strings.HasPrefix(d.Query, "datamodel=Malware ") {
			continue
		}
		if !strings.Contains(d.Query, "sourcetype=WinEventLog:") && !strings.Contains(d.Query, `sourcetype="WinEventLog:`) &&
			!strings.Contains(d.Query, "sourcetype=sysmon:linux") && !strings.Contains(d.Query, "sourcetype=linux:audit") &&
			!strings.HasPrefix(d.Query, "datamodel=Web ") && !strings.HasPrefix(d.Query, "sourcetype=aws:cloudtrail ") &&
			!strings.Contains(d.Query, "sourcetype=azure:monitor:") && !strings.HasPrefix(d.Query, "sourcetype=o365:management:activity ") &&
			!strings.HasPrefix(d.Query, "sourcetype=google:gcp:pubsub:message ") && !strings.Contains(d.Query, "sourcetype=OktaIM2:log ") &&
			!strings.Contains(d.Query, "sourcetype=_json AND source=kubernetes") && !strings.HasPrefix(d.Query, "sourcetype=_json source=kubernetes ") &&
			!strings.Contains(d.Query, "sourcetype=github:cloud:audit ") && !strings.HasPrefix(d.Query, "datamodel=Endpoint sourcetype=osquery:process_start ") {
			t.Errorf("%s: not limited to Windows, Sysmon for Linux, Linux audit, macOS osquery, web server, CloudTrail, Azure, Microsoft 365, Google Cloud, Okta, Kubernetes or GitHub events: %s", d.ID, d.Query)
		}
	}
}

// networkPackRule reports whether a pack rule is a generic network one
// (Sigma's dns, proxy or firewall category, or a Splunk network
// detection over a network data model), limited to its data model.
func networkPackRule(d *Detection) bool {
	if d.Origin != nil && d.Origin.Pack == "splunk" && slices.Contains(d.Tags, "network") {
		for _, m := range []string{"Network_Traffic", "Network_Resolution"} {
			if strings.HasPrefix(d.Query, "datamodel="+m+" ") {
				return true
			}
		}
	}
	models := map[string]string{"dns": "Network_Resolution", "proxy": "Web", "firewall": "Network_Traffic"}
	for _, t := range d.Tags {
		if m, ok := models[t]; ok && strings.HasPrefix(d.Query, "datamodel="+m+" ") {
			return true
		}
	}
	return false
}

// DQ-01: the Splunk pack ranks its TTPs, so severity filters and the
// high-and-critical button see its strongest rules. security_content gives
// nearly every TTP the same risk score, so a change upstream that flattens
// them again fails here.
func TestSplunkPackSeverities(t *testing.T) {
	_, ds, err := Packs()
	if err != nil {
		t.Fatal(err)
	}
	n := map[string]int{}
	sev := map[string]string{}
	for _, d := range ds {
		if d.Origin != nil && d.Origin.Pack == "splunk" {
			n[d.Severity]++
			sev[d.ID] = d.Severity
		}
	}
	t.Logf("splunk severities: %v", n)
	if n["critical"] < 20 || n["high"] < 100 || n["medium"] < 100 || n["low"] < 100 {
		t.Errorf("splunk severities: %v", n)
	}
	for id, want := range map[string]string{
		"splunk-windows-steal-authentication-certificates-esc1-abuse": "high",
		"splunk-dump-lsass-via-procdump":                              "high",
		"splunk-bcdedit-failure-recovery-modification":                "critical",
	} {
		if sev[id] != want {
			t.Errorf("%s: %q, want %s", id, sev[id], want)
		}
	}
}

// The starter set is 100 to 150 high and critical pack rules that read
// only what hosts send as installed (BUY-03).
func TestStarterSet(t *testing.T) {
	_, ds, err := Packs()
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]*Detection{}
	tagged := 0
	for _, d := range ds {
		byID[d.ID] = d
		if slices.Contains(d.Tags, StarterTag) {
			tagged++
		}
	}
	if n := len(starterIDs); n < 100 || n > 150 || tagged != n {
		t.Errorf("starter set: %d listed, %d tagged", n, tagged)
	}
	for id := range starterIDs {
		d := byID[id]
		if d == nil {
			t.Errorf("%s: no such pack rule", id)
			continue
		}
		if d.Severity != "high" && d.Severity != "critical" {
			t.Errorf("%s: %s", id, d.Severity)
		}
		for _, tag := range d.Tags {
			if strings.HasPrefix(tag, "needs-") {
				t.Errorf("%s: %s", id, tag)
			}
		}
	}
}
