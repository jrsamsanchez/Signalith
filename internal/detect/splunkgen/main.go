// Command splunkgen builds the Splunk security_content pack from a
// checkout of https://github.com/splunk/security_content: every
// production TTP and anomaly detection over Windows process, file and
// registry events that converts exactly and agrees with Splunk's reading
// of its where clause on its test events (internal/splcheck). It copies
// those rules and the macros they use unchanged, writes their test
// events, the manifest and REPORT.md listing what was left out and why.
//
//	go run ./internal/detect/splunkgen -splunk ../security_content
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
	"github.com/jrsamsanchez/signalith/internal/splcheck"
)

var (
	splunkDir = flag.String("splunk", "", "security_content checkout")
	outDir    = flag.String("out", "internal/detect/packs/splunk", "pack folder")
)

// windowsSources are the data sources whose events Signalith parses into
// the data model nodes the pack reads.
var windowsSources = []string{
	"Sysmon EventID 1", "Windows Event Log Security 4688", "Sysmon EventID 11", "Sysmon EventID 12",
	"Sysmon EventID 13", "Sysmon EventID 14", "Sysmon EventID 23", "Sysmon EventID 26",
	"Powershell Script Block Logging 4104", "Sysmon EventID 7", "Sysmon EventID 8", "Sysmon EventID 10",
	"Sysmon for Linux EventID 1", "Sysmon for Linux EventID 11", "Windows Event Log Security 4698",
	"Windows Event Log Security 4663", "Windows Event Log System 7045",
	"Windows Event Log Security 5136", "Windows Event Log Security 5145",
	"Windows Event Log Security 4768", "Windows Event Log Security 4769",
	"Windows Event Log Security 4738", "Windows Event Log Security 4732",
	"Sysmon EventID 3", "Sysmon EventID 22", "Windows Event Log Security 4624", "Windows Event Log Security 4625",
	"Sysmon EventID 15", "Sysmon EventID 17", "Sysmon EventID 18", "Sysmon EventID 5", "Sysmon EventID 9",
	"Windows Event Log Security 4648", "Windows Event Log Security 4776", "Windows Event Log Security 4771",
	"Windows Event Log Security 4741", "Windows Event Log Security 4742", "Windows Event Log Security 4781",
	"Windows Event Log Security 4727", "Windows Event Log Security 4730", "Windows Event Log Security 4737",
	"Windows Event Log Security 4798", "Windows Event Log Security 4799", "Windows Event Log Security 4886",
	"Windows Event Log Security 4887", "Windows Event Log Security 4662", "Windows Event Log Security 4723",
	"Windows Event Log Security 4724", "Windows Event Log Security 4722", "Windows Event Log Security 4725",
	"Windows Event Log Security 5447", "Windows Event Log Security 4728", "Windows Event Log Security 4719",
	"Windows Event Log Security 5140", "Windows Event Log Security 4731", "Windows Event Log Security 4756",
	// Other Windows logs whose events the parser reads: the
	// Service Control Manager's service events, WMI's permanent event
	// subscriptions, app packages deployed and NTLM authentications
	// audited, and SQL Server's events in the Application log
	// (splcheck's channel nodes).
	"Windows Event Log Application 15457", "Windows Event Log Application 17135", "Windows Event Log System 7036", "Windows Event Log System 7040", "Windows Event Log WMI Activity 5861",
	"Windows Event Log AppXDeployment-Server 854", "Windows Event Log AppXDeployment-Server 855", "NTLM Operational 8004",
	// Linux audit records, which Signalith reads from the audit log.
	"Linux Auditd Execve", "Linux Auditd Proctitle", "Linux Auditd Syscall", "Linux Auditd Path", "Linux Auditd Cwd",
	"Linux Auditd Service Stop", "Linux Auditd Add User", "Linux Auditd Daemon Start", "Linux Auditd Daemon End",
	"Linux Auditd Daemon Abort",
}

// windowsSource reports whether a data source is one of windowsSources,
// or events of several of them together (Sysmon EventID 1 AND Sysmon
// EventID 11), as a rule that joins a program start to the file it
// writes reads.
func windowsSource(s string) bool {
	for _, part := range strings.Split(s, " AND ") {
		if !slices.Contains(windowsSources, strings.TrimSpace(part)) {
			return false
		}
	}
	return true
}

// maxWildcardTerms keeps a rule's searches under
// OpenSearch's default limit of 1,024 clauses in one search (see
// search.WildcardFieldTerms and search.Clauses), as for the SigmaHQ pack.
const maxWildcardTerms = 1000

// maxClauses is OpenSearch's limit of clauses in one search, which a
// rule's whole search must stay within (search.Clauses).
const maxClauses = 1024

var macroRef = regexp.MustCompile("`([\\w-]+)`")

func main() {
	flag.Parse()
	if *splunkDir == "" {
		log.Fatal("-splunk is required")
	}
	commit := gitCommit(*splunkDir)
	macros := map[string]*splcheck.Macro{}
	macroFiles := map[string]string{}
	files, _ := filepath.Glob(filepath.Join(*splunkDir, "macros", "*.yml"))
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}
		m, err := splcheck.ParseMacro(src)
		if err != nil {
			continue
		}
		macros[m.Name] = m
		macroFiles[m.Name] = f
	}
	pack := &detect.Pack{
		Name:   "splunk",
		Title:  "Splunk Security Content",
		Format: "splunk",
		Description: "Windows detections for process, file and registry events, macOS detections for the program starts osquery reports, web detections for web requests, network detections over connections and DNS lookups, AWS detections for CloudTrail records, Entra ID detections for its sign-in and audit logs, Microsoft 365 detections for its audit records, Okta detections for its System Log, Kubernetes detections for its audit log and GitHub detections for its audit log, from Splunk's Threat Research Team (security_content), converted to Signalith detections. " +
			"TTP rules raise findings; anomaly rules only add risk, as in Splunk's risk-based alerting. Each rule shipped here agrees with Splunk's reading of its search on its test events, checked in CI.",
		Source:     "https://github.com/splunk/security_content",
		Version:    commit,
		Date:       time.Now().UTC().Format("2006-01-02"),
		License:    "Apache-2.0",
		LicenseURL: "https://www.apache.org/licenses/LICENSE-2.0",
		Notice: "The detections in this pack, and the lookup tables they read (lookups/), are from Splunk security_content, Copyright Splunk Inc., licensed under the Apache License 2.0. " +
			"They are shipped unchanged; Signalith converts the detections when it starts. Findings from them name the rule's author.",
	}
	pack.UseMacros(macros)
	lookups, lookupErrs, lookupFiles := readLookups(*splunkDir)
	pack.UseLookups(lookups)
	old := map[string]string{}
	if data, err := os.ReadFile(filepath.Join(*outDir, "pack.yaml")); err == nil {
		var p detect.Pack
		if err := yaml.Unmarshal(data, &p); err != nil {
			log.Fatal(err)
		}
		for _, r := range p.Rules {
			old[r.RuleID] = r.ID
		}
	}
	// Real recorded events (attackgen) are kept across a refresh.
	recorded := map[string][]sigmacheck.Case{}
	oldTests, _ := filepath.Glob(filepath.Join(*outDir, "tests", "*.json"))
	for _, f := range oldTests {
		data, err := os.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}
		tf, err := sigmacheck.DecodeTestFile(data)
		if err != nil {
			log.Fatalf("%s: %v", f, err)
		}
		for _, c := range tf.Cases {
			if c.Source == splcheck.AttackDataSource {
				recorded[tf.Rule] = append(recorded[tf.Rule], c)
			}
		}
	}
	for _, d := range []string{"rules", "tests", "macros", "lookups"} {
		if err := os.RemoveAll(filepath.Join(*outDir, d)); err != nil {
			log.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(*outDir, d), 0o755); err != nil {
			log.Fatal(err)
		}
	}

	skipped := map[string][]string{}
	skip := func(reason, file string) { skipped[reason] = append(skipped[reason], file) }
	usedIDs := map[string]bool{}
	usedMacros := map[string]bool{}
	usedLookups := map[string]bool{}
	rules, _ := filepath.Glob(filepath.Join(*splunkDir, "detections", "endpoint", "*.yml"))
	// Web detections search the Web data model, whatever log fills it,
	// and so do a few network ones. The other network detections are
	// tstats searches over connections and DNS lookups, which a network
	// sensor fills, or searches of Sysmon's network events.
	web, _ := filepath.Glob(filepath.Join(*splunkDir, "detections", "web", "*.yml"))
	rules = append(rules, web...)
	network, _ := filepath.Glob(filepath.Join(*splunkDir, "detections", "network", "*.yml"))
	rules = append(rules, network...)
	// Cloud detections that read CloudTrail records, Entra ID and Azure
	// records, Microsoft 365 audit records or Okta's System Log, and the
	// application detections over Okta's System Log.
	cloud, _ := filepath.Glob(filepath.Join(*splunkDir, "detections", "cloud", "*.yml"))
	apps, _ := filepath.Glob(filepath.Join(*splunkDir, "detections", "application", "*.yml"))
	cloud = append(cloud, apps...)
	for _, f := range cloud {
		if src, err := os.ReadFile(f); err == nil && (cloudFile.Match(src) || oktaFile.Match(src)) {
			rules = append(rules, f)
		}
	}
	sort.Strings(rules)
	for _, f := range rules {
		rel, _ := filepath.Rel(*splunkDir, f)
		rel = filepath.ToSlash(rel)
		src, err := os.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}
		var meta splcheck.Rule
		if err := yaml.Unmarshal(src, &meta); err != nil {
			skip("not valid YAML", rel)
			continue
		}
		if meta.Status != "production" {
			skip("status "+meta.Status, rel)
			continue
		}
		if meta.Type != "TTP" && meta.Type != "Anomaly" {
			skip("type "+meta.Type+" (not TTP or Anomaly)", rel)
			continue
		}
		web := webSearch.MatchString(meta.Search)
		opt := splcheck.ParseOptions{Network: detect.SplunkNetworkRule(rel) && !web, Lookups: lookups, LookupErrors: lookupErrs}
		if opt.Network {
			// A network rule over connections or DNS lookups reads its
			// data model from any source, a network sensor's among them.
			// One over Sysmon's events is endpoint content, left to the
			// endpoint rules.
			r, err := splcheck.ParseWith(src, macros, opt)
			if err != nil && sensorSearch.MatchString(meta.Search) {
				// A search of connections or DNS lookups that does not
				// convert says why.
				skip("does not convert exactly: "+short(err), rel)
				continue
			}
			if err != nil || !splcheck.IsSensorNode(r.Node) {
				skip("network detection that is not a tstats search of connections or DNS lookups", rel)
				continue
			}
		} else if !slices.ContainsFunc(meta.DataSource, windowsSource) && !web &&
			!cloudSearch.MatchString(meta.Search) && !slices.Equal(meta.DataSource, []string{"Okta"}) && !slices.Equal(meta.DataSource, []string{"Osquery Results"}) {
			skip("no Windows Sysmon or Security log data source", rel)
			continue
		}
		rule, err := splcheck.ParseWith(src, macros, opt)
		if err != nil {
			skip("does not convert exactly: "+short(err), rel)
			continue
		}
		stem := strings.TrimSuffix(filepath.Base(f), ".yml")
		id := old[rule.ID]
		if id == "" {
			id = newID(stem, rule.ID, usedIDs)
		}
		usedIDs[id] = true
		pr := detect.PackRule{ID: id, RuleID: rule.ID, File: stem + ".yml", Path: rel}
		d, err := detect.PackDetection(pack, pr, src)
		if err != nil {
			skip("does not convert exactly: "+short(err), rel)
			continue
		}
		q, err := query.Parse(d.Query)
		if err != nil {
			log.Fatalf("%s: converted query does not parse: %v", rel, err)
		}
		if n := search.WildcardFieldTerms(q.Search); n > maxWildcardTerms {
			skip("too many script text pieces for one OpenSearch search", fmt.Sprintf("%s: about %d", rel, n))
			continue
		}
		if n, err := search.Clauses(q.Search); err != nil || n > maxClauses {
			skip("too many clauses for one OpenSearch search", clauseNote(rel, n, err))
			continue
		}
		tf := &sigmacheck.TestFile{Rule: rule.ID, Cases: splcheck.Cases(rule)}
		if !slices.ContainsFunc(tf.Cases, func(c sigmacheck.Case) bool { return c.Expect }) {
			skip(splcheck.NoEventsReason(rule, tf.Cases), rel)
			continue
		}
		for _, c := range recorded[rule.ID] {
			c.Expect = splcheck.Reads(rule, c)
			tf.Cases = append(tf.Cases, c)
		}
		if errs := splcheck.Verify(rule, q, tf); len(errs) > 0 {
			skip("converted detection disagrees with the rule", rel+": "+errs[0].Error())
			continue
		}
		if err := os.WriteFile(filepath.Join(*outDir, "rules", pr.File), src, 0o644); err != nil {
			log.Fatal(err)
		}
		data, err := sigmacheck.EncodeTestFile(tf)
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(*outDir, "tests", stem+".json"), data, 0o644); err != nil {
			log.Fatal(err)
		}
		markMacros(rule.Search, macros, usedMacros)
		for _, l := range rule.Lookups {
			usedLookups[l] = true
		}
		pack.Rules = append(pack.Rules, pr)
	}
	for name := range usedMacros {
		src, err := os.ReadFile(macroFiles[name])
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(*outDir, "macros", filepath.Base(macroFiles[name])), src, 0o644); err != nil {
			log.Fatal(err)
		}
	}
	// The tables the rules look values up in, as security_content ships
	// them: the CSV and the yml that says how it matches.
	for name := range usedLookups {
		for _, src := range []string{lookupFiles[name], strings.TrimSuffix(lookupFiles[name], ".yml") + ".csv"} {
			data, err := os.ReadFile(src)
			if err != nil {
				log.Fatal(err)
			}
			dst := name + filepath.Ext(src)
			if err := os.WriteFile(filepath.Join(*outDir, "lookups", dst), data, 0o644); err != nil {
				log.Fatal(err)
			}
		}
	}
	lic, err := os.ReadFile(filepath.Join(*splunkDir, "LICENSE"))
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "LICENSE"), lic, 0o644); err != nil {
		log.Fatal(err)
	}
	sort.Slice(pack.Rules, func(i, j int) bool { return pack.Rules[i].ID < pack.Rules[j].ID })
	var buf bytes.Buffer
	buf.WriteString("# Generated by go run ./internal/detect/splunkgen; see REPORT.md for the rules left out and why.\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(pack); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "pack.yaml"), buf.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
	writeReport(pack, skipped)
	n := 0
	for _, v := range skipped {
		n += len(v)
	}
	fmt.Printf("%d rules shipped, %d left out (see %s)\n", len(pack.Rules), n, filepath.Join(*outDir, "REPORT.md"))
}

// readLookups reads security_content's tables (lookups/csv): those
// Signalith reads, why it cannot read the others (and the KV store
// lookups, which are not files), and each one's yml.
func readLookups(dir string) (map[string]*splcheck.Lookup, map[string]error, map[string]string) {
	lookups := map[string]*splcheck.Lookup{}
	errs := map[string]error{}
	files := map[string]string{}
	metas, _ := filepath.Glob(filepath.Join(dir, "lookups", "*", "*.yml"))
	for _, f := range metas {
		meta, err := os.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}
		var m struct {
			Name string `yaml:"name"`
			Type string `yaml:"lookup_type"`
		}
		if err := yaml.Unmarshal(meta, &m); err != nil || m.Name == "" {
			continue
		}
		if m.Type != "csv" {
			errs[m.Name] = fmt.Errorf("a %s lookup, which security_content does not ship as a file", m.Type)
			continue
		}
		data, err := os.ReadFile(strings.TrimSuffix(f, ".yml") + ".csv")
		if err != nil {
			errs[m.Name] = fmt.Errorf("security_content has no CSV for it")
			continue
		}
		l, err := splcheck.ParseLookup(meta, data)
		if err != nil {
			errs[m.Name] = err
			continue
		}
		lookups[l.Name] = l
		files[l.Name] = f
	}
	return lookups, errs, files
}

// markMacros records the macros a search's where clause uses, and the
// macros those use.
func markMacros(s string, macros map[string]*splcheck.Macro, used map[string]bool) {
	for _, m := range macroRef.FindAllStringSubmatch(s, -1) {
		name := m[1]
		mac := macros[name]
		if mac == nil || used[name] || strings.HasSuffix(name, "_filter") || name == "security_content_summariesonly" {
			continue
		}
		used[name] = true
		markMacros(mac.Definition, macros, used)
	}
}

// cloudSearch is a search of CloudTrail, Entra ID, Azure, Microsoft 365
// or Okta records, and cloudFile a rule file with one.
var (
	cloudSearch = regexp.MustCompile("^\\s*`(cloudtrail|azure_monitor_aad|azure_monitor_activity|o365_management_activity|okta|kube_audit|github_enterprise|github_organizations)`")
	cloudFile   = regexp.MustCompile("(?m)^(?:search:\\s*['\"|>-]*)?\\s*`(cloudtrail|azure_monitor_aad|azure_monitor_activity|o365_management_activity|okta|kube_audit|github_enterprise|github_organizations)`")
)

// oktaFile is a rule file whose only data source is Okta: a tstats
// search over the Authentication or Change data model reads Okta's
// events.
var oktaFile = regexp.MustCompile(`(?m)^data_source:\s*\n\s*-\s*Okta\s*\n\S`)

// webSearch is a search of the Web data model.
var webSearch = regexp.MustCompile(`(?i)\bfrom\s+datamodel=Web\b`)

// sensorSearch is a tstats search of connections or DNS lookups, the data
// models a network rule reads from any source.
var sensorSearch = regexp.MustCompile(`(?i)^\s*\|\s*tstats\b[^|]*\bfrom\s+datamodel\s*=\s*"?(Network_Traffic|Network_Resolution)\b`)

var quoted = regexp.MustCompile(`"[^"]*"|\b[A-Z][a-z]+\.\w+`)

func short(err error) string {
	s := quoted.ReplaceAllString(err.Error(), "…")
	if len(s) > 90 {
		// Cut on a character boundary.
		s = strings.ToValidUTF8(s[:90], "")
	}
	return s
}

var nonID = regexp.MustCompile(`[^a-z0-9]+`)

func newID(stem, ruleID string, used map[string]bool) string {
	id := strings.Trim(nonID.ReplaceAllString(strings.ToLower("splunk-"+stem), "-"), "-")
	if len(id) > 64 {
		id = strings.TrimRight(id[:64], "-")
	}
	if used[id] {
		tail := "-" + strings.ReplaceAll(ruleID, "-", "")[:6]
		id = strings.TrimRight(id[:min(len(id), 64-len(tail))], "-") + tail
	}
	return id
}

func gitCommit(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		log.Fatalf("reading the security_content commit: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func writeReport(p *detect.Pack, skipped map[string][]string) {
	var b strings.Builder
	fmt.Fprintf(&b, "# Splunk Security Content pack report\n\nGenerated by `go run ./internal/detect/splunkgen` from security_content commit `%s` on %s.\n\n", p.Version, p.Date)
	total := 0
	for _, v := range skipped {
		total += len(v)
	}
	fmt.Fprintf(&b, "%d rules shipped. %d endpoint, web, network and cloud detections were left out:\n\n| Rules | Reason |\n| ---: | --- |\n", len(p.Rules), total)
	reasons := make([]string, 0, len(skipped))
	for r := range skipped {
		reasons = append(reasons, r)
	}
	sort.Slice(reasons, func(i, j int) bool {
		if len(skipped[reasons[i]]) != len(skipped[reasons[j]]) {
			return len(skipped[reasons[i]]) > len(skipped[reasons[j]])
		}
		return reasons[i] < reasons[j]
	})
	for _, r := range reasons {
		fmt.Fprintf(&b, "| %d | %s |\n", len(skipped[r]), strings.ReplaceAll(r, "|", `\|`))
	}
	for _, r := range reasons {
		fmt.Fprintf(&b, "\n## %s\n\n", r)
		files := skipped[r]
		sort.Strings(files)
		for _, f := range files {
			fmt.Fprintf(&b, "- %s\n", f)
		}
	}
	if err := os.WriteFile(filepath.Join(*outDir, "REPORT.md"), []byte(b.String()), 0o644); err != nil {
		log.Fatal(err)
	}
}

// clauseNote is a report line for a rule over the clause limit.
func clauseNote(rel string, n int, err error) string {
	if err != nil {
		return fmt.Sprintf("%s: %v", rel, err)
	}
	return fmt.Sprintf("%s: about %d", rel, n)
}
