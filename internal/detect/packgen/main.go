// Command packgen builds the SigmaHQ content pack from a checkout of
// https://github.com/SigmaHQ/sigma. It converts every Windows rule of the
// log sources Signalith parses, makes test events for each one (and uses
// SigmaHQ's own recorded events where it has them), and keeps only the
// rules whose converted detection agrees with the Sigma rule on every test
// event. The pack's own test (internal/detect/pack_test.go) repeats the
// check in CI, and the integration test runs it against OpenSearch.
//
//	git clone https://github.com/SigmaHQ/sigma /tmp/sigma
//	go run ./internal/detect/packgen -sigma /tmp/sigma
//
// Rule IDs already in the manifest are kept, so an admin's on/off choices
// survive a refresh even when SigmaHQ renames a file.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
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
)

// categories are the Sigma log source categories with a Signalith parser,
// and the folders their rules live in.
var categories = map[string]string{
	"process_creation":     "rules/windows/process_creation",
	"network_connection":   "rules/windows/network_connection",
	"file_event":           "rules/windows/file/file_event",
	"file_delete":          "rules/windows/file/file_delete",
	"registry_add":         "rules/windows/registry/registry_add",
	"registry_delete":      "rules/windows/registry/registry_delete",
	"registry_set":         "rules/windows/registry/registry_set",
	"registry_event":       "rules/windows/registry/registry_event",
	"dns_query":            "rules/windows/dns_query",
	"image_load":           "rules/windows/image_load",
	"driver_load":          "rules/windows/driver_load",
	"process_access":       "rules/windows/process_access",
	"create_remote_thread": "rules/windows/create_remote_thread",
	"ps_script":            "rules/windows/powershell/powershell_script",
}

// linuxCategories are the Linux log source categories Sysmon for Linux
// records, and the folders their rules live in.
var linuxCategories = map[string]string{
	"process_creation":   "rules/linux/process_creation",
	"network_connection": "rules/linux/network_connection",
	"file_event":         "rules/linux/file_event",
}

// maxWildcardTerms keeps a rule's searches of wildcard fields under
// OpenSearch's default limit of 1,024 clauses in one search (see
// search.WildcardFieldTerms).
const maxWildcardTerms = 1000

var (
	sigmaDir = flag.String("sigma", "", "SigmaHQ checkout")
	outDir   = flag.String("out", "internal/detect/packs/sigmahq", "pack folder")
)

func main() {
	flag.Parse()
	if *sigmaDir == "" {
		log.Fatal("-sigma is required")
	}
	commit := gitCommit(*sigmaDir)
	old := map[string]string{} // Sigma id -> detection id
	if data, err := os.ReadFile(filepath.Join(*outDir, "pack.yaml")); err == nil {
		var p detect.Pack
		if err := yaml.Unmarshal(data, &p); err != nil {
			log.Fatal(err)
		}
		for _, r := range p.Rules {
			old[r.RuleID] = r.ID
		}
	}
	pack := &detect.Pack{
		Name:  "sigmahq",
		Title: "SigmaHQ community rules",
		Description: "Windows rules for Sysmon and Security events (processes, network connections, files, registry, DNS, DLL loads and process access) from the SigmaHQ project, converted to Signalith detections. " +
			"Each rule shipped here fires on its test events and stays quiet on its exclusions, checked in CI.",
		Source:     "https://github.com/SigmaHQ/sigma",
		Version:    commit,
		Date:       time.Now().UTC().Format("2006-01-02"),
		License:    "DRL-1.1",
		LicenseURL: "https://github.com/SigmaHQ/Detection-Rule-License",
		Notice: "The rules in this pack are by the SigmaHQ authors named in each rule and are licensed under the " +
			"Detection Rule License (DRL) 1.1. Findings from them name the rule's author.",
	}
	for _, d := range []string{"rules", "tests"} {
		if err := os.RemoveAll(filepath.Join(*outDir, d)); err != nil {
			log.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(*outDir, d), 0o755); err != nil {
			log.Fatal(err)
		}
	}

	skipped := map[string][]string{}
	skip := func(reason, file string) { skipped[reason] = append(skipped[reason], file) }
	used := map[string]bool{}
	type source struct{ product, cat, dir string }
	var sources []source
	for c, dir := range categories {
		sources = append(sources, source{"windows", c, dir})
	}
	for c, dir := range linuxCategories {
		sources = append(sources, source{"linux", c, dir})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].dir < sources[j].dir })
	for _, src := range sources {
		cat, product := src.cat, src.product
		bases, cases := sigmacheck.Bases[cat], sigmacheck.Cases
		if product == "linux" {
			bases, cases = sigmacheck.LinuxBases[cat], sigmacheck.LinuxCases
		}
		files, _ := filepath.Glob(filepath.Join(*sigmaDir, src.dir, "*.yml"))
		sort.Strings(files)
		for _, f := range files {
			rel, _ := filepath.Rel(*sigmaDir, f)
			rel = filepath.ToSlash(rel)
			src, err := os.ReadFile(f)
			if err != nil {
				log.Fatal(err)
			}
			rule, err := sigmacheck.Parse(src)
			if err != nil {
				skip("Sigma checker cannot read it: "+short(err), rel)
				continue
			}
			switch rule.Status {
			case "stable", "test":
			default:
				skip("status "+rule.Status, rel)
				continue
			}
			if rule.Level == "informational" || rule.Level == "" {
				skip("level informational", rel)
				continue
			}
			if rule.Logsource["product"] != product || rule.Logsource["category"] != cat || rule.Logsource["service"] != "" {
				skip("log source is not plain "+product+" "+cat, rel)
				continue
			}
			stem := strings.TrimSuffix(filepath.Base(f), ".yml")
			id := old[rule.ID]
			if id == "" {
				id = newID(stem, rule.ID, used)
			}
			used[id] = true
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
			} else if os.Getenv("PACKGEN_TERMS") != "" && n > 0 {
				fmt.Fprintln(os.Stderr, "TERMS", n, rel)
			}
			syn, err := rule.Synthesize(seed(rule.ID), nil, bases)
			if err != nil {
				skip("no test events: "+short(err), rel)
				continue
			}
			tf := &sigmacheck.TestFile{Rule: rule.ID, Cases: cases(cat, syn, rule.Fields())}
			if product == "windows" {
				tf.Cases = append(tf.Cases, regression(*sigmaDir, rel, rule, cat)...)
			}
			if errs := sigmacheck.Verify(rule, q.Datamodel, q.Search, tf); len(errs) > 0 {
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
			pack.Rules = append(pack.Rules, pr)
		}
	}
	sort.Slice(pack.Rules, func(i, j int) bool { return pack.Rules[i].ID < pack.Rules[j].ID })
	var buf bytes.Buffer
	buf.WriteString("# Generated by go run ./internal/detect/packgen; see REPORT.md for the rules left out and why.\n")
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

func short(err error) string {
	s := err.Error()
	if i := strings.Index(s, " (in "); i > 0 {
		s = s[:i]
	}
	// Group like reasons: drop quoted values and field names.
	s = regexp.MustCompile(`"[^"]*"|'[^']*'`).ReplaceAllString(s, "…")
	s = regexp.MustCompile(`^[A-Za-z0-9_.]+\|[^:]*: `).ReplaceAllString(s, "")
	s = regexp.MustCompile(`field \S+ has`).ReplaceAllString(s, "a field has")
	if len(s) > 90 {
		s = s[:90]
	}
	return s
}

var prefixes = []struct{ from, to string }{
	{"proc_creation_win_", "sigma-proc-"},
	{"proc_creation_lnx_", "sigma-lnx-proc-"},
	{"net_connection_lnx_", "sigma-lnx-net-"},
	{"file_event_lnx_", "sigma-lnx-file-"},
	{"net_connection_win_", "sigma-net-"},
	{"file_event_win_", "sigma-file-"},
	{"file_delete_win_", "sigma-file-delete-"},
	{"registry_add_", "sigma-reg-add-"},
	{"registry_delete_", "sigma-reg-delete-"},
	{"registry_set_", "sigma-reg-set-"},
	{"registry_event_", "sigma-reg-"},
	{"dns_query_win_", "sigma-dns-"},
	{"image_load_", "sigma-load-"},
	{"driver_load_win_", "sigma-driver-"},
	{"proc_access_win_", "sigma-access-"},
	{"create_remote_thread_win_", "sigma-thread-"},
	{"posh_ps_", "sigma-ps-"},
}

var nonID = regexp.MustCompile(`[^a-z0-9]+`)

func newID(stem, ruleID string, used map[string]bool) string {
	id := "sigma-" + stem
	for _, p := range prefixes {
		if strings.HasPrefix(stem, p.from) {
			id = p.to + strings.TrimPrefix(stem, p.from)
		}
	}
	id = strings.Trim(nonID.ReplaceAllString(strings.ToLower(id), "-"), "-")
	if len(id) > 64 {
		id = strings.TrimRight(id[:64], "-")
	}
	if used[id] {
		tail := "-" + strings.ReplaceAll(ruleID, "-", "")[:6]
		id = strings.TrimRight(id[:min(len(id), 64-len(tail))], "-") + tail
	}
	return id
}

func seed(id string) int64 {
	h := fnv.New64a()
	io.WriteString(h, id)
	return int64(h.Sum64() >> 1)
}

func gitCommit(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		log.Fatalf("reading the SigmaHQ commit: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// regression returns SigmaHQ's recorded events for a rule (converted from
// its .evtx files), as positive cases. Events from channels Signalith does
// not parse for this category are left out.
func regression(root, rel string, rule *sigmacheck.Rule, cat string) []sigmacheck.Case {
	dir := filepath.Join(root, "regression_data", strings.TrimSuffix(rel, ".yml"))
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	sysmonIDs := sigmacheck.SysmonEventIDs(cat)
	var out []sigmacheck.Case
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		for {
			var ev struct {
				Event struct {
					System struct {
						Channel string `json:"Channel"`
						EventID any    `json:"EventID"`
					} `json:"System"`
					EventData map[string]any `json:"EventData"`
				} `json:"Event"`
			}
			if err := dec.Decode(&ev); err != nil {
				break
			}
			id := fmt.Sprint(ev.Event.System.EventID)
			if m, ok := ev.Event.System.EventID.(map[string]any); ok {
				id = fmt.Sprint(m["#text"])
			}
			id = strings.TrimSuffix(id, ".0")
			c := sigmacheck.Case{Expect: true, Source: "sigmahq", Channel: ev.Event.System.Channel, EventID: id, Data: map[string]string{}}
			for k, v := range ev.Event.EventData {
				if v == nil {
					continue
				}
				switch x := v.(type) {
				case float64:
					c.Data[k] = fmt.Sprint(int64(x))
				case string:
					c.Data[k] = x
				default:
					b, _ := json.Marshal(x)
					c.Data[k] = string(b)
				}
			}
			ok := (strings.EqualFold(c.Channel, sigmacheck.Channel(cat)) && slices.Contains(sysmonIDs, id)) ||
				(cat == "process_creation" && c.Channel == sigmacheck.SecurityChannel && id == "4688")
			if !ok {
				continue
			}
			// Only events the Sigma rule itself matches: a recording can
			// hold the events around the one that fires.
			view, _ := c.SigmaView()
			if m, err := rule.Match(view); err != nil || !m {
				continue
			}
			out = append(out, c)
		}
	}
	return out
}

func writeReport(p *detect.Pack, skipped map[string][]string) {
	var b strings.Builder
	n := 0
	for _, v := range skipped {
		n += len(v)
	}
	fmt.Fprintf(&b, "# SigmaHQ pack report\n\nGenerated by `go run ./internal/detect/packgen` from SigmaHQ commit `%s` on %s.\n\n", p.Version, p.Date)
	fmt.Fprintf(&b, "%d rules shipped. %d Windows and Linux rules for these log sources were left out:\n\n", len(p.Rules), n)
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
	b.WriteString("| Rules | Reason |\n| ---: | --- |\n")
	for _, r := range reasons {
		fmt.Fprintf(&b, "| %d | %s |\n", len(skipped[r]), strings.ReplaceAll(r, "|", `\|`))
	}
	for _, r := range reasons {
		fmt.Fprintf(&b, "\n## %s\n\n", strings.ReplaceAll(r, "|", `\|`))
		sort.Strings(skipped[r])
		for _, f := range skipped[r] {
			fmt.Fprintf(&b, "- %s\n", strings.ReplaceAll(f, "|", `\|`))
		}
	}
	if err := os.WriteFile(filepath.Join(*outDir, "REPORT.md"), []byte(b.String()), 0o644); err != nil {
		log.Fatal(err)
	}
}
