// Command splcorpus collects the searches of a Splunk security_content
// checkout, with its macros expanded, into the corpus TestSplunkCorpus
// runs: every detection that is not deprecated, every baseline and every
// dashboard search. Macros the checkout does not define are left as they
// are, so the test counts them. The searches are Splunk's, from
// github.com/splunk/security_content (Apache License 2.0).
//
//	go run ./internal/search/splcorpus -splunk ../security_content
package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	splunkDir = flag.String("splunk", "", "security_content checkout")
	out       = flag.String("out", "internal/search/testdata/splunk_corpus.json.gz", "corpus file")
)

// Search is one search of the corpus.
type Search struct {
	Source string `json:"source"` // detection, baseline or dashboard
	Name   string `json:"name"`
	Search string `json:"search"`
}

type macro struct {
	Definition string   `yaml:"definition"`
	Arguments  []string `yaml:"arguments"`
}

func main() {
	flag.Parse()
	if *splunkDir == "" {
		log.Fatal("-splunk is required")
	}
	macros := map[string]macro{}
	files, _ := filepath.Glob(filepath.Join(*splunkDir, "macros", "*.yml"))
	for _, f := range files {
		var m struct {
			Name  string `yaml:"name"`
			macro `yaml:",inline"`
		}
		if err := readYAML(f, &m); err != nil {
			log.Fatal(err)
		}
		key := m.Name
		if len(m.Arguments) > 0 {
			key = fmt.Sprintf("%s(%d)", m.Name, len(m.Arguments))
		}
		macros[key] = m.macro
	}
	// Splunk's CIM app defines this one, not security_content.
	macros["drop_dm_object_name(1)"] = macro{Definition: "rename $object$.* as *", Arguments: []string{"object"}}
	var corpus []Search
	add := func(source, name, s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		corpus = append(corpus, Search{source, name, expand(s, macros, 0)})
	}
	for _, dir := range []string{"detections", "baselines"} {
		err := filepath.WalkDir(filepath.Join(*splunkDir, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yml") || strings.Contains(p, "deprecated") {
				return err
			}
			var y struct {
				Name   string `yaml:"name"`
				Status string `yaml:"status"`
				Search string `yaml:"search"`
			}
			if err := readYAML(p, &y); err != nil {
				return err
			}
			if y.Status == "deprecated" || y.Status == "removed" {
				return nil
			}
			add(strings.TrimSuffix(dir, "s"), y.Name, y.Search)
			return nil
		})
		if err != nil {
			log.Fatal(err)
		}
	}
	boards, _ := filepath.Glob(filepath.Join(*splunkDir, "dashboards", "*.json"))
	for _, f := range boards {
		raw, err := os.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}
		var b struct {
			Title       string `json:"title"`
			DataSources map[string]struct {
				Type    string `json:"type"`
				Name    string `json:"name"`
				Options struct {
					Query string `json:"query"`
				} `json:"options"`
			} `json:"dataSources"`
		}
		if err := json.Unmarshal(raw, &b); err != nil {
			log.Fatal(f, err)
		}
		var ids []string
		for id := range b.DataSources {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			ds := b.DataSources[id]
			if ds.Type == "ds.search" {
				add("dashboard", b.Title+": "+ds.Name, ds.Options.Query)
			}
		}
	}
	sort.SliceStable(corpus, func(i, j int) bool {
		if corpus[i].Source != corpus[j].Source {
			return corpus[i].Source < corpus[j].Source
		}
		return corpus[i].Name < corpus[j].Name
	})
	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	zw, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	enc := json.NewEncoder(zw)
	enc.SetIndent("", " ")
	if err := enc.Encode(corpus); err != nil {
		log.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d searches\n", len(corpus))
}

func readYAML(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(raw, v)
}

var (
	macroRE   = regexp.MustCompile("`([^`]+)`")
	commentRE = regexp.MustCompile("(?s)```.*?```")
)

// expand replaces each `name` or `name(a, b)` with its definition, as
// Splunk does, up to 10 levels deep.
func expand(s string, macros map[string]macro, depth int) string {
	if depth > 10 {
		return s
	}
	// ```text``` is a comment.
	s = commentRE.ReplaceAllString(s, " ")
	return macroRE.ReplaceAllStringFunc(s, func(ref string) string {
		body := ref[1 : len(ref)-1]
		name, args := body, []string(nil)
		if i := strings.Index(body, "("); i > 0 && strings.HasSuffix(body, ")") {
			name = body[:i]
			args = splitArgs(body[i+1 : len(body)-1])
		}
		key := name
		if args != nil {
			key = fmt.Sprintf("%s(%d)", name, len(args))
		}
		m, ok := macros[key]
		if !ok && args == nil && strings.HasSuffix(name, "_filter") {
			// contentctl gives every detection a filter macro of its
			// own, empty until a customer tunes it.
			return "search *"
		}
		if !ok {
			return ref
		}
		def := m.Definition
		for i, a := range m.Arguments {
			if i < len(args) {
				def = strings.ReplaceAll(def, "$"+a+"$", args[i])
			}
		}
		return expand(def, macros, depth+1)
	})
}

// splitArgs splits a macro's arguments at commas outside quotes.
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			cur.WriteRune(r)
		case r == ',' && !quoted:
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(out, strings.TrimSpace(cur.String()))
}
