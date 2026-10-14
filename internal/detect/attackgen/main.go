// Command attackgen checks the Splunk pack against the real attack
// recordings its rules name (tests.attack_data in each rule, from
// https://github.com/splunk/attack_data): each recorded Windows event goes
// through Signalith's parser, and the converted detection must read it as
// the rule's where clause does, and find at least one event, as Splunk
// does on that data.
//
//	go run ./internal/detect/attackgen -splunk ../security_content
package main

import (
	"bytes"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
	"github.com/jrsamsanchez/signalith/internal/splcheck"
)

var (
	packDir  = flag.String("pack", "internal/detect/packs/splunk", "pack folder")
	cacheDir = flag.String("cache", filepath.Join(os.TempDir(), "attack_data"), "download cache")
	maxBytes = flag.Int64("max", 40<<20, "largest recording to read")
	only     = flag.String("only", "", "check only rule files containing this")
	write    = flag.Bool("write", false, "add up to two recorded events each rule finds to its test file")
	list     = flag.String("list", "", "check only the rule files this file lists, one a line")
)

type manifest struct {
	Rules []struct {
		ID   string `yaml:"id"`
		File string `yaml:"file"`
	} `yaml:"rules"`
}

type ruleTests struct {
	Tests []struct {
		AttackData []struct {
			Data       string `yaml:"data"`
			Source     string `yaml:"source"`
			Sourcetype string `yaml:"sourcetype"`
		} `yaml:"attack_data"`
	} `yaml:"tests"`
}

type event struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Channel     string `xml:"Channel"`
		Computer    string `xml:"Computer"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

func main() {
	flag.Parse()
	var m manifest
	src, err := os.ReadFile(filepath.Join(*packDir, "pack.yaml"))
	if err != nil {
		log.Fatal(err)
	}
	if err := yaml.Unmarshal(src, &m); err != nil {
		log.Fatal(err)
	}
	macros := map[string]*splcheck.Macro{}
	files, _ := filepath.Glob(filepath.Join(*packDir, "macros", "*.yml"))
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			log.Fatal(err)
		}
		mc, err := splcheck.ParseMacro(src)
		if err != nil {
			log.Fatalf("%s: %v", f, err)
		}
		macros[mc.Name] = mc
	}
	var listed map[string]bool
	if *list != "" {
		b, err := os.ReadFile(*list)
		if err != nil {
			log.Fatal(err)
		}
		listed = map[string]bool{}
		for _, l := range strings.Fields(string(b)) {
			listed[l] = true
		}
	}
	fired, silent, noData, wrong := 0, []string{}, 0, []string{}
	for _, r := range m.Rules {
		if *only != "" && !strings.Contains(r.File, *only) || listed != nil && !listed[r.File] {
			continue
		}
		src, err := os.ReadFile(filepath.Join(*packDir, "rules", r.File))
		if err != nil {
			log.Fatal(err)
		}
		rule, err := splcheck.Parse(src, macros)
		if err != nil {
			log.Fatalf("%s: %v", r.File, err)
		}
		filter, err := detect.SplunkFilter(rule)
		if err != nil {
			log.Fatalf("%s: %v", r.File, err)
		}
		var rt ruleTests
		_ = yaml.Unmarshal(src, &rt)
		var cases []sigmacheck.Case
		for _, t := range rt.Tests {
			for _, a := range t.AttackData {
				if !strings.HasPrefix(a.Sourcetype, "XmlWinEventLog") {
					continue
				}
				evs, err := recording(a.Data)
				if err != nil {
					log.Printf("%s: %v", r.File, err)
					continue
				}
				cases = append(cases, evs...)
			}
		}
		if len(cases) == 0 {
			noData++
			continue
		}
		dm := splcheck.NodeModel[rule.Node]
		hits := 0
		var found []sigmacheck.Case
		for _, c := range cases {
			doc, model := splcheck.Stored(c)
			// The node's own events: a Processes rule does not read a
			// process access, which is in Endpoint too.
			splunk := splcheck.Reads(rule, c)
			ours := false
			if dm == "" || strings.EqualFold(model, dm) {
				ours, err = search.MatchDoc(filter, doc)
				if err != nil {
					log.Fatalf("%s: %v", r.File, err)
				}
			}
			if ours != splunk {
				wrong = append(wrong, fmt.Sprintf("%s: Splunk %v, detection %v on %s", r.File, splunk, ours, sigmacheck.String(c.Data)))
			}
			if ours {
				hits++
				if splunk {
					c.Expect = true
					found = append(found, c)
				}
			}
		}
		if *write {
			if err := keep(r.File, found); err != nil {
				log.Fatal(err)
			}
		}
		if hits > 0 {
			fired++
		} else {
			silent = append(silent, fmt.Sprintf("%s (%d events)", r.File, len(cases)))
		}
	}
	sort.Strings(silent)
	fmt.Printf("fired %d, silent %d, no Windows recording %d, disagreements %d\n", fired, len(silent), noData, len(wrong))
	for _, s := range silent {
		fmt.Println("silent:", s)
	}
	for _, w := range wrong {
		fmt.Println("disagree:", w)
	}
}

// keep puts a rule's smallest recorded events that it finds (two at most,
// distinct) in its test file, in place of the ones there.
func keep(file string, found []sigmacheck.Case) error {
	path := filepath.Join(*packDir, "tests", strings.TrimSuffix(file, ".yml")+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	tf, err := sigmacheck.DecodeTestFile(data)
	if err != nil {
		return err
	}
	tf.Cases = slices.DeleteFunc(tf.Cases, func(c sigmacheck.Case) bool { return c.Source == splcheck.AttackDataSource })
	size := func(c sigmacheck.Case) int { return len(sigmacheck.String(c.Data)) }
	sort.SliceStable(found, func(i, j int) bool { return size(found[i]) < size(found[j]) })
	seen := map[string]bool{}
	for _, c := range found {
		k := sigmacheck.String(c.Data)
		if seen[k] || size(c) > maxEventSize || secretRe.MatchString(k) {
			continue
		}
		seen[k] = true
		c.Source = splcheck.AttackDataSource
		tf.Cases = append(tf.Cases, c)
		if len(seen) == 2 {
			break
		}
	}
	out, err := sigmacheck.EncodeTestFile(tf)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

// secretRe finds credentials a recording may hold (a lab's access
// tokens and keys), which stay out of the repository.
var secretRe = regexp.MustCompile(`ya29\.|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abpr]-|-----BEGIN [A-Z ]*PRIVATE KEY|eyJ[A-Za-z0-9_-]{10,}\.eyJ|AIza[0-9A-Za-z_-]{35}`)

// maxEventSize keeps a long script block or call stack out of the tests.
const maxEventSize = 4000

// recording reads a recorded Windows event log (one XML event a line).
func recording(url string) ([]sigmacheck.Case, error) {
	path := filepath.Join(*cacheDir, strings.NewReplacer("https://", "", "/", "_").Replace(url))
	if _, err := os.Stat(path); err != nil {
		if err := download(url, path); err != nil {
			return nil, err
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, *maxBytes))
	if err != nil {
		return nil, err
	}
	// Each event on its own: one that does not decode (a script block
	// with a stray control character) does not end the recording.
	var out []sigmacheck.Case
	for _, raw := range eventRe.FindAll(b, -1) {
		var e event
		d := xml.NewDecoder(bytes.NewReader(raw))
		d.Strict = false
		if err := d.Decode(&e); err != nil {
			continue
		}
		data := map[string]string{}
		for _, v := range e.Data {
			if v.Name != "" {
				data[v.Name] = strings.TrimSpace(v.Value)
			}
		}
		if e.System.Channel == sigmacheck.SystemChannel && e.System.Provider.Name != "" {
			// System event IDs are their provider's.
			data["Provider_Name"] = e.System.Provider.Name
		}
		out = append(out, sigmacheck.Case{Source: "attack_data", Channel: e.System.Channel, EventID: e.System.EventID, Data: data})
	}
	return out, nil
}

var eventRe = regexp.MustCompile(`(?s)<Event[ >].*?</Event>`)

func download(url, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	tmp := path + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, io.LimitReader(resp.Body, *maxBytes)); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}
