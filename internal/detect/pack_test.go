package detect

import (
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
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
			rule, err := sigmacheck.Parse(src)
			if err != nil {
				t.Errorf("%s: %v", r.ID, err)
				continue
			}
			if rule.ID != r.RuleID {
				t.Errorf("%s: manifest says rule %s, file has %s", r.ID, r.RuleID, rule.ID)
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
			for _, err := range sigmacheck.Verify(rule, q.Datamodel, q.Search, tf) {
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
	if total < 500 {
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
		if o == nil || o.Rule == "" || o.License != "DRL-1.1" || !strings.HasPrefix(o.URL, "https://github.com/SigmaHQ/sigma/blob/") || o.LicenseURL == "" {
			t.Errorf("%s: origin %+v", d.ID, o)
			continue
		}
		// DRL 1.1: findings must name the rule's author.
		if o.Author == "" || !strings.Contains(o.Credit(), o.Author) {
			t.Errorf("%s: credit %q", d.ID, o.Credit())
		}
		if !strings.Contains(d.Query, "sourcetype=WinEventLog:*") {
			t.Errorf("%s: not limited to Windows events: %s", d.ID, d.Query)
		}
	}
}
