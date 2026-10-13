package detect

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// Content packs are rule sets from other projects that ship inside the
// binary, off until an admin turns rules on. Each pack is a folder under
// packs/ with a pack.yaml manifest and the rules exactly as their authors
// published them; they are converted when Signalith starts, so the
// converter's checks apply to every rule, and only rules whose test events
// pass in CI are listed in the manifest (see pack_test.go and
// internal/sigmacheck).
//
//go:embed packs/*/pack.yaml packs/*/rules/*.yml
var packFS embed.FS

// Origin says where a detection from a content pack came from. It is
// kept on overrides too, so the credit stays when an admin edits a rule.
type Origin struct {
	Pack       string   `yaml:"pack" json:"pack"`             // pack name, such as sigmahq
	PackTitle  string   `yaml:"pack_title" json:"pack_title"` // SigmaHQ community rules
	Rule       string   `yaml:"rule" json:"rule"`             // the rule's own ID in its project
	Author     string   `yaml:"author,omitempty" json:"author,omitempty"`
	License    string   `yaml:"license" json:"license"` // such as DRL-1.1
	LicenseURL string   `yaml:"license_url" json:"license_url"`
	URL        string   `yaml:"url" json:"url"`                           // the rule at the pinned version
	Status     string   `yaml:"status,omitempty" json:"status,omitempty"` // the author's maturity, such as stable or test
	References []string `yaml:"references,omitempty" json:"references,omitempty"`
}

// Credit is the attribution findings from the rule carry, as the rule's
// licence asks.
func (o *Origin) Credit() string {
	if o == nil {
		return ""
	}
	by := ""
	if o.Author != "" {
		by = "Rule by " + o.Author + ", "
	}
	return by + "from " + o.PackTitle + " (" + o.License + ", " + o.LicenseURL + ")"
}

// Pack is one content pack's manifest.
type Pack struct {
	Name        string     `yaml:"name" json:"name"`
	Title       string     `yaml:"title" json:"title"`
	Description string     `yaml:"description" json:"description"`
	Source      string     `yaml:"source" json:"source"`   // the project's repository
	Version     string     `yaml:"version" json:"version"` // the upstream commit the rules come from
	Date        string     `yaml:"date" json:"date"`       // when the pack was made
	License     string     `yaml:"license" json:"license"`
	LicenseURL  string     `yaml:"license_url" json:"license_url"`
	Notice      string     `yaml:"notice" json:"notice"`
	Rules       []PackRule `yaml:"rules" json:"-"`
}

// PackRule is one rule in a manifest.
type PackRule struct {
	ID     string `yaml:"id"`      // the Signalith detection ID
	RuleID string `yaml:"rule_id"` // the rule's own ID upstream
	File   string `yaml:"file"`    // under rules/
	Path   string `yaml:"path"`    // where it lives upstream
}

var (
	packsOnce sync.Once
	packs     []*Pack
	packDets  []*Detection
	packsErr  error
)

// Packs returns the content packs in the binary and their detections,
// converted once and shared (callers copy before changing one).
func Packs() ([]*Pack, []*Detection, error) {
	packsOnce.Do(func() { packs, packDets, packsErr = loadPacks(packFS) })
	return packs, packDets, packsErr
}

func loadPacks(fsys fs.FS) ([]*Pack, []*Detection, error) {
	manifests, err := fs.Glob(fsys, "packs/*/pack.yaml")
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(manifests)
	var ps []*Pack
	var ds []*Detection
	ids := map[string]string{}
	for _, m := range manifests {
		data, err := fs.ReadFile(fsys, m)
		if err != nil {
			return nil, nil, err
		}
		var p Pack
		if err := yaml.Unmarshal(data, &p); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", m, err)
		}
		dir := path.Dir(m)
		for _, r := range p.Rules {
			src, err := fs.ReadFile(fsys, path.Join(dir, "rules", r.File))
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", m, err)
			}
			d, err := PackDetection(&p, r, src)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %s: %w", m, r.File, err)
			}
			if prev, dup := ids[d.ID]; dup {
				return nil, nil, fmt.Errorf("%s: id %s is used by %s too", m, d.ID, prev)
			}
			ids[d.ID] = r.File
			ds = append(ds, d)
		}
		p.Rules = nil
		ps = append(ps, &p)
	}
	return ps, ds, nil
}

// Risk the pack rules add, by Sigma level. Low rules only add risk, as
// Splunk ES's risk-based alerting does with weak signals; the rest raise
// findings and add risk.
var sigmaRisk = map[string]int{"informational": 5, "low": 10, "medium": 25, "high": 50, "critical": 80}

// packThrottle is what makes two findings of a pack rule different: the
// host, the program and what it acted on.
func packThrottle(category, datamodel string) []string {
	switch category {
	case "process_access", "create_remote_thread":
		return []string{"host", "process_path", "target_process_path"}
	}
	switch strings.ToLower(datamodel) {
	case "network_traffic":
		return []string{"host", "process_path", "dest", "dest_port"}
	case "filesystem":
		return []string{"host", "process_path", "file_path"}
	case "registry":
		return []string{"host", "process_path", "registry_path"}
	case "network_resolution":
		return []string{"host", "process_path", "query"}
	case "image_load":
		return []string{"host", "process_path", "loaded_file_path"}
	case "script":
		return []string{"host", "script_block_id", "script_part"}
	}
	return []string{"host", "user", "process"}
}

// PackDetection converts one pack rule, strictly, into an off detection
// with the pack's defaults: a title naming the host, one finding a day per
// host, program and what it acted on (packThrottle), and risk on the user
// and the host.
func PackDetection(p *Pack, r PackRule, src []byte) (*Detection, error) {
	res, err := ConvertSigmaWith(src, SigmaOptions{Strict: true})
	if err != nil {
		return nil, err
	}
	var meta struct {
		Title      string   `yaml:"title"`
		Author     string   `yaml:"author"`
		Status     string   `yaml:"status"`
		Level      string   `yaml:"level"`
		References []string `yaml:"references"`
		Logsource  struct {
			Product  string `yaml:"product"`
			Category string `yaml:"category"`
		} `yaml:"logsource"`
	}
	if err := yaml.Unmarshal(src, &meta); err != nil {
		return nil, err
	}
	d := res.Detection
	d.ID = r.ID
	d.Title = strings.TrimSpace(meta.Title) + " on $host$"
	d.Enabled = false
	d.Source = ""
	q, err := query.Parse(d.Query)
	if err != nil {
		return nil, err
	}
	d.Throttle = Throttle{Window: "24h", Fields: packThrottle(strings.ToLower(meta.Logsource.Category), q.Datamodel)}
	score := sigmaRisk[strings.ToLower(meta.Level)]
	if score == 0 {
		score = 25
	}
	d.Risk = &Risk{Score: score, Objects: []RiskObject{{Field: "user", Type: "user"}, {Field: "host", Type: "system"}}}
	if l := strings.ToLower(meta.Level); l == "low" || l == "informational" {
		d.Risk.Only = true
	}
	tags := []string{"sigma", p.Name}
	if meta.Logsource.Product != "" {
		tags = append(tags, strings.ToLower(meta.Logsource.Product))
	}
	if meta.Logsource.Category != "" {
		tags = append(tags, strings.ReplaceAll(strings.ToLower(meta.Logsource.Category), "_", "-"))
	}
	d.Tags = tags
	d.Origin = &Origin{
		Pack: p.Name, PackTitle: p.Title, Rule: r.RuleID, Author: strings.TrimSpace(meta.Author),
		License: p.License, LicenseURL: p.LicenseURL, Status: meta.Status,
		URL:        strings.TrimSuffix(p.Source, "/") + "/blob/" + p.Version + "/" + r.Path,
		References: meta.References,
	}
	d.Defaults()
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return d, nil
}
