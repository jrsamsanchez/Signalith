package detect

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/splcheck"
)

// Content packs are rule sets from other projects that ship inside the
// binary, off until an admin turns rules on. Each pack is a folder under
// packs/ with a pack.yaml manifest and the rules exactly as their authors
// published them; they are converted when Signalith starts, so the
// converter's checks apply to every rule, and only rules whose test events
// pass in CI are listed in the manifest (see pack_test.go and
// internal/sigmacheck).
//
//go:embed packs/*/pack.yaml packs/*/rules/*.yml packs/*/macros/*.yml
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
	Name        string `yaml:"name" json:"name"`
	Title       string `yaml:"title" json:"title"`
	Description string `yaml:"description" json:"description"`
	Source      string `yaml:"source" json:"source"`   // the project's repository
	Version     string `yaml:"version" json:"version"` // the upstream commit the rules come from
	Date        string `yaml:"date" json:"date"`       // when the pack was made
	License     string `yaml:"license" json:"license"`
	LicenseURL  string `yaml:"license_url" json:"license_url"`
	Notice      string `yaml:"notice" json:"notice"`
	// Format is how the rules are written: sigma (the default) or splunk
	// (security_content detections, with the macros they use in macros/).
	Format string     `yaml:"format,omitempty" json:"format,omitempty"`
	Rules  []PackRule `yaml:"rules" json:"-"`

	macros map[string]*splcheck.Macro
}

// PackRule is one rule in a manifest.
type PackRule struct {
	ID     string `yaml:"id"`      // the Signalith detection ID
	RuleID string `yaml:"rule_id"` // the rule's own ID upstream
	File   string `yaml:"file"`    // under rules/
	Path   string `yaml:"path"`    // where it lives upstream
}

var (
	embeddedOnce sync.Once
	embedded     packSet

	packsMu sync.RWMutex
	update  *packSet // a content update in use, else nil
)

// packSet is a set of packs and their detections, from the binary or a
// content update.
type packSet struct {
	packs []*Pack
	dets  []*Detection
	err   error
	// Version is when the content was made (content.VersionLayout).
	version string
}

func builtinPacks() *packSet {
	embeddedOnce.Do(func() {
		embedded.packs, embedded.dets, _, embedded.err = loadPacks(packFS, false)
		embedded.version = packsVersion(embedded.packs)
	})
	return &embedded
}

// packsVersion is the content version of packs built into Signalith: the
// day its newest pack was made.
func packsVersion(ps []*Pack) string {
	v := ""
	for _, p := range ps {
		if d := strings.ReplaceAll(p.Date, "-", ""); len(d) == 8 && d > v {
			v = d
		}
	}
	if v == "" {
		return ""
	}
	return v + "000000"
}

// Packs returns the content packs in use and their detections, converted
// once and shared (callers copy before changing one): those of a content
// update when one is in use (UsePacks), else those built into Signalith.
func Packs() ([]*Pack, []*Detection, error) {
	packsMu.RLock()
	u := update
	packsMu.RUnlock()
	if u != nil {
		return u.packs, u.dets, nil
	}
	b := builtinPacks()
	return b.packs, b.dets, b.err
}

// ContentVersion is the version of the content in use and whether it is
// a content update.
func ContentVersion() (version string, updated bool) {
	packsMu.RLock()
	defer packsMu.RUnlock()
	if update != nil {
		return update.version, true
	}
	return builtinPacks().version, false
}

// BuiltinContentVersion is the version of the packs built into Signalith.
// A content update older than it is not used.
func BuiltinContentVersion() string { return builtinPacks().version }

// LoadPacks converts the packs of a content update (packs/<name>/ in
// fsys). A rule this build cannot convert, such as one for a log source
// it does not know yet, is left out and reported in skipped; a broken
// manifest or a clash of IDs is an error.
func LoadPacks(fsys fs.FS) (ps []*Pack, ds []*Detection, skipped []error, err error) {
	ps, ds, skipped, err = loadPacks(fsys, true)
	if err == nil && len(ps) == 0 {
		err = errors.New("the content has no packs")
	}
	return ps, ds, skipped, err
}

// UsePacks makes packs from LoadPacks, at version, the ones in use; nil
// goes back to the packs built into Signalith. Libraries pick them up
// with Library.ReloadPacks.
func UsePacks(ps []*Pack, ds []*Detection, version string) {
	packsMu.Lock()
	defer packsMu.Unlock()
	if ps == nil {
		update = nil
		return
	}
	update = &packSet{packs: ps, dets: ds, version: version}
}

func loadPacks(fsys fs.FS, lenient bool) ([]*Pack, []*Detection, []error, error) {
	manifests, err := fs.Glob(fsys, "packs/*/pack.yaml")
	if err != nil {
		return nil, nil, nil, err
	}
	sort.Strings(manifests)
	var ps []*Pack
	var ds []*Detection
	var skipped []error
	ids := map[string]string{}
	for _, m := range manifests {
		data, err := fs.ReadFile(fsys, m)
		if err != nil {
			return nil, nil, nil, err
		}
		var p Pack
		if err := yaml.Unmarshal(data, &p); err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", m, err)
		}
		dir := path.Dir(m)
		if p.Format == "splunk" {
			if p.macros, err = loadMacros(fsys, dir); err != nil {
				return nil, nil, nil, err
			}
		}
		for _, r := range p.Rules {
			src, err := fs.ReadFile(fsys, path.Join(dir, "rules", r.File))
			var d *Detection
			if err == nil {
				d, err = PackDetection(&p, r, src)
			}
			if err != nil {
				err = fmt.Errorf("%s: %s: %w", m, r.File, err)
				if lenient {
					skipped = append(skipped, err)
					continue
				}
				return nil, nil, nil, err
			}
			if prev, dup := ids[d.ID]; dup {
				return nil, nil, nil, fmt.Errorf("%s: id %s is used by %s too", m, d.ID, prev)
			}
			ids[d.ID] = r.File
			ds = append(ds, d)
		}
		p.Rules = nil
		ps = append(ps, &p)
	}
	return ps, ds, skipped, nil
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
	switch p.Format {
	case "", "sigma":
	case "splunk":
		return SplunkDetection(p, r, src)
	default:
		return nil, fmt.Errorf("pack format %q is unknown", p.Format)
	}
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
