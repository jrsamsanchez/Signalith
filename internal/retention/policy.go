// Package retention decides how long each kind of data is kept and
// enforces it. Daily event indices are compacted, archived and deleted by
// per-category policies, resolved and closed findings and cases are
// deleted after a set time, and a disk guard deletes the oldest days
// before OpenSearch runs out of disk and stops accepting events.
//
// Every run plans first and then acts, and the same planner previews what
// a policy change would do before it is saved.
package retention

import (
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
)

// Category kinds.
const (
	// KindEvents are daily indices named <prefix>-<category>-YYYY.MM.DD.
	KindEvents = "events"
	// KindRecords are findings and cases: one index each, where resolved
	// and closed records expire and open ones are always kept.
	KindRecords = "records"
	// KindManaged is threat intel, which expires through each feed's
	// max_age and is not managed here.
	KindManaged = "managed"
	// KindMonthly are monthly indices named <prefix>_<category>-YYYY.MM,
	// such as the audit records of servers that share one OpenSearch.
	// Only keep_days and archive apply: a month goes once its last day is
	// older than keep_days, and the current month is never touched.
	KindMonthly = "monthly"
)

// IDs of the categories that are not data models.
const (
	Findings = "findings"
	Cases    = "cases"
	Intel    = "intel"
	// Audit is the audit records of servers that share one OpenSearch.
	Audit = "audit"
)

// DefaultAuditKeepDays is how long audit records are kept when the audit
// category has no policy of its own.
const DefaultAuditKeepDays = 400

// Category is one kind of data a policy applies to.
type Category struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

// Categories lists every category in display order: the data models, then
// other and risk events, findings, investigations and threat intel.
func Categories() []Category {
	var models, tail []Category
	for _, m := range datamodel.Models {
		c := Category{ID: strings.ToLower(m.Name), Kind: KindEvents, Description: m.Description}
		switch m.Name {
		case "Other":
			c.Name, c.Description = "Other events", "Events no parser recognized yet"
			tail = append([]Category{c}, tail...)
		case datamodel.RiskModel:
			c.Name, c.Description = "Risk events", "Risk that detections attributed to users and systems"
			tail = append(tail, c)
		default:
			name := strings.ReplaceAll(m.Name, "_", " ")
			c.Name = name[:1] + strings.ToLower(name[1:])
			models = append(models, c)
		}
	}
	return append(append(models, tail...),
		Category{ID: Findings, Name: "Findings", Kind: KindRecords,
			Description: "Alerts raised by detections; only resolved and closed findings are ever deleted"},
		Category{ID: Cases, Name: "Investigations", Kind: KindRecords,
			Description: "Cases; only resolved and closed cases are ever deleted"},
		Category{ID: Audit, Name: "Audit records", Kind: KindMonthly,
			Description: "Who changed what, on every server; kept by month"},
		Category{ID: Intel, Name: "Threat intel", Kind: KindManaged,
			Description: "Indicators expire through each feed's max_age setting"},
	)
}

// CategoryByID returns a category by its ID.
func CategoryByID(id string) (Category, bool) {
	for _, c := range Categories() {
		if c.ID == id {
			return c, true
		}
	}
	return Category{}, false
}

func categoryIDs(kinds ...string) []string {
	var out []string
	for _, c := range Categories() {
		for _, k := range kinds {
			if c.Kind == k {
				out = append(out, c.ID)
			}
		}
	}
	return out
}

// Limits on policy values.
const (
	MaxKeepDays = 36500
	MaxSizeGB   = 1 << 20
)

// GB is the unit of size caps. Like OpenSearch, a gigabyte is 1024³ bytes.
const GB = 1 << 30

// Policy says how long one category is kept and what happens to it on the
// way out. Each policy is complete: a category with its own policy does
// not inherit anything from the default policy.
type Policy struct {
	// KeepDays keeps data searchable for this many days after today;
	// older days are deleted, or archived and then deleted. 0 keeps data
	// forever. For findings and cases it is how long a resolved or closed
	// one is kept after its last change.
	KeepDays int `yaml:"keep_days" json:"keep_days"`
	// MaxSizeGB deletes the oldest days while the category is larger than
	// this. 0 is no cap.
	MaxSizeGB float64 `yaml:"max_size_gb,omitempty" json:"max_size_gb"`
	// CompactAfterDays makes days older than this read-only and merges
	// each into one segment, which saves disk and memory. 0 never compacts.
	CompactAfterDays int `yaml:"compact_after_days,omitempty" json:"compact_after_days"`
	// Archive exports a day to the archive folder before it is deleted.
	Archive bool `yaml:"archive,omitempty" json:"archive"`
}

// CapBytes returns the size cap in bytes, 0 for none.
func (p Policy) CapBytes() int64 { return int64(p.MaxSizeGB * GB) }

// Deletes reports whether the policy ever deletes anything.
func (p Policy) Deletes() bool { return p.KeepDays > 0 || p.MaxSizeGB > 0 }

// Problems lists what is wrong with a policy for a kind of category. Each
// problem starts with the setting's name.
func (p Policy) Problems(kind string) []string {
	var out []string
	switch {
	case p.KeepDays < 0:
		out = append(out, "keep_days cannot be negative (0 keeps data forever)")
	case p.KeepDays > MaxKeepDays:
		out = append(out, fmt.Sprintf("keep_days must be at most %d (0 keeps data forever)", MaxKeepDays))
	}
	if kind == KindRecords || kind == KindMonthly {
		what := "findings and investigations, which only use keep_days"
		if kind == KindMonthly {
			what = "audit records, which only use keep_days and archive"
		}
		for _, f := range []struct {
			name string
			set  bool
		}{{"max_size_gb", p.MaxSizeGB != 0}, {"compact_after_days", p.CompactAfterDays != 0}, {"archive", p.Archive && kind == KindRecords}} {
			if f.set {
				out = append(out, f.name+" does not apply to "+what)
			}
		}
		return out
	}
	if kind == KindManaged {
		return []string{"threat intel indicators expire through each feed's max_age setting"}
	}
	switch {
	case p.MaxSizeGB < 0:
		out = append(out, "max_size_gb cannot be negative (0 is no cap)")
	case p.MaxSizeGB > MaxSizeGB:
		out = append(out, fmt.Sprintf("max_size_gb must be at most %d", MaxSizeGB))
	}
	switch {
	case p.CompactAfterDays < 0:
		out = append(out, "compact_after_days cannot be negative (0 never compacts)")
	case p.KeepDays > 0 && p.CompactAfterDays >= p.KeepDays:
		out = append(out, "compact_after_days must be less than keep_days, or days are deleted before they are compacted")
	case p.CompactAfterDays > MaxKeepDays:
		out = append(out, fmt.Sprintf("compact_after_days must be at most %d", MaxKeepDays))
	}
	return out
}

// Guard defaults. OpenSearch stops placing new data on a node at 90% disk
// use (the high watermark) and makes every index read-only at 95% (the
// flood stage), which stops ingest; the guard acts well before that.
const (
	DefaultMaxDiskPercent = 85
	DefaultMinDays        = 7
	MinGuardPercent       = 50
	MaxGuardPercent       = 94
)

// Guard deletes the oldest event days when OpenSearch's data disk gets
// too full, across every event category.
type Guard struct {
	// Enabled defaults to true.
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled"`
	// MaxDiskPercent is the disk use the guard keeps OpenSearch under.
	MaxDiskPercent int `yaml:"max_disk_percent,omitempty" json:"max_disk_percent"`
	// MinDays is how many days before today the guard never deletes.
	MinDays int `yaml:"min_days,omitempty" json:"min_days"`
}

// IsEnabled reports whether the guard is on.
func (g Guard) IsEnabled() bool { return g.Enabled == nil || *g.Enabled }

// Normalized fills unset values with defaults.
func (g Guard) Normalized() Guard {
	on := g.IsEnabled()
	g.Enabled = &on
	if g.MaxDiskPercent == 0 {
		g.MaxDiskPercent = DefaultMaxDiskPercent
	}
	if g.MinDays == 0 {
		g.MinDays = DefaultMinDays
	}
	return g
}

// Problems lists what is wrong with guard settings.
func (g Guard) Problems() []string {
	var out []string
	if g.MaxDiskPercent != 0 && (g.MaxDiskPercent < MinGuardPercent || g.MaxDiskPercent > MaxGuardPercent) {
		out = append(out, fmt.Sprintf("max_disk_percent must be between %d and %d; OpenSearch stops accepting events at 95%%",
			MinGuardPercent, MaxGuardPercent))
	}
	if g.MinDays < 0 || g.MinDays > MaxKeepDays {
		out = append(out, fmt.Sprintf("min_days must be between 1 and %d", MaxKeepDays))
	}
	return out
}

// Config is what signalith.yaml says about retention. Settings made here
// cannot be changed on the Data retention page.
type Config struct {
	// Days is the default policy's keep_days until a default is saved on
	// the page (retention.days).
	Days     int
	Default  *Policy
	Policies map[string]Policy
	Guard    *Guard
}

// Problems lists what is wrong with the config, naming each setting as it
// appears in signalith.yaml.
func (c Config) Problems() []string {
	var out []string
	if c.Default != nil {
		for _, p := range c.Default.Problems(KindEvents) {
			out = append(out, "retention.default."+p)
		}
	}
	for id, p := range c.Policies {
		cat, ok := CategoryByID(id)
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("retention.policies.%s: unknown category; use one of %s",
				id, strings.Join(categoryIDs(KindEvents, KindRecords, KindMonthly), ", ")))
		case cat.Kind == KindManaged:
			out = append(out, "retention.policies.intel: threat intel indicators expire through each feed's max_age setting")
		default:
			for _, msg := range p.Problems(cat.Kind) {
				out = append(out, fmt.Sprintf("retention.policies.%s.%s", id, msg))
			}
		}
	}
	if c.Guard != nil {
		for _, p := range c.Guard.Problems() {
			out = append(out, "retention.guard."+p)
		}
	}
	return out
}

// Saved is what the Data retention page saved, in retention.yaml next to
// the asset and identity lists, or, when servers share their settings,
// the shared retention policies.
type Saved struct {
	// Days is retention.days, which only the shared policies carry: a
	// server with its own files reads it from signalith.yaml.
	Days     *int              `yaml:"-"`
	Default  *Policy           `yaml:"default,omitempty"`
	Policies map[string]Policy `yaml:"policies,omitempty"`
	Guard    *Guard            `yaml:"guard,omitempty"`
	// From says, for a shared setting applied from a server's
	// signalith.yaml, which one and when: by "days", "default", "guard"
	// or "policies.<category>".
	From map[string]Provenance `yaml:"-"`
}

// Provenance is where a shared setting's value came from, when not from
// the page: Source is yaml (a server's signalith.yaml) or import (the
// files of the server that founded the cluster).
type Provenance struct {
	Source string `json:"source"`
	Node   string `json:"node,omitempty"`
	At     string `json:"at,omitempty"`
}

// Note says where the value came from, for the page.
func (p Provenance) Note() string {
	what := "Applied from signalith.yaml"
	if p.Source == "import" {
		what = "Imported from the files"
	}
	if p.Node != "" {
		what += " on " + p.Node
	}
	if t, err := time.Parse(time.RFC3339Nano, p.At); err == nil {
		what += ", " + t.UTC().Format(time.DateOnly)
	}
	return what
}

func (s Saved) clone() Saved {
	out := Saved{Policies: maps.Clone(s.Policies), From: maps.Clone(s.From)}
	if s.Days != nil {
		d := *s.Days
		out.Days = &d
	}
	if s.Default != nil {
		d := *s.Default
		out.Default = &d
	}
	if s.Guard != nil {
		g := *s.Guard
		if g.Enabled != nil {
			on := *g.Enabled
			g.Enabled = &on
		}
		out.Guard = &g
	}
	return out
}

// problems checks saved settings the way the page's API does.
func (s Saved) problems() []string {
	var out []string
	if s.Days != nil && (*s.Days < 0 || *s.Days > MaxKeepDays) {
		out = append(out, fmt.Sprintf("days must be between 0 and %d (0 keeps data forever)", MaxKeepDays))
	}
	if s.Default != nil {
		for _, p := range s.Default.Problems(KindEvents) {
			out = append(out, "default."+p)
		}
	}
	for id, p := range s.Policies {
		cat, ok := CategoryByID(id)
		if !ok || cat.Kind == KindManaged {
			out = append(out, fmt.Sprintf("policies.%s: not a category with a policy", id))
			continue
		}
		for _, msg := range p.Problems(cat.Kind) {
			out = append(out, fmt.Sprintf("policies.%s.%s", id, msg))
		}
	}
	if s.Guard != nil {
		for _, p := range s.Guard.Problems() {
			out = append(out, "guard."+p)
		}
	}
	return out
}

// Where a setting comes from.
const (
	// SourceDefault: the category has no policy of its own. Event
	// categories follow the default policy; findings and investigations
	// are kept forever.
	SourceDefault = "default"
	// SourceDays: the default policy is retention.days from signalith.yaml,
	// which the page can replace.
	SourceDays = "days"
	// SourceBuiltin: the guard uses its built-in settings.
	SourceBuiltin = "builtin"
	// SourceUI: saved on the Data retention page.
	SourceUI = "ui"
	// SourceConfig: set in signalith.yaml, so the page cannot change it.
	SourceConfig = "config"
	// SourceFeeds: threat intel, which its feeds manage.
	SourceFeeds = "feeds"
)

// Settings are the policies in effect, merged from signalith.yaml and the
// page's saved settings. signalith.yaml wins.
type Settings struct {
	Default       Policy
	DefaultSource string
	// Policies holds the categories that have their own policy, and
	// Sources where each came from.
	Policies    map[string]Policy
	Sources     map[string]string
	Guard       Guard
	GuardSource string
	// From says where shared settings applied from a signalith.yaml came
	// from (see Saved.From).
	From map[string]Provenance
}

// Effective merges signalith.yaml with the page's saved settings.
func Effective(cfg Config, saved Saved) Settings {
	s := Settings{
		Default:       Policy{KeepDays: cfg.Days},
		DefaultSource: SourceDays,
		Policies:      map[string]Policy{},
		Sources:       map[string]string{},
		Guard:         Guard{}.Normalized(),
		GuardSource:   SourceBuiltin,
		From:          maps.Clone(saved.From),
	}
	if saved.Days != nil {
		// Shared policies carry retention.days; signalith.yaml no longer
		// sets it directly (it is applied when it changes).
		s.Default.KeepDays = *saved.Days
	}
	switch {
	case cfg.Default != nil:
		s.Default, s.DefaultSource = *cfg.Default, SourceConfig
	case saved.Default != nil:
		s.Default, s.DefaultSource = *saved.Default, SourceUI
	}
	for id, p := range saved.Policies {
		s.Policies[id], s.Sources[id] = p, SourceUI
	}
	for id, p := range cfg.Policies {
		s.Policies[id], s.Sources[id] = p, SourceConfig
	}
	switch {
	case cfg.Guard != nil:
		s.Guard, s.GuardSource = cfg.Guard.Normalized(), SourceConfig
	case saved.Guard != nil:
		s.Guard, s.GuardSource = saved.Guard.Normalized(), SourceUI
	}
	return s
}

// For returns the policy that applies to a category and where it comes
// from.
func (s Settings) For(id string) (Policy, string) {
	cat, ok := CategoryByID(id)
	if !ok {
		return Policy{}, ""
	}
	if cat.Kind == KindManaged {
		return Policy{}, SourceFeeds
	}
	if p, ok := s.Policies[id]; ok {
		return p, s.Sources[id]
	}
	switch cat.Kind {
	case KindRecords:
		return Policy{}, SourceDefault
	case KindMonthly:
		return Policy{KeepDays: DefaultAuditKeepDays}, SourceDefault
	}
	return s.Default, SourceDefault
}

// ShortestKeepDays returns the smallest keep_days of any event category,
// 0 when every one is kept forever.
func (s Settings) ShortestKeepDays() int {
	out := 0
	for _, c := range Categories() {
		if c.Kind != KindEvents {
			continue
		}
		if p, _ := s.For(c.ID); p.KeepDays > 0 && (out == 0 || p.KeepDays < out) {
			out = p.KeepDays
		}
	}
	return out
}

func (s Settings) clone() Settings {
	out := s
	out.Policies = maps.Clone(s.Policies)
	out.Sources = maps.Clone(s.Sources)
	out.From = maps.Clone(s.From)
	return out
}

// Change is a proposed settings change, for previews. Set exactly one of
// Category (with Policy, or nil Policy to go back to the default),
// Default or Guard.
type Change struct {
	Category string  `json:"category,omitempty"`
	Policy   *Policy `json:"policy,omitempty"`
	Default  *Policy `json:"default,omitempty"`
	Guard    *Guard  `json:"guard,omitempty"`
}

// Errors for settings changes.
var (
	ErrUnknownCategory = errors.New("unknown data category")
	ErrFromConfig      = errors.New("this is set in signalith.yaml; change it there")
	ErrManaged         = errors.New("threat intel indicators expire through each feed's max_age setting, not a retention policy")
)

// PolicyError lists what is wrong with a proposed policy or guard.
type PolicyError struct{ Problems []string }

func (e *PolicyError) Error() string { return strings.Join(e.Problems, "; ") }

// apply returns settings with a change applied, checking it first.
func (s Settings) apply(ch Change) (Settings, error) {
	out := s.clone()
	set := 0
	if ch.Category != "" {
		set++
		cat, ok := CategoryByID(ch.Category)
		switch {
		case !ok:
			return s, ErrUnknownCategory
		case cat.Kind == KindManaged:
			return s, ErrManaged
		case s.Sources[ch.Category] == SourceConfig:
			return s, ErrFromConfig
		}
		if ch.Policy == nil {
			delete(out.Policies, ch.Category)
			delete(out.Sources, ch.Category)
		} else {
			if p := ch.Policy.Problems(cat.Kind); len(p) > 0 {
				return s, &PolicyError{Problems: p}
			}
			out.Policies[ch.Category], out.Sources[ch.Category] = *ch.Policy, SourceUI
		}
	}
	if ch.Default != nil {
		set++
		if s.DefaultSource == SourceConfig {
			return s, ErrFromConfig
		}
		if p := ch.Default.Problems(KindEvents); len(p) > 0 {
			return s, &PolicyError{Problems: p}
		}
		out.Default, out.DefaultSource = *ch.Default, SourceUI
	}
	if ch.Guard != nil {
		set++
		if s.GuardSource == SourceConfig {
			return s, ErrFromConfig
		}
		if p := ch.Guard.Problems(); len(p) > 0 {
			return s, &PolicyError{Problems: p}
		}
		out.Guard, out.GuardSource = ch.Guard.Normalized(), SourceUI
	}
	if set != 1 {
		return s, &PolicyError{Problems: []string{"set one of category, default or guard"}}
	}
	return out, nil
}
