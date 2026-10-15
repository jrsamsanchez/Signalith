package clustercfg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// A server that kept its own files (it served alone, or waited to join
// the cluster) and joins with signalith join --merge keeps what the
// cluster lacks: Merge adds its feeds, retention policies, users and
// shared settings that the shared settings do not have, and changes
// nothing the cluster has. What differs is listed in its migration
// report, <prefix>_config/migration-report:<node id> (signed), for an
// admin to decide. Differing retention policies set the confirmation
// hold (reason "merge"), so nothing is deleted by a policy the servers
// disagree on until an admin confirms.

// The migration reports' document kind.
const (
	MigrationKind   = "migration-report"
	MigrationWatch  = "migration-reports"
	MigrationFormat = 1
)

// What a merge item is.
const (
	MergeFeed      = "feed"
	MergeRetention = "retention"
	MergeUser      = "user"
	MergeSetting   = "setting"
	MergeAgents    = "agents"
)

// MergeItem is one thing a merge added or found different. Detail says
// what differs in plain words; it never holds a password, key, token or
// password hash.
type MergeItem struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Detail string `json:"detail,omitempty"`
}

// MigrationReport is what a server's merge added and what it found
// different.
type MigrationReport struct {
	NodeID string      `json:"node_id"`
	Name   string      `json:"name"`
	By     string      `json:"by"`
	At     time.Time   `json:"at"`
	Added  []MergeItem `json:"added"`
	Differ []MergeItem `json:"differ"`
	// Held is true when the merge set the retention policies'
	// confirmation hold.
	Held         bool `json:"held,omitempty"`
	shared.Extra `json:"-"`
}

// MarshalJSON writes the report with the fields this version does not
// know.
func (r MigrationReport) MarshalJSON() ([]byte, error) {
	type plain MigrationReport
	return shared.MarshalExtra(plain(r), r.Extra)
}

// UnmarshalJSON reads the report, keeping the fields this version does
// not know.
func (r *MigrationReport) UnmarshalJSON(data []byte) error {
	type plain MigrationReport
	var p plain
	extra, err := shared.UnmarshalExtra(data, &p)
	*r = MigrationReport(p)
	r.Extra = extra
	return err
}

// Reports holds the migration reports, made again on each hub the
// runtime builds (Track).
type Reports struct {
	mu sync.Mutex
	c  *shared.Collection[MigrationReport]
}

// NewReports returns the holder; Track makes the collection.
func NewReports() *Reports { return &Reports{} }

// Track makes the collection on h.
func (r *Reports) Track(h *shared.Hub) {
	c := shared.NewCollection[MigrationReport](h, MigrationKind, MigrationWatch, MigrationFormat)
	r.mu.Lock()
	r.c = c
	r.mu.Unlock()
}

// Reset is for the trackers: the reports keep no subscribers.
func (r *Reports) Reset() {}

func (r *Reports) coll() (*shared.Collection[MigrationReport], error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.c == nil {
		return nil, errors.New("the shared settings are not open")
	}
	return r.c, nil
}

// Get returns the report of the server nodeID.
func (r *Reports) Get(nodeID string) (*MigrationReport, bool) {
	c, err := r.coll()
	if err != nil {
		return nil, false
	}
	v, _, ok := c.Get(nodeID)
	return v, ok
}

// List returns every report.
func (r *Reports) List() []MigrationReport {
	c, err := r.coll()
	if err != nil {
		return nil
	}
	var out []MigrationReport
	for _, it := range c.List() {
		if it.Value != nil {
			out = append(out, *it.Value)
		}
	}
	return out
}

// Save writes rep as its server's report, replacing an earlier one.
func (r *Reports) Save(ctx context.Context, by string, rep *MigrationReport) error {
	c, err := r.coll()
	if err != nil {
		return err
	}
	if _, _, ok := c.Get(rep.NodeID); !ok {
		if _, err := c.Create(ctx, by, rep.NodeID, rep); err == nil {
			return nil
		}
		// Made meanwhile: replace it.
	}
	_, err = c.Mutate(ctx, by, rep.NodeID, func(b *MigrationReport) error {
		*b = *rep
		return nil
	})
	return err
}

// errMergeNothing ends a change that has nothing to write.
var errMergeNothing = errors.New("nothing to merge")

// MergeOptions say what the cluster shares, by its level.
type MergeOptions struct {
	// Users and Settings: the cluster keeps users, and the settings of the
	// Settings page, in the shared settings.
	Users, Settings bool
}

// Merge adds what this server's own files (f) hold and the shared
// settings (d) lack, for the user by, and returns the report of what it
// added and what differs. It never changes what the cluster has. It can
// run again: what it added before counts as there.
func Merge(ctx context.Context, d *Docs, f Files, by string, o MergeOptions) (*MigrationReport, error) {
	if d.Hub() == nil || d.Hub().Keys() == nil || d.Hub().Keys().Active() == nil {
		return nil, errors.New("this server has no cluster key")
	}
	rep := &MigrationReport{NodeID: f.NodeID, Name: f.Node, By: by, At: f.now().UTC(), Added: []MergeItem{}, Differ: []MergeItem{}}
	if err := mergeFeeds(ctx, d, f, by, rep); err != nil {
		return nil, fmt.Errorf("the threat intel feeds: %w", err)
	}
	if err := mergeRetention(ctx, d, f, by, rep); err != nil {
		return nil, fmt.Errorf("the retention policies: %w", err)
	}
	if a := d.Auth(); o.Users && a != nil {
		if err := mergeUsers(ctx, a, f, by, rep); err != nil {
			return nil, fmt.Errorf("the users: %w", err)
		}
	}
	if o.Settings {
		if err := mergeSettings(ctx, d, f, by, rep); err != nil {
			return nil, fmt.Errorf("the settings: %w", err)
		}
	}
	return rep, nil
}

// localFeeds are this server's feeds: signalith.yaml's, then those of its
// page with another name.
func localFeeds(c *config.Config) ([]intel.FeedSpec, error) {
	page, err := (&intel.FileList{Path: c.IntelFeedsFile()}).Load()
	if err != nil {
		return nil, err
	}
	out := yamlFeeds(c)
	for _, s := range page.UI {
		if !slices.ContainsFunc(out, func(y intel.FeedSpec) bool { return y.Name == s.Name }) {
			out = append(out, s)
		}
	}
	return out, nil
}

func mergeFeeds(ctx context.Context, d *Docs, f Files, by string, rep *MigrationReport) error {
	local, err := localFeeds(f.Config())
	if err != nil {
		return err
	}
	if len(local) == 0 {
		return nil
	}
	k := d.Hub().Keys().Active()
	now := f.now()
	var added, differ []MergeItem
	_, err = d.Feeds().Mutate(ctx, by, func(b *FeedsBody) error {
		added, differ = nil, nil
		for _, s := range local {
			i := slices.IndexFunc(b.Feeds, func(e FeedEntry) bool { return e.Name == s.Name })
			if i < 0 {
				e, err := entryOf(s, k, stamp(FromImport, f.Node, now))
				if err != nil {
					return err
				}
				b.Feeds = append(b.Feeds, e)
				added = append(added, MergeItem{Kind: MergeFeed, ID: s.Name})
				continue
			}
			e := b.Feeds[i]
			var what []string
			if e.URL != s.URL {
				what = append(what, "address")
			}
			if e.Kind != s.Kind || e.Format != s.Format || e.Type != s.Type {
				what = append(what, "format")
			}
			if len(what) > 0 {
				differ = append(differ, MergeItem{Kind: MergeFeed, ID: s.Name,
					Detail: "its " + strings.Join(what, " and ") + " differ from the cluster's feed of the same name, which is kept"})
			}
		}
		if len(added) == 0 {
			return errMergeNothing
		}
		return nil
	})
	if err != nil && !errors.Is(err, errMergeNothing) {
		return err
	}
	rep.Added = append(rep.Added, added...)
	rep.Differ = append(rep.Differ, differ...)
	return nil
}

// policyText is a retention policy as the report says it.
func policyText(p retention.Policy) string {
	b, _ := json.Marshal(p)
	return string(b)
}

func mergeRetention(ctx context.Context, d *Docs, f Files, by string, rep *MigrationReport) error {
	c := f.Config()
	saved, err := retention.NewStore(RetentionFile(c)).Get()
	if err != nil {
		return err
	}
	eff := retention.Effective(c.RetentionPolicies(), saved)
	now := f.now()
	from := func(src string) From {
		if src == retention.SourceConfig {
			return *stamp(FromYAML, f.Node, now)
		}
		return *stamp(FromImport, f.Node, now)
	}
	ownDefault := eff.DefaultSource == retention.SourceConfig || eff.DefaultSource == retention.SourceUI
	ownGuard := eff.GuardSource != retention.SourceBuiltin
	if len(eff.Policies) == 0 && !ownDefault && !ownGuard {
		return nil
	}
	var added, differ []MergeItem
	held := false
	_, err = d.Retention().Mutate(ctx, by, func(b *RetentionBody) error {
		added, differ, held = nil, nil, false
		if b.From == nil {
			b.From = map[string]From{}
		}
		for _, id := range slices.Sorted(maps.Keys(eff.Policies)) {
			p := eff.Policies[id]
			cur, ok := b.Policies[id]
			switch {
			case !ok:
				if b.Policies == nil {
					b.Policies = map[string]retention.Policy{}
				}
				b.Policies[id] = p
				b.From["policies."+id] = from(eff.Sources[id])
				added = append(added, MergeItem{Kind: MergeRetention, ID: id})
			case !reflect.DeepEqual(cur, p):
				differ = append(differ, MergeItem{Kind: MergeRetention, ID: id,
					Detail: "this server's policy " + policyText(p) + " differs from the cluster's " + policyText(cur) + ", which is kept"})
			}
		}
		if ownDefault {
			switch {
			case b.Default == nil:
				p := eff.Default
				b.Default = &p
				b.From["default"] = from(eff.DefaultSource)
				added = append(added, MergeItem{Kind: MergeRetention, ID: "default"})
			case !reflect.DeepEqual(*b.Default, eff.Default):
				differ = append(differ, MergeItem{Kind: MergeRetention, ID: "default",
					Detail: "this server's default policy " + policyText(eff.Default) + " differs from the cluster's " + policyText(*b.Default) + ", which is kept"})
			}
		}
		if ownGuard {
			switch {
			case b.Guard == nil:
				g := eff.Guard
				b.Guard = &g
				b.From["guard"] = from(eff.GuardSource)
				added = append(added, MergeItem{Kind: MergeRetention, ID: "guard"})
			case !reflect.DeepEqual(*b.Guard, eff.Guard):
				differ = append(differ, MergeItem{Kind: MergeRetention, ID: "guard",
					Detail: "this server's disk guard differs from the cluster's, which is kept"})
			}
		}
		if len(differ) > 0 {
			// Nothing deletes by policies the servers disagree on until an
			// admin confirms them.
			if b.Confirm == nil {
				b.Confirm = &Confirm{Reason: ConfirmMerge, At: now.UTC().Format(time.RFC3339Nano)}
			}
			if b.Confirm.Servers == nil {
				b.Confirm.Servers = map[string]string{}
			}
			b.Confirm.Servers[f.Node] = RetentionFingerprint(c)
			held = true
		}
		if len(added) == 0 && !held {
			return errMergeNothing
		}
		return nil
	})
	if err != nil && !errors.Is(err, errMergeNothing) {
		return err
	}
	rep.Added = append(rep.Added, added...)
	rep.Differ = append(rep.Differ, differ...)
	rep.Held = rep.Held || held
	return nil
}

func mergeUsers(ctx context.Context, a *clusterauth.Docs, f Files, by string, rep *MigrationReport) error {
	c := f.Config()
	recs, _, err := users.ReadFile(c.UsersFile())
	if err != nil {
		return err
	}
	ub := &clusterauth.UsersBackend{Docs: a}
	have, err := ub.Load()
	if err != nil {
		return err
	}
	builtin, _, _ := a.Builtin()
	for _, name := range slices.Sorted(maps.Keys(recs)) {
		r := recs[name]
		if strings.EqualFold(name, builtin) || strings.EqualFold(name, c.Auth.AdminUser) {
			rep.Differ = append(rep.Differ, MergeItem{Kind: MergeUser, ID: name,
				Detail: "has the built-in admin's name, so it was not added; the cluster's built-in admin is kept"})
			continue
		}
		cur, ok := have[name]
		if !ok {
			r.LastSignIn, r.Epoch = nil, 1
			if _, err := ub.Create(ctx, by, r); err != nil && !errors.Is(err, users.ErrExists) {
				return fmt.Errorf("user %s: %w", name, err)
			}
			rep.Added = append(rep.Added, MergeItem{Kind: MergeUser, ID: name})
			continue
		}
		var what []string
		if cur.Role != r.Role {
			what = append(what, fmt.Sprintf("role %s here, %s in the cluster", r.Role, cur.Role))
		}
		if cur.Source != r.Source {
			what = append(what, fmt.Sprintf("sign-in by %s here, by %s in the cluster", r.Source, cur.Source))
		}
		if cur.Disabled != r.Disabled {
			what = append(what, map[bool]string{true: "disabled here", false: "disabled in the cluster"}[r.Disabled])
		}
		if cur.Hash != r.Hash && r.Source == users.SourceLocal {
			what = append(what, "another password")
		}
		if len(what) > 0 {
			rep.Differ = append(rep.Differ, MergeItem{Kind: MergeUser, ID: name,
				Detail: strings.Join(what, "; ") + "; the cluster's user is kept"})
		}
	}
	return nil
}

// mergeSettings adds the shared settings this server's Settings page,
// signalith.yaml or environment set and the cluster has not, as the
// import does, and lists those whose values differ.
func mergeSettings(ctx context.Context, d *Docs, f Files, by string, rep *MigrationReport) error {
	c := f.Config()
	keys := d.Hub().Keys()
	now := f.now()
	page, err := config.ReadPageSettings(c.SettingsFile())
	if err != nil {
		page = &config.PageSettings{}
	}
	values := map[string]SettingValue{}
	for _, key := range config.SharedKeys() {
		src := c.Source(key)
		if key == "ingest.tokens" || src.Kind != config.FromPage && src.Kind != config.FromFile && src.Kind != config.FromEnv {
			continue
		}
		if config.AddressHasSecret(key, c.Value(key)) {
			continue
		}
		sentTo := ""
		if s, ok := config.Lookup(key); ok && s.Type == config.TypeSecret {
			sentTo = s.SentTo(c)
			if e := page.Settings[key]; src.Kind == config.FromPage && e != nil {
				sentTo = e.SentTo
			}
		}
		at := src.At
		if at.IsZero() {
			at = now
		}
		sv, err := settingValue(keys, key, c.Value(key), sentTo, shared.From{Source: FromImport, Node: f.Node, By: src.By, At: at.UTC()})
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		if sv.Secret == "" && sv.Value == nil {
			continue
		}
		values[key] = sv
	}
	if len(values) == 0 {
		return nil
	}
	var added, differ []MergeItem
	_, err = d.Settings().Mutate(ctx, by, func(b *SettingsBody) error {
		added, differ = nil, nil
		if b.Values == nil {
			b.Values = map[string]SettingValue{}
		}
		for _, key := range slices.Sorted(maps.Keys(values)) {
			sv := values[key]
			cur, ok := b.Values[key]
			switch {
			case !ok:
				b.set(key, sv)
				added = append(added, MergeItem{Kind: MergeSetting, ID: key})
			case !sameSetting(keys, key, cur, sv):
				detail := "this server's value differs from the cluster's, which is kept"
				if s, ok := config.Lookup(key); !ok || s.Type != config.TypeSecret {
					detail = fmt.Sprintf("%s here, %s in the cluster, which is kept", compact(sv.Value), compact(cur.Value))
				}
				differ = append(differ, MergeItem{Kind: MergeSetting, ID: key, Detail: detail})
			}
		}
		if len(added) == 0 {
			return errMergeNothing
		}
		return nil
	})
	if err != nil && !errors.Is(err, errMergeNothing) {
		return err
	}
	rep.Added = append(rep.Added, added...)
	rep.Differ = append(rep.Differ, differ...)
	return nil
}
