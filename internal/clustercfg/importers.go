package clustercfg

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Files is this server's own files and settings, which the founder
// imports and every member applies when they change.
type Files struct {
	// Config is the configuration in use now.
	Config func() *config.Config
	// Node is this server's name and NodeID its id.
	Node   string
	NodeID string
	// Client is the OpenSearch client and index prefix in use now.
	Client func() (*store.Client, string)
	// LeaseEpoch is the job lease's epoch, written with imported status.
	LeaseEpoch func() int64
	// Peers lists the other servers' retention fingerprints (their
	// heartbeats' files_fingerprint.retention) from the last 7 days, by
	// server name.
	Peers func() map[string]string
	// NodeCfg returns this server's nodecfg document, where the users and
	// directory importers record what this server's files say of auth.*,
	// so only later changes apply (see Apply).
	NodeCfg func() *shared.Doc[shared.NodeCfg]
	Log     *slog.Logger
	Now     func() time.Time
}

func (f Files) log() *slog.Logger {
	if f.Log != nil {
		return f.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (f Files) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// FeedStatusFile is where a server keeps its feeds' status.
func FeedStatusFile(c *config.Config) string {
	return filepath.Join(c.LookupsDir(), "intel_feeds.json")
}

// RetentionFile is where a server keeps the retention policies saved on
// its page.
func RetentionFile(c *config.Config) string {
	return filepath.Join(c.LookupsDir(), "retention.yaml")
}

// hashOf hashes what an importer reads: file contents (a missing file
// counts as empty) and values.
func hashOf(files []string, values ...any) (string, error) {
	h := sha256.New()
	for _, p := range files {
		data, err := os.ReadFile(p)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		h.Write([]byte(p))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	for _, v := range values {
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		h.Write(b)
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// The names of the importers of the feed list and of the retention
// policies (Importers).
const (
	ImportFeeds     = "feeds"
	ImportRetention = "retention"
)

// Importers returns the importers of the shared settings: the feed list
// (the feeds added on the page and intel.feeds in signalith.yaml), the
// feeds' status (so downloads stay on their schedules) and the retention
// policies (with the confirmation hold when other servers' policies
// differed), which are always written, even empty, so every member finds
// them; then, once the cluster's level keeps users in the shared settings
// and when d has the users' documents (UseAuth), the users and the
// directory sign-in settings; and once its level keeps the settings of the
// Settings page there, those every server shares.
func Importers(d *Docs, f Files) []shared.Importer {
	out := []shared.Importer{
		{Name: ImportFeeds, Source: func() (string, error) {
			c := f.Config()
			return hashOf([]string{c.IntelFeedsFile()}, c.Intel.Feeds)
		}, Run: func(ctx context.Context, by string) error { return importFeeds(ctx, d, f, by) }},
		{Name: "feed_status", Source: func() (string, error) {
			p := FeedStatusFile(f.Config())
			if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
				return "", nil
			}
			return hashOf([]string{p})
		}, Run: func(ctx context.Context, _ string) error { return importFeedStatus(ctx, f) }},
		{Name: ImportRetention, Source: func() (string, error) {
			c := f.Config()
			return hashOf([]string{RetentionFile(c)}, c.RetentionPolicies())
		}, Run: func(ctx context.Context, by string) error { return importRetention(ctx, d, f, by) }},
	}
	if a := d.Auth(); a != nil {
		out = append(out, shared.Importer{Name: shared.ImportUsers, MinLevel: shared.LevelSharedUsers, Source: func() (string, error) {
			c := f.Config()
			return hashOf([]string{c.UsersFile()}, c.Auth.AdminUser, c.AdminPasswordVersion())
		}, Run: func(ctx context.Context, by string) error { return importUsers(ctx, a, f, by) }},
			shared.Importer{Name: shared.ImportDirectory, MinLevel: shared.LevelSharedUsers, Source: func() (string, error) {
				return directorySource(f.Config())
			}, Run: func(ctx context.Context, by string) error { return importDirectory(ctx, a, f, by) }})
	}
	return append(out, shared.Importer{Name: shared.ImportSettings, MinLevel: shared.LevelSharedSettings, Source: func() (string, error) {
		return settingsSource(d, f.Config())
	}, Run: func(ctx context.Context, by string) error { return importSettings(ctx, d, f, by) }})
}

// yamlFeeds returns the feeds in signalith.yaml, with ${ENV} references
// filled in now, on the server whose files they are: the shared copy is
// sealed with the cluster key and never reads another server's
// environment.
func yamlFeeds(c *config.Config) []intel.FeedSpec {
	out := make([]intel.FeedSpec, 0, len(c.Intel.Feeds))
	for _, s := range c.Intel.Feeds {
		s.Headers = maps.Clone(s.Headers)
		for k, v := range s.Headers {
			s.Headers[k] = intel.ExpandEnv(v)
		}
		s.Password = intel.ExpandEnv(s.Password)
		s.Tags = slices.Clone(s.Tags)
		if s.Enabled != nil {
			on := *s.Enabled
			s.Enabled = &on
		}
		s.Defaults()
		out = append(out, s)
	}
	return out
}

func importFeeds(ctx context.Context, d *Docs, f Files, by string) error {
	c := f.Config()
	page, err := (&intel.FileList{Path: c.IntelFeedsFile()}).Load()
	if err != nil {
		return err
	}
	k := d.Hub().Keys().Active()
	now := f.now()
	var entries []FeedEntry
	inYAML := map[string]bool{}
	for _, s := range yamlFeeds(c) {
		e, err := entryOf(s, k, stamp(FromYAML, f.Node, now))
		if err != nil {
			return err
		}
		inYAML[s.Name] = true
		entries = append(entries, e)
	}
	for _, s := range page.UI {
		if inYAML[s.Name] {
			// A feed in signalith.yaml with the same name won.
			continue
		}
		e, err := entryOf(s, k, stamp(FromImport, f.Node, now))
		if err != nil {
			return err
		}
		entries = append(entries, e)
	}
	var kept []KeptEntry
	for _, kf := range page.Kept {
		if kf.Until.After(now) {
			kept = append(kept, KeptEntry{Name: kf.Name, Until: kf.Until.UTC()})
		}
	}
	_, err = d.Feeds().Mutate(ctx, by, func(b *FeedsBody) error {
		b.Feeds, b.Kept = entries, kept
		return nil
	})
	return err
}

func importFeedStatus(ctx context.Context, f Files) error {
	c := f.Config()
	cl, prefix := f.Client()
	st := &StatusStore{Client: cl, Index: cluster.RuntimeIndex(prefix), Node: f.NodeID, Now: f.Now}
	var epoch int64
	if f.LeaseEpoch != nil {
		epoch = f.LeaseEpoch()
	}
	all := (&intel.StatusFile{Path: FeedStatusFile(c)}).Load()
	for _, name := range slices.Sorted(maps.Keys(all)) {
		s := all[name]
		s.Running = false
		if err := st.write(ctx, name, s, epoch); err != nil {
			return err
		}
	}
	return nil
}

// RetentionFingerprint is the fingerprint of the retention policies a
// server's own files give, as its heartbeat carries it.
func RetentionFingerprint(c *config.Config) string {
	m := &retention.Manager{Config: c.RetentionPolicies(), Store: retention.NewStore(RetentionFile(c))}
	fp, _ := m.Fingerprint()
	return fp
}

func importRetention(ctx context.Context, d *Docs, f Files, by string) error {
	c := f.Config()
	saved, err := retention.NewStore(RetentionFile(c)).Get()
	if err != nil {
		return err
	}
	cfg := c.RetentionPolicies()
	eff := retention.Effective(cfg, saved)
	now := f.now()
	from := func(yaml bool) From {
		if yaml {
			return *stamp(FromYAML, f.Node, now)
		}
		return *stamp(FromImport, f.Node, now)
	}
	inFile := func(key string) bool { return c.Source(key).Kind == config.FromFile }
	body := RetentionBody{From: map[string]From{}}
	days := cfg.Days
	body.Days = &days
	body.From["days"] = from(inFile("retention.days"))
	if eff.DefaultSource == retention.SourceConfig || eff.DefaultSource == retention.SourceUI {
		p := eff.Default
		body.Default = &p
		body.From["default"] = from(eff.DefaultSource == retention.SourceConfig)
	}
	if len(eff.Policies) > 0 {
		body.Policies = maps.Clone(eff.Policies)
		for id := range eff.Policies {
			body.From["policies."+id] = from(eff.Sources[id] == retention.SourceConfig)
		}
	}
	if eff.GuardSource != retention.SourceBuiltin {
		g := eff.Guard
		body.Guard = &g
		body.From["guard"] = from(eff.GuardSource == retention.SourceConfig)
	}
	// The servers whose own policies differ must agree before anything
	// but the disk guard deletes by the policies imported.
	mine := RetentionFingerprint(c)
	differ := map[string]string{}
	if f.Peers != nil {
		for name, fp := range f.Peers() {
			if fp != "" && fp != mine && !strings.HasPrefix(fp, cluster.SharedPrefix) {
				differ[name] = fp
			}
		}
	}
	if len(differ) > 0 {
		body.Confirm = &Confirm{Reason: ConfirmImport, Servers: differ, At: now.UTC().Format(time.RFC3339Nano)}
	}
	_, err = d.Retention().Mutate(ctx, by, func(b *RetentionBody) error {
		extra, store := b.Extra, b.StoreID
		*b = body
		b.Extra, b.StoreID = extra, store
		return nil
	})
	return err
}

// importUsers moves this server's users into the shared settings, each
// step safe to run again (what is there counts as done): the built-in
// admin with the password in use here (the one signalith passwd wrote to
// the state folder included); every user of users.json with their
// password hash, flags and session epoch 1 (one with the built-in admin's
// name is left out: it could never sign in); and their last sign-ins.
// It records what this server's files say of auth.*.
func importUsers(ctx context.Context, a *clusterauth.Docs, f Files, by string) error {
	c := f.Config()
	now := f.now()
	builtin, err := a.CreateBuiltin(ctx, by, c.Auth.AdminUser, c.Auth.AdminPasswordHash, now)
	if err != nil {
		return err
	}
	if !strings.EqualFold(builtin, c.Auth.AdminUser) {
		f.log().Warn("the cluster's built-in admin has another name than auth.admin_user on this server; the cluster's name is used",
			"builtin", builtin, "admin_user", c.Auth.AdminUser)
	}
	recs, builtinLast, err := users.ReadFile(c.UsersFile())
	if err != nil {
		return err
	}
	ub := &clusterauth.UsersBackend{Docs: a}
	seen := &clusterauth.LastSeen{Client: f.Client, Node: f.Node}
	for _, name := range slices.Sorted(maps.Keys(recs)) {
		r := recs[name]
		if strings.EqualFold(name, builtin) {
			f.log().Warn("users.json has a user with the built-in admin's name; it is not imported", "user", name)
			continue
		}
		last := r.LastSignIn
		r.LastSignIn, r.Epoch = nil, 1
		if _, err := ub.Create(ctx, by, r); err != nil && !errors.Is(err, users.ErrExists) {
			return fmt.Errorf("user %s: %w", name, err)
		}
		if last != nil {
			if err := seen.Import(ctx, clusterauth.Seen{User: name, At: last.UTC(), Node: f.Node, Method: clusterauth.MethodSession}); err != nil {
				return err
			}
		}
	}
	if builtinLast != nil {
		if err := seen.Import(ctx, clusterauth.Seen{User: builtin, At: builtinLast.UTC(), Node: f.Node, Method: clusterauth.MethodSession}); err != nil {
			return err
		}
	}
	return recordAuth(ctx, f, a)
}

// directorySource hashes the directory sign-in settings a server's files
// hold (auth.ldap in signalith.yaml, else directory.json), "" when there
// are none.
func directorySource(c *config.Config) (string, error) {
	p := c.DirectoryFile()
	_, err := os.Stat(p)
	if c.Auth.LDAP == nil && errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	s, err := c.LDAPFromFile()
	if err != nil {
		return "", err
	}
	return hashOf([]string{p}, s)
}

// importDirectory moves this server's directory sign-in settings into
// the shared settings: auth.ldap from signalith.yaml (with
// SIGNALITH_LDAP_BIND_PASSWORD) when set, else those saved on its Users
// page, the service account password sealed again with the cluster key.
// A password that cannot be opened here is left out, and the Users page
// asks for it.
func importDirectory(ctx context.Context, a *clusterauth.Docs, f Files, by string) error {
	c := f.Config()
	var s users.LDAPSettings
	switch y, err := c.LDAP(); {
	case err != nil:
		return err
	case y != nil:
		s = *y
	default:
		d, err := users.OpenDirectory(c.DirectoryFile(), nil)
		if err != nil {
			return err
		}
		if !d.Saved() {
			return recordAuth(ctx, f, a)
		}
		if p := d.Problem(); p != "" {
			f.log().Warn("the directory sign-in service account password could not be opened, so it is not imported; enter it again on the Users page", "problem", p)
		}
		s = d.Settings()
	}
	b := &clusterauth.DirectoryBackend{Docs: a, Node: f.Node, Now: f.Now}
	if err := b.SaveFrom(ctx, by, s, clusterauth.FromImport); err != nil {
		return err
	}
	return recordAuth(ctx, f, a)
}

// secretSetting reports whether a shared setting holds passwords, keys
// or tokens.
func secretSetting(key string) bool {
	s, ok := config.Lookup(key)
	return key == "ingest.tokens" || ok && s.Type == config.TypeSecret
}

// settingsSource hashes what the settings importer reads: settings.yaml,
// the values signalith.yaml and the environment give the shared settings
// (passwords and keys as keyed hashes) and the built-in admin's name.
func settingsSource(d *Docs, c *config.Config) (string, error) {
	var k *shared.ClusterKey
	if keys := d.Hub().Keys(); keys != nil {
		k = keys.Active()
	}
	var values []any
	for _, fv := range settingValues(c) {
		v := fv.value
		if secretSetting(fv.key) {
			v = "set"
			if k != nil {
				v, _ = shared.SeenHash(k, fv.key, fv.value)
			}
		}
		values = append(values, fv.key, fv.source, v)
	}
	return hashOf([]string{c.SettingsFile()}, values, c.Auth.AdminUser)
}

// importSettings moves the founder's shared settings of the Settings page
// into the settings document: each one whose value comes from its
// Settings page (with who changed it, and when), signalith.yaml or the
// environment; one at its default is not written, so a later version's
// new default still applies. Passwords and keys are sealed again with the
// cluster key, for the address they are sent to, and the shared agent
// tokens of signalith.yaml and the environment are added as this
// server's. A change the Settings page set aside is not imported. What is
// there already is kept as it is, so running it again changes nothing.
// It records what this server's files say of them, so only later changes
// apply.
func importSettings(ctx context.Context, d *Docs, f Files, by string) error {
	c := f.Config()
	keys := d.Hub().Keys()
	if keys == nil || keys.Active() == nil {
		return errors.New("this server has no cluster key")
	}
	now := f.now()
	page, err := config.ReadPageSettings(c.SettingsFile())
	if err != nil {
		f.log().Warn("the settings file cannot be read, so only signalith.yaml and the environment are imported into the shared settings", "err", err)
		page = &config.PageSettings{}
	}
	var aside []string
	for _, key := range page.Keys() {
		if page.Settings[key].Refused != "" && config.ScopeOf(key) == config.ScopeCluster {
			aside = append(aside, key)
		}
	}
	if len(aside) > 0 {
		f.log().Warn("changes the Settings page set aside are not imported into the shared settings", "settings", strings.Join(aside, ","))
	}
	values := map[string]SettingValue{}
	for _, key := range config.SharedKeys() {
		src := c.Source(key)
		if key == "ingest.tokens" || src.Kind != config.FromPage && src.Kind != config.FromFile && src.Kind != config.FromEnv {
			continue
		}
		if config.AddressHasSecret(key, c.Value(key)) {
			f.log().Warn("an address with a password or key in it is not imported into the shared settings, which every server shows; "+
				"take it out of the address and set it on the Settings page", "setting", key)
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
	tokens := c.SourceValues("ingest.tokens")
	if _, err := d.Settings().Mutate(ctx, by, func(b *SettingsBody) error {
		if b.Values == nil {
			b.Values = map[string]SettingValue{}
		}
		for _, key := range slices.Sorted(maps.Keys(values)) {
			sv := values[key]
			if cur, ok := b.Values[key]; ok && sameSetting(keys, key, cur, sv) {
				continue
			}
			b.set(key, sv)
		}
		for _, tv := range tokens {
			plain, _ := tv.Value.([]string)
			list, _, err := setTokens(keys, b.IngestTokens, f.NodeID, f.Node, tv.Source, plain, now)
			if err != nil {
				return err
			}
			b.IngestTokens = list
		}
		return nil
	}); err != nil {
		return err
	}
	return recordSettings(ctx, f, keys.Active())
}

// recordSettings records what this server's files say of the settings of
// the settings document, as the import does: only later changes apply.
func recordSettings(ctx context.Context, f Files, k *shared.ClusterKey) error {
	if f.NodeCfg == nil || f.NodeCfg() == nil {
		return nil
	}
	var list []fileValue
	for _, fv := range settingValues(f.Config()) {
		if fv.setting {
			list = append(list, fv)
		}
	}
	_, err := f.NodeCfg().Mutate(ctx, "signalith", func(n *shared.NodeCfg) error {
		for _, fv := range list {
			h, err := shared.SeenHash(k, fv.key, fv.value)
			if err != nil {
				return err
			}
			n.Record(fv.key, cmp.Or(fv.source, shared.SourceYAML), h)
		}
		if n.SettingsApplied == "" {
			n.SettingsApplied = f.now().UTC().Format(time.RFC3339Nano)
		}
		return nil
	})
	return err
}
