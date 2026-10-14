package clustercfg

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// A shared setting set in a server's signalith.yaml or environment is
// applied to the shared value when it changes, not at every start, so an
// unchanged file never undoes a change made on a page (design 4.6). The
// settings are retention.days, .default, .policies.<category> and .guard,
// and each feed of intel.feeds, whose only source is signalith.yaml; and,
// once users are shared, the built-in admin's password
// (auth.admin_password_hash, from signalith.yaml or
// SIGNALITH_ADMIN_PASSWORD(_FILE); the file signalith passwd writes is
// not a source) and directory sign-in (auth.ldap from signalith.yaml, its
// service account password from SIGNALITH_LDAP_BIND_PASSWORD(_FILE));
// and, once the settings of the Settings page are shared, each of them
// (config.SharedKeys) from signalith.yaml and from the environment, each
// source on its own. The shared agent tokens of older setups
// (ingest.tokens) are a list every server adds its own to: a changed
// SIGNALITH_INGEST_TOKEN_FILE replaces the tokens that server's
// environment brought, and they are added, not only recorded, at its
// first start with shared settings, so agents that send them keep
// working. auth.admin_user is never applied: renaming the built-in admin,
// the break-glass account, takes signalith cluster apply; a differing
// value is drift.

// fileValue is one shared setting as this server's signalith.yaml or
// environment sets it.
type fileValue struct {
	key   string
	value any
	// source is shared.SourceYAML or shared.SourceEnv.
	source string
	// feed is the feed's settings, for intel.feeds[<name>].
	feed *intel.FeedSpec
	// auth marks a setting of the users and directory sign-in, which
	// applies only once users are shared. hash is the built-in admin's
	// password hash to apply, ldap the directory sign-in settings to
	// apply, and password the service account password to apply.
	auth     bool
	hash     string
	ldap     *users.LDAPSettings
	password string
	// conn is the directory connection signalith.yaml names, which the
	// service account password is for.
	conn *users.LDAPSettings
	// setting marks a setting of the settings document, which applies
	// only once settings are shared, and adminUser auth.admin_user, which
	// is only compared (Drift).
	setting   bool
	adminUser bool
}

// from says where a value came from, for the audit.
func (fv fileValue) from() string {
	if fv.source == shared.SourceEnv {
		return "the environment"
	}
	return "signalith.yaml"
}

// fileValues lists the shared settings signalith.yaml and the
// environment set. Only keys actually set count: removing one from the
// file changes nothing.
func fileValues(c *config.Config) []fileValue {
	out := contentValues(c)
	for _, p := range c.SeenAdminPassword() {
		out = append(out, fileValue{key: "auth.admin_password_hash", value: p.Seen, source: p.Source, auth: true, hash: p.Hash})
	}
	if s, err := c.LDAPFromFile(); err == nil && s != nil {
		applied, _ := c.LDAP()
		// The password signalith.yaml gives is part of the value; the one
		// the environment gives is its own source.
		out = append(out, fileValue{key: "auth.ldap", value: ldapValue(*s), source: shared.SourceYAML, auth: true, ldap: applied})
	}
	// The environment's password is only for the connection this
	// server's signalith.yaml names: without auth.ldap it is not used.
	if s, err := c.LDAPFromFile(); err == nil && s != nil {
		if pw := c.LDAPBindPasswordFromEnv(); pw != "" {
			out = append(out, fileValue{key: "auth.ldap.bind_password", value: pw, source: shared.SourceEnv, auth: true, password: pw, conn: s})
		}
	}
	return append(out, settingValues(c)...)
}

// settingValues lists the settings of the settings document that
// signalith.yaml and the environment set, each source on its own, and
// auth.admin_user. An address with a password or key in it is left out
// (see addressSecrets).
func settingValues(c *config.Config) []fileValue {
	var out []fileValue
	for _, key := range config.SharedKeys() {
		for _, sv := range c.SourceValues(key) {
			if config.AddressHasSecret(key, sv.Value) {
				continue
			}
			out = append(out, fileValue{key: key, value: sv.Value, source: sv.Source, setting: true})
		}
	}
	for _, sv := range c.SourceValues("auth.admin_user") {
		out = append(out, fileValue{key: "auth.admin_user", value: sv.Value, source: sv.Source, adminUser: true})
	}
	return out
}

// addressSecrets lists the shared settings whose address in this
// server's signalith.yaml or environment has a password or key in it:
// the shared settings, kept unencrypted and shown on every server's
// page, take none of them, as the Settings page does not.
func addressSecrets(c *config.Config) []string {
	var out []string
	for _, key := range config.SharedKeys() {
		for _, sv := range c.SourceValues(key) {
			if config.AddressHasSecret(key, sv.Value) && !slices.Contains(out, key) {
				out = append(out, key)
			}
		}
	}
	return out
}

// warnAddressSecrets says which addresses of this server's files the
// shared settings do not take, and why.
func warnAddressSecrets(log *slog.Logger, c *config.Config) {
	if keys := addressSecrets(c); len(keys) > 0 && log != nil {
		log.Warn("these addresses in signalith.yaml or the environment have a password or key in them, so the servers do not share them; "+
			"take it out of the address (an API key has its own setting) and the change applies",
			"settings", strings.Join(keys, ","))
	}
}

// ldapValue is the directory sign-in settings as compared: normalised,
// with the service account password.
func ldapValue(s users.LDAPSettings) any {
	s = s.Clone()
	s.Normalize()
	return struct {
		Settings     users.LDAPSettings `json:"settings"`
		BindPassword string             `json:"bind_password"`
	}{s, s.BindPassword}
}

// contentValues lists the settings of the shared content signalith.yaml
// sets.
func contentValues(c *config.Config) []fileValue {
	inFile := func(key string) bool { return c.Source(key).Kind == config.FromFile }
	var out []fileValue
	if inFile("retention.days") {
		out = append(out, fileValue{key: "retention.days", value: c.Retention.Days})
	}
	if c.Retention.Default != nil && inFile("retention.default") {
		out = append(out, fileValue{key: "retention.default", value: *c.Retention.Default})
	}
	for _, id := range slices.Sorted(maps.Keys(c.Retention.Policies)) {
		if key := "retention.policies." + id; inFile(key) {
			out = append(out, fileValue{key: key, value: c.Retention.Policies[id]})
		}
	}
	if c.Retention.Guard != nil && inFile("retention.guard") {
		out = append(out, fileValue{key: "retention.guard", value: c.Retention.Guard.Normalized()})
	}
	if inFile("intel.feeds") {
		for _, s := range yamlFeeds(c) {
			s := s
			out = append(out, fileValue{key: "intel.feeds[" + s.Name + "]", value: s, feed: &s})
		}
	}
	return out
}

// Applied is the result of the step: what was applied, and the settings
// whose file value differs from the shared one without having changed.
type Applied struct {
	Applied []string
	Drift   []string
}

// Apply applies the values of this server's signalith.yaml and
// environment that changed since its previous start to the shared
// settings, records what it saw, and audits each change
// ("retention.days applied from signalith.yaml on siem-b"). At a
// server's first start as a member it only records them; the settings of
// the users and directory sign-in are only recorded at its first start
// once users are shared, and left alone before, and so are those of the
// Settings page once settings are shared; the agent tokens are added.
func Apply(ctx context.Context, rt *shared.Runtime, d *Docs, c *config.Config, node string, log *slog.Logger) (Applied, error) {
	var res Applied
	keys := d.Hub().Keys()
	k := keys.Active()
	if k == nil {
		return res, fmt.Errorf("this server has no cluster key")
	}
	auth := d.Auth()
	withAuth := auth != nil && rt.SharedUsers()
	ncDoc := rt.NodeCfg()
	nc, _ := ncDoc.Get()
	first := nc.Applied == ""
	firstAuth := nc.UsersApplied == ""
	withSettings := rt.SharedSettings()
	firstSettings := nc.SettingsApplied == ""
	if withSettings {
		warnAddressSecrets(log, c)
	}
	now := time.Now()
	type seen struct{ key, source, hash string }
	var record []seen
	var apply []fileValue
	for _, fv := range fileValues(c) {
		if fv.adminUser || fv.auth && !withAuth || fv.setting && !withSettings {
			continue
		}
		h, err := shared.SeenHash(k, fv.key, fv.value)
		if err != nil {
			return res, err
		}
		src := cmp.Or(fv.source, shared.SourceYAML)
		record = append(record, seen{fv.key, src, h})
		only := first || fv.auth && firstAuth || fv.setting && firstSettings
		if fv.key == "ingest.tokens" {
			// Added at the first start too: agents that send this server's
			// tokens must keep working.
			only = false
		}
		if nc.Changed(fv.key, src, h, only) {
			apply = append(apply, fv)
		}
	}
	applied, err := write(ctx, rt, d, c, apply, node, log, func(fv fileValue) string { return "applied from " + fv.from() + " on " + node })
	if err != nil {
		return res, err
	}
	res.Applied = applied
	if first || len(record) > 0 || withAuth && firstAuth || withSettings && firstSettings {
		_, err := ncDoc.Mutate(ctx, "signalith", func(n *shared.NodeCfg) error {
			for _, s := range record {
				n.Record(s.key, s.source, s.hash)
			}
			stamp := now.UTC().Format(time.RFC3339Nano)
			if n.Applied == "" {
				n.Applied = stamp
			}
			if withAuth && n.UsersApplied == "" {
				n.UsersApplied = stamp
			}
			if withSettings && n.SettingsApplied == "" {
				n.SettingsApplied = stamp
			}
			return nil
		})
		if err != nil {
			return res, err
		}
	}
	res.Drift = Drift(d, c)
	return res, nil
}

// write writes values of the shared settings to their documents: the
// retention policies, the feeds, the settings document and the users'
// documents, and audits each one as how words it. It returns the keys
// written.
func write(ctx context.Context, rt *shared.Runtime, d *Docs, c *config.Config, apply []fileValue, node string, log *slog.Logger,
	how func(fileValue) string) ([]string, error) {
	keys := d.Hub().Keys()
	k := keys.Active()
	if k == nil {
		return nil, fmt.Errorf("this server has no cluster key")
	}
	now := time.Now()
	var feeds, ret, creds, sets []fileValue
	for _, fv := range apply {
		switch {
		case fv.auth:
			creds = append(creds, fv)
		case fv.setting:
			sets = append(sets, fv)
		case fv.feed != nil:
			feeds = append(feeds, fv)
		default:
			ret = append(ret, fv)
		}
	}
	from := *stamp(FromYAML, node, now)
	if len(ret) > 0 {
		_, err := d.Retention().Mutate(ctx, "signalith", func(b *RetentionBody) error {
			if b.From == nil {
				b.From = map[string]From{}
			}
			for _, fv := range ret {
				switch v := fv.value.(type) {
				case int:
					b.Days = &v
					b.From["days"] = from
				case retention.Policy:
					if fv.key == "retention.default" {
						b.Default = &v
						b.From["default"] = from
						continue
					}
					id := strings.TrimPrefix(fv.key, "retention.policies.")
					if b.Policies == nil {
						b.Policies = map[string]retention.Policy{}
					}
					b.Policies[id] = v
					b.From["policies."+id] = from
				case retention.Guard:
					b.Guard = &v
					b.From["guard"] = from
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(feeds) > 0 {
		_, err := d.Feeds().Mutate(ctx, "signalith", func(b *FeedsBody) error {
			for _, fv := range feeds {
				e, err := entryOf(*fv.feed, k, &from)
				if err != nil {
					return err
				}
				i := slices.IndexFunc(b.Feeds, func(x FeedEntry) bool { return x.Name == fv.feed.Name })
				if i < 0 {
					b.Feeds = append(b.Feeds, e)
					continue
				}
				e.Extra = b.Feeds[i].Extra
				b.Feeds[i] = e
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if err := applySettings(ctx, d, sets, c, rt.Self(), now); err != nil {
		return nil, err
	}
	applied, err := applyAuth(ctx, d.Auth(), creds, node, log)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, fv := range apply {
		if fv.auth && !slices.Contains(applied, fv.key+"/"+fv.source) {
			continue
		}
		out = append(out, fv.key)
		log.Info(fv.key+" "+how(fv), "audit", true, "setting", fv.key, "server", node)
	}
	return out, nil
}

// applyAuth applies the settings of the users and directory sign-in that
// changed, and returns which (key/source).
func applyAuth(ctx context.Context, a *clusterauth.Docs, list []fileValue, node string, log *slog.Logger) ([]string, error) {
	var done []string
	ldapApplied := slices.ContainsFunc(list, func(fv fileValue) bool { return fv.ldap != nil })
	dir := &clusterauth.DirectoryBackend{Docs: a, Node: node}
	for _, fv := range list {
		var err error
		switch {
		case fv.hash != "":
			err = a.SetBuiltinHash(ctx, "signalith", fv.hash)
		case fv.ldap != nil:
			err = dir.SaveFrom(ctx, "signalith", *fv.ldap, clusterauth.FromYAML)
		case fv.password != "" && ldapApplied:
			// Applied with auth.ldap just now.
		case fv.password != "" && fv.conn != nil:
			if err = dir.SetBindPassword(ctx, "signalith", fv.password, clusterauth.FromEnv, *fv.conn); err != nil {
				if errors.Is(err, clusterauth.ErrOtherConnection) {
					log.Warn("SIGNALITH_LDAP_BIND_PASSWORD changed, but the shared directory sign-in settings no longer connect as auth.ldap in this server's signalith.yaml does, "+
						"so the password is not used with them; enter it on the Users page if it is meant for them", "err", err)
				} else {
					log.Warn("SIGNALITH_LDAP_BIND_PASSWORD changed, but there are no directory sign-in settings to use it with", "err", err)
				}
				continue
			}
		}
		if err != nil {
			return done, fmt.Errorf("%s: %w", fv.key, err)
		}
		done = append(done, fv.key+"/"+fv.source)
	}
	return done, nil
}

// recordAuth records what this server's files say of the settings of the
// users and directory sign-in, as the import does: only later changes
// apply.
func recordAuth(ctx context.Context, f Files, a *clusterauth.Docs) error {
	if f.NodeCfg == nil || f.NodeCfg() == nil {
		return nil
	}
	k := a.Hub().Keys().Active()
	if k == nil {
		return fmt.Errorf("this server has no cluster key")
	}
	var list []fileValue
	for _, fv := range fileValues(f.Config()) {
		if fv.auth {
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
		if n.UsersApplied == "" {
			n.UsersApplied = f.now().UTC().Format(time.RFC3339Nano)
		}
		return nil
	})
	return err
}

// Drift lists the shared settings whose value in this server's
// signalith.yaml differs from the shared one, for the Servers page
// ("siem-b's signalith.yaml says retention.days: 90; the shared value is
// 365"): information, not a problem.
func Drift(d *Docs, c *config.Config) []string {
	var out []string
	rb, rok := d.Retention().Get()
	fb, fok := d.Feeds().Get()
	var shared intel.FeedSet
	if fok {
		shared = decodeFeeds(fb, opener(d.Hub().Keys()))
	}
	auth := d.Auth()
	sb, sok := d.Settings().Get()
	envPassword := slices.ContainsFunc(c.SeenAdminPassword(), func(p config.SeenPassword) bool { return p.Source == "env" })
	for _, fv := range fileValues(c) {
		var have any
		known := rok
		switch {
		case fv.adminUser:
			if auth != nil {
				if name, _, ok := auth.Builtin(); ok && !strings.EqualFold(name, fmt.Sprint(fv.value)) && !slices.Contains(out, fv.key) {
					out = append(out, fv.key)
				}
			}
			continue
		case fv.setting:
			if sok && settingDrift(sb, fv) && !slices.Contains(out, fv.key) {
				out = append(out, fv.key)
			}
			continue
		case fv.auth:
			if auth != nil && authDrift(auth, fv, envPassword) {
				out = append(out, fv.key)
			}
			continue
		case fv.feed != nil:
			known = fok
			i := slices.IndexFunc(shared.UI, func(s intel.FeedSpec) bool { return s.Name == fv.feed.Name })
			if known && (i < 0 || !sameSpec(shared.UI[i], *fv.feed)) {
				out = append(out, fv.key)
			}
			continue
		case fv.key == "retention.days":
			if rb.Days != nil {
				have = *rb.Days
			}
		case fv.key == "retention.default":
			if rb.Default != nil {
				have = *rb.Default
			}
		case fv.key == "retention.guard":
			if rb.Guard != nil {
				have = rb.Guard.Normalized()
			}
		default:
			if p, ok := rb.Policies[strings.TrimPrefix(fv.key, "retention.policies.")]; ok {
				have = p
			}
		}
		if known && !sameJSON(have, fv.value) {
			out = append(out, fv.key)
		}
	}
	return out
}

// authDrift reports whether a setting of the users and directory sign-in
// in this server's files differs from the shared one. A password the
// environment gives cannot be compared without being kept, so it never
// counts, and the file's password does not either while the environment
// gives one (envPassword), which is the one in use on this server.
func authDrift(a *clusterauth.Docs, fv fileValue, envPassword bool) bool {
	switch {
	case fv.hash != "" && fv.source == shared.SourceYAML && !envPassword:
		_, hash, ok := a.Builtin()
		return ok && hash != fv.hash
	case fv.ldap != nil:
		body, ok := a.Directory().Get()
		if !ok {
			return false
		}
		mine, theirs := fv.ldap.Clone(), body.Settings.Clone()
		mine.BindPassword, theirs.BindPassword = "", ""
		mine.Normalize()
		theirs.Normalize()
		return !sameJSON(mine, theirs)
	}
	return false
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return reflect.DeepEqual(x, y)
}

// settingDrift reports whether a setting of the settings document in this
// server's files differs from the shared one. Passwords, keys and the
// agent tokens never count: they cannot be compared without being kept.
func settingDrift(b *SettingsBody, fv fileValue) bool {
	if s, ok := config.Lookup(fv.key); fv.key == "ingest.tokens" || ok && s.Type == config.TypeSecret {
		return false
	}
	have, ok := b.Values[fv.key]
	raw := have.Value
	if !ok {
		raw, _ = json.Marshal(defaults().Value(fv.key))
	}
	mine, err := json.Marshal(fv.value)
	return err == nil && !bytes.Equal(compact(raw), compact(mine))
}

// applySettings writes the settings of the settings document that
// changed in this server's files, as from them, in one change.
func applySettings(ctx context.Context, d *Docs, list []fileValue, c *config.Config, self shared.Self, now time.Time) error {
	if len(list) == 0 {
		return nil
	}
	keys := d.Hub().Keys()
	batch := map[string]any{}
	for _, fv := range list {
		batch[fv.key] = fv.value
	}
	_, err := d.Settings().Mutate(ctx, "signalith", func(b *SettingsBody) error {
		if b.Values == nil {
			b.Values = map[string]SettingValue{}
		}
		for _, fv := range list {
			src := cmp.Or(fv.source, shared.SourceYAML)
			if fv.key == "ingest.tokens" {
				plain, _ := fv.value.([]string)
				toks, _, err := setTokens(keys, b.IngestTokens, self.NodeID, self.Name, src, plain, now)
				if err != nil {
					return err
				}
				b.IngestTokens = toks
				continue
			}
			sv, err := settingValue(keys, fv.key, fv.value, sentToFor(c, fv.key, batch), shared.From{Source: src, Node: self.Name, At: now.UTC()})
			if err != nil {
				return fmt.Errorf("%s: %w", fv.key, err)
			}
			b.set(fv.key, sv)
		}
		return nil
	})
	return err
}

// settingValue is a shared setting's value v, a password or key sealed
// for sentTo.
func settingValue(keys *shared.KeySet, key string, v any, sentTo string, from shared.From) (SettingValue, error) {
	sv := SettingValue{From: from}
	if s, ok := config.Lookup(key); ok && s.Type == config.TypeSecret {
		plain, _ := v.(string)
		if plain == "" {
			return sv, nil
		}
		sealed, err := sealFor(keys, key, plain, sentTo)
		if err != nil {
			return sv, err
		}
		sv.Secret, sv.SentTo = sealed, sentTo
		return sv, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return sv, err
	}
	sv.Value = raw
	return sv, nil
}

// sentToFor returns where the password or key of setting key may be sent
// with the configuration c and the values of batch, changed with it.
func sentToFor(c *config.Config, key string, batch map[string]any) string {
	s, ok := config.Lookup(key)
	if !ok || len(s.SentWith) == 0 {
		return ""
	}
	view := config.Default()
	for _, k := range s.SentWith {
		v := c.Value(k)
		if b, ok := batch[k]; ok {
			v = b
		}
		if v != nil {
			_ = view.SetValue(k, v)
		}
	}
	return s.SentTo(view)
}

// setTokens replaces the shared agent tokens server node (named name)
// brought from source with plain, and reports whether that changed them:
// the same tokens are kept as they are.
func setTokens(keys *shared.KeySet, list []IngestToken, node, name, source string, plain []string, now time.Time) ([]IngestToken, bool, error) {
	var others, mine []IngestToken
	var have []string
	for _, t := range list {
		if t.Node != node || t.Source != source {
			others = append(others, t)
			continue
		}
		mine = append(mine, t)
		if p, err := openFor(keys, "ingest.tokens", t.Secret, ""); err == nil {
			have = append(have, p)
		}
	}
	if len(have) == len(mine) && slices.Equal(have, plain) {
		return list, false, nil
	}
	out := others
	for _, p := range plain {
		sealed, err := sealFor(keys, "ingest.tokens", p, "")
		if err != nil {
			return list, false, err
		}
		out = append(out, IngestToken{Secret: sealed, Node: node, Name: name, Source: source, At: now.UTC()})
	}
	return out, true, nil
}
