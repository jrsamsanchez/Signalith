package clustercfg

import (
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
// service account password from SIGNALITH_LDAP_BIND_PASSWORD(_FILE)).

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
	return out
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
// once users are shared, and left alone before.
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
	now := time.Now()
	type seen struct{ key, source, hash string }
	var record []seen
	var apply []fileValue
	for _, fv := range fileValues(c) {
		if fv.auth && !withAuth {
			continue
		}
		h, err := shared.SeenHash(k, fv.key, fv.value)
		if err != nil {
			return res, err
		}
		src := cmp.Or(fv.source, shared.SourceYAML)
		record = append(record, seen{fv.key, src, h})
		if nc.Changed(fv.key, src, h, first || fv.auth && firstAuth) {
			apply = append(apply, fv)
		}
	}
	var feeds, ret, creds []fileValue
	for _, fv := range apply {
		switch {
		case fv.auth:
			creds = append(creds, fv)
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
			return res, err
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
			return res, err
		}
	}
	applied, err := applyAuth(ctx, auth, creds, node, log)
	if err != nil {
		return res, err
	}
	for _, fv := range apply {
		if fv.auth && !slices.Contains(applied, fv.key+"/"+fv.source) {
			continue
		}
		res.Applied = append(res.Applied, fv.key)
		log.Info(fv.key+" applied from "+fv.from()+" on "+node, "audit", true, "setting", fv.key, "server", node)
	}
	if first || len(record) > 0 || withAuth && firstAuth {
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
			return nil
		})
		if err != nil {
			return res, err
		}
	}
	res.Drift = Drift(d, c)
	return res, nil
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
	envPassword := slices.ContainsFunc(c.SeenAdminPassword(), func(p config.SeenPassword) bool { return p.Source == "env" })
	for _, fv := range fileValues(c) {
		var have any
		known := rok
		switch {
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
