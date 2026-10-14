package clustercfg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// signalith cluster apply -f <file> writes the shared settings a file in
// signalith.yaml's shape sets (configuration as code): the settings of
// the settings document, the cluster's name, the retention policies, the
// threat intel feeds and directory sign-in, through the same writers as a
// change applied from a server's signalith.yaml; and auth.admin_user,
// which renames the built-in admin (clusterauth.Docs.RenameBuiltin). One
// server's own settings, and those it needs to reach OpenSearch, are
// refused: they belong on that server. The file GET /api/settings/export
// writes is applied as it is, which changes nothing.

// FileChange is one setting a file given to signalith cluster apply sets
// to another value than the one in use. Have and Want are the values as
// JSON; a password or key shows neither.
type FileChange struct {
	Key    string
	Have   string
	Want   string
	Secret bool
}

// FilePlan is what signalith cluster apply would change.
type FilePlan struct {
	Changes []FileChange
	// values are the settings to write, name the cluster's new name and
	// adminUser the built-in admin's new name ("" for no change).
	values    []fileValue
	name      *string
	adminUser string
}

// Empty reports whether the file changes nothing.
func (p *FilePlan) Empty() bool { return len(p.Changes) == 0 }

// AdminUser is the built-in admin's new name, "" when the file does not
// rename it.
func (p *FilePlan) AdminUser() string { return p.adminUser }

// applyKey reports whether signalith cluster apply takes key from a file,
// or why not.
func applyKey(key string) (bool, string) {
	switch {
	case key == "auth.admin_password_hash":
		return false, "the built-in admin's password is changed with signalith passwd"
	case key == "ingest.tokens":
		return false, "the shared agent tokens of older setups come from each server's signalith.yaml or environment; new agents get a token of their own on Add data"
	case key == "cluster.leader_eligible" || key == "detections.scheduler":
		return false, "whether a server may run the background jobs is that server's own setting: change it on its Settings page"
	case key == "retention.archive_dir":
		return false, "it is a folder on each server"
	case strings.HasPrefix(key, "retention.") || key == "intel.feeds" || key == "auth.ldap" || strings.HasPrefix(key, "auth.ldap.") ||
		key == "auth.admin_user":
		return true, ""
	}
	switch config.ScopeOf(key) {
	case config.ScopeCluster:
		return true, ""
	case config.ScopeServer:
		return false, "it is one server's own setting: change it on that server's Settings page, or with signalith settings on that server"
	case config.ScopeBootstrap:
		return false, "each server needs it to reach OpenSearch, so it stays in each server's own files"
	}
	return false, "it is not a setting the servers share"
}

// asJSON is v as compact JSON, for comparing and showing values.
func asJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// PlanFile works out what applying f, a file ReadSettingsFile read, would
// change: each shared setting it sets to another value than cur, this
// server's configuration with the shared settings, uses; and the
// retention policies, feeds and directory sign-in it sets to others than
// the shared ones. Settings it cannot apply are refused, all at once.
func PlanFile(rt *shared.Runtime, d *Docs, cur, f *config.Config) (*FilePlan, error) {
	var refused []string
	for _, k := range f.FileKeys() {
		if ok, why := applyKey(k); !ok {
			refused = append(refused, k+": "+why)
		}
	}
	if len(refused) > 0 {
		return nil, fmt.Errorf("the file has settings signalith cluster apply does not change; take them out of it:\n  %s", strings.Join(refused, "\n  "))
	}
	var problems []string
	keys := f.FileKeys()
	var verr *config.ValidationError
	if err := f.Validate(); errors.As(err, &verr) {
		problems = verr.Problems
	} else if err != nil {
		return nil, err
	}
	all := problems
	problems = nil
	for _, p := range all {
		for _, k := range config.ProblemKeys(p) {
			if slices.ContainsFunc(keys, func(fk string) bool { return fk == k || strings.HasPrefix(fk, k+".") || strings.HasPrefix(k, fk+".") }) {
				problems = append(problems, p)
				break
			}
		}
	}
	for _, k := range addressSecrets(f) {
		problems = append(problems, k+": leave passwords and keys out of the address; the shared settings are shown on every server's page")
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("the file's settings have problems; nothing was changed:\n  %s", strings.Join(problems, "\n  "))
	}
	p := &FilePlan{}
	sb, _ := d.Settings().Get()
	drift := Drift(d, f)
	for _, fv := range fileValues(f) {
		switch {
		case fv.source != "" && fv.source != shared.SourceYAML, fv.key == "ingest.tokens", fv.key == "auth.admin_password_hash":
			continue
		case fv.adminUser:
			name := fmt.Sprint(fv.value)
			if a := d.Auth(); a != nil && slices.Contains(drift, fv.key) {
				p.adminUser = name
				p.Changes = append(p.Changes, FileChange{Key: fv.key, Have: asJSON(a.BuiltinName()), Want: asJSON(name)})
			}
		case fv.setting:
			set, _ := config.Lookup(fv.key)
			if set != nil && set.Type == config.TypeSecret {
				plain, _ := fv.value.(string)
				if plain == "" {
					continue
				}
				if sb != nil {
					if have, ok := sb.Values[fv.key]; ok && have.Secret != "" {
						if old, err := openFor(d.Hub().Keys(), fv.key, have.Secret, have.SentTo); err == nil && old == plain {
							continue
						}
					}
				}
				p.values = append(p.values, fv)
				p.Changes = append(p.Changes, FileChange{Key: fv.key, Secret: true})
				continue
			}
			have, want := asJSON(cur.Value(fv.key)), asJSON(fv.value)
			if have != want {
				p.values = append(p.values, fv)
				p.Changes = append(p.Changes, FileChange{Key: fv.key, Have: have, Want: want})
			}
		default:
			if slices.Contains(drift, fv.key) {
				p.values = append(p.values, fv)
				p.Changes = append(p.Changes, FileChange{Key: fv.key, Want: asJSON(fv.value), Secret: fv.auth})
			}
		}
	}
	if slices.Contains(keys, "cluster.name") {
		cb, _ := rt.Cluster().Get()
		have := ""
		if cb != nil {
			have = cb.Name
		}
		if want := f.Cluster.Name; want != have {
			p.name = &want
			p.Changes = append(p.Changes, FileChange{Key: "cluster.name", Have: asJSON(have), Want: asJSON(want)})
		}
	}
	return p, nil
}

// Apply writes the plan, by by on node, and audits each change. The
// built-in admin's rename is left to the caller (AdminUser). It returns
// the settings written.
func (p *FilePlan) Apply(ctx context.Context, rt *shared.Runtime, d *Docs, f *config.Config, by, node string, log *slog.Logger) ([]string, error) {
	if !rt.SharedSettings() {
		return nil, errors.New("the servers of this cluster do not share their settings yet")
	}
	how := func(fileValue) string { return "applied with signalith cluster apply on " + node + " by " + by }
	out, err := write(ctx, rt, d, f, p.values, node, log, how)
	if err != nil {
		return out, err
	}
	if p.name != nil {
		if _, err := rt.Cluster().Mutate(ctx, by, func(b *shared.ClusterBody) error {
			b.Name = *p.name
			return nil
		}); err != nil {
			return out, err
		}
		out = append(out, "cluster.name")
		log.Info("cluster.name "+how(fileValue{}), "audit", true, "setting", "cluster.name", "server", node)
	}
	return out, nil
}
