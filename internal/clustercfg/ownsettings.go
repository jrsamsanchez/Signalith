package clustercfg

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// The founder's import moves the shared settings of its Settings page into
// the settings document. Each server, the founder too, then moves its own
// settings.yaml once, at its first start with shared settings: its own
// settings (server scope) go to its nodecfg, where any server's Settings
// page changes them; its shared ones that differ from the shared value
// are listed in its nodecfg (migrated), for the Servers page, as they are
// no longer used; and settings.yaml keeps only the settings a server
// needs to reach OpenSearch, the original kept next to it as
// settings.yaml.imported-YYYYMMDD.

// setOn is a password or key in a list of values: it is never written
// out.
var setOn = json.RawMessage(`{"set":true}`)

// ImportOwn moves this server's settings.yaml as said above, once:
// nodecfg records the hash of the file it moved (settings_imported), and
// the file is rewritten last, so a start after a crash in between only
// rewrites it. A value changed on a Settings page since is kept. It
// reports whether it rewrote settings.yaml.
func ImportOwn(ctx context.Context, rt *shared.Runtime, d *Docs, c *config.Config, log *slog.Logger) (bool, error) {
	path := c.SettingsFile()
	hash, err := hashOf([]string{path})
	if err != nil {
		return false, err
	}
	ncDoc := rt.NodeCfg()
	nc, _ := ncDoc.Get()
	if nc == nil {
		nc = &shared.NodeCfg{}
	}
	if nc.SettingsImported != "" && nc.SettingsImported != hash {
		return false, nil
	}
	page, err := config.ReadPageSettings(path)
	if err != nil {
		return false, err
	}
	self := rt.Self()
	now := time.Now().UTC()
	if nc.SettingsImported == "" {
		values := map[string]shared.PageValue{}
		var migrated []shared.MigratedValue
		var aside []string
		sb, _ := d.Settings().Get()
		for _, key := range page.Keys() {
			e := page.Settings[key]
			switch config.ScopeOf(key) {
			case config.ScopeServer:
				to := key
				if key == "detections.scheduler" {
					if _, both := page.Settings["cluster.leader_eligible"]; both {
						// The new name wins.
						continue
					}
					to = "cluster.leader_eligible"
				}
				pv, err := pageValueOf(key, e, self.Name)
				if err != nil {
					return false, err
				}
				pv.From.Source, pv.Rev = FromImport, 1
				values[to] = pv
			case config.ScopeCluster:
				if e.Refused != "" {
					aside = append(aside, key)
					continue
				}
				m, differs, err := migratedOf(c, d.Hub().Keys(), sb, key, e)
				if err != nil {
					log.Warn("a setting of the Settings page cannot be compared with the shared value", "setting", key, "err", err)
					continue
				}
				if differs {
					m.At = now
					migrated = append(migrated, m)
				}
			}
		}
		if _, err := ncDoc.Mutate(ctx, "signalith", func(n *shared.NodeCfg) error {
			if n.SettingsImported != "" {
				return nil
			}
			for k, pv := range values {
				if _, ok := n.Values[k]; ok {
					continue
				}
				if n.Values == nil {
					n.Values = map[string]shared.PageValue{}
				}
				n.Values[k] = pv
			}
			n.Migrated = append(n.Migrated, migrated...)
			n.SettingsImported = hash
			return nil
		}); err != nil {
			return false, err
		}
		var names []string
		for _, m := range migrated {
			names = append(names, m.Key)
		}
		log.Info("this server's own settings moved from settings.yaml into the shared settings", "audit", true, "server", self.Name,
			"settings", len(values), "differ", strings.Join(names, ","), "set_aside", strings.Join(aside, ","))
	}
	keep := &config.PageSettings{Settings: map[string]*config.PageEntry{}}
	for key, e := range page.Settings {
		if sc := config.ScopeOf(key); sc == config.ScopeBootstrap || sc == "" {
			keep.Settings[key] = e
		}
	}
	if len(keep.Settings) == len(page.Settings) {
		return false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	backup := path + ".imported-" + now.Format("20060102")
	if err := securefile.Replace(backup, data); err != nil {
		return false, fmt.Errorf("could not keep a copy of %s: %w", path, err)
	}
	if err := config.WritePageSettings(path, keep); err != nil {
		return false, err
	}
	log.Info("settings.yaml now keeps only the settings this server needs to reach OpenSearch", "file", path, "copy", backup)
	return true, nil
}

// migratedOf compares a shared setting on this server's Settings page (e)
// with the shared value in sb (nil for none: the default), and returns
// both when they differ. Passwords and keys are compared, never listed.
func migratedOf(c *config.Config, keys *shared.KeySet, sb *SettingsBody, key string, e *config.PageEntry) (shared.MigratedValue, bool, error) {
	m := shared.MigratedValue{Key: key}
	var sv SettingValue
	has := false
	if sb != nil {
		sv, has = sb.Values[key]
	}
	if s, ok := config.Lookup(key); ok && s.Type == config.TypeSecret {
		mine := ""
		if e.Secret != nil {
			var err error
			if mine, err = c.Keyring().Open("settings."+key, *e.Secret); err != nil {
				return m, false, err
			}
		}
		theirs := ""
		if has && sv.Secret != "" {
			var err error
			if theirs, err = openFor(keys, key, sv.Secret, sv.SentTo); err != nil {
				return m, false, err
			}
		}
		if mine == theirs && (mine == "" || e.SentTo == sv.SentTo) {
			return m, false, nil
		}
		m.Value = setOn
		if theirs != "" {
			m.Shared = setOn
		}
		return m, true, nil
	}
	pv, err := pageValueOf(key, e, "")
	if err != nil {
		return m, false, err
	}
	theirs := sv.Value
	if !has {
		theirs, _ = json.Marshal(defaults().Value(key))
	}
	if string(compact(pv.Value)) == string(compact(theirs)) {
		return m, false, nil
	}
	m.Value, m.Shared = pv.Value, theirs
	return m, true, nil
}
