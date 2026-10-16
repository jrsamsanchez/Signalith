package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// The settings the servers of a cluster share, from the command line:
// signalith cluster export -settings writes them as a file in
// signalith.yaml's shape, signalith cluster apply -f changes them to a
// file's (configuration as code), and signalith settings reset on a
// member takes one back to its default for every server, or one of this
// server's own (-local while OpenSearch cannot be reached: see
// setAsideFile).

// sharedSettings returns the runtime, read once, with this server's
// configuration loaded with the shared settings, when the servers share
// their settings; why says otherwise.
func (x *clusterCLI) sharedSettings() (*shared.Runtime, *config.Config, error) {
	rt := x.runtime(true, "")
	if m, why := rt.Mode(); m != shared.ModeMember {
		return nil, nil, fmt.Errorf("this server cannot use the cluster's shared settings now (%s)", cmp.Or(why, m.Text()))
	}
	if !rt.SharedSettings() {
		return nil, nil, errors.New("the servers of this cluster do not share their settings yet")
	}
	cb, _ := rt.Cluster().Get()
	nc, _ := rt.NodeCfg().Get()
	cur, err := config.LoadShared(x.c.Path(), clustercfg.Layer(x.docs, cb, nc, x.self.Name))
	if err != nil {
		return nil, nil, err
	}
	return rt, cur, nil
}

// apply changes the shared settings to those of file.
func (x *clusterCLI) apply(ctx context.Context, file string, yes bool) error {
	rt, cur, err := x.sharedSettings()
	if err != nil {
		return err
	}
	f, err := config.ReadSettingsFile(file, x.c.Keyring())
	if err != nil {
		return err
	}
	plan, err := clustercfg.PlanFile(rt, x.docs, cur, f)
	if err != nil {
		return err
	}
	if plan.Empty() {
		fmt.Fprintln(x.out, "Nothing to change: the servers share these settings already.")
		return nil
	}
	fmt.Fprintf(x.out, "Changes to the settings every server of the cluster shares (%d):\n", len(plan.Changes))
	for _, ch := range plan.Changes {
		switch {
		case ch.Secret:
			fmt.Fprintf(x.out, "  %s: (hidden) is changed\n", ch.Key)
		case ch.Have == "":
			fmt.Fprintf(x.out, "  %s: %s\n", ch.Key, printable(ch.Want))
		default:
			fmt.Fprintf(x.out, "  %s: %s -> %s\n", ch.Key, printable(ch.Have), printable(ch.Want))
		}
	}
	if name := plan.AdminUser(); name != "" {
		fmt.Fprintf(x.out, "The built-in admin is renamed to %s: its sessions end, and it signs in under the new name with the same password.\n", printable(name))
	}
	if err := x.confirm("Apply these changes to every server?", yes); err != nil {
		return err
	}
	if name := plan.AdminUser(); name != "" {
		prev, err := x.auth.RenameBuiltin(ctx, x.by, name)
		if err != nil {
			return fmt.Errorf("could not rename the built-in admin (run the same command again to finish): %w", err)
		}
		if prev != "" {
			x.audit("renamed the built-in admin for every server of the cluster", "from", prev, "to", name)
		}
	}
	applied, err := plan.Apply(ctx, rt, x.docs, f, x.by, x.self.Name, x.log)
	if err != nil {
		if len(applied) > 0 {
			err = fmt.Errorf("%w (%s were applied before this)", err, strings.Join(applied, ", "))
		}
		return err
	}
	fmt.Fprintf(x.out, "Applied. What applies at once does so on every server within a few seconds; "+
		"the settings that wait for a restart are listed on the Settings page, which restarts the servers one at a time.\n")
	return nil
}

// exportSettings writes the settings the servers share as a file
// signalith cluster apply takes, then every server's own settings (only
// server's, a name or node id, when given) as comments.
func (x *clusterCLI) exportSettings(ctx context.Context, outFile, server string) error {
	rt, cur, err := x.sharedSettings()
	if err != nil {
		return err
	}
	heartbeats, err := x.heartbeats(ctx)
	if err != nil {
		return err
	}
	var list []api.ExportServer
	for _, hb := range heartbeats {
		if server != "" && hb.NodeID != server && !strings.EqualFold(hb.Name, server) {
			continue
		}
		if hb.NodeID == x.self.NodeID {
			list = append(list, api.ExportServer{Name: hb.Name, Value: cur.Value})
			continue
		}
		nc, err := clustercfg.NodeCfgOf(ctx, rt, hb.NodeID)
		list = append(list, api.ExportServer{Name: hb.Name, Value: api.NodeCfgValue(nc), Err: err})
	}
	if server != "" && len(list) == 0 {
		return fmt.Errorf("no server %q shares this OpenSearch", server)
	}
	text, err := api.ExportShared(cur, x.self.Name, list, time.Now())
	if err != nil {
		return err
	}
	return x.write(outFile, []byte(text))
}

// heartbeats reads the servers' heartbeats, sorted by name; those of
// servers stopped for good are left out.
func (x *clusterCLI) heartbeats(ctx context.Context) ([]cluster.Heartbeat, error) {
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	docs, err := x.cl.SearchDocs(rctx, cluster.RuntimeIndex(x.prefix()), map[string]any{"term": map[string]any{"kind": "node"}})
	if err != nil {
		return nil, err
	}
	var out []cluster.Heartbeat
	for _, d := range docs {
		var hb cluster.Heartbeat
		if json.Unmarshal(d.Source, &hb) != nil || hb.NodeID == "" {
			continue
		}
		out = append(out, hb)
	}
	slices.SortFunc(out, func(a, b cluster.Heartbeat) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// settingsResetShared is signalith settings reset on a member whose
// settings are shared: a shared setting goes back to its default for
// every server, one of this server's own leaves its nodecfg, and one it
// needs to reach OpenSearch leaves settings.yaml as before. Without keys,
// this server's own settings and settings.yaml are reset, never the
// shared ones. It reports false, nil when the settings are not shared,
// for the command to go on as before.
func settingsResetShared(path string, keys []string) (bool, error) {
	stateDir := config.StateDirFor(path)
	if _, err := os.Stat(shared.CachePath(stateDir)); err != nil {
		// Never a member of a cluster.
		return false, nil
	}
	log := newLogger(os.Stderr)
	c, err := loadConfig(path, log)
	if err != nil {
		return false, nil
	}
	self, err := cluster.ReadIdentity(c.StateDir())
	if err != nil {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cl, err := cliOpenSearch(ctx, c, "the shared settings cannot be changed")
	if err != nil {
		// Only settings.yaml can change: as before.
		fmt.Fprintf(os.Stderr, "%s. Only %s is changed; on a member whose settings are shared, "+
			"signalith settings reset -local sets the others aside for this server's next start.\n", strings.TrimSuffix(err.Error(), "."), c.SettingsFile())
		return false, nil
	}
	defer cl.CloseIdleConnections()
	x := &clusterCLI{c: c, cl: cl, log: log, self: self, errOut: os.Stderr, out: os.Stdout, by: cliUser()}
	rt := x.runtime(true, "")
	if m, _ := rt.Mode(); m != shared.ModeMember || !rt.SharedSettings() {
		return false, nil
	}
	var cluster_, own, local []string
	for _, k := range keys {
		set, ok := config.Lookup(k)
		if !ok && k != "retention.interval" {
			return true, fmt.Errorf("%s is not a setting on the Settings page; see signalith settings list", k)
		}
		switch {
		case k == "detections.scheduler":
			own = append(own, "cluster.leader_eligible", k)
		case set != nil && set.Scope == config.ScopeServer:
			own = append(own, k)
		case set == nil || set.Scope == config.ScopeCluster:
			cluster_ = append(cluster_, k)
		default:
			local = append(local, k)
		}
	}
	var removed []string
	if len(cluster_) > 0 {
		_, err := x.docs.Settings().Mutate(ctx, x.by, func(b *clustercfg.SettingsBody) error {
			removed = removed[:0]
			from := shared.From{Source: clustercfg.FromApply, Node: self.Name, By: x.by, At: time.Now().UTC()}
			for _, k := range cluster_ {
				if b.ResetValue(k, from) > 0 {
					removed = append(removed, k)
				}
			}
			return nil
		})
		if err != nil {
			return true, fmt.Errorf("could not change the shared settings: %w", err)
		}
		if slices.Contains(cluster_, "cluster.name") {
			if _, err := rt.Cluster().Mutate(ctx, x.by, func(b *shared.ClusterBody) error {
				b.Name = ""
				return nil
			}); err != nil {
				return true, err
			}
			removed = append(removed, "cluster.name")
		}
		for _, k := range removed {
			x.audit("reset a shared setting to its default for every server of the cluster", "setting", k)
		}
	}
	var mine []string
	if len(own) > 0 || len(keys) == 0 {
		_, err := rt.NodeCfg().Mutate(ctx, x.by, func(n *shared.NodeCfg) error {
			mine = mine[:0]
			from := shared.From{Source: clustercfg.FromApply, Node: self.Name, By: x.by, At: time.Now().UTC()}
			for k := range n.Values {
				if len(keys) == 0 || slices.Contains(own, k) {
					n.ResetValue(k, from)
					mine = append(mine, k)
				}
			}
			return nil
		})
		if err != nil {
			return true, fmt.Errorf("could not change this server's settings in the shared settings: %w", err)
		}
		slices.Sort(mine)
		for _, k := range mine {
			x.audit("reset one of this server's own settings", "setting", k, "server", self.Name)
		}
	}
	file := c.SettingsFile()
	var fromFile []string
	if page, err := config.ReadPageSettings(file); err == nil && (len(local) > 0 || len(keys) == 0) {
		for _, k := range page.Keys() {
			if (len(keys) == 0 || slices.Contains(local, k)) && page.Remove(k) {
				fromFile = append(fromFile, k)
			}
		}
		if len(fromFile) > 0 {
			if err := config.WritePageSettings(file, page); err != nil {
				return true, err
			}
		}
	}
	if len(removed)+len(mine)+len(fromFile) == 0 {
		return true, errors.New("none of these were changed on a Settings page, so nothing was reset")
	}
	if len(removed) > 0 {
		fmt.Printf("Reset %s for every server of the cluster; the default applies again on every server within a few seconds "+
			"(a setting that waits for a restart applies once each server restarts).\n", strings.Join(removed, ", "))
	}
	if len(mine) > 0 {
		fmt.Printf("Reset %s of this server's own settings; signalith.yaml or the default applies again. Restart this server to apply it.\n", strings.Join(mine, ", "))
	}
	if len(fromFile) > 0 {
		fmt.Printf("Reset %s in %s; signalith.yaml or the default applies again. Restart this server to apply it.\n", strings.Join(fromFile, ", "), file)
	}
	return true, nil
}

// settingsResetLocal is signalith settings reset -local on a member: the
// shared settings and this server's own named are set aside for its next
// start, in setaside.json, without OpenSearch; the server refuses them in
// the shared settings once it can write there. The settings it needs to
// reach OpenSearch leave settings.yaml as before (handled by the caller,
// which gets them back).
func settingsResetLocal(path string, keys []string) ([]string, error) {
	stateDir := config.StateDirFor(path)
	if _, err := os.Stat(shared.CachePath(stateDir)); err != nil {
		return nil, errors.New("this server was never a member of a cluster: -local is for the settings servers share; run signalith settings reset without it")
	}
	if len(keys) == 0 {
		return nil, errors.New("name the settings to set aside: signalith settings reset -local <key>...")
	}
	var aside, local []string
	for _, k := range keys {
		set, ok := config.Lookup(k)
		if !ok {
			return nil, fmt.Errorf("%s is not a setting on the Settings page; see signalith settings list", k)
		}
		if set.Scope == config.ScopeBootstrap {
			local = append(local, k)
			continue
		}
		aside = append(aside, k)
	}
	if len(aside) > 0 {
		if err := writeSetAside(stateDir, aside, cliUser()); err != nil {
			return nil, err
		}
		fmt.Printf("Set aside %s on this server only, in %s.\n", strings.Join(aside, ", "), setAsideFile(stateDir))
		fmt.Println("Restart this server: it starts without them, and once OpenSearch takes writes again it records in the shared settings " +
			"that it does not use them, so the other servers' Settings pages say so. Fix them there, then try again.")
	}
	return local, nil
}
