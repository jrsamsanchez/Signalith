package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// The settings of the Settings page of a member of a cluster, once every
// server reads them from the shared settings (cluster level 3) and the
// founder's were imported (shared.Runtime.SharedSettings): the settings
// every server shares come from the settings document, each server's own
// from its nodecfg document, and only the settings it needs to reach
// OpenSearch from its settings.yaml (see config.Shared). Each start loads
// its configuration with that layer (loadConfig), so the checks before a
// restart, the rollback and the settings set aside all see the settings
// in effect. A change made on any server reaches this one within a poll:
// what applies at once is applied (followSettings), and what waits for a
// restart is listed in the heartbeat until this server restarts, by
// itself or as one of the servers a restart request names (one at a time:
// each restart ends once the server serves again). A shared value this
// server cannot use is refused here only: it keeps the value it ran with,
// says so, and the other servers go on with the shared one.
//
// Until the settings are shared, and on any server that is not a member,
// every path is as before: settings.yaml and signalith.yaml.

// settingsState is what the heartbeat says of the settings: the ones that
// wait for a restart, the shared ones refused, and how far the shared
// settings and the nodecfg document were applied.
type settingsState struct {
	restart, refused []string
	rev              cluster.SettingsRev
}

// settingsShared reports whether this server takes the settings of the
// Settings page from the shared settings now.
func (r *runner) settingsShared() bool {
	return r.shared != nil && r.sharedContent != nil && r.node != nil && r.shared.SharedSettings()
}

// layer returns this server's shared layer as the documents hold it now.
// Before its own settings were moved out of settings.yaml (its first
// start with shared settings, while OpenSearch could not be written),
// they are still taken from there.
func (r *runner) layer() *config.Shared {
	cb, _ := r.shared.Cluster().Get()
	nc, _ := r.shared.NodeCfg().Get()
	sh := clustercfg.Layer(r.sharedContent.docs, cb, nc, r.node.Name())
	if nc == nil || nc.SettingsImported == "" {
		if c := r.sharedContent.cfg.Load(); c != nil {
			if page, err := config.ReadPageSettings(c.SettingsFile()); err == nil {
				for _, k := range page.Keys() {
					if config.ScopeOf(k) == config.ScopeServer || k == "detections.scheduler" {
						if _, ok := sh.Server[k]; !ok {
							sh.Server[k] = page.Settings[k]
						}
					}
				}
			}
		}
	}
	return sh
}

// loadConfig loads the configuration to start with: with the shared layer
// while the settings are shared (moving this server's own settings out of
// settings.yaml first, once), and without the settings that signalith
// settings reset -local set aside; else as before.
func (r *runner) loadConfig() (*config.Config, error) {
	if !r.settingsShared() {
		return config.Load(r.path)
	}
	files, err := config.Load(r.path)
	if err != nil {
		return nil, err
	}
	r.importOwn(files)
	sh := r.layer()
	if aside, _ := readSetAside(files.StateDir()); aside != nil {
		return config.LoadSetAsideShared(r.path, sh, aside.Keys, aside.Reason)
	}
	return config.LoadShared(r.path, sh)
}

// loadStartConfig is loadConfig for a start or a restart: the shared
// settings changed in signalith.yaml or the environment since they were
// last applied are applied first (applyFiles), so one that needs a
// restart applies at this one.
func (r *runner) loadStartConfig() (*config.Config, error) {
	r.applyFiles()
	return r.loadConfig()
}

// applyFiles applies the shared settings changed in this server's
// signalith.yaml or environment to the shared settings
// (clustercfg.Apply), while the settings are shared and OpenSearch takes
// writes. Each start applies them too, in the background (see
// sharedContent.apply), which then finds them applied; it does so as
// well when they could not be applied here.
func (r *runner) applyFiles() {
	if !r.settingsShared() || r.shared.Writable() != nil {
		return
	}
	c, err := r.loadConfig()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.backgroundContext(context.Background()), 30*time.Second)
	defer cancel()
	ct := r.sharedContent
	ct.applyMu.Lock()
	defer ct.applyMu.Unlock()
	if _, err := clustercfg.Apply(ctx, r.shared, ct.docs, c, r.node.Name(), r.log); err != nil {
		r.log.Warn("could not apply the changes to signalith.yaml and the environment to the shared settings before starting; they apply once this start can", "err", err)
	}
}

// loadSetAside is loadConfig with keys set aside for reason, whether or
// not that could be recorded.
func (r *runner) loadSetAside(keys []string, reason string) (*config.Config, error) {
	if !r.settingsShared() {
		return config.LoadSetAside(r.path, keys, reason)
	}
	return config.LoadSetAsideShared(r.path, r.layer(), keys, reason)
}

// importOwn moves this server's own settings out of settings.yaml into
// its nodecfg document, once (clustercfg.ImportOwn), when OpenSearch takes
// writes; until then layer reads them from settings.yaml.
func (r *runner) importOwn(c *config.Config) {
	if r.shared.Writable() != nil {
		return
	}
	r.sharedContent.cfg.Store(c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := clustercfg.ImportOwn(ctx, r.shared, r.sharedContent.docs, c, r.log); err != nil {
		r.log.Warn("could not move this server's own settings from settings.yaml into the shared settings; trying again at the next start", "err", err)
	}
}

// primeShared points the runtime at OpenSearch before the first start of
// the components, so the configuration they start with can be loaded
// with the shared settings when they are shared already: the listen
// address and the certificate depend on them.
func (r *runner) primeShared(c *config.Config) *config.Config {
	if r.shared == nil || r.sharedContent == nil || r.node == nil {
		return c
	}
	useShared(r.shared, r.sharedContent, c, newStore(c))
	if !r.settingsShared() {
		return c
	}
	next, err := r.loadStartConfig()
	if err != nil {
		r.log.Error("the settings the servers share cannot be used; starting with this server's files", "err", err)
		return c
	}
	return next
}

// setAside sets the changes to keys aside, for reason, wherever they are
// kept: in settings.yaml (as before, and for the settings a server needs
// to reach OpenSearch), among this server's own settings in its nodecfg,
// and, for a shared setting, as a refusal of the shared value by this
// server, which keeps the value it runs in keep. It returns those it set
// aside. next is the configuration they come from.
func (r *runner) setAside(next, keep *config.Config, keys []string, reason string) []string {
	marked, _ := r.trySetAside(next, keep, keys, reason)
	return marked
}

// trySetAside is setAside, with the error that kept it from recording the
// settings in the shared settings.
func (r *runner) trySetAside(next, keep *config.Config, keys []string, reason string) ([]string, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	if !next.SharedSettings() || !r.settingsShared() {
		keys = config.SetAsideAlong(r.path, keys)
		marked, err := config.MarkRefused(next.SettingsFile(), keys, reason)
		if err != nil {
			r.log.Error("could not set changes from the Settings page aside in its file; the next start may use them again",
				"settings", strings.Join(keys, ","), "file", next.SettingsFile(), "err", err)
			return nil, err
		}
		return marked, nil
	}
	keys = config.SetAsideAlongShared(r.path, r.layer(), keys)
	var local, own, sharedKeys []string
	for _, k := range keys {
		switch config.ScopeOf(k) {
		case config.ScopeServer:
			own = append(own, k)
		case config.ScopeCluster:
			sharedKeys = append(sharedKeys, k)
		default:
			local = append(local, k)
		}
	}
	var out []string
	if len(local) > 0 {
		marked, err := config.MarkRefused(next.SettingsFile(), local, reason)
		if err != nil {
			r.log.Error("could not set changes from the Settings page aside in its file; the next start may use them again",
				"settings", strings.Join(local, ","), "file", next.SettingsFile(), "err", err)
		}
		out = append(out, marked...)
	}
	if len(own)+len(sharedKeys) == 0 {
		return out, nil
	}
	sh := r.layer()
	now := time.Now().UTC()
	refusals := map[string]shared.Refusal{}
	for _, k := range sharedKeys {
		v, ok := sh.Cluster[k]
		if !ok {
			continue
		}
		kept, err := keep.KeptValue(k)
		if err != nil {
			r.log.Warn("the value this server runs a shared setting with cannot be kept", "setting", k, "err", err)
			continue
		}
		refusals[k] = shared.Refusal{Hash: clustercfg.RefusalHash(r.shared.Hub().Keys(), k, v), Kept: kept, Reason: reason, At: now}
	}
	var marked []string
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := r.shared.NodeCfg().Mutate(ctx, "signalith", func(n *shared.NodeCfg) error {
		marked = nil
		for _, k := range own {
			if pv, ok := n.Values[k]; ok && pv.Refused == "" {
				pv.Refused, pv.RefusedAt = reason, now
				n.Values[k] = pv
				marked = append(marked, k)
			}
		}
		for k, ref := range refusals {
			if n.Refused == nil {
				n.Refused = map[string]shared.Refusal{}
			}
			ref.Extra = n.Refused[k].Extra
			n.Refused[k] = ref
			marked = append(marked, k)
		}
		return nil
	})
	if err != nil {
		r.log.Error("could not set changes aside in the shared settings; the next start may use them again",
			"settings", strings.Join(append(own, sharedKeys...), ","), "err", err)
		return out, err
	}
	if len(refusals) > 0 {
		r.log.Error("this server could not use shared settings and keeps the values it ran with; the other servers use the shared ones",
			"audit", true, "server", r.node.Name(), "settings", strings.Join(slices.Sorted(maps.Keys(refusals)), ","), "reason", reason)
	}
	slices.Sort(marked)
	return append(out, marked...), nil
}

// startWithout starts the components when c, with the shared layer, could
// not start (err): without this server's own settings from its nodecfg,
// then with signalith.yaml alone. The settings to blame that the start
// left out are refused here once OpenSearch takes writes, and this server
// keeps the values it started with meanwhile. A start without this
// server's own settings ran with the shared values, so none of those is
// to blame; and as a start knows no values that ran before, a shared
// value is to blame only when err names it (see blame): the others are
// tried again at the next start.
func (r *runner) startWithout(ctx context.Context, c *config.Config, err error) (*config.Config, *instance, net.Listener, error) {
	keys := blame(err, c, nil)
	own := slices.DeleteFunc(slices.Clone(keys), func(k string) bool { return config.ScopeOf(k) == config.ScopeCluster })
	reason := fmt.Sprintf("Signalith could not start with them (%v)", err)
	for _, step := range []struct {
		what string
		// left are the settings to blame this step leaves out.
		left []string
		load func() (*config.Config, error)
	}{
		{"without this server's own settings saved on a Settings page", own, func() (*config.Config, error) {
			return config.LoadWithoutServerValues(r.path, r.layer(), reason, own)
		}},
		{"with signalith.yaml alone", keys, func() (*config.Config, error) {
			return config.LoadWithoutShared(r.path, reason, keys)
		}},
	} {
		next, lerr := step.load()
		if lerr == nil {
			var in *instance
			var ln net.Listener
			if in, ln, lerr = r.open(ctx, next); lerr == nil {
				r.log.Error("Signalith could not start with the settings saved on the Settings pages; started "+step.what,
					"err", err, "settings", strings.Join(step.left, ","))
				r.refuseWhenWritable(ctx, c, next, step.left, reason)
				return next, in, ln, nil
			}
		}
		r.log.Error("Signalith cannot start "+step.what+" either", "err", lerr)
	}
	return nil, nil, nil, err
}

// refuseWhenWritable sets keys of next aside, for reason, keeping the
// values of keep, once OpenSearch takes writes, in the background: the
// start fell back without them.
func (r *runner) refuseWhenWritable(ctx context.Context, next, keep *config.Config, keys []string, reason string) {
	if len(keys) == 0 || !r.settingsShared() {
		return
	}
	go func() {
		for {
			if r.shared.Writable() == nil {
				if _, err := r.trySetAside(next, keep, keys, reason); err == nil {
					break
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(settleRetry()):
			}
		}
		r.sharedContent.kickSettings()
	}()
}

// pendingKeys lists the settings on the page whose value differs between
// the configuration running and the one in effect: they wait for a
// restart.
func pendingKeys(running, effective *config.Config) []string {
	out := []string{}
	for i := range config.Registry {
		set := &config.Registry[i]
		if set.OnPage(true) && !config.SameValue(running, effective, set.Key) {
			out = append(out, set.Key)
		}
	}
	return out
}

// refusedKeys lists the shared settings c keeps its own value of.
func refusedKeys(c *config.Config) []string {
	out := []string{}
	for _, k := range config.SharedKeys() {
		if _, ok := c.SharedKept(k); ok {
			out = append(out, k)
		}
	}
	return out
}

// followSettings applies the changes of the shared settings and of this
// server's own while the components of a start run (until ctx ends): the
// configuration is loaded again, a shared value that does not work here
// is refused (this server keeps the value it runs), what applies at once
// is applied, and what waits for a restart is listed for the heartbeat.
func (r *runner) followSettings(ctx context.Context, srv *api.Server, ret *retention.Manager, c *config.Config) {
	ct := r.sharedContent
	prev := c
	var reported string
	for {
		// A value refused keeps the one in use now: what this start began
		// with, and the changes applied at once since.
		next, err := r.loadConfig()
		if err == nil && next.SettingsProblem() != "" && r.refuseUnusable(srv.Running(), next.SettingsProblem()) {
			// Started without settings saved for this server that it
			// cannot use: they are refused, and so left out from now on.
			continue
		}
		if err != nil {
			if r.refuseUnusable(srv.Running(), strings.TrimPrefix(err.Error(), r.path+": ")) {
				continue
			}
			if msg := err.Error(); msg != reported {
				reported = msg
				r.log.Error("the changed settings cannot be loaded; this server keeps the ones in use", "err", err)
			}
		} else {
			reported = ""
			applied := srv.ApplySettings(prev, next)
			if len(applied) > 0 {
				r.log.Info("settings changed on a Settings page apply now", "settings", strings.Join(applied, ","))
			}
			if ret != nil && prev.RetentionInterval() != next.RetentionInterval() {
				ret.SetInterval(next.RetentionInterval())
			}
			prev = next
			running := srv.Running()
			st := &settingsState{restart: pendingKeys(running, next), refused: refusedKeys(next)}
			_, _, st.rev.Settings = ct.docs.Settings().Updated()
			_, _, st.rev.NodeCfg = r.shared.NodeCfg().Updated()
			ct.settings.Store(st)
			r.recordRunning(ctx, running)
		}
		select {
		case <-ctx.Done():
			return
		case <-ct.settingsKick:
		case <-time.After(sharedCheck()):
		}
	}
}

// refuseUnusable refuses here the settings saved for this server that
// keep the configuration from loading, or that it was loaded without
// (problem says why): shared values, keeping the values in use
// (running), and this server's own. It reports whether it refused any.
func (r *runner) refuseUnusable(running *config.Config, problem string) bool {
	if r.shared.Writable() != nil {
		return false
	}
	saved, serr := config.LoadSavedShared(r.path, r.layer())
	if serr != nil || saved.Problems == nil {
		return false
	}
	var keys []string
	for _, p := range saved.Problems {
		for _, k := range config.ProblemKeys(p) {
			src := saved.Source(k)
			own := config.ScopeOf(k) == config.ScopeServer && src.Kind == config.FromPage
			if (src.Kind == config.FromShared || own) && !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
	}
	if len(keys) == 0 {
		return false
	}
	reason := "This server cannot use it: " + strings.Join(saved.Problems, "; ")
	r.log.Error("settings saved for this server cannot be used here; they are set aside", "settings", strings.Join(keys, ","), "problem", problem)
	return len(r.setAside(saved.Config, running, keys, reason)) > 0
}

// recordRunning writes what this server runs of its own settings, and
// where each value comes from, into its nodecfg document when that
// changed, so another server's Settings page can show it.
func (r *runner) recordRunning(ctx context.Context, c *config.Config) {
	if r.shared.Writable() != nil {
		return
	}
	run := map[string]shared.RunningValue{}
	for i := range config.Registry {
		set := &config.Registry[i]
		if set.Scope != config.ScopeServer || !set.OnPage(true) {
			continue
		}
		src := c.Source(set.Key)
		v := shared.RunningValue{Source: src.Kind, Env: src.Env}
		if set.Type == config.TypeSecret {
			s, _ := c.Value(set.Key).(string)
			v.Set = s != ""
		} else if raw, err := json.Marshal(c.Value(set.Key)); err == nil {
			v.Value = raw
		}
		run[set.Key] = v
	}
	if nc, _ := r.shared.NodeCfg().Get(); nc != nil && sameRunning(nc.Running, run) {
		return
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := r.shared.NodeCfg().Mutate(wctx, "signalith", func(n *shared.NodeCfg) error {
		n.Running, n.RunningAt = run, time.Now().UTC()
		return nil
	}); err != nil && ctx.Err() == nil {
		r.log.Debug("could not record this server's own settings for the other servers' pages", "err", err)
	}
}

// sameRunning reports whether two lists of running values hold the same.
func sameRunning(a, b map[string]shared.RunningValue) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// kickSettings wakes followSettings: the settings document or this
// server's nodecfg document changed.
func (ct *sharedContent) kickSettings() {
	select {
	case ct.settingsKick <- struct{}{}:
	default:
	}
}

// followDocs makes the shared documents of the settings wake
// followSettings when they change: the settings document's subscriptions
// end with each start (Docs.Reset), the runtime's documents last as long
// as the hub, so each is subscribed once.
func (ct *sharedContent) followDocs(rt *shared.Runtime) {
	ct.docs.OnSettings(ct.kickSettings)
	ct.followMu.Lock()
	defer ct.followMu.Unlock()
	if d := rt.NodeCfg(); d != nil && d != ct.followedNC {
		ct.followedNC = d
		d.OnChange(func(_, _ *shared.NodeCfg) { ct.kickSettings() })
	}
	if d := rt.Cluster(); d != nil && d != ct.followedCluster {
		ct.followedCluster = d
		d.OnChange(func(a, b *shared.ClusterBody) {
			if a == nil || b == nil || a.Name != b.Name {
				ct.kickSettings()
			}
		})
	}
}

// settingsStatus is the heartbeat's say on the settings, nil while they
// are not shared.
func (ct *sharedContent) settingsStatus() (restart, refused []string, rev *cluster.SettingsRev) {
	if ct == nil || !ct.settingsOn.Load() {
		return nil, nil, nil
	}
	st := ct.settings.Load()
	if st == nil {
		return nil, nil, nil
	}
	r := st.rev
	return st.restart, st.refused, &r
}

// settingsRev is how far this server applied the shared settings, for the
// heartbeat; nil while they are not shared.
func (ct *sharedContent) settingsRev() *cluster.SettingsRev {
	_, _, rev := ct.settingsStatus()
	return rev
}

// restartStatus is the heartbeat's say on this server's restarts.
func (r *runner) restartStatus() cluster.RestartStatus {
	st := r.RestartStatus()
	out := cluster.RestartStatus{Busy: st.InProgress}
	if l := st.Last; l != nil {
		out.Last = &cluster.RestartResult{At: l.At, OK: l.OK && !l.Reverted, Error: l.Error, RolledBack: l.RolledBack || l.Reverted, Keys: l.Keys}
	}
	return out
}

// remoteRestart is a restart another server asked for (a restart
// request): done hears how it ended, once it ended, a move of the web
// page included.
type remoteRestart struct {
	req  *shared.Request
	done chan *api.RestartResult
}

func (rr *remoteRestart) end(res *api.RestartResult) {
	if rr == nil {
		return
	}
	select {
	case rr.done <- res:
	default:
	}
}

// restartWait is how long a restart request waits for this server's own
// restart under way to end before it fails.
var restartWait = 5 * time.Minute

// serverHandlers run the requests that name this server.
func (r *runner) serverHandlers() map[string]shared.Handler {
	return map[string]shared.Handler{
		clustercfg.RequestRestart:       r.handleRestartRequest,
		clustercfg.RequestSettingsCheck: r.handleSettingsCheck,
	}
}

// handleRestartRequest restarts this server as part of a restart request,
// and ends once it serves again: with the new settings, back with the
// previous ones, or once a move of its web page was confirmed or undone.
func (r *runner) handleRestartRequest(ctx context.Context, req *shared.Request) error {
	var a clustercfg.RestartArgs
	if len(req.Args) > 0 {
		if err := json.Unmarshal(req.Args, &a); err != nil {
			return fmt.Errorf("the request's arguments cannot be read: %w", err)
		}
	}
	deadline := time.Now().Add(restartWait)
	for {
		r.mu.Lock()
		free := !r.busy && r.awaiting == nil
		if free {
			r.busy = true
		}
		r.mu.Unlock()
		if free {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("another restart of this server did not end in time")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	rr := &remoteRestart{req: req, done: make(chan *api.RestartResult, 1)}
	r.requests <- restartRequest{by: req.RequestedBy, client: "restart request " + req.ID, localOnly: a.LocalOnly, remote: rr}
	var res *api.RestartResult
	select {
	case res = <-rr.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	self := r.node.ID()
	out := clustercfg.RestartResult{OK: res.OK && !res.Reverted, RolledBack: res.RolledBack || res.Reverted, Error: res.Error,
		Keys: res.Keys, BootID: r.shared.BootID()}
	if len(res.ProblemKeys) > 0 && !out.OK {
		out.Keys = res.ProblemKeys
	}
	var mine clustercfg.RestartResults
	if json.Unmarshal(req.Result, &mine) == nil && mine[self].Move != nil {
		mv := *mine[self].Move
		mv.Confirmed = res.Confirmed
		out.Move = &mv
	}
	if err := req.SetResult(clustercfg.RestartResults{self: out}); err != nil {
		return err
	}
	if !out.OK {
		return errors.New(strings.TrimSuffix(cmpOr(res.Error, "the restart did not apply the settings"), "."))
	}
	return nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// announceMove writes where a restart run by request moved this server's
// web page, with the token that confirms it, into its part of the
// request, for the server that asked to probe.
func (r *runner) announceMove(rr *remoteRestart, m *move, next *config.Config) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return
	}
	m.token = "mv_" + hex.EncodeToString(b)
	to := nodeURL(next)
	if to == "" {
		to = webAddress(next)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rr.req.SetResult(clustercfg.RestartResults{r.node.ID(): {Move: &clustercfg.Move{Token: m.token, To: to}}}); err != nil {
		return
	}
	if err := r.shared.Requests().SaveResult(ctx, rr.req); err != nil {
		r.log.Warn("could not say where this server's web page moved; nobody can confirm it from another server", "err", err)
	}
}

// confirmProbe confirms a move of the web page waiting for a probe of
// the new address with its token, when req came in there.
func (r *runner) confirmProbe(req *http.Request, token string) bool {
	w, _ := req.Context().Value(webKey{}).(*webServer)
	r.mu.Lock()
	m := r.awaiting
	ok := m != nil && w != nil && w == m.web && m.token != "" && m.token == token
	r.mu.Unlock()
	if !ok {
		return false
	}
	return r.Confirm(req)
}

// probeMoves follows a restart request this server made and probes the
// new address of each server whose restart moved its web page, which
// confirms the move there. Until the servers share one certificate
// authority, the probe does not check the certificate: the token, which
// only the request holds, reaching the new address is the proof, and a
// probe can confirm a move, nothing else.
func (r *runner) probeMoves(id string) {
	ctx, cancel := context.WithTimeout(r.backgroundContext(context.Background()), 2*time.Hour)
	defer cancel()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // the move token is the proof (see above)
	}}
	defer client.CloseIdleConnections()
	for {
		req, ok, err := r.shared.Requests().Get(ctx, id)
		if err == nil && (!ok || req.Over()) {
			return
		}
		var res clustercfg.RestartResults
		if err == nil && json.Unmarshal(req.Result, &res) == nil {
			for _, p := range res {
				if p.Move == nil || p.Move.Confirmed || p.Move.Token == "" || p.Move.To == "" {
					continue
				}
				u := strings.TrimRight(p.Move.To, "/") + "/readyz?move=" + url.QueryEscape(p.Move.Token)
				if resp, err := client.Get(u); err == nil {
					resp.Body.Close()
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// handleSettingsCheck checks a change of this server's own settings made
// on another server's Settings page.
func (r *runner) handleSettingsCheck(ctx context.Context, req *shared.Request) error {
	var a clustercfg.SettingsCheckArgs
	if err := json.Unmarshal(req.Args, &a); err != nil {
		return fmt.Errorf("the request's arguments cannot be read: %w", err)
	}
	srv := r.srv.Load()
	if srv == nil {
		return errors.New("this server is not running its parts")
	}
	res, err := srv.CheckOwnEdit(ctx, req.RequestedBy, a)
	if err != nil {
		return err
	}
	return req.SetResult(res)
}

// settingsStore keeps the Settings page's settings in the shared
// settings (api.SettingsStore).
type settingsStore struct{ r *runner }

func (s settingsStore) Shared() bool    { return s.r.sharedContent.settingsOn.Load() }
func (s settingsStore) Writable() error { return s.r.shared.Writable() }
func (s settingsStore) Self() string    { return s.r.node.ID() }
func (s settingsStore) ETag() string    { return s.r.sharedContent.docs.Settings().ETag() }
func (s settingsStore) Revision() int64 {
	_, _, rev := s.r.sharedContent.docs.Settings().Updated()
	return rev
}

func (s settingsStore) Layer(ctx context.Context, server string) (*config.Shared, *shared.NodeCfg, error) {
	r := s.r
	if server == "" || server == r.node.ID() {
		nc, _ := r.shared.NodeCfg().Get()
		return r.layer(), nc, nil
	}
	nc, err := clustercfg.NodeCfgOf(ctx, r.shared, server)
	if err != nil {
		return nil, nil, err
	}
	name := server
	for _, p := range r.node.Status().Servers {
		if p.NodeID == server {
			name = p.Name
		}
	}
	cb, _ := r.shared.Cluster().Get()
	return clustercfg.Layer(r.sharedContent.docs, cb, nc, name), nc, nil
}

func (s settingsStore) Save(ctx context.Context, by, server string, base *config.Shared, res *config.SharedEditResult, versions map[string]int64) (map[string]int64, error) {
	revs, err := clustercfg.Save(ctx, s.r.shared, s.r.sharedContent.docs, by, server, base, res, versions)
	if err == nil && server == s.r.node.ID() {
		s.r.sharedContent.kickSettings()
	}
	return revs, err
}

func (s settingsStore) Check(ctx context.Context, by, server string, args clustercfg.SettingsCheckArgs) (*clustercfg.SettingsCheckResult, bool, error) {
	rq := s.r.shared.Requests()
	req, err := rq.Submit(ctx, clustercfg.RequestSettingsCheck, server, args, by)
	if err != nil {
		return nil, false, err
	}
	deadline := time.Now().Add(clustercfg.SettingsCheckWait)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		now, ok, err := rq.Get(ctx, req.ID)
		if err != nil || !ok || !now.Over() {
			continue
		}
		if now.State == shared.RequestFailed {
			return nil, false, errors.New(now.Error)
		}
		var res clustercfg.SettingsCheckResult
		if err := json.Unmarshal(now.Result, &res); err != nil {
			return nil, false, err
		}
		return &res, true, nil
	}
	return nil, false, nil
}

func (s settingsStore) Restart(ctx context.Context, by string, servers []string, sequential bool) (*shared.Request, error) {
	if err := s.r.shared.Writable(); err != nil {
		return nil, err
	}
	req, err := s.r.shared.Requests().SubmitTo(ctx, clustercfg.RequestRestart, servers, sequential, clustercfg.RestartArgs{}, by)
	if err != nil {
		return nil, err
	}
	go s.r.probeMoves(req.ID)
	return req, nil
}

// setAsideFile is where signalith settings reset -local sets shared
// settings and this server's own aside while OpenSearch cannot be
// reached: the next start leaves them out, and refuses them in the shared
// settings once it can write there.
func setAsideFile(stateDir string) string {
	return filepath.Join(stateDir, "cluster", "setaside.json")
}

// setAsideList is the content of setaside.json.
type setAsideList struct {
	Keys   []string  `json:"keys"`
	Reason string    `json:"reason"`
	By     string    `json:"by,omitempty"`
	At     time.Time `json:"at"`
}

// readSetAside reads setaside.json; nil when there is none.
func readSetAside(stateDir string) (*setAsideList, error) {
	data, err := os.ReadFile(setAsideFile(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var l setAsideList
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("%s: %w", setAsideFile(stateDir), err)
	}
	if len(l.Keys) == 0 {
		return nil, nil
	}
	return &l, nil
}

// writeSetAside adds keys to setaside.json.
func writeSetAside(stateDir string, keys []string, by string) error {
	l, err := readSetAside(stateDir)
	if err != nil || l == nil {
		l = &setAsideList{}
	}
	for _, k := range keys {
		if !slices.Contains(l.Keys, k) {
			l.Keys = append(l.Keys, k)
		}
	}
	l.Reason = "Set aside with signalith settings reset -local while OpenSearch could not be reached"
	l.By, l.At = by, time.Now().UTC()
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(setAsideFile(stateDir)), 0o700); err != nil {
		return err
	}
	return securefile.Replace(setAsideFile(stateDir), data)
}

// settleRetryEvery is how often a refusal waiting for OpenSearch to take
// writes is tried again, in nanoseconds; atomic, for the tests.
var settleRetryEvery atomic.Int64

func init() { settleRetryEvery.Store(int64(5 * time.Second)) }

// settleRetry is how often a refusal waiting for writes is tried again.
func settleRetry() time.Duration { return time.Duration(settleRetryEvery.Load()) }

// trySetAsideErr sets the settings of l aside in the shared settings.
func (r *runner) trySetAsideErr(c *config.Config, l *setAsideList) error {
	_, err := r.trySetAside(c, c, l.Keys, l.Reason)
	return err
}

// settleSetAside sets the settings of setaside.json aside in the shared
// settings once OpenSearch takes writes, then deletes the file: from then
// on the shared settings say they are not used here.
func (r *runner) settleSetAside(ctx context.Context, c *config.Config) {
	l, err := readSetAside(c.StateDir())
	if err != nil {
		r.log.Error("the settings set aside with signalith settings reset -local cannot be read", "err", err)
		return
	}
	if l == nil {
		return
	}
	// Until OpenSearch takes the write: it may answer reads and still
	// refuse writes.
	for r.shared.Writable() != nil || r.trySetAsideErr(c, l) != nil {
		select {
		case <-ctx.Done():
			return
		case <-time.After(settleRetry()):
		}
	}
	if err := os.Remove(setAsideFile(c.StateDir())); err != nil && !errors.Is(err, os.ErrNotExist) {
		r.log.Warn("could not delete setaside.json after setting its settings aside in the shared settings", "err", err)
		return
	}
	r.log.Info("settings set aside with signalith settings reset -local are now set aside in the shared settings", "settings", strings.Join(l.Keys, ","))
}
