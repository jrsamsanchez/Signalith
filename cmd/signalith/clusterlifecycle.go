package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Draining, moving the background jobs, removing servers and rotating the
// cluster key. A drain is kept in the server's nodecfg, so it survives a
// restart; the server follows it (followDrain).

// drainJobsWait is how long a drain request waits for the server to give the
// background jobs up.
var drainJobsWait = 90 * time.Second

// releaseDelay is how long a release_jobs request waits, once it is
// over, before the jobs are given up: giving them up ends the request
// loop that runs it.
var releaseDelay = 2 * time.Second

// lifecycleServerHandlers run the drain and resume requests that name
// this server.
func (r *runner) lifecycleServerHandlers() map[string]shared.Handler {
	return map[string]shared.Handler{
		clustercfg.RequestDrain:  r.handleDrain,
		clustercfg.RequestResume: r.handleResume,
	}
}

// lifecycleLeaderHandlers run, on the server that runs the background
// jobs, the requests that move them and rotate the cluster key.
func (r *runner) lifecycleLeaderHandlers() map[string]shared.Handler {
	if r.shared == nil || r.node == nil {
		return nil
	}
	return map[string]shared.Handler{
		clustercfg.RequestReleaseJobs: r.handleReleaseJobs,
		clustercfg.RequestRotateKey:   r.handleRotateKey,
	}
}

// handleDrain drains this server: the drain is kept in its nodecfg, and
// the request ends once the server gave the background jobs up.
func (r *runner) handleDrain(ctx context.Context, req *shared.Request) error {
	by := cmp.Or(req.RequestedBy, "an admin")
	if _, err := r.shared.NodeCfg().Mutate(ctx, "signalith", func(n *shared.NodeCfg) error {
		if n.Drained == nil {
			n.Drained = &shared.DrainMark{By: by, At: time.Now().UTC()}
		}
		return nil
	}); err != nil {
		return err
	}
	r.node.Drain("drained by " + by)
	r.log.Info("this server was drained: it wants no traffic and runs no background jobs until it is resumed", "audit", true, "by", by)
	deadline := time.Now().Add(drainJobsWait)
	for r.node.Lease().Holding() {
		if time.Now().After(deadline) {
			return errors.New("the server is drained, but it did not give the background jobs up in time; they move once its jobs finish")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return req.SetResult(map[string]bool{"drained": true})
}

// handleResume undoes a drain of this server.
func (r *runner) handleResume(ctx context.Context, req *shared.Request) error {
	if _, err := r.shared.NodeCfg().Mutate(ctx, "signalith", func(n *shared.NodeCfg) error {
		n.Drained = nil
		return nil
	}); err != nil {
		return err
	}
	r.node.Resume()
	r.log.Info("this server was resumed", "audit", true, "by", req.RequestedBy)
	return req.SetResult(map[string]bool{"drained": false})
}

// followDrain keeps the node drained while this server's nodecfg says
// so, from the start on, until ctx ends.
func (r *runner) followDrain(ctx context.Context) {
	if r.shared == nil || r.node == nil {
		return
	}
	for {
		if m, _ := r.shared.Mode(); m == shared.ModeMember || m == shared.ModeDegraded {
			if nc, ok := r.shared.NodeCfg().Get(); ok {
				switch {
				case nc.Drained != nil && !r.node.Drained():
					r.node.Drain("drained by " + cmp.Or(nc.Drained.By, "an admin"))
				case nc.Drained == nil && r.node.Drained() && m == shared.ModeMember:
					r.node.Resume()
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// handleReleaseJobs hands the background jobs to the server the request
// names, once the request is over.
func (r *runner) handleReleaseJobs(ctx context.Context, req *shared.Request) error {
	var a clustercfg.ReleaseJobsArgs
	if err := json.Unmarshal(req.Args, &a); err != nil || a.To == "" {
		return errors.New("the request does not name the server to take the background jobs")
	}
	if a.To == r.node.ID() {
		// Run again by the server it named (the request went back to the
		// queue when the jobs moved): done.
		return req.SetResult(map[string]string{"to": r.node.Name()})
	}
	sv, ok := serverIn(r.node.Status(), a.To)
	if !ok {
		return errors.New("the server to take the background jobs is not among the servers")
	}
	switch {
	case sv.State != cluster.StateReady:
		return fmt.Errorf("%s is not running normally, so it cannot take the background jobs", sv.Name)
	case sv.Jobs != "standby":
		return fmt.Errorf("%s may not run the background jobs", sv.Name)
	case sv.CannotTakeOver != "":
		return fmt.Errorf("%s cannot take the background jobs: %s", sv.Name, sv.CannotTakeOver)
	}
	if cb, ok := r.shared.Cluster().Get(); ok && sv.Detail != nil && max(sv.Detail.LevelMax, shared.LevelMin) < cb.Level {
		return fmt.Errorf("%s runs a version too old for the cluster: upgrade it first", sv.Name)
	}
	if err := req.SetResult(map[string]string{"to": sv.Name}); err != nil {
		return err
	}
	go func() {
		time.Sleep(releaseDelay)
		r.log.Info("handing the background jobs to another server", "audit", true, "to", sv.Name, "by", req.RequestedBy)
		r.node.MoveJobs(a.To)
	}()
	return nil
}

// serverIn finds the server nodeID in st.
func serverIn(st cluster.Status, nodeID string) (cluster.ServerStatus, bool) {
	for _, sv := range st.Servers {
		if sv.NodeID == nodeID {
			return sv, true
		}
	}
	return cluster.ServerStatus{}, false
}

// handleRotateKey rotates the cluster key, recording each step in the
// request.
func (r *runner) handleRotateKey(ctx context.Context, req *shared.Request) error {
	var a clustercfg.RotateKeyArgs
	if len(req.Args) > 0 {
		if err := json.Unmarshal(req.Args, &a); err != nil {
			return fmt.Errorf("the request's arguments cannot be read: %w", err)
		}
	}
	rt := r.shared
	ct := r.sharedContent
	client := func() (*store.Client, string) {
		if t := ct.target.Load(); t != nil {
			return t.cl, t.prefix
		}
		return nil, ""
	}
	reqs := rt.Requests()
	res, err := rt.RotateKey(ctx, shared.RotateOptions{By: cmp.Or(req.RequestedBy, "signalith"), Reason: cmp.Or(a.Reason, "rotate-key"),
		Resealers: sharedResealers(ct.sharedDocs, client),
		Progress: func(step string, done, total int) {
			_ = req.SetResult(map[string]string{"step": step})
			if err := reqs.SaveResult(ctx, req); err != nil {
				r.log.Debug("could not record how far the key rotation came", "err", err)
			}
			_ = reqs.SetProgress(ctx, req, int64(done), int64(total))
		}})
	if res != nil {
		_ = req.SetResult(res)
	}
	if err != nil {
		return err
	}
	var mark error
	if len(a.Removed) > 0 {
		mark = rt.MarkRotated(ctx, a.Removed...)
	} else {
		mark = rt.MarkAllRotated(ctx)
	}
	if mark != nil {
		r.log.Warn("rotated the cluster key, but could not note it on the removed servers", "err", mark)
	}
	return nil
}

// lifecycleAPI drains and removes servers for the API
// (api.ClusterServers).
type lifecycleAPI struct {
	rt   *shared.Runtime
	node *cluster.Node
}

// clusterServersAPI returns the API's view, nil on a server that does
// not use the shared settings.
func (r *runner) clusterServersAPI() api.ClusterServers {
	if r.shared == nil || r.node == nil {
		return nil
	}
	return lifecycleAPI{rt: r.shared, node: r.node}
}

func (a lifecycleAPI) Off() string {
	if m, why := a.rt.Mode(); m != shared.ModeMember {
		return "This server doesn't use the cluster's shared settings now (" + cmp.Or(why, m.Text()) + "), so servers cannot be drained or removed from it."
	}
	if !a.rt.SharedSettings() {
		return "Servers can be drained and removed once every server is upgraded to a version that shares its settings."
	}
	return ""
}

func (a lifecycleAPI) Lifecycle() api.ClusterLifecycle {
	return lifecycleOf(a.rt)
}

// lifecycleOf is the keyring's members, the removed servers and the key
// rotation.
func lifecycleOf(rt *shared.Runtime) api.ClusterLifecycle {
	out := api.ClusterLifecycle{Members: []api.LifecycleMember{}, Removed: rt.Removed(), Rotation: rt.Rotation()}
	if out.Removed == nil {
		out.Removed = []shared.RemovedServer{}
	}
	if kr, ok := rt.Keyring().Get(); ok {
		for id, m := range kr.Members {
			out.Members = append(out.Members, api.LifecycleMember{NodeID: id, Name: m.Name, Fingerprint: m.Fingerprint, AddedBy: m.AddedBy, AddedAt: m.AddedAt})
		}
	}
	slices.SortFunc(out.Members, func(x, y api.LifecycleMember) int { return strings.Compare(x.Name, y.Name) })
	return out
}

func (a lifecycleAPI) Submit(ctx context.Context, typ, target string, args any, by string) (*shared.Request, error) {
	if err := a.rt.Writable(); err != nil {
		return nil, err
	}
	return a.rt.Requests().Submit(ctx, typ, target, args, by)
}

func (a lifecycleAPI) Remove(ctx context.Context, nodeID, name, by string, live bool) (shared.RemovedServer, error) {
	return removeServer(ctx, a.rt, nodeID, name, by, live)
}

// removeServer takes the server nodeID out of the keyring, records it as
// removed and deletes its nodecfg document and, unless it still runs, its
// heartbeat.
func removeServer(ctx context.Context, rt *shared.Runtime, nodeID, name, by string, live bool) (shared.RemovedServer, error) {
	rec, err := rt.RemoveMember(ctx, nodeID, name, by)
	if err != nil {
		return rec, err
	}
	c, prefix := rtTarget(rt)
	if c == nil {
		return rec, nil
	}
	if err := deleteDoc(ctx, c, shared.ConfigIndex(prefix), shared.NodeCfgID(nodeID)); err != nil {
		return rec, fmt.Errorf("%s was removed, but its own settings could not be deleted: %w", rec.Name, err)
	}
	if !live {
		if err := deleteDoc(ctx, c, cluster.RuntimeIndex(prefix), cluster.NodeDocID(nodeID)); err != nil {
			return rec, fmt.Errorf("%s was removed, but its heartbeat could not be deleted: %w", rec.Name, err)
		}
	}
	var errs []error
	for _, h := range removeHooks(rt) {
		if err := h(ctx, by, nodeID); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return rec, fmt.Errorf("%s was removed, but %w", rec.Name, err)
	}
	return rec, nil
}

// removeHook is told of a server removed from the cluster, for a feature
// that issued it something that must stop working with it (such as an
// OpenSearch client certificate). Its error is reported; the removal
// stands.
type removeHook func(ctx context.Context, by, nodeID string) error

// removeHooks lists the features' removeHooks. Append a feature's hook
// here.
func removeHooks(rt *shared.Runtime) []removeHook {
	_ = rt
	return nil
}

// rtTarget is the OpenSearch client and index prefix rt uses.
func rtTarget(rt *shared.Runtime) (*store.Client, string) { return rt.Target() }

// deleteDoc deletes the document id of index, if it is there.
func deleteDoc(ctx context.Context, c *store.Client, index, id string) error {
	_, ver, found, err := c.Get(ctx, index, id)
	if err != nil || !found {
		return err
	}
	err = c.DeleteIf(ctx, index, id, ver, false)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

// ---- the command line ----

// rotateKey runs signalith cluster rotate-key: the server that runs the
// background jobs rotates the cluster key, and this command follows it.
func (x *clusterCLI) rotateKey(ctx context.Context, yes bool) error {
	rt := x.runtime(true, "")
	if m, why := rt.Mode(); m != shared.ModeMember {
		return fmt.Errorf("this server cannot use the cluster's shared settings now (%s)", cmp.Or(why, m.Text()))
	}
	if !rt.KeyRotation() {
		return shared.ErrNoRotation
	}
	if err := x.confirm("Rotate the cluster key? Every running server picks up the new key; one offline catches up within 7 days.", yes); err != nil {
		return err
	}
	req, err := rt.Requests().Submit(ctx, clustercfg.RequestRotateKey, shared.TargetLeader, clustercfg.RotateKeyArgs{Reason: "rotate-key"}, x.by)
	if err != nil {
		return err
	}
	x.audit("asked for a rotation of the cluster key", "request", req.ID)
	return x.follow(ctx, rt, req.ID, "the key rotation")
}

// follow prints how the request id goes until it is over.
func (x *clusterCLI) follow(ctx context.Context, rt *shared.Runtime, id, what string) error {
	fmt.Fprintf(x.errOut, "Waiting for the server that runs the background jobs to run %s (request %s; Ctrl-C stops waiting, not the request)...\n", what, id)
	last := ""
	for {
		req, found, err := rt.Requests().Get(ctx, id)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("request %s is gone", id)
		}
		var step struct {
			Step string `json:"step"`
		}
		if json.Unmarshal(req.Result, &step) == nil && step.Step != "" && step.Step != last {
			last = step.Step
			fmt.Fprintf(x.errOut, "  %s\n", step.Step)
		}
		switch req.State {
		case shared.RequestDone:
			fmt.Fprintf(x.out, "Done: %s finished.\n", what)
			return nil
		case shared.RequestFailed:
			return fmt.Errorf("%s failed: %s", what, req.Error)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// removeCLI runs signalith cluster remove <server>.
func (x *clusterCLI) removeCLI(ctx context.Context, which string, noRotate, yes bool) error {
	rt := x.runtime(true, "")
	if m, why := rt.Mode(); m != shared.ModeMember {
		return fmt.Errorf("this server cannot use the cluster's shared settings now (%s)", cmp.Or(why, m.Text()))
	}
	hbs, err := x.heartbeats(ctx)
	if err != nil {
		return err
	}
	lc := lifecycleOf(rt)
	id, name := "", ""
	for _, m := range lc.Members {
		if m.NodeID == which || strings.EqualFold(m.Name, which) {
			id, name = m.NodeID, m.Name
		}
	}
	var hb *cluster.Heartbeat
	for i := range hbs {
		if hbs[i].NodeID == which || strings.EqualFold(hbs[i].Name, which) || hbs[i].NodeID == id {
			hb = &hbs[i]
			id, name = hbs[i].NodeID, hbs[i].Name
		}
	}
	if id == "" {
		return fmt.Errorf("no server is named %q", which)
	}
	if id == x.self.NodeID {
		return errors.New("this is this server: to take it out of the cluster, run signalith cluster leave on it")
	}
	live := hb != nil && hb.State != cluster.StateStopped && time.Since(hb.HeartbeatAt) < cliHeartbeatAge
	if hb != nil && hb.State != cluster.StateStopped && hb.State != cluster.StateDraining && time.Since(hb.HeartbeatAt) < api.RemoveAfter {
		return fmt.Errorf("%s is running or went offline less than %d minutes ago: drain it on the Servers page, or stop it, first", name, int(api.RemoveAfter/time.Minute))
	}
	if err := x.confirm(fmt.Sprintf("Remove %s from the cluster?", name), yes); err != nil {
		return err
	}
	rec, err := removeServer(ctx, rt, id, name, x.by, live)
	if err != nil {
		return err
	}
	x.audit("cluster.remove: removed a server from the cluster", "server", rec.Name, "node_id", id)
	fmt.Fprintf(x.out, "Removed %s from the cluster.\n", rec.Name)
	return x.rotateAfterRemove(ctx, rt, []string{id}, rec.Name, noRotate)
}

// rotateAfterRemove asks for a rotation of the cluster key after the
// removal of the servers ids, unless noRotate.
func (x *clusterCLI) rotateAfterRemove(ctx context.Context, rt *shared.Runtime, ids []string, name string, noRotate bool) error {
	switch {
	case noRotate:
		fmt.Fprintf(x.out, "The cluster key was not rotated, so %s's copy of it still works until it is (signalith cluster rotate-key).\n", name)
		return nil
	case !rt.KeyRotation():
		fmt.Fprintf(x.out, "The cluster key was not rotated: %s. Rotate it once every server is upgraded.\n", strings.TrimSuffix(shared.ErrNoRotation.Error(), "."))
		return nil
	}
	req, err := rt.Requests().Submit(ctx, clustercfg.RequestRotateKey, shared.TargetLeader, clustercfg.RotateKeyArgs{Reason: "removed " + name, Removed: ids}, x.by)
	if err != nil {
		return fmt.Errorf("the cluster key could not be rotated (%w): run signalith cluster rotate-key", err)
	}
	fmt.Fprintf(x.out, "The server that runs the background jobs rotates the cluster key now (request %s).\n", req.ID)
	return nil
}

// leave runs signalith cluster leave on a stopped server: it takes
// itself out of the cluster and forgets the cluster key.
func (x *clusterCLI) leave(ctx context.Context, noRotate, yes bool) error {
	dir := x.c.StateDir()
	return cluster.WhileStopped(dir, func() error {
		rt := x.runtime(true, "")
		if m, why := rt.Mode(); m != shared.ModeMember {
			return fmt.Errorf("this server cannot use the cluster's shared settings now (%s)", cmp.Or(why, m.Text()))
		}
		peers, err := x.peers(ctx, 0)
		if err != nil {
			return err
		}
		for _, p := range peers {
			if p.NodeID == x.self.NodeID && p.Live {
				return errors.New("this server's heartbeat still moves: stop it first")
			}
		}
		if err := x.confirm(fmt.Sprintf("Take %s out of the cluster and delete its copy of the cluster key?", x.self.Name), yes); err != nil {
			return err
		}
		rec, err := removeServer(ctx, rt, x.self.NodeID, x.self.Name, x.by, false)
		if err != nil {
			return err
		}
		x.audit("cluster.remove: this server left the cluster", "server", rec.Name)
		rotErr := x.rotateAfterRemove(ctx, rt, []string{x.self.NodeID}, rec.Name, noRotate)
		if err := forgetCluster(dir); err != nil {
			return fmt.Errorf("this server left the cluster, but its copy of the cluster key could not all be deleted: %w", err)
		}
		fmt.Fprintf(x.out, "%s left the cluster and deleted its copy of the cluster key. Uninstall it, or give it a new identity (signalith cluster new-identity) before you add it again.\n", rec.Name)
		return rotErr
	})
}

// forgetCluster deletes, in the state folder dir, the cluster key's
// copies and the copy of the shared settings. The HTTPS certificate is
// kept: it still comes from the cluster's certificate authority.
func forgetCluster(dir string) error {
	var errs []error
	paths := append(shared.ClusterKeyFiles(dir), shared.CachePath(dir))
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// newIdentity runs signalith cluster new-identity on a stopped server: a
// copy of another server's state folder (a cloned computer, a restored
// backup) becomes a server of its own, which then needs the cluster key
// again.
func newIdentity(dir string, out, errOut interface{ Write([]byte) (int, error) }, confirm func(string) error) error {
	return cluster.WhileStopped(dir, func() error {
		id, err := cluster.ReadIdentity(dir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("this server has no identity yet (no node.id in %s): it makes one when it starts", dir)
			}
			return err
		}
		if err := confirm(fmt.Sprintf("Give this server (%s, %s) a new identity? It forgets the cluster key and needs it again to rejoin.", id.Name, id.NodeID)); err != nil {
			return err
		}
		moved, err := cluster.ReplaceIdentity(dir, time.Now())
		if err != nil {
			return err
		}
		var errs []error
		for _, p := range []string{shared.NodeKeyPath(dir)} {
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
		}
		if err := forgetCluster(dir); err != nil {
			errs = append(errs, err)
		}
		if err := errors.Join(errs...); err != nil {
			return fmt.Errorf("node.id was moved to %s, but some of the old identity's keys could not be deleted: %w", moved, err)
		}
		fmt.Fprintf(out, "The old identity was moved to %s. The server makes a new one when it starts; give it the cluster key again to rejoin the cluster.\n", moved)
		return nil
	})
}
