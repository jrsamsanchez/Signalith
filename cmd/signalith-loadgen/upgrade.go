// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// A rolling upgrade, as docs/servers.md tells an admin to do it: before
// each server, wait until the upgrade check says it is safe; drain the
// server it names next, install the new version (the fault's command),
// wait until the server is back on it, resume it, and go on with the next.

// upgradeLimit is how long one wait of an upgrade lasts at most: for the
// check to say it is safe, or for a server to come back on the new
// version. The install command has as long.
const upgradeLimit = 10 * time.Minute

// stateLimit is how long a drain or a resume is waited for.
const stateLimit = 2 * time.Minute

// UpgradeStep is one server's upgrade.
type UpgradeStep struct {
	Server string `json:"server"`
	From   string `json:"from"`
	To     string `json:"to,omitempty"`
	// Seconds is from the drain until the server was resumed.
	Seconds float64 `json:"seconds"`
	// Drained is false when the server could not be drained (a version
	// without drain), so it was upgraded while it took traffic.
	Drained bool   `json:"drained"`
	Error   string `json:"error,omitempty"`
	Output  string `json:"output,omitempty"`
}

// upgradeView is GET /api/cluster/upgrade, as signalith cluster
// upgrade-check -json prints it.
type upgradeView struct {
	Safe    bool `json:"safe"`
	Servers []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		State   string `json:"state"`
		Live    bool   `json:"live"`
		Jobs    bool   `json:"jobs"`
		NodeID  string `json:"node_id"`
		OS      string `json:"os"`
	} `json:"servers"`
	Blockers []struct {
		Server string `json:"server"`
		Text   string `json:"text"`
	} `json:"blockers"`
	Next string `json:"next"`
}

// blockers is the reasons the check gives for waiting, on one line.
func (v upgradeView) blockers() string {
	var out []string
	for _, b := range v.Blockers {
		out = append(out, b.Text)
	}
	if len(out) == 0 {
		return "no reason given"
	}
	return strings.Join(out, "; ")
}

// pick is the server to upgrade next of todo: the one the check names,
// else the first by name that does not run the jobs, else the first.
func (v upgradeView) pick(todo map[string]string) string {
	if _, ok := todo[v.Next]; ok {
		return v.Next
	}
	names := make([]string, 0, len(todo))
	for n := range todo {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		for _, s := range v.Servers {
			if s.Name == n && !s.Jobs {
				return n
			}
		}
	}
	return names[0]
}

// adminDo makes an admin request to the first target that answers.
func (r *runner) adminDo(ctx context.Context, method, path string, in, out any) error {
	err := errors.New("no admin credentials")
	for _, s := range r.admin {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = s.Do(c, method, path, in, out)
		cancel()
		if err == nil || statusOf(err) != 0 {
			return err
		}
	}
	return err
}

// upgradeAll upgrades every live server in turn and records each step in
// res. It stops at the first step that fails, as a person would.
func (r *runner) upgradeAll(ctx context.Context, f Fault, res *FaultResult) {
	if len(r.admin) == 0 {
		res.Skipped = "an upgrade needs credentials.admin_file"
		return
	}
	var first upgradeView
	if err := r.adminDo(ctx, http.MethodGet, "/api/cluster/upgrade", nil, &first); err != nil {
		res.Skipped = "GET /api/cluster/upgrade: " + err.Error()
		return
	}
	todo := map[string]string{}
	for _, s := range first.Servers {
		if s.Live && (f.Version == "" || s.Version != f.Version) {
			todo[s.Name] = s.Version
			res.ToUpgrade = append(res.ToUpgrade, s.Name)
		}
	}
	slices.Sort(res.ToUpgrade)
	for len(todo) > 0 && ctx.Err() == nil {
		v, err := r.waitSafe(ctx)
		if err != nil {
			res.Error = err.Error()
			return
		}
		name := v.pick(todo)
		step := r.upgradeOne(ctx, f, v, name, todo[name])
		delete(todo, name)
		res.Upgrades = append(res.Upgrades, step)
		if step.Error != "" {
			res.Error = name + ": " + step.Error
			return
		}
		r.m.Set("", "upgrade_server_seconds", step.Seconds)
	}
}

// waitSafe waits until the upgrade check says the next server may be
// upgraded.
func (r *runner) waitSafe(ctx context.Context) (upgradeView, error) {
	deadline := time.Now().Add(upgradeLimit)
	var last upgradeView
	var lastErr error
	for {
		var v upgradeView
		lastErr = r.adminDo(ctx, http.MethodGet, "/api/cluster/upgrade", nil, &v)
		if lastErr == nil {
			if v.Safe {
				return v, nil
			}
			last = v
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return v, fmt.Errorf("the upgrade check did not answer for %s: %w", upgradeLimit, lastErr)
			}
			return v, fmt.Errorf("not safe to upgrade for %s: %s", upgradeLimit, last.blockers())
		}
		select {
		case <-ctx.Done():
			return v, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// upgradeOne drains name, runs the install command, waits for the server
// to come back on a version other than from (f.Version when set) and
// resumes it.
func (r *runner) upgradeOne(ctx context.Context, f Fault, v upgradeView, name, from string) UpgradeStep {
	start := time.Now()
	step := UpgradeStep{Server: name, From: from}
	cmd, id := f.Cmd, ""
	for _, s := range v.Servers {
		if s.Name == name {
			id = s.NodeID
			if s.OS == "windows" && f.WindowsCmd != "" {
				cmd = f.WindowsCmd
			}
		}
	}
	r.logf("upgrade: draining %s", name)
	if id != "" {
		err := r.adminDo(ctx, http.MethodPost, "/api/cluster/servers/"+url.PathEscape(id)+"/drain", nil, nil)
		if err == nil {
			step.Drained = true
			if err := r.waitServer(ctx, name, stateLimit, func(state, _ string) bool { return state == "draining" }); err != nil {
				step.Error = "drain: " + err.Error()
				return step
			}
		} else {
			step.Output = "not drained: " + err.Error()
		}
	}
	r.logf("upgrade: installing on %s", name)
	out, err := runShellFor(ctx, strings.ReplaceAll(cmd, "{server}", name), upgradeLimit)
	if s := strings.TrimSpace(out); s != "" {
		step.Output = truncate(strings.TrimSpace(step.Output+"\n"+s), 2000)
	}
	if err != nil {
		step.Error = err.Error()
		return step
	}
	r.logf("upgrade: waiting for %s on the new version", name)
	err = r.waitServer(ctx, name, upgradeLimit, func(state, ver string) bool {
		if ver == "" || ver == from || (f.Version != "" && ver != f.Version) {
			return false
		}
		step.To = ver
		return state == "ready" || state == "draining"
	})
	if err != nil {
		step.Error = "not back on a new version: " + err.Error()
		return step
	}
	if step.Drained {
		r.logf("upgrade: resuming %s on %s", name, step.To)
		if err := r.adminDo(ctx, http.MethodPost, "/api/cluster/servers/"+url.PathEscape(id)+"/resume", nil, nil); err != nil {
			step.Error = "resume: " + err.Error()
			return step
		}
		if err := r.waitServer(ctx, name, stateLimit, func(state, _ string) bool { return state == "ready" }); err != nil {
			step.Error = "resume: " + err.Error()
			return step
		}
	}
	step.Seconds = time.Since(start).Seconds()
	return step
}

// waitServer waits up to limit until the list of servers shows name in a
// state and version ok accepts.
func (r *runner) waitServer(ctx context.Context, name string, limit time.Duration, ok func(state, version string) bool) error {
	deadline := time.Now().Add(limit)
	seen := "not listed"
	for {
		if v, answered := r.anyView(ctx); answered {
			for _, s := range v.Servers {
				if s.Name == name {
					seen = s.State + " on " + orNone(s.Version)
					if ok(s.State, s.Version) {
						return nil
					}
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("after %s it is %s", limit, seen)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
