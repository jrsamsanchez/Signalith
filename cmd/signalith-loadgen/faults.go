package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// FaultResult is what one fault did.
type FaultResult struct {
	Kind   string  `json:"kind"`
	Target string  `json:"target,omitempty"`
	Server string  `json:"server,omitempty"`
	At     float64 `json:"at_seconds"`
	// Skipped says why the fault was not run.
	Skipped string `json:"skipped,omitempty"`
	Error   string `json:"error,omitempty"`
	Output  string `json:"output,omitempty"`
	// Undone is when the fault was put right, from the start.
	Undone *float64 `json:"undone_seconds,omitempty"`
	// TakeoverSeconds is how long until another server ran the jobs, when
	// the fault hit the server that ran them.
	TakeoverSeconds *float64 `json:"takeover_seconds,omitempty"`
	NewLeader       string   `json:"new_leader,omitempty"`
}

// takeoverLimit is how long a takeover is waited for before it counts as
// not happening.
const takeoverLimit = 5 * time.Minute

// faults runs the scenario's faults on their timeline from start.
func (r *runner) faults(ctx context.Context, start time.Time) []FaultResult {
	out := make([]FaultResult, len(r.s.Faults))
	var wg sync.WaitGroup
	for i, f := range r.s.Faults {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				out[i] = FaultResult{Kind: f.Kind, Target: f.Target, At: f.At.D().Seconds(), Skipped: "the run ended first"}
				return
			case <-time.After(time.Until(start.Add(f.At.D()))):
			}
			out[i] = r.fault(ctx, f, start)
		}()
	}
	wg.Wait()
	return out
}

func (r *runner) fault(ctx context.Context, f Fault, start time.Time) FaultResult {
	res := FaultResult{Kind: f.Kind, Target: f.Target, At: time.Since(start).Seconds()}
	if signalFaults[f.Kind] && runtime.GOOS == "windows" {
		res.Skipped = "this fault stops processes with signals, which needs Linux"
		return res
	}
	leader := ""
	if f.Target != "" {
		server, wasLeader, err := r.resolveTarget(ctx, f.Target)
		if err != nil {
			res.Skipped = err.Error()
			return res
		}
		res.Server = server
		if wasLeader {
			leader = server
		}
	}
	r.logf("fault %s on %s", f.Kind, orNone(res.Server))
	if err := r.faultAction(ctx, f, f.Cmd, res.Server, false, &res); err != nil {
		res.Error = err.Error()
		return res
	}
	var wg sync.WaitGroup
	if leader != "" && (f.Kind == "kill9" || f.Kind == "stop" || f.Kind == "cut_opensearch") && r.cluster {
		wg.Add(1)
		go func() {
			defer wg.Done()
			took, by := r.waitTakeover(ctx, leader)
			secs := took.Seconds()
			res.TakeoverSeconds, res.NewLeader = &secs, by
			r.m.Set("", "takeover_seconds", secs)
		}()
	}
	if f.For > 0 {
		// Put right even if the run is stopped, so the lab is left working.
		select {
		case <-ctx.Done():
		case <-time.After(f.For.D()):
		}
		undo, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		if err := r.faultAction(undo, f, f.Undo, res.Server, true, &res); err != nil && res.Error == "" {
			res.Error = "undo: " + err.Error()
		}
		cancel()
		u := time.Since(start).Seconds()
		res.Undone = &u
	}
	wg.Wait()
	return res
}

func orNone(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// faultAction runs the fault's command, or turns the toxiproxy proxy off
// (or on again, to undo) when the scenario names no command.
func (r *runner) faultAction(ctx context.Context, f Fault, cmd, server string, undo bool, res *FaultResult) error {
	if cmd != "" {
		out, err := runShell(ctx, strings.ReplaceAll(cmd, "{server}", server))
		if s := strings.TrimSpace(out); s != "" {
			res.Output = truncate(strings.TrimSpace(res.Output+"\n"+s), 2000)
		}
		return err
	}
	if f.Kind == "cut_opensearch" && r.s.Toxiproxy.URL != "" {
		return toxiproxyEnabled(ctx, r.s.Toxiproxy, undo)
	}
	return nil
}

// runShell runs a command line with the system's shell.
func runShell(ctx context.Context, line string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.CommandContext(ctx, "cmd", "/C", line)
	} else {
		c = exec.CommandContext(ctx, "sh", "-c", line)
	}
	var buf bytes.Buffer
	c.Stdout, c.Stderr = &buf, &buf
	err := c.Run()
	if err != nil {
		err = fmt.Errorf("%q: %w", line, err)
	}
	return buf.String(), err
}

// toxiproxyEnabled turns a toxiproxy proxy on or off through its HTTP API.
func toxiproxyEnabled(ctx context.Context, t Toxiproxy, enabled bool) error {
	body := fmt.Sprintf(`{"enabled":%t}`, enabled)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(t.URL, "/")+"/proxies/"+t.Proxy, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("toxiproxy answered HTTP %d", resp.StatusCode)
	}
	return nil
}

// resolveTarget turns leader or standby into a server name; any other
// target is a server name already.
func (r *runner) resolveTarget(ctx context.Context, target string) (server string, leader bool, err error) {
	if target != "leader" && target != "standby" {
		v, ok := r.anyView(ctx)
		return target, ok && v.Lease.HolderName == target, nil
	}
	if !r.cluster {
		return "", false, fmt.Errorf("%s: not a cluster", target)
	}
	v, ok := r.anyView(ctx)
	if !ok {
		return "", false, fmt.Errorf("%s: no server answered GET /api/cluster", target)
	}
	if target == "leader" {
		if v.Lease.HolderName == "" {
			return "", false, fmt.Errorf("leader: no server runs the jobs")
		}
		return v.Lease.HolderName, true, nil
	}
	for _, name := range v.live() {
		if name != v.Lease.HolderName {
			return name, false, nil
		}
	}
	return "", false, fmt.Errorf("standby: no server is ready besides the leader")
}

// anyView is GET /api/cluster from the first target that answers.
func (r *runner) anyView(ctx context.Context) (clusterView, bool) {
	for _, s := range r.admin {
		var v clusterView
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := s.Do(c, http.MethodGet, "/api/cluster", nil, &v)
		cancel()
		if err == nil {
			return v, true
		}
	}
	return clusterView{}, false
}

// waitTakeover waits until a server other than old says it runs the
// jobs.
func (r *runner) waitTakeover(ctx context.Context, old string) (time.Duration, string) {
	start := time.Now()
	for time.Since(start) < takeoverLimit {
		for _, s := range r.admin {
			var v clusterView
			c, cancel := context.WithTimeout(ctx, 3*time.Second)
			err := s.Do(c, http.MethodGet, "/api/cluster", nil, &v)
			cancel()
			if err == nil && v.Lease.Mine && v.selfName() != old && v.selfName() != "" {
				return time.Since(start), v.selfName()
			}
		}
		select {
		case <-ctx.Done():
			return time.Since(start), ""
		case <-time.After(250 * time.Millisecond):
		}
	}
	return time.Since(start), ""
}

// sampleLeaders asks every target, once a second, whether it runs the
// jobs, and records the most that said so at the same moment.
func (r *runner) sampleLeaders(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		var mu sync.Mutex
		var wg sync.WaitGroup
		n := 0
		for _, s := range r.admin {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var v clusterView
				c, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				if s.Do(c, http.MethodGet, "/api/cluster", nil, &v) == nil && v.Lease.Mine {
					mu.Lock()
					n++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if ctx.Err() != nil {
			return
		}
		r.m.Add("leader_samples", 1)
		r.m.Set("", "leaders_at_once", float64(n))
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
