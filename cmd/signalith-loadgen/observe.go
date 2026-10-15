package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// indexHealth is the health of the servers' own indices ({prefix}_*:
// settings, sessions, findings, cases, the cluster's records), not of the
// event indices. With one OpenSearch node gone they should be yellow
// (a copy missing), never red (no copy left). The nodes are asked in
// turn, each briefly, so a stopped node costs one short wait.
func (r *osReader) indexHealth(ctx context.Context) (string, error) {
	var last error
	start := int(r.cur.Load())
	for i := range r.urls {
		n := (start + i) % len(r.urls)
		var resp struct {
			Status string `json:"status"`
		}
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := r.doAt(c, r.urls[n], http.MethodGet, "/_cluster/health/"+r.prefix+"_*", nil, &resp)
		cancel()
		if err == nil {
			r.cur.Store(int64(n))
			return resp.Status, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return "", last
}

// sampleHealth asks OpenSearch every two seconds how the servers' own
// indices are, and counts the red answers and the times no node answered.
func (r *runner) sampleHealth(ctx context.Context) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		status, err := r.os.indexHealth(ctx)
		if ctx.Err() != nil {
			return
		}
		r.m.Add("opensearch_health_samples", 1)
		switch {
		case err != nil:
			r.m.Add("opensearch_unreachable_samples", 1)
		case status == "red":
			r.m.Add("opensearch_red_samples", 1)
		case status == "yellow":
			r.m.Add("opensearch_yellow_samples", 1)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// procStat is one process's CPU time and resident memory, read from
// /proc on Linux.
type procStat struct {
	cpu time.Duration
	rss int64
}

// clockTicks is USER_HZ, which Linux fixes at 100 on every architecture
// Signalith is built for.
const clockTicks = 100

func readProcStat(pid int) (procStat, error) {
	if runtime.GOOS != "linux" {
		return procStat{}, errors.New("process statistics need Linux")
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return procStat{}, err
	}
	return parseProcStat(string(b))
}

// parseProcStat reads utime, stime and rss from a /proc/<pid>/stat line.
// The command name in parentheses may hold spaces, so fields are counted
// from the last ")".
func parseProcStat(line string) (procStat, error) {
	i := strings.LastIndexByte(line, ')')
	if i < 0 {
		return procStat{}, errors.New("unexpected /proc stat line")
	}
	f := strings.Fields(line[i+1:])
	// After the name: state(3) ... utime(14) stime(15) ... rss(24); f[0]
	// is field 3.
	if len(f) < 22 {
		return procStat{}, errors.New("short /proc stat line")
	}
	ut, err1 := strconv.ParseInt(f[11], 10, 64)
	st, err2 := strconv.ParseInt(f[12], 10, 64)
	rss, err3 := strconv.ParseInt(f[21], 10, 64)
	if err := errors.Join(err1, err2, err3); err != nil {
		return procStat{}, err
	}
	return procStat{cpu: time.Duration(ut+st) * time.Second / clockTicks, rss: rss * int64(os.Getpagesize())}, nil
}

// procSampler measures the servers' processes while a phase runs: the
// CPU cores each used on average and the most memory each held.
type procSampler struct {
	pids map[string]int
	m    *Metrics
	read func(pid int) (procStat, error)
}

// phase samples until ctx ends and records, for phase, cpu_cores_<server>
// and memory_mb_<server>, and the busiest server's as server_cpu_cores
// and server_memory_mb.
func (p *procSampler) phase(ctx context.Context, phase string) {
	read := p.read
	if read == nil {
		read = readProcStat
	}
	type first struct {
		at  time.Time
		cpu time.Duration
	}
	starts := map[string]first{}
	var mu sync.Mutex
	sample := func(final bool) {
		for name, pid := range p.pids {
			st, err := read(pid)
			if err != nil {
				p.m.Add("proc_read_errors", 1)
				continue
			}
			mb := float64(st.rss) / (1 << 20)
			p.m.Set(phase, "memory_mb_"+name, mb)
			p.m.Set(phase, "server_memory_mb", mb)
			mu.Lock()
			f, ok := starts[name]
			if !ok {
				starts[name] = first{time.Now(), st.cpu}
			}
			mu.Unlock()
			if final && ok {
				if secs := time.Since(f.at).Seconds(); secs > 0 {
					cores := (st.cpu - f.cpu).Seconds() / secs
					p.m.Set(phase, "cpu_cores_"+name, cores)
					p.m.Set(phase, "server_cpu_cores", cores)
				}
			}
		}
	}
	sample(false)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			sample(true)
			return
		case <-tick.C:
			sample(false)
		}
	}
}

// parsePIDs reads "a=123,b=456" into server names and process IDs.
func parsePIDs(s string) (map[string]int, error) {
	out := map[string]int{}
	for _, part := range splitComma(s) {
		name, v, ok := strings.Cut(part, "=")
		pid, err := strconv.Atoi(strings.TrimSpace(v))
		if !ok || strings.TrimSpace(name) == "" || err != nil || pid <= 0 {
			return nil, fmt.Errorf("%q is not server=pid", part)
		}
		out[strings.TrimSpace(name)] = pid
	}
	return out, nil
}

// CheckResult is one check command's outcome.
type CheckResult struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Output string `json:"output,omitempty"`
}

// runChecks runs the scenario's checks in order.
func (r *runner) runChecks(ctx context.Context) {
	for _, c := range r.s.Checks {
		r.logf("check %s", c.Name)
		out, err := runShell(ctx, c.Cmd)
		res := CheckResult{Name: c.Name, Pass: err == nil, Output: truncate(strings.TrimSpace(out), 2000)}
		if err != nil && res.Output == "" {
			res.Output = err.Error()
		}
		r.report.Checks = append(r.report.Checks, res)
	}
}

// endState records how many servers, and how many Windows servers, are
// ready once the load is over.
func (r *runner) endState(ctx context.Context) {
	if len(r.admin) == 0 {
		return
	}
	v, ok := r.anyView(ctx)
	if !ok {
		return
	}
	ready, win := len(v.live()), len(v.windows())
	r.endReady, r.endWindows = &ready, &win
}

// wantsCriterion says whether the scenario checks any of names.
func (s *Scenario) wantsCriterion(names ...string) bool {
	for _, c := range s.Criteria {
		for _, n := range names {
			if c.Name == n {
				return true
			}
		}
	}
	return false
}
