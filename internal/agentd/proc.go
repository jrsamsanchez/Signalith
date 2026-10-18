package agentd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
)

// A collector the agent runs and keeps running.
//
// The loop starts it with the arguments and variables of its latest
// spec, says "starting" until it has stayed up for upAfter, then
// "running". When it stops by itself the loop starts it again after a
// pause that doubles each time it stops quickly (up to maxBackoff) and
// counts the restart; when its spec changes the loop stops it and starts
// it with the new one, which is not counted.
type proc struct {
	name string
	log  *slog.Logger
	now  func() time.Time
	// changed is told whenever the state changes, so the agent reports
	// at once.
	changed func()

	mu       sync.Mutex
	spec     *procSpec
	kick     chan struct{}
	state    string
	since    time.Time
	restarts int
	err      string
	version  string
	tail     *lineRing

	// procMu guards cmd, the process the loop started, while it runs.
	procMu sync.Mutex
	cmd    *exec.Cmd
}

// procSpec is how to run the collector; nil runs none.
type procSpec struct {
	Path string
	Args []string
	Env  []string
}

// Timings of the loop; tests make them shorter.
var (
	upAfter      = 5 * time.Second
	quickExit    = 30 * time.Second
	firstBackoff = time.Second
	maxBackoff   = time.Minute
	stopWait     = 10 * time.Second
	missingWait  = time.Minute
)

func newProc(name string, log *slog.Logger, now func() time.Time, changed func()) *proc {
	return &proc{name: name, log: log, now: now, changed: changed, kick: make(chan struct{}, 1),
		state: agentproto.StateOff, since: now(), tail: &lineRing{max: 20}}
}

// set gives the collector a new spec; the loop applies it.
func (p *proc) set(s *procSpec) {
	p.mu.Lock()
	p.spec = s
	p.mu.Unlock()
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// setVersion records the collector's version, for the status.
func (p *proc) setVersion(v string) {
	p.mu.Lock()
	p.version = v
	p.mu.Unlock()
}

func (p *proc) setState(state, err string) {
	p.mu.Lock()
	if p.state == state && p.err == err {
		p.mu.Unlock()
		return
	}
	p.state, p.err, p.since = state, err, p.now()
	p.mu.Unlock()
	if p.changed != nil {
		p.changed()
	}
}

// component is the collector as the agent reports it.
func (p *proc) component() agentproto.Component {
	p.mu.Lock()
	defer p.mu.Unlock()
	return agentproto.Component{Name: p.name, Version: p.version, State: p.state, Restarts: p.restarts,
		Since: p.since.UTC().Format(time.RFC3339), Error: p.err}
}

// stateNow returns the collector's state.
func (p *proc) stateNow() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

// run is the loop; it returns when ctx is done, with the collector
// stopped.
func (p *proc) run(ctx context.Context) {
	backoff := firstBackoff
	for {
		p.mu.Lock()
		spec := p.spec
		p.mu.Unlock()
		if spec == nil {
			p.setState(agentproto.StateOff, "")
			if !p.wait(ctx, 0) {
				return
			}
			continue
		}
		if _, err := os.Stat(spec.Path); err != nil {
			p.setState(agentproto.StateMissing, fmt.Sprintf("%s is not installed (%s); run the line from Add data > Signalith Agent again", p.name, spec.Path))
			if !p.wait(ctx, missingWait) {
				return
			}
			continue
		}
		started := p.now()
		exited, err := p.start(spec)
		if err != nil {
			p.setState(agentproto.StateFailed, "could not start: "+err.Error())
			if !p.wait(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		p.setState(agentproto.StateStarting, "")
		up := time.NewTimer(upAfter)
		running := true
		for running {
			select {
			case <-up.C:
				p.setState(agentproto.StateRunning, "")
			case err := <-exited:
				up.Stop()
				running = false
				ran := p.now().Sub(started)
				if ran >= quickExit {
					backoff = firstBackoff
				}
				p.mu.Lock()
				p.restarts++
				p.mu.Unlock()
				why := "it stopped"
				if err != nil {
					why = "it stopped: " + err.Error()
				}
				if t := p.tail.String(); t != "" {
					why += "\n" + t
				}
				p.log.Warn("a collector stopped; starting it again", "collector", p.name, "after", backoff, "err", err)
				p.setState(agentproto.StateFailed, why)
				if !p.wait(ctx, backoff) {
					return
				}
				backoff = min(backoff*2, maxBackoff)
			case <-p.kick:
				up.Stop()
				running = false
				p.stop(exited)
				backoff = firstBackoff
			case <-ctx.Done():
				up.Stop()
				p.stop(exited)
				return
			}
		}
	}
}

// wait waits for a new spec, d (0 for no end) or ctx; false when ctx is
// done.
func (p *proc) wait(ctx context.Context, d time.Duration) bool {
	var t <-chan time.Time
	if d > 0 {
		timer := time.NewTimer(d)
		defer timer.Stop()
		t = timer.C
	}
	select {
	case <-ctx.Done():
		return false
	case <-p.kick:
	case <-t:
	}
	return true
}

// start starts the collector; the channel gets its exit.
func (p *proc) start(s *procSpec) (chan error, error) {
	cmd := exec.Command(s.Path, s.Args...)
	cmd.Env = s.Env
	cmd.Stdin = nil
	setProcAttr(cmd)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	p.tail.reset()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p.log.Info("started a collector", "collector", p.name, "pid", cmd.Process.Pid)
	p.procMu.Lock()
	p.cmd = cmd
	p.procMu.Unlock()
	lines := make(chan struct{})
	go func() {
		defer close(lines)
		p.copyLines(out)
	}()
	exited := make(chan error, 1)
	go func() {
		<-lines
		err := cmd.Wait()
		p.procMu.Lock()
		p.cmd = nil
		p.procMu.Unlock()
		exited <- err
	}()
	return exited, nil
}

// stop asks the collector to stop, and kills it after stopWait.
func (p *proc) stop(exited chan error) {
	p.procMu.Lock()
	cmd := p.cmd
	p.procMu.Unlock()
	if cmd == nil || cmd.Process == nil {
		<-exited
		return
	}
	_ = askStop(cmd.Process)
	select {
	case <-exited:
	case <-time.After(stopWait):
		_ = cmd.Process.Kill()
		<-exited
	}
}

// copyLines passes on what the collector writes to the agent's log, and
// keeps its last lines for the status.
func (p *proc) copyLines(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		p.tail.add(line)
		fmt.Fprintf(os.Stderr, "[%s] %s\n", p.name, line)
	}
	// Whatever is left after a line too long to keep.
	_, _ = io.Copy(io.Discard, r)
}

// lineRing keeps the last max lines.
type lineRing struct {
	mu    sync.Mutex
	max   int
	lines []string
}

func (r *lineRing) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(s) > 500 {
		s = s[:500]
	}
	r.lines = append(r.lines, s)
	if len(r.lines) > r.max {
		r.lines = r.lines[len(r.lines)-r.max:]
	}
}

func (r *lineRing) reset() {
	r.mu.Lock()
	r.lines = nil
	r.mu.Unlock()
}

// String is the last lines, the newest last, up to 8 of them.
func (r *lineRing) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	l := r.lines
	if len(l) > 8 {
		l = l[len(l)-8:]
	}
	return strings.Join(l, "\n")
}
