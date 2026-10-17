package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/lookuptables"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// Spreading detections over servers (detections.spread): every server
// that may run background work runs, per tenant, a second scheduler for
// the buckets assigned to it, and the server running the background jobs
// keeps the assignment. See internal/detect/spread.go.

const (
	// assignTick is how often the job holder brings each tenant's
	// assignment up to date, and followTick how often every server reads
	// it; a read stays good for the fence time (detect.DefaultFollowMaxAge).
	assignTick = 10 * time.Second
	followTick = 5 * time.Second
	// detPrintsAge is how long a tenant's detection files fingerprint is
	// kept before the files are hashed again.
	detPrintsAge = time.Minute
)

// detSpread is one tenant's part of spreading detections.
type detSpread struct {
	assigner *detect.Assigner
	follower *detect.Follower
	sched    *detect.Scheduler
	tenant   string
	prints   *detPrints
	// views, when set, lists the tenant's spread on the Servers page.
	views *detViews
	files func() string
}

// newDetSpread wires tenant's spreading. leader is the tenant's scheduler
// that runs on the job holder while nothing is spread, and spread a new
// one made like it, for the buckets assigned to this server. Both read
// and write the tenant's own runtime index, from which the follower reads
// the tenant's assignment only.
func newDetSpread(node *cluster.Node, rt *shared.Runtime, tenant string, eligible bool, leader, spread *detect.Scheduler, prints *detPrints, files func() string, log *slog.Logger) *detSpread {
	ds := &detSpread{sched: spread, tenant: tenant, prints: prints, files: files}
	ds.follower = &detect.Follower{Tenant: tenant, Self: node.ID(), Runtime: spread.Runtime, RuntimeIndex: spread.RuntimeIndex, Log: log}
	spread.Tenant, spread.Owned, spread.Moving = tenant, ds.follower.Owned, ds.follower.Moving
	spread.NodeID, spread.ClusterNow, spread.Epoch = node.ID(), node.ClusterNow, node.Lease().Epoch
	// A server cut off from the others stops running its buckets by
	// itself, as the job holder stops its jobs.
	spread.Allowed = func() bool { return eligible && node.HeartbeatFresh() }
	ds.assigner = &detect.Assigner{
		Tenant: tenant, Runtime: leader.Runtime, RuntimeIndex: leader.RuntimeIndex, Self: node.ID(),
		Lease: node.Lease().Epoch, Allowed: node.RunsJobs,
		On: func() bool { return leader.SpreadOn() && rt.DetectionEpochs() },
		Servers: func() []detect.SpreadServer {
			var out []detect.SpreadServer
			for _, s := range node.DetectionServers() {
				out = append(out, detect.SpreadServer{ID: s.NodeID, Spread: s.Spread, Eligible: s.Eligible, Live: s.Live,
					Fingerprint: s.Tenants[tenant], ClockOffsetMS: s.ClockOffsetMS, Released: s.Released[tenant]})
			}
			return out
		},
		Now: node.ClusterNow, Log: log, Resume: leader.Forget,
	}
	// The job holder's own scheduler runs the rules only while none are
	// spread.
	leader.Allowed = func() bool { return node.RunsJobs() && ds.assigner.LeaderRuns() }
	return ds
}

// follow reads the assignment and runs the assigned buckets until ctx
// ends, on a server that may run background work.
func (ds *detSpread) follow(ctx context.Context, jobs *sync.WaitGroup) {
	jobs.Go(func() { ds.follower.Run(ctx, followTick) })
	jobs.Go(func() { ds.sched.Start(ctx) })
	ds.publish(ctx, jobs)
	if ds.views != nil {
		ds.views.add(ctx, jobs, ds.tenant, func(ctx context.Context) (detect.SpreadView, error) {
			return detect.ReadSpread(ctx, ds.follower.Runtime, ds.follower.RuntimeIndex, ds.tenant)
		})
	}
}

// publish puts the tenant's fingerprint in the heartbeat while ctx lasts:
// only a server that follows the assignment and runs its buckets may be
// given some, so a tenant whose indices could not be made, or that
// stopped, gets none here.
func (ds *detSpread) publish(ctx context.Context, jobs *sync.WaitGroup) {
	e := ds.prints.set(ds.tenant, ds.files, ds.released)
	jobs.Go(func() {
		<-ctx.Done()
		ds.prints.drop(ds.tenant, e)
	})
}

// released is the tenant's buckets this server released, for the
// heartbeat.
func (ds *detSpread) released() map[int]int64 {
	if ds.follower == nil {
		return nil
	}
	return ds.follower.Released(ds.sched.BucketBusy)
}

// assign is the job holder's job keeping the assignment.
func (ds *detSpread) assign(ctx context.Context) { ds.assigner.Run(ctx, assignTick) }

// detPrints keeps, per tenant this server runs, the fingerprint of the
// files its detections use, for the heartbeat: the job holder gives a
// tenant's buckets only to servers whose fingerprint matches its own.
type detPrints struct {
	mu      sync.Mutex
	tenants map[string]*detPrint
}

type detPrint struct {
	// files returns the fingerprint of the tenant's files, and released
	// the buckets this server released.
	files    func() string
	released func() map[int]int64
	fp       string
	at       time.Time
}

func newDetPrints() *detPrints { return &detPrints{tenants: map[string]*detPrint{}} }

// set publishes tenant's fingerprint, worked out by files, and returns
// its entry for drop.
func (p *detPrints) set(tenant string, files func() string, released func() map[int]int64) *detPrint {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := &detPrint{files: files, released: released}
	p.tenants[tenant] = e
	return e
}

// drop takes tenant's fingerprint out while e, from set, is still it: a
// later start of the tenant set its own.
func (p *detPrints) drop(tenant string, e *detPrint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tenants[tenant] == e {
		delete(p.tenants, tenant)
	}
}

// released returns, per tenant, the buckets this server released and
// has not been told have moved on yet.
func (p *detPrints) released() map[string]map[int]int64 {
	p.mu.Lock()
	fns := map[string]func() map[int]int64{}
	for id, e := range p.tenants {
		if e.released != nil {
			fns[id] = e.released
		}
	}
	p.mu.Unlock()
	var out map[string]map[int]int64
	for id, fn := range fns {
		if r := fn(); len(r) > 0 {
			if out == nil {
				out = map[string]map[int]int64{}
			}
			out[id] = r
		}
	}
	return out
}

// all returns every tenant's fingerprint, hashing a tenant's files again
// once its last one is detPrintsAge old.
func (p *detPrints) all() map[string]string {
	p.mu.Lock()
	ids := make([]string, 0, len(p.tenants))
	for id := range p.tenants {
		ids = append(ids, id)
	}
	p.mu.Unlock()
	out := make(map[string]string, len(ids))
	for _, id := range ids {
		p.mu.Lock()
		e := p.tenants[id]
		if e == nil {
			p.mu.Unlock()
			continue
		}
		fp, files, fresh := e.fp, e.files, e.fp != "" && time.Since(e.at) < detPrintsAge
		p.mu.Unlock()
		if !fresh {
			fp = files()
			p.mu.Lock()
			if p.tenants[id] == e {
				e.fp, e.at = fp, time.Now()
			}
			p.mu.Unlock()
		}
		out[id] = fp
	}
	return out
}

// detFilesFingerprint hashes the files a tenant's detections use: its
// rules and their on and off choices, and its lookups folder, which holds
// its asset and identity lists, and lookup tables. A part kept in the shared settings is the shared sentinel
// instead, the same on every server.
func detFilesFingerprint(c *config.Config, rt *shared.Runtime, sharedOn, isDefault bool) string {
	sentinel := ""
	if sharedOn && rt != nil {
		if id := rt.Status().ClusterID; id != "" {
			sentinel = cluster.SharedFingerprint(id)
		}
	}
	rules := detectionsFingerprint(c.DetectionsDir())
	if isDefault && sentinel != "" && rt.SharedLibrary() {
		rules = sentinel
	}
	lookups := filesHash(c.LookupsDir(), lookuptables.Dir(c.LookupsDir()))
	if isDefault && sentinel != "" && rt.SharedLookups() {
		lookups = sentinel
	}
	return cluster.Hash([]byte(rules), []byte{0}, []byte(lookups))
}

// filesHash hashes the names and contents of the regular files directly
// in dirs, line ends made the same; each folder counts by its place in
// dirs, not its path, which differs between servers.
func filesHash(dirs ...string) string {
	var parts [][]byte
	for i, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil && !os.IsNotExist(err) {
			parts = append(parts, []byte("unreadable: "+err.Error()))
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.Type().IsRegular() {
				names = append(names, e.Name())
			}
		}
		slices.Sort(names)
		for _, n := range names {
			b, err := os.ReadFile(filepath.Join(dir, n))
			if err != nil {
				b = []byte("unreadable: " + err.Error())
			}
			b = bytes.ReplaceAll(bytes.TrimPrefix(b, []byte("\ufeff")), []byte("\r\n"), []byte("\n"))
			parts = append(parts, []byte(strconv.Itoa(i)+"/"+n), []byte{0}, b, []byte{0})
		}
	}
	return cluster.Hash(parts...)
}
