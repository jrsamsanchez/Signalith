package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The content of the shared settings: the threat intel feed list and its
// status, and the retention policies. A member of the cluster takes them
// from OpenSearch (internal/clustercfg); any other server from its own
// files, as before. Which one is decided at each start of the
// components, and a change (this server founded or joined the cluster)
// restarts them in place.

// sharedContent links the shared settings' documents to the components
// of each start. Like the runtime, it belongs to the process.
type sharedContent struct {
	// sharedDocs are the documents of the shared settings: the content's
	// (docs) and the users' (auth, which are users.docs).
	sharedDocs
	// users links the users, the directory sign-in settings and the
	// sessions kept in the shared settings (see sharedusers.go).
	users *sharedUsers
	node  *cluster.Node
	log   *slog.Logger
	// cfg and target are the configuration and the OpenSearch client of
	// the start running now, which the importers read.
	cfg    atomic.Pointer[config.Config]
	target atomic.Pointer[osTarget]
	// on is true while the components running now take the content from
	// the shared settings.
	on atomic.Bool
	// drift lists the shared settings whose value in signalith.yaml
	// differs from the shared one.
	drift atomic.Pointer[[]string]
	// rt is the runtime, whose nodecfg document the importers record
	// this server's settings in.
	rt atomic.Pointer[shared.Runtime]
	// settingsOn is true while the components running now take the
	// settings of the Settings page from the shared settings, settings is
	// what the heartbeat says of them, and settingsKick wakes the follower
	// (see sharedsettings.go). followedNC and followedCluster are the
	// runtime's documents subscribed to, under followMu.
	settingsOn      atomic.Bool
	settings        atomic.Pointer[settingsState]
	settingsKick    chan struct{}
	followMu        sync.Mutex
	followedNC      *shared.Doc[shared.NodeCfg]
	followedCluster *shared.Doc[shared.ClusterBody]
	// applyMu keeps the changes of the files from being applied twice at
	// once: by a start, and before the next one (runner.applyFiles).
	applyMu sync.Mutex
}

type osTarget struct {
	cl     *store.Client
	prefix string
}

// newSharedContent returns the content's link for the process.
func newSharedContent(c *config.Config, node *cluster.Node, log *slog.Logger) *sharedContent {
	users := newSharedUsers(log)
	ct := &sharedContent{sharedDocs: newSharedDocs(users.docs), users: users, node: node, log: log, settingsKick: make(chan struct{}, 1)}
	ct.cfg.Store(c)
	return ct
}

// files is what the importers read: this server's files and settings.
func (ct *sharedContent) files() clustercfg.Files {
	return clustercfg.Files{
		Config: func() *config.Config { return ct.cfg.Load() },
		Node:   ct.node.Name(),
		NodeID: ct.node.ID(),
		Client: func() (*store.Client, string) {
			if t := ct.target.Load(); t != nil {
				return t.cl, t.prefix
			}
			return nil, ""
		},
		LeaseEpoch: ct.node.Lease().Epoch,
		Peers:      func() map[string]string { return retentionPeers(ct.node.Status(), time.Now()) },
		NodeCfg: func() *shared.Doc[shared.NodeCfg] {
			if rt := ct.rt.Load(); rt != nil {
				return rt.NodeCfg()
			}
			return nil
		},
		Log: ct.log,
	}
}

// use records the configuration and client of a start, before the
// runtime is pointed at them.
func (ct *sharedContent) use(c *config.Config, cl *store.Client) {
	if ct == nil {
		return
	}
	ct.cfg.Store(c)
	ct.target.Store(&osTarget{cl: cl, prefix: c.OpenSearch.IndexPrefix})
	// A component of the start that ended hears of no more changes.
	ct.reset()
}

// peerAge is how recent another server's heartbeat must be for its
// retention policies to count when the founder imports its own.
const peerAge = 7 * 24 * time.Hour

// retentionPeers lists the other servers' retention fingerprints from
// their heartbeats of the last 7 days, by name.
func retentionPeers(st cluster.Status, now time.Time) map[string]string {
	out := map[string]string{}
	for _, s := range st.Servers {
		if s.Self || s.Detail == nil || now.Sub(s.HeartbeatAt) > peerAge {
			continue
		}
		if fp := s.Detail.FilesFingerprint.Retention; fp != "" {
			out[s.Name] = fp
		}
	}
	return out
}

// heartbeatRetention reads the other servers' retention fingerprints
// from their heartbeats, for the command line, which has no node.
func heartbeatRetention(ctx context.Context, cl *store.Client, prefix, self string) map[string]string {
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	docs, err := cl.SearchDocs(rctx, cluster.RuntimeIndex(prefix), map[string]any{"term": map[string]any{"kind": "node"}})
	out := map[string]string{}
	if err != nil {
		return out
	}
	for _, d := range docs {
		var hb cluster.Heartbeat
		if json.Unmarshal(d.Source, &hb) != nil || hb.NodeID == "" || hb.NodeID == self || time.Since(hb.HeartbeatAt) > peerAge {
			continue
		}
		if fp := hb.FilesFingerprint.Retention; fp != "" {
			out[hb.Name] = fp
		}
	}
	return out
}

// sharedRetention makes ret enforce the shared retention policies: the
// page edits them on any member, and signalith.yaml reaches them only
// when it changes (applied when changed).
func (ct *sharedContent) sharedRetention(ret *retention.Manager) {
	ps := &clustercfg.PolicyStore{Docs: ct.docs, Log: ct.log}
	ret.Store, ret.Config, ret.Shared = ps, retention.Config{}, true
	ret.Hold, ret.ConfirmHold = ps.Hold, ps.Confirm
}

// sharedFeeds makes the feeds come from the shared feed list, with their
// status in the runtime index, and tells the other servers when this one
// wrote indicators. The status store's writer runs in jobs until ctx
// ends.
func (ct *sharedContent) sharedFeeds(ctx context.Context, f *intel.Feeds, indicators *intel.Store, cl *store.Client, prefix string, jobs *sync.WaitGroup) {
	f.List = nil
	f.Saved = &clustercfg.FeedList{Docs: ct.docs, Node: ct.node.Name()}
	st := &clustercfg.StatusStore{Client: cl, Index: cluster.RuntimeIndex(prefix), Node: ct.node.ID(),
		Leads: ct.node.RunsJobs, Epoch: ct.node.Lease().Epoch, Log: ct.log}
	f.StatusStore = st
	jobs.Go(func() { st.Run(ctx) })
	if indicators != nil {
		indicators.AfterWrite = func() { ct.bumpIntel(ctx) }
		ct.docs.OnIntel(indicators.Wake)
	}
}

// bumpIntel tells the other servers that this one wrote indicators, in
// the background.
func (ct *sharedContent) bumpIntel(ctx context.Context) {
	h := ct.docs.Hub()
	if h == nil {
		return
	}
	go func() {
		bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if _, err := h.Bump(bctx, "intel"); err != nil {
			ct.log.Debug("could not tell the other servers that threat intel indicators changed; they reload within a minute", "err", err)
		}
	}()
}

// apply applies the values of signalith.yaml that changed since this
// server's previous start to the shared settings, once it can, and keeps
// the drift for the heartbeat.
func (ct *sharedContent) apply(ctx context.Context, rt *shared.Runtime, c *config.Config) {
	ct.drift.Store(nil)
	for {
		if rt.Writable() == nil {
			ct.applyMu.Lock()
			res, err := clustercfg.Apply(ctx, rt, ct.docs, c, ct.node.Name(), ct.log)
			ct.applyMu.Unlock()
			if err == nil {
				ct.drift.Store(&res.Drift)
				return
			}
			if ctx.Err() != nil {
				return
			}
			ct.log.Warn("could not apply the changes to signalith.yaml to the shared settings; trying again", "err", err)
		}
		d := clustercfg.Drift(ct.docs, c)
		ct.drift.Store(&d)
		select {
		case <-ctx.Done():
			return
		case <-time.After(applyRetry):
		}
	}
}

// applyRetry is how long apply waits before it tries again.
var applyRetry = 30 * time.Second

// settingsDrift is the drift for the heartbeat.
func (ct *sharedContent) settingsDrift() map[string][]string {
	if ct == nil || !ct.on.Load() {
		return nil
	}
	d := ct.drift.Load()
	if d == nil || len(*d) == 0 {
		return nil
	}
	return map[string][]string{"yaml": *d}
}

// sharedFingerprints puts the shared sentinel in place of the retention
// and feed fingerprints of a member that takes them from the shared
// settings, and of the users' once those are shared too: two members
// always agree on them, and a server that keeps them in its own files
// never agrees with a member.
func sharedFingerprints(fp cluster.Fingerprints, rt *shared.Runtime, on bool) cluster.Fingerprints {
	if !on || rt == nil {
		return fp
	}
	if id := rt.Status().ClusterID; id != "" {
		for _, put := range sharedPrints {
			put(&fp, rt, cluster.SharedFingerprint(id))
		}
	}
	return fp
}

// sharedPrints put the shared sentinel s in place of the fingerprints of
// one feature, when rt takes it from the shared settings. A new shared
// feature appends its entry here.
var sharedPrints = []func(fp *cluster.Fingerprints, rt *shared.Runtime, s string){
	// The retention policies and the feeds come with the content.
	func(fp *cluster.Fingerprints, _ *shared.Runtime, s string) { fp.Retention, fp.Feeds = s, s },
	// The users, once they are shared too.
	func(fp *cluster.Fingerprints, rt *shared.Runtime, s string) {
		if rt.SharedUsers() {
			fp.Users = s
		}
	},
	// Append a new shared feature's entry here.
}

// contentHandlers runs the requests of the content on the server that
// runs the background jobs: a feed download asked on another server, and
// a retention run. A new shared feature appends its handlers to the list,
// each with its own request types.
func contentHandlers(feeds *intel.Feeds, ret *retention.Manager, archives map[string]shared.Handler) map[string]shared.Handler {
	out := map[string]shared.Handler{}
	for _, hs := range []map[string]shared.Handler{
		feedHandlers(feeds),
		retentionHandlers(ret),
		// Restores of shared archives (sharedaudit.go), nil until they
		// are shared.
		archives,
		// Append a new shared feature's handlers here.
	} {
		for k := range hs {
			if _, dup := out[k]; dup {
				// Two features naming one request type would leave one
				// of them silently unrun.
				panic("shared request type " + k + " has two handlers")
			}
		}
		maps.Copy(out, hs)
	}
	return out
}

// feedHandlers runs a feed download asked on another server.
func feedHandlers(feeds *intel.Feeds) map[string]shared.Handler {
	return map[string]shared.Handler{
		clustercfg.RequestFeedRefresh: func(ctx context.Context, req *shared.Request) error {
			var a clustercfg.FeedRefreshArgs
			if err := json.Unmarshal(req.Args, &a); err != nil || a.Feed == "" {
				return errors.New("the request does not name a feed")
			}
			st, err := feeds.Refresh(ctx, a.Feed)
			if errors.Is(err, intel.ErrFeedRunning) {
				// Its status is the download before; the page says the
				// download is still going instead.
				return req.SetResult(map[string]bool{"already_running": true})
			}
			if err != nil {
				return err
			}
			return req.SetResult(st)
		},
	}
}

// retentionHandlers runs a retention run asked on any server.
func retentionHandlers(ret *retention.Manager) map[string]shared.Handler {
	return map[string]shared.Handler{
		clustercfg.RequestRetentionRun: func(ctx context.Context, req *shared.Request) error {
			var a clustercfg.RetentionRunArgs
			if len(req.Args) > 0 {
				if err := json.Unmarshal(req.Args, &a); err != nil {
					return fmt.Errorf("the request's arguments cannot be read: %w", err)
				}
			}
			trigger := retention.TriggerManual
			if a.Trigger == retention.TriggerChange {
				trigger = retention.TriggerChange
			}
			res, err := ret.ApplySoon(trigger, req.RequestedBy)
			if err != nil {
				return err
			}
			return req.SetResult(map[string]string{"result": res})
		},
	}
}

// liveMaxAge keeps the event age the pipeline and the syslog receiver
// accept in step with the retention policies, which may change on any
// server while they run.
type liveMaxAge struct {
	c        *config.Config
	ret      *retention.Manager
	pipeline interface{ SetMaxEventAge(time.Duration) }
	receiver interface{ SetMaxAge(time.Duration) }
	mu       sync.Mutex
	last     time.Duration
}

// Use works the age out again with c, the configuration in use after
// ingest.max_event_age was changed (api.EventAge).
func (l *liveMaxAge) Use(c *config.Config) {
	l.mu.Lock()
	l.c = c
	l.mu.Unlock()
	l.update(nil)
}

// update works the age out again from s, or from the policies in use when
// s is nil.
func (l *liveMaxAge) update(s *retention.Settings) {
	if s == nil {
		cur, err := l.ret.Settings()
		if err != nil {
			return
		}
		s = &cur
	}
	l.mu.Lock()
	d := l.c.MaxEventAge(s.ShortestKeepDays())
	same := d == l.last
	l.last = d
	l.mu.Unlock()
	if same {
		return
	}
	if l.pipeline != nil {
		l.pipeline.SetMaxEventAge(d)
	}
	if l.receiver != nil {
		l.receiver.SetMaxAge(d)
	}
}

// sharedAPI is the shared configuration as the API uses it (api.Shared),
// for the components of one start: on says whether they take their
// content from the shared settings.
type sharedAPI struct {
	rt *shared.Runtime
	on bool
}

func (a sharedAPI) Content() bool   { return a.on }
func (a sharedAPI) Writable() error { return a.rt.Writable() }

func (a sharedAPI) Submit(ctx context.Context, typ string, args any, by string) (*shared.Request, error) {
	return a.rt.Requests().Submit(ctx, typ, shared.TargetLeader, args, by)
}

func (a sharedAPI) Request(ctx context.Context, id string) (*shared.Request, bool, error) {
	return a.rt.Requests().Get(ctx, id)
}

// configToken is how far this server has read the shared settings
// (api.ConfigToken), from the runtime's hub of the moment.
type configToken struct{ rt *shared.Runtime }

func (t configToken) Token() string               { return t.rt.Hub().Token() }
func (t configToken) Written() int64              { return t.rt.Hub().Written() }
func (t configToken) TokenAfter(seq int64) string { return t.rt.Hub().TokenAfter(seq) }
func (t configToken) Wait(ctx context.Context, min string) bool {
	return t.rt.Hub().Wait(ctx, min)
}
