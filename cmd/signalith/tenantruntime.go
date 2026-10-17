package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/content"
	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/lookuptables"
	"github.com/jrsamsanchez/signalith/internal/notebooks"
	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/playbooks"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/risk"
	"github.com/jrsamsanchez/signalith/internal/sample"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/tenants"
)

// tenantRuntime runs the data of each tenant other than the default one
// (api.TenantRuntime): a server of its own per tenant, built from the
// tenant's config (config.ForTenant), so every store, index and folder it
// uses is the tenant's. The default tenant's server sends a tenant's
// requests on to it. Its users, sessions and certificate are the default
// tenant's server's, which sign everyone in.
type tenantRuntime struct {
	r     *runner
	c     *config.Config
	cl    *store.Client
	reg   *tenants.Registry
	front *api.Server
	ctx   context.Context
	log   *slog.Logger
	// leader reports whether this server runs the background jobs now,
	// and sharedOK, set while the users are shared, whether the cluster
	// keeps tenants (shared.LevelTenants).
	leader   func() bool
	sharedOK func() bool
	// limits are the ingest slots and receive budget the default tenant's
	// pipeline uses, which every tenant's pipeline shares.
	limits *ingest.Limits

	// changing makes Changed one at a time; mu guards running, which
	// requests read while a tenant starts.
	changing sync.Mutex
	mu       sync.Mutex
	running  map[string]*tenantInstance
	stopped  bool

	// listErr is the last problem logged by startAll's loop, so each is
	// logged once.
	listErr string
}

// tenantInstance is one tenant's running server.
type tenantInstance struct {
	srv    *api.Server
	cancel context.CancelFunc
	jobs   sync.WaitGroup
}

func newTenantRuntime(ctx context.Context, r *runner, c *config.Config, cl *store.Client, reg *tenants.Registry, front *api.Server, limits *ingest.Limits) *tenantRuntime {
	t := &tenantRuntime{r: r, c: c, cl: cl, reg: reg, front: front, ctx: ctx, log: r.log, limits: limits, running: map[string]*tenantInstance{}}
	t.leader = func() bool { return r.node == nil || r.node.RunsJobs() }
	return t
}

// startAll starts every tenant that is not turned off. One that cannot
// start is logged and left stopped: its users' requests are refused.
func (t *tenantRuntime) startAll() {
	t.reconcile()
	if t.sharedOK == nil {
		return
	}
	// In a cluster the list is shared: follow what other servers change
	// in it.
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-tick.C:
		}
		t.reconcile()
	}
}

// reconcile runs the tenants that are on, and stops those turned off or
// gone.
func (t *tenantRuntime) reconcile() {
	list, err := t.reg.List()
	if err != nil {
		if fmt.Sprint(err) != t.listErr {
			t.log.Error("the list of tenants cannot be read; no tenant's data can be used until it is fixed", "file", t.reg.Path, "err", err)
		}
		t.listErr = fmt.Sprint(err)
		return
	}
	t.listErr = ""
	want := map[string]bool{}
	for _, tn := range list {
		if !tn.Disabled {
			want[tn.ID] = true
		}
	}
	t.mu.Lock()
	var change []string
	for id := range t.running {
		if !want[id] {
			change = append(change, id)
		}
	}
	for id := range want {
		if t.running[id] == nil {
			change = append(change, id)
		}
	}
	t.mu.Unlock()
	for _, id := range change {
		if err := t.Changed(t.ctx, id); err != nil {
			t.log.Error("could not start a tenant", "tenant", id, "err", err)
		}
	}
}

// Ready says why this server cannot run tenants now: while servers share
// their users, tenants run on the one that runs the background jobs, and
// only once every server reads tenants. Tenants' requests and agents are
// refused on the others, and on a server that lost the job lease, rather
// than answered with data it no longer keeps up to date.
func (t *tenantRuntime) Ready() error {
	if t.sharedOK == nil {
		return nil
	}
	if !t.sharedOK() {
		return clusterauth.ErrTenantUsers
	}
	if !t.leader() {
		return errors.New("tenants run on the server that runs the background jobs; use that one")
	}
	return nil
}

func (t *tenantRuntime) Server(id string) *api.Server {
	if t.Ready() != nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if ti := t.running[id]; ti != nil {
		return ti.srv
	}
	return nil
}

// Servers returns every tenant server running here, also while another
// server runs the tenants (Ready): their agent tokens tell this server
// which tenant an agent is of.
func (t *tenantRuntime) Servers() []*api.Server {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*api.Server, 0, len(t.running))
	for _, ti := range t.running {
		out = append(out, ti.srv)
	}
	return out
}

// Changed starts tenant id when it exists and is on, and stops it when
// it is turned off or gone.
func (t *tenantRuntime) Changed(_ context.Context, id string) error {
	tn, err := t.reg.Get(id)
	if err != nil && !errors.Is(err, tenants.ErrNotFound) {
		return err
	}
	want := err == nil && !tn.Disabled
	t.changing.Lock()
	defer t.changing.Unlock()
	t.mu.Lock()
	cur, stopped := t.running[id], t.stopped
	if !want && cur != nil {
		// Its requests are refused from now on.
		delete(t.running, id)
	}
	t.mu.Unlock()
	switch {
	case stopped:
		return errors.New("Signalith is stopping")
	case want && cur == nil:
		ti, err := t.start(id)
		if err != nil {
			return err
		}
		t.mu.Lock()
		if t.stopped {
			t.mu.Unlock()
			ti.stop()
			return errors.New("Signalith is stopping")
		}
		t.running[id] = ti
		t.mu.Unlock()
		// A change applied while it started.
		ti.srv.FollowLive(t.front.Running())
		t.log.Info("tenant started", "tenant", id)
	case !want && cur != nil:
		cur.stop()
		t.log.Info("tenant stopped", "tenant", id)
	}
	return nil
}

// SettingsChanged has every running tenant's server follow the settings
// the default tenant's server applied at once.
// NotebookStores returns a store of hunting notebooks for each tenant in
// the list, turned off ones too: a deleted provider user's notebooks are
// released in all of them.
func (t *tenantRuntime) NotebookStores() map[string]notebooks.Store {
	list, err := t.reg.List()
	if err != nil {
		t.log.Warn("could not list the tenants to release a deleted user's hunting notebooks", "err", err)
		return nil
	}
	front := t.front.Running()
	out := make(map[string]notebooks.Store, len(list))
	for _, tn := range list {
		if tn.ID == tenants.Default {
			continue
		}
		out[tn.ID] = notebooks.NewOpenSearch(t.cl, front.ForTenant(tn.ID).OpenSearch.IndexPrefix)
	}
	return out
}

func (t *tenantRuntime) SettingsChanged() {
	t.mu.Lock()
	list := make([]*tenantInstance, 0, len(t.running))
	for _, ti := range t.running {
		list = append(list, ti)
	}
	t.mu.Unlock()
	front := t.front.Running()
	for _, ti := range list {
		ti.srv.FollowLive(front)
	}
}

// stop stops every tenant, and starts none after.
func (t *tenantRuntime) stop() {
	t.mu.Lock()
	t.stopped = true
	list := t.running
	t.running = map[string]*tenantInstance{}
	t.mu.Unlock()
	for _, ti := range list {
		ti.stop()
	}
}

func (ti *tenantInstance) stop() {
	ti.cancel()
	ti.jobs.Wait()
}

// start builds tenant id's server, as runner.start builds the default
// tenant's, from the tenant's own config. What a tenant cannot have yet
// is left out (see docs/multi-tenant.md): syslog, Microsoft 365,
// vulnerability scans, network sensors, osquery, content updates and
// the shared settings of a cluster.
func (t *tenantRuntime) start(id string) (*tenantInstance, error) {
	if err := tenants.ValidID(id); err != nil {
		return nil, err
	}
	// The settings in use now, with those applied at once since start.
	c := t.front.Running().ForTenant(id)
	cl := t.cl
	log := t.log.With("tenant", id)
	prefix := c.OpenSearch.IndexPrefix
	for _, d := range []string{t.c.TenantDir(id), c.LookupsDir(), c.DetectionsDir(), c.DashboardsDir()} {
		if err := securefile.MkdirPrivate(d); err != nil {
			return nil, fmt.Errorf("tenant %s: %w", id, err)
		}
	}
	ctx, cancel := context.WithCancel(t.ctx)
	ti := &tenantInstance{cancel: cancel}
	ok := false
	defer func() {
		if !ok {
			ti.stop()
		}
	}()

	ret := newRetention(c, cl, log)
	archiveCrypto(ret.Archive, c, t.r.clusterKey)
	maxAge := c.MaxEventAge(retentionKeepDays(ret))
	pipeline := &ingest.Pipeline{Store: cl, Prefix: prefix, MaxEventAge: maxAge, Limits: t.limits, Tenant: id, Log: log}
	pipeline.SetURLQuery(c.URLQueryMode())
	pipeline.Servers = func() int { return t.r.node.IndexingServers(10 * time.Minute) }
	pipeline.FieldCount = ingest.MappingFieldCount(cl)
	// The custom parsers are the provider's, saved on the default
	// tenant's Add data page: they read every tenant's records alike.
	if t.front.Parsers != nil {
		pipeline.Custom = t.front.Parsers
	}
	live := &liveMaxAge{c: c, ret: ret, pipeline: pipeline, last: maxAge}
	ret.OnSettings = func(s retention.Settings) { live.update(&s) }

	eng := newEngine(c, cl)
	lists, err := assets.OpenStore(c.LookupsDir())
	if err != nil {
		log.Error("asset or identity list has errors; using empty lists until it is fixed", "err", err)
	}
	eng.Assets = lists
	ti.jobs.Go(func() { reloadLookups(ctx, lists, log) })
	tables, err := lookuptables.Open(lookuptables.Dir(c.LookupsDir()))
	if err != nil {
		log.Error("some lookup tables could not be read and are left out", "err", err)
	}
	eng.Lookups = tables
	sumBuilder := newSummaries(ctx, c, cl, eng, ret, log, ti.jobs.Go)
	ibackend := intel.NewOpenSearch(cl, prefix)
	ibackend.Replicas = c.OpenSearch.Replicas.IndexSettings()
	indicators := intel.NewStore(ibackend)
	eng.Intel = indicators
	feeds := newFeeds(c, indicators, log)
	if err := feeds.Load(); err != nil {
		log.Error("threat intel feeds cannot be used until the file is fixed", "err", err)
	}
	// The built-in detections, and the tenant's own. Content updates
	// are installed for the default tenant only, for now.
	updater := &content.Updater{Dir: filepath.Join(c.DetectionsDir(), "content"), Log: log}
	lib, problems, err := detect.NewLibrary(c.DetectionsDir())
	if err != nil {
		return nil, err
	}
	updater.Library = lib
	for _, p := range problems {
		log.Error("detection skipped", "err", p)
	}
	boards, err := dashboards.NewStore(c.DashboardsDir())
	if err != nil {
		return nil, fmt.Errorf("tenant %s dashboards: %w", id, err)
	}
	fstore := findings.NewOpenSearch(cl, prefix)
	fstore.Replicas = c.OpenSearch.Replicas.IndexSettings()
	cstore := cases.NewOpenSearch(cl, prefix)
	cstore.Replicas = c.OpenSearch.Replicas.IndexSettings()
	nstore := notebooks.NewOpenSearch(cl, prefix)
	nstore.Replicas = c.OpenSearch.Replicas.IndexSettings()
	estore := endpoint.NewStore(cl, prefix)
	ti.jobs.Go(func() { estore.Run(ctx, 30*time.Second) })
	notes, deliveries, senders := newNotify(c, cl, log)
	if err := notes.Load(); err != nil {
		log.Error("notifications are not sent until the notifications file is fixed", "err", err)
	}
	runtimeIndex := cluster.RuntimeIndex(prefix)
	sched := &detect.Scheduler{
		Library: lib, Engine: eng, Findings: fstore, Log: log,
		Risk: &risk.Store{Client: cl, Prefix: prefix}, Assets: lists,
		MaxFindingsPerRun: c.Detections.MaxFindingsPerRun,
		Runtime:           cl, RuntimeIndex: runtimeIndex,
	}
	sched.SetCatchUp(c.DetectionsCatchUp())
	server, nodeID := "", ""
	if t.r.node != nil {
		server, nodeID = t.r.node.Name(), t.r.node.ID()
	}
	sampleLoader := &sample.Loader{
		Prefix: prefix, Bulk: cl, OS: cl, Docs: cl, Intel: indicators, Assets: lists, Library: lib, Engine: eng,
		Findings: fstore, Cases: cstore, Risk: &risk.Store{Client: cl, Prefix: prefix},
		Server: server, NodeID: nodeID, URLQuery: pipeline.URLQuery, Log: log,
	}
	ti.jobs.Go(func() { sampleLoader.WatchLists(ctx, time.Minute) })
	dispatcher := &notify.Dispatcher{
		Settings: notes, Findings: fstore, Deliveries: deliveries, Sender: senders, Server: server, Log: log,
		PublicURL: func() string { return c.Server.PublicURL },
	}
	astore := respond.NewOpenSearch(cl, prefix)
	astore.Replicas = c.OpenSearch.Replicas.IndexSettings()
	// No Directory: the directory of the Users page is the provider's, and
	// a tenant's response actions must never change its accounts.
	responder := &respond.Runner{
		Actions:    &respond.Actions{File: c.ResponseFile(), Log: log},
		ScriptsDir: c.ResponseScriptsDir(),
		Store:      astore,
		Server:     server,
		Log:        log,
	}
	if p := intel.ProtectedAddr(c.OpenSearch.URL); p != "" {
		responder.Protected = []string{p}
	}
	ensureScriptsDir(c.ResponseScriptsDir(), log)
	pbooks := &playbooks.Manager{File: c.PlaybooksFile()}
	if err := pbooks.Load(); err != nil {
		log.Error("playbooks do not start until the playbooks file is fixed", "err", err)
	}
	pruns := playbooks.NewOpenSearch(cl, prefix)
	pruns.Replicas = c.OpenSearch.Replicas.IndexSettings()
	// The tenant's agent tokens, in its own runtime index: no token of the
	// default tenant's or another tenant's is accepted for its data.
	tokens := &agenttokens.Registry{Client: cl, Prefix: prefix, Log: log, Node: func() string { return nodeID }}
	tokens.OnRevoke(estore.RevokeToken)
	// The tokens in signalith.yaml and the environment are the default
	// tenant's; set before the first load, so the server never sets it.
	tokens.Legacy = func() []agenttokens.Legacy { return nil }
	{
		lctx, lcancel := context.WithTimeout(ctx, 5*time.Second)
		if err := tokens.Load(lctx); err != nil {
			log.Warn("agent tokens could not be read from OpenSearch yet; agents that send with one are asked to send again until they are", "err", err)
		}
		lcancel()
	}
	ti.jobs.Go(func() { tokens.Run(ctx) })
	front := t.front
	agentsInv := &agentinv.Inventory{Client: cl, Prefix: prefix, Log: log,
		Node: func() string { return nodeID }, Server: func() string { return server },
		ServerCA: func() string {
			if front.TLS == nil || !c.Server.HTTPS() {
				return ""
			}
			return agentinv.Pin(front.TLS.Fingerprint())
		},
		Leader: t.leader}
	ti.jobs.Go(func() { agentsInv.Run(ctx) })

	srv := &api.Server{
		Config:     c,
		Tokens:     tokens,
		Agents:     agentsInv,
		Engine:     eng,
		Pipeline:   pipeline,
		EventAge:   live,
		Backend:    cl,
		Detections: lib,
		Scheduler:  sched,
		Findings:   fstore,
		Assets:     lists,
		Intel:      indicators,
		Feeds:      feeds,
		Notify:     &api.Notify{Settings: notes, Deliveries: deliveries, Sender: senders, Server: server},
		Dashboards: boards,
		Cases:      cstore,
		Notebooks:  nstore,
		Respond:    responder,
		Playbooks:  &api.Playbooks{Manager: pbooks, Runs: pruns},
		Retention:  ret,
		Sample:     sampleLoader,
		Content:    updater,
		Endpoints:  estore,
		Background: front.Background,
		Assistant:  newAssistant(c),
		// The provider's users and sessions: everyone signs in on the
		// default tenant's server, which hands a tenant's requests on.
		Users:         front.Users,
		Directory:     front.Directory,
		TLS:           front.TLS,
		Sessions:      front.Sessions,
		SessionStore:  front.SessionStore,
		KnownBrowsers: front.KnownBrowsers,
		Limiter:       front.Limiter,
		Started:       front.Started,
		Tenants:       t.reg,
		TenantID:      id,
		Log:           log,
		Version:       front.Version,
	}
	srv.Handler()
	pbRunner := &playbooks.Runner{
		Playbooks: pbooks, Findings: fstore, Runs: pruns, Desk: srv.PlaybookDesk(), Respond: responder,
		Notify: notes, Sender: senders, Deliveries: deliveries, Server: server, Log: log,
		PublicURL: func() string { return c.Server.PublicURL },
	}
	if t.r.node != nil {
		ret.Leader = func() (bool, string) { return t.r.node.RunsJobs(), t.r.node.JobHolder() }
		ret.Fence = t.r.node.Check
		sched.Allowed, feeds.Allowed, dispatcher.Allowed, pbRunner.Allowed = t.r.node.RunsJobs, t.r.node.RunsJobs, t.r.node.RunsJobs, t.r.node.RunsJobs
		sched.Epoch, sched.NodeID, sched.ClusterNow = t.r.node.Lease().Epoch, t.r.node.ID(), t.r.node.ClusterNow
		sumBuilder.Allowed, sumBuilder.Epoch, sumBuilder.Node, sumBuilder.Now = t.r.node.RunsJobs, t.r.node.Lease().Epoch, t.r.node.ID(), t.r.node.ClusterNow
	}
	if t.sharedOK != nil && ret.Archive != nil {
		// A tenant's archive folder is in this server's state folder,
		// which a server running the tenants after it would not see:
		// days to archive are kept until tenants' archives can be shared.
		ret.CanArchive = func() (bool, string) {
			return false, "a tenant's events are not archived while servers share their settings"
		}
	}

	// The tenant's index template and indices, then its background jobs
	// while this server runs the default tenant's.
	ti.jobs.Go(func() {
		if !ensureTemplate(ctx, cl, c, log) {
			return
		}
		ti.jobs.Go(func() { keepTemplate(ctx, cl, c, log) })
		intelOK := ibackend.EnsureIndex(ctx) == nil
		if intelOK {
			ti.jobs.Go(func() { indicators.Watch(ctx, time.Minute, log) })
		}
		findingsOK := fstore.EnsureIndex(ctx) == nil
		notifyOK := deliveries.EnsureIndex(ctx) == nil
		playbooksOK := pruns.EnsureIndex(ctx) == nil
		for _, e := range []interface{ EnsureIndex(context.Context) error }{cstore, nstore, estore, astore} {
			if err := e.EnsureIndex(ctx); err != nil {
				log.Error("could not create an index of the tenant", "err", err)
			}
		}
		if !intelOK || !findingsOK || !notifyOK || !playbooksOK {
			log.Error("could not create the tenant's indices; its detections, feeds, notifications and playbooks do not run until it is started again")
			return
		}
		runWhileLeader(ctx, t.leader, []cluster.Job{
			{Name: "summaries", Run: sumBuilder.Run},
			{Name: "detections", Run: sched.Start},
			{Name: "threat intel feeds", Run: feeds.Start},
			{Name: "notifications", Run: dispatcher.Run},
			{Name: "playbooks", Run: pbRunner.Run},
			{Name: "retention", Run: func(ctx context.Context) {
				ret.Start(ctx)
				ret.Wait()
			}},
		})
	})
	ti.srv = srv
	ok = true
	return ti, nil
}

// runWhileLeader runs jobs while leader reports true, and stops them when
// it reports false or ctx ends. It returns once they stopped.
func runWhileLeader(ctx context.Context, leader func() bool, jobs []cluster.Job) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var stop context.CancelFunc
	var wg sync.WaitGroup
	begin := func() {
		jctx, cancel := context.WithCancel(ctx)
		stop = cancel
		for _, j := range jobs {
			wg.Go(func() { j.Run(jctx) })
		}
	}
	end := func() {
		if stop != nil {
			stop()
			wg.Wait()
			stop = nil
		}
	}
	defer end()
	for {
		switch on := leader(); {
		case on && stop == nil:
			begin()
		case !on:
			end()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
