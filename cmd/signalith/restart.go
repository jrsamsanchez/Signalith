package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/httpserver"
	"github.com/jrsamsanchez/signalith/internal/sample"
	"github.com/jrsamsanchez/signalith/internal/security"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// The server restarts itself when the Settings page asks: it builds every
// component again from the saved settings inside the same process, so a
// restart works the same under Docker, systemd, a Windows service or a
// terminal, with nothing outside to restart it. Sign-in sessions, the
// failed sign-in limits and the user store carry over, so admins stay
// signed in.
//
// A restart first checks that the new settings can work: the files and
// folders the components read, the new web and syslog addresses, the
// certificate, and OpenSearch with the new connection settings. If not,
// nothing changes, and the changes to blame are set aside in the
// settings file so the next start does not use them either. Then the old
// components stop and new ones start; if they cannot, the previous
// settings are started again, and if even those cannot, the web page
// stays up to say so while Signalith keeps trying.
//
// With HTTPS on, the web listener serves HTTPS and, on the same port,
// plain HTTP that sends browsers to HTTPS (httpserver.ServeBoth). A
// restart keeps the certificate in use when its settings did not change,
// and in auto mode always keeps Signalith's own certificate authority, so
// agents and browsers that trust it go on doing so.
//
// A restart that moves the web page (another address, or HTTPS turned on
// or off) waits for an admin to reach it at the new address. When nobody
// does within api.MoveWait, Signalith goes back to the old one; for a
// move to another port, the old address keeps answering until then.

// Timings of a restart; tests shorten them.
var (
	// restartDelay lets the answer to "restart" reach the browser first.
	restartDelay = 200 * time.Millisecond
	// drainWait is how long a restart waits for requests in progress.
	drainWait = 5 * time.Second
	// oldAddressGrace is how long the old web address keeps answering
	// after a move is confirmed, so the page there can learn where to go.
	oldAddressGrace = 30 * time.Second
	// pauseLimit is how long a request waits for a restart to finish
	// before it is answered 503.
	pauseLimit = 30 * time.Second
	// moveWait is how long a move of the web page waits for someone to
	// reach the new address.
	moveWait = api.MoveWait
	// downRetry is how often Signalith tries to start again when neither
	// the new settings nor the previous ones could.
	downRetry = 30 * time.Second
	// bootCheckTimeout bounds the OpenSearch check at startup.
	bootCheckTimeout = store.CheckTimeout
)

// runner runs the server and restarts it in-process.
type runner struct {
	path    string
	log     *slog.Logger
	started time.Time

	// These carry over a restart.
	sessions *auth.Sessions
	limiter  *auth.Limiter
	// browsers signs the known-browser cookies: the key in the state
	// folder, or one kept in memory.
	browsers *auth.BrowserKey
	people   *users.Store
	// node is this server among those that share its OpenSearch: its
	// identity and lock, heartbeat and job lease. A restart keeps it and
	// points it at the new OpenSearch client; nil in some tests.
	node *cluster.Node
	// shared is this server's place in the shared configuration: its
	// watcher, its copy of the settings and cache.enc. A restart keeps it
	// and points it at the new OpenSearch client; nil in some tests.
	shared *shared.Runtime
	// sharedContent links the shared settings' content (feeds, retention
	// policies) to the components of each start; nil with shared.
	sharedContent *sharedContent
	// audit is the process's audit spool (see sharedaudit.go); nil in
	// some tests.
	audit *processAudit
	// security runs the Security page's checks and keeps the last
	// report, which a restart keeps.
	security *api.SecurityChecker
	// agents is the agent inventory of the instance running now, which
	// hears of the agents that refuse the certificate.
	agents atomic.Pointer[agentinv.Inventory]

	front *front
	// prepared is the HTTPS certificate a restart's checks loaded or made
	// for the new settings, which starting with them then uses, and
	// preparedKey the settings it was made for. It lasts only for that
	// restart (see forgetPrepared): a later one would get a copy that
	// misses the names Add data gave the certificate in use since.
	prepared    *tlsauto.Manager
	preparedKey string

	requests  chan restartRequest
	confirmed chan *move
	mu        sync.Mutex
	busy      bool
	last      *api.RestartResult
	awaiting  *move

	// background is the context of work a request starts that runs on
	// after it and across restarts in place, such as a sample-data load;
	// shutdown ends it. Set by run; nil in some tests.
	background     context.Context
	stopBackground context.CancelFunc

	// Owned by run.
	cur     *instance // nil while nothing could start
	good    *config.Config
	web     *webServer
	retired []*webServer // old web servers still answering for a while

	// srv is the API server of the start running now, which checks a
	// change of this server's own settings made on another server's page.
	srv atomic.Pointer[api.Server]

	// failStart, for tests, makes starting with a config fail.
	failStart func(*config.Config) error
	// keysLogged is where the master key came from when that was last
	// logged (see useKeys).
	keysLogged string
}

type restartRequest struct {
	by, client string
	// localOnly is true when the admin agreed that the web page answers
	// on the server itself only: a move is then not undone.
	localOnly bool
	// keep restarts with the settings in use rather than the saved ones:
	// the components are built again for another reason (see
	// followShared).
	keep bool
	// reload, with keep, starts with the configuration loaded again: the
	// settings of the Settings page moved to the shared settings or back.
	reload bool
	// remote is the restart request of another server this restart
	// runs for; nil for one asked for here.
	remote *remoteRestart
}

// move is a restart that moved the web page, waiting for someone to reach
// it at the new address.
type move struct {
	api.AwaitingMove
	// web is the new web server, where the confirmation must come in, and
	// old the previous one, kept answering until then (nil when the new
	// one took its port).
	web, old *webServer
	// prev are the settings to go back to, and refuse the changes made on
	// the Settings page that are set aside when it does.
	prev   *config.Config
	refuse []string
	timer  *time.Timer
	// token, for a restart run by a restart request, is the token the
	// server that asked probes the new address with, and remote that
	// request, which ends once the move was confirmed or undone.
	token  string
	remote *remoteRestart
}

func newRunner(path string, log *slog.Logger) *runner {
	r := &runner{
		path: path, log: log, started: time.Now(),
		sessions: auth.NewSessions(12 * time.Hour), limiter: auth.NewLimiter(), browsers: auth.NewBrowserKey(),
		front: &front{}, requests: make(chan restartRequest, 1), confirmed: make(chan *move, 1),
	}
	r.front.ready = r.ready
	r.front.confirmMove = r.confirmProbe
	// While the users are shared, the limits are shared out among the
	// servers that take sign-ins, and a lock tripped here is reported to
	// the others; otherwise these change nothing. Set once, as the limiter
	// carries over a restart.
	r.limiter.Divisor, r.limiter.OnLock = r.signInServers, r.reportLock
	r.security = api.NewSecurityChecker(log)
	r.security.Started = r.started
	r.security.OnReport = func(rep *security.Report) {
		// The heartbeat sums it up for the other servers' Security pages.
		if r.node != nil {
			r.node.SetSecurity(api.SecuritySummaryOf(rep))
		}
	}
	return r
}

// signInServers is the limiter's Divisor (see sharedUsers).
func (r *runner) signInServers() int {
	if r.sharedContent == nil {
		return 1
	}
	return r.sharedContent.users.signInServers()
}

// reportLock is the limiter's OnLock (see sharedUsers).
func (r *runner) reportLock(scope, key string, until time.Time) {
	if r.sharedContent != nil {
		r.sharedContent.users.reportLock(scope, key, until)
	}
}

// ready answers /readyz: whether a load balancer should send this server
// traffic, and if not, why, in a word.
func (r *runner) ready() (bool, string) {
	if r.node == nil {
		return true, ""
	}
	if ok, why := r.node.Ready(); !ok {
		return ok, why
	}
	return sharedReady(r.shared)
}

// fatal receives an error when this server must not run at all.
func (r *runner) fatal() <-chan error {
	if r.node == nil {
		return nil
	}
	return r.node.Fatal()
}

// sharedFatal receives an error when the shared configuration in
// OpenSearch is of a level this version cannot use.
func (r *runner) sharedFatal() <-chan error {
	if r.shared == nil {
		return nil
	}
	return r.shared.Fatal()
}

// Restart implements api.Restarter.
func (r *runner) Restart(by, client string, localOnly bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.busy {
		return api.ErrRestarting
	}
	if r.awaiting != nil {
		return api.ErrAwaitingMove
	}
	r.busy = true
	go func() {
		time.Sleep(restartDelay)
		r.requests <- restartRequest{by: by, client: client, localOnly: localOnly}
	}()
	return nil
}

// restartInPlace builds the components again with the settings in use,
// or, with reload, with the configuration loaded again, for why; it
// returns api.ErrRestarting while a restart is going.
func (r *runner) restartInPlace(why string, reload bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.busy || r.awaiting != nil {
		return api.ErrRestarting
	}
	r.busy = true
	go func() { r.requests <- restartRequest{by: "signalith", client: why, keep: true, reload: reload} }()
	return nil
}

// sharedCheckEvery is how often followShared looks again without being
// told, in nanoseconds; atomic, as the tests shorten it while servers of
// earlier tests may still look.
var sharedCheckEvery atomic.Int64

func init() { sharedCheckEvery.Store(int64(30 * time.Second)) }

// sharedCheck is how often followShared looks again without being told.
func sharedCheck() time.Duration { return time.Duration(sharedCheckEvery.Load()) }

// followShared restarts the components in place when the shared
// configuration changes where their content comes from: this server
// founded or joined the cluster (its files to the shared settings), or
// left it; or the users, the directory sign-in settings and the sessions
// moved to the shared settings (or back); or the settings of the Settings
// page did, which loads the configuration again. Each start decides once,
// so the switch takes a restart, one for every change seen at once.
func (r *runner) followShared(ctx context.Context) {
	if r.shared == nil || r.sharedContent == nil {
		return
	}
	changed := make(chan struct{}, 1)
	kick := func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	r.shared.OnMode(func(_, _ shared.Mode) { kick() })
	// A server that joins while the founder still moves its files into
	// OpenSearch is a member before the shared content may be used: that
	// waits for the cluster document to say the import is done, which
	// changes no mode. So the cluster document is followed too, the one
	// of the runtime's index prefix of the moment.
	var watched *shared.Doc[shared.ClusterBody]
	watch := func() {
		if d := r.shared.Cluster(); d != nil && d != watched {
			watched = d
			d.OnChange(func(_, _ *shared.ClusterBody) { kick() })
		}
	}
	// tried is the switch of the settings a restart in place was asked
	// for: one that kept the settings in use (they could not be loaded,
	// or they move the web page, which waits for a restart) leaves the
	// switch undone, and it is not asked for again until another restart
	// decides once more.
	var tried *bool
	for {
		watch()
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-time.After(sharedCheck()):
		}
		ct := r.sharedContent
		want, wantUsers, wantSettings := r.shared.SharedContent(), r.shared.SharedUsers(), r.settingsShared()
		// Read once, so that the switch below agrees with settingsFlip.
		settingsOn := ct.settingsOn.Load()
		settingsFlip := wantSettings != settingsOn
		if !settingsFlip {
			tried = nil
		} else if tried != nil && *tried == wantSettings {
			settingsFlip = false
		}
		// A switch of the settings left undone counts as made until
		// another restart decides once more.
		if !settingsFlip {
			settingsOn = wantSettings
		}
		// The parts of the components that switch between the shared
		// settings and this server's own files, the first to switch
		// giving the reason.
		switches := []sharedSwitch{
			{want, ct.on.Load(), switchWhy(want,
				"this server now takes the threat intel feeds and retention policies from the shared settings",
				"this server now takes the threat intel feeds and retention policies from its own files")},
			{wantUsers, ct.users.on.Load(), switchWhy(wantUsers,
				"the users and sign-in are now shared by every server of the cluster; everyone signs in once more",
				"this server now keeps the users and sign-in in its own files")},
			{wantSettings, settingsOn, switchWhy(wantSettings,
				"this server now takes the settings of the Settings page from the shared settings",
				"this server now takes the settings of the Settings page from its own files")},
			// The audit records, the retention history and the archive
			// list (sharedaudit.go).
			{r.wantAudit(), r.auditOn(), switchWhy(r.wantAudit(),
				"every server now keeps its audit records, the retention history and the archive list in OpenSearch",
				"this server now keeps its retention history and archive list in its own files")},
			// Append a new shared feature's switch here.
		}
		i := slices.IndexFunc(switches, func(s sharedSwitch) bool { return s.want != s.on })
		if i < 0 {
			continue
		}
		why := switches[i].why
		if !want {
			// Leaving the shared content says so, whatever switches with it.
			why = switches[0].why
		}
		if err := r.restartInPlace(why, settingsFlip); err != nil {
			// Another restart is going; it decides again, and so does the
			// next look.
			continue
		}
		if settingsFlip {
			tried = &wantSettings
		}
	}
}

// sharedSwitch is a part of the components that takes its content from
// the shared settings or from this server's own files (followShared):
// want is where the shared configuration says it comes from now, on
// whether the components running now take it from the shared settings,
// and why the reason a restart in place gives for the switch.
type sharedSwitch struct {
	want, on bool
	why      string
}

// switchWhy is the reason for a switch to the shared settings when want,
// to this server's own files otherwise.
func switchWhy(want bool, toShared, toOwn string) string {
	if want {
		return toShared
	}
	return toOwn
}

// RestartStatus implements api.Restarter.
func (r *runner) RestartStatus() api.RestartStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := api.RestartStatus{InProgress: r.busy, Last: r.last}
	if m := r.awaiting; m != nil {
		a := m.AwaitingMove
		st.Awaiting = &a
	}
	return st
}

// webKey is the context key of the web server a request came in at.
type webKey struct{}

// Confirm implements api.Restarter: a request that came in at the web
// server a move waits on confirms it.
func (r *runner) Confirm(req *http.Request) bool {
	w, _ := req.Context().Value(webKey{}).(*webServer)
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.awaiting
	if m == nil || w == nil || w != m.web {
		return false
	}
	r.awaiting = nil
	if r.last != nil {
		last := *r.last
		last.Confirmed = true
		r.last = &last
	}
	select {
	case r.confirmed <- m:
	default:
	}
	return true
}

// run serves until ctx ends, restarting when asked.
func (r *runner) run(ctx context.Context, c *config.Config) error {
	r.background, r.stopBackground = context.WithCancel(ctx)
	defer r.stopBackground()
	// While the settings are shared, the configuration to start with
	// comes from them, which the runtime reads first.
	c = r.primeShared(c)
	c = r.checkPageOpenSearch(ctx, c)
	in, ln, err := r.open(ctx, c)
	if err != nil && c.SharedSettings() {
		// The shared settings, or this server's own, must not keep it from
		// starting either: without its own settings, then with
		// signalith.yaml alone. Those to blame are refused here once
		// OpenSearch takes writes.
		var bc *config.Config
		if bc, in, ln, err = r.startWithout(ctx, c, err); err == nil {
			c = bc
		}
	} else if err != nil && len(c.PageKeys()) > 0 {
		// Settings saved on the Settings page must not keep Signalith from
		// starting, which would also lock everyone out of the page that
		// can fix them: start with signalith.yaml alone, and say why there.
		// They are to blame only when that starts.
		keys := blame(err, c, nil)
		base, berr := config.LoadWithoutPage(r.path, fmt.Sprintf("Signalith could not start with them (%v)", err), keys)
		if berr == nil {
			var bin *instance
			var bln net.Listener
			bin, bln, berr = r.open(ctx, base)
			if berr == nil {
				r.log.Error("Signalith could not start with the settings saved on the Settings page; started with signalith.yaml alone",
					"err", err, "settings", strings.Join(keys, ","), "file", c.SettingsFile())
				c, in, ln, err = base, bin, bln, nil
			}
		}
		if berr != nil {
			r.log.Error("Signalith cannot start with signalith.yaml alone either, so the Settings page is not to blame", "err", berr)
		}
	}
	if err != nil {
		return err
	}
	r.cur, r.good = in, c
	r.front.resume(in.handler, in.plain)
	r.web = r.serveWeb(c, ln, in.certs)
	go r.followShared(ctx)
	if r.shared != nil && r.node != nil {
		// The restart and check requests that name this server; it runs
		// them only while it is a member.
		go r.shared.RunServerRequests(ctx, r.serverHandlers())
	}
	logListening(r.log, c, ln.Addr().String())
	var retry <-chan time.Time
	for {
		var moveTimeout <-chan time.Time
		r.mu.Lock()
		if r.awaiting != nil {
			moveTimeout = r.awaiting.timer.C
		}
		r.mu.Unlock()
		select {
		case err := <-r.web.errc:
			r.shutdown()
			return err
		case err := <-r.fatal():
			r.shutdown()
			return err
		case err := <-r.sharedFatal():
			r.shutdown()
			return err
		case req := <-r.requests:
			r.restart(ctx, req)
		case m := <-r.confirmed:
			m.timer.Stop()
			r.log.Info("new web address confirmed: someone reached it", "audit", true, "addr", m.To)
			if m.old != nil {
				r.retire(m.old, oldAddressGrace)
			}
			r.mu.Lock()
			last := r.last
			r.mu.Unlock()
			m.remote.end(last)
		case <-moveTimeout:
			r.mu.Lock()
			m := r.awaiting
			if m != nil {
				r.awaiting, r.busy = nil, true
			}
			r.mu.Unlock()
			if m != nil {
				r.revert(ctx, m)
			}
		case <-retry:
		case <-ctx.Done():
			r.log.Info("shutting down")
			return r.shutdown()
		}
		retry = nil
		if r.cur == nil {
			if !r.recover(ctx) {
				retry = time.After(downRetry)
			}
		}
	}
}

// backgroundContext is the context of work a request starts that runs on
// after it (see runner.background); parent where run did not set one.
func (r *runner) backgroundContext(parent context.Context) context.Context {
	if r.background != nil {
		return r.background
	}
	return parent
}

// open listens on the web address and starts the components, which load
// or make the HTTPS certificate.
func (r *runner) open(ctx context.Context, c *config.Config) (*instance, net.Listener, error) {
	ln, err := httpserver.Listen(c.Server.Listen, webLimits(c), r.log)
	if err != nil {
		return nil, nil, keyed(fmt.Errorf("cannot listen on %s: %w", c.Server.Listen, opError(err)), "server.listen")
	}
	in, err := r.start(ctx, c)
	if err != nil {
		ln.Close()
		return nil, nil, err
	}
	return in, ln, nil
}

// logListening says where the web page answers, and how.
func logListening(log *slog.Logger, c *config.Config, addr string) {
	if c.Server.HTTPS() {
		log.Info("signalith listening", "addr", addr, "ui", c.Server.PublicURL, "https", c.Server.TLSMode(),
			"plaintext_ingest", c.Server.PlaintextIngest(), "version", version)
		return
	}
	log.Info("signalith listening", "addr", addr, "ui", c.Server.PublicURL, "https", "off", "version", version)
}

// keyedError is an error about some settings.
type keyedError struct {
	err  error
	keys []string
}

func (e *keyedError) Error() string { return e.err.Error() }
func (e *keyedError) Unwrap() error { return e.err }

func keyed(err error, keys ...string) error { return &keyedError{err: err, keys: keys} }

// blame returns the settings changed on the Settings page that err is
// about, or every one that a restart applies when that is not known: each
// setting of this server's page whose value differs from signalith.yaml's,
// and, while the settings are shared, each shared value that differs from
// the one prev ran with (prev is the configuration in use before c; nil
// at a start, when none is known, so a shared value is to blame only when
// err names it). A shared value at another value than signalith.yaml's is
// no sign it is to blame: the files do not set it. A password saved there
// that cannot be decrypted is never among them: it is left out, not used,
// and set aside it would stay unused after the master key it needs is
// back.
func blame(err error, c, prev *config.Config) []string {
	var ke *keyedError
	var keys []string
	if errors.As(err, &ke) {
		for _, k := range ke.keys {
			if fromPage(c, k) {
				keys = append(keys, k)
			}
		}
		if keys = usable(c, keys); keys != nil {
			return keys
		}
	}
	base := c.Base()
	for _, k := range pageKeys(c) {
		if c.Source(k).Kind != config.FromShared {
			if !config.SameValue(base, c, k) {
				keys = append(keys, k)
			}
			continue
		}
		if prev != nil && !config.SameValue(prev, c, k) {
			keys = append(keys, k)
		}
	}
	return usable(c, keys)
}

// fromPage reports whether key's value in c was set on a Settings page:
// this server's, or, while the settings are shared, any server's.
func fromPage(c *config.Config, key string) bool {
	k := c.Source(key).Kind
	return k == config.FromPage || k == config.FromShared
}

// pageKeys lists the settings of c set on a Settings page (see fromPage).
func pageKeys(c *config.Config) []string {
	keys := c.PageKeys()
	if !c.SharedSettings() {
		return keys
	}
	for _, k := range config.SharedKeys() {
		if c.Source(k).Kind == config.FromShared && !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}

// undecryptable returns those of keys whose password or key saved on the
// Settings page cannot be decrypted, and so is left out of c (see
// config.PageUnreadable).
func undecryptable(c *config.Config, keys []string) []string {
	var out []string
	for _, k := range keys {
		if c.PageSecretProblem(k) != "" {
			out = append(out, k)
		}
	}
	return out
}

// usable returns keys without those undecryptable returns: a check or a
// start that fails without such a password says nothing about it, and
// the decryption problem is reported on its own.
func usable(c *config.Config, keys []string) []string {
	var out []string
	for _, k := range keys {
		if c.PageSecretProblem(k) == "" {
			out = append(out, k)
		}
	}
	return out
}

// openSearchKeys are the settings of the OpenSearch connection.
var openSearchKeys = []string{"opensearch.url", "opensearch.username", "opensearch.password", "opensearch.ca_file",
	"opensearch.cert_file", "opensearch.key_file", "opensearch.proxy", "opensearch.allow_insecure_http", "opensearch.tls_skip_verify"}

// checkPageOpenSearch checks, at startup, an OpenSearch connection set on
// the Settings page that no restart has checked: one saved with no
// restart since. When OpenSearch answers with signalith.yaml's settings
// but not with the page's, those are set aside, and Signalith starts with
// signalith.yaml's. When neither answers, OpenSearch is just not up yet.
func (r *runner) checkPageOpenSearch(ctx context.Context, c *config.Config) *config.Config {
	var keys []string
	unchecked := false
	for _, k := range openSearchKeys {
		if c.Source(k).Kind == config.FromPage {
			keys = append(keys, k)
			unchecked = unchecked || !c.PageChecked(k)
		}
	}
	base := c.Base()
	if !unchecked || base.OpenSearchConnection() == c.OpenSearchConnection() {
		return c
	}
	// A password saved on the page that cannot be decrypted is left out,
	// and the other settings saved there are still used: OpenSearch
	// refusing Signalith without it says nothing about them, and the
	// decryption problem is reported (config.PageUnreadable).
	if len(undecryptable(c, keys)) > 0 {
		return c
	}
	check := func(c *config.Config) store.Report {
		cfg := c.OpenSearchConnection()
		cfg.Timeout = bootCheckTimeout
		return store.Check(ctx, cfg)
	}
	rep := check(c)
	if rep.OK {
		if err := config.MarkChecked(c.SettingsFile(), keys); err != nil {
			r.log.Warn("could not note in the settings file that its OpenSearch settings work", "err", err)
		}
		return c
	}
	if !check(base).OK {
		return c
	}
	reason := "When Signalith started, OpenSearch did not answer with these settings but did with those in signalith.yaml: " + rep.Message
	r.setAside(c, c, keys, reason)
	next, err := r.loadSetAside(keys, reason)
	if err != nil {
		return c
	}
	r.log.Error("OpenSearch did not answer with the settings saved on the Settings page, but did with those in signalith.yaml; using those",
		"settings", strings.Join(keys, ","), "problem", rep.Message)
	return next
}

// shutdown stops the web servers and the components. A move of the web
// page that nobody confirmed is set aside, so the next start uses the
// address that is known to work.
func (r *runner) shutdown() error {
	r.mu.Lock()
	m := r.awaiting
	r.awaiting = nil
	r.mu.Unlock()
	if m != nil {
		cur := m.prev
		if r.cur != nil {
			cur = r.cur.srv.Running()
		}
		reason := "Signalith stopped before anyone opened it at " + m.To + ", so it was not used"
		r.setAside(cur, m.prev, m.refuse, reason)
		m.remote.end(&api.RestartResult{Error: reason + "."})
	}
	// A sample-data load or removal running here stops, and notes in
	// OpenSearch that it did not finish, so every server shows that at
	// once rather than a minute later.
	var sampleWait sync.WaitGroup
	if r.stopBackground != nil {
		r.stopBackground()
		sampleWait.Go(func() {
			if !sample.WaitJobs(30 * time.Second) {
				r.log.Warn("a sample-data load or removal did not stop in time; the other servers show it as not finished within a minute")
			}
		})
	}
	if r.node != nil {
		// First, while the web page still answers (/readyz says
		// "stopping"): the background jobs finish their current step and
		// are handed over, so another server takes them within seconds.
		r.node.Stop()
	}
	flushShared(r.shared, r.log)
	var err error
	if r.web != nil {
		err = r.web.close(10 * time.Second)
	}
	sampleWait.Wait()
	var wg sync.WaitGroup
	for _, w := range r.retired {
		w.keep()
		wg.Go(func() { w.close(10 * time.Second) })
	}
	if r.cur != nil {
		r.cur.stop()
	}
	wg.Wait()
	return err
}

// finish records how a restart went.
func (r *runner) finish(res *api.RestartResult, m *move) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last, r.busy = res, false
	if m != nil {
		r.awaiting = m
	}
}

// restart applies the saved settings. Problems found before the switch
// keep everything as it was; a failure after it goes back to the previous
// settings.
func (r *runner) restart(ctx context.Context, req restartRequest) {
	start := time.Now()
	res := &api.RestartResult{At: start.UTC(), By: req.by, Keys: []string{}}
	var awaiting *move
	defer func() { r.done(res, req, start, awaiting) }()
	if r.cur == nil {
		res.Error = "Signalith is not running its parts, so it cannot restart. It tries to start again every 30 seconds."
		return
	}
	// The settings in use, including those applied at once from the
	// Settings page since the last start.
	prev := r.cur.srv.Running()
	if req.keep {
		r.log.Info("restarting in place: " + req.client)
		next := prev
		if req.reload {
			// The settings of the Settings page moved: the configuration
			// is loaded again, with the same values unless they changed.
			if c, err := r.loadStartConfig(); err != nil {
				r.log.Error("the settings cannot be loaded again; restarting with those in use", "err", err)
			} else if !moved(prev, c) {
				next = c
			} else {
				r.log.Warn("the settings loaded again move the web page; restarting with those in use until a restart applies them")
			}
		}
		r.switchTo(ctx, prev, next, res, false)
		return
	}
	next, err := r.loadStartConfig()
	if err != nil {
		res.Error = fmt.Sprintf("The saved settings could not be loaded (%v). Signalith kept running with the previous settings.", err)
		return
	}
	if p := next.SettingsProblem(); p != "" {
		res.Error = "The settings saved on the Settings page cannot be used, so Signalith kept running with the previous settings. " + p
		return
	}
	r.log.Info("restarting to apply the saved settings", "by", req.by, "settings", strings.Join(changedSettings(prev, next), ","))
	confirm := moved(prev, next) && !req.localOnly
	if !r.switchTo(ctx, prev, next, res, confirm) || !res.OK {
		return
	}
	if err := config.MarkChecked(next.SettingsFile(), usable(next, next.PageKeys())); err != nil {
		r.log.Warn("could not note in the settings file that its settings work", "err", err)
	}
	if confirm {
		awaiting = r.awaitMove(prev, next)
		if req.remote != nil {
			awaiting.remote = req.remote
			r.announceMove(req.remote, awaiting, next)
		}
	}
}

// done logs and records how a restart went, and lets the requests held
// back through.
func (r *runner) done(res *api.RestartResult, req restartRequest, start time.Time, m *move) {
	res.TookMS = time.Since(start).Milliseconds()
	switch {
	case res.OK && res.Reverted:
		r.log.Warn("went back to the previous web address", "audit", true, "by", req.by, "settings", strings.Join(res.Keys, ","), "reason", res.Error)
	case res.OK && req.keep:
		r.log.Info("restarted in place", "reason", req.client, "took_ms", res.TookMS)
	case res.OK:
		r.log.Info("restarted with the saved settings", "audit", true, "by", req.by, "client", req.client, "settings", strings.Join(res.Keys, ","), "took_ms", res.TookMS)
	default:
		r.log.Error("restart failed", "audit", true, "by", req.by, "client", req.client, "settings", strings.Join(res.Keys, ","),
			"rolled_back", res.RolledBack, "set_aside", strings.Join(res.Refused, ","), "reason", res.Error)
	}
	// The result is in place before the requests held back go through,
	// so the page sees it at once.
	r.finish(res, m)
	if r.cur != nil {
		r.front.resume(r.cur.handler, r.cur.plain)
	}
	if m == nil {
		// A restart another server asked for ends here, unless it moved the
		// web page: then once the move was confirmed or undone.
		req.remote.end(res)
	}
}

// moved reports whether the web page answers somewhere else with next:
// another address, or HTTPS turned on or off.
func moved(prev, next *config.Config) bool {
	return prev.Server.Listen != next.Server.Listen || prev.Server.HTTPS() != next.Server.HTTPS()
}

// moveKeys are the settings that move the web page.
var moveKeys = []string{"server.listen", "server.tls.mode"}

// webAddress names where a web server answers, for people.
func webAddress(c *config.Config) string {
	if c.Server.HTTPS() {
		return "https://" + c.Server.Listen
	}
	return "http://" + c.Server.Listen
}

// awaitMove starts waiting for someone to reach the web page at the
// address it moved to.
func (r *runner) awaitMove(prev, next *config.Config) *move {
	m := &move{web: r.web, prev: prev, timer: time.NewTimer(moveWait)}
	m.From, m.To, m.Until = webAddress(prev), webAddress(next), time.Now().Add(moveWait).UTC()
	m.Keys = []string{}
	for _, k := range moveKeys {
		if !config.SameValue(prev, next, k) {
			m.Keys = append(m.Keys, k)
			if fromPage(next, k) {
				m.refuse = append(m.refuse, k)
			}
		}
	}
	for _, w := range r.retired {
		if w.cfg == nil || w.timer != nil || !w.open() {
			continue
		}
		if w.cfg.Server.Listen == prev.Server.Listen {
			m.old = w
		}
	}
	return m
}

// revert goes back to the previous web address after nobody reached the
// new one in time, and sets the changes that moved it aside.
func (r *runner) revert(ctx context.Context, m *move) {
	start := time.Now()
	res := &api.RestartResult{At: start.UTC(), By: "Signalith", Keys: []string{}, Reverted: true}
	req := restartRequest{by: "Signalith", remote: m.remote}
	defer func() { r.done(res, req, start, nil) }()
	if r.cur == nil {
		return
	}
	reason := fmt.Sprintf("Nobody opened Signalith at %s within %d minutes, so it went back to %s", m.To, int(moveWait.Minutes()), m.From)
	if moveWait < time.Minute {
		reason = fmt.Sprintf("Nobody opened Signalith at %s in time, so it went back to %s", m.To, m.From)
	}
	cur := r.cur.srv.Running()
	res.Refused = r.setAside(cur, m.prev, m.refuse, reason)
	next, err := r.loadSetAside(m.refuse, reason)
	if err != nil || next.SettingsProblem() != "" || moved(m.prev, next) {
		// The move came from signalith.yaml, or the settings cannot be
		// read now: go back to the settings in use before it.
		next = m.prev
	}
	if m.old != nil {
		// It still answers at the old address: nothing to wait for.
		m.old.keep()
	}
	if r.switchTo(ctx, cur, next, res, false) {
		res.ProblemKeys = m.Keys
		if res.OK {
			res.Error = reason + "."
		}
	}
}

// switchTo checks next and switches to it from prev, filling in res. It
// reports false when the checks refused next, so nothing changed. confirm
// is true when a move of the web page waits to be confirmed: the old web
// server then keeps answering until it is.
func (r *runner) switchTo(ctx context.Context, prev, next *config.Config, res *api.RestartResult, confirm bool) bool {
	defer r.forgetPrepared()
	res.Keys = changedSettings(prev, next)
	plan, err := r.check(ctx, prev, next)
	if err != nil {
		res.Error = err.Error()
		var ke *keyedError
		if errors.As(err, &ke) {
			res.ProblemKeys = ke.keys
			// Not used at the next start either, until tried again. The
			// reason is the cause alone: the setting is not in use. A
			// password that cannot be decrypted is not set aside (see
			// usable).
			res.Refused = r.setAside(next, prev, usable(next, ke.keys), strings.TrimSuffix(res.Error, keptRunning))
		}
		return false
	}

	// Switch: hold new requests back, stop the old components, start new ones.
	old := r.cur
	r.front.pause(drainWait)
	old.stop()
	in, err := r.start(ctx, next)
	if err == nil && plan.moveWeb && plan.ln == nil && plan.reuse == nil {
		// The new address takes the old one's port: free it, then listen.
		r.web.close(5 * time.Second)
		plan.ln, err = httpserver.Listen(next.Server.Listen, webLimits(next), r.log)
		if err != nil {
			in.stop()
			err = keyed(fmt.Errorf("cannot listen on %s: %w", next.Server.Listen, opError(err)), "server.listen")
			if back, lerr := httpserver.Listen(prev.Server.Listen, webLimits(prev), r.log); lerr == nil {
				r.web = r.serveWeb(prev, back, old.certs)
			} else {
				r.log.Error("the previous web address cannot be listened on again", "addr", prev.Server.Listen, "err", lerr)
			}
		}
	}
	if err != nil {
		res.RolledBack = true
		res.Error = fmt.Sprintf("Signalith could not start with the saved settings (%v), so it went back to the previous settings.", err)
		if plan.ln != nil {
			plan.ln.Close()
		}
		if plan.reuse != nil {
			r.retire(plan.reuse, 0)
		}
		res.ProblemKeys = blame(err, next, prev)
		res.Refused = r.setAside(next, prev, res.ProblemKeys, fmt.Sprintf("Signalith could not start with it (%v).", err))
		back, err2 := r.start(ctx, prev)
		if err2 != nil {
			res.Error = fmt.Sprintf("Signalith could not start with the saved settings (%v) or the previous ones (%v). It tries again every 30 seconds.", err, err2)
			r.log.Error("Signalith could not start with the new settings or the previous ones; it tries again every 30 seconds", "new", err, "previous", err2)
			r.cur = nil
			r.front.resume(downHandler, downHandler)
			if r.node != nil {
				// Another server that shares the OpenSearch runs the jobs
				// meanwhile.
				r.node.Pause("Signalith could not start its parts on this server")
			}
			return true
		}
		r.cur = back
		r.web.certs.Store(back.certs)
		return true
	}
	if plan.moveWeb {
		prevWeb := r.web
		if plan.reuse != nil {
			r.web = plan.reuse
			r.web.certs.Store(in.certs)
			r.retired = slices.DeleteFunc(r.retired, func(w *webServer) bool { return w == plan.reuse })
		} else {
			r.web = r.serveWeb(next, plan.ln, in.certs)
		}
		logListening(r.log, next, next.Server.Listen)
		if prevWeb.open() {
			// The page at the old address asks how the restart went before
			// it moves. A move then waits to be confirmed; otherwise the
			// old address closes after a while.
			if confirm {
				r.retire(prevWeb, -1)
			} else {
				r.retire(prevWeb, oldAddressGrace)
			}
		}
	} else {
		// The same listener serves the new certificate.
		r.web.certs.Store(in.certs)
	}
	r.cur, r.good = in, next
	res.OK = true
	return true
}

// recover tries to start again after neither the new settings nor the
// previous ones could: with the saved settings, then the last ones that
// ran. It reports whether one did.
func (r *runner) recover(ctx context.Context) bool {
	try := func(c *config.Config) bool {
		defer r.forgetPrepared()
		if r.web == nil || !r.web.open() {
			certs, err := r.prepare(c)
			if err != nil {
				r.log.Error("Signalith still cannot start; it tries again in 30 seconds", "err", err)
				return false
			}
			ln, err := httpserver.Listen(c.Server.Listen, webLimits(c), r.log)
			if err != nil {
				return false
			}
			r.web = r.serveWeb(c, ln, certs)
		}
		in, err := r.start(ctx, c)
		if err != nil {
			r.log.Error("Signalith still cannot start; it tries again in 30 seconds", "err", err)
			return false
		}
		r.cur, r.good = in, c
		r.web.certs.Store(in.certs)
		r.front.resume(in.handler, in.plain)
		r.log.Info("Signalith started again", "audit", true)
		r.finish(&api.RestartResult{At: time.Now().UTC(), By: "Signalith", OK: true, Keys: []string{}}, nil)
		return true
	}
	// The saved settings, unless they move the web page: that is checked
	// by a restart.
	if c, err := r.loadConfig(); err == nil && c.SettingsProblem() == "" && (r.web == nil || !moved(r.web.cfg, c)) {
		if try(c) {
			return true
		}
	}
	return r.good != nil && try(r.good)
}

// plan is what the checks before a restart prepared.
type plan struct {
	// moveWeb is true when the web listener changes. ln is the new one,
	// already listening, or reuse an old web server that answers there
	// already; both are nil when the new address takes the old one's port
	// and must wait for it to close.
	moveWeb bool
	ln      net.Listener
	reuse   *webServer
}

// keptRunning ends the words of a check that failed.
const keptRunning = " Signalith kept running with the previous settings."

// refuse words a check that failed: Signalith kept running with the
// previous settings.
func refuse(format string, args ...any) error {
	return fmt.Errorf(format+keptRunning, args...)
}

// check makes sure the new settings can work before anything stops: no
// data retention job would be cut short, the folders and files the
// components read open, the certificate loads, OpenSearch answers with the
// new connection settings, and the web page and syslog can listen on
// their new addresses.
func (r *runner) check(ctx context.Context, old, next *config.Config) (*plan, error) {
	if ret := r.cur.retention; ret != nil {
		if job := ret.Job(); job != "" {
			what := map[string]string{"run": "deleting or archiving old days", "restore": "restoring archived days"}[job]
			return nil, refuse("Data retention is %s right now, which a restart would cut short. Restart again when it has finished; the Data retention page shows how it is going.", what)
		}
	}
	if err := checkFiles(r.people, next); err != nil {
		return nil, refuse("%s. Fix it on the server, then restart again.", sentenceOf(err))
	}
	p := &plan{}
	if _, err := r.prepare(next); err != nil {
		return nil, keyed(refuse("%s.", sentenceOf(err)), certKeys(next)...)
	}
	if openSearchMoves(old, next) {
		var keys []string
		for _, k := range openSearchKeys {
			if !config.SameValue(old, next, k) {
				keys = append(keys, k)
			}
		}
		if rep := store.Check(ctx, next.OpenSearchConnection()); !rep.OK {
			// Without a password saved on the Settings page that cannot be
			// decrypted, OpenSearch may well refuse Signalith: that is what
			// to fix, and the settings are not set aside for it.
			if locked := undecryptable(next, openSearchKeys); len(locked) > 0 {
				return nil, keyed(refuse("OpenSearch did not answer with the new settings: %s But the %s saved on the Settings page cannot be used, which may be why. %s",
					rep.Message, locked[0], next.PageSecretProblem(locked[0])), locked...)
			}
			return nil, keyed(refuse("OpenSearch did not answer with the new settings: %s", rep.Message), keys...)
		}
	}
	if webChanges(old, next) {
		p.moveWeb = true
		if w := r.retiredAt(next); w != nil {
			p.reuse = w
		} else {
			// An old web server still answering after an earlier move gives
			// its address up.
			r.closeRetired(next.Server.Listen)
			ln, err := httpserver.Listen(next.Server.Listen, webLimits(next), r.log)
			switch {
			case err == nil:
				p.ln = ln
			case addrInUse(err) && overlaps(old.Server.Listen, next.Server.Listen):
				// The web server in use holds it: listening waits for it to
				// close.
			default:
				return nil, keyed(refuse("Signalith cannot listen on %s (%v). Choose another address or port.", next.Server.Listen, opError(err)), "server.listen")
			}
		}
	}
	fail := func(err error) (*plan, error) {
		if p.ln != nil {
			p.ln.Close()
		}
		return nil, err
	}
	// New syslog addresses must be free; one that takes a port Signalith
	// holds now, with the same protocol, is freed by the switch. Another
	// program may hold the same port number with the other protocol.
	type listener struct{ network, addr string }
	inUse := []listener{{"udp", old.Syslog.UDP}, {"tcp", old.Syslog.TCP}, {"tcp", old.Syslog.TLS}, {"tcp", old.Server.Listen}}
	for _, l := range []struct{ setting, network, addr string }{
		{"syslog.udp", "udp", next.Syslog.UDP}, {"syslog.tcp", "tcp", next.Syslog.TCP}, {"syslog.tls", "tcp", next.Syslog.TLS},
	} {
		if l.addr == "" || slices.ContainsFunc(inUse, func(u listener) bool { return u.network == l.network && overlaps(u.addr, l.addr) }) {
			continue
		}
		if err := tryListen(l.network, l.addr); err != nil {
			return fail(keyed(refuse("Signalith cannot receive syslog on %s/%s (%v). Choose another address or port.", l.addr, l.network, opError(err)), l.setting))
		}
	}
	return p, nil
}

// checkFiles opens what the components read from files and folders, as
// starting with c does, so that one that cannot be read stops the restart
// before anything stops.
func checkFiles(people *users.Store, c *config.Config) error {
	if _, _, err := detect.NewLibrary(c.DetectionsDir()); err != nil {
		return err
	}
	if _, err := dashboards.NewStore(c.DashboardsDir()); err != nil {
		return fmt.Errorf("dashboards.dir: %w", err)
	}
	if people == nil || people.Path() != c.UsersFile() {
		if _, err := users.Open(c.UsersFile()); err != nil {
			return err
		}
	}
	fromFile, err := c.LDAP()
	if err != nil {
		return err
	}
	if _, err := users.OpenDirectory(c.DirectoryFile(), fromFile); err != nil {
		return err
	}
	return nil
}

// tryListen checks that an address can be listened on.
func tryListen(network, addr string) error {
	if network == "udp" {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}
		return pc.Close()
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

// opError is the reason in a listen error, without the address again.
func opError(err error) error {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return oe.Err
	}
	return err
}

func sentenceOf(err error) string {
	s := strings.TrimSuffix(err.Error(), ".")
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// certificates returns the HTTPS certificate for c, which syslog over
// TLS uses too, or nil when c needs none. The one in use, or the one a
// restart's checks prepared, is used again when it was made for the same
// settings; a new one in auto mode comes from the same certificate
// authority, kept in the state folder. key names the settings it is for.
func (r *runner) certificates(c *config.Config) (*tlsauto.Manager, string, error) {
	o, ok := certOptions(c)
	if !ok {
		return nil, "", nil
	}
	key := certKey(o)
	if r.cur != nil && r.cur.certs != nil && r.cur.certKey == key {
		return r.cur.certs, key, nil
	}
	if r.prepared != nil && r.preparedKey == key {
		// Made by this restart's checks. Names Add data gave the
		// certificate in use while they ran are added now.
		if err := r.prepared.Refresh(); err != nil {
			return nil, "", keyed(err, certKeys(c)...)
		}
		return r.prepared, key, nil
	}
	m, err := newCertificates(c, r.log)
	if err != nil {
		return nil, "", keyed(err, certKeys(c)...)
	}
	return m, key, nil
}

// prepare loads or makes the HTTPS certificate for c ahead of starting
// with it, so a problem with it stops a restart before anything stops.
func (r *runner) prepare(c *config.Config) (*tlsauto.Manager, error) {
	m, key, err := r.certificates(c)
	if err != nil {
		return nil, err
	}
	r.prepared, r.preparedKey = m, key
	return m, nil
}

// forgetPrepared drops the certificate a restart prepared, once that
// restart is over, however it went.
func (r *runner) forgetPrepared() { r.prepared, r.preparedKey = nil, "" }

// certKey names the settings a certificate is made from.
func certKey(o tlsauto.Options) string {
	if o.CertFile != "" {
		return "files\x00" + o.CertFile + "\x00" + o.KeyFile
	}
	return "auto\x00" + o.Dir + "\x00" + strings.Join(o.Names, "\x00")
}

// certKeys are the settings a problem with c's certificate is about.
func certKeys(c *config.Config) []string {
	if c.Server.TLSMode() == config.TLSFiles {
		return []string{"server.tls_cert", "server.tls_key", "server.tls.mode"}
	}
	return []string{"server.tls.mode", "server.tls.names"}
}

// webChanges reports whether the web listener changes: another address,
// HTTPS turned on or off, or other connection limits. Another certificate
// is served by the same listener.
func webChanges(old, next *config.Config) bool {
	return moved(old, next) || old.Server.MaxConnections != next.Server.MaxConnections ||
		!slices.Equal(old.Server.SharedAddresses, next.Server.SharedAddresses)
}

// webLimits are the connection limits of the web listener.
func webLimits(c *config.Config) httpserver.Limits {
	return httpserver.Limits{Max: c.Server.MaxConnections, Shared: c.Server.SharedList()}
}

// openSearchMoves reports whether the OpenSearch connection changes.
func openSearchMoves(old, next *config.Config) bool {
	return old.OpenSearchConnection() != next.OpenSearchConnection() ||
		old.OpenSearch.AllowInsecureHTTP != next.OpenSearch.AllowInsecureHTTP
}

// samePort reports whether two listen addresses use the same port.
func samePort(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	_, pa, err1 := net.SplitHostPort(a)
	_, pb, err2 := net.SplitHostPort(b)
	return err1 == nil && err2 == nil && pa == pb && pa != "0"
}

// overlaps reports whether a listener on a holds the port b asks for: the
// same port, on the same address or on every address.
func overlaps(a, b string) bool {
	if !samePort(a, b) {
		return false
	}
	ha, _, _ := net.SplitHostPort(a)
	hb, _, _ := net.SplitHostPort(b)
	any := func(h string) bool { return h == "" || h == "0.0.0.0" || h == "::" }
	loop := func(h string) bool {
		ip := net.ParseIP(h)
		return strings.EqualFold(h, "localhost") || (ip != nil && ip.IsLoopback())
	}
	return any(ha) || any(hb) || strings.EqualFold(ha, hb) || (loop(ha) && loop(hb))
}

// changedSettings lists the page's settings that differ between two
// configs, for the log and the restart result.
func changedSettings(a, b *config.Config) []string {
	out := []string{}
	for _, s := range config.Registry {
		if s.OnPage(false) && !config.SameValue(a, b, s.Key) {
			out = append(out, s.Key)
		}
	}
	return out
}

// webServer is one web listener.
type webServer struct {
	// hs serves the page and the API: over HTTPS when cfg has it on, and
	// then plain answers plain HTTP on the same port.
	hs, plain *http.Server
	cfg       *config.Config
	errc      chan error
	closed    atomic.Bool
	// certs is the certificate it serves, with HTTPS. A restart that
	// keeps the listener changes it.
	certs atomic.Pointer[tlsauto.Manager]
	// timer closes a retired web server; nil while it is kept.
	timer *time.Timer
}

// errNoCertificate answers a TLS handshake when no certificate is loaded,
// which does not happen while HTTPS is on.
var errNoCertificate = errors.New("no HTTPS certificate is loaded")

// serveWeb serves the front handler on ln, with HTTPS and plain HTTP on
// the same port when c has HTTPS on. Requests carry the web server they
// came in at, so a move can tell when someone reached the new one.
func (r *runner) serveWeb(c *config.Config, ln net.Listener, certs *tlsauto.Manager) *webServer {
	lim := webLimits(c)
	w := &webServer{hs: httpserver.New(r.front, lim, r.log), cfg: c, errc: make(chan error, 1)}
	w.certs.Store(certs)
	tag := func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, webKey{}, w)
	}
	w.hs.ConnContext = tag
	useTLS := c.Server.HTTPS()
	if useTLS {
		// Browsers and agents that refuse the certificate, for the Security
		// page after a switch of certificate authority.
		httpserver.OnRefusal(w.hs, func(addr string) {
			if m := w.certs.Load(); m != nil {
				m.NoteRefusal(addr, "https")
			}
			// An agent pinned to a certificate authority this server does
			// not use never gets a batch through: the Endpoints page says
			// it needs a new configuration.
			if v := r.agents.Load(); v != nil {
				v.NoteRefusedCA(addr)
			}
		})
		w.hs.TLSConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			m := w.certs.Load()
			if m == nil {
				return nil, errNoCertificate
			}
			return m.GetCertificate(hello)
		}
		w.plain = httpserver.New(r.front.plainSide(), lim, r.log)
		w.plain.ConnContext = tag
	}
	go func() {
		var err error
		if useTLS {
			err = httpserver.ServeBoth(w.hs, w.plain, ln)
		} else {
			err = w.hs.Serve(ln)
		}
		if w.closed.Load() {
			// Closing it ends serving, with http.ErrServerClosed or, for
			// the side that did not close the listener, net.ErrClosed.
			return
		}
		w.errc <- err
	}()
	return w
}

func (w *webServer) open() bool { return !w.closed.Load() }

// close stops the listener, which frees the port at once, and waits up to
// wait for requests in progress, on both HTTPS and plain HTTP.
func (w *webServer) close(wait time.Duration) error {
	if w.closed.Swap(true) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	if w.plain == nil {
		return w.hs.Shutdown(ctx)
	}
	var plainErr error
	var wg sync.WaitGroup
	wg.Go(func() { plainErr = w.plain.Shutdown(ctx) })
	err := w.hs.Shutdown(ctx)
	wg.Wait()
	return errors.Join(err, plainErr)
}

// keep stops a retired web server's timer, so it is not closed.
func (w *webServer) keep() bool {
	if w.timer == nil {
		return true
	}
	if !w.timer.Stop() {
		return false
	}
	w.timer = nil
	return true
}

// retire keeps an old web server answering for a while, then closes it:
// after the time given, at once for 0, or not until told for -1.
func (r *runner) retire(w *webServer, after time.Duration) {
	if !slices.Contains(r.retired, w) {
		r.retired = append(r.retired, w)
	}
	if w.timer != nil && !w.keep() {
		return
	}
	switch {
	case after < 0:
		return
	case after == 0:
		w.close(10 * time.Second)
		r.retired = slices.DeleteFunc(r.retired, func(o *webServer) bool { return o == w })
		return
	}
	w.timer = time.AfterFunc(after, func() { w.close(10 * time.Second) })
}

// retiredAt returns a retired web server that answers as next asks, to
// serve again instead of listening anew.
func (r *runner) retiredAt(next *config.Config) *webServer {
	for _, w := range r.retired {
		c := w.cfg
		if c == nil || !w.open() || c.Server.Listen != next.Server.Listen || c.Server.HTTPS() != next.Server.HTTPS() ||
			c.Server.MaxConnections != next.Server.MaxConnections || !slices.Equal(c.Server.SharedAddresses, next.Server.SharedAddresses) {
			continue
		}
		if w.keep() {
			return w
		}
	}
	return nil
}

// closeRetired closes the retired web servers that hold addr's port.
func (r *runner) closeRetired(addr string) {
	for _, w := range slices.Clone(r.retired) {
		if w.cfg != nil && overlaps(w.cfg.Server.Listen, addr) && w.keep() {
			r.retire(w, 0)
		}
	}
	r.retired = slices.DeleteFunc(r.retired, func(w *webServer) bool { return !w.open() })
}

// downHandler answers while Signalith cannot run its parts: neither the
// new settings nor the previous ones started. It says no more than that;
// the log on the server says why.
var downHandler http.Handler = downPage{}

type downPage struct{}

func (downPage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", "30")
	w.Header().Set("Cache-Control", "no-store")
	const msg = "Signalith could not start and tries again every 30 seconds. Its log on the server says why."
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"` + msg + `","code":"down"}` + "\n"))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(msg + "\n"))
}

// front is the handler every web listener serves. It passes requests to
// the current components and holds new ones back while a restart swaps
// them.
type front struct {
	mu sync.Mutex
	// h serves the page and the API, and plain serves plain HTTP on a
	// port that serves HTTPS (see api.Server.PlainHandler).
	h, plain http.Handler
	paused   chan struct{} // closed when a pause ends; nil when not paused
	inflight int
	idle     chan struct{} // closed when the last request in progress ends
	// ready says whether this server should get traffic, for /readyz.
	ready func() (bool, string)
	// confirmMove confirms a move of the web page that a restart request
	// made, with the token the server that asked probes /readyz?move=
	// with (see runner.probeMoves).
	confirmMove func(*http.Request, string) bool
}

func (f *front) ServeHTTP(w http.ResponseWriter, r *http.Request) { f.serve(w, r, false) }

// plainSide is the handler for plain HTTP on a port that serves HTTPS.
func (f *front) plainSide() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.serve(w, r, true) })
}

func (f *front) serve(w http.ResponseWriter, r *http.Request, plain bool) {
	// /livez and /readyz answer on both sides of a port that serves HTTPS:
	// they carry no password or session and say only a word, and a load
	// balancer that checks over plain HTTP should learn whether this server
	// is ready rather than be sent to https://, which many treat as healthy.
	if f.probe(w, r) {
		return
	}
	h := f.enter(r, plain)
	if h == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"Signalith is restarting. Try again in a few seconds.","code":"restarting"}` + "\n"))
		return
	}
	defer f.leave()
	h.ServeHTTP(w, r)
}

// probe answers /livez and /readyz, which load balancers and container
// platforms ask without signing in. They answer at once, even while a
// restart holds other requests back, and say nothing more than whether
// this server is alive and should get traffic, and if not, why in a word:
// starting, restarting, down, opensearch, identity or stopping.
func (f *front) probe(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/livez" && r.URL.Path != "/readyz" {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	status, body := http.StatusOK, `{"live":true}`
	if t := r.URL.Query().Get("move"); t != "" && r.URL.Path == "/readyz" && f.confirmMove != nil {
		f.confirmMove(r, t)
	}
	if r.URL.Path == "/readyz" {
		if ok, why := f.readiness(); ok {
			body = `{"ready":true}`
		} else {
			status, body = http.StatusServiceUnavailable, `{"ready":false,"reason":"`+why+`"}`
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte(body + "\n"))
	}
	return true
}

// readiness says whether this server should get traffic now, and if
// not, why.
func (f *front) readiness() (bool, string) {
	f.mu.Lock()
	h, paused := f.h, f.paused != nil
	f.mu.Unlock()
	switch {
	case paused:
		return false, "restarting"
	case h == nil:
		return false, "starting"
	}
	if _, down := h.(downPage); down {
		return false, "down"
	}
	if f.ready != nil {
		return f.ready()
	}
	return true, ""
}

// enter waits while a restart swaps the components, and returns the
// handler to use, the one for plain HTTP when plain is true, or nil when
// the wait was too long.
func (f *front) enter(r *http.Request, plain bool) http.Handler {
	timeout := time.NewTimer(pauseLimit)
	defer timeout.Stop()
	for {
		f.mu.Lock()
		if f.paused == nil && f.h != nil {
			f.inflight++
			h := f.h
			if plain {
				h = f.plain
			}
			f.mu.Unlock()
			return h
		}
		wait := f.paused
		f.mu.Unlock()
		if wait == nil {
			return nil
		}
		select {
		case <-wait:
		case <-r.Context().Done():
			return nil
		case <-timeout.C:
			return nil
		}
	}
}

func (f *front) leave() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inflight--
	if f.inflight == 0 && f.idle != nil {
		close(f.idle)
		f.idle = nil
	}
}

// pause holds new requests back and waits up to wait for those in
// progress to finish.
func (f *front) pause(wait time.Duration) {
	f.mu.Lock()
	if f.paused == nil {
		f.paused = make(chan struct{})
	}
	if f.inflight == 0 {
		f.mu.Unlock()
		return
	}
	if f.idle == nil {
		f.idle = make(chan struct{})
	}
	idle := f.idle
	f.mu.Unlock()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-idle:
	case <-t.C:
	}
}

// resume serves requests with h, and plain HTTP on a port that serves
// HTTPS with plain, letting those held back through.
func (f *front) resume(h, plain http.Handler) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.h, f.plain = h, plain
	if f.paused != nil {
		close(f.paused)
		f.paused = nil
	}
}
