// Package api serves the REST API and the embedded web UI.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agents"
	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/clientaddr"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/redact"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/sample"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/syslog"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Backend is what the API needs from OpenSearch beyond searching.
type Backend interface {
	Health(ctx context.Context) (string, error)
	Mapping(ctx context.Context, pattern string) (map[string]string, error)
}

// Server wires the API together.
type Server struct {
	Config   *config.Config
	Engine   *search.Engine
	Pipeline *ingest.Pipeline
	Backend  Backend
	// Detections, Scheduler and Findings enable detections and the
	// findings queue; when nil those endpoints return 503.
	Detections *detect.Library
	Scheduler  *detect.Scheduler
	Findings   findings.Store
	// Assets holds the asset and identity lists; nil disables them.
	Assets *assets.Store
	// Intel holds threat intel indicators and Feeds downloads them; nil
	// Intel disables the threat intel endpoints.
	Intel *intel.Store
	Feeds *intel.Feeds
	// Notify backs the Notifications page; nil disables it.
	Notify *Notify
	// Dashboards holds custom dashboards; nil disables them (the built-in
	// posture dashboard still works).
	Dashboards *dashboards.Store
	// Cases holds investigations; nil disables them.
	Cases cases.Store
	// Respond runs response actions; nil disables them.
	Respond *respond.Runner
	// Playbooks backs the Playbooks and Approvals pages; nil disables
	// them.
	Playbooks *Playbooks
	// Retention enforces data retention policies; nil disables the Data
	// retention page.
	Retention *retention.Manager
	// Endpoints manages the hosts that run osquery (the Endpoints page and
	// osquery's remote API); nil disables them.
	Endpoints *endpoint.Store
	// Sample loads and removes the one-click sample data; nil disables the
	// sample-data card and its endpoints.
	Sample *sample.Loader
	// Background is the context of work a request starts that runs on
	// after it, such as a sample-data load: it ends when the process stops
	// (not at a restart in place), so that work can stop cleanly and say
	// so. nil is context.Background().
	Background context.Context
	// Assistant is an optional AI model for plain-English questions.
	Assistant *assistant.Client
	UI        fs.FS // web UI files; nil disables the UI
	Log       *slog.Logger
	Version   string

	// Syslog is the syslog receiver, for its stats; nil when it is off.
	Syslog *syslog.Receiver
	// TLS is the HTTPS certificate, for the CA agents and browsers trust;
	// nil when Signalith does not serve HTTPS itself.
	TLS *tlsauto.Manager
	// Runtime overrides what api/health says about the system the server
	// runs on; nil looks it up.
	Runtime *Runtime

	// Sessions and Limiter back the sign-in page; nil uses defaults.
	Sessions *auth.Sessions
	Limiter  *auth.Limiter
	// KnownBrowsers signs the cookie that marks a browser as one that
	// signed in to an account before (see auth.Limiter); nil makes a key
	// kept in memory only.
	KnownBrowsers *auth.BrowserKey
	// Users holds local users and directory users seen at sign-in, and
	// Directory the LDAP or Active Directory sign-in settings. nil keeps
	// them in memory only.
	Users     *users.Store
	Directory *users.Directory

	// DirectoryRecheck is how often signed-in directory users are looked
	// up again; 0 means every 5 minutes.
	DirectoryRecheck time.Duration

	// Restarter restarts the server with the settings saved on the
	// Settings page; nil means the page cannot restart it. Started is when
	// the process started, for the page's uptime.
	Restarter Restarter
	Started   time.Time
	// Pages keeps the settings saved on the Settings page; nil keeps them
	// in the settings file next to Config (config.PageFile).
	Pages config.PageStore
	// Cluster is this server among those that share its OpenSearch: it
	// says which one runs the background jobs. nil means this server runs
	// them when detections.scheduler is on, and lists no servers.
	Cluster Cluster
	// Security runs the Security page's checks and keeps the last
	// report; it carries over a restart in place. nil makes one.
	Security *SecurityChecker

	authOnce     sync.Once
	creds        credCache  // recently checked Basic credentials
	routes       []route    // every API route and its role, from Handler
	caseMu       sync.Mutex // serializes case changes
	checksMu     sync.Mutex
	dirChecks    map[string]dirCheck // when each directory user was last checked
	dirSlotsOnce sync.Once
	dirSlots     chan struct{}  // limits directory connections at once
	background   sync.WaitGroup // directory checks still running
	settingsMu   sync.Mutex     // serializes saves on the Settings page
	testMu       sync.Mutex     // one connection test at a time
	sampleJob    sampleJob      // the one running sample-data load or remove
	// live holds Config with the settings saved on the Settings page that
	// apply at once, and liveAI the assistant they give.
	live   atomic.Pointer[config.Config]
	liveAI atomic.Pointer[liveModel]

	// legacyProxies are reverse proxies believed only because the config
	// predates HTTPS by default (see viaTrustedProxy).
	legacyProxies addrSeen
	secOnce       sync.Once
	sec           *SecurityChecker
	caMu          sync.Mutex // one change of certificate authority at a time
	blockedLog    logOnce    // blocked osquery hosts that tried to enroll
}

// liveModel is the assistant after a change on the Settings page; nil
// when it was turned off.
type liveModel struct{ c *assistant.Client }

// conf returns the configuration in use: Config, with the settings saved
// on the Settings page that apply at once.
func (s *Server) conf() *config.Config {
	if c := s.live.Load(); c != nil {
		return c
	}
	return s.Config
}

// Running returns the configuration in use: the one the server started
// with, plus the settings applied at once from the Settings page since.
func (s *Server) Running() *config.Config { return s.conf() }

// model returns the AI assistant in use, or nil when it is off.
func (s *Server) model() *assistant.Client {
	if m := s.liveAI.Load(); m != nil {
		return m.c
	}
	return s.Assistant
}

// Handler returns the HTTP handler. Every API route is registered with
// the least role that may use it (see router); the role table is in
// docs/users.md.
func (s *Server) Handler() http.Handler {
	s.sessions()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/ingest", s.handleIngest)
	mux.HandleFunc(otlpLogsRoute, s.handleOTLPLogs)
	s.routeOsquery(mux)

	api := &router{s: s, mux: http.NewServeMux()}
	api.viewer("GET /api/health", s.handleHealth)
	// Searching and the query tools only read events.
	api.viewer("POST /api/search", s.handleSearch)
	api.viewer("POST /api/explain", s.handleExplain)
	api.viewer("POST /api/build", s.handleBuild)
	api.viewer("POST /api/parse", s.handleParse)
	api.viewer("GET /api/datamodels", s.handleDatamodels)
	api.viewer("GET /api/fields", s.handleFields)
	api.viewer("GET /api/fields/values", s.handleFieldValues)
	api.viewer("GET /api/language", s.handleLanguage)
	// Agent configs carry the ingest token.
	api.admin("GET /api/agents/config", s.handleAgentConfig)
	// Adds the address agents or syslog devices send to to the HTTPS
	// certificate.
	api.admin("POST /api/tls/names", s.handleTLSName)
	// The security checks name files, accounts and addresses on the
	// server, and the certificate authority is the server's to change.
	api.admin("GET /api/security", s.handleSecurity)
	api.admin("POST /api/security/ca", s.handleSecurityCA)
	s.routeDetections(api)
	s.routeRisk(api)
	s.routeAsk(api)
	s.routeIntel(api)
	s.routeNotify(api)
	s.routeDashboards(api)
	s.routeCases(api)
	s.routeRespond(api)
	s.routePlaybooks(api)
	s.routeUsers(api)
	s.routeRetention(api)
	s.routeSample(api)
	s.routeEndpoints(api)
	s.routeSettings(api)
	s.routeCluster(api)
	if s.UI != nil {
		api.add(route{Pattern: "GET /", Role: users.Viewer}, revalidate(staticFiles(s.UI, true)))
	}
	s.routes = api.routes
	s.routeLogin(mux)
	mux.Handle("/", s.requireUser(api.mux))
	return limitBodies(s.securityHeaders(s.guardAPI(mux)))
}

// guardAPI makes sure no /api/ route escapes sign-in: a route registered
// straight on the outer mux, rather than with a role on the router, is
// admin-only unless it is one of publicRoutes.
func (s *Server) guardAPI(mux *http.ServeMux) http.Handler {
	guarded := s.requireUser(s.allow(route{Pattern: "(outer mux)", Role: users.Admin, Unclassified: true}, mux))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if _, pattern := mux.Handler(r); pattern != "" && pattern != "/" && !slices.Contains(publicRoutes, pattern) {
				guarded.ServeHTTP(w, r)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	body := map[string]any{"error": err.Error()}
	var qe *query.Error
	if errors.As(err, &qe) {
		body["error"] = qe.Msg
		body["pos"] = qe.Pos
	}
	writeJSON(w, status, body)
}

// writeSearchError answers a failed search: 400 for a query that cannot
// run as written, 503 (retry shortly) when too many searches are running,
// 429 when the user's own searches hold their share of the slots, and 502
// when OpenSearch failed.
func writeSearchError(w http.ResponseWriter, err error) {
	var qe *search.QueryError
	switch {
	case errors.As(err, &qe):
		writeError(w, http.StatusBadRequest, err)
	case errors.Is(err, search.ErrBusy):
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, err)
	case errors.Is(err, search.ErrUserBusy):
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, err)
	default:
		writeError(w, http.StatusBadGateway, err)
	}
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		return errors.New("request body must be JSON: " + err.Error())
	}
	return nil
}

func decodeJSON(b []byte, v any) error {
	if err := json.Unmarshal(b, v); err != nil {
		return errors.New("request body must be JSON: " + err.Error())
	}
	return nil
}

// ---- ingest ----

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	from := clientaddr.Parse(r.RemoteAddr)
	if !s.validToken(r) && !s.retiredTokenAccepted(w, r) {
		return
	}
	// Only agents that hold a token count: anyone can send a request.
	s.noteName(r)
	s.notePlainAgent(r)
	var res *ingest.Result
	if plaintextIngest(r) {
		// Noted once the batch is in, with the host names in its events:
		// they tell apart agents that share an address.
		defer func() {
			var hosts []string
			if res != nil {
				hosts = res.Hosts
			}
			s.Pipeline.NotePlaintext(from, hosts)
		}()
	}
	// The whole batch is read before a pipeline slot is taken, so a
	// sender that sends slowly holds only its connection and the bytes it
	// has sent, never a slot other agents are waiting for.
	body, release, err := s.readBatch(w, r)
	if err != nil {
		s.batchReadFailed(w, r, err)
		return
	}
	defer release()
	slot, err := s.Pipeline.Admit(r.Context(), ingestQueueWait)
	if err != nil {
		// 503 makes Fluent Bit retry later instead of dropping data.
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	defer slot()
	tag := r.Header.Get("X-Signalith-Tag")
	if tag == "" {
		tag = r.URL.Query().Get("tag")
	}
	res, err = s.Pipeline.IngestBody(r.Context(), tag, body)
	if err != nil {
		var bad *ingest.BodyError
		if errors.As(err, &bad) {
			writeError(w, bad.Status, bad)
			return
		}
		s.Log.Error("ingest failed", "err", err, "bytes", len(body))
		// 503 makes Fluent Bit retry later instead of dropping data. The
		// details, such as where OpenSearch is, stay in the server log.
		writeError(w, http.StatusServiceUnavailable, errors.New("events could not be stored right now; try again later"))
		return
	}
	if len(res.Errors) > 0 {
		s.Log.Warn("some events were rejected", "rejected", res.Rejected, "temporary", res.Temporary, "first", res.Errors[0].Reason)
	}
	if res.Temporary > 0 {
		// OpenSearch may take these later (its disk is full, or it is too
		// busy): 503 makes Fluent Bit send the batch again instead of
		// dropping it. Events already stored count as duplicates then.
		w.Header().Set("Retry-After", "30")
		writeJSON(w, http.StatusServiceUnavailable, struct {
			Error string `json:"error"`
			*ingest.Result
		}{"some events could not be stored right now; send them again later", res})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// Agent batches. The sender has proved who it is, so its batch may arrive
// more slowly than other request bodies, over a slow link: it has
// ingestReadTimeout, and while it keeps arriving (ingestProgressBytes at
// least every ingestProgressWindow) up to ingestMaxReadTime in all. A
// sender that stalls part way is cut off at the deadline. ingestQueueWait
// is how long a batch that has arrived waits for a free pipeline slot
// before the sender is told to retry. They are variables so tests can
// shorten them.
var (
	ingestReadTimeout    = 2 * time.Minute
	ingestMaxReadTime    = 10 * time.Minute
	ingestProgressWindow = 30 * time.Second
	ingestProgressBytes  = int64(16 << 10)
	ingestQueueWait      = 15 * time.Second
)

// ingestReplyTimeout is how long, once a batch has arrived, Signalith has
// to write it and reply: the server's usual write time, counted from then
// rather than from the request headers.
const ingestReplyTimeout = 10 * time.Minute

// readBatch reads an agent's request body within the ingest deadlines
// and the ingest memory budget (see ingest.Pipeline.ReadBody). Call release
// once the batch has been written.
func (s *Server) readBatch(w http.ResponseWriter, r *http.Request) (body []byte, release func(), err error) {
	rc := http.NewResponseController(w)
	in := &batchBody{ReadCloser: r.Body, rc: rc, start: time.Now()}
	in.deadline = in.start.Add(ingestReadTimeout)
	_ = rc.SetReadDeadline(in.deadline)
	sender := netip.Addr{}
	if from := clientaddr.Parse(r.RemoteAddr); !clientaddr.Shared(from, s.Config.Server.SharedList()) {
		sender = clientaddr.Key(from)
	}
	body, release, err = s.Pipeline.ReadBody(http.MaxBytesReader(w, in, ingest.MaxBodyBytes), sender, r.ContentLength)
	if err != nil {
		return nil, nil, &batchError{err: err, received: in.n, took: time.Since(in.start)}
	}
	_ = rc.SetWriteDeadline(time.Now().Add(ingestReplyTimeout))
	return body, release, nil
}

// batchError is why an agent's batch could not be read, with how much of
// it had arrived.
type batchError struct {
	err      error
	received int64
	took     time.Duration
}

func (e *batchError) Error() string { return e.err.Error() }
func (e *batchError) Unwrap() error { return e.err }

// batchReadFailed answers a batch that could not be read: 413 when it is
// too large, 408 when it did not arrive in time, and 503 (retry shortly)
// when too many batches are arriving at once.
func (s *Server) batchReadFailed(w http.ResponseWriter, r *http.Request, err error) {
	status, retry, msg := s.batchFailure(r, err)
	if retry != "" {
		w.Header().Set("Retry-After", retry)
	}
	writeError(w, status, msg)
}

// batchFailure is how to answer a batch that could not be read: the
// status, the Retry-After header ("" for none) and the message.
func (s *Server) batchFailure(r *http.Request, err error) (int, string, error) {
	var tooBig *http.MaxBytesError
	var bad *ingest.BodyError
	var be *batchError
	errors.As(err, &be)
	switch {
	case errors.As(err, &tooBig):
		return http.StatusRequestEntityTooLarge, "", fmt.Errorf("the request body is larger than %d MB; send smaller batches", ingest.MaxBodyBytes>>20)
	case errors.As(err, &bad):
		return bad.Status, "", bad
	case errors.Is(err, ingest.ErrBusy), errors.Is(err, ingest.ErrSenderBusy):
		return http.StatusServiceUnavailable, "5", errors.Unwrap(err)
	case errors.Is(err, os.ErrDeadlineExceeded) && be != nil:
		took := be.took.Round(time.Second)
		s.warnSlowBatch("an agent batch took too long to arrive and was refused; the agent will send it again (logged at most once a minute)",
			"client", r.RemoteAddr, "received_bytes", be.received, "took", took.String())
		return http.StatusRequestTimeout, "", fmt.Errorf("the batch took too long to arrive (%d KB in %s). A batch must arrive within %s, "+
			"or within %s while at least %d KB arrives every %s. Send smaller batches (for example a lower Flush in Fluent Bit's [SERVICE] section) or check the network",
			be.received>>10, took, ingestReadTimeout, ingestMaxReadTime, ingestProgressBytes>>10, ingestProgressWindow)
	default:
		return http.StatusBadRequest, "", fmt.Errorf("the request body could not be read: %w", errors.Unwrap(err))
	}
}

var lastSlowBatchWarning atomic.Int64

// warnSlowBatch logs at most once a minute.
func (s *Server) warnSlowBatch(msg string, args ...any) {
	now := time.Now().UnixNano()
	prev := lastSlowBatchWarning.Load()
	if s.Log == nil || (prev != 0 && now-prev < int64(time.Minute)) || !lastSlowBatchWarning.CompareAndSwap(prev, now) {
		return
	}
	s.Log.Warn(msg, args...)
}

// batchBody gives an agent's batch more time while it keeps arriving:
// each ingestProgressBytes received moves the read deadline to at least
// ingestProgressWindow from then, but never past ingestMaxReadTime after
// the batch began.
type batchBody struct {
	io.ReadCloser
	rc              *http.ResponseController
	start, deadline time.Time
	n, sinceMove    int64
}

func (b *batchBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n += int64(n)
	b.sinceMove += int64(n)
	// Not once the body has ended: the deadline is lifted then (see
	// deadlineBody), and one set again would cancel the request when it
	// passed.
	if err == nil && b.sinceMove >= ingestProgressBytes {
		b.sinceMove = 0
		next := time.Now().Add(ingestProgressWindow)
		if last := b.start.Add(ingestMaxReadTime); next.After(last) {
			next = last
		}
		if next.After(b.deadline) {
			b.deadline = next
			_ = b.rc.SetReadDeadline(next)
		}
	}
	return n, err
}

func (s *Server) validToken(r *http.Request) bool {
	tok := bearerToken(r)
	if tok == "" {
		return false
	}
	for _, t := range s.conf().Ingest.Tokens {
		if subtle.ConstantTimeCompare([]byte(t), []byte(tok)) == 1 {
			return true
		}
	}
	return false
}

func bearerToken(r *http.Request) string {
	return strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
}

// retiredTokenAccepted decides on a batch whose token is not one of this
// server's, and answers it when it is refused.
//
// The Docker quick start used to give every agent the same example token,
// change-this-ingest-token, over plain HTTP. On a Docker quick start
// upgraded from such a version (see config.Config.OldToken), agents still
// sending it over plain HTTP are accepted while agents on plain HTTP are,
// as other agents set up for http:// are, and the Health page lists them
// to update. There, and while Signalith has not yet found out whether the
// quick start was upgraded, it is otherwise refused with 503, which
// Fluent Bit keeps and sends again. Everywhere else, a quick start
// installed new included, it is a wrong token like any other: anyone can
// look it up. A wrong token is refused with 401. Refused agents are noted
// for the Health page.
func (s *Server) retiredTokenAccepted(w http.ResponseWriter, r *http.Request) bool {
	from := clientaddr.Parse(r.RemoteAddr)
	if s.oldTokenAgent(r) {
		if s.conf().OldToken() == config.OldTokenAccepted && plaintextIngest(r) {
			return true
		}
		s.Pipeline.NoteRefused(from, ingest.RefusedOldToken)
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusServiceUnavailable, errors.New("this agent sends the example ingest token from an older docker-compose.yml, "+
			"which this server no longer accepts; the agent keeps its events and sends them again. Get a new configuration for it from the Add data page"))
		return false
	}
	s.Pipeline.NoteRefused(from, ingest.RefusedToken)
	writeError(w, http.StatusUnauthorized, errors.New("missing or invalid ingest token"))
	return false
}

// oldTokenAgent reports whether r carries the example ingest token on a
// Docker quick start that may still have agents sending it: one upgraded
// from a version that gave it to them, or one not yet known to be new.
// Such a batch is answered as one from an agent of this server's.
func (s *Server) oldTokenAgent(r *http.Request) bool {
	if !config.IsPublicIngestToken(bearerToken(r)) || !s.inContainer() {
		return false
	}
	return s.conf().OldToken() != config.OldTokenRefused
}

// UseDockerUpgrade puts into use the decision about the example ingest
// token that Signalith made after the server started (see
// config.Config.OldToken): an upgraded Docker quick start then accepts
// its older agents at once.
func (s *Server) UseDockerUpgrade(u *config.DockerUpgrade) {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	s.live.Store(s.conf().WithDockerUpgrade(u))
	s.endOldTokenLocked()
}

// EndOldTokenIfRefused ends the example ingest token for good when the
// server starts with agents on plain HTTP refused (see endOldTokenLocked).
func (s *Server) EndOldTokenIfRefused() {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	s.endOldTokenLocked()
}

// endOldTokenLocked ends the example ingest token for good on a Docker
// quick start upgraded from a version whose agents send it, once agents
// on plain HTTP are refused: it notes when in the state folder, and the
// token is refused from then on, even if they are accepted again. The
// caller holds settingsMu.
func (s *Server) endOldTokenLocked() {
	c := s.conf()
	if c.OldToken() != config.OldTokenAccepted || c.Server.PlaintextIngest() {
		return
	}
	u := *c.DockerUpgrade()
	u.Ended = time.Now().UTC()
	dir := c.StateDir()
	if err := config.WriteDockerUpgrade(dir, &u); err != nil {
		if s.Log != nil {
			s.Log.Error("could not note in the state folder that the example ingest token change-this-ingest-token is refused for good; "+
				"it is refused until Signalith restarts, and after that while agents on plain HTTP are refused", "file", config.DockerUpgradeFileIn(dir), "err", err)
		}
	} else if s.Log != nil {
		s.Log.Info("agents on plain HTTP are refused, so the example ingest token change-this-ingest-token, which the older Docker quick start gave every agent, is refused for good",
			"audit", true, "file", config.DockerUpgradeFileIn(dir))
	}
	s.live.Store(c.WithDockerUpgrade(&u))
}

// ---- search ----

type searchRequest struct {
	Query    string `json:"query"`
	Earliest string `json:"earliest,omitempty"` // time picker; overridden by earliest= in the query
	Latest   string `json:"latest,omitempty"`
}

func (s *Server) parseRequest(w http.ResponseWriter, r *http.Request) (*query.Query, bool) {
	var req searchRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return nil, false
	}
	if strings.TrimSpace(req.Query) == "" {
		req.Query = "*"
	}
	q, err := query.Parse(req.Query)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return nil, false
	}
	if q.Earliest == "" {
		q.Earliest = req.Earliest
	}
	if q.Latest == "" {
		q.Latest = req.Latest
	}
	return q, true
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parseRequest(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	res, err := s.Engine.Execute(ctx, q)
	if err != nil {
		writeSearchError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parseRequest(w, r)
	if !ok {
		return
	}
	plan, err := s.Engine.Compile(q)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"canonical": q.String(),
		"steps":     Explain(q),
		"index":     plan.Index,
		"body":      plan.Body,
	})
}

func (s *Server) handleBuild(w http.ResponseWriter, r *http.Request) {
	var spec query.Spec
	if err := readJSON(r, &spec); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"query": query.Build(spec).String()})
}

func (s *Server) handleParse(w http.ResponseWriter, r *http.Request) {
	var req searchRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	q, err := query.Parse(req.Query)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	spec, ok := query.FromQuery(q)
	writeJSON(w, http.StatusOK, map[string]any{"spec": spec, "builder_ok": ok, "canonical": q.String()})
}

// ---- fields ----

func (s *Server) handleDatamodels(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, datamodel.Models)
}

type fieldInfo struct {
	datamodel.Field
	Indexed bool `json:"indexed"` // seen in stored data
}

func (s *Server) handleFields(w http.ResponseWriter, r *http.Request) {
	dm := r.URL.Query().Get("datamodel")
	pattern, err := s.Engine.IndexPattern(&query.Query{Datamodel: dm})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	out := map[string]*fieldInfo{}
	var order []string
	for _, f := range datamodel.FieldsFor(dm) {
		out[f.Name] = &fieldInfo{Field: f}
		order = append(order, f.Name)
	}
	if s.Backend != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if mapping, err := s.Backend.Mapping(ctx, pattern); err == nil {
			var extra []string
			for name, typ := range mapping {
				if name == ingest.SampleField {
					continue // internal marker for sample data; see the sample package
				}
				switch name {
				case "@timestamp":
					name = "_time"
				case "message":
					name = "_raw"
				}
				if fi, ok := out[name]; ok {
					fi.Indexed = true
					continue
				}
				t := "string"
				switch typ {
				case "long", "integer", "short", "byte", "double", "float", "half_float", "scaled_float":
					t = "number"
				case "date":
					t = "time"
				case "text":
					t = "text"
				}
				out[name] = &fieldInfo{Field: datamodel.Field{Name: name, Type: t, Description: "Discovered in your data"}, Indexed: true}
				extra = append(extra, name)
			}
			sort.Strings(extra)
			order = append(order, extra...)
		}
	}
	list := make([]*fieldInfo, 0, len(order))
	for _, n := range order {
		list = append(list, out[n])
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleFieldValues(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	field := v.Get("field")
	if field == "" || strings.ContainsAny(field, " |\"()") {
		writeError(w, http.StatusBadRequest, errors.New("field is required"))
		return
	}
	q := &query.Query{
		Datamodel: v.Get("datamodel"),
		Earliest:  v.Get("earliest"),
		Commands:  []query.Command{&query.Top{Limit: 10, Fields: []string{field}}},
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res, err := s.Engine.Execute(ctx, q)
	if err != nil {
		writeSearchError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res.Rows)
}

func (s *Server) handleLanguage(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"commands":  query.Commands,
		"functions": query.AggFuncs,
		"operators": []string{"=", "!=", "<", "<=", ">", ">=", "IN", "AND", "OR", "NOT"},
	})
}

// ---- agents and health ----

// handleAgentConfig writes a Fluent Bit config. server=<url> replaces
// server.public_url as the address agents send to, for when the configured
// one (often localhost) is not reachable from the hosts being set up.
// When Signalith serves HTTPS, agents send over https and check the
// server with its CA, and the certificate is made to cover the address.
func (s *Server) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	conf := s.conf()
	server := conf.Server.PublicURL
	fieldError := func(err error) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "field": "server"})
	}
	if o := v.Get("server"); o != "" {
		u, err := agents.ParseServerURL(o)
		if err != nil {
			fieldError(err)
			return
		}
		if u.Scheme == "http" && conf.Server.HTTPS() {
			fieldError(fmt.Errorf("this server only accepts agents over HTTPS; use https://%s", u.Host))
			return
		}
		server = o
	}
	u, err := agents.ParseServerURL(server)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("server.public_url: %w", err))
		return
	}
	// With HTTPS off, a certificate kept for syslog over TLS is not the
	// one agents meet (a proxy in front has its own).
	certs := s.TLS
	if !conf.Server.HTTPS() {
		certs = nil
	}
	// Building the config changes nothing: the page adds the address to
	// the certificate (POST api/tls/names) once it is entered, not while
	// it is being typed. Here it only checks that it can.
	addName := ""
	if u.Scheme == "https" && certs != nil {
		if err := certs.CanCover(u.Hostname()); err != nil {
			fieldError(err)
			return
		}
		if !certs.Covers(u.Hostname()) {
			addName = u.Hostname()
		}
	}
	token := s.agentToken()
	opts := agents.Options{
		OS:          v.Get("os"),
		ServerURL:   server,
		Token:       token,
		LinuxSource: v.Get("source"),
		Sysmon:      v.Get("sysmon") == "true",
		CollectorOS: v.Get("collector"),
		Platform:    v.Get("platform"),
	}
	if certs != nil {
		// While a new certificate authority is prepared, agents get both,
		// so they keep sending after the switch.
		opts.CA = string(certs.AgentCAPEM())
		opts.CAUnknown = opts.CA == "" && !certs.PublicCA()
		opts.OwnCA = certs.LocalCA()
		if leaf := certs.Leaf(); leaf != nil {
			opts.CertNames = leaf.DNSNames
		}
	}
	a, err := agents.Generate(opts)
	if errors.Is(err, agents.ErrNoNameToCheck) {
		fieldError(err)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	out := agentConfig{Agent: a, AddName: addName}
	if a.CA != "" {
		a.CAFingerprint = certs.Fingerprint()
		if next := certs.Next(); next != nil {
			out.NextCAFingerprint = next.Fingerprint
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// agentConfig is the answer to GET api/agents/config. AddName is the
// address the certificate does not cover yet, for the page to add.
type agentConfig struct {
	*agents.Agent
	AddName string `json:"add_name,omitempty"`
	// NextCAFingerprint is the new certificate authority's, while
	// Signalith is switching: the CA file holds both.
	NextCAFingerprint string `json:"next_ca_fingerprint,omitempty"`
}

// agentToken is the ingest token new agents get: the first that is not
// the example token from an older docker-compose.yml, which anyone can
// look up (kept only for agents that still use it).
func (s *Server) agentToken() string {
	tokens := s.conf().Ingest.Tokens
	for _, t := range tokens {
		if !config.IsPublicIngestToken(t) {
			return t
		}
	}
	if len(tokens) > 0 {
		return tokens[0]
	}
	return ""
}

// handleTLSName adds the address agents or syslog devices are being set up
// to send to to the HTTPS certificate (see tlsauto.Manager.EnsureName),
// and answers with the names it covers then.
func (s *Server) handleTLSName(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if s.TLS == nil {
		writeError(w, http.StatusConflict, errors.New("Signalith has no certificate of its own here (server.tls.mode is off), so there is nothing to add the name to"))
		return
	}
	if err := s.TLS.EnsureName(req.Name); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "field": "name"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"names": s.TLS.Names()})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	out := map[string]any{"version": s.Version, "ingest": s.Pipeline.Stats(), "syslog": s.Syslog.Stats()}
	status, err := s.Backend.Health(ctx)
	var problem, advice string
	if err != nil {
		status, problem, advice = osTrouble(err)
	}
	// No server running detections, a full disk: everyone sees those, on
	// every page.
	if s.Cluster != nil {
		if b := s.Cluster.Banners(); len(b) > 0 {
			out["cluster_banners"] = b
		}
	}
	// Everyone signed in sees whether things work. Where they run (file
	// paths, addresses, the OpenSearch URL and its errors) and the setup
	// advice is for admins, who are the ones able to change it.
	if p := principalOf(r); p == nil || !p.Role.AtLeast(users.Admin) {
		brief := map[string]any{"status": status}
		if problem != "" {
			brief["problem"] = problem
		}
		out["opensearch"] = brief
		writeJSON(w, http.StatusOK, out)
		return
	}
	out["config_file"] = s.conf().Path()
	// For the steps that turn syslog on: edit the section or add one.
	out["config_has_syslog"] = s.Config.HasSection("syslog")
	out["runtime"] = s.runtimeInfo()
	out["tls"] = s.tlsInfo()
	if sec := s.securityHealth(); sec != nil {
		out["security"] = sec
	}
	osOut := map[string]any{"status": status, "url": redact.URL(s.conf().OpenSearch.URL)}
	if err != nil {
		osOut["error"] = err.Error()
	}
	if problem != "" {
		osOut["problem"] = problem
	}
	if advice != "" {
		osOut["advice"] = advice
	}
	out["opensearch"] = osOut
	warnings := s.conf().Warnings()
	if len(s.conf().Ingest.Tokens) == 0 {
		warnings = append(warnings, "No ingest tokens are configured, so agents cannot send data. Add one under ingest.tokens.")
	}
	since := time.Now().Add(-plaintextWindow)
	docker := s.inContainer()
	if senders := s.Pipeline.PlaintextSenders(since); len(senders) > 0 {
		out["plaintext_senders"] = senders
		warnings = append(warnings, plaintextWarning(senders, docker, docker && s.conf().OldToken() == config.OldTokenAccepted))
	}
	if refused := s.Pipeline.RefusedSenders(since); len(refused) > 0 {
		out["refused_senders"] = refused
		warnings = append(warnings, refusedWarnings(refused, docker)...)
	}
	if proxies := s.legacyProxies.since(since); len(proxies) > 0 {
		warnings = append(warnings, legacyProxyWarning(proxies))
	}
	if outside := s.TLS.Outside(); len(outside) > 0 {
		warnings = append(warnings, "Signalith's HTTPS certificate leaves out "+joinAnd(outside)+": Signalith's own certificate authority only signs "+
			"the names and private network addresses it was made with, so that trusting it can't expose other websites. "+
			"See \"Names the certificate can cover\" in docs/https.md.")
	}
	if p := s.dir().Problem(); p != "" {
		warnings = append(warnings, p)
	}
	if w := s.behindWarning(time.Now()); w != "" {
		warnings = append(warnings, w)
	}
	warnings = append(warnings, s.notifyWarnings(ctx)...)
	if len(warnings) > 0 {
		out["warnings"] = warnings
	}
	writeJSON(w, http.StatusOK, out)
}

// behindWarning names the detections falling behind their schedule
// (see detect.Behind), on the server that runs them; "" when none are.
func (s *Server) behindWarning(now time.Time) string {
	if s.Scheduler == nil || s.Detections == nil || !s.conf().Detections.Scheduler || (s.Cluster != nil && !s.Cluster.RunsJobs()) {
		return ""
	}
	states := s.Scheduler.Status()
	var late []string
	for _, d := range s.Detections.List() {
		if detect.Behind(d, states[d.ID], now) {
			late = append(late, d.ID)
		}
	}
	if len(late) == 0 {
		return ""
	}
	if len(late) > 10 {
		late = append(late[:10], fmt.Sprintf("%d more", len(late)-10))
	}
	return "Detections are running behind schedule. " + joinAnd(late) + " waited more than their schedule interval for a free worker, " +
		"because slower detections held every worker. Each run searches on from where the last one stopped, up to a limit, so events are not skipped, " +
		"but findings arrive late. On the Detections page, narrow or reschedule the slow or timed-out detections."
}

// tlsInfo says how Signalith serves HTTPS, the names its certificate
// covers and, when it has one to give out, the fingerprint of the CA
// certificate agents and syslog devices check it with (GET
// /api/tls/ca.pem). own_ca says the CA is Signalith's own, which issues
// certificates for this server only.
func (s *Server) tlsInfo() map[string]any {
	t := map[string]any{"mode": s.conf().Server.TLSMode()}
	if s.TLS != nil {
		t["names"] = s.TLS.Names()
	}
	if s.TLS.CAPEM() != nil {
		t["ca_sha256"] = s.TLS.Fingerprint()
		t["own_ca"] = s.TLS.LocalCA()
	}
	if ca := s.TLS.CAInfo(); ca != nil {
		t["ca_scope"] = ca.Scope
		// When it was made, for the Settings page's "In use now".
		t["ca_made"] = ca.NotBefore
	}
	if next := s.TLS.Next(); next != nil {
		// Signalith is switching certificate authority: agents and browsers
		// get both until then.
		t["next_ca_sha256"] = next.Fingerprint
	}
	return t
}

// plaintextWindow is how far back the Health page looks for agents
// sending over plain HTTP: long enough to see agents that send rarely.
const plaintextWindow = 24 * time.Hour

// plaintextWarning names the agents still sending over plain HTTP and
// says how to move them to HTTPS. docker adds that Docker's port
// forwarding may hide the agents' own addresses, and oldToken that
// refusing them also ends the example token on an upgraded Docker quick
// start.
func plaintextWarning(senders []ingest.Sender, docker, oldToken bool) string {
	n, list := agentList(senders)
	where := "signalith.yaml"
	if docker {
		where = "signalith.yaml (deploy/docker/signalith.yaml in the Docker quick start)"
	}
	var msg string
	if n == 1 {
		msg = "An agent still sends events over plain HTTP, which anyone on the network can read: " + list + ". " +
			"On the Add data page, get a new configuration for it, which uses HTTPS, and put it on that agent. " +
			"Then refuse agents on plain HTTP on the Settings page, under HTTPS, or set server.tls.plaintext_ingest: deny in " + where + "."
	} else {
		msg = fmt.Sprintf("%d agents still send events over plain HTTP, which anyone on the network can read: %s. "+
			"On the Add data page, get a new configuration, which uses HTTPS, and put it on each of them. "+
			"Once all are updated, refuse agents on plain HTTP on the Settings page, under HTTPS, or set server.tls.plaintext_ingest: deny in %s.", n, list, where)
	}
	if oldToken {
		msg += " That also ends for good the example token change-this-ingest-token, which the older Docker quick start gave every agent and which anyone can look up."
	}
	return msg + dockerNote(senders, docker)
}

// refusedWarnings says which agents' batches were turned away and why,
// one warning for each reason.
func refusedWarnings(refused []ingest.Sender, docker bool) []string {
	by := map[string][]ingest.Sender{}
	for _, x := range refused {
		by[x.Reason] = append(by[x.Reason], x)
	}
	var out []string
	for _, reason := range []string{ingest.RefusedPlaintext, ingest.RefusedOldToken, ingest.RefusedToken} {
		list := by[reason]
		if len(list) == 0 {
			continue
		}
		n, names := agentList(list)
		agent := "An agent was"
		if n > 1 {
			agent = fmt.Sprintf("%d agents were", n)
		}
		var msg string
		switch reason {
		case ingest.RefusedPlaintext:
			msg = agent + " turned away for sending over plain HTTP (server.tls.plaintext_ingest is deny): " + names + ". " +
				"They keep their events and send them again. On the Add data page, get a new configuration, which uses HTTPS, and put it on each."
		case ingest.RefusedOldToken:
			msg = agent + " turned away for sending the example ingest token from an older docker-compose.yml: " + names + ". " +
				"They keep their events and send them again. On the Add data page, get a new configuration and put it on each."
		default:
			msg = agent + " turned away for a wrong or missing ingest token: " + names + ". " +
				"Fluent Bit drops what is refused this way. On the Add data page, get a new configuration and put it on each."
		}
		out = append(out, msg+dockerNote(list, docker))
	}
	return out
}

// agentList counts the agents in senders and names them, at most five
// addresses: an address with host names from several machines counts
// as that many agents.
func agentList(senders []ingest.Sender) (int, string) {
	n := 0
	var names []string
	for i, x := range senders {
		n += max(1, len(x.Hosts))
		if i == 5 {
			names = append(names, fmt.Sprintf("%d more", len(senders)-5))
			continue
		}
		if i > 5 {
			continue
		}
		name := x.Address
		if len(x.Hosts) > 0 {
			name += " (" + strings.Join(x.Hosts, ", ") + ")"
		}
		names = append(names, name)
	}
	return n, joinAnd(names)
}

// dockerNote explains, in Docker, why agents may share one address.
func dockerNote(senders []ingest.Sender, docker bool) string {
	if !docker {
		return ""
	}
	for _, x := range senders {
		if len(x.Hosts) > 0 {
			return " Docker's port forwarding can make every agent seem to come from one address; the names in brackets come from their events."
		}
	}
	return " Docker's port forwarding can make every agent seem to come from one address; each agent's own log (fluent-bit) shows the refusal."
}

// legacyProxyWarning names the reverse proxies believed only because the
// config predates HTTPS by default, and says how to keep them working.
func legacyProxyWarning(proxies []string) string {
	return "A reverse proxy at " + joinAnd(proxies) + " sends requests to Signalith over plain HTTP, saying the browser used HTTPS (X-Forwarded-Proto). " +
		"Signalith believes it for now only because signalith.yaml was written before HTTPS was the default. List it under Trusted reverse proxies on the Settings page, " +
		"under HTTPS, or add server.trusted_proxies: [" + strings.Join(proxies, ", ") + "] to signalith.yaml and restart Signalith."
}

// joinAnd joins a list as "a, b and c".
func joinAnd(list []string) string {
	switch len(list) {
	case 0:
		return ""
	case 1:
		return list[0]
	}
	return strings.Join(list[:len(list)-1], ", ") + " and " + list[len(list)-1]
}
