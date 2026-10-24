// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/metrics"
	"github.com/jrsamsanchez/signalith/internal/retention"
)

// The scrape endpoint for Prometheus and other OpenMetrics scrapers (see
// package metrics and docs/metrics.md). It is off until an admin turns it
// on (metrics.enabled) with a scrape token, whose SHA-256 is a setting
// (metrics.token_sha256), like the SCIM token. A scrape must then come
// over HTTPS (or from this computer), from an address metrics.allow
// lists when it lists any, within metricsRate, with the token. What it
// answers is this server's own numbers: counters, gauges and histograms
// whose labels come from fixed lists, never a user, host, address or
// anything from an event.

const (
	metricsRoute      = "GET /metrics"
	metricsViewRoute  = "GET /api/metrics"
	metricsTokenRoute = "POST /api/metrics/token"
	// metricsTokenPrefix starts every scrape token, so secret scanners
	// can find a leaked one.
	metricsTokenPrefix = "sgl_metrics_"
)

// metricsPublicRoutes check the scrape token instead of a sign-in.
var metricsPublicRoutes = []string{metricsRoute}

func (s *Server) routeMetrics(mux *http.ServeMux, api *router) {
	s.metricsRate.Each, s.metricsRate.All = metricsPerAddress, metricsAll
	mux.HandleFunc(metricsRoute, s.handleMetrics)
	// The Metrics tab of Settings.
	api.admin(metricsViewRoute, s.handleMetricsView)
	api.admin(metricsTokenRoute, s.handleMetricsToken)
}

// Scrapes allowed: per client address, and from every address together.
// A scraper every 15 seconds takes 4 a minute.
const (
	metricsPerAddress = 30 // a minute
	metricsAll        = 3600
)

// metricsFail answers a refused scrape in plain text.
func metricsFail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg + "\n"))
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	c := s.conf()
	if !c.MetricsOn() {
		// As if there were no such page: nothing tells a scanner the
		// endpoint exists until an admin turns it on.
		http.NotFound(w, r)
		return
	}
	client := s.client(r)
	if wait := s.metricsRate.take(client.Addr.String(), time.Now()); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		metricsFail(w, http.StatusTooManyRequests, "too many scrapes from this address; scrape less often")
		return
	}
	if !s.overHTTPS(r) && !client.Addr.IsLoopback() {
		metricsFail(w, http.StatusForbidden, "the metrics endpoint answers only over HTTPS, so the scrape token is never sent in the clear")
		return
	}
	if allow := c.MetricsAllowList(); len(allow) > 0 && !inPrefixes(client.Addr, allow) {
		s.noteMetricsRefusal(r, "address not allowed")
		metricsFail(w, http.StatusForbidden, "this address may not scrape metrics (metrics.allow)")
		return
	}
	scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "Bearer") || !c.MetricsToken(strings.TrimSpace(token)) {
		s.noteMetricsRefusal(r, "wrong or missing token")
		w.Header().Set("WWW-Authenticate", `Bearer realm="Signalith metrics"`)
		metricsFail(w, http.StatusUnauthorized, "the scrape token is missing or wrong")
		return
	}
	mw := metrics.NewWriter(metrics.WantsOpenMetrics(r.Header.Get("Accept")))
	s.writeMetrics(r.Context(), mw)
	w.Header().Set("Content-Type", mw.ContentType())
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(mw.Bytes())
}

// noteMetricsRefusal logs a refused scrape, at most once a minute for
// each address, with how many were refused since.
func (s *Server) noteMetricsRefusal(r *http.Request, why string) {
	c := s.client(r)
	if n := s.metricsRefused.note(c.Addr.String(), time.Now()); n > 0 {
		s.Log.Warn("metrics scrape refused", slices.Concat([]any{"audit", true, "why", why, "refusals", n}, c.logAttrs())...)
	}
}

// ---- what a scrape answers ----

// metricsCacheFor is how long what a scrape asks OpenSearch for is kept,
// so scrapers, however many and however often, ask it at most this often.
const metricsCacheFor = 30 * time.Second

// metricsCache is what scrapes ask OpenSearch for, kept metricsCacheFor.
type metricsCache struct {
	mu   sync.Mutex
	at   time.Time
	slow slowMetrics
}

// slowMetrics are the numbers read from OpenSearch.
type slowMetrics struct {
	status     string // green, yellow, red or unreachable
	blocked    *bool  // a write block (a full disk); nil when unknown
	shards     int
	shardLimit int
	retention  *retention.MetricsView
}

// opensearchStatuses are the status label's values.
var opensearchStatuses = []string{"green", "yellow", "red", "unreachable", "unknown"}

func (s *Server) slowMetrics(ctx context.Context) slowMetrics {
	c := &s.metricsSlow
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && time.Since(c.at) < metricsCacheFor {
		return c.slow
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var out slowMetrics
	if s.Backend != nil {
		status, err := s.Backend.Health(ctx)
		switch {
		case err != nil:
			out.status = "unreachable"
		case slices.Contains(opensearchStatuses[:3], status):
			out.status = status
		default:
			out.status = "unknown"
		}
		if b, ok := s.Backend.(writeBlocker); ok && err == nil {
			if says, berr := b.WriteBlocks(ctx); berr == nil {
				blocked := len(says) > 0
				out.blocked = &blocked
			}
		}
		if oc, ok := s.Backend.(osCluster); ok && err == nil {
			if used, limit, serr := oc.ShardRoom(ctx); serr == nil && limit > 0 {
				out.shards, out.shardLimit = used, limit
			}
		}
	}
	if s.Retention != nil {
		v := s.Retention.Metrics(ctx)
		out.retention = &v
	}
	c.slow, c.at = out, time.Now()
	return out
}

// runsJobs reports whether this server runs the background jobs.
func (s *Server) runsJobs() bool {
	if s.Cluster != nil {
		return s.Cluster.RunsJobs()
	}
	return s.conf().Detections.Scheduler
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func unixSeconds(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

func (s *Server) writeMetrics(ctx context.Context, w *metrics.Writer) {
	w.Info("signalith_build", "The Signalith version this server runs.",
		metrics.Label{Name: "version", Value: s.Version}, metrics.Label{Name: "goversion", Value: runtime.Version()})
	if !s.Started.IsZero() {
		w.Gauge("signalith_start_time_seconds", "When this server started, in Unix seconds.", metrics.L(unixSeconds(s.Started)))
	}
	w.Gauge("signalith_jobs_holder", "1 when this server runs the background jobs (detections, retention, feeds), else 0.", metrics.L(boolValue(s.runsJobs())))

	// Ingest: every pipeline of this server, every tenant's included.
	m := ingest.Metrics()
	var events []metrics.Sample
	for _, e := range m.Events {
		events = append(events,
			metrics.L(float64(e.Indexed), "intake", e.Intake, "result", "indexed"),
			metrics.L(float64(e.Rejected), "intake", e.Intake, "result", "rejected"),
			metrics.L(float64(e.Failed), "intake", e.Intake, "result", "failed"))
	}
	w.Counter("signalith_ingest_events", "Events written to OpenSearch, by how they arrived (intake) and the outcome: indexed, rejected by OpenSearch, or failed with the whole write.", events...)
	var received, retimed, dropped float64
	var lastIndexed time.Time
	for _, p := range s.pipelines() {
		st := p.Stats()
		received += float64(st.Received)
		retimed += float64(st.Retimed)
		dropped += float64(st.FieldsDropped)
		if st.LastIndexed.After(lastIndexed) {
			lastIndexed = st.LastIndexed
		}
	}
	w.Counter("signalith_ingest_events_received", "Events received from agents, senders and syslog, before they are written.", metrics.L(received))
	w.Counter("signalith_ingest_events_retimed", "Events filed under the time they arrived, because their own time was too old or too far ahead.", metrics.L(retimed))
	w.Counter("signalith_ingest_fields_dropped", "Fields left out of events: invalid names, too many fields, or too many new field names in a day.", metrics.L(dropped))
	if !lastIndexed.IsZero() {
		w.Gauge("signalith_ingest_last_indexed_timestamp_seconds", "When this server last stored an event, in Unix seconds.", metrics.L(unixSeconds(lastIndexed)))
	}
	var reasons []metrics.Sample
	for _, r := range ingest.MetricRejections {
		reasons = append(reasons, metrics.L(float64(m.Rejections[r]), "reason", r))
	}
	w.Counter("signalith_opensearch_rejected_events", "Events OpenSearch turned away, by why: too_many_requests (429, full queues), shard_limit, read_only (a block, as when the disk is full), mapping, unavailable or other.", reasons...)
	var failures []metrics.Sample
	for _, r := range ingest.MetricWriteFailures {
		failures = append(failures, metrics.L(float64(m.WriteFailures[r]), "reason", r))
	}
	w.Counter("signalith_opensearch_bulk_failures", "Writes of a batch of events to OpenSearch that failed as a whole, by why.", failures...)
	w.Histogram("signalith_opensearch_bulk_duration_seconds", "How long writing a batch of events to OpenSearch took.", m.BulkSeconds)
	if s.Pipeline != nil {
		capacity, held, waiting := s.Pipeline.SlotUse()
		w.Gauge("signalith_ingest_slots", "Ingest slots: how many batches this server writes at once (ingest.max_concurrent).", metrics.L(float64(capacity)))
		w.Gauge("signalith_ingest_slots_in_use", "Ingest slots held now.", metrics.L(float64(held)))
		w.Gauge("signalith_ingest_slots_waiting", "Batches waiting for an ingest slot now.", metrics.L(float64(waiting)))
	}
	w.Histogram("signalith_ingest_slot_wait_seconds", "How long batches waited for an ingest slot.", m.SlotWait)
	w.Counter("signalith_ingest_slot_timeouts", "Batches that waited too long for an ingest slot; their senders were told to try again.", metrics.L(float64(m.SlotTimeouts)))

	// Syslog.
	sy := s.Syslog.Stats()
	w.Gauge("signalith_syslog_enabled", "1 when this server receives syslog.", metrics.L(boolValue(sy.Enabled)))
	if sy.Enabled {
		w.Counter("signalith_syslog_messages_received", "Syslog messages accepted from allowed senders.", metrics.L(float64(sy.Received)))
		w.Counter("signalith_syslog_messages_dropped", "Syslog messages lost because the queue was full or the server was stopping.", metrics.L(float64(sy.Dropped)))
		w.Counter("signalith_syslog_messages_write_failed", "Syslog messages OpenSearch did not store and the spool did not keep.", metrics.L(float64(sy.WriteFailed)))
		rb := sy.RejectedBy
		w.Counter("signalith_syslog_messages_rejected", "Syslog messages and connections turned away, by why.",
			metrics.L(float64(rb.NotAllowed), "reason", "not_allowed"), metrics.L(float64(rb.TooLarge), "reason", "too_large"),
			metrics.L(float64(rb.BadFraming), "reason", "bad_framing"), metrics.L(float64(rb.TooManyConnections), "reason", "too_many_connections"),
			metrics.L(float64(rb.TooManyFromSender), "reason", "too_many_from_sender"), metrics.L(float64(rb.ProxyUntrusted), "reason", "proxy_untrusted"))
		w.Gauge("signalith_syslog_queue_depth", "Syslog messages waiting to be written now.", metrics.L(float64(sy.Queued)))
		w.Gauge("signalith_syslog_connections", "Open syslog TCP and TLS connections.", metrics.L(float64(sy.Connections)))
		w.Counter("signalith_syslog_spooled", "Syslog messages kept in the spool on disk because OpenSearch refused them for now.", metrics.L(float64(sy.Spooled)))
		w.Counter("signalith_syslog_replayed", "Syslog messages written from the spool since.", metrics.L(float64(sy.Replayed)))
		w.Counter("signalith_syslog_spool_dropped", "Syslog messages the spool dropped because it was full.", metrics.L(float64(sy.SpoolDropped)))
		w.Gauge("signalith_syslog_spool_events", "Syslog messages in the spool now.", metrics.L(float64(sy.SpoolEvents)))
		w.Gauge("signalith_syslog_spool_bytes", "Bytes in the syslog spool now.", metrics.L(float64(sy.SpoolBytes)))
		w.Gauge("signalith_syslog_spool_max_bytes", "The most bytes the syslog spool holds; 0 when there is no spool.", metrics.L(float64(sy.SpoolMaxBytes)))
	}

	// What OpenSearch and retention say, read at most every 30 seconds.
	slow := s.slowMetrics(ctx)
	if s.Backend != nil {
		var st []metrics.Sample
		for _, v := range opensearchStatuses {
			st = append(st, metrics.L(boolValue(v == slow.status), "status", v))
		}
		w.Gauge("signalith_opensearch_status", "OpenSearch's cluster health as this server sees it: 1 for the status it has.", st...)
	}
	if slow.blocked != nil {
		w.Gauge("signalith_opensearch_write_blocked", "1 when OpenSearch refuses writes because of a block, as when its disk is full.", metrics.L(boolValue(*slow.blocked)))
	}
	if slow.shardLimit > 0 {
		w.Gauge("signalith_opensearch_shards", "Shards the OpenSearch cluster holds.", metrics.L(float64(slow.shards)))
		w.Gauge("signalith_opensearch_shards_limit", "The most shards the OpenSearch cluster allows (cluster.max_shards_per_node times the data nodes).", metrics.L(float64(slow.shardLimit)))
	}
	if rv := slow.retention; rv != nil {
		w.Gauge("signalith_retention_running", "1 while a retention run or a restore is in progress on this server.", metrics.L(boolValue(rv.Running)))
		if !rv.LastRun.IsZero() {
			w.Gauge("signalith_retention_last_run_timestamp_seconds", "When the last retention run ended, in Unix seconds.", metrics.L(unixSeconds(rv.LastRun)))
			w.Gauge("signalith_retention_last_run_age_seconds", "How long ago the last retention run ended.", metrics.L(time.Since(rv.LastRun).Seconds()))
			w.Gauge("signalith_retention_last_run_errors", "Errors in the last retention run.", metrics.L(float64(rv.LastRunErrors)))
		}
		var gs []metrics.Sample
		for _, v := range []string{retention.GuardOff, retention.GuardOK, retention.GuardOver, retention.GuardUnknown, retention.GuardPaused} {
			gs = append(gs, metrics.L(boolValue(v == rv.GuardState), "state", v))
		}
		w.Gauge("signalith_retention_disk_guard_state", "The disk guard now: 1 for its state (off, ok, over its limit, unknown, or paused because the retention settings have errors).", gs...)
		w.Gauge("signalith_retention_disk_guard_waiting", "1 while the disk guard waits for the next scheduled run, after one that could not get the disk under its limit.", metrics.L(boolValue(rv.GuardPausedRun)))
		if rv.GuardLimit > 0 {
			w.Gauge("signalith_retention_disk_guard_limit_percent", "The disk use above which the disk guard deletes the oldest days.", metrics.L(float64(rv.GuardLimit)))
		}
		if rv.DiskPercent >= 0 {
			w.Gauge("signalith_opensearch_disk_used_percent", "How full the fullest OpenSearch data disk is, in percent.", metrics.L(rv.DiskPercent))
		}
	}
}

// pipelines are the ingest pipelines of this server: its own and those
// of the tenants it runs.
func (s *Server) pipelines() []*ingest.Pipeline {
	var out []*ingest.Pipeline
	if s.Pipeline != nil {
		out = append(out, s.Pipeline)
	}
	if s.TenantRuntime != nil {
		for _, t := range s.TenantRuntime.Servers() {
			if t != nil && t.Pipeline != nil && t.Pipeline != s.Pipeline {
				out = append(out, t.Pipeline)
			}
		}
	}
	return out
}

// ---- the Metrics tab of Settings ----

// handleMetricsView is what the Metrics tab shows: whether the endpoint
// answers, the address to scrape and the settings. Never a token.
func (s *Server) handleMetricsView(w http.ResponseWriter, r *http.Request) {
	saved, err := s.savedSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	running := s.conf()
	scrape := strings.TrimRight(saved.Config.Server.PublicURL, "/") + "/metrics"
	warning := ""
	if strings.HasPrefix(scrape, "http://") {
		warning = "Scrapes are answered only over HTTPS, or from this server itself. Turn HTTPS on under Settings > Server, or scrape from this server."
	}
	allow := saved.Config.Metrics.Allow
	if allow == nil {
		allow = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"on":         running.MetricsOn(),
		"enabled":    saved.Config.Metrics.Enabled,
		"token_set":  saved.Config.Metrics.TokenSHA256 != "",
		"allow":      allow,
		"scrape_url": scrape,
		"warning":    warning,
		"demo":       running.DemoOn(),
		"editable":   s.Config.Path() != "",
	})
}

// handleMetricsToken makes a new scrape token: the token, shown once, and
// its SHA-256, which the page saves as metrics.token_sha256. Nothing
// changes until it is saved, so the token in use keeps working until
// then.
func (s *Server) handleMetricsToken(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	token := metricsTokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(token))
	s.audit(r, "metrics scrape token created", "saved", false)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "sha256": hex.EncodeToString(sum[:]), "created": time.Now().UTC()})
}
