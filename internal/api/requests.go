package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// Shared is the shared configuration in OpenSearch as the API uses it: on
// a member of the cluster, the threat intel feeds and the retention
// policies are shared, any member changes them, and work only the server
// that runs the background jobs does (a feed download, a retention run)
// is asked of it as a request.
type Shared interface {
	// Content reports whether this server takes the feeds and retention
	// policies from the shared settings.
	Content() bool
	// Writable says why the shared settings cannot be changed on this
	// server now (a *shared.PausedError), or nil when they can.
	Writable() error
	// Submit makes a request of type typ for the server that runs the
	// background jobs, by the user by.
	Submit(ctx context.Context, typ string, args any, by string) (*shared.Request, error)
	// Request reads a request; false when there is none with that id.
	Request(ctx context.Context, id string) (*shared.Request, bool, error)
}

func (s *Server) routeRequests(api *router) {
	// Requests are made by the admin routes that start them (feed
	// downloads, retention runs), so following one is for admins too.
	api.admin("GET /api/requests/{id}", s.handleRequest)
}

var errNoRequests = errors.New("requests to other servers are not available on this server: it is not a member of a cluster")

// sharedContent reports whether the feeds and retention policies are
// shared on this server now.
func (s *Server) sharedContent() bool {
	return s.Shared != nil && s.Shared.Content()
}

// leads reports whether this server runs the background jobs now, so
// work they do can run here at once.
func (s *Server) leads() bool {
	if s.Cluster == nil {
		return s.conf() != nil && s.conf().Detections.Scheduler
	}
	return s.Cluster.RunsJobs()
}

// sharedWritable refuses a change of the shared settings while they
// cannot be changed on this server.
func (s *Server) sharedWritable(w http.ResponseWriter) bool {
	if err := s.Shared.Writable(); err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return false
	}
	return true
}

// submit asks the server that runs the background jobs to do typ, and
// answers 202 with the request's id, which GET /api/requests/{id}
// follows.
func (s *Server) submit(w http.ResponseWriter, r *http.Request, typ string, args any, out map[string]any) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	req, err := s.Shared.Submit(ctx, typ, args, userOf(r))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	if out == nil {
		out = map[string]any{}
	}
	out["request_id"] = req.ID
	if s.Cluster != nil {
		out["queued_on"] = s.Cluster.JobHolder()
	}
	s.Log.Info("asked the server that runs the background jobs to do work", "request", req.ID, "type", typ, "by", userOf(r))
	writeJSON(w, http.StatusAccepted, out)
}

// sharedError answers the errors of a change of the shared settings:
// a change someone else made first (412), and settings that cannot be
// changed or read now (503). It reports whether err was one of them.
func sharedError(w http.ResponseWriter, err error) bool {
	var stale *shared.StaleError
	var paused *shared.PausedError
	switch {
	case errors.As(err, &stale):
		writeJSON(w, http.StatusPreconditionFailed, staleBody(err, stale))
	case errors.Is(err, intel.ErrFeedStale):
		writeError(w, http.StatusPreconditionFailed, err)
	case errors.As(err, &paused), errors.Is(err, intel.ErrFeedsUnavailable), errors.Is(err, clustercfg.ErrPoliciesUnavailable):
		writeError(w, http.StatusServiceUnavailable, err)
	default:
		return false
	}
	return true
}

// staleBody is the body of a 412 for err, a change refused as stale:
// who changed it, where and when, so a page can say so in its own words.
func staleBody(err error, stale *shared.StaleError) map[string]any {
	body := map[string]any{"error": err.Error(), "code": "stale"}
	if stale.By != "" {
		body["changed_by"] = stale.By
	}
	if stale.Node != "" {
		body["changed_on"] = stale.Node
	}
	if stale.At != "" {
		body["changed_at"] = stale.At
	}
	return body
}

// handleRequest returns a request: its state, progress and result.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	if s.Shared == nil {
		writeError(w, http.StatusNotFound, errNoRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	req, ok, err := s.Shared.Request(ctx, r.PathValue("id"))
	switch {
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, err)
	case !ok:
		writeError(w, http.StatusNotFound, errors.New("there is no such request; finished requests are kept for 7 days"))
	default:
		writeJSON(w, http.StatusOK, req)
	}
}
