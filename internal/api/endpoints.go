package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/endpoint/checks"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// The Endpoints page: hosts running osquery that report to Signalith,
// what they collect, and live queries.
func (s *Server) routeEndpoints(api *router) {
	// Analysts see the hosts and what they collect.
	api.analyst("GET /api/endpoints", s.handleEndpoints)
	api.analyst("GET /api/endpoints/{id}", s.handleEndpoint)
	api.analyst("GET /api/endpoints/settings", s.handleEndpointSettings)
	api.analyst("GET /api/endpoints/checks", s.handleEndpointChecks)
	// Changing what every host collects, removing hosts and running SQL
	// on them (which can read any file the host's osquery can) are for
	// admins.
	api.admin("PUT /api/endpoints/settings", s.handleSaveEndpointSettings)
	api.admin("DELETE /api/endpoints/{id}", s.handleRemoveEndpoint)
	api.admin("GET /api/endpoints/blocked", s.handleBlockedEndpoints)
	api.admin("DELETE /api/endpoints/blocked/{host}", s.handleUnblockEndpoint)
	api.admin("POST /api/endpoints/queries", s.handleNewLiveQuery)
	api.admin("GET /api/endpoints/queries/{id}", s.handleLiveQuery)
}

// onlineWindow is how long after its last contact a host counts as
// online. Hosts poll for live queries every 10 seconds and send results
// every 10, so a few minutes of silence means it is off or cut off.
const onlineWindow = 3 * time.Minute

// endpointView is a host as the page shows it.
type endpointView struct {
	*endpoint.Node
	Online     bool  `json:"online"`
	SeenAgoSec int64 `json:"seen_ago_sec"`
}

func (s *Server) endpointsMissing(w http.ResponseWriter) bool {
	if s.Endpoints == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("endpoint management is not running on this server"))
		return true
	}
	return false
}

func view(n *endpoint.Node, now time.Time) endpointView {
	ago := now.Sub(n.LastSeen)
	return endpointView{Node: n, Online: ago < onlineWindow, SeenAgoSec: int64(max(ago, 0) / time.Second)}
}

func (s *Server) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	if s.endpointsMissing(w) {
		return
	}
	nodes, err := s.Endpoints.Nodes(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	now := time.Now()
	out := make([]endpointView, 0, len(nodes))
	sum := map[string]int{"total": len(nodes), "online": 0, endpoint.Windows: 0, endpoint.Linux: 0, endpoint.Darwin: 0}
	for _, n := range nodes {
		v := view(n, now)
		if v.Online {
			sum["online"]++
		}
		sum[n.Platform]++
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": out, "summary": sum, "online_window_sec": int(onlineWindow / time.Second)})
}

func (s *Server) handleEndpoint(w http.ResponseWriter, r *http.Request) {
	if s.endpointsMissing(w) {
		return
	}
	n, err := s.Endpoints.Node(r.Context(), r.PathValue("id"))
	if errors.Is(err, endpoint.ErrNotFound) {
		writeError(w, http.StatusNotFound, errors.New("no such host; it may have been removed"))
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	res, err := s.Endpoints.HostCheckResults(r.Context(), n.ID)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	var list []hostCheck
	for _, c := range checks.For(n.Platform) {
		hc := hostCheck{Check: checkInfo(c), Result: "pending"}
		if r, ok := res[c.ID]; ok {
			hc.Result, hc.Detail, hc.At = r.Result, r.Detail, r.At
		}
		list = append(list, hc)
	}
	writeJSON(w, http.StatusOK, map[string]any{"endpoint": view(n, time.Now()), "checks": list})
}

// checkView describes a configuration check for the page.
type checkView struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Platform    string   `json:"platform"`
	Severity    string   `json:"severity"`
	RuleID      string   `json:"rule_id,omitempty"`
	References  []string `json:"references,omitempty"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
}

func checkInfo(c checks.Check) checkView {
	return checkView{c.ID, c.Title, c.Platform, c.Severity, c.RuleID, c.References, c.Description, c.Remediation}
}

// hostCheck is one check's latest result on one host; "pending" until the
// host first reports it.
type hostCheck struct {
	Check  checkView `json:"check"`
	Result string    `json:"result"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at,omitzero"`
}

// handleEndpointChecks lists every configuration check with how many hosts
// pass and fail it, and the hosts that fail.
func (s *Server) handleEndpointChecks(w http.ResponseWriter, r *http.Request) {
	if s.endpointsMissing(w) {
		return
	}
	nodes, err := s.Endpoints.Nodes(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	all, err := s.Endpoints.Checks(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	type failing struct {
		ID       string `json:"id"`
		Hostname string `json:"hostname"`
		Detail   string `json:"detail,omitempty"`
	}
	type row struct {
		checkView
		Counts  map[string]int `json:"counts"`
		Failing []failing      `json:"failing"`
	}
	set, _ := s.Endpoints.CachedSettings(r.Context())
	byPlatform := map[string][]*endpoint.Node{}
	for _, n := range nodes {
		byPlatform[n.Platform] = append(byPlatform[n.Platform], n)
	}
	rows := []row{}
	totals := map[string]int{"pass": 0, "fail": 0, "n/a": 0, "error": 0, "pending": 0}
	for _, c := range checks.All() {
		rw := row{checkView: checkInfo(c), Counts: map[string]int{"pass": 0, "fail": 0, "n/a": 0, "error": 0, "pending": 0}, Failing: []failing{}}
		for _, n := range byPlatform[c.Platform] {
			res, ok := all[n.ID].Results[c.ID]
			if !ok {
				rw.Counts["pending"]++
				totals["pending"]++
				continue
			}
			rw.Counts[res.Result]++
			totals[res.Result]++
			if res.Result == "fail" {
				rw.Failing = append(rw.Failing, failing{n.ID, n.Hostname, res.Detail})
			}
		}
		rows = append(rows, rw)
	}
	writeJSON(w, http.StatusOK, map[string]any{"checks": rows, "totals": totals, "enabled": set.Checks, "hosts": len(nodes)})
}

func (s *Server) handleEndpointSettings(w http.ResponseWriter, r *http.Request) {
	if s.endpointsMissing(w) {
		return
	}
	set, v, err := s.Endpoints.Settings(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": set, "version": v.String(), "defaults": endpoint.DefaultSettings()})
}

func (s *Server) handleSaveEndpointSettings(w http.ResponseWriter, r *http.Request) {
	if s.endpointsMissing(w) {
		return
	}
	var req struct {
		Settings endpoint.Settings `json:"settings"`
		Version  string            `json:"version"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	_, cur, err := s.Endpoints.Settings(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	// The page sends the version it read; a save from someone else since
	// then is not overwritten.
	if req.Version != cur.String() {
		writeError(w, http.StatusConflict, errors.New("someone else saved these settings since you opened them; reload to see their changes"))
		return
	}
	set := req.Settings
	set.UpdatedBy = userOf(r)
	if err := s.Endpoints.SaveSettings(r.Context(), set, cur); err != nil {
		var bad *endpoint.InputError
		switch {
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, errors.New("someone else saved these settings since you opened them; reload to see their changes"))
		case errors.As(err, &bad):
			writeError(w, http.StatusBadRequest, err)
		default:
			writeError(w, http.StatusBadGateway, err)
		}
		return
	}
	s.audit(r, "endpoint settings saved", "fim", set.FIM, "inventory_minutes", set.InventoryMinutes)
	s.handleEndpointSettings(w, r)
}

func (s *Server) handleRemoveEndpoint(w http.ResponseWriter, r *http.Request) {
	if s.endpointsMissing(w) {
		return
	}
	block := r.URL.Query().Get("block") == "true"
	n, err := s.Endpoints.Remove(r.Context(), r.PathValue("id"), block, userOf(r))
	if errors.Is(err, endpoint.ErrNotFound) {
		writeError(w, http.StatusNotFound, errors.New("no such host; it may have been removed already"))
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.audit(r, "endpoint removed", "host", n.Hostname, "endpoint", n.ID, "blocked", block)
	writeJSON(w, http.StatusOK, map[string]any{"removed": n.ID, "blocked": block})
}

func (s *Server) handleBlockedEndpoints(w http.ResponseWriter, r *http.Request) {
	if s.endpointsMissing(w) {
		return
	}
	b, err := s.Endpoints.BlockedHosts(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"blocked": b})
}

func (s *Server) handleUnblockEndpoint(w http.ResponseWriter, r *http.Request) {
	if s.endpointsMissing(w) {
		return
	}
	host := r.PathValue("host")
	if err := s.Endpoints.Unblock(r.Context(), host); err != nil {
		if errors.Is(err, endpoint.ErrNotFound) {
			writeError(w, http.StatusNotFound, errors.New("that host is not blocked"))
			return
		}
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.audit(r, "endpoint unblocked", "host_identifier", host)
	writeJSON(w, http.StatusOK, map[string]any{"unblocked": host})
}

func (s *Server) handleNewLiveQuery(w http.ResponseWriter, r *http.Request) {
	if s.endpointsMissing(w) {
		return
	}
	var req struct {
		SQL string `json:"sql"`
		// Targets are node IDs; All sends to every host, or every host of
		// Platform when it is set.
		Targets  []string `json:"targets"`
		All      bool     `json:"all"`
		Platform string   `json:"platform"`
		// Online sends only to hosts seen in the last few minutes, so the
		// results do not wait on hosts that are off.
		Online bool `json:"online"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	nodes, err := s.Endpoints.Nodes(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	want := map[string]bool{}
	for _, id := range req.Targets {
		want[id] = true
	}
	now := time.Now()
	var targets []string
	for _, n := range nodes {
		switch {
		case req.All && req.Platform != "" && n.Platform != req.Platform:
			continue
		case !req.All && !want[n.ID]:
			continue
		case req.Online && !view(n, now).Online:
			continue
		}
		targets = append(targets, n.ID)
	}
	if len(targets) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("none of the chosen hosts is enrolled (and online, when asked)"))
		return
	}
	q, err := s.Endpoints.NewLiveQuery(r.Context(), req.SQL, targets, userOf(r))
	if err != nil {
		var bad *endpoint.InputError
		if errors.As(err, &bad) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.audit(r, "live query sent", "query", q.ID, "hosts", len(targets), "sql", q.SQL)
	writeJSON(w, http.StatusOK, q)
}

func (s *Server) handleLiveQuery(w http.ResponseWriter, r *http.Request) {
	if s.endpointsMissing(w) {
		return
	}
	q, res, err := s.Endpoints.LiveQuery(r.Context(), r.PathValue("id"))
	if errors.Is(err, endpoint.ErrNotFound) {
		writeError(w, http.StatusNotFound, errors.New("no such live query"))
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"query": q, "results": res, "expired": time.Now().After(q.ExpiresAt)})
}
