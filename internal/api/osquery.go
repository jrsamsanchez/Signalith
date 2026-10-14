package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clientaddr"
	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// osquery's TLS remote API: hosts running osquery enroll here with an
// agent token, then fetch their configuration, send results and answer
// live queries with the node key they got. The flags Add data generates
// point osquery at these routes.
const (
	osqueryEnrollRoute = "POST /api/osquery/enroll"
	osqueryConfigRoute = "POST /api/osquery/config"
	osqueryLogRoute    = "POST /api/osquery/log"
	osqueryReadRoute   = "POST /api/osquery/distributed/read"
	osqueryWriteRoute  = "POST /api/osquery/distributed/write"
)

// osqueryRoutes are public: they take an agent token (enroll) or a node
// key (the rest) instead of a signed-in user.
var osqueryRoutes = []string{osqueryEnrollRoute, osqueryConfigRoute, osqueryLogRoute, osqueryReadRoute, osqueryWriteRoute}

// maxOsquerySmall caps the requests that carry no results.
const maxOsquerySmall = 256 << 10

func (s *Server) routeOsquery(mux *http.ServeMux) {
	mux.HandleFunc(osqueryEnrollRoute, s.handleOsqueryEnroll)
	mux.HandleFunc(osqueryConfigRoute, s.handleOsqueryConfig)
	mux.HandleFunc(osqueryLogRoute, s.handleOsqueryLog)
	mux.HandleFunc(osqueryReadRoute, s.handleOsqueryRead)
	mux.HandleFunc(osqueryWriteRoute, s.handleOsqueryWrite)
}

// enrollToken checks an enroll secret and returns the ID of the token it
// is: an active agent token, or an accepted shared one (see EnrollToken).
func (s *Server) enrollToken(secret string) (string, bool) {
	return s.EnrollToken(secret)
}

// readSmall reads a request that carries no results.
func readSmall(w http.ResponseWriter, r *http.Request, v any) error {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxOsquerySmall))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// nodeInvalid tells osquery its node key is not (or no longer) valid, so
// it enrolls again.
func nodeInvalid(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusUnauthorized, map[string]any{"node_invalid": true, "error": msg})
}

func (s *Server) osqueryUnavailable(w http.ResponseWriter) bool {
	if s.Endpoints == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "endpoint management is not running on this server"})
		return true
	}
	return false
}

// osqueryNode authenticates a request by its node key.
func (s *Server) osqueryNode(w http.ResponseWriter, r *http.Request, key string) *endpoint.Node {
	n, err := s.Endpoints.Authenticate(r.Context(), key)
	switch {
	case errors.Is(err, endpoint.ErrNotFound):
		nodeInvalid(w, "unknown node key; enroll again")
		return nil
	case err == nil && !s.TokenActive(n.TokenID):
		// Checked on every request, so a revoked token ends its hosts at
		// once on every server, whatever the endpoint store has cached.
		nodeInvalid(w, "this host's agent token was revoked; enroll it again with a new token")
		return nil
	case err != nil:
		s.Log.Warn("could not look up an osquery host", "err", err)
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusServiceUnavailable, errors.New("try again later"))
		return nil
	}
	s.Endpoints.Seen(n, clientaddr.Parse(r.RemoteAddr).String())
	return n
}

func (s *Server) handleOsqueryEnroll(w http.ResponseWriter, r *http.Request) {
	if s.osqueryUnavailable(w) {
		return
	}
	var req struct {
		Secret         string `json:"enroll_secret"`
		HostIdentifier string `json:"host_identifier"`
		HostDetails    struct {
			OSVersion struct {
				Name         string `json:"name"`
				Version      string `json:"version"`
				Platform     string `json:"platform"`
				PlatformLike string `json:"platform_like"`
			} `json:"os_version"`
			Osquery struct {
				Version string `json:"version"`
			} `json:"osquery_info"`
			System struct {
				Hostname       string `json:"hostname"`
				ComputerName   string `json:"computer_name"`
				HardwareVendor string `json:"hardware_vendor"`
				HardwareModel  string `json:"hardware_model"`
				HardwareSerial string `json:"hardware_serial"`
				CPUBrand       string `json:"cpu_brand"`
				PhysicalMemory string `json:"physical_memory"`
				UUID           string `json:"uuid"`
			} `json:"system_info"`
		} `json:"host_details"`
	}
	from := clientaddr.Parse(r.RemoteAddr)
	if err := readSmall(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"node_invalid": true, "error": "the enrollment request is not valid JSON"})
		return
	}
	tokenID, ok := s.enrollToken(req.Secret)
	if !ok {
		s.Pipeline.NoteRefused(from, ingest.RefusedToken)
		s.Log.Warn("osquery enrollment refused: wrong enroll secret", "client", from.String())
		writeJSON(w, http.StatusUnauthorized, map[string]any{"node_invalid": true, "error": "the enroll secret is not an active agent token"})
		return
	}
	d := req.HostDetails
	host := cut(firstNonEmpty(d.System.Hostname, d.System.ComputerName, req.HostIdentifier), 255)
	key, id := endpoint.NewNodeKey()
	now := time.Now().UTC()
	n := &endpoint.Node{
		ID:             id,
		HostIdentifier: cut(firstNonEmpty(req.HostIdentifier, d.System.UUID), 128),
		Hostname:       host,
		Platform:       endpoint.NormalizePlatform(d.OSVersion.Platform, d.OSVersion.PlatformLike),
		OSName:         cut(d.OSVersion.Name, 128),
		OSVersion:      cut(d.OSVersion.Version, 128),
		OsqueryVersion: cut(d.Osquery.Version, 32),
		HardwareVendor: cut(d.System.HardwareVendor, 128),
		HardwareModel:  cut(d.System.HardwareModel, 128),
		Serial:         cut(d.System.HardwareSerial, 128),
		CPU:            cut(d.System.CPUBrand, 128),
		Address:        from.String(),
		TokenID:        tokenID,
		EnrolledAt:     now,
		LastSeen:       now,
	}
	if m, ok := parseInt(d.System.PhysicalMemory); ok {
		n.MemoryBytes = m
	}
	if err := s.Endpoints.Enroll(r.Context(), n); err != nil {
		if errors.Is(err, endpoint.ErrBlocked) {
			// A blocked host keeps trying every few seconds: say so once an hour.
			if s.blockedLog.due(n.HostIdentifier, time.Hour) {
				s.Log.Warn("osquery enrollment refused: host is blocked (logged once an hour per host)", "host", host, "client", from.String())
			}
			writeJSON(w, http.StatusForbidden, map[string]any{"node_invalid": true, "error": err.Error()})
			return
		}
		s.Log.Error("osquery enrollment failed", "host", host, "err", err)
		w.Header().Set("Retry-After", "30")
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"node_invalid": true, "error": "the host could not be recorded right now; osquery tries again"})
		return
	}
	s.Log.Info("osquery host enrolled", "audit", true, "host", host, "platform", n.Platform, "endpoint", id, "client", from.String())
	writeJSON(w, http.StatusOK, map[string]any{"node_key": key, "node_invalid": false})
}

func (s *Server) handleOsqueryConfig(w http.ResponseWriter, r *http.Request) {
	if s.osqueryUnavailable(w) {
		return
	}
	var req struct {
		NodeKey string `json:"node_key"`
	}
	if err := readSmall(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("not valid JSON"))
		return
	}
	n := s.osqueryNode(w, r, req.NodeKey)
	if n == nil {
		return
	}
	set, err := s.Endpoints.CachedSettings(r.Context())
	if err != nil {
		s.Log.Warn("could not read the endpoint settings", "err", err)
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusServiceUnavailable, errors.New("try again later"))
		return
	}
	cfg, hash := endpoint.Config(n.Platform, set)
	if err := s.Endpoints.NoteConfig(r.Context(), n, hash); err != nil {
		s.Log.Debug("could not note an osquery host's configuration", "err", err)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(cfg)
}

func (s *Server) handleOsqueryLog(w http.ResponseWriter, r *http.Request) {
	if s.osqueryUnavailable(w) {
		return
	}
	body, release, err := s.osqueryBody(w, r)
	if err != nil {
		return
	}
	defer release()
	var req struct {
		NodeKey string            `json:"node_key"`
		LogType string            `json:"log_type"`
		Data    []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("not valid JSON"))
		return
	}
	n := s.osqueryNode(w, r, req.NodeKey)
	if n == nil {
		return
	}
	switch req.LogType {
	case "status":
		s.osqueryStatus(r.Context(), n, req.Data)
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	case "result":
	default:
		writeJSON(w, http.StatusOK, map[string]any{}) // nothing Signalith keeps
		return
	}
	b := endpoint.ParseResults(n, req.Data, time.Now())
	if len(b.Checks) > 0 {
		if err := s.Endpoints.SaveChecks(r.Context(), n, b.Checks); err != nil {
			s.Log.Warn("could not save an osquery host's check results", "host", n.Hostname, "err", err)
		}
	}
	if b.IPs != nil {
		if err := s.Endpoints.NoteIPs(r.Context(), n, b.IPs); err != nil {
			s.Log.Debug("could not note an osquery host's addresses", "err", err)
		}
	}
	if len(b.Events) > 0 {
		slot, err := s.Pipeline.Admit(r.Context(), ingestQueueWait)
		if err != nil {
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusServiceUnavailable, err)
			return
		}
		defer slot()
		// The ID events record: a host enrolled with a shared token before
		// shared tokens had keyed IDs holds the old one, never recorded.
		who, _ := s.tokens().Lookup(n.TokenID)
		ctx := ingest.WithOrigin(r.Context(), ingest.Origin{Intake: ingest.IntakeOsquery, TokenID: who.ID,
			TokenName: who.Name, Sender: clientaddr.Parse(r.RemoteAddr).String()})
		if _, err := s.Pipeline.IngestEvents(ctx, b.Events); err != nil {
			s.Log.Error("osquery results could not be stored", "host", n.Hostname, "err", err)
			// osquery keeps the results and sends them again.
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusServiceUnavailable, errors.New("results could not be stored right now; try again later"))
			return
		}
		s.tokens().Note(who.ID, clientaddr.Parse(r.RemoteAddr).String(), len(b.Events))
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// osqueryStatus keeps osquery's latest warning or error about itself, so
// the Endpoints page can show a host that is not working right.
func (s *Server) osqueryStatus(ctx context.Context, n *endpoint.Node, lines []json.RawMessage) {
	var last string
	for _, raw := range lines {
		if len(raw) > 0 && raw[0] == '"' {
			var str string
			if json.Unmarshal(raw, &str) == nil {
				raw = json.RawMessage(str)
			}
		}
		var l struct {
			Severity json.Number `json:"severity"`
			Message  string      `json:"message"`
		}
		if json.Unmarshal(raw, &l) != nil {
			continue
		}
		// 0 info, 1 warning, 2 error, 3 fatal. Warnings are mostly about
		// watched paths that do not exist on this host, so only errors
		// count.
		if sev, err := l.Severity.Int64(); err == nil && sev >= 2 && l.Message != "" {
			last = l.Message
		}
	}
	if last != "" {
		if err := s.Endpoints.NoteError(ctx, n, last); err != nil {
			s.Log.Debug("could not note an osquery host's error", "err", err)
		}
	}
}

func (s *Server) handleOsqueryRead(w http.ResponseWriter, r *http.Request) {
	if s.osqueryUnavailable(w) {
		return
	}
	var req struct {
		NodeKey string `json:"node_key"`
	}
	if err := readSmall(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("not valid JSON"))
		return
	}
	n := s.osqueryNode(w, r, req.NodeKey)
	if n == nil {
		return
	}
	qs, err := s.Endpoints.Pending(r.Context(), n)
	if err != nil {
		s.Log.Warn("could not read live queries", "err", err)
		qs = map[string]string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"queries": qs})
}

func (s *Server) handleOsqueryWrite(w http.ResponseWriter, r *http.Request) {
	if s.osqueryUnavailable(w) {
		return
	}
	body, release, err := s.osqueryBody(w, r)
	if err != nil {
		return
	}
	defer release()
	var req struct {
		NodeKey  string                         `json:"node_key"`
		Queries  map[string][]map[string]string `json:"queries"`
		Statuses map[string]json.Number         `json:"statuses"`
		Messages map[string]string              `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("not valid JSON"))
		return
	}
	n := s.osqueryNode(w, r, req.NodeKey)
	if n == nil {
		return
	}
	ids := map[string]bool{}
	for id := range req.Queries {
		ids[id] = true
	}
	for id := range req.Statuses {
		ids[id] = true
	}
	for id := range ids {
		if len(id) > 64 {
			continue
		}
		status, _ := req.Statuses[id].Int64()
		err := s.Endpoints.SaveResult(r.Context(), n, id, req.Queries[id], int(status), req.Messages[id])
		if err != nil && !errors.Is(err, endpoint.ErrNotFound) {
			s.Log.Warn("could not save a live query answer", "host", n.Hostname, "err", err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// osqueryBody reads a request that carries results, from the same
// receive budget as agents' batches, and answers it when it cannot.
func (s *Server) osqueryBody(w http.ResponseWriter, r *http.Request) ([]byte, func(), error) {
	body, release, err := s.readBatch(w, r)
	if err != nil {
		s.batchReadFailed(w, r, err)
		return nil, nil, err
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Content-Encoding")), "gzip") {
		sender := netip.Addr{}
		if from := clientaddr.Parse(r.RemoteAddr); !clientaddr.Shared(from, s.Config.Server.SharedList()) {
			sender = clientaddr.Key(from)
		}
		raw, releaseRaw, err := gunzip(s.Pipeline, body, sender)
		release()
		if err != nil {
			s.batchReadFailed(w, r, err)
			return nil, nil, err
		}
		return raw, releaseRaw, nil
	}
	return body, release, nil
}

// logOnce says whether something about a key is due to be logged again.
type logOnce struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (l *logOnce) due(key string, every time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if t, ok := l.last[key]; ok && now.Sub(t) < every {
		return false
	}
	if l.last == nil || len(l.last) > 10000 {
		l.last = map[string]time.Time{}
	}
	l.last[key] = now
	return true
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// cut tidies text a host sent: no NUL bytes (osquery pads some hardware
// names with them), no surrounding spaces, at most n bytes.
func cut(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\x00", ""))
	if len(s) > n {
		return s[:n]
	}
	return s
}

func parseInt(s string) (int64, bool) {
	var n int64
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' || n > (1<<62)/10 {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	return n, true
}
