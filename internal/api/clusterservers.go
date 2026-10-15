package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// ClusterServers drains, resumes and removes servers, moves the
// background jobs and rotates the cluster key, as the API uses it: each
// change but a removal is a request another server runs, which
// GET /api/requests/{id} follows.
type ClusterServers interface {
	// Off says why servers cannot be drained, moved or removed on this
	// server now, "" when they can.
	Off() string
	// Lifecycle is the keyring's members, the removed servers and the key
	// rotation.
	Lifecycle() ClusterLifecycle
	// Submit makes a request of type typ for target (a node id, or
	// shared.TargetLeader), for the user by.
	Submit(ctx context.Context, typ, target string, args any, by string) (*shared.Request, error)
	// Remove takes the server nodeID (named name) out of the cluster,
	// for the user by; live is true while its heartbeat moves.
	Remove(ctx context.Context, nodeID, name, by string, live bool) (shared.RemovedServer, error)
}

// ClusterLifecycle is GET /api/cluster/lifecycle.
type ClusterLifecycle struct {
	// Members are the servers in the keyring.
	Members []LifecycleMember `json:"members"`
	// Removed are the servers removed from the cluster, newest last.
	Removed  []shared.RemovedServer `json:"removed"`
	Rotation shared.RotationStatus  `json:"rotation"`
}

// LifecycleMember is a server in the keyring.
type LifecycleMember struct {
	NodeID      string `json:"node_id"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	AddedBy     string `json:"added_by"`
	AddedAt     string `json:"added_at"`
}

// RemoveAfter is how long a server that was not drained must have been
// offline before it may be removed.
const RemoveAfter = 10 * time.Minute

func (s *Server) routeClusterServers(api *router) {
	// Adding and removing servers is for admins, like the rest of the
	// Servers page.
	api.admin("GET /api/cluster/lifecycle", s.handleClusterLifecycle)
	api.admin("POST /api/cluster/servers/{id}/drain", s.handleServerDrain)
	api.admin("POST /api/cluster/servers/{id}/resume", s.handleServerResume)
	api.admin("DELETE /api/cluster/servers/{id}", s.handleServerRemove)
	api.admin("POST /api/cluster/jobs/move", s.handleJobsMove)
	api.admin("POST /api/cluster/rotate-key", s.handleRotateKey)
}

// clusterServersOff is why servers cannot be drained or removed here.
func (s *Server) clusterServersOff() string {
	switch {
	case s.ClusterServers == nil:
		return "This server isn't a member of a cluster."
	case s.Cluster == nil:
		return "This server has no list of servers."
	}
	return s.ClusterServers.Off()
}

// handleClusterLifecycle answers GET /api/cluster/lifecycle.
func (s *Server) handleClusterLifecycle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if off := s.clusterServersOff(); off != "" {
		writeJSON(w, http.StatusOK, map[string]any{"on": false, "off": off})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"on": true, "lifecycle": s.ClusterServers.Lifecycle()})
}

// serverOf finds the server id (a node id) in the list of servers.
func serverOf(st cluster.Status, id string) (cluster.ServerStatus, bool) {
	for _, sv := range st.Servers {
		if sv.NodeID == id {
			return sv, true
		}
	}
	return cluster.ServerStatus{}, false
}

func goneState(state string) bool {
	return state == cluster.StateOffline || state == cluster.StateStopped
}

// lifecycleReady checks that this server can drain and remove servers
// now, and answers when it cannot.
func (s *Server) lifecycleReady(w http.ResponseWriter) bool {
	if off := s.clusterServersOff(); off != "" {
		writeError(w, http.StatusServiceUnavailable, errors.New(off))
		return false
	}
	return true
}

// submitted answers a request made, or the error of making it.
func (s *Server) submitted(w http.ResponseWriter, rq *shared.Request, err error, extra map[string]any) {
	if err != nil {
		if !sharedError(w, err) {
			writeError(w, http.StatusServiceUnavailable, err)
		}
		return
	}
	out := map[string]any{"request_id": rq.ID}
	for k, v := range extra {
		out[k] = v
	}
	writeJSON(w, http.StatusAccepted, out)
}

// handleServerDrain answers POST /api/cluster/servers/{id}/drain: the
// server stops wanting traffic and gives the background jobs up (a drain
// request it runs), 202 with the request's id.
func (s *Server) handleServerDrain(w http.ResponseWriter, r *http.Request) {
	s.drainOrResume(w, r, clustercfg.RequestDrain)
}

// handleServerResume answers POST /api/cluster/servers/{id}/resume.
func (s *Server) handleServerResume(w http.ResponseWriter, r *http.Request) {
	s.drainOrResume(w, r, clustercfg.RequestResume)
}

func (s *Server) drainOrResume(w http.ResponseWriter, r *http.Request, typ string) {
	if !s.lifecycleReady(w) {
		return
	}
	sv, ok := serverOf(s.Cluster.Status(), r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("there is no such server"))
		return
	}
	if goneState(sv.State) {
		writeError(w, http.StatusConflict, fmt.Errorf("%s is not running, so it cannot be drained or resumed now", sv.Name))
		return
	}
	if sv.Detail == nil || !slices.Contains(sv.Detail.Features, cluster.FeatureDrain) {
		writeError(w, http.StatusConflict, fmt.Errorf("%s runs a version that cannot be drained: upgrade it first", sv.Name))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rq, err := s.ClusterServers.Submit(ctx, typ, sv.NodeID, nil, userOf(r))
	if err == nil {
		s.audit(r, "server "+map[string]string{clustercfg.RequestDrain: "drained", clustercfg.RequestResume: "resumed"}[typ],
			"server", sv.Name, "node_id", sv.NodeID, "request", rq.ID)
	}
	s.submitted(w, rq, err, map[string]any{"server": sv.Name})
}

// handleJobsMove answers POST /api/cluster/jobs/move {to}: the server
// that runs the background jobs hands them to the server to (a node id),
// 202 with the request's id.
func (s *Server) handleJobsMove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To string `json:"to"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.lifecycleReady(w) {
		return
	}
	st := s.Cluster.Status()
	sv, ok := serverOf(st, req.To)
	if !ok {
		writeError(w, http.StatusBadRequest, errors.New("name the server to run the background jobs (to)"))
		return
	}
	switch {
	case st.Jobs.Holder == "":
		writeError(w, http.StatusConflict, errors.New("no server runs the background jobs right now, so there is nothing to move: one takes them within a minute"))
		return
	case st.Jobs.Holder == sv.NodeID:
		writeError(w, http.StatusConflict, fmt.Errorf("%s runs the background jobs already", sv.Name))
		return
	case sv.State != cluster.StateReady || sv.Jobs != "standby":
		why := "it may not run them"
		if sv.Detail != nil && sv.Detail.NotEligible != "" {
			why = sv.Detail.NotEligible
		}
		if sv.State != cluster.StateReady {
			why = "it is not running normally"
		}
		writeError(w, http.StatusConflict, fmt.Errorf("%s cannot take the background jobs: %s", sv.Name, why))
		return
	case sv.CannotTakeOver != "":
		writeError(w, http.StatusConflict, fmt.Errorf("%s cannot take the background jobs: %s", sv.Name, sv.CannotTakeOver))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rq, err := s.ClusterServers.Submit(ctx, clustercfg.RequestReleaseJobs, shared.TargetLeader, clustercfg.ReleaseJobsArgs{To: sv.NodeID}, userOf(r))
	if err == nil {
		s.audit(r, "background jobs moved", "to", sv.Name, "node_id", sv.NodeID, "request", rq.ID)
	}
	s.submitted(w, rq, err, map[string]any{"to": sv.Name})
}

// handleServerRemove answers DELETE /api/cluster/servers/{id}?rotate=:
// the server leaves the keyring and the list of servers, and, unless
// rotate=false, the cluster key is rotated (a rotate_key request, whose
// id the answer carries). Only a server that is drained, stopped, or
// offline for RemoveAfter may be removed, and never this server itself
// (signalith cluster leave does that on the server).
func (s *Server) handleServerRemove(w http.ResponseWriter, r *http.Request) {
	rotate := true
	if v := r.URL.Query().Get("rotate"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("rotate is true or false"))
			return
		}
		rotate = b
	}
	if !s.lifecycleReady(w) {
		return
	}
	id := r.PathValue("id")
	st := s.Cluster.Status()
	lc := s.ClusterServers.Lifecycle()
	name, member := "", false
	for _, m := range lc.Members {
		if m.NodeID == id {
			name, member = m.Name, true
		}
	}
	sv, seen := serverOf(st, id)
	if seen {
		name = sv.Name
	}
	live := seen && !goneState(sv.State)
	switch {
	case !seen && !member:
		writeError(w, http.StatusNotFound, errors.New("there is no such server"))
		return
	case id == st.Self:
		writeError(w, http.StatusBadRequest, errors.New("a server cannot remove itself from its own page: remove it from another server's, or run signalith cluster leave on it"))
		return
	case seen && sv.State == cluster.StateOffline && (sv.SeenAgo == nil || *sv.SeenAgo < RemoveAfter):
		writeError(w, http.StatusConflict, fmt.Errorf("%s went offline less than %d minutes ago: drain it first, or wait", name, int(RemoveAfter/time.Minute)))
		return
	case live && sv.State != cluster.StateDraining:
		writeError(w, http.StatusConflict, fmt.Errorf("%s is running: drain it first, or stop it", name))
		return
	case member && len(lc.Members) == 1:
		writeError(w, http.StatusConflict, shared.ErrLastMember)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rec, err := s.ClusterServers.Remove(ctx, id, name, userOf(r), live)
	if err != nil {
		if !sharedError(w, err) {
			writeError(w, http.StatusServiceUnavailable, err)
		}
		return
	}
	out := map[string]any{"removed": rec}
	switch {
	case !rotate:
		out["rotate_skipped"] = fmt.Sprintf("%s's copy of the cluster key still works until the key is rotated.", rec.Name)
	case !lc.Rotation.On:
		out["rotate_skipped"] = "Rotating the cluster key needs every server on a version that supports it: upgrade them, then rotate it."
	default:
		rq, err := s.ClusterServers.Submit(ctx, clustercfg.RequestRotateKey, shared.TargetLeader,
			clustercfg.RotateKeyArgs{Reason: "removed " + rec.Name, Removed: []string{id}}, userOf(r))
		if err != nil {
			out["rotate_skipped"] = "The cluster key could not be rotated now (" + err.Error() + "): rotate it from the Servers page."
		} else {
			out["request_id"] = rq.ID
		}
	}
	s.audit(r, "cluster.remove: server removed from the cluster", "server", rec.Name, "node_id", id, "rotate", rotate, "request", out["request_id"])
	writeJSON(w, http.StatusOK, out)
}

// handleRotateKey answers POST /api/cluster/rotate-key: the server that
// runs the background jobs rotates the cluster key (a rotate_key
// request), 202 with the request's id.
func (s *Server) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	if !s.lifecycleReady(w) {
		return
	}
	lc := s.ClusterServers.Lifecycle()
	if !lc.Rotation.On {
		writeError(w, http.StatusConflict, shared.ErrNoRotation)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rq, err := s.ClusterServers.Submit(ctx, clustercfg.RequestRotateKey, shared.TargetLeader, clustercfg.RotateKeyArgs{Reason: "rotate-key"}, userOf(r))
	if err == nil {
		s.audit(r, "cluster key rotation asked for", "request", rq.ID)
	}
	s.submitted(w, rq, err, nil)
}
