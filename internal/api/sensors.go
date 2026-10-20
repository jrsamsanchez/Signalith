// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/sensortune"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Settings > Network sensors: every sensor's health and what to fix on it
// (GET /api/sensors), and the Suricata rule tuning every sensor fetches
// (GET and PUT /api/sensors/tuning, admins; GET /api/sensor/tuning, the
// sensors themselves with their sensor token).

const (
	// tuningPendingFor is how long after a save a sensor that does not
	// run the new tuning yet is waiting for it rather than failing: it
	// fetches every 10 minutes, give or take 2, and then tests the rules.
	tuningPendingFor = 20 * time.Minute
	// msgTuningConflict answers a save from a page opened before someone
	// else's save.
	msgTuningConflict = "someone else saved the rule tuning since you opened it; reload to see their changes (what you typed is kept)"
	// msgTuningOff answers when this server keeps no tuning (no
	// OpenSearch).
	msgTuningOff = "rule tuning is kept in OpenSearch, which this server does not use"
)

func (s *Server) routeSensors(api *router) {
	api.admin("GET /api/sensors", s.handleSensors)
	api.admin("GET /api/sensors/tuning", s.handleSensorTuning)
	api.admin("PUT /api/sensors/tuning", s.handleSaveSensorTuning)
}

// isSensor reports whether an agent is a network sensor: it sent a
// status line, or Zeek or Suricata batches.
func isSensor(a agentinv.Agent) bool {
	return !a.Refusing && (a.Sensor != nil || sensorTag.MatchString(a.Tag))
}

// sensorCheck is one line of a sensor's checklist. ID is a warning code
// of the status line (ingest.SensorStatus.Warnings) or silent, no_status,
// tuning or token; the page words each.
type sensorCheck struct {
	ID string `json:"id"`
	OK bool   `json:"ok"`
	// State and Detail say more, for tuning (current, pending, failed,
	// stale, old_script, none) and token (active, revoked, unknown).
	State  string `json:"state,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// tuningNow is the tuning sensors should run, for the checklist.
type tuningNow struct {
	// Hash is its sensortune.ShortHash, "" when it could not be read;
	// Saved when it was saved, zero when it never was.
	Hash  string
	Saved time.Time
}

// sensorChecks is the checklist of sensor a at now: what its status line
// and the server know. A sensor set up by hand sends no status line, so
// only whether it sends and its token can be checked.
func sensorChecks(a agentinv.Agent, tuning tuningNow, tokenState string, now time.Time) []sensorCheck {
	out := []sensorCheck{{ID: "silent", OK: !agentinv.Silent(a, now)}}
	s := a.Sensor
	if s == nil {
		out = append(out, sensorCheck{ID: "no_status", OK: false})
	} else {
		warned := map[string]bool{}
		for _, w := range s.Warnings {
			warned[w] = true
		}
		add := func(id string, ok bool) { out = append(out, sensorCheck{ID: id, OK: ok && !warned[id]}) }
		if s.Zeek != nil {
			add("zeek_stopped", s.Zeek.Running)
		}
		if s.Suricata != nil {
			add("suricata_stopped", s.Suricata.Running)
		}
		add("capture_link", s.Link == "" || s.Link == "up")
		add("capture_ip", true)
		add("no_traffic", true)
		add("drops", s.DropPercent <= sensorDropping)
		add("disk_low", true)
		if s.Suricata != nil {
			add("rules_failed", s.RulesUpdate != "failed")
			updated, err := time.Parse(time.RFC3339, s.RulesUpdated)
			add("rules_old", err == nil && now.Sub(updated) <= sensorRulesOld)
			out = append(out, tuningCheck(s, tuning, now))
		}
		add("time_not_synced", s.TimeSynced)
	}
	out = append(out, sensorCheck{ID: "token", OK: tokenState == "active", State: tokenState})
	return out
}

// tuningCheck says whether the sensor runs the rule tuning saved last.
func tuningCheck(s *ingest.SensorStatus, t tuningNow, now time.Time) sensorCheck {
	c := sensorCheck{ID: "tuning"}
	saved := !t.Saved.IsZero()
	switch {
	case t.Hash == "":
		// The tuning could not be read: nothing to compare with.
		c.OK, c.State = true, "unknown"
	case s.TuningResult == "" && !saved:
		c.OK, c.State = true, "none"
	case s.TuningResult == "":
		// The sensor's script is older than tuning: it never fetches.
		c.State = "old_script"
	case s.TuningHash == t.Hash:
		c.OK, c.State = true, "current"
	case s.TuningResult == "failed" && s.TuningFailed == t.Hash:
		c.State, c.Detail = "failed", s.TuningError
	case saved && now.Sub(t.Saved) < tuningPendingFor:
		// Saved lately: a failure it reports is of a tuning before this
		// one, which it has not fetched and tested yet.
		c.OK, c.State = true, "pending"
	case s.TuningResult == "failed" && s.TuningFailed == "":
		// Which tuning failed is not said: the failure stands.
		c.State, c.Detail = "failed", s.TuningError
	case !saved:
		// Nothing was ever saved: the sensor has nothing to apply yet.
		c.OK, c.State = true, "none"
	default:
		c.State = "stale"
		if s.TuningResult == "unreachable" {
			c.Detail = s.TuningError
		}
	}
	return c
}

// sensorRow is one sensor on the page.
type sensorRow struct {
	Key       string               `json:"key"`
	Name      string               `json:"name"`
	Addresses []string             `json:"addresses"`
	LastSeen  time.Time            `json:"last_seen"`
	Silent    bool                 `json:"silent"`
	Events1h  int64                `json:"events_1h"`
	TokenID   string               `json:"token_id,omitempty"`
	TokenName string               `json:"token_name,omitempty"`
	Status    *ingest.SensorStatus `json:"status"`
	// RulesAgeSec is how old the rules are, -1 when unknown.
	RulesAgeSec int64 `json:"rules_age_sec"`
	// State is healthy, attention or silent.
	State    string        `json:"state"`
	Checks   []sensorCheck `json:"checks"`
	Problems []string      `json:"problems"`
}

// sensorToken is a sensor token on the page.
type sensorTokenRow struct {
	agenttokens.Token
	UsedBy []string `json:"used_by"`
}

// tokenState is whether the token id is active, revoked or unknown.
func (s *Server) tokenState(id string) string {
	t := s.tokens()
	switch {
	case id == "":
		return "unknown"
	case t.Active(id):
		return "active"
	}
	if _, ok := t.Lookup(id); ok {
		return "revoked"
	}
	if !t.Loaded() {
		return "active" // not read yet: not said to be wrong
	}
	return "unknown"
}

// currentTuning returns the tuning sensors should run, for the
// checklist; nothing saved when it cannot be read.
func (s *Server) currentTuning(r *http.Request) (sensortune.Tuning, store.Version, error) {
	if s.SensorTuning == nil {
		return sensortune.Tuning{}, store.Version{}, nil
	}
	return s.SensorTuning.Get(r.Context())
}

func (s *Server) handleSensors(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	var list []agentinv.Agent
	if s.Agents != nil {
		var err error
		list, _, err = s.agents().List(r.Context())
		if err != nil {
			s.Log.Warn("the agents other servers heard from could not be read", "err", err)
		}
	}
	tu, v, terr := s.currentTuning(r)
	tn := tuningNow{}
	if terr == nil {
		tn.Hash = sensortune.ShortHash(tu.Hash())
		if !v.IsZero() {
			tn.Saved = tu.UpdatedAt
		}
	}
	rows := []sensorRow{}
	usedBy := map[string][]string{}
	summary := map[string]int{"total": 0, "healthy": 0, "attention": 0, "silent": 0, "running_tuning": 0, "with_suricata": 0}
	for _, a := range list {
		if !isSensor(a) {
			continue
		}
		name := a.Name
		if name == "" && len(a.Addresses) > 0 {
			name = a.Addresses[0]
		}
		row := sensorRow{Key: a.Key, Name: name, Addresses: a.Addresses, LastSeen: a.LastSeen, Silent: agentinv.Silent(a, now),
			Events1h: a.Events1h, TokenID: a.TokenID, TokenName: a.TokenName, Status: a.Sensor, RulesAgeSec: -1, Problems: []string{}}
		if a.Sensor != nil {
			if t, err := time.Parse(time.RFC3339, a.Sensor.RulesUpdated); err == nil {
				row.RulesAgeSec = int64(now.Sub(t).Seconds())
			}
			if a.Sensor.Suricata != nil {
				summary["with_suricata"]++
				if a.Sensor.TuningResult != "" && tn.Hash != "" && a.Sensor.TuningHash == tn.Hash {
					summary["running_tuning"]++
				}
			}
		}
		row.Checks = sensorChecks(a, tn, s.tokenState(a.TokenID), now)
		for _, c := range row.Checks {
			// Pending tuning is fine; a sensor set up by hand sends no
			// status line, which is not a problem to fix.
			if !c.OK && c.ID != "no_status" {
				row.Problems = append(row.Problems, c.ID)
			}
		}
		summary["total"]++
		switch {
		case row.Silent:
			row.State = "silent"
		case len(row.Problems) > 0:
			row.State = "attention"
		default:
			row.State = "healthy"
		}
		summary[row.State]++
		rows = append(rows, row)
		if a.TokenID != "" {
			usedBy[a.TokenID] = append(usedBy[a.TokenID], name)
		}
	}
	rank := map[string]int{"silent": 0, "attention": 1, "healthy": 2}
	sort.SliceStable(rows, func(i, j int) bool {
		if rank[rows[i].State] != rank[rows[j].State] {
			return rank[rows[i].State] < rank[rows[j].State]
		}
		return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name)
	})
	tokens := []sensorTokenRow{}
	tl := s.tokens().List(r.Context())
	for _, t := range tl.Tokens {
		if t.Purpose != agenttokens.PurposeSensor {
			continue
		}
		u := usedBy[t.ID]
		if u == nil {
			u = []string{}
		}
		sort.Strings(u)
		tokens = append(tokens, sensorTokenRow{Token: t, UsedBy: u})
	}
	out := map[string]any{
		"sensors": rows, "summary": summary, "tokens": tokens, "tokens_loaded": tl.Loaded,
		"silent_after_sec": int64(agentinv.SensorSilentAfter.Seconds()), "pending_sec": int64(tuningPendingFor.Seconds()),
		"tuning": tuningSummary(tu, v),
	}
	if terr != nil {
		out["tuning_error"] = "the rule tuning could not be read from OpenSearch: " + terr.Error()
	}
	writeJSON(w, http.StatusOK, out)
}

// tuningSummary is the tuning without its text, for the sensor list.
func tuningSummary(t sensortune.Tuning, v store.Version) map[string]any {
	out := map[string]any{"saved": !v.IsZero(), "counts": t.Counts()}
	if !v.IsZero() {
		out["hash"] = sensortune.ShortHash(t.Hash())
		out["updated_by"] = t.UpdatedBy
		out["updated_at"] = t.UpdatedAt
	}
	return out
}

// tuningView is the answer to GET /api/sensors/tuning.
func tuningView(t sensortune.Tuning, v store.Version) map[string]any {
	out := tuningSummary(t, v)
	out["tuning"] = map[string]string{
		sensortune.FieldDisable: t.Disable, sensortune.FieldThreshold: t.Threshold, sensortune.FieldLocal: t.Local,
	}
	out["version"] = v.String()
	out["warnings"] = nonNil(t.Warnings())
	out["limits"] = map[string]int{
		"field_bytes": sensortune.MaxFieldBytes, "line_bytes": sensortune.MaxLineBytes,
		sensortune.FieldDisable: sensortune.MaxDisable, sensortune.FieldThreshold: sensortune.MaxThreshold, sensortune.FieldLocal: sensortune.MaxLocal,
	}
	return out
}

func (s *Server) handleSensorTuning(w http.ResponseWriter, r *http.Request) {
	if s.SensorTuning == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New(msgTuningOff))
		return
	}
	t, v, err := s.SensorTuning.Read(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, tuningView(t, v))
}

func (s *Server) handleSaveSensorTuning(w http.ResponseWriter, r *http.Request) {
	if s.SensorTuning == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New(msgTuningOff))
		return
	}
	var req struct {
		Tuning  map[string]string `json:"tuning"`
		Version string            `json:"version"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, sensortune.MaxBundleBytes*2)
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	for k := range req.Tuning {
		if _, ok := sensortune.Labels[k]; !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown field " + k})
			return
		}
	}
	prev, cur, err := s.SensorTuning.Read(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	// The page sends the version it read: a save from someone else since
	// then is not overwritten.
	if req.Version != cur.String() {
		writeError(w, http.StatusConflict, errors.New(msgTuningConflict))
		return
	}
	in := sensortune.Tuning{Disable: req.Tuning[sensortune.FieldDisable], Threshold: req.Tuning[sensortune.FieldThreshold], Local: req.Tuning[sensortune.FieldLocal]}
	t, v, err := s.SensorTuning.Save(r.Context(), in, cur, userOf(r))
	var le *sensortune.LineError
	switch {
	case errors.As(err, &le):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": le.Error(), "field": le.Field, "line": le.Line})
		return
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, errors.New(msgTuningConflict))
		return
	case err != nil:
		writeError(w, http.StatusBadGateway, err)
		return
	}
	c := t.Counts()
	// What changed, line by line: the tuning can turn rules off on every
	// sensor, so the audit trail says who turned off what.
	args := []any{"hash", sensortune.ShortHash(t.Hash()), "previous_hash", sensortune.ShortHash(prev.Hash()),
		"disabled", c[sensortune.FieldDisable], "thresholds", c[sensortune.FieldThreshold], "rules", c[sensortune.FieldLocal]}
	for _, f := range sensortune.Fields {
		added, removed := sensortune.Diff(prev.Field(f), t.Field(f))
		if len(added) > 0 {
			args = append(args, f+"_added", added)
		}
		if len(removed) > 0 {
			args = append(args, f+"_removed", removed)
		}
	}
	s.audit(r, "sensor rule tuning saved", args...)
	writeJSON(w, http.StatusOK, tuningView(t, v))
}

// refusedTuning logs and audits, once per tuning, a stored tuning that
// fails the checks of a save.
func (s *Server) refusedTuning(r *http.Request, hash string, err error) {
	s.badTuningMu.Lock()
	seen := s.badTuning == hash
	s.badTuning = hash
	s.badTuningMu.Unlock()
	if seen {
		return
	}
	s.Log.Error("the rule tuning stored in OpenSearch fails the checks of a save: no sensor gets it until an admin saves it again", "audit", true,
		"hash", sensortune.ShortHash(hash), "err", err)
}

// handleSensorTuningFetch hands a sensor the rule tuning, with its
// sensor token only. The body is the bundle (sensortune.Bundle), its
// ETag the bundle's SHA-256, which the sensor checks; a sensor that has
// it gets 304. When the tuning cannot be read, the answer is 503, never
// an empty tuning, which would take every sensor's tuning away.
func (s *Server) handleSensorTuningFetch(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sensorToken(w, r); !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if s.SensorTuning == nil {
		w.Header().Set("Retry-After", "600")
		writeError(w, http.StatusServiceUnavailable, errors.New(msgTuningOff))
		return
	}
	t, _, err := s.SensorTuning.Get(r.Context())
	if err != nil {
		s.Log.Warn("a sensor could not be given the rule tuning", "err", err)
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusServiceUnavailable, errors.New("the rule tuning cannot be read from OpenSearch right now; the sensor keeps the tuning it has"))
		return
	}
	// Only a save checks the tuning: a document written to OpenSearch
	// some other way is checked again before any sensor gets it, and
	// refused whole, so sensors keep the tuning they have.
	if verr := t.Normalize().Validate(); verr != nil || t.Normalize() != t {
		if verr == nil {
			verr = errors.New("it is not in the form a save writes")
		}
		s.refusedTuning(r, t.Hash(), verr)
		w.Header().Set("Retry-After", "600")
		writeError(w, http.StatusServiceUnavailable, errors.New("the rule tuning stored in OpenSearch fails Signalith's checks, so no sensor gets it; an admin saves it again on Settings > Network sensors"))
		return
	}
	body := t.Bundle()
	etag := `"` + t.Hash() + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.TrimSpace(inm) == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(body)
}
