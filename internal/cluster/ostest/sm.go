// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ostest

import (
	"encoding/json"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

// Snapshot Management and snapshot repositories, as far as scheduled
// snapshots use them (internal/snapshots):
//
//   - GET /_snapshot/<repo> (a repository AddRepository registered, else
//     404 repository_missing_exception);
//   - GET /_snapshot/<repo>/<pattern> with ignore_unavailable (the
//     snapshots SMRan recorded, as OpenSearch lists them);
//   - GET, POST, PUT (with if_seq_no and if_primary_term) and DELETE
//     /_plugins/_sm/policies/<name>, and GET .../_explain, with
//     OpenSearch's answers, its 404 before any policy exists and its 409
//     on a stale update.
//
// Nothing runs a policy: SMRan records a run as OpenSearch would.

// smState is the fake's snapshot repositories and policies.
type smState struct {
	repos    map[string]string // name: type
	policies map[string]*smPolicy
	// configIndex is set once a policy was ever created, as OpenSearch
	// makes its config index then.
	configIndex bool
	seq         int64
	snaps       map[string][]smSnapshot // by repository
}

type smPolicy struct {
	body        map[string]any
	seqNo       int64
	enabledTime int64
	next        int64
	latest      map[string]any
	// ranSeqNo is the version of the policy the last run read.
	ranSeqNo int64
}

type smSnapshot struct {
	name, state, policy string
	start, end          time.Time
}

func (s *Server) smLocked() *smState {
	if s.sm == nil {
		s.sm = &smState{repos: map[string]string{}, policies: map[string]*smPolicy{}, snaps: map[string][]smSnapshot{}}
	}
	return s.sm
}

// AddRepository registers a snapshot repository of type typ (fs, s3).
func (s *Server) AddRepository(name, typ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.smLocked().repos[name] = typ
}

// SMPolicy returns the policy as it was last written, or nil.
func (s *Server) SMPolicy(name string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.smLocked().policies[name]; p != nil {
		return p.body
	}
	return nil
}

// SMRan records a run of policy name that started at start: a snapshot
// <name>-<time>-<n> in its repository in state (SUCCESS, FAILED,
// PARTIAL), the run as _explain answers it, and next as the time of the
// next run.
func (s *Server) SMRan(name, state string, start time.Time, took time.Duration, next time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	sm := s.smLocked()
	p := sm.policies[name]
	if p == nil {
		return ""
	}
	repo, _ := p.body["snapshot_config"].(map[string]any)["repository"].(string)
	snap := smSnapshot{name: name + "-" + strings.ToLower(start.UTC().Format("2006-01-02t15:04:05")) + "-" + strconv.Itoa(len(sm.snaps[repo])),
		state: state, policy: name, start: start, end: start.Add(took)}
	sm.snaps[repo] = append(sm.snaps[repo], snap)
	status := "SUCCESS"
	if state != "SUCCESS" {
		status = "FAILED"
	}
	p.latest = map[string]any{"status": status, "start_time": start.UnixMilli(), "end_time": snap.end.UnixMilli(),
		"info": map[string]any{"message": "Snapshot " + snap.name + " creation has finished: " + state}}
	p.next = next.UnixMilli()
	// The run read the policy as it is now (see _explain's policy_seq_no).
	p.ranSeqNo = p.seqNo
	return snap.name
}

// serveSM answers the requests above, and reports whether it did.
func (s *Server) serveSM(w http.ResponseWriter, r *http.Request, parts []string, body []byte) bool {
	switch {
	case len(parts) >= 2 && parts[0] == "_snapshot" && r.Method == http.MethodGet:
		s.smSnapshotGet(w, r, parts)
	case len(parts) >= 3 && parts[0] == "_plugins" && parts[1] == "_sm" && parts[2] == "policies":
		s.smPolicies(w, r, parts[3:], body)
	default:
		return false
	}
	return true
}

func (s *Server) smSnapshotGet(w http.ResponseWriter, r *http.Request, parts []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sm := s.smLocked()
	repo := parts[1]
	typ, ok := sm.repos[repo]
	if !ok {
		writeError(w, http.StatusNotFound, "repository_missing_exception", "["+repo+"] missing")
		return
	}
	if len(parts) == 2 {
		writeJSON(w, 200, map[string]any{repo: map[string]any{"type": typ, "settings": map[string]any{}}})
		return
	}
	var out []any
	for _, sn := range sm.snaps[repo] {
		if ok, _ := path.Match(parts[2], sn.name); !ok && parts[2] != "_all" {
			continue
		}
		out = append(out, map[string]any{"snapshot": sn.name, "state": sn.state, "indices": []string{},
			"include_global_state": false, "metadata": map[string]any{"sm_policy": sn.policy, "created_by": "signalith"},
			"start_time_in_millis": sn.start.UnixMilli(), "end_time_in_millis": sn.end.UnixMilli()})
	}
	if len(out) == 0 && r.URL.Query().Get("ignore_unavailable") != "true" && strings.Contains(parts[2], "*") {
		writeError(w, http.StatusNotFound, "snapshot_missing_exception", "["+repo+":"+parts[2]+"] is missing")
		return
	}
	if out == nil {
		out = []any{}
	}
	writeJSON(w, 200, map[string]any{"snapshots": out})
}

func (s *Server) smPolicies(w http.ResponseWriter, r *http.Request, rest []string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sm := s.smLocked()
	if len(rest) == 0 {
		writeError(w, http.StatusBadRequest, "illegal_argument_exception", "no policy named")
		return
	}
	name := rest[0]
	p := sm.policies[name]
	missing := func() {
		reason := "Snapshot management policy not found"
		if !sm.configIndex {
			reason = "Snapshot management config index not found"
		}
		writeError(w, http.StatusNotFound, "status_exception", reason)
	}
	answer := func(status int) {
		writeJSON(w, status, map[string]any{"_id": name + "-sm-policy", "_version": 1, "_seq_no": p.seqNo, "_primary_term": s.primaryTerm,
			"sm_policy": p.view(name)})
	}
	switch {
	case len(rest) == 2 && rest[1] == "_explain" && r.Method == http.MethodGet:
		if !sm.configIndex {
			missing()
			return
		}
		var list []any
		if p != nil {
			ex := map[string]any{"name": name, "enabled": true}
			if p.next > 0 {
				ex["policy_seq_no"], ex["policy_primary_term"] = p.ranSeqNo, s.primaryTerm
				creation := map[string]any{"current_state": "CREATION_START", "trigger": map[string]any{"time": p.next}}
				if p.latest != nil {
					creation["latest_execution"] = p.latest
				}
				ex["creation"] = creation
			}
			list = append(list, ex)
		}
		if list == nil {
			list = []any{}
		}
		writeJSON(w, 200, map[string]any{"policies": list})
	case len(rest) != 1:
		writeError(w, http.StatusBadRequest, "illegal_argument_exception", "no handler found for uri ["+r.URL.Path+"]")
	case r.Method == http.MethodGet:
		if p == nil {
			missing()
			return
		}
		answer(200)
	case r.Method == http.MethodPost || r.Method == http.MethodPut:
		var b map[string]any
		if json.Unmarshal(body, &b) != nil || b["snapshot_config"] == nil || b["creation"] == nil {
			writeError(w, http.StatusBadRequest, "illegal_argument_exception", "snapshot_config field must not be null")
			return
		}
		q := r.URL.Query()
		if r.Method == http.MethodPost && p != nil {
			writeError(w, http.StatusConflict, "version_conflict_engine_exception", "["+name+"-sm-policy]: version conflict, document already exists")
			return
		}
		if r.Method == http.MethodPut {
			if p == nil {
				missing()
				return
			}
			if q.Get("if_seq_no") == "" || q.Get("if_primary_term") == "" {
				writeError(w, http.StatusBadRequest, "action_request_validation_exception", "Validation Failed: 1: Sequence number and primary term must be provided when updating a snapshot management policy;")
				return
			}
			if q.Get("if_seq_no") != strconv.FormatInt(p.seqNo, 10) || q.Get("if_primary_term") != strconv.FormatInt(s.primaryTerm, 10) {
				writeError(w, http.StatusConflict, "version_conflict_engine_exception", "["+name+"-sm-policy]: version conflict")
				return
			}
		}
		status := http.StatusOK
		if p == nil {
			p = &smPolicy{enabledTime: s.now().UnixMilli()}
			sm.policies[name] = p
			status = http.StatusCreated
		}
		sm.configIndex = true
		sm.seq++
		p.body, p.seqNo = b, sm.seq
		answer(status)
	case r.Method == http.MethodDelete:
		if p == nil {
			missing()
			return
		}
		delete(sm.policies, name)
		writeJSON(w, 200, map[string]any{"_id": name + "-sm-policy", "result": "deleted"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "illegal_argument_exception", "no handler found for uri ["+r.URL.Path+"] and method ["+r.Method+"]")
	}
}

// view is the policy as OpenSearch answers it: what was written, with the
// deletion schedule filled in and the fields OpenSearch adds.
func (p *smPolicy) view(name string) map[string]any {
	b, _ := json.Marshal(p.body)
	var v map[string]any
	_ = json.Unmarshal(b, &v)
	v["name"] = name
	if _, ok := v["enabled"]; !ok {
		v["enabled"] = true
	}
	v["enabled_time"] = p.enabledTime
	v["schema_version"] = 21
	if del, ok := v["deletion"].(map[string]any); ok {
		if _, ok := del["schedule"]; !ok {
			del["schedule"] = v["creation"].(map[string]any)["schedule"]
		}
	}
	return v
}
