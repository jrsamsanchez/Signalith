// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package snapshots

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// States of the scheduled snapshots, as Status.State says.
const (
	StateOff = "off"
	// StateOK: the last successful snapshot is recent enough.
	StateOK = "ok"
	// StateWaiting: none yet, and the first is not overdue.
	StateWaiting = "waiting"
	// StateLate: the last successful snapshot is older than two periods
	// (or there has been none for that long).
	StateLate = "late"
	// StateProblem: something stops them (Problem says what).
	StateProblem = "problem"
)

// cacheFor is how long Status keeps an answer: the Health page asks
// every few seconds, and snapshots change at most hourly.
const cacheFor = time.Minute

// Snapshot is one snapshot the policy took.
type Snapshot struct {
	Name  string     `json:"name"`
	State string     `json:"state"` // SUCCESS, PARTIAL, FAILED, IN_PROGRESS
	Start time.Time  `json:"start"`
	End   *time.Time `json:"end,omitempty"`
}

// Status is how the scheduled snapshots are going.
type Status struct {
	On         bool   `json:"on"`
	State      string `json:"state"`
	Policy     string `json:"policy,omitempty"`
	Repository string `json:"repository,omitempty"`
	// Schedule words it: "every day at 02:30 UTC".
	Schedule string `json:"schedule,omitempty"`
	Keep     int    `json:"keep,omitempty"`
	// Kept counts the successful snapshots in the repository.
	Kept int `json:"kept"`
	// Last is the newest snapshot, and LastSuccess the newest that
	// succeeded.
	Last        *Snapshot  `json:"last,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	// Next is when OpenSearch takes the next one.
	Next *time.Time `json:"next,omitempty"`
	// Run is how OpenSearch says its last run went, when it failed.
	Run string `json:"run,omitempty"`
	// Problem says what stops the snapshots, or that they are late, and
	// what to do.
	Problem string `json:"problem,omitempty"`
	// Pending is set while the policy in OpenSearch does not match the
	// settings yet: the server that runs the background jobs writes it
	// within a minute.
	Pending bool      `json:"pending,omitempty"`
	Checked time.Time `json:"checked"`
}

// Alert is the red Health item, or "".
func (s *Status) Alert() string {
	switch s.State {
	case StateLate, StateProblem:
		return s.Problem
	}
	return ""
}

// Status returns how the snapshots are going, from a cache of a minute
// unless fresh. Any server can answer it: it only reads.
func (m *Manager) Status(ctx context.Context, fresh bool) *Status {
	for {
		m.mu.Lock()
		if c := m.cached; c != nil && !fresh && m.now().Sub(c.Checked) < cacheFor {
			m.mu.Unlock()
			cp := *c
			return &cp
		}
		if wait := m.refreshing; wait != nil {
			m.mu.Unlock()
			select {
			case <-wait:
				fresh = false
				continue
			case <-ctx.Done():
				return &Status{On: m.settings().On, State: StateProblem, Problem: "OpenSearch did not answer in time about the snapshots.", Checked: m.now()}
			}
		}
		done := make(chan struct{})
		m.refreshing = done
		m.mu.Unlock()
		st := m.read(ctx)
		m.mu.Lock()
		if ctx.Err() == nil {
			m.cached = st
		}
		m.refreshing = nil
		close(done)
		m.mu.Unlock()
		cp := *st
		return &cp
	}
}

// read works the status out from OpenSearch.
func (m *Manager) read(ctx context.Context) *Status {
	s := m.settings().Normal()
	now := m.now()
	st := &Status{On: s.On, State: StateOff, Checked: now}
	if !s.On {
		return st
	}
	name := PolicyName(m.Prefix)
	st.Policy, st.Repository, st.Schedule, st.Keep = name, s.Repository, s.Describe(), s.Keep
	fail := func(err error) *Status {
		st.State = StateProblem
		if p := m.problem(err); p != "" {
			st.Problem = p
		} else {
			st.Problem = "Could not read the snapshots from OpenSearch: " + err.Error()
		}
		return st
	}
	if p, err := m.repository(ctx, s.Repository); err != nil {
		return fail(err)
	} else if p != "" {
		st.State, st.Problem = StateProblem, p
		return st
	}
	cur, ver, found, err := m.getPolicy(ctx)
	if err != nil {
		return fail(err)
	}
	want := desiredDoc(m.Prefix, s)
	st.Pending = !found || cur.key() != want.key()
	if found && !cur.ours() {
		st.State = StateProblem
		st.Problem = fmt.Sprintf("OpenSearch already has a snapshot policy named %s that Signalith did not make. Delete it (DELETE _plugins/_sm/policies/%s) or give Signalith another opensearch.index_prefix.", name, name)
		return st
	}
	if last := m.LastSync(); last != nil && last.Problem != "" {
		st.State, st.Problem = StateProblem, last.Problem
		return st
	}
	if found {
		var ex struct {
			Policies []struct {
				Name string `json:"name"`
				// The version of the policy OpenSearch last ran: an older
				// one after a change, until it runs the new one (within a
				// minute or so), and its next time is the old schedule's.
				SeqNo       *int64 `json:"policy_seq_no"`
				PrimaryTerm *int64 `json:"policy_primary_term"`
				Creation    struct {
					Trigger struct {
						Time int64 `json:"time"`
					} `json:"trigger"`
					LatestExecution *struct {
						Status string `json:"status"`
						Info   struct {
							Message string `json:"message"`
							Cause   string `json:"cause"`
						} `json:"info"`
					} `json:"latest_execution"`
				} `json:"creation"`
			} `json:"policies"`
		}
		if err := m.Client.Do(ctx, http.MethodGet, "/_plugins/_sm/policies/"+url.PathEscape(name)+"/_explain", nil, &ex); err != nil && !notFound(err) {
			return fail(err)
		}
		for _, p := range ex.Policies {
			if p.Name != name {
				continue
			}
			current := p.SeqNo != nil && p.PrimaryTerm != nil && *p.SeqNo == ver.SeqNo && *p.PrimaryTerm == ver.PrimaryTerm
			if t := p.Creation.Trigger.Time; t > 0 && current {
				next := time.UnixMilli(t).UTC()
				st.Next = &next
			}
			if le := p.Creation.LatestExecution; le != nil {
				switch le.Status {
				case "FAILED", "TIME_LIMIT_EXCEEDED", "RETRYING":
					st.Run = strings.TrimSpace(strings.Join([]string{le.Status, le.Info.Message, le.Info.Cause}, " "))
				}
			}
		}
	}
	if st.Next == nil && found && cur.Enabled {
		next := s.Next(now)
		st.Next = &next
	}
	snaps, err := m.snapshots(ctx, s.Repository, name)
	if err != nil {
		return fail(err)
	}
	for i := range snaps {
		sn := snaps[i]
		if sn.State == "SUCCESS" {
			st.Kept++
			if sn.End != nil && (st.LastSuccess == nil || sn.End.After(*st.LastSuccess)) {
				end := *sn.End
				st.LastSuccess = &end
			}
		}
	}
	if len(snaps) > 0 {
		last := snaps[len(snaps)-1]
		st.Last = &last
	}
	// Late after two periods without a successful snapshot, counted from
	// the last one, or from when the policy was turned on.
	late := 2 * s.Period()
	since := time.Time{}
	switch {
	case st.LastSuccess != nil:
		since = *st.LastSuccess
	case found && cur.EnabledTime > 0:
		since = time.UnixMilli(cur.EnabledTime)
	}
	switch {
	case !since.IsZero() && now.Sub(since) > late:
		st.State = StateLate
		what := "There has been no successful snapshot"
		if st.LastSuccess != nil {
			what = "The last successful snapshot was taken " + st.LastSuccess.UTC().Format("2006-01-02 15:04 UTC") + ","
		}
		st.Problem = fmt.Sprintf("%s more than two scheduled periods ago (%s).", what, s.Describe())
		if st.Run != "" {
			st.Problem += " OpenSearch says: " + st.Run
		} else if st.Last != nil && st.Last.State != "SUCCESS" {
			st.Problem += " The last snapshot, " + st.Last.Name + ", is " + strings.ToLower(st.Last.State) + "."
		}
		st.Problem += " See Scheduled snapshots in docs/backup.md."
	case st.LastSuccess != nil:
		st.State = StateOK
	default:
		st.State = StateWaiting
	}
	return st
}

// snapshots lists the policy's snapshots in repo, oldest first.
func (m *Manager) snapshots(ctx context.Context, repo, policy string) ([]Snapshot, error) {
	var resp struct {
		Snapshots []struct {
			Snapshot string            `json:"snapshot"`
			State    string            `json:"state"`
			Start    int64             `json:"start_time_in_millis"`
			End      int64             `json:"end_time_in_millis"`
			Metadata map[string]string `json:"metadata"`
		} `json:"snapshots"`
	}
	// ignore_unavailable: none yet is an empty list, not a 404.
	path := "/_snapshot/" + url.PathEscape(repo) + "/" + url.PathEscape(policy) + "-*?ignore_unavailable=true"
	if err := m.Client.Do(ctx, http.MethodGet, path, nil, &resp); err != nil {
		if notFound(err) && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, nil
		}
		return nil, err
	}
	var out []Snapshot
	for _, s := range resp.Snapshots {
		if s.Metadata["sm_policy"] != policy {
			continue
		}
		sn := Snapshot{Name: s.Snapshot, State: s.State, Start: time.UnixMilli(s.Start).UTC()}
		if s.End > 0 {
			end := time.UnixMilli(s.End).UTC()
			sn.End = &end
		}
		out = append(out, sn)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out, nil
}
