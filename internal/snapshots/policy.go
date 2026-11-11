// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package snapshots

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// The policy is OpenSearch's Snapshot Management (the index-management
// plugin, in every OpenSearch distribution since 2.1), the same on 2.17
// and 3.x:
//
//	GET    _plugins/_sm/policies/<name>            the policy, with _seq_no and _primary_term
//	POST   _plugins/_sm/policies/<name>            creates it
//	PUT    _plugins/_sm/policies/<name>?if_seq_no=&if_primary_term=
//	                                               replaces it, only if unchanged
//	DELETE _plugins/_sm/policies/<name>
//	GET    _plugins/_sm/policies/<name>/_explain   when it runs next, how the last run went
//
// Before any policy exists, GET and _explain answer 404 "Snapshot
// management config index not found". OpenSearch runs the policy as the
// user that wrote it, with that user's roles, so Signalith's own
// OpenSearch user needs the snapshot permissions (see Permissions).

// Permissions are the cluster permissions Signalith's OpenSearch user
// needs for scheduled snapshots: the signalith_snapshots role of the
// quick start's roles.yml.
const Permissions = "cluster:admin/opensearch/snapshot_management/policy/write, cluster:admin/opensearch/snapshot_management/policy/get, " +
	"cluster:admin/opensearch/snapshot_management/policy/delete, cluster:admin/opensearch/snapshot_management/policy/explain, " +
	"cluster:admin/snapshot/create, cluster:admin/snapshot/get, cluster:admin/snapshot/delete and cluster:admin/repository/get"

// Role is the role in deploy/docker/opensearch/security/roles.yml with
// Permissions.
const Role = "signalith_snapshots"

// managedBy marks the policy, and the snapshots it takes, as Signalith's.
const managedBy = "signalith"

// PolicyName is the policy's name for an index prefix.
func PolicyName(prefix string) string { return prefix + "-daily" }

// Indices are the indices the snapshots hold: every index of Signalith's,
// the tenants' too, and none of anyone else's.
func Indices(prefix string) string {
	return prefix + "-*," + prefix + "_*," + prefix + ".t.*"
}

// Body is the policy for s that snapshots indices (see Indices and
// IndicesLeavingOut), as it is sent to OpenSearch.
func Body(indices string, s Settings) map[string]any {
	n := s.Normal()
	return map[string]any{
		"description": "Signalith's scheduled snapshots of its own indices. Signalith keeps this policy in step with its backup settings: a change made here is replaced.",
		"enabled":     true,
		"creation": map[string]any{
			"schedule":   map[string]any{"cron": map[string]any{"expression": n.Cron(), "timezone": n.TimeZone}},
			"time_limit": "1h",
		},
		// Deletion runs on the creation schedule when it names none.
		"deletion": map[string]any{
			"condition":  map[string]any{"max_count": n.Keep, "min_count": 1},
			"time_limit": "1h",
		},
		"snapshot_config": map[string]any{
			"repository": n.Repository,
			"indices":    indices,
			// OpenSearch's own settings and its security configuration stay
			// with OpenSearch, as in docs/backup.md.
			"include_global_state": "false",
			"ignore_unavailable":   "true",
			"partial":              "false",
			"metadata":             map[string]any{"created_by": managedBy},
		},
	}
}

// policyDoc is the part of a policy OpenSearch answers that Signalith
// sets, to compare with Body.
type policyDoc struct {
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	EnabledTime int64  `json:"enabled_time"`
	Creation    struct {
		Schedule struct {
			Cron struct {
				Expression string `json:"expression"`
				TimeZone   string `json:"timezone"`
			} `json:"cron"`
		} `json:"schedule"`
	} `json:"creation"`
	Deletion struct {
		Condition struct {
			MaxCount int `json:"max_count"`
			MinCount int `json:"min_count"`
		} `json:"condition"`
	} `json:"deletion"`
	SnapshotConfig struct {
		Repository         string            `json:"repository"`
		Indices            string            `json:"indices"`
		IncludeGlobalState string            `json:"include_global_state"`
		Metadata           map[string]string `json:"metadata"`
	} `json:"snapshot_config"`
}

// ours reports whether Signalith wrote the policy, by the metadata it
// sets. OpenSearch keeps the user that wrote a policy, but neither 2.17
// nor 3.9 shows it in the GET answer, so that cannot be checked.
func (p *policyDoc) ours() bool { return p.SnapshotConfig.Metadata["created_by"] == managedBy }

// key is what of the policy Signalith decides, to tell whether it needs
// writing again.
func (p *policyDoc) key() [8]any {
	return [8]any{p.Enabled, p.Creation.Schedule.Cron.Expression, p.Creation.Schedule.Cron.TimeZone,
		p.Deletion.Condition.MaxCount, p.SnapshotConfig.Repository, p.SnapshotConfig.Indices,
		p.SnapshotConfig.IncludeGlobalState, p.ours()}
}

// desiredDoc is Body read back as OpenSearch answers it.
func desiredDoc(indices string, s Settings) policyDoc {
	var d policyDoc
	b, _ := json.Marshal(Body(indices, s))
	_ = json.Unmarshal(b, &d)
	return d
}

// Client sends a request to OpenSearch; *store.Client is one.
type Client interface {
	Do(ctx context.Context, method, path string, body, out any) error
}

// Manager writes the policy (on the server that runs the background
// jobs) and reports how the snapshots go (on any server).
type Manager struct {
	Client Client
	Prefix string
	// Settings returns the backup settings as they are now.
	Settings func() Settings
	// Allowed, when set, says whether this server runs the background
	// jobs; Run writes nothing while it does not.
	Allowed func() bool
	// Fence, when set, is asked right before each write: it confirms with
	// a fresh read of the job lease that this server still holds it.
	Fence func(ctx context.Context) error
	// Docker says the server runs in the Docker quick start, for the
	// commands in its advice.
	Docker bool
	Log    *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Every is how often Run checks the policy; 0 is a minute.
	Every time.Duration

	mu sync.Mutex
	// last is the outcome of the last Sync on this server.
	last *Synced
	// cached is the last Status, and refreshing is closed when the one
	// being read is done.
	cached     *Status
	refreshing chan struct{}
	// tooMany is set while the cold indices are too many to leave out.
	tooMany bool
	// indices is the indices expression the last Sync wanted, for Status
	// on this server, so that health checks never read the cold set.
	indices string
}

// Synced is what the last Sync did.
type Synced struct {
	At time.Time `json:"at"`
	// Action is created, updated, deleted or "" for nothing to do.
	Action string `json:"action,omitempty"`
	// Problem says what stops Signalith from keeping the policy, and how
	// to fix it.
	Problem string `json:"problem,omitempty"`
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func (m *Manager) settings() Settings {
	if m.Settings == nil {
		return Settings{}
	}
	return m.Settings()
}

// Run keeps the policy in step with the settings until ctx ends: at once,
// then every minute (a changed setting applies within one).
func (m *Manager) Run(ctx context.Context) {
	every := m.Every
	if every <= 0 {
		every = time.Minute
	}
	var lastProblem string
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if m.Allowed == nil || m.Allowed() {
			res, err := m.Sync(ctx)
			switch {
			case err != nil && ctx.Err() == nil:
				m.log().Warn("could not keep the scheduled snapshots' policy; trying again in a minute", "policy", PolicyName(m.Prefix), "err", err)
			case res.Action != "":
				m.log().Info("backup.snapshots: "+res.Action+" OpenSearch's snapshot policy", "audit", true, "policy", PolicyName(m.Prefix),
					"repository", m.settings().Normal().Repository, "schedule", m.settings().Describe())
			case res.Problem != "" && res.Problem != lastProblem:
				m.log().Warn("scheduled snapshots cannot run", "policy", PolicyName(m.Prefix), "problem", res.Problem)
			}
			lastProblem = res.Problem
		}
		t.Reset(every)
	}
}

// Sync writes the policy as the settings want it, deletes it when they
// are off, or says what stops it. It asks Fence before each write.
func (m *Manager) Sync(ctx context.Context) (Synced, error) {
	res, err := m.sync(ctx)
	res.At = m.now()
	if err == nil {
		m.mu.Lock()
		m.last = &res
		// What Status shows changed.
		m.cached = nil
		m.mu.Unlock()
	}
	return res, err
}

func (m *Manager) sync(ctx context.Context) (Synced, error) {
	s := m.settings().Normal()
	name := PolicyName(m.Prefix)
	cur, ver, found, err := m.getPolicy(ctx)
	if err != nil && !s.On {
		// Off, with no policy it may read (no permission, no Snapshot
		// Management): there is nothing of Signalith's to delete.
		if m.problem(err) != "" {
			return Synced{}, nil
		}
		return Synced{}, err
	}
	if err != nil {
		if p := m.problem(err); p != "" {
			return Synced{Problem: p}, nil
		}
		return Synced{}, err
	}
	if !s.On {
		if !found || !cur.ours() {
			return Synced{}, nil
		}
		if err := m.fence(ctx); err != nil {
			return Synced{}, err
		}
		// OpenSearch 2.17 and 3.9 refuse if_seq_no and if_primary_term on
		// this DELETE ("unrecognized parameters"), so it cannot name the
		// version read; the fence just before keeps it to the lease holder.
		if err := m.Client.Do(ctx, http.MethodDelete, "/_plugins/_sm/policies/"+url.PathEscape(name), nil, nil); err != nil && !notFound(err) {
			return Synced{}, err
		}
		return Synced{Action: "deleted"}, nil
	}
	if p, err := m.repository(ctx, s.Repository); err != nil || p != "" {
		return Synced{Problem: p}, err
	}
	if found && !cur.ours() {
		return Synced{Problem: fmt.Sprintf("OpenSearch already has a snapshot policy named %s that Signalith did not make. Delete it (DELETE _plugins/_sm/policies/%s) or give Signalith another opensearch.index_prefix.", name, name)}, nil
	}
	indices, err := m.readIndices(ctx)
	if err != nil {
		return Synced{}, err
	}
	m.mu.Lock()
	m.indices = indices
	m.mu.Unlock()
	want := desiredDoc(indices, s)
	if found && cur.key() == want.key() {
		return Synced{}, nil
	}
	if err := m.fence(ctx); err != nil {
		return Synced{}, err
	}
	path := "/_plugins/_sm/policies/" + url.PathEscape(name)
	action := "created"
	method := http.MethodPost
	if found {
		action, method = "updated", http.MethodPut
		path += fmt.Sprintf("?if_seq_no=%d&if_primary_term=%d", ver.SeqNo, ver.PrimaryTerm)
	}
	if err := m.Client.Do(ctx, method, path, Body(indices, s), nil); err != nil {
		if p := m.problem(err); p != "" {
			return Synced{Problem: p}, nil
		}
		// A conflict means someone changed it meanwhile: the next round
		// reads it again.
		return Synced{}, err
	}
	return Synced{Action: action}, nil
}

func (m *Manager) fence(ctx context.Context) error {
	if m.Fence == nil {
		return nil
	}
	return m.Fence(ctx)
}

// getPolicy reads the policy, and whether there is one.
func (m *Manager) getPolicy(ctx context.Context) (policyDoc, store.Version, bool, error) {
	var resp struct {
		SeqNo       int64     `json:"_seq_no"`
		PrimaryTerm int64     `json:"_primary_term"`
		Policy      policyDoc `json:"sm_policy"`
	}
	err := m.Client.Do(ctx, http.MethodGet, "/_plugins/_sm/policies/"+url.PathEscape(PolicyName(m.Prefix)), nil, &resp)
	if notFound(err) {
		return policyDoc{}, store.Version{}, false, nil
	}
	if err != nil {
		return policyDoc{}, store.Version{}, false, err
	}
	return resp.Policy, store.Version{SeqNo: resp.SeqNo, PrimaryTerm: resp.PrimaryTerm}, true, nil
}

// repository says what is wrong with the repository, or "".
func (m *Manager) repository(ctx context.Context, repo string) (string, error) {
	err := m.Client.Do(ctx, http.MethodGet, "/_snapshot/"+url.PathEscape(repo), nil, nil)
	if err == nil {
		return "", nil
	}
	var se *store.Error
	if errors.As(err, &se) && se.Status == http.StatusNotFound {
		fix := "Register it once with OpenSearch's admin account (see Scheduled snapshots in docs/backup.md)"
		if m.Docker {
			fix = "Register it once: docker compose -f deploy/docker/docker-compose.yml exec opensearch sh snapshot.sh register"
		}
		return fmt.Sprintf("OpenSearch has no snapshot repository named %s. %s, or name a registered one in the backup settings.", repo, fix), nil
	}
	if p := m.problem(err); p != "" {
		return p, nil
	}
	return "", err
}

// problem words an answer from OpenSearch that settles what is wrong
// until someone changes OpenSearch: no permission, or no Snapshot
// Management.
func (m *Manager) problem(err error) string {
	var se *store.Error
	if !errors.As(err, &se) {
		return ""
	}
	body := strings.ToLower(se.Body)
	switch {
	case se.Status == http.StatusForbidden || strings.Contains(body, "security_exception") && strings.Contains(body, "no permissions"):
		fix := "give its OpenSearch user the " + Role + " role from deploy/docker/opensearch/security/roles.yml, which has " + Permissions +
			" (in the Helm chart, set opensearch.snapshotRole: true)"
		if m.Docker {
			fix = "run docker compose -f deploy/docker/docker-compose.yml exec opensearch sh snapshot.sh register, which gives its OpenSearch certificate the " + Role + " role (" + Permissions + ")"
		}
		return "OpenSearch does not let Signalith manage snapshots: " + fix + ". See Scheduled snapshots in docs/backup.md."
	case strings.Contains(body, "no handler found"):
		return "This OpenSearch has no snapshot management (its index-management plugin): install the plugin, or take snapshots another way (see docs/backup.md)."
	case strings.Contains(body, "zone_rules_exception") || strings.Contains(body, "illegal_argument_exception"):
		return "OpenSearch refused the snapshot schedule: " + se.Error()
	}
	return ""
}

// notFound reports a 404 that means there is no such policy (or no
// policy at all yet), not a missing plugin.
func notFound(err error) bool {
	var se *store.Error
	return errors.As(err, &se) && se.Status == http.StatusNotFound && !strings.Contains(strings.ToLower(se.Body), "no handler found")
}

// LastSync returns what the last Sync on this server did, or nil.
func (m *Manager) LastSync() *Synced {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.last == nil {
		return nil
	}
	c := *m.last
	return &c
}
