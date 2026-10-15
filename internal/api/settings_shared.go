package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/redact"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// Once the servers of a cluster share their settings (see
// internal/clustercfg), the Settings page of any server changes the
// settings every server shares and the own settings of any server; only
// the settings a server needs to reach OpenSearch stay in its
// settings.yaml, changed on its own page. A change names the revision of
// each setting it read (if_version): one someone else changed since is
// refused with 412, saying who, where and when; changes to other settings
// never conflict. The settings that apply at once reach every server
// within a few seconds; the others wait for a restart of each server,
// which this page can ask for, one server at a time.

// SettingsStore keeps the settings of the Settings page in the shared
// settings of a cluster. The serve command provides one; without it, or
// while it says Shared is false, the page keeps them in settings.yaml as
// before.
type SettingsStore interface {
	// Shared reports whether this server's settings are shared now.
	Shared() bool
	// HoldFile keeps this server's own settings from moving out of
	// settings.yaml into the shared settings (clustercfg.ImportOwn) until
	// release is called, and reports whether they moved already. A save
	// to settings.yaml holds it, so a save made while they move is never
	// lost: one made before moves with them, and one made after, while
	// the components running still take the settings from settings.yaml
	// (Shared is false until the restart that switches them), goes to the
	// shared settings, where they are now.
	HoldFile() (moved bool, release func())
	// Writable says why the shared settings cannot be changed now (a
	// *shared.PausedError), or nil when they can.
	Writable() error
	// Self returns this server's node id.
	Self() string
	// Layer returns the shared layer of server (a node id) and its
	// nodecfg document: this server's from its own copies, another's
	// read from OpenSearch now.
	Layer(ctx context.Context, server string) (*config.Shared, *shared.NodeCfg, error)
	// ETag is the settings document's ETag, and Revision its revision.
	ETag() string
	Revision() int64
	// Save writes an edit of server's settings checked against base (see
	// clustercfg.Save), and returns the new revision of each setting
	// written.
	Save(ctx context.Context, by, server string, base *config.Shared, res *config.SharedEditResult, versions map[string]int64) (map[string]int64, error)
	// Check asks server to check a change of its own settings against its
	// own files, environment and certificate files, and waits up to
	// clustercfg.SettingsCheckWait for its answer; answered is false when
	// none came in time.
	Check(ctx context.Context, by, server string, args clustercfg.SettingsCheckArgs) (res *clustercfg.SettingsCheckResult, answered bool, err error)
	// Restart asks servers (node ids) to restart, one after the other
	// when sequential.
	Restart(ctx context.Context, by string, servers []string, sequential bool) (*shared.Request, error)
}

// settingsShared reports whether the Settings page changes the shared
// settings now.
func (s *Server) settingsShared() bool {
	return s.Settings != nil && s.Settings.Shared() && s.Config.Path() != ""
}

// savedShared returns this server's configuration as saved, with the
// shared layer as it is now.
func (s *Server) savedShared(ctx context.Context) (*config.Saved, *config.Shared, *shared.NodeCfg, error) {
	sh, nc, err := s.Settings.Layer(ctx, "")
	if err != nil {
		return nil, nil, nil, err
	}
	saved, err := config.LoadSavedShared(s.Config.Path(), sh)
	return saved, sh, nc, err
}

// sharedServer is a server as the Settings page lists them.
type sharedServer struct {
	NodeID  string `json:"node_id"`
	Name    string `json:"name"`
	Self    bool   `json:"self"`
	Offline bool   `json:"offline"`
	NodeURL string `json:"node_url,omitempty"`
	// RestartNeeded lists the settings that wait for its restart, and
	// Refused the shared settings it could not use.
	RestartNeeded []string               `json:"restart_needed"`
	Refused       []string               `json:"refused"`
	Restart       *cluster.RestartStatus `json:"restart,omitempty"`
	SettingsRev   *cluster.SettingsRev   `json:"settings_rev,omitempty"`
}

// sharedServers lists the servers from their heartbeats.
func (s *Server) sharedServers() []sharedServer {
	out := []sharedServer{}
	if s.Cluster == nil {
		return out
	}
	for _, sv := range s.Cluster.Status().Servers {
		// A server stopped, or whose heartbeat stopped, is listed as
		// offline: its settings can be changed, and it checks them when it
		// starts; it cannot be asked to restart.
		v := sharedServer{NodeID: sv.NodeID, Name: sv.Name, Self: sv.Self, Offline: !sv.Self && (sv.State == cluster.StateOffline || sv.State == cluster.StateStopped),
			RestartNeeded: []string{}, Refused: []string{}}
		if d := sv.Detail; d != nil {
			v.NodeURL, v.Restart, v.SettingsRev = d.NodeURL, d.Restart, d.SettingsRev
			v.RestartNeeded, v.Refused = nonNil(d.RestartNeeded), nonNil(d.SettingsRefused)
		}
		out = append(out, v)
	}
	return out
}

// serverNamed finds a server by node id or name; "" is this server.
func (s *Server) serverNamed(name string) (sharedServer, bool) {
	list := s.sharedServers()
	for _, sv := range list {
		if name == "" && sv.Self || name != "" && (sv.NodeID == name || strings.EqualFold(sv.Name, name)) {
			return sv, true
		}
	}
	if name == "" || name == s.Settings.Self() {
		// No heartbeat read yet: this server all the same.
		return sharedServer{NodeID: s.Settings.Self(), Self: true, RestartNeeded: []string{}, Refused: []string{}}, true
	}
	return sharedServer{}, false
}

// keptSetting is a shared value a server could not use, and keeps its
// own value of.
type keptSetting struct {
	Reason string    `json:"reason"`
	At     time.Time `json:"at,omitzero"`
}

// sourceWords words where a shared value came from, for its field: who
// changed it on which server, or the file it came from when it changed
// there.
func sourceWords(src config.Source) string {
	day := ""
	if !src.At.IsZero() {
		day = ", " + src.At.UTC().Format("2 Jan")
	}
	switch src.Applied {
	case "env":
		return "applied from the environment on " + src.Node + day
	case "yaml":
		return "applied from signalith.yaml on " + src.Node + day
	}
	return ""
}

// decorateShared adds to the view of this server's settings what a page
// of shared settings shows: each field's scope, revision and provenance,
// the shared values this server keeps its own value of, the other
// servers' state, and the settings document's ETag.
func (s *Server) decorateShared(view map[string]any, sh *config.Shared, nc *shared.NodeCfg, saved *config.Saved) {
	servers := s.sharedServers()
	sections, _ := view["sections"].([]settingsSection)
	for i := range sections {
		for j := range sections[i].Fields {
			f := &sections[i].Fields[j]
			set, _ := config.Lookup(f.Key)
			f.Scope = string(set.Scope)
			switch set.Scope {
			case config.ScopeCluster:
				v := sh.Rev(f.Key)
				f.Version = &v
				f.AppliedFrom = sourceWords(f.Source)
				if r, ok := saved.SharedKept(f.Key); ok {
					f.Kept = &keptSetting{Reason: r.Reason, At: r.At}
				}
				// Where a change that waits for a restart is in use yet.
				if set.Restart {
					f.Servers = serverStates(servers, f.Key, s.Settings.Revision())
				}
			case config.ScopeServer:
				var v int64
				if nc != nil {
					v = nc.ValueRev(f.Key)
				}
				f.Version = &v
			}
		}
	}
	self, _ := s.serverNamed("")
	var migrated []shared.MigratedValue
	if nc != nil {
		migrated = nc.Migrated
	}
	view["migrated"] = migratedView(migrated)
	view["shared"] = true
	view["server"] = self
	view["servers"] = servers
	view["etag"] = s.Settings.ETag()
	view["writable"] = s.Settings.Writable() == nil
	if err := s.Settings.Writable(); err != nil {
		view["paused"] = sentence(err.Error())
	}
}

// migratedView is a server's settings that differed from the shared ones
// when they were moved to the shared settings, as the page shows them:
// an address with a user name and password in it shown without them.
func migratedView(list []shared.MigratedValue) []shared.MigratedValue {
	out := make([]shared.MigratedValue, 0, len(list))
	for _, m := range list {
		if set, ok := config.Lookup(m.Key); ok && set.Type == config.TypeURL || urlKeys[m.Key] {
			m.Value, m.Shared = redactedRaw(m.Value), redactedRaw(m.Shared)
		}
		out = append(out, m)
	}
	return out
}

// redactedRaw is an address as JSON without the password in it.
func redactedRaw(raw json.RawMessage) json.RawMessage {
	var str string
	if len(raw) == 0 || json.Unmarshal(raw, &str) != nil {
		return raw
	}
	out, err := json.Marshal(redact.URL(str))
	if err != nil {
		return nil
	}
	return out
}

// serverStates says, by server name, where a shared setting that waits
// for a restart is in use: "refused" where the server could not use it,
// "waiting" where it waits for the server's restart, or where the
// server's last heartbeat had not seen the settings document at
// revision rev yet, "offline" for a server stopped or not heard from
// (what it said last may predate the change), else "applied". A value
// refused somewhere, or not known to be in use, is never said to be
// applied there.
func serverStates(servers []sharedServer, key string, rev int64) map[string]string {
	out := map[string]string{}
	for _, sv := range servers {
		switch {
		case sv.Offline:
			out[sv.Name] = "offline"
		case slices.Contains(sv.Refused, key):
			out[sv.Name] = "refused"
		case slices.Contains(sv.RestartNeeded, key), rev > 0 && (sv.SettingsRev == nil || sv.SettingsRev.Settings < rev):
			out[sv.Name] = "waiting"
		default:
			out[sv.Name] = "applied"
		}
	}
	return out
}

// sharedSettingsView is GET /api/settings on a server whose settings are
// shared: this server's (server is "" or its own), or another's.
func (s *Server) sharedSettingsView(ctx context.Context, server string) (map[string]any, error) {
	sv, ok := s.serverNamed(server)
	if !ok {
		return nil, errUnknownServer(server)
	}
	if sv.Self {
		view, err := s.settingsView()
		if err != nil {
			return nil, err
		}
		saved, sh, nc, err := s.savedShared(ctx)
		if err != nil {
			return nil, err
		}
		s.decorateShared(view, sh, nc, saved)
		return view, nil
	}
	return s.otherServerView(ctx, sv)
}

type errUnknownServer string

func (e errUnknownServer) Error() string {
	return fmt.Sprintf("no server %q shares this OpenSearch", string(e))
}

// otherServerView is the Settings page of another server: the shared
// settings as this server has them, that server's own settings from its
// nodecfg (as changed on a page, and as it runs them), and no connection
// and folder settings, which only its own page changes.
func (s *Server) otherServerView(ctx context.Context, sv sharedServer) (map[string]any, error) {
	saved, sh, _, err := s.savedShared(ctx)
	if err != nil {
		return nil, err
	}
	osh, nc, err := s.Settings.Layer(ctx, sv.NodeID)
	if err != nil {
		return nil, fmt.Errorf("the settings of %s cannot be read now: %w", sv.Name, err)
	}
	servers := s.sharedServers()
	if nc == nil {
		nc = &shared.NodeCfg{}
	}
	sections := make([]settingsSection, 0, len(config.Sections))
	for _, sec := range config.Sections {
		out := settingsSection{ID: sec.ID, Title: sec.Title, Help: sec.Help, Fields: []settingField{}}
		for i := range config.Registry {
			set := &config.Registry[i]
			if set.Section != sec.ID || !set.OnPage(true) || set.Scope == config.ScopeBootstrap {
				continue
			}
			f := settingField{Key: set.Key, Label: set.Label, Help: set.Help, Type: set.Type, Choices: set.Choices,
				Min: set.Min, Max: set.Max, Placeholder: set.Placeholder, EmptyMeans: set.EmptyMeans, Env: set.Env, Apply: "live",
				Dangerous: set.Confirm != "", Confirm: set.Confirm, ConfirmWhen: set.ConfirmWhen, Scope: string(set.Scope)}
			if set.Restart {
				f.Apply = "restart"
			}
			switch set.Scope {
			case config.ScopeCluster:
				f.Value, f.Set = fieldValue(saved.Config, set)
				f.Source = saved.Source(set.Key)
				f.AppliedFrom = sourceWords(f.Source)
				v := sh.Rev(set.Key)
				f.Version = &v
				if r, ok := osh.Refused[set.Key]; ok {
					f.Kept = &keptSetting{Reason: r.Reason, At: r.At}
				}
				f.Pending = slices.Contains(sv.RestartNeeded, set.Key)
				if set.Restart {
					f.Servers = serverStates(servers, set.Key, s.Settings.Revision())
				}
			case config.ScopeServer:
				pv, onPage := nc.Values[set.Key]
				run, runs := nc.Running[set.Key]
				v := nc.ValueRev(set.Key)
				f.Version = &v
				switch {
				case onPage && pv.Refused != "":
					f.Refused = &config.RefusedSetting{Key: set.Key, Reason: pv.Refused, At: pv.RefusedAt, By: pv.From.By}
					f.Source = config.Source{Kind: run.Source, Env: run.Env}
					f.Value = rawValue(run.Value)
				case onPage:
					f.Value = rawValue(pv.Value)
					f.Source = config.Source{Kind: config.FromPage, By: pv.From.By, At: pv.From.At, Node: pv.From.Node}
				case runs:
					f.Value = rawValue(run.Value)
					f.Source = config.Source{Kind: run.Source, Env: run.Env}
				default:
					f.Source = config.Source{Kind: config.FromDefault}
				}
				if runs && run.Source == config.FromEnv {
					f.Locked, f.LockedReason = true, config.LockedReason(run.Env)
				}
				f.Pending = slices.Contains(sv.RestartNeeded, set.Key)
				if str, ok := f.Value.(string); ok && urlKeys[set.Key] {
					f.Value = redact.URL(str)
				}
			}
			out.Fields = append(out.Fields, f)
		}
		sections = append(sections, out)
	}
	var restart map[string]any
	if sv.Restart != nil {
		restart = map[string]any{"in_progress": sv.Restart.Busy, "last": sv.Restart.Last}
	} else {
		restart = map[string]any{"in_progress": false, "last": nil}
	}
	restart["needed"] = len(sv.RestartNeeded) > 0
	restart["available"] = !sv.Offline
	elsewhere := "Change the connection and folder settings of " + sv.Name + " on its own Settings page"
	if sv.NodeURL != "" {
		elsewhere += ", at " + sv.NodeURL
	}
	return map[string]any{
		"sections":  sections,
		"editable":  true,
		"shared":    true,
		"server":    sv,
		"servers":   servers,
		"etag":      s.Settings.ETag(),
		"writable":  s.Settings.Writable() == nil,
		"restart":   restart,
		"bootstrap": map[string]any{"elsewhere": elsewhere + ".", "node_url": sv.NodeURL},
		"migrated":  migratedView(nc.Migrated),
		"pending":   []pendingSetting{},
		"refused":   []config.RefusedSetting{},
		"problems":  []string{},
		"warnings":  []string{},
	}, nil
}

// settingsPending returns why a member of a cluster does not share its
// settings yet, as usersPending does for the users: the servers whose
// version cannot read them, or none while the server that founded the
// cluster has not brought its settings in. nil on a server that shares
// them, or that is no member.
func (s *Server) settingsPending() *sharedPending {
	if s.settingsShared() || !s.sharedContent() {
		return nil
	}
	out := &sharedPending{Version: s.Version, Servers: []pendingServer{}}
	if s.Cluster == nil {
		return out
	}
	for _, sv := range s.Cluster.Status().Servers {
		if sv.Self || sv.SeenAgo != nil && *sv.SeenAgo >= shared.LevelSeen {
			continue
		}
		if sv.Detail == nil || max(sv.Detail.LevelMax, 1) < shared.LevelSharedSettings {
			out.Servers = append(out.Servers, pendingServer{Name: sv.Name, Version: sv.Version})
		}
	}
	return out
}

// rawValue is a value as JSON for the page; nil for none.
func rawValue(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	return v
}

// sharedSettingsRequest is the body of PUT /api/settings on a server
// whose settings are shared: settingsRequest, with the server whose
// settings change ("" for this one), the scope to change when only one,
// and the revision of each setting as the page read it.
type sharedSettingsRequest struct {
	settingsRequest
	Server    string           `json:"server"`
	Scope     string           `json:"scope"`
	IfVersion map[string]int64 `json:"if_version"`
}

// scopeEdit is the part of a change of one scope.
type scopeEdit struct {
	scope config.Scope
	edit  config.Edit
	res   *config.SharedEditResult
	// note says why the change was saved without being checked on the
	// server it is for.
	note string
	// confirm is what that server asks before saving.
	confirm []string
}

// splitEdit splits a change of the page by the scope of each setting, or
// keeps it whole for one scope. ResetAll takes the page of the server
// back: its own settings and its connection and folder settings, never
// the shared ones, unless only those are named.
func splitEdit(req sharedSettingsRequest, by string, at time.Time) []*scopeEdit {
	parts := map[config.Scope]*scopeEdit{}
	part := func(key string) *scopeEdit {
		sc := config.Scope(req.Scope)
		if sc == "" {
			if sc = config.ScopeOf(key); sc == "" {
				// Not a setting at all: the page's own check names it.
				sc = config.ScopeCluster
			}
			if key == "detections.scheduler" {
				sc = config.ScopeServer
			}
		}
		p := parts[sc]
		if p == nil {
			p = &scopeEdit{scope: sc, edit: config.Edit{Values: map[string]any{}, By: by, At: at}}
			parts[sc] = p
		}
		return p
	}
	for k, v := range req.Values {
		part(k).edit.Values[k] = v
	}
	for _, k := range req.Clear {
		p := part(k)
		p.edit.Clear = append(p.edit.Clear, k)
	}
	for _, k := range req.Reset {
		p := part(k)
		p.edit.Reset = append(p.edit.Reset, k)
	}
	for _, k := range req.Retry {
		p := part(k)
		p.edit.Retry = append(p.edit.Retry, k)
	}
	if req.ResetAll {
		scopes := []config.Scope{config.ScopeServer, config.ScopeBootstrap}
		if req.Scope != "" {
			scopes = []config.Scope{config.Scope(req.Scope)}
		}
		for _, sc := range scopes {
			p := parts[sc]
			if p == nil {
				p = &scopeEdit{scope: sc, edit: config.Edit{Values: map[string]any{}, By: by, At: at}}
				parts[sc] = p
			}
			p.edit.ResetAll = true
		}
	}
	// Written in this order: a failure part way leaves the shared
	// settings, which every server checks, changed first.
	var out []*scopeEdit
	for _, sc := range []config.Scope{config.ScopeCluster, config.ScopeServer, config.ScopeBootstrap} {
		if p := parts[sc]; p != nil {
			out = append(out, p)
		}
	}
	for sc, p := range parts {
		if sc != config.ScopeCluster && sc != config.ScopeServer && sc != config.ScopeBootstrap {
			out = append(out, p)
		}
	}
	return out
}

// handlePutSharedSettings is PUT /api/settings on a server whose settings
// are shared.
func (s *Server) handlePutSharedSettings(w http.ResponseWriter, r *http.Request, body []byte) {
	var req sharedSettingsRequest
	if err := decodeJSON(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Scope != "" && req.Scope != string(config.ScopeCluster) && req.Scope != string(config.ScopeServer) && req.Scope != string(config.ScopeBootstrap) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no settings have the scope %q", req.Scope))
		return
	}
	sv, ok := s.serverNamed(req.Server)
	if !ok {
		writeError(w, http.StatusNotFound, errUnknownServer(req.Server))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	saved, sh, _, err := s.savedShared(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	base := sh
	if !sv.Self {
		if base, _, err = s.Settings.Layer(ctx, sv.NodeID); err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("the settings of %s cannot be read now: %w", sv.Name, err))
			return
		}
	}
	parts := splitEdit(req, userOf(r), time.Now())
	// Try again of a shared value another server could not use takes its
	// refusal out of that server's nodecfg; the shared values themselves
	// are checked on this server, whichever server's page this is.
	var retryThere []string
	if !sv.Self {
		for _, p := range parts {
			if p.scope == config.ScopeCluster {
				retryThere, p.edit.Retry = p.edit.Retry, nil
			}
		}
	}
	fields := map[string]string{}
	var problems []string
	for _, p := range parts {
		if p.scope != config.ScopeBootstrap {
			if err := s.Settings.Writable(); err != nil {
				writeError(w, http.StatusServiceUnavailable, err)
				return
			}
		}
		switch {
		case p.scope == config.ScopeBootstrap && !sv.Self:
			for _, k := range editKeys(p.edit) {
				fields[k] = "Change this on the Settings page of " + sv.Name + " itself: it is one of the settings it needs to reach OpenSearch."
			}
			continue
		case p.scope == config.ScopeServer && !sv.Self:
			err = s.checkOnServer(ctx, r, sv, base, p)
		default:
			p.res, err = config.CheckEditShared(s.Config.Path(), sh, p.scope, p.edit)
		}
		switch {
		case errors.Is(err, config.ErrPageFile):
			writeJSON(w, http.StatusConflict, map[string]any{"error": "Nothing was saved, because the settings file cannot be read. Fix it on the server, or start a new one.", "code": "settings_file"})
			return
		case err != nil:
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		maps.Copy(fields, p.res.Fields)
		problems = append(problems, p.res.Problems...)
	}
	if len(fields) > 0 || len(problems) > 0 {
		msg := "Nothing was saved. Fix the settings marked below."
		if len(problems) > 0 {
			msg = "Nothing was saved, because the settings have problems: " + strings.Join(problems, "; ") + "."
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg, "fields": fields, "problems": nonNil(problems)})
		return
	}
	// The proxy the browser came through is this server's: a shared
	// change applies here too, whichever server's page it was saved on,
	// and its Config is this server's with the change. A change of
	// another server's own settings is not.
	for _, p := range parts {
		if p.res.Config == nil || !sv.Self && p.scope != config.ScopeCluster {
			continue
		}
		if msg := s.proxyLockout(r, p.res.Config); msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Nothing was saved. Fix the settings marked below.",
				"fields": map[string]string{"server.trusted_proxies": msg}, "problems": []string{}})
			return
		}
	}
	if req.CheckOnly {
		changed, confirm := []string{}, []confirmation{}
		var notes []string
		for _, p := range parts {
			changed = append(changed, p.res.Changed...)
			if p.res.Config != nil {
				confirm = append(confirm, confirmations(r, &p.res.EditResult)...)
			}
			for _, k := range p.confirm {
				if set, ok := config.Lookup(k); ok && set.Confirm != "" {
					confirm = append(confirm, confirmation{Key: k, Text: set.Confirm})
				}
			}
			if p.note != "" {
				notes = append(notes, p.note)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": changed, "confirm": confirm, "notes": nonNil(notes)})
		return
	}
	var savedKeys, notes []string
	versions := map[string]int64{}
	for _, p := range parts {
		if len(p.res.Touched) == 0 && p.res.Page == nil {
			continue
		}
		switch p.scope {
		case config.ScopeBootstrap:
			err = s.pages().Write(p.res.Page)
		case config.ScopeCluster:
			var revs map[string]int64
			revs, err = s.Settings.Save(ctx, userOf(r), s.Settings.Self(), sh, p.res, req.IfVersion)
			maps.Copy(versions, revs)
		default:
			var revs map[string]int64
			revs, err = s.Settings.Save(ctx, userOf(r), sv.NodeID, base, p.res, req.IfVersion)
			maps.Copy(versions, revs)
		}
		if err != nil {
			if len(savedKeys) > 0 {
				err = fmt.Errorf("%w (%s were saved before this)", err, strings.Join(savedKeys, ", "))
			}
			var stale *shared.StaleError
			if errors.As(err, &stale) && len(savedKeys) > 0 {
				// The page says which were saved, and that only the rest
				// were refused.
				body := staleBody(err, stale)
				body["saved"] = savedKeys
				writeJSON(w, http.StatusPreconditionFailed, body)
				return
			}
			if !sharedError(w, err) {
				writeError(w, http.StatusInternalServerError, err)
			}
			return
		}
		savedKeys = append(savedKeys, p.res.Changed...)
		if p.note != "" {
			notes = append(notes, p.note)
		}
		s.audit(r, "settings saved", "scope", string(p.scope), "server", sv.Name, "changes", describeChanges(&p.res.EditResult),
			"reset", strings.Join(p.edit.Reset, ","), "cleared", strings.Join(p.edit.Clear, ","), "retried", strings.Join(p.edit.Retry, ","),
			"reset_all", p.edit.ResetAll)
	}
	if len(retryThere) > 0 && !req.CheckOnly {
		next := base.Clone()
		var touched []string
		for _, k := range retryThere {
			if _, ok := next.Refused[k]; ok {
				delete(next.Refused, k)
				touched = append(touched, k)
			}
		}
		if len(touched) > 0 {
			res := &config.SharedEditResult{EditResult: config.EditResult{Fields: map[string]string{}}, Scope: config.ScopeCluster,
				Shared: next, Touched: touched}
			if _, err := s.Settings.Save(ctx, userOf(r), sv.NodeID, base, res, nil); err != nil {
				if !sharedError(w, err) {
					writeError(w, http.StatusInternalServerError, err)
				}
				return
			}
			savedKeys = append(savedKeys, touched...)
			s.audit(r, "settings saved", "scope", string(config.ScopeCluster), "server", sv.Name, "retried", strings.Join(touched, ","))
		}
	}
	var applied, restart []string
	if sv.Self {
		// What applies at once is used here now; the other servers use
		// it within a few seconds.
		if after, _, _, err := s.savedShared(ctx); err == nil && after.Problems == nil {
			applied = s.applyLive(saved.Config, after.Config)
			running := s.conf()
			for _, k := range savedKeys {
				if !slices.Contains(applied, k) && !config.SameValue(running, after.Config, k) {
					restart = append(restart, k)
				}
			}
		}
	}
	view, err := s.sharedSettingsView(ctx, req.Server)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	view["saved"], view["applied"], view["after_restart"] = nonNil(savedKeys), nonNil(applied), nonNil(restart)
	view["versions"], view["notes"] = versions, nonNil(notes)
	writeJSON(w, http.StatusOK, view)
}

// editKeys lists the settings a change names.
func editKeys(e config.Edit) []string {
	keys := slices.Collect(maps.Keys(e.Values))
	keys = append(keys, e.Clear...)
	keys = append(keys, e.Reset...)
	keys = append(keys, e.Retry...)
	slices.Sort(keys)
	return slices.Compact(keys)
}

// checkOnServer checks a change of another server's own settings: their
// types here, then, when that server answers in time, against its own
// files, environment and certificate files there. One offline, or slow
// to answer, is saved after the type checks alone; that server checks it
// when it starts, and refuses it then if need be.
func (s *Server) checkOnServer(ctx context.Context, r *http.Request, sv sharedServer, base *config.Shared, p *scopeEdit) error {
	_, nc, err := s.Settings.Layer(ctx, sv.NodeID)
	if err != nil {
		return err
	}
	env := map[string]string{}
	if nc != nil {
		for k, run := range nc.Running {
			if run.Source == config.FromEnv {
				env[k] = run.Env
			}
		}
	}
	p.res = config.EditServer(base, p.edit, env)
	if len(p.res.Fields) > 0 || len(p.res.Touched) == 0 {
		return nil
	}
	if sv.Offline {
		p.note = sv.Name + " is offline; it checks this change when it starts."
		return nil
	}
	args := clustercfg.SettingsCheckArgs{Values: map[string]json.RawMessage{}, Clear: p.edit.Clear, Reset: p.edit.Reset, Retry: p.edit.Retry}
	for k, v := range p.edit.Values {
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		args.Values[k] = raw
	}
	res, answered, err := s.Settings.Check(ctx, userOf(r), sv.NodeID, args)
	switch {
	case err != nil:
		p.note = fmt.Sprintf("%s could not be asked to check this change (%v); it checks it when it starts.", sv.Name, err)
	case !answered:
		p.note = sv.Name + " did not answer in time; it checks this change when it starts."
	default:
		maps.Copy(p.res.Fields, res.Fields)
		p.res.Problems = append(p.res.Problems, res.Problems...)
		p.confirm = res.Confirm
	}
	return nil
}

// CheckOwnEdit checks a change of this server's own settings asked for
// on another server's Settings page (a settings_check request) against
// this server's files, environment and certificate files.
func (s *Server) CheckOwnEdit(ctx context.Context, by string, args clustercfg.SettingsCheckArgs) (*clustercfg.SettingsCheckResult, error) {
	if !s.settingsShared() {
		return nil, errors.New("this server's settings are not shared now")
	}
	e := config.Edit{Values: map[string]any{}, Clear: args.Clear, Reset: args.Reset, Retry: args.Retry, By: by, At: time.Now()}
	for k, raw := range args.Values {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		e.Values[k] = v
	}
	_, sh, _, err := s.savedShared(ctx)
	if err != nil {
		return nil, err
	}
	res, err := config.CheckEditShared(s.Config.Path(), sh, config.ScopeServer, e)
	if err != nil {
		return nil, err
	}
	out := &clustercfg.SettingsCheckResult{Fields: res.Fields, Problems: res.Problems, Changed: res.Changed}
	if res.OK() {
		for _, c := range confirmations(&http.Request{RemoteAddr: "127.0.0.1:0"}, &res.EditResult) {
			out.Confirm = append(out.Confirm, c.Key)
		}
	}
	return out, nil
}

// ApplySettings puts the settings that changed from old to next and apply
// at once into use, as a save on this page does, and returns their keys:
// the serve command calls it when another server changed the shared
// settings, or this server's own.
func (s *Server) ApplySettings(old, next *config.Config) []string {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	return s.applyLive(old, next)
}

// sharedLiveKeys are shared settings that are not on the page and apply
// at once: the shared agent tokens of older setups, which the agent
// tokens read from the configuration in use, and how often retention
// runs (the serve command tells the retention manager).
var sharedLiveKeys = []string{"ingest.tokens", "retention.interval"}

// clusterRestartRequest is the body of POST /api/cluster/restart.
type clusterRestartRequest struct {
	// Servers are node ids or names, in the order to restart them.
	Servers    []string `json:"servers"`
	Sequential bool     `json:"sequential"`
}

// handleClusterRestart asks servers to restart, one after the other when
// sequential, so they apply the settings that wait for a restart. It
// answers 202 with the request's id, which GET /api/requests/{id}
// follows.
func (s *Server) handleClusterRestart(w http.ResponseWriter, r *http.Request) {
	if !s.settingsShared() {
		writeError(w, http.StatusConflict, errors.New("this server's settings are not shared with other servers; restart it on its Settings page"))
		return
	}
	var req clusterRestartRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Servers) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("name the servers to restart"))
		return
	}
	var ids, names []string
	for _, name := range req.Servers {
		sv, ok := s.serverNamed(name)
		if !ok || name == "" {
			writeError(w, http.StatusBadRequest, errUnknownServer(name))
			return
		}
		if sv.Offline {
			writeError(w, http.StatusConflict, fmt.Errorf("%s is offline, so it cannot be asked to restart; it applies the settings when it starts", sv.Name))
			return
		}
		if slices.Contains(ids, sv.NodeID) {
			continue
		}
		ids, names = append(ids, sv.NodeID), append(names, sv.Name)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rq, err := s.Settings.Restart(ctx, userOf(r), ids, req.Sequential)
	if err != nil {
		if !sharedError(w, err) {
			writeError(w, http.StatusServiceUnavailable, err)
		}
		return
	}
	s.audit(r, "restart of servers requested", "servers", strings.Join(names, ","), "sequential", req.Sequential, "request", rq.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{"request_id": rq.ID, "servers": names})
}

// ExportServer is one server whose own settings ExportShared writes:
// Value gives each one's value, and Err says why they cannot be read.
type ExportServer struct {
	Name  string
	Value func(key string) any
	Err   error
}

// NodeCfgValue gives the value of each of a server's own settings from
// its nodecfg document: the one saved for it, or the one it runs.
func NodeCfgValue(nc *shared.NodeCfg) func(key string) any {
	return func(key string) any {
		if key == "detections.scheduler" {
			key = "cluster.leader_eligible"
		}
		if nc == nil {
			return nil
		}
		if pv, ok := nc.Values[key]; ok && pv.Refused == "" {
			return rawValue(pv.Value)
		}
		return rawValue(nc.Running[key].Value)
	}
}

// exportShared is GET /api/settings/export while the settings are
// shared: ExportShared, for every server or only server (a node id or
// name).
func (s *Server) exportShared(ctx context.Context, saved *config.Saved, server string, now time.Time) (string, error) {
	self, _ := s.serverNamed("")
	var list []ExportServer
	for _, sv := range s.sharedServers() {
		if server != "" && sv.NodeID != server && !strings.EqualFold(sv.Name, server) {
			continue
		}
		e := ExportServer{Name: sv.Name, Value: saved.Config.Value}
		if !sv.Self {
			_, nc, err := s.Settings.Layer(ctx, sv.NodeID)
			e.Value, e.Err = NodeCfgValue(nc), err
		}
		list = append(list, e)
	}
	return ExportShared(saved.Config, self.Name, list, now)
}

// ExportShared writes the shared settings as c has them, as
// signalith.yaml sections: the file signalith cluster apply -f takes.
// Then each server's own settings follow as comments marked as that
// server's only, so pasting the file never turns on a second server's
// background jobs. from names the server it is exported from.
func ExportShared(c *config.Config, from string, servers []ExportServer, now time.Time) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# Settings shared by the servers of this cluster, exported from %s on %s.\n", from, now.UTC().Format("2006-01-02"))
	b.WriteString("# signalith cluster apply -f takes this file as it is. Passwords and keys\n")
	b.WriteString("# are left out: set them on the Settings page.\n")
	var list []*config.Setting
	for i := range config.Registry {
		if set := &config.Registry[i]; set.Scope == config.ScopeCluster && set.OnPage(true) {
			list = append(list, set)
		}
	}
	fileOnly := func(set *config.Setting) string {
		if set.File {
			return "a file on this server"
		}
		return ""
	}
	if err := (exporter{value: c.Value, note: fileOnly}).write(&b, list); err != nil {
		return "", err
	}
	var own []*config.Setting
	for i := range config.Registry {
		if set := &config.Registry[i]; set.Scope == config.ScopeServer && set.OnPage(true) {
			own = append(own, set)
		}
	}
	if old, ok := config.Lookup("detections.scheduler"); ok {
		own = append(own, old)
	}
	only := func(set *config.Setting) string {
		if set.Key == "detections.scheduler" {
			return "this server only (the old name of cluster.leader_eligible)"
		}
		if set.File {
			return "a file on this server"
		}
		return "this server only"
	}
	for _, sv := range servers {
		if sv.Err != nil {
			fmt.Fprintf(&b, "\n# %s's own settings cannot be read now (%v).\n", sv.Name, sv.Err)
			continue
		}
		fmt.Fprintf(&b, "\n# %s's own settings: for that server alone, changed on any server's\n# Settings page; never paste them for another server.\n", sv.Name)
		if err := (exporter{value: sv.Value, note: only, comment: true}).write(&b, own); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}
