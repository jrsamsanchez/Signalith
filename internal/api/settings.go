package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/clientaddr"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/redact"
	"github.com/jrsamsanchez/signalith/internal/store"
	"gopkg.in/yaml.v3"
)

// The Settings page changes the server's settings. Values saved there go
// to their own file (see config.PageSettings), never to signalith.yaml;
// environment variables still win over them. Settings that are simple to
// change while running apply at once; the others wait for a restart,
// which the server does in-process (see Restarter).

func (s *Server) routeSettings(api *router) {
	api.admin("GET /api/settings", s.handleGetSettings)
	api.admin("PUT /api/settings", s.handlePutSettings)
	api.admin("POST /api/settings/test/opensearch", s.handleTestOpenSearch)
	api.admin("POST /api/settings/test/assistant", s.handleTestAssistant)
	api.admin("POST /api/settings/restart", s.handleRestart)
	api.admin("POST /api/settings/restart/confirm", s.handleConfirmMove)
	api.admin("GET /api/settings/export", s.handleExportSettings)
}

// Restarter restarts the server in-process with the saved settings. The
// serve command provides one; without it the page can save settings but
// not restart.
type Restarter interface {
	// Restart begins a restart shortly after it returns, so the answer to
	// the request that asked for it still goes out. It returns
	// ErrRestarting while one is under way, and ErrAwaitingMove while a
	// move of the web page waits for someone to reach the new address.
	// localOnly is true when the admin agreed that the web page will
	// answer on the server itself only: then a move is not undone when
	// nobody reaches the new address from elsewhere.
	Restart(by, client string, localOnly bool) error
	// RestartStatus reports whether a restart is under way and how the
	// last one went.
	RestartStatus() RestartStatus
	// Confirm tells a restart that moved the web page that someone
	// reached it at its new address, when r came in there. It reports
	// whether it did.
	Confirm(r *http.Request) bool
}

// ErrRestarting refuses a restart while one is under way.
var ErrRestarting = errors.New("a restart is already under way; wait for it to finish")

// ErrAwaitingMove refuses a restart while the web page waits for someone
// to reach it at its new address.
var ErrAwaitingMove = errors.New("Signalith moved to a new web address and waits for someone to open this page there. Open it at the new address first, or wait until Signalith goes back by itself")

// MoveWait is how long a restart that moves the web page waits for
// someone to reach the new address before it goes back to the old one.
const MoveWait = 2 * time.Minute

// RestartStatus is the state of restarts.
type RestartStatus struct {
	InProgress bool `json:"in_progress"`
	// Last is how the last restart went; nil before the first.
	Last *RestartResult `json:"last"`
	// Awaiting is set while a move of the web page waits for someone to
	// reach the new address.
	Awaiting *AwaitingMove `json:"awaiting,omitempty"`
}

// AwaitingMove is a move of the web page that waits to be confirmed.
type AwaitingMove struct {
	// From and To are the old and new listen addresses, with the scheme.
	From  string    `json:"from"`
	To    string    `json:"to"`
	Until time.Time `json:"until"`
	// Keys are the settings that moved it.
	Keys []string `json:"keys"`
}

// RestartResult is how a restart went.
type RestartResult struct {
	At time.Time `json:"at"`
	By string    `json:"by"`
	OK bool      `json:"ok"`
	// Error says why it failed, and that the previous settings were kept.
	Error string `json:"error,omitempty"`
	// RolledBack is true when the new settings failed after the switch and
	// the previous ones were started again.
	RolledBack bool `json:"rolled_back,omitempty"`
	// Keys are the settings it applied, or tried to.
	Keys []string `json:"keys"`
	// ProblemKeys are the settings a failure is about, when known.
	ProblemKeys []string `json:"problem_keys,omitempty"`
	// Refused lists the changes made on the Settings page that were set
	// aside for it: they are not used, not even when Signalith next
	// starts, until they are tried again or changed.
	Refused []string `json:"refused,omitempty"`
	// Reverted is true when nobody reached the web page at its new
	// address in time, so Signalith went back to the previous one.
	Reverted bool `json:"reverted,omitempty"`
	// Confirmed is true once someone reached the web page at its new
	// address.
	Confirmed bool  `json:"confirmed,omitempty"`
	TookMS    int64 `json:"took_ms"`
}

// noConfigFile refuses changes on a server started without a file.
var errNoConfigFile = errors.New("this server was started without a configuration file, so its settings cannot be changed here")

// savedSettings returns the configuration as saved: on the page, in
// signalith.yaml and in the environment.
func (s *Server) savedSettings() (*config.Saved, error) {
	if s.Config.Path() == "" {
		return &config.Saved{Config: s.conf()}, nil
	}
	saved, err := config.LoadSaved(s.Config.Path())
	if err != nil {
		return nil, fmt.Errorf("Signalith could not read its configuration file: %v. Fix it on the server; until then settings cannot be changed here", err)
	}
	return saved, nil
}

// settingField is one setting as the page shows it.
type settingField struct {
	Key         string          `json:"key"`
	Label       string          `json:"label"`
	Help        string          `json:"help"`
	Type        string          `json:"type"`
	Choices     []config.Choice `json:"choices,omitempty"`
	Min         *int            `json:"min,omitempty"`
	Max         *int            `json:"max,omitempty"`
	Placeholder string          `json:"placeholder,omitempty"`
	EmptyMeans  string          `json:"empty_means,omitempty"`
	// Value is the saved value; null for a secret, which is never shown.
	Value any `json:"value"`
	// For a secret: Set says whether one is saved, and SentTo the only
	// address it is sent to.
	Set    *bool         `json:"set,omitempty"`
	SentTo string        `json:"sent_to,omitempty"`
	Source config.Source `json:"source"`
	// Env is the environment variable that would override the setting.
	// Locked is true when it does, and the page shows it read-only.
	Env          string `json:"env,omitempty"`
	Locked       bool   `json:"locked"`
	LockedReason string `json:"locked_reason,omitempty"`
	// Apply is live (at once) or restart.
	Apply string `json:"apply"`
	// A dangerous setting asks Confirm before saving; ConfirmWhen limits
	// that to a switch turned on or off.
	Dangerous   bool   `json:"dangerous"`
	Confirm     string `json:"confirm,omitempty"`
	ConfirmWhen string `json:"confirm_when,omitempty"`
	// Pending is true when the saved value waits for a restart.
	Pending bool `json:"pending"`
	// ResetTo is what Reset goes back to, for a value set on the page.
	ResetTo *resetTo `json:"reset_to,omitempty"`
	// Problem must be fixed before saving or restarting; Warning is a
	// value that is not used, and why. Suggest is a value the page can
	// offer in its place.
	Problem string `json:"problem,omitempty"`
	Warning string `json:"warning,omitempty"`
	Suggest string `json:"suggest,omitempty"`
	// Refused is a change made here that a restart set aside, and why.
	Refused *config.RefusedSetting `json:"refused,omitempty"`
	// StartupProblem is true when this setting kept Signalith from
	// starting with the settings saved here.
	StartupProblem bool `json:"startup_problem,omitempty"`
}

// resetTo is a setting's value without the page: from signalith.yaml
// (source file) or the default.
type resetTo struct {
	Value  any    `json:"value"`
	Set    *bool  `json:"set,omitempty"`
	Source string `json:"source"`
}

type settingsSection struct {
	ID     string         `json:"id"`
	Title  string         `json:"title"`
	Help   string         `json:"help,omitempty"`
	Fields []settingField `json:"fields"`
}

// pendingSetting is a saved change that waits for a restart. Old and New
// are left out for secrets.
type pendingSetting struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Section string `json:"section"`
	Secret  bool   `json:"secret,omitempty"`
	Old     any    `json:"old,omitempty"`
	New     any    `json:"new,omitempty"`
}

// urlKeys are settings whose value is an address that may hold a user
// name and password, from signalith.yaml or the environment. The page
// shows them without it, and the logs and the export too.
var urlKeys = map[string]bool{"server.public_url": true, "opensearch.url": true, "opensearch.proxy": true, "assistant.url": true}

// shownValue is a setting's value as the page, the logs and the export
// show it: an address without any password in it.
func shownValue(c *config.Config, key string) any {
	v := c.Value(key)
	if s, ok := v.(string); ok && urlKeys[key] {
		return redact.URL(s)
	}
	return v
}

// fieldValue is a setting's value for the page; secrets are never sent.
func fieldValue(c *config.Config, set *config.Setting) (any, *bool) {
	if set.Type == config.TypeSecret {
		v, _ := c.Value(set.Key).(string)
		has := v != ""
		return nil, &has
	}
	return shownValue(c, set.Key), nil
}

// pendingSettings lists the saved settings that differ from those in use.
func pendingSettings(running, saved *config.Config) []pendingSetting {
	out := []pendingSetting{}
	for i := range config.Registry {
		set := &config.Registry[i]
		if config.SameValue(running, saved, set.Key) {
			continue
		}
		p := pendingSetting{Key: set.Key, Label: set.Label, Section: set.Section}
		if set.Type == config.TypeSecret {
			p.Secret = true
		} else {
			p.Old, p.New = shownValue(running, set.Key), shownValue(saved, set.Key)
		}
		out = append(out, p)
	}
	return out
}

// warningsByField sorts warnings by the setting they are about, worded
// for its field, and returns the rest.
func warningsByField(list []string) (map[string]string, []string) {
	fields := map[string]string{}
	var rest []string
	for _, w := range list {
		placed := false
		for _, k := range config.ProblemKeys(w) {
			if _, ok := config.Lookup(k); ok {
				if _, dup := fields[k]; !dup {
					fields[k] = config.PlainProblem(k, w)
				}
				placed = true
			}
		}
		if !placed {
			rest = append(rest, w)
		}
	}
	return fields, rest
}

// httpsOn reports whether the web server of c serves HTTPS (server.tls.mode
// auto or files).
func httpsOn(c *config.Config) bool { return c.Server.HTTPS() }

// webURL is the address of the web page at host and port, without the
// port when it is the scheme's own.
func webURL(scheme, host, port string) string {
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		if strings.Contains(host, ":") {
			return scheme + "://[" + host + "]"
		}
		return scheme + "://" + host
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

// publicURLWarning notes a public address that does not match how the web
// server answers: another scheme (http:// while it serves HTTPS) or
// another port, as after the listen address moved. A proxy or a port
// forward in between makes that right, so it is only a warning. soon is
// true when that is how it answers after the next restart. It also
// returns the address that matches, for the page to offer.
func publicURLWarning(c *config.Config, soon bool) (string, string) {
	if c.Server.PublicURL == "" || c.PublicURLDerived() {
		return "", ""
	}
	// As it is set: an http:// one is read as https:// while HTTPS is on.
	raw, _ := c.Value("server.public_url").(string)
	if raw == "" {
		raw = c.Server.PublicURL
	}
	u, err := url.Parse(raw)
	_, listen, lerr := net.SplitHostPort(c.Server.Listen)
	if err != nil || lerr != nil || u.Host == "" || listen == "0" {
		return "", ""
	}
	told := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[told]
	}
	serves := "http"
	if httpsOn(c) {
		serves = "https"
	}
	if port == "" || (told == serves && port == listen) {
		return "", ""
	}
	verb := "answers"
	if soon {
		verb = "will answer"
	}
	var msg string
	switch {
	case told != serves && port != listen:
		msg = fmt.Sprintf("Agents are told to use %s:// on port %s, but Signalith %s with %s:// on port %s.", told, port, verb, serves, listen)
	case told != serves:
		msg = fmt.Sprintf("Agents are told to use %s://, but Signalith %s with %s://.", told, verb, serves)
	default:
		msg = fmt.Sprintf("Agents are told to use port %s, but Signalith %s on port %s.", port, verb, listen)
	}
	msg += " That is right only when a proxy or a port forward passes one on to the other."
	suggest := webURL(serves, u.Hostname(), listen)
	if p := strings.TrimRight(u.EscapedPath(), "/"); p != "" {
		suggest += p
	}
	return msg, suggest
}

// webMoves reports whether the web page answers somewhere else with c
// than with running: another listen address, or HTTPS turned on or off.
func webMoves(running, c *config.Config) bool {
	return running.Server.Listen != c.Server.Listen || httpsOn(running) != httpsOn(c)
}

// settingsView is GET /api/settings.
func (s *Server) settingsView() (map[string]any, error) {
	saved, err := s.savedSettings()
	if err != nil {
		return nil, err
	}
	running := s.conf()
	problems, general := config.FieldProblems(saved.Config, saved.Problems)
	warnings, otherWarnings := warningsByField(saved.SettingsWarnings())
	suggest := map[string]string{}
	if w, sg := s.httpsWarning(saved.Config); w != "" && warnings["server.public_url"] == "" {
		warnings["server.public_url"], suggest["server.public_url"] = w, sg
	}
	if w, sg := publicURLWarning(saved.Config, webMoves(running, saved.Config)); w != "" && warnings["server.public_url"] == "" {
		warnings["server.public_url"], suggest["server.public_url"] = w, sg
	}
	for k, w := range s.certNamesWarnings(saved.Config) {
		if warnings[k] == "" {
			warnings[k] = w
		}
	}
	if w := unencryptedWarning(saved.Config); w != "" && warnings["server.tls.mode"] == "" {
		warnings["server.tls.mode"] = w
	}
	pending := pendingSettings(running, saved.Config)
	waiting := map[string]bool{}
	for _, p := range pending {
		waiting[p.Key] = true
	}
	refusedList := saved.Refused()
	refused := map[string]*config.RefusedSetting{}
	for i := range refusedList {
		if str, ok := refusedList[i].Value.(string); ok && urlKeys[refusedList[i].Key] {
			refusedList[i].Value = redact.URL(str)
		}
		refused[refusedList[i].Key] = &refusedList[i]
	}
	startupKeys := running.SettingsProblemKeys()
	sections := make([]settingsSection, 0, len(config.Sections))
	for _, sec := range config.Sections {
		out := settingsSection{ID: sec.ID, Title: sec.Title, Help: sec.Help, Fields: []settingField{}}
		for i := range config.Registry {
			set := &config.Registry[i]
			if set.Section != sec.ID {
				continue
			}
			f := settingField{Key: set.Key, Label: set.Label, Help: set.Help, Type: set.Type, Choices: set.Choices,
				Min: set.Min, Max: set.Max, Placeholder: set.Placeholder, EmptyMeans: set.EmptyMeans,
				Source: saved.Source(set.Key), Env: set.Env, Apply: "live",
				Dangerous: set.Confirm != "", Confirm: set.Confirm, ConfirmWhen: set.ConfirmWhen,
				Pending: waiting[set.Key], Problem: problems[set.Key], Warning: warnings[set.Key], Suggest: suggest[set.Key],
				Refused: refused[set.Key], StartupProblem: slices.Contains(startupKeys, set.Key)}
			if set.Restart {
				f.Apply = "restart"
			}
			f.Value, f.Set = fieldValue(saved.Config, set)
			// A public address worked out from the listen address shows as
			// empty, with what it works out to now.
			if set.Key == "server.public_url" && saved.PublicURLDerived() {
				f.EmptyMeans = saved.Server.PublicURL + ", worked out from the listen address"
			}
			// A file from before HTTPS was the default believes a proxy on
			// this computer or a private network until one is listed.
			if set.Key == "server.trusted_proxies" && saved.Server.LegacyProxy(netip.IPv6Loopback()) {
				f.EmptyMeans = "this computer and private networks, until you list one (signalith.yaml is from before HTTPS was the default)"
			}
			if f.Set != nil && *f.Set {
				f.SentTo = set.SentTo(saved.Config)
			}
			// A secret saved here that cannot be decrypted is not used.
			if msg := saved.PageSecretProblem(set.Key); msg != "" && f.Warning == "" {
				f.Warning = msg
			}
			if f.Source.Kind == config.FromEnv {
				f.Locked, f.LockedReason = true, config.LockedReason(f.Source.Env)
			}
			if f.Source.Kind == config.FromPage {
				base := saved.Base()
				rt := &resetTo{Source: base.Source(set.Key).Kind}
				rt.Value, rt.Set = fieldValue(base, set)
				f.ResetTo = rt
			}
			out.Fields = append(out.Fields, f)
		}
		sections = append(sections, out)
	}
	file := map[string]any{
		"path": fullPath(saved.SettingsFile()), "env": "SIGNALITH_SETTINGS_FILE", "from_env": saved.SettingsFileFromEnv(),
		"keys": saved.PageKeys(),
	}
	if saved.PageErr != nil {
		// Only the reason: the page names the file itself.
		var pe *config.PageFileError
		reason := saved.PageErr
		if errors.As(saved.PageErr, &pe) && pe.Err != nil {
			reason = pe.Err
		}
		file["error"] = plainFileError(reason)
		file["backup"] = fullPath(saved.SettingsFile()) + ".broken"
	}
	restart := map[string]any{"available": s.Restarter != nil, "in_progress": false, "last": nil, "needed": len(pending) > 0}
	if s.Restarter != nil {
		st := s.Restarter.RestartStatus()
		restart["in_progress"], restart["last"] = st.InProgress, st.Last
		if st.Awaiting != nil {
			restart["awaiting"] = st.Awaiting
		}
	} else {
		restart["unavailable"] = "This server cannot restart itself. Restart Signalith on the server to apply the changes."
	}
	if blocked := restartBlocked(saved); blocked != "" {
		restart["blocked"] = blocked
	}
	if general == nil {
		general = []string{}
	}
	if otherWarnings == nil {
		otherWarnings = []string{}
	}
	return map[string]any{
		"sections":      sections,
		"editable":      s.Config.Path() != "",
		"config_file":   s.Config.Path(),
		"settings_file": file,
		// startup_problem says why the running server is not using the
		// page's settings, when it started without them; startup_keys are
		// the settings to blame, when known, and startup_file is true when
		// it was that their file cannot be read.
		"startup_problem": running.SettingsProblem(),
		"startup_keys":    startupKeys,
		"startup_file":    running.SettingsFileProblem(),
		"problems":        general,
		"warnings":        otherWarnings,
		"pending":         pending,
		"refused":         refusedList,
		"restart":         restart,
		"move_wait_s":     int(MoveWait.Seconds()),
		"tls":             s.tlsInfo(),
		"about":           s.aboutServer(running),
		"elsewhere":       s.managedElsewhere(running),
	}, nil
}

// httpsWarning notes an http:// public address while HTTPS is on: agents
// are set up with the same address over https://, which it returns for
// the page to offer.
func (s *Server) httpsWarning(c *config.Config) (string, string) {
	raw, _ := c.Value("server.public_url").(string)
	if !httpsOn(c) || !strings.HasPrefix(strings.ToLower(raw), "http://") || c.Server.PublicURL == raw {
		return "", ""
	}
	return "Signalith serves HTTPS on this port, so agents are set up with " + redact.URL(c.Server.PublicURL) +
		". Change it to that, or to the https:// address of a reverse proxy in front.", c.Server.PublicURL
}

// certNamesWarnings notes, by setting, the names for Signalith's own
// certificate, in server.tls.names and public_url, that its certificate
// authority may not sign, as the Add data page does for an address agents
// are to use.
func (s *Server) certNamesWarnings(c *config.Config) map[string]string {
	out := map[string]string{}
	if c.Server.TLSMode() != config.TLSAuto || s.TLS == nil || !s.TLS.LocalCA() {
		return out
	}
	for _, n := range c.Server.TLSNames() {
		if err := s.TLS.CanCover(n); err != nil {
			out["server.tls.names"] = sentence(err.Error())
			break
		}
	}
	if u, err := url.Parse(c.Server.PublicURL); err == nil && u.Hostname() != "" {
		if err := s.TLS.CanCover(u.Hostname()); err != nil {
			out["server.public_url"] = sentence(err.Error())
		}
	}
	return out
}

// unencryptedWarning notes HTTPS off with a listen address other
// computers reach and no reverse proxy listed, as Validate does.
func unencryptedWarning(c *config.Config) string {
	host, _, err := net.SplitHostPort(c.Server.Listen)
	if err != nil || httpsOn(c) || isLoopback(host) || len(c.Server.TrustedProxies) > 0 {
		return ""
	}
	return "Other computers can reach Signalith at " + c.Server.Listen + ", so passwords, sessions and events cross the network unencrypted " +
		"unless a reverse proxy in front serves HTTPS. List the proxy under Trusted reverse proxies, or choose Automatic."
}

// plainFileError words why the settings file cannot be read, without the
// YAML library's type names.
func plainFileError(err error) string {
	msg := err.Error()
	rest, ok := strings.CutPrefix(msg, "yaml: ")
	if !ok {
		return sentence(msg)
	}
	if lines, ok := strings.CutPrefix(rest, "unmarshal errors:"); ok {
		var where []string
		for _, l := range strings.Split(lines, "\n") {
			if n, _, ok := strings.Cut(strings.TrimSpace(l), ":"); ok && strings.HasPrefix(n, "line ") {
				where = append(where, n)
			}
		}
		if len(where) > 0 {
			return "It is not laid out as Signalith writes it (" + strings.Join(where, ", ") + ")."
		}
		return "It is not laid out as Signalith writes it."
	}
	return "It is not valid YAML (" + strings.TrimSuffix(rest, ".") + ")."
}

// restartBlocked says why the saved settings cannot be applied, or "".
func restartBlocked(saved *config.Saved) string {
	switch {
	case saved.PageErr != nil:
		return "The settings file cannot be read. Fix it on the server, or start a new one, before restarting."
	case len(saved.Problems) > 0:
		return "Fix the problems shown on this page before restarting."
	}
	return ""
}

// aboutServer describes the server for the page's read-only part.
func (s *Server) aboutServer(c *config.Config) map[string]any {
	type pathInfo struct {
		Key    string        `json:"key,omitempty"`
		Label  string        `json:"label"`
		Path   string        `json:"path"`
		Source config.Source `json:"source"`
	}
	paths := []pathInfo{
		{Label: "Configuration file", Path: c.Path(), Source: config.Source{Kind: config.FromFile}},
		{Label: "Settings page file", Path: c.SettingsFile(), Source: settingsFileSource(c)},
		{Key: "lookups.dir", Label: "Lookups folder", Path: c.LookupsDir(), Source: c.Source("lookups.dir")},
		{Key: "detections.dir", Label: "Detections folder", Path: c.DetectionsDir(), Source: c.Source("detections.dir")},
		{Key: "dashboards.dir", Label: "Dashboards folder", Path: c.DashboardsDir(), Source: c.Source("dashboards.dir")},
		{Key: "auth.users_file", Label: "Users file", Path: c.UsersFile(), Source: c.Source("auth.users_file")},
		{Key: "intel.feeds_file", Label: "Threat intel feeds file", Path: c.IntelFeedsFile(), Source: c.Source("intel.feeds_file")},
		{Key: "notify.file", Label: "Notifications file", Path: c.NotifyFile(), Source: c.Source("notify.file")},
		{Key: "response.file", Label: "Response actions file", Path: c.ResponseFile(), Source: c.Source("response.file")},
		{Key: "response.scripts_dir", Label: "Response scripts folder", Path: c.ResponseScriptsDir(), Source: c.Source("response.scripts_dir")},
	}
	// Whoever reads the page is not in Signalith's working folder.
	for i := range paths {
		paths[i].Path = fullPath(paths[i].Path)
	}
	about := map[string]any{
		"version":       s.Version,
		"platform":      runtime.GOOS + "/" + runtime.GOARCH,
		"paths":         paths,
		"ingest_tokens": len(c.Ingest.Tokens),
		"container":     s.runtimeInfo().Container,
	}
	if !s.Started.IsZero() {
		about["started"] = s.Started.UTC()
		about["uptime_seconds"] = int64(time.Since(s.Started).Seconds())
	}
	return about
}

func settingsFileSource(c *config.Config) config.Source {
	if c.SettingsFileFromEnv() {
		return config.Source{Kind: config.FromEnv, Env: "SIGNALITH_SETTINGS_FILE"}
	}
	return config.Source{Kind: config.FromDefault}
}

// managedElsewhere points to the pages that manage what this one does
// not. Page is the app's page name.
func (s *Server) managedElsewhere(c *config.Config) []map[string]any {
	tokens := len(c.Ingest.Tokens)
	detail := fmt.Sprintf("%d agent tokens are set in signalith.yaml or the environment.", tokens)
	switch tokens {
	case 0:
		detail = "No agent token is set, so agents cannot send data. Set one in signalith.yaml (ingest.tokens) or with SIGNALITH_INGEST_TOKEN, then restart."
	case 1:
		detail = "1 agent token is set in signalith.yaml or the environment."
	}
	return []map[string]any{
		{"what": "Users and directory sign-in", "page": "users"},
		{"what": "Agent setup", "page": "data", "detail": detail},
		{"what": "Threat intel feeds", "page": "intel"},
		{"what": "Data retention", "page": "retention"},
	}
}

// confirmMove tells a restart that moved the web page that an admin
// reached it, when r came in at the new address.
func (s *Server) confirmMove(r *http.Request) bool {
	if s.Restarter == nil || !s.Restarter.Confirm(r) {
		return false
	}
	s.audit(r, "new web address confirmed", "host", r.Host)
	return true
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	s.confirmMove(r)
	view, err := s.settingsView()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handleConfirmMove is how the page, opened at the new address after a
// restart moved it, says it got there. It answers whether that confirmed
// a move.
func (s *Server) handleConfirmMove(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"confirmed": s.confirmMove(r)})
}

// settingsRequest is the body of PUT /api/settings.
type settingsRequest struct {
	// Values are new values by key. An empty secret keeps the saved one.
	Values map[string]any `json:"values"`
	// Clear lists secrets to remove.
	Clear []string `json:"clear"`
	// Reset lists settings to take off the page.
	Reset []string `json:"reset"`
	// Retry lists changes a restart set aside, to use again.
	Retry []string `json:"retry"`
	// ResetAll takes every setting off the page.
	ResetAll bool `json:"reset_all"`
	// CheckOnly checks the changes without saving them, and returns what
	// to ask before saving them.
	CheckOnly bool `json:"check_only"`
}

// confirmation is something the page asks before it saves a change.
type confirmation struct {
	Key string `json:"key"`
	// Name and Title, when set, name what changes and the question to ask,
	// where the setting's label would not say it.
	Name  string `json:"name,omitempty"`
	Title string `json:"title,omitempty"`
	// Old and New are the setting's values, for the page to show; left
	// out for switches and secrets.
	Old  any    `json:"old,omitempty"`
	New  any    `json:"new,omitempty"`
	Text string `json:"text"`
	// Code is "local_only" for a web address only the server can reach,
	// which the restart asks again about unless told it was agreed to.
	Code string `json:"code,omitempty"`
	// Also is a change the page offers to make with this one.
	Also *alsoChange `json:"also,omitempty"`
}

// alsoChange is another setting the page offers to change with one, such
// as the public address with the listen port.
type alsoChange struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
	Label string `json:"label"`
}

// confirmations lists what to ask before saving res: the dangerous changes,
// and changes that would keep people or agents from reaching Signalith.
func confirmations(r *http.Request, res *config.EditResult) []confirmation {
	out := []confirmation{}
	before, after := res.Before, res.Config
	changed := func(k string) bool { return slices.Contains(res.Changed, k) }
	for _, k := range res.Changed {
		set, _ := config.Lookup(k)
		if set.Confirm == "" {
			continue
		}
		v := after.Value(k)
		if (set.ConfirmWhen == "on" && v != true) || (set.ConfirmWhen == "off" && v != false) {
			continue
		}
		c := confirmation{Key: k, Text: set.Confirm}
		if set.Type != config.TypeBool && set.Type != config.TypeSecret {
			c.Old, c.New = shownValue(before, k), shownValue(after, k)
		}
		if k == "server.listen" && loopbackOnly(after.Server.Listen) && !isLoopback(clientHost(r)) {
			c.Text = "Only programs on the server itself can reach Signalith at " + after.Server.Listen +
				". You could not open this page again from here, and agents on other computers cannot send. Use this only with a proxy on the same server."
			c.Code = "local_only"
		}
		out = append(out, c)
	}
	if c, ok := httpsConfirmation(before, after); ok {
		out = append(out, c)
	}
	// A public address that matched the old web address and does not
	// match the new one would send agents to the old one.
	if webMoves(before, after) && !changed("server.public_url") && !after.PublicURLDerived() {
		if _, sg := publicURLWarning(after, true); sg != "" {
			if old, _ := publicURLWarning(before, false); old == "" {
				set, _ := config.Lookup("server.public_url")
				out = append(out, confirmation{Key: "server.public_url", Title: "Agents would still use the old address", Old: shownValue(after, "server.public_url"),
					Text: fmt.Sprintf("Agents are told to send to %v, the old address. Unless a proxy or a port forward passes it on, they stop sending.", shownValue(after, "server.public_url")),
					Also: &alsoChange{Key: "server.public_url", Value: sg, Label: "Also change " + set.Label + " to " + sg}})
			}
		}
	}
	return out
}

// httpsConfirmation is what to ask before HTTPS is turned on or off, or
// before Signalith's own certificate and the admin's own files trade
// places: browsers and agents that trusted one do not trust the other.
func httpsConfirmation(before, after *config.Config) (confirmation, bool) {
	from, to := before.Server.TLSMode(), after.Server.TLSMode()
	if from == to {
		return confirmation{}, false
	}
	c := confirmation{Key: "server.tls.mode", Name: "HTTPS", Old: shownValue(before, "server.tls.mode"), New: shownValue(after, "server.tls.mode")}
	switch {
	case to == config.TLSOff:
		c.Title = "Turn HTTPS off?"
		c.Text = "After the restart Signalith answers with plain http:// only. Bookmarks and agents that use https:// stop working until they are changed, " +
			"and passwords, sessions and events cross the network unencrypted unless a reverse proxy in front serves HTTPS. " +
			"Browsers that opened Signalith by name over HTTPS keep asking for https:// there; use the proxy's address."
	case from == config.TLSOff:
		c.Title = "Turn HTTPS on?"
		c.Text = "After the restart the web page and the API answer with https:// only; browsers that use http:// on the same port are sent there. " +
			"Agents set up for http:// stop sending until they get a new configuration from Add data, unless Agents on plain HTTP accepts them for now."
		if to == config.TLSAuto {
			c.Text += " Browsers warn until they trust Signalith's own certificate authority, which the sign-in page offers to download."
		}
	case to == config.TLSAuto:
		c.Title = "Use Signalith's own certificate?"
		c.Text = "After the restart Signalith uses its own certificate instead of your files. Browsers warn until they trust its certificate authority, " +
			"and agents set up to check your certificate stop sending until they get a new configuration from Add data."
	default:
		c.Title = "Use your own certificate files?"
		c.Text = "After the restart Signalith uses the certificate in your files instead of its own. Agents set up with Signalith's own certificate authority " +
			"stop sending until they get a new configuration from Add data, unless your certificate comes from an authority they already trust."
	}
	return c, true
}

// loopbackOnly reports whether a listen address takes connections from
// the server itself only.
func loopbackOnly(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	return err == nil && host != "" && isLoopback(host)
}

// clientHost is the address of the computer r came from.
func clientHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var req settingsRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if s.Config.Path() == "" {
		writeError(w, http.StatusConflict, errNoConfigFile)
		return
	}
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	pages := s.pages()
	res, err := pages.CheckEdit(config.Edit{Values: req.Values, Clear: req.Clear, Reset: req.Reset,
		Retry: req.Retry, ResetAll: req.ResetAll, By: userOf(r)})
	switch {
	case errors.Is(err, config.ErrPageFile):
		writeJSON(w, http.StatusConflict, map[string]any{"error": "Nothing was saved, because the settings file cannot be read. Fix it on the server, or start a new one.", "code": "settings_file"})
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !res.OK() {
		msg := "Nothing was saved. Fix the settings marked below."
		if len(res.Problems) > 0 {
			msg = "Nothing was saved, because signalith.yaml has problems: " + strings.Join(res.Problems, "; ") + "."
		}
		problems := res.Problems
		if problems == nil {
			problems = []string{}
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg, "fields": res.Fields, "problems": problems})
		return
	}
	if msg := s.proxyLockout(r, res.Config); msg != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Nothing was saved. Fix the settings marked below.",
			"fields": map[string]string{"server.trusted_proxies": msg}, "problems": []string{}})
		return
	}
	if req.CheckOnly {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": nonNil(res.Changed), "confirm": confirmations(r, res)})
		return
	}
	file := res.Config.SettingsFile()
	backup := ""
	if req.ResetAll {
		// A file that cannot be read is kept next to the new one, so what
		// it held can still be looked at.
		if _, err := pages.Read(); err != nil {
			if backup, err = pages.Backup(); err != nil {
				writeError(w, http.StatusInternalServerError, fmt.Errorf("could not keep a copy of the settings file before starting a new one: %w", err))
				return
			}
		}
	}
	if err := pages.Write(res.Page); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("could not save the settings file %s: %w", file, err))
		return
	}
	applied := s.applyLive(res.Before, res.Config)
	// Changes that wait for a restart; one back to the value in use, such
	// as a reset of a change not applied yet, needs none.
	var restart []string
	running := s.conf()
	for _, k := range res.Changed {
		if !slices.Contains(applied, k) && !config.SameValue(running, res.Config, k) {
			restart = append(restart, k)
		}
	}
	s.audit(r, "settings saved", "changes", describeChanges(res), "reset", strings.Join(req.Reset, ","),
		"cleared", strings.Join(req.Clear, ","), "retried", strings.Join(req.Retry, ","), "reset_all", req.ResetAll,
		"applied_now", strings.Join(applied, ","), "after_restart", strings.Join(restart, ","), "file", file, "backup", backup)
	view, err := s.settingsView()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	view["saved"], view["applied"], view["after_restart"] = nonNil(res.Changed), nonNil(applied), nonNil(restart)
	if backup != "" {
		view["backup"] = fullPath(backup)
	}
	writeJSON(w, http.StatusOK, view)
}

// proxyLockout says why next must not be saved when r came through a
// reverse proxy that next would no longer believe: the list of trusted
// proxies applies at once, and with HTTPS on the very next request
// through that proxy would be sent to https:// or refused, so this page
// could not be opened through it again to undo the change. It returns ""
// when r did not come through such a proxy, or next still believes it.
func (s *Server) proxyLockout(r *http.Request, next *config.Config) string {
	if r.TLS != nil || !s.viaTrustedProxy(r) {
		return ""
	}
	from := clientaddr.Parse(r.RemoteAddr)
	if !s.conf().Server.HTTPS() && !next.Server.HTTPS() {
		// With HTTPS off nothing is refused for it: signing in again
		// works through the proxy.
		return ""
	}
	if next.Server.TrustsProxy(from) || next.Server.LegacyProxy(from) {
		return ""
	}
	addr := from.Unmap().WithZone("").String()
	return "You reached this page through the reverse proxy at " + addr + ", which this list leaves out. Signalith would stop believing it at once, " +
		"and this page could not be opened through it again. Add " + addr + ", or make this change from a browser that reaches Signalith without the proxy."
}

func nonNil(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

// describeChanges lists what a save changed for the audit log: the new
// values, but for secrets only that they changed, and addresses without
// any password in them.
func describeChanges(res *config.EditResult) string {
	var parts []string
	for _, k := range res.Changed {
		set, _ := config.Lookup(k)
		v := shownValue(res.Config, k)
		switch {
		case set.Type == config.TypeSecret:
			if s, _ := v.(string); s == "" {
				parts = append(parts, k+"=(none)")
			} else {
				parts = append(parts, k+"=(changed)")
			}
		case set.Type == config.TypeList:
			parts = append(parts, k+"="+strings.Join(v.([]string), ","))
		default:
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	return strings.Join(parts, " ")
}

// pages returns where the Settings page's settings are kept.
func (s *Server) pages() config.PageStore {
	if s.Pages != nil {
		return s.Pages
	}
	return config.PageFile{Config: s.Config.Path()}
}

// applyLive puts the settings that changed from old to saved, and that
// apply at once, into use, and returns their keys. A setting worked out
// from one that waits for a restart waits too.
//
// A secret goes into use together with the settings that say where it is
// sent (its SentWith), all as saved, and only when it is then sent to the
// address it was saved for. Nothing applies at once while the server runs
// without the page's settings (SettingsProblem): mixing some of them into
// signalith.yaml's could send a secret somewhere else.
func (s *Server) applyLive(old, saved *config.Config) []string {
	cur := s.conf()
	if cur.SettingsProblem() != "" {
		return nil
	}
	var changedKeys []string
	for i := range config.Registry {
		if k := config.Registry[i].Key; !config.SameValue(old, saved, k) {
			changedKeys = append(changedKeys, k)
		}
	}
	next := *cur
	live := func(key string) bool {
		set, _ := config.Lookup(key)
		if !set.Live() {
			return false
		}
		for _, k := range set.WaitsFor {
			if !config.SameValue(cur, saved, k) {
				return false
			}
		}
		return true
	}
	copyKeys := map[string]bool{}
	for _, key := range changedKeys {
		if live(key) {
			copyKeys[key] = true
		}
	}
	// A secret and where it is sent apply as one.
	var groups [][]string
	for i := range config.Registry {
		set := &config.Registry[i]
		if set.Type != config.TypeSecret || len(set.SentWith) == 0 {
			continue
		}
		group := append([]string{set.Key}, set.SentWith...)
		if !slices.ContainsFunc(group, func(k string) bool { return copyKeys[k] || slices.Contains(changedKeys, k) }) {
			continue
		}
		if slices.ContainsFunc(group, func(k string) bool { return !live(k) }) {
			for _, k := range group {
				delete(copyKeys, k)
			}
			continue
		}
		for _, k := range group {
			copyKeys[k] = true
		}
		groups = append(groups, group)
	}
	for k := range copyKeys {
		if err := next.CopyValue(k, saved); err != nil {
			delete(copyKeys, k)
		}
	}
	for _, group := range groups {
		set, _ := config.Lookup(group[0])
		secret, _ := next.Value(set.Key).(string)
		if secret == "" || set.SentTo(&next) == set.SentTo(saved) {
			continue
		}
		// It would go somewhere else: it waits for the restart.
		for _, k := range group {
			_ = next.CopyValue(k, cur)
			delete(copyKeys, k)
		}
	}
	var applied []string
	for i := range config.Registry {
		k := config.Registry[i].Key
		if copyKeys[k] && !config.SameValue(cur, &next, k) {
			applied = append(applied, k)
		}
	}
	if len(applied) == 0 {
		return nil
	}
	s.live.Store(&next)
	// Parts of the server that keep their own copy.
	changed := func(prefix string) bool {
		return slices.ContainsFunc(applied, func(k string) bool { return strings.HasPrefix(k, prefix) })
	}
	if changed("auth.session_timeout") {
		s.sessions().SetIdle(next.SessionIdle())
	}
	if changed("search.") && s.Engine != nil {
		s.Engine.SetDefaults(next.Search.DefaultEarliest, next.Search.MaxEvents)
	}
	if changed("detections.max_findings_per_run") && s.Scheduler != nil {
		s.Scheduler.SetMaxFindingsPerRun(next.Detections.MaxFindingsPerRun)
	}
	if changed("assistant.") {
		a := next.Assistant
		s.liveAI.Store(&liveModel{c: assistant.New(a.Provider, a.URL, a.Model, a.APIKey)})
	}
	if changed("server.public_url") {
		s.coverPublicURL(&next)
	}
	if changed("server.tls.plaintext_ingest") {
		s.endOldTokenLocked()
	}
	return applied
}

// coverPublicURL adds the public address's host to Signalith's own HTTPS
// certificate, as the Add data page does for the address agents are set
// up with. One its certificate authority may not sign is left out; the
// page says so (see certNamesWarnings).
func (s *Server) coverPublicURL(c *config.Config) {
	if s.TLS == nil || !s.TLS.LocalCA() || c.Server.TLSMode() != config.TLSAuto {
		return
	}
	u, err := url.Parse(c.Server.PublicURL)
	if err != nil || u.Hostname() == "" {
		return
	}
	if err := s.TLS.EnsureName(u.Hostname()); err != nil {
		s.Log.Warn("the HTTPS certificate does not cover the public address saved on the Settings page", "host", u.Hostname(), "err", err)
	}
}

// settingsTest is the body of the test routes: form values, saved or not,
// by key; settings left out use their saved values.
type settingsTest struct {
	Values map[string]any `json:"values"`
	Clear  []string       `json:"clear"`
}

// testValues returns the saved configuration with the form's values in
// place, and the problems with them by key. A secret left empty is the
// saved one, but only when it would go to the address it was saved for.
func (s *Server) testValues(r *http.Request, keys ...string) (*config.Config, map[string]string, error) {
	var req settingsTest
	if r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			return nil, nil, err
		}
	}
	saved, err := s.savedSettings()
	if err != nil {
		return nil, nil, err
	}
	test := *saved.Config
	fields := map[string]string{}
	typed := map[string]bool{}
	for _, key := range keys {
		set, _ := config.Lookup(key)
		raw, given := req.Values[key]
		if saved.Source(key).Kind == config.FromEnv {
			continue
		}
		if slices.Contains(req.Clear, key) {
			raw, given, typed[key] = "", true, true
		}
		if !given {
			continue
		}
		v, err := config.ParseValue(set, raw)
		if err == nil {
			err = set.Check(v)
		}
		if err != nil {
			fields[key] = sentence(err.Error())
			continue
		}
		if set.Type == config.TypeSecret && v.(string) == "" && !typed[key] {
			continue
		}
		// The page shows addresses without their password; one sent back
		// as shown is the saved one.
		if str, ok := v.(string); ok && urlKeys[key] && str == shownValue(saved.Config, key) {
			continue
		}
		typed[key] = true
		if err := test.SetValue(key, v); err != nil {
			fields[key] = sentence(err.Error())
		}
	}
	for _, key := range keys {
		set, _ := config.Lookup(key)
		if set.Type != config.TypeSecret || typed[key] {
			continue
		}
		v, _ := saved.Value(key).(string)
		if v == "" {
			continue
		}
		bound := set.SentTo(saved.Config)
		if now := set.SentTo(&test); now != "" && now != bound {
			what := set.Noun()
			if env := saved.Source(key).Env; env != "" {
				for _, k := range set.SentWith {
					fields[k] = fmt.Sprintf("The %s comes from the %s environment variable and is only sent to %s.", what, env, bound)
				}
				continue
			}
			fields[key] = fmt.Sprintf("Enter the %s again: the saved one is only sent to %s.", what, bound)
		}
	}
	return &test, fields, nil
}

// writeFieldProblems answers 400 with problems by field.
func writeFieldProblems(w http.ResponseWriter, fields map[string]string) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Fix the settings marked below, then test again.", "fields": fields, "problems": []string{}})
}

// oneTest runs one connection test at a time: each can take a while and
// read a large answer. It reports false, having answered 429, when
// another is running.
func (s *Server) oneTest(w http.ResponseWriter) (func(), bool) {
	if !s.testMu.TryLock() {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"code": "busy",
			"error": "Another connection test is running. Try again when it has finished."})
		return nil, false
	}
	return s.testMu.Unlock, true
}

// openSearchTestKeys are the settings the OpenSearch test uses.
var openSearchTestKeys = []string{"opensearch.url", "opensearch.username", "opensearch.password", "opensearch.ca_file",
	"opensearch.cert_file", "opensearch.key_file", "opensearch.proxy", "opensearch.allow_insecure_http", "opensearch.tls_skip_verify"}

// handleTestOpenSearch tries the OpenSearch connection settings in the
// form, saved or not, and says what it found in plain words.
func (s *Server) handleTestOpenSearch(w http.ResponseWriter, r *http.Request) {
	c, fields, err := s.testValues(r, openSearchTestKeys...)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(fields) == 0 && config.Origin(c.OpenSearch.URL) == "" {
		fields["opensearch.url"] = "Enter an address like https://opensearch.example.com:9200."
	}
	if len(fields) == 0 {
		byKey, _ := config.FieldProblems(c, c.OpenSearchProblems())
		for _, k := range openSearchTestKeys {
			if byKey[k] != "" {
				fields[k] = byKey[k]
			}
		}
	}
	if len(fields) > 0 {
		writeFieldProblems(w, fields)
		return
	}
	done, ok := s.oneTest(w)
	if !ok {
		return
	}
	defer done()
	ctx, cancel := context.WithTimeout(r.Context(), store.CheckTimeout+5*time.Second)
	defer cancel()
	rep := store.Check(ctx, c.OpenSearchConnection())
	s.audit(r, "settings tested", "what", "opensearch", "url", redact.URL(c.OpenSearch.URL), "username", c.OpenSearch.Username,
		"ok", rep.OK, "problem", rep.Problem)
	writeJSON(w, http.StatusOK, rep)
}

// assistantQuestion is the fixed question the assistant test asks.
const assistantQuestion = "failed logins in the last 24 hours"

// assistantReport is what the assistant test found.
type assistantReport struct {
	OK       bool   `json:"ok"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
	URL      string `json:"url"`
	Question string `json:"question"`
	// Query is the model's answer, when it gave one.
	Query   string `json:"query,omitempty"`
	Message string `json:"message"`
	TookMS  int64  `json:"took_ms"`
}

// handleTestAssistant asks the model in the form one fixed question and
// says whether it answered.
func (s *Server) handleTestAssistant(w http.ResponseWriter, r *http.Request) {
	c, fields, err := s.testValues(r, "assistant.provider", "assistant.url", "assistant.model", "assistant.api_key")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a := c.Assistant
	if len(fields) == 0 {
		switch {
		case a.Provider == "":
			fields["assistant.provider"] = "Choose a provider to test."
		case a.Provider != assistant.Anthropic && a.Provider != assistant.OpenAI:
			fields["assistant.provider"] = "Choose Anthropic or OpenAI or compatible."
		case a.URL != "" && config.Origin(a.URL) == "":
			fields["assistant.url"] = "Enter an address like http://localhost:11434/v1, or leave it empty."
		case a.Provider == assistant.OpenAI && a.Model == "":
			fields["assistant.model"] = "Enter the model's name: OpenAI or compatible needs one, such as llama3.1 with Ollama or gpt-4.1 with OpenAI."
		case a.Provider == assistant.Anthropic && a.APIKey == "":
			fields["assistant.api_key"] = "Enter the API key."
		}
	}
	if len(fields) > 0 {
		writeFieldProblems(w, fields)
		return
	}
	done, ok := s.oneTest(w)
	if !ok {
		return
	}
	defer done()
	client := assistant.New(a.Provider, a.URL, a.Model, a.APIKey)
	client.HTTP.Timeout = 45 * time.Second
	rep := assistantReport{Provider: a.Provider, Model: client.Model, URL: redact.URL(client.URL), Question: assistantQuestion}
	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	q, err := client.Translate(ctx, assistantQuestion, "")
	rep.TookMS = time.Since(start).Milliseconds()
	if err != nil {
		rep.Message = explainAssistant(err)
	} else {
		rep.OK, rep.Query = true, q
		rep.Message = fmt.Sprintf("The model answered in %.1f seconds.", time.Since(start).Seconds())
	}
	s.audit(r, "settings tested", "what", "assistant", "provider", a.Provider, "url", redact.URL(client.URL), "model", client.Model, "ok", rep.OK)
	writeJSON(w, http.StatusOK, rep)
}

// explainAssistant words a failed assistant test.
func explainAssistant(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "returned 401"), strings.Contains(msg, "returned 403"):
		return "The model's service refused the API key. Check the key. (" + msg + ")"
	case strings.Contains(msg, "returned 404"):
		return "The model's service answered \"not found\": check the address and the model's name. (" + msg + ")"
	case strings.Contains(msg, "did not parse"):
		return "The model answered, but not with a query Signalith understands. A larger model may do better."
	}
	return sentence(msg)
}

// sentence makes an error message a sentence.
func sentence(s string) string {
	if s == "" {
		return s
	}
	s = strings.ToUpper(s[:1]) + s[1:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

// restartRequest is the body of POST /api/settings/restart.
type restartRequest struct {
	// LocalOnly is the admin's yes to a web address that only the server
	// itself can reach, asked from another computer.
	LocalOnly bool `json:"local_only"`
}

// handleRestart restarts the server with the saved settings, shortly
// after answering 202.
func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	var req restartRequest
	if r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if s.Restarter == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": "restart_unavailable",
			"error": "This server cannot restart itself. Restart Signalith on the server to apply the changes."})
		return
	}
	s.confirmMove(r)
	saved, err := s.savedSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if blocked := restartBlocked(saved); blocked != "" {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "settings_invalid", "error": blocked})
		return
	}
	running := s.conf()
	// Moving the web page to an address only the server itself can reach
	// locks out whoever asks from elsewhere: they say yes first.
	localOnly := running.Server.Listen != saved.Server.Listen && loopbackOnly(saved.Server.Listen) && !isLoopback(clientHost(r))
	if localOnly && !req.LocalOnly {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "local_only", "listen": saved.Server.Listen,
			"error": "After this restart only programs on the server itself can reach Signalith, at " + saved.Server.Listen +
				". You could not open this page again from here."})
		return
	}
	pending := pendingSettings(running, saved.Config)
	if err := s.Restarter.Restart(userOf(r), s.client(r).String(), localOnly); err != nil {
		code := "restart_failed"
		switch {
		case errors.Is(err, ErrRestarting):
			code = "restarting"
		case errors.Is(err, ErrAwaitingMove):
			code = "awaiting"
		}
		writeJSON(w, http.StatusConflict, map[string]any{"code": code, "error": sentence(err.Error())})
		return
	}
	keys := []string{}
	for _, p := range pending {
		keys = append(keys, p.Key)
	}
	s.audit(r, "restart requested", "pending", strings.Join(keys, ","), "local_only", localOnly)
	resp := map[string]any{"restarting": true, "pending": keys, "listen_changed": false, "reachable": !localOnly}
	if moved := newAddress(r, running, saved.Config, r.TLS == nil && s.viaTrustedProxy(r)); moved != "" {
		resp["listen_changed"], resp["new_listen"], resp["go_to"] = true, saved.Server.Listen, moved
		if !localOnly {
			resp["confirm_within_s"] = int(MoveWait.Seconds())
		}
	}
	writeJSON(w, http.StatusAccepted, resp)
}

// newAddress returns where the browser finds the web page after a
// restart that moves it, or "" when it stays: the host the browser uses
// now (or the new listen address's own host, when it listens on one
// address only), with the new port and scheme. viaProxy is set when r
// came through a trusted reverse proxy: HTTPS turned on or off behind it
// leaves the proxy's address as it is, and the page there confirms the
// move.
func newAddress(r *http.Request, running, saved *config.Config, viaProxy bool) string {
	if !webMoves(running, saved) || (viaProxy && running.Server.Listen == saved.Server.Listen) {
		return ""
	}
	lhost, port, err := net.SplitHostPort(saved.Server.Listen)
	if err != nil {
		return ""
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	switch lhost {
	case "", "0.0.0.0", "::":
	default:
		if !strings.EqualFold(lhost, host) && !(isLoopback(lhost) && isLoopback(host)) {
			host = lhost
		}
	}
	scheme := "http"
	if httpsOn(saved) {
		scheme = "https"
	}
	return webURL(scheme, host, port) + "/"
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// handleExportSettings returns the saved settings as a signalith.yaml
// snippet, for setting up other servers the same way. Secrets are left
// out. ?download=1 sends it as a file.
func (s *Server) handleExportSettings(w http.ResponseWriter, r *http.Request) {
	saved, err := s.savedSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	c := saved.Config
	if len(saved.Problems) > 0 || saved.PageErr != nil {
		c = s.conf()
	}
	text, err := exportSettings(c, redact.URL(s.conf().Server.PublicURL), time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	const name = "signalith-settings.yaml"
	if r.URL.Query().Get("download") != "" {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		_, _ = w.Write([]byte(text))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"yaml": text, "filename": name})
}

// serverOwn says why a setting in the export may not suit another
// server, or returns "" for one every server can share: a file path is a
// file on this server, and a setting of ScopeServer belongs to this server
// alone, such as whether it may run the background jobs. The public
// address and the certificate's extra names are shared by servers that
// share one OpenSearch, but another server set up on its own has its own.
func serverOwn(set *config.Setting) string {
	switch {
	case set.File:
		return "a file on this server"
	case set.Key == "server.public_url":
		return "this server's own address"
	case set.Key == "server.tls.names":
		return "this server's own names"
	case set.Scope != config.ScopeServer:
		return ""
	case set.Type == config.TypeAddress:
		return "this server's own address"
	}
	return "this server only"
}

// exportSettings writes the page's settings of c as signalith.yaml
// sections, in page order.
func exportSettings(c *config.Config, from string, now time.Time) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# Settings exported from Signalith at %s on %s.\n", from, now.UTC().Format("2006-01-02"))
	b.WriteString("# Copy what you need into signalith.yaml on another server. Passwords and\n")
	b.WriteString("# keys are left out: set them there, or with environment variables.\n")
	// signalith.yaml groups settings by their first word, which does not
	// always follow the page's sections (server.public_url is under
	// General, server.listen under Web server).
	var tops []string
	byTop := map[string][]*config.Setting{}
	for i := range config.Registry {
		set := &config.Registry[i]
		top, _, _ := strings.Cut(set.Key, ".")
		if byTop[top] == nil {
			tops = append(tops, top)
		}
		byTop[top] = append(byTop[top], set)
	}
	for _, top := range tops {
		fmt.Fprintf(&b, "%s:\n", top)
		if err := exportSection(&b, c, byTop[top]); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

func exportSection(b *strings.Builder, c *config.Config, settings []*config.Setting) error {
	// A setting a level deeper, such as server.tls.mode, goes in its own
	// part, written where the first of its settings is.
	var flat []*config.Setting
	var subs []string
	bySub := map[string][]*config.Setting{}
	for _, set := range settings {
		_, name, _ := strings.Cut(set.Key, ".")
		sub, _, nested := strings.Cut(name, ".")
		if !nested {
			flat = append(flat, set)
			continue
		}
		if bySub[sub] == nil {
			subs = append(subs, sub)
			flat = append(flat, nil) // where the part goes
		}
		bySub[sub] = append(bySub[sub], set)
	}
	next := 0
	for _, set := range flat {
		if set == nil {
			sub := subs[next]
			next++
			fmt.Fprintf(b, "  %s:\n", sub)
			if err := exportSettingLines(b, c, bySub[sub], "    "); err != nil {
				return err
			}
			continue
		}
		if err := exportSettingLines(b, c, []*config.Setting{set}, "  "); err != nil {
			return err
		}
	}
	return nil
}

// exportSettingLines writes settings, each under the last word of its key,
// indented by indent.
func exportSettingLines(b *strings.Builder, c *config.Config, settings []*config.Setting, indent string) error {
	for _, set := range settings {
		name := set.Key[strings.LastIndex(set.Key, ".")+1:]
		if set.Type == config.TypeSecret {
			hint := "set it here"
			if set.Env != "" {
				hint += " or with " + set.Env
			}
			fmt.Fprintf(b, "%s# %s: left out; %s\n", indent, name, hint)
			continue
		}
		// An address with a password in it is left out like a password.
		if s, _ := c.Value(set.Key).(string); urlKeys[set.Key] && s != "" && redact.URL(s) != s {
			fmt.Fprintf(b, "%s# %s: left out, as it holds a password; set it here\n", indent, name)
			continue
		}
		v := &yaml.Node{}
		if err := v.Encode(c.Value(set.Key)); err != nil {
			return err
		}
		if v.Kind == yaml.SequenceNode {
			v.Style = yaml.FlowStyle
		}
		out, err := yaml.Marshal(v)
		if err != nil {
			return err
		}
		line := fmt.Sprintf("%s%s: %s", indent, name, strings.TrimSpace(string(out)))
		if note := serverOwn(set); note != "" {
			line += "  # " + note
		}
		b.WriteString(line + "\n")
	}
	return nil
}

// fullPath is p from the root, as people on the server look for it; p
// itself when it cannot be worked out.
func fullPath(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}
