package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/users"
)

func (s *Server) routeUsers(api *router) {
	api.self("GET /api/me", s.handleMe)
	api.self("POST /api/me/password", s.handleChangeOwnPassword)

	api.admin("GET /api/users", s.handleListUsers)
	api.admin("POST /api/users", s.handleCreateUser)
	api.admin("PUT /api/users/{username}", s.handleUpdateUser)
	api.admin("DELETE /api/users/{username}", s.handleDeleteUser)
	api.admin("POST /api/users/{username}/password", s.handleResetPassword)

	api.admin("GET /api/auth/directory", s.handleGetDirectory)
	api.admin("PUT /api/auth/directory", s.handlePutDirectory)
	api.admin("POST /api/auth/directory/test", s.handleTestDirectory)
	api.admin("POST /api/auth/directory/test-user", s.handleTestDirectoryUser)
}

// audit logs a change someone made, with who and from where. Passwords
// are never passed here.
func (s *Server) audit(r *http.Request, msg string, args ...any) {
	s.Log.Info(msg, append([]any{"audit", true, "by", userOf(r), "client", clientIP(r)}, args...)...)
}

// ---- the signed-in user ----

// meView describes the signed-in user for the UI.
func meView(p *principal) map[string]any {
	return map[string]any{
		"user":                 p.Username, // older UI code reads this
		"username":             p.Username,
		"name":                 p.Name,
		"email":                p.Email,
		"role":                 p.Role,
		"role_label":           p.Role.Label(),
		"source":               p.Source,
		"must_change_password": p.MustChangePassword,
		// Only local users' passwords are kept by Signalith.
		"can_change_password": p.Source == users.SourceLocal,
		"auth":                p.Method,
	}
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	me := meView(p)
	// The Search page starts with the default time range set on the
	// Settings page, until someone picks another.
	me["search_default_earliest"] = s.conf().Search.DefaultEarliest
	// Every page asks this first: an admin who gets here at a new web
	// address after a restart moved it confirms that it works.
	if p.Role == users.Admin && !p.MustChangePassword {
		s.confirmMove(r)
	}
	writeJSON(w, http.StatusOK, me)
}

// handleChangeOwnPassword lets local users change their own password. It
// is also how a temporary password is replaced after signing in.
func (s *Server) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	var req struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	switch p.Source {
	case users.SourceBuiltin:
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "builtin",
			"error": "The built-in admin's password is kept on the server. Change it there with signalith passwd, then restart Signalith. " +
				"With the Docker quick start, from the Signalith folder: docker compose -f deploy/docker/docker-compose.yml exec signalith signalith passwd, " +
				"then docker compose -f deploy/docker/docker-compose.yml restart signalith"})
		return
	case users.SourceDirectory:
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "directory",
			"error": "Your password belongs to your directory (Active Directory or LDAP). Change it there."})
		return
	}
	client := clientIP(r)
	attempt, err := s.beginAttempt(r, p.Username)
	if err != nil {
		writeSignInError(w, err)
		return
	}
	if !s.userStore().CheckPassword(p.Username, req.Current) {
		attempt.Fail()
		s.Log.Warn("password change refused", "audit", true, "user", p.Username, "client", client, "reason", "wrong current password")
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "wrong_password", "field": "current_password",
			"error": "Your current password is not right."})
		return
	}
	attempt.Succeed()
	if req.New == req.Current {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "same_password", "field": "new_password",
			"error": "Choose a new password that is different from the current one."})
		return
	}
	u, err := s.userStore().SetPassword(p.Username, req.New, false)
	if errors.Is(err, users.ErrBusy) {
		writeUserError(w, err)
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "invalid_password", "field": "new_password", "error": err.Error()})
		return
	}
	// Other browsers signed in as this user are signed out; on servers
	// that share the users file, they are when they next make a request.
	ended := s.sessions().EndUser(p.Username, p.token)
	s.sessions().SetVersion(p.token, s.passwordStamp(p.Username))
	s.audit(r, "password changed", "user", p.Username, "other_sessions_ended", ended)
	np := principalFromUser(u)
	np.Method = p.Method
	writeJSON(w, http.StatusOK, meView(np))
}

// ---- managing users ----

// userView is a user as the Users page shows it. Actions lists what the
// signed-in admin may do to them: edit (name and email), role,
// reset_password, disable or enable, and delete.
type userView struct {
	Username           string     `json:"username"`
	Name               string     `json:"name"`
	Email              string     `json:"email"`
	Role               users.Role `json:"role"`
	Source             string     `json:"source"`
	Disabled           bool       `json:"disabled"`
	MustChangePassword bool       `json:"must_change_password"`
	DN                 string     `json:"dn,omitempty"`
	// Refused says why the directory no longer lets a directory user in;
	// their role is then empty.
	Refused    string     `json:"refused,omitempty"`
	Created    *time.Time `json:"created"`
	Updated    *time.Time `json:"updated"`
	LastSignIn *time.Time `json:"last_sign_in"`
	You        bool       `json:"you"`
	Actions    []string   `json:"actions"`
}

func (s *Server) viewUser(u users.User, me string) userView {
	created, updated := u.Created, u.Updated
	v := userView{Username: u.Username, Name: u.Name, Email: u.Email, Role: u.Role, Source: u.Source,
		Disabled: u.Disabled, MustChangePassword: u.MustChangePassword, DN: u.DN,
		Refused: u.Refused, Created: &created, Updated: &updated, LastSignIn: u.LastSignIn, You: strings.EqualFold(u.Username, me)}
	if u.Refused != "" {
		v.Role = ""
	}
	toggle := "disable"
	if u.Disabled {
		toggle = "enable"
	}
	switch {
	case u.Source == users.SourceLocal && v.You:
		v.Actions = []string{"edit"}
	case u.Source == users.SourceLocal:
		v.Actions = []string{"edit", "role", "reset_password", toggle, "delete"}
	case v.You:
		v.Actions = []string{}
	default:
		v.Actions = []string{toggle, "delete"}
	}
	return v
}

func (s *Server) builtinView(me string) userView {
	return userView{Username: s.conf().Auth.AdminUser, Role: users.Admin, Source: users.SourceBuiltin,
		LastSignIn: s.userStore().BuiltinLastSignIn(), You: strings.EqualFold(s.conf().Auth.AdminUser, me), Actions: []string{}}
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	me := userOf(r)
	list := s.userStore().List()
	out := make([]userView, 0, len(list)+1)
	out = append(out, s.builtinView(me))
	for _, u := range list {
		out = append(out, s.viewUser(u, me))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"users": out,
		"roles": users.RoleInfos,
		"directory": map[string]any{
			"enabled":     s.dir().Enabled(),
			"from_config": s.dir().FromConfig(),
		},
	})
}

// writeUserError maps store errors to status codes. A value the form
// should mark also names its field.
func writeUserError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, users.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, users.ErrExists), errors.Is(err, users.ErrLastAdmin), errors.Is(err, users.ErrManaged), errors.Is(err, users.ErrReserved):
		status = http.StatusConflict
	case errors.Is(err, users.ErrBusy):
		status = http.StatusServiceUnavailable
	}
	body := map[string]any{"error": err.Error()}
	var fe *users.FieldError
	if errors.As(err, &fe) {
		body["field"] = fe.Field
	}
	writeJSON(w, status, body)
}

// builtinTarget refuses changes to the built-in admin, which lives in
// signalith.yaml.
func (s *Server) builtinTarget(w http.ResponseWriter, name string) bool {
	if strings.EqualFold(name, s.conf().Auth.AdminUser) {
		writeError(w, http.StatusConflict, errors.New("the built-in admin is set in signalith.yaml and cannot be changed here; use signalith passwd on the server to change its password"))
		return true
	}
	return false
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string     `json:"username"`
		Name     string     `json:"name"`
		Email    string     `json:"email"`
		Role     users.Role `json:"role"`
		// Password is the temporary password; empty generates one.
		Password string `json:"password"`
		// MustChangePassword defaults to true.
		MustChangePassword *bool `json:"must_change_password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Role == "" {
		req.Role = users.Viewer
	}
	generated := ""
	if req.Password == "" {
		generated = users.GeneratePassword()
		req.Password = generated
	}
	mustChange := req.MustChangePassword == nil || *req.MustChangePassword
	if s.builtinTarget(w, req.Username) {
		return
	}
	u, err := s.userStore().Create(users.NewUser{Username: req.Username, Name: req.Name, Email: req.Email, Role: req.Role,
		Password: req.Password, MustChangePassword: mustChange})
	if err != nil {
		writeUserError(w, err)
		return
	}
	s.audit(r, "user created", "user", u.Username, "role", u.Role, "must_change_password", mustChange)
	resp := map[string]any{"user": s.viewUser(u, userOf(r))}
	if generated != "" {
		// Shown once; it is not stored anywhere but as a hash.
		resp["temporary_password"] = generated
	}
	writeJSON(w, http.StatusCreated, resp)
}

// targetName is the user a /api/users/{username} request is about, in
// the form the store keeps, so the checks below compare like with like.
func targetName(r *http.Request) string { return users.NormalizeUsername(r.PathValue("username")) }

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	name := targetName(r)
	var req struct {
		Name     *string     `json:"name"`
		Email    *string     `json:"email"`
		Role     *users.Role `json:"role"`
		Disabled *bool       `json:"disabled"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if s.builtinTarget(w, name) {
		return
	}
	cur, ok := s.userStore().Get(name)
	if !ok {
		writeUserError(w, users.ErrNotFound)
		return
	}
	if strings.EqualFold(cur.Username, userOf(r)) {
		if req.Disabled != nil && *req.Disabled {
			writeError(w, http.StatusConflict, errors.New("you cannot disable your own account; ask another admin"))
			return
		}
		if req.Role != nil && *req.Role != cur.Role {
			writeError(w, http.StatusConflict, errors.New("you cannot change your own role; ask another admin"))
			return
		}
	}
	u, err := s.userStore().Update(name, users.Change{Name: req.Name, Email: req.Email, Role: req.Role, Disabled: req.Disabled})
	if err != nil {
		writeUserError(w, err)
		return
	}
	var changed []string
	if u.Name != cur.Name {
		changed = append(changed, "name")
	}
	if u.Email != cur.Email {
		changed = append(changed, "email")
	}
	if len(changed) > 0 {
		s.audit(r, "user changed", "user", u.Username, "fields", strings.Join(changed, ","))
	}
	if u.Role != cur.Role {
		s.audit(r, "user role changed", "user", u.Username, "from", cur.Role, "to", u.Role)
	}
	if u.Disabled != cur.Disabled {
		if u.Disabled {
			ended := s.sessions().EndUser(u.Username, "")
			s.audit(r, "user disabled", "user", u.Username, "sessions_ended", ended)
		} else {
			s.audit(r, "user enabled", "user", u.Username)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": s.viewUser(u, userOf(r))})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	name := targetName(r)
	if s.builtinTarget(w, name) {
		return
	}
	cur, ok := s.userStore().Get(name)
	if !ok {
		writeUserError(w, users.ErrNotFound)
		return
	}
	if strings.EqualFold(cur.Username, userOf(r)) {
		writeError(w, http.StatusConflict, errors.New("you cannot delete your own account; ask another admin"))
		return
	}
	u, err := s.userStore().Delete(cur.Username)
	if err != nil {
		writeUserError(w, err)
		return
	}
	ended := s.sessions().EndUser(u.Username, "")
	s.audit(r, "user deleted", "user", u.Username, "source", u.Source, "role", u.Role, "sessions_ended", ended)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": u.Username})
}

// handleResetPassword gives a local user a temporary password, which they
// replace at their next sign-in. Their sessions end.
func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	name := targetName(r)
	var req struct {
		Password string `json:"password"`
	}
	if r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if s.builtinTarget(w, name) {
		return
	}
	cur, ok := s.userStore().Get(name)
	if !ok {
		writeUserError(w, users.ErrNotFound)
		return
	}
	if strings.EqualFold(cur.Username, userOf(r)) {
		writeError(w, http.StatusConflict, errors.New("to change your own password, use Change password in your user menu"))
		return
	}
	name = cur.Username
	generated := ""
	if req.Password == "" {
		generated = users.GeneratePassword()
		req.Password = generated
	}
	u, err := s.userStore().SetPassword(name, req.Password, true)
	if err != nil {
		writeUserError(w, err)
		return
	}
	ended := s.sessions().EndUser(u.Username, "")
	s.audit(r, "password reset", "user", u.Username, "sessions_ended", ended)
	resp := map[string]any{"user": s.viewUser(u, userOf(r))}
	if generated != "" {
		resp["temporary_password"] = generated
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- directory sign-in settings ----

// settingsView is directory settings as the API shows them: never the
// bind password, only whether one is set.
type settingsView struct {
	users.LDAPSettings
	BindPasswordSet bool `json:"bind_password_set"`
}

// settingsInput is directory settings as the API takes them. An empty or
// missing bind_password keeps the saved one.
type settingsInput struct {
	users.LDAPSettings
	BindPassword string `json:"bind_password"`
}

func (s *Server) directoryView() map[string]any {
	d := s.dir()
	cur := d.Settings()
	presets := map[string]settingsView{}
	for _, typ := range []string{users.TypeActiveDirectory, users.TypeOpenLDAP} {
		p := users.Preset(typ)
		p.Normalize()
		p.Enabled = nil
		presets[typ] = settingsView{LDAPSettings: p}
	}
	warnings := cur.Warnings()
	if p := d.Problem(); p != "" {
		warnings = append([]string{p}, warnings...)
	}
	if warnings == nil {
		warnings = []string{}
	}
	view := map[string]any{
		"settings":        settingsView{LDAPSettings: cur, BindPasswordSet: cur.BindPassword != ""},
		"from_config":     d.FromConfig(),
		"saved":           d.Saved(),
		"warnings":        warnings,
		"presets":         presets,
		"directory_users": s.userStore().Count()[users.SourceDirectory],
	}
	if d.FromConfig() {
		view["config_file"] = s.conf().Path()
	}
	return view
}

func (s *Server) handleGetDirectory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.directoryView())
}

// mergeSettings turns input into settings. When no bind password was
// typed, the saved one is kept, but only while the servers, the service
// account and the TLS settings are the saved ones: otherwise anyone who can
// edit the settings could have the saved password sent to a server of
// their choosing. Then again is true and the password must be typed again.
func (s *Server) mergeSettings(in *settingsInput) (set users.LDAPSettings, again bool) {
	cur := s.dir().Settings()
	if in == nil {
		return cur, false
	}
	next := in.LDAPSettings.Clone()
	next.BindPassword = in.BindPassword
	if next.BindPassword == "" && strings.TrimSpace(next.BindDN) != "" && cur.BindPassword != "" {
		if users.SameConnection(cur, next) {
			next.BindPassword = cur.BindPassword
		} else {
			again = true
		}
	}
	return next, again
}

// bindPasswordAgain says why the saved bind password was not used.
const bindPasswordAgain = "enter the service account's password again: the saved one is only used with the saved servers, bind DN and TLS settings"

// explainAgain rewords the missing bind password problem when the saved
// one was held back by mergeSettings.
func explainAgain(problems []users.Problem, again bool) []users.Problem {
	if !again {
		return problems
	}
	for i, p := range problems {
		if p.Field == "bind_password" {
			problems[i].Message = bindPasswordAgain
		}
	}
	return problems
}

// serversOf lists the servers settings point at, for the audit log.
func serversOf(set users.LDAPSettings) string {
	return strings.Join(slices.DeleteFunc([]string{set.URL, set.FailoverURL}, func(v string) bool { return v == "" }), " ")
}

// writeProblems reports settings that need fixing, as a list and by field
// for the form.
func writeProblems(w http.ResponseWriter, problems []users.Problem) {
	msgs := make([]string, 0, len(problems))
	fields := map[string]string{}
	for _, p := range problems {
		msgs = append(msgs, p.Message)
		if _, ok := fields[p.Field]; !ok {
			fields[p.Field] = p.Message
		}
	}
	writeJSON(w, http.StatusBadRequest, map[string]any{
		"error":    "Some settings need fixing: " + strings.Join(msgs, "; ") + ".",
		"problems": msgs,
		"fields":   fields,
	})
}

func (s *Server) handlePutDirectory(w http.ResponseWriter, r *http.Request) {
	d := s.dir()
	if d.FromConfig() {
		writeError(w, http.StatusConflict, users.ErrReadOnly)
		return
	}
	var in settingsInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	before := d.Settings()
	next, again := s.mergeSettings(&in)
	err := d.Save(next)
	var se *users.SettingsError
	switch {
	case errors.As(err, &se):
		writeProblems(w, explainAgain(se.Problems, again))
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, fmt.Errorf("could not save the directory settings: %w", err))
		return
	}
	after := d.Settings()
	// Check signed-in directory users against the new settings now, rather
	// than at their next request.
	for _, name := range s.sessions().Users() {
		if u, ok := s.userStore().Get(name); ok && u.Source == users.SourceDirectory && !u.Disabled && u.Refused == "" && after.IsEnabled() {
			s.recheckDirectoryUser(u.Username)
		}
	}
	s.audit(r, "directory settings changed", "enabled", after.IsEnabled(), "servers", serversOf(after),
		"fields", strings.Join(changedSettings(before, after), ","))
	writeJSON(w, http.StatusOK, s.directoryView())
}

// changedSettings names the settings that differ, by their keys. The bind
// password is named but its value never appears.
func changedSettings(a, b users.LDAPSettings) []string {
	var out []string
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	t := va.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		key := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if !reflect.DeepEqual(va.Field(i).Interface(), vb.Field(i).Interface()) {
			out = append(out, key)
		}
	}
	return out
}

// testSettings checks settings well enough to test them: switched on or
// not, a test needs a server address, and a user lookup needs the user
// search settings. Group mappings are not needed.
func testSettings(set users.LDAPSettings, forUser bool) []users.Problem {
	set.Normalize()
	off := false
	set.Enabled = &off
	p := set.Problems()
	need := func(field, v, msg string) {
		if v == "" {
			p = append(p, users.Problem{Field: field, Message: msg})
		}
	}
	need("url", set.URL, "enter the server address, like ldaps://dc1.corp.example.com")
	if forUser {
		need("type", set.Type, "choose ad (Active Directory) or openldap")
		need("user_base_dn", set.UserBaseDN, "enter where to search for users, like DC=corp,DC=example,DC=com")
		need("user_filter", set.UserFilter, "enter a user filter containing {username}")
		need("username_attribute", set.UsernameAttribute, "enter the attribute holding the username")
	}
	return p
}

// handleTestDirectory tests the connection and the service account, with
// the settings in the request (unsaved form values) or the saved ones.
func (s *Server) handleTestDirectory(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Settings *settingsInput `json:"settings"`
	}
	if r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	if s.dir().FromConfig() {
		req.Settings = nil
	}
	set, again := s.mergeSettings(req.Settings)
	if p := testSettings(set, false); len(p) > 0 {
		writeProblems(w, explainAgain(p, again))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	rep := users.TestConnection(ctx, set)
	s.audit(r, "directory connection tested", "servers", serversOf(set), "bind_dn", set.BindDN, "ok", rep.OK)
	writeJSON(w, http.StatusOK, rep)
}

// handleTestDirectoryUser looks a user up as sign-in would, and checks
// their password when one is given.
func (s *Server) handleTestDirectoryUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string         `json:"username"`
		Password string         `json:"password"`
		Settings *settingsInput `json:"settings"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Enter a username to look up.", "fields": map[string]string{"username": "enter a username"}})
		return
	}
	if s.dir().FromConfig() {
		req.Settings = nil
	}
	set, again := s.mergeSettings(req.Settings)
	if p := testSettings(set, true); len(p) > 0 {
		writeProblems(w, explainAgain(p, again))
		return
	}
	var attempt *auth.Attempt
	if req.Password != "" {
		// Testing passwords counts toward the limits, like signing in.
		var err error
		if attempt, err = s.beginAttempt(r, req.Username); err != nil {
			writeSignInError(w, err)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	rep := users.LookupUser(ctx, set, req.Username, req.Password)
	switch {
	case attempt == nil:
	case rep.Code == "wrong_password":
		attempt.Fail()
	case rep.OK:
		attempt.Succeed()
	default:
		attempt.Done()
	}
	warning := ""
	login := users.LoginName(req.Username)
	if strings.EqualFold(login, s.conf().Auth.AdminUser) {
		warning = "This is the built-in admin's name, so sign-in never asks the directory about it."
	} else if u, ok := s.userStore().Get(login); ok && u.Source == users.SourceLocal {
		warning = "A local Signalith user has this name, so sign-in uses the local password and never asks the directory."
	}
	s.audit(r, "directory user looked up", "user", login, "servers", serversOf(set), "ok", rep.OK, "code", rep.Code, "password_checked", rep.PasswordChecked)
	writeJSON(w, http.StatusOK, struct {
		users.UserReport
		Warning string `json:"warning,omitempty"`
	}{rep, warning})
}
