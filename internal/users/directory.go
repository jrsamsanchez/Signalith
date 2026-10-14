package users

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// DirectoryUser is what the directory says about someone signing in.
type DirectoryUser struct {
	Username string `json:"username"`
	DN       string `json:"dn"`
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
	// Groups lists every group found; Matched those mapped to a role.
	Groups  []string `json:"groups"`
	Matched []string `json:"matched_groups"`
	// Role is "" when no mapped group matched and such users are refused.
	Role Role `json:"role,omitempty"`
}

var (
	// ErrBadCredentials is every refused username or password, so the
	// reply does not reveal which one was wrong.
	ErrBadCredentials = errors.New("username and password don't match")
	// ErrNoRole refuses a correct password from a user in no mapped group.
	ErrNoRole = errors.New("your directory account is not in a group that can use Signalith; ask an admin to add you to one")
	// ErrPasswordExpired refuses a correct password that Active Directory
	// says has expired or must be changed first.
	ErrPasswordExpired = errors.New("your directory password has expired or must be changed; change it, then sign in again")
	// ErrDirectoryOff means directory sign-in is switched off.
	ErrDirectoryOff = errors.New("directory sign-in is off")
	// ErrReadOnly refuses UI changes to settings from signalith.yaml.
	ErrReadOnly = errors.New("directory sign-in is set up in signalith.yaml (auth.ldap); change it there")
)

// SignInError is a refused directory sign-in. Err is ErrBadCredentials,
// ErrNoRole or ErrPasswordExpired; Reason says why, for the server log
// only.
type SignInError struct {
	Err    error
	Reason string
	// Revoke, when set, says in plain words why the directory no longer
	// lets this person use Signalith: not found (deleted, or disabled in
	// Active Directory), disabled or expired there, or in no mapped group.
	// It is only set when a wrong password cannot be the cause, so a
	// stranger typing someone's name cannot take their access away.
	Revoke string
}

func (e *SignInError) Error() string { return e.Err.Error() }
func (e *SignInError) Unwrap() error { return e.Err }

// DirectoryError means the directory could not be used: it could not be
// reached, its certificate was not trusted, the service account was
// refused, and so on. Message explains it for an admin.
type DirectoryError struct {
	// Code names the problem: connect, tls_untrusted, tls_hostname,
	// tls_expired, tls_handshake, ca_cert, starttls_refused, bind_refused,
	// encryption_required, bind_failed, base_not_found, search_refused,
	// bind_required, search_failed.
	Code    string
	Message string
	Server  string
	Err     error
}

func (e *DirectoryError) Error() string { return e.Message }
func (e *DirectoryError) Unwrap() error { return e.Err }

// Detail is the underlying error text, useful to search for.
func (e *DirectoryError) Detail() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

// SettingsError lists the settings that need fixing.
type SettingsError struct{ Problems []Problem }

func (e *SettingsError) Error() string {
	msgs := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		msgs[i] = p.Field + ": " + p.Message
	}
	return "fix these settings: " + strings.Join(msgs, "; ")
}

// Directory holds the directory sign-in settings and signs users in. The
// settings are kept in a DirectoryBackend: directory.json or
// signalith.yaml (OpenDirectory), or the shared configuration of a
// cluster.
type Directory struct {
	b DirectoryBackend
}

// DirectoryBackend keeps the directory sign-in settings.
type DirectoryBackend interface {
	// Load returns the settings in use, with the service account
	// password; saved is false for the untouched defaults, and problem
	// says why saved settings cannot be used as they are ("" when they
	// can), such as a password that cannot be decrypted.
	Load() (s LDAPSettings, saved bool, problem string)
	// Save stores checked settings, read at etag when it is set
	// (ErrStale, or an error naming who changed them, when they changed
	// since).
	Save(ctx context.Context, by, etag string, s LDAPSettings) error
	// Revision changes whenever the settings do.
	Revision() uint64
	// ETag is the version of the settings in use.
	ETag() string
	// From says where the settings in use came from.
	From() DirectoryFrom
}

// DirectoryFrom says where directory settings came from: Source is
// "yaml" (auth.ldap in signalith.yaml), "page" (saved on the Users page),
// "import", or "" for the untouched defaults; Node and At, when known,
// say on which server and when.
type DirectoryFrom struct {
	Source string    `json:"source"`
	Node   string    `json:"node,omitempty"`
	At     time.Time `json:"at,omitzero"`
}

// NewDirectory returns the directory sign-in kept in b.
func NewDirectory(b DirectoryBackend) *Directory { return &Directory{b: b} }

// fileDirectory keeps the settings in directory.json, or uses those of
// signalith.yaml as they are.
type fileDirectory struct {
	path       string
	fromConfig bool
	mu         sync.RWMutex
	settings   LDAPSettings
	rev        uint64
	saved      bool
	problem    string
}

// directoryFile is directory.json. It holds the service account password,
// encrypted with the master key (package secrets), and is written readable
// only by Signalith's own account.
type directoryFile struct {
	Version      int          `json:"version"`
	Settings     LDAPSettings `json:"settings"`
	BindPassword string       `json:"bind_password,omitempty"`
}

// BindPasswordField is the setting the service account password in
// directory.json is encrypted for.
const BindPasswordField = "directory.bind_password"

// OpenDirectory loads directory sign-in settings. When fromConfig is set
// (auth.ldap in signalith.yaml) it is used as is and cannot be changed
// from the UI; otherwise settings come from the file at path, which Save
// writes. An empty path keeps settings in memory only.
func OpenDirectory(path string, fromConfig *LDAPSettings) (*Directory, error) {
	d := &fileDirectory{path: path}
	if fromConfig != nil {
		d.fromConfig = true
		d.settings = fromConfig.Clone()
		d.settings.Normalize()
		return NewDirectory(d), nil
	}
	off := false
	d.settings = Preset(TypeActiveDirectory)
	d.settings.Enabled = &off
	d.settings.Normalize()
	if path == "" {
		return NewDirectory(d), nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return NewDirectory(d), nil
	}
	if err != nil {
		return nil, err
	}
	var f directoryFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("directory settings file %s is damaged (%v); fix it or move it away", path, err)
	}
	// A password that cannot be decrypted is left out rather than stopping
	// the server: directory sign-in then fails without trying a wrong
	// password on the service account (which could lock it), and Problem
	// says how to fix it.
	pw, err := secrets.Open(BindPasswordField, f.BindPassword)
	if err != nil {
		d.problem = fmt.Sprintf("Directory sign-in cannot search for users until the service account password is entered again (open Users, then Directory sign-in). In %s, %v", path, err)
	}
	f.Settings.BindPassword = pw
	f.Settings.Normalize()
	d.settings = f.Settings
	d.saved = true
	return NewDirectory(d), nil
}

func (d *fileDirectory) Load() (LDAPSettings, bool, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.settings.Clone(), d.saved || d.fromConfig, d.problem
}

func (d *fileDirectory) Revision() uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.rev
}

func (d *fileDirectory) ETag() string { return strconv.FormatUint(d.Revision(), 10) }

func (d *fileDirectory) From() DirectoryFrom {
	d.mu.RLock()
	defer d.mu.RUnlock()
	switch {
	case d.fromConfig:
		return DirectoryFrom{Source: "yaml"}
	case d.saved:
		return DirectoryFrom{Source: "page"}
	}
	return DirectoryFrom{}
}

func (d *fileDirectory) Save(_ context.Context, _, etag string, s LDAPSettings) error {
	if d.fromConfig {
		return ErrReadOnly
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if etag != "" && etag != strconv.FormatUint(d.rev, 10) {
		return ErrStale
	}
	if d.path != "" {
		sealed, err := secrets.Seal(BindPasswordField, s.BindPassword)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(directoryFile{Version: 1, Settings: s, BindPassword: sealed}, "", "  ")
		if err != nil {
			return err
		}
		if err := WriteFileAtomic(d.path, append(data, '\n')); err != nil {
			return err
		}
	}
	d.settings = s
	d.rev++
	d.saved = true
	d.problem = ""
	return nil
}

// Problem says why saved settings cannot be used as they are, such as a
// service account password that cannot be decrypted; "" when they can.
func (d *Directory) Problem() string {
	_, _, p := d.b.Load()
	return p
}

// ResealDirectoryFile passes the service account password in the
// directory.json text data through fn and returns the file with what fn
// returned, and 1 if that changed it (0 otherwise).
func ResealDirectoryFile(data []byte, fn secrets.Reseal) ([]byte, int, error) {
	var f directoryFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, 0, fmt.Errorf("not valid JSON: %w", err)
	}
	if f.BindPassword == "" {
		return data, 0, nil
	}
	v, err := fn(secrets.Stored{Field: BindPasswordField, Label: "bind_password (service account password)", Value: f.BindPassword})
	if err != nil || v == f.BindPassword {
		return data, 0, err
	}
	f.BindPassword = v
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, 0, err
	}
	return append(out, '\n'), 1, nil
}

// Settings returns a copy of the current settings, with the password.
func (d *Directory) Settings() LDAPSettings {
	s, _, _ := d.b.Load()
	return s
}

// Saved reports whether settings were ever saved, or come from
// signalith.yaml, rather than being the untouched defaults.
func (d *Directory) Saved() bool {
	_, saved, _ := d.b.Load()
	return saved
}

// FromConfig reports whether the settings come from signalith.yaml and
// cannot be changed from the UI.
func (d *Directory) FromConfig() bool {
	f, ok := d.b.(*fileDirectory)
	return ok && f.fromConfig
}

// Path returns the settings file the UI saves to, or "" when there is
// none.
func (d *Directory) Path() string {
	if f, ok := d.b.(*fileDirectory); ok {
		return f.path
	}
	return ""
}

// Enabled reports whether directory sign-in is on.
func (d *Directory) Enabled() bool {
	s, _, _ := d.b.Load()
	return s.IsEnabled()
}

// Revision changes whenever the settings do, so a cache of checked
// passwords can include it in its keys.
func (d *Directory) Revision() uint64 { return d.b.Revision() }

// ETag returns the version of the settings in use, for SaveIf.
func (d *Directory) ETag() string { return d.b.ETag() }

// From says where the settings in use came from.
func (d *Directory) From() DirectoryFrom { return d.b.From() }

// Save checks and stores new settings.
func (d *Directory) Save(ctx context.Context, s LDAPSettings) error {
	return d.SaveIf(ctx, "", s)
}

// SaveIf is Save for settings read at etag (ETag): ErrStale, or an error
// naming who changed them, when they changed since. An empty etag saves
// over whatever is there.
func (d *Directory) SaveIf(ctx context.Context, etag string, s LDAPSettings) error {
	if d.FromConfig() {
		return ErrReadOnly
	}
	s = s.Clone()
	if s.Enabled == nil {
		off := false
		s.Enabled = &off
	}
	s.Normalize()
	if p := s.Problems(); len(p) > 0 {
		return &SettingsError{Problems: p}
	}
	return d.b.Save(ctx, Actor(ctx), etag, s)
}

// Authenticate checks a username and password with the directory and
// returns who they are and the role their groups give.
func (d *Directory) Authenticate(ctx context.Context, login, password string) (*DirectoryUser, error) {
	s := d.Settings()
	if !s.IsEnabled() {
		return nil, ErrDirectoryOff
	}
	return lookup(ctx, &s, login, password, true)
}

// Lookup finds a user with the service account, without their password,
// and returns who they are and the role their groups give now. It is how
// signed-in directory users are checked again while they use Signalith.
func (d *Directory) Lookup(ctx context.Context, login string) (*DirectoryUser, error) {
	s := d.Settings()
	if !s.IsEnabled() {
		return nil, ErrDirectoryOff
	}
	return lookup(ctx, &s, login, "", false)
}

// LoginName strips a DOMAIN\ prefix, which Windows users often type.
func LoginName(login string) string {
	login = strings.TrimSpace(login)
	if i := strings.LastIndexByte(login, '\\'); i >= 0 {
		login = login[i+1:]
	}
	return login
}

var (
	errNoMatch     = errors.New("not found in the directory")
	errManyMatches = errors.New("more than one directory entry matches")
)

// lookup finds a user and their groups and, when checkPassword is set,
// binds as them to check the password.
func lookup(ctx context.Context, s *LDAPSettings, login, password string, checkPassword bool) (*DirectoryUser, error) {
	login = LoginName(login)
	if login == "" {
		return nil, &SignInError{Err: ErrBadCredentials, Reason: "empty username"}
	}
	if checkPassword && password == "" {
		// An empty password makes a simple bind "unauthenticated", which
		// many servers report as success. Refuse before asking.
		return nil, &SignInError{Err: ErrBadCredentials, Reason: "empty password"}
	}
	c, err := dialAny(ctx, s)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if err := c.bindService(s); err != nil {
		return nil, err
	}
	e, err := c.findUser(s, login)
	if errors.Is(err, errNoMatch) || errors.Is(err, errManyMatches) {
		why := "not found in the directory"
		if errors.Is(err, errManyMatches) {
			why = "more than one directory entry has this name"
		}
		return nil, &SignInError{Err: ErrBadCredentials, Reason: err.Error(), Revoke: why}
	}
	if err != nil {
		return nil, err
	}
	// The directory's spelling of the name goes into group filters
	// (memberUid matches case); Signalith stores it in lower case.
	name := e.GetEqualFoldAttributeValue(s.UsernameAttribute)
	if name == "" {
		name = login
	}
	u := &DirectoryUser{
		DN:       e.DN,
		Username: strings.ToLower(name),
		Name:     e.GetEqualFoldAttributeValue(s.NameAttribute),
		Email:    e.GetEqualFoldAttributeValue(s.EmailAttribute),
	}
	u.Groups, err = c.groups(s, e, name)
	if err != nil {
		return u, err
	}
	u.Role, u.Matched = s.roleFor(u.Groups)
	if password != "" {
		if err := c.l.Bind(e.DN, password); err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
				why := adReason(err)
				if why == "password expired" || why == "must change password first" {
					// AD only says this when the password itself was right.
					return u, &SignInError{Err: ErrPasswordExpired, Reason: why}
				}
				reason := "wrong password"
				if why != "" && why != reason {
					reason += " (" + why + ")"
				}
				// Active Directory only names these when the password was right.
				gone := ""
				if why == "account disabled" || why == "account expired" {
					gone = strings.TrimPrefix(why, "account ") + " in the directory"
				}
				return u, &SignInError{Err: ErrBadCredentials, Reason: reason, Revoke: gone}
			}
			return u, explain("userbind", c.server, err, s)
		}
	}
	if !validDirectoryName(u.Username) {
		return u, &SignInError{Err: ErrBadCredentials, Reason: fmt.Sprintf("directory username %q has characters Signalith cannot use", u.Username)}
	}
	if u.Role == "" {
		return u, &SignInError{Err: ErrNoRole, Reason: "in no group mapped to a role", Revoke: "not in a group mapped to a role"}
	}
	return u, nil
}

// validDirectoryName accepts what directories allow in a logon name
// except slashes and control characters, which would break URLs and logs.
func validDirectoryName(name string) bool {
	if name == "" || len(name) > 128 || strings.ContainsAny(name, `/\`) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// conn is one connection to a directory server.
type conn struct {
	l      *ldap.Conn
	server string
	tls    string // TLS version, or "" for a plain connection
	stop   func() bool
}

func (c *conn) Close() {
	c.l.Close()
	c.stop()
}

func (s *LDAPSettings) connectTimeout() time.Duration {
	return time.Duration(max(s.ConnectTimeout, 1)) * time.Second
}
func (s *LDAPSettings) timeout() time.Duration { return time.Duration(max(s.Timeout, 1)) * time.Second }

// servers lists the URLs to try, in order.
func (s *LDAPSettings) servers() []string {
	out := []string{s.URL}
	if s.FailoverURL != "" {
		out = append(out, s.FailoverURL)
	}
	return out
}

// dialAny connects to the first server that answers. Only connection and
// TLS problems move on to the failover server; a refused password would be
// refused there too.
func dialAny(ctx context.Context, s *LDAPSettings) (*conn, error) {
	var last error
	for _, u := range s.servers() {
		c, err := dial(ctx, s, u)
		if err == nil {
			return c, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

// dial opens a connection, with TLS for ldaps:// or StartTLS. The whole
// exchange has a deadline, so a server that stops answering cannot hold a
// sign-in for long.
func dial(ctx context.Context, s *LDAPSettings, rawURL string) (*conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, &DirectoryError{Code: "connect", Server: rawURL, Message: fmt.Sprintf("%q is not a server address", rawURL), Err: err}
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "389"
		if u.Scheme == "ldaps" {
			port = "636"
		}
	}
	addr := net.JoinHostPort(host, port)
	server := u.Scheme + "://" + addr
	d := net.Dialer{Timeout: s.connectTimeout()}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, connectError(server, addr, err, s)
	}
	_ = raw.SetDeadline(time.Now().Add(s.connectTimeout() + 4*s.timeout()))
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	fail := func(err error) (*conn, error) {
		stop()
		raw.Close()
		return nil, err
	}
	var nc net.Conn = raw
	version := ""
	if u.Scheme == "ldaps" || s.StartTLS {
		cfg, err := tlsConfig(s, host)
		if err != nil {
			return fail(&DirectoryError{Code: "ca_cert", Server: server, Message: err.Error(), Err: err})
		}
		if u.Scheme == "ldap" {
			if err := startTLS(raw); err != nil {
				if _, ok := err.(*ldap.Error); ok {
					return fail(&DirectoryError{Code: "starttls_refused", Server: server, Err: err,
						Message: fmt.Sprintf("%s refused StartTLS. Use ldaps:// instead, or ask the directory admin to enable TLS on the server.", addr)})
				}
				return fail(connectError(server, addr, err, s))
			}
		}
		tc := tls.Client(raw, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return fail(tlsError(server, host, u.Scheme, err, s))
		}
		nc, version = tc, tls.VersionName(tc.ConnectionState().Version)
	}
	l := ldap.NewConn(nc, version != "")
	l.Start()
	l.SetTimeout(s.timeout())
	return &conn{l: l, server: server, tls: version, stop: stop}, nil
}

func tlsConfig(s *LDAPSettings, host string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, InsecureSkipVerify: s.TLSSkipVerify} //nolint:gosec // only when the admin turns it on, with a warning
	if s.CACert != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(s.CACert)) {
			return nil, errors.New("the CA certificate could not be read; paste it in PEM form, starting with -----BEGIN CERTIFICATE-----")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// startTLS asks the server to switch to TLS (RFC 4511 section 4.14) on the
// raw connection, before the LDAP client takes it over, so a certificate
// problem is reported as itself rather than as text.
func startTLS(c net.Conn) error {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "MessageID"))
	req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationExtendedRequest, nil, "Start TLS")
	req.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "1.3.6.1.4.1.1466.20037", "TLS Extended Command"))
	p.AppendChild(req)
	if _, err := c.Write(p.Bytes()); err != nil {
		return err
	}
	resp, err := ber.ReadPacket(c)
	if err != nil {
		return err
	}
	return ldap.GetLDAPError(resp)
}

// bindService signs in as the service account, if there is one.
func (c *conn) bindService(s *LDAPSettings) error {
	if s.BindDN == "" {
		return nil
	}
	if err := c.l.Bind(s.BindDN, s.BindPassword); err != nil {
		return explain("bind", c.server, err, s)
	}
	return nil
}

// findUser returns the one entry the user filter matches.
func (c *conn) findUser(s *LDAPSettings, login string) (*ldap.Entry, error) {
	filter := strings.ReplaceAll(s.UserFilter, "{username}", ldap.EscapeFilter(login))
	attrs := []string{"memberOf"}
	for _, a := range []string{s.UsernameAttribute, s.NameAttribute, s.EmailAttribute} {
		if a != "" {
			attrs = append(attrs, a)
		}
	}
	// A size limit of 2 is enough to tell one match from several.
	res, err := c.l.Search(ldap.NewSearchRequest(s.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, s.Timeout, false, filter, attrs, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) || (res != nil && len(res.Entries) > 1) {
		return nil, errManyMatches
	}
	if err != nil {
		return nil, explain("search", c.server, err, s)
	}
	if len(res.Entries) == 0 {
		return nil, errNoMatch
	}
	return res.Entries[0], nil
}

// groups returns the DNs of the groups a user is in.
func (c *conn) groups(s *LDAPSettings, e *ldap.Entry, username string) ([]string, error) {
	var out []string
	base := s.groupBase(e.DN)
	filter := ""
	switch s.GroupSearch {
	case GroupsMemberOf:
		out = append(out, e.GetEqualFoldAttributeValues("memberOf")...)
		if s.Nested() {
			// The server follows groups inside groups for us.
			filter = "(&(objectClass=group)(member:" + inChain + ":=" + ldap.EscapeFilter(e.DN) + "))"
		}
	case GroupsSearch:
		filter = strings.NewReplacer("{dn}", ldap.EscapeFilter(e.DN), "{username}", ldap.EscapeFilter(username)).Replace(s.GroupFilter)
	}
	if filter != "" {
		res, err := c.l.SearchWithPaging(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, s.Timeout, false, filter, []string{"1.1"}, nil), 500)
		if err != nil {
			return nil, explain("groups", c.server, err, s)
		}
		for _, g := range res.Entries {
			out = append(out, g.DN)
		}
	}
	return cleanDNs(out), nil
}

// ---- explaining errors ----

func connectError(server, addr string, err error, s *LDAPSettings) *DirectoryError {
	var dnsErr *net.DNSError
	var msg string
	var ne net.Error
	switch {
	case errors.As(err, &dnsErr):
		msg = fmt.Sprintf("The server name %s could not be found. Check the address for typos, and that this server can resolve it (DNS).", dnsErr.Name)
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		msg = fmt.Sprintf("%s did not answer within %d seconds. Check the address and port, and that no firewall blocks the connection.", addr, s.ConnectTimeout)
	case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "refused"):
		msg = fmt.Sprintf("%s refused the connection: nothing is listening on that port. LDAP usually uses port 389 and LDAPS port 636.", addr)
	default:
		msg = fmt.Sprintf("Could not connect to %s: %v.", addr, err)
	}
	return &DirectoryError{Code: "connect", Server: server, Message: msg, Err: err}
}

// wsaConnReset is Windows' "connection was forcibly closed" error
// (WSAECONNRESET), which syscall.ECONNRESET does not match there.
const wsaConnReset = syscall.Errno(10054)

func tlsError(server, host, scheme string, err error, s *LDAPSettings) *DirectoryError {
	var unknown x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalid x509.CertificateInvalidError
	var record tls.RecordHeaderError
	e := &DirectoryError{Code: "tls_handshake", Server: server, Err: err}
	switch {
	case errors.As(err, &unknown):
		e.Code = "tls_untrusted"
		if s.CACert != "" {
			e.Message = "The server's TLS certificate is not signed by the CA certificate you gave. Check that it is the CA (or intermediate) that issued the server's certificate."
		} else {
			e.Message = "The server's TLS certificate is not trusted. Paste the certificate of the CA that issued it under CA certificate."
		}
	case errors.As(err, &hostErr):
		e.Code = "tls_hostname"
		names := hostErr.Certificate.DNSNames
		if len(names) == 0 && hostErr.Certificate.Subject.CommonName != "" {
			names = []string{hostErr.Certificate.Subject.CommonName}
		}
		e.Message = fmt.Sprintf("The server's TLS certificate is for %s, not %s. Use a name on the certificate in the server address.", strings.Join(names, ", "), host)
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		e.Code = "tls_expired"
		e.Message = "The server's TLS certificate has expired or is not valid yet. Renew it, or check the clocks on both servers."
	case errors.As(err, &record) || errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, wsaConnReset) || strings.Contains(err.Error(), "reset"):
		// A plain LDAP port answers a TLS hello with junk or by hanging up.
		if scheme == "ldaps" {
			e.Message = "The server did not answer with TLS. If it listens on port 389, use ldap:// with StartTLS instead of ldaps://."
		} else {
			e.Message = "The server did not start TLS after agreeing to StartTLS."
		}
	case strings.Contains(err.Error(), "protocol version"):
		e.Message = "The server only offers TLS older than 1.2, which Signalith does not accept. Enable TLS 1.2 or newer on the directory server."
	default:
		e.Message = fmt.Sprintf("The TLS handshake with %s failed: %v.", host, err)
	}
	return e
}

// adCodes explains the "data NNN" code Active Directory adds to a refused
// bind.
var adCodes = map[string]string{
	"525": "user not found",
	"52e": "wrong password",
	"530": "not allowed to sign in at this time",
	"531": "not allowed to sign in from this computer",
	"532": "password expired",
	"533": "account disabled",
	"701": "account expired",
	"773": "must change password first",
	"775": "account locked out",
}

var adData = regexp.MustCompile(`data ([0-9a-f]{3,4})`)

func adReason(err error) string {
	if m := adData.FindStringSubmatch(err.Error()); m != nil {
		return adCodes[m[1]]
	}
	return ""
}

// explain turns an LDAP error from a step of the conversation into words.
func explain(step, server string, err error, s *LDAPSettings) *DirectoryError {
	e := &DirectoryError{Server: server, Err: err}
	var le *ldap.Error
	if !errors.As(err, &le) || le.ResultCode >= ldap.ErrorNetwork {
		e.Code = "connect"
		e.Message = fmt.Sprintf("The connection to %s failed while talking to it: %v. Try again; if it keeps failing, check the server.", server, err)
		return e
	}
	code := le.ResultCode
	switch {
	case code == ldap.LDAPResultStrongAuthRequired || code == ldap.LDAPResultConfidentialityRequired:
		e.Code = "encryption_required"
		e.Message = "The server only accepts sign-ins over an encrypted connection. Use ldaps:// or turn on StartTLS."
		return e
	case step == "bind" && code == ldap.LDAPResultInvalidCredentials:
		e.Code = "bind_refused"
		e.Message = "The directory refused the service account's bind DN or password."
		if why := adReason(err); why != "" {
			e.Message += " Active Directory says: " + why + "."
		}
		return e
	case step == "bind" || step == "userbind":
		e.Code = "bind_failed"
		e.Message = fmt.Sprintf("Signing in to the directory failed: %s.", le.Err)
		if code == ldap.LDAPResultUnwillingToPerform {
			e.Message += " The server may require an encrypted connection: use ldaps:// or StartTLS."
		}
		return e
	}
	base, what := s.UserBaseDN, "user base DN"
	if step == "groups" {
		what = "group base DN"
		base = s.groupBase("")
	}
	switch code {
	case ldap.LDAPResultNoSuchObject:
		e.Code = "base_not_found"
		e.Message = fmt.Sprintf("The %s %s was not found. Check its spelling; it usually looks like DC=corp,DC=example,DC=com.", what, base)
	case ldap.LDAPResultInvalidDNSyntax:
		e.Code = "base_not_found"
		e.Message = fmt.Sprintf("The %s %s is not a valid DN.", what, base)
	case ldap.LDAPResultInsufficientAccessRights:
		e.Code = "search_refused"
		e.Message = fmt.Sprintf("The service account is not allowed to search %s. Give it read access there.", base)
	case ldap.LDAPResultOperationsError:
		if s.BindDN == "" {
			e.Code = "bind_required"
			e.Message = "The server does not allow anonymous searches. Enter a service account's bind DN and password."
			break
		}
		fallthrough
	default:
		e.Code = "search_failed"
		if step == "groups" {
			e.Message = fmt.Sprintf("Looking up the user's groups failed: %s.", le.Err)
			if code == ldap.LDAPResultInappropriateMatching || code == ldap.LDAPResultUnavailableCriticalExtension {
				e.Message += " Nested groups only work with Active Directory; turn them off for other servers."
			}
		} else {
			e.Message = fmt.Sprintf("Searching for the user failed: %s.", le.Err)
		}
	}
	return e
}

// ---- testing settings ----

// Step is one part of a test, passed or failed.
type Step struct {
	Step    string `json:"step"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// ServerReport is the connection test of one server.
type ServerReport struct {
	URL     string `json:"url"`
	OK      bool   `json:"ok"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
	Steps   []Step `json:"steps"`
}

// ConnectionReport is the result of TestConnection.
type ConnectionReport struct {
	OK      bool           `json:"ok"`
	Message string         `json:"message"`
	Servers []ServerReport `json:"servers"`
}

// TestConnection connects to each server, signs in as the service account
// and checks that the base DNs exist.
func TestConnection(ctx context.Context, s LDAPSettings) ConnectionReport {
	s.Normalize()
	rep := ConnectionReport{OK: true, Servers: []ServerReport{}}
	for _, u := range s.servers() {
		sr := testServer(ctx, &s, u)
		rep.Servers = append(rep.Servers, sr)
		if !sr.OK && rep.OK {
			rep.OK, rep.Message = false, sr.Message
		}
	}
	if rep.OK {
		rep.Message = "Connected and signed in as the service account."
		if s.BindDN == "" {
			rep.Message = "Connected. There is no service account, so searches are anonymous."
		}
		if len(rep.Servers) > 1 {
			rep.Message = "Both servers work. " + rep.Message
		}
	}
	return rep
}

func testServer(ctx context.Context, s *LDAPSettings, rawURL string) ServerReport {
	sr := ServerReport{URL: rawURL, Steps: []Step{}}
	failed := func(step string, err error) ServerReport {
		var de *DirectoryError
		if errors.As(err, &de) {
			sr.Code, sr.Message, sr.Detail = de.Code, de.Message, de.Detail()
		} else {
			sr.Code, sr.Message = "failed", err.Error()
		}
		sr.Steps = append(sr.Steps, Step{Step: step, Message: sr.Message})
		return sr
	}
	c, err := dial(ctx, s, rawURL)
	if err != nil {
		return failed("connect", err)
	}
	defer c.Close()
	how := "without encryption"
	if c.tls != "" {
		how = "over " + c.tls
	}
	sr.Steps = append(sr.Steps, Step{Step: "connect", OK: true, Message: fmt.Sprintf("Connected to %s %s.", strings.TrimPrefix(strings.TrimPrefix(c.server, "ldaps://"), "ldap://"), how)})
	if s.BindDN != "" {
		if err := c.bindService(s); err != nil {
			return failed("bind", err)
		}
		sr.Steps = append(sr.Steps, Step{Step: "bind", OK: true, Message: "Signed in as " + s.BindDN + "."})
	}
	bases := []struct{ step, dn string }{{"user_base", s.UserBaseDN}}
	if s.GroupBaseDN != "" && !sameDN(s.GroupBaseDN, s.UserBaseDN) {
		bases = append(bases, struct{ step, dn string }{"group_base", s.GroupBaseDN})
	}
	for _, b := range bases {
		if b.dn == "" {
			continue
		}
		_, err := c.l.Search(ldap.NewSearchRequest(b.dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, s.Timeout, false,
			"(objectClass=*)", []string{"1.1"}, nil))
		if err != nil {
			step := "search"
			if b.step == "group_base" {
				step = "groups"
			}
			return failed(b.step, explain(step, c.server, err, s))
		}
		sr.Steps = append(sr.Steps, Step{Step: b.step, OK: true, Message: "Found " + b.dn + "."})
	}
	sr.OK = true
	sr.Message = sr.Steps[0].Message
	return sr
}

// UserReport is the result of LookupUser.
type UserReport struct {
	OK bool `json:"ok"`
	// Code is "" on success, or user_not_found, multiple_matches,
	// wrong_password, no_role, or a DirectoryError code.
	Code    string         `json:"code,omitempty"`
	Message string         `json:"message"`
	Detail  string         `json:"detail,omitempty"`
	User    *DirectoryUser `json:"user,omitempty"`
	// PasswordChecked is set when a password was given and checked.
	PasswordChecked bool `json:"password_checked"`
}

// LookupUser finds a user as sign-in would and reports their entry,
// groups and role, or why they could not sign in. The password is only
// checked when one is given.
func LookupUser(ctx context.Context, s LDAPSettings, login, password string) UserReport {
	s.Normalize()
	login = LoginName(login)
	u, err := lookup(ctx, &s, login, password, false)
	rep := UserReport{User: u, PasswordChecked: password != ""}
	var se *SignInError
	var de *DirectoryError
	switch {
	case err == nil:
		rep.OK = true
		rep.Message = fmt.Sprintf("%s would sign in as %s.", u.Username, u.Role.Label())
		if len(u.Matched) == 0 {
			rep.Message = fmt.Sprintf("%s is in no mapped group, so they would sign in as Viewer.", u.Username)
		}
		if password == "" {
			rep.Message += " The password was not checked."
		}
	case errors.As(err, &de):
		rep.Code, rep.Message, rep.Detail = de.Code, de.Message, de.Detail()
	case errors.As(err, &se) && errors.Is(err, ErrPasswordExpired):
		rep.Code = "password_expired"
		rep.Message = fmt.Sprintf("The password is right, but Active Directory says: %s. %s must change it before signing in.", se.Reason, u.Username)
	case errors.As(err, &se) && errors.Is(err, ErrNoRole):
		rep.Code = "no_role"
		rep.Message = fmt.Sprintf("%s is not in any group mapped to a role, so they cannot sign in. Add one of their groups to a role, or let unmapped users in as viewers.", u.Username)
	case errors.As(err, &se) && se.Reason == errNoMatch.Error():
		rep.Code = "user_not_found"
		rep.Message = fmt.Sprintf("No user matches %q under %s. Check the user base DN and the user filter.", login, s.UserBaseDN)
		if s.Type == TypeActiveDirectory {
			rep.Message += " Disabled Active Directory accounts are skipped."
		}
	case errors.As(err, &se) && se.Reason == errManyMatches.Error():
		rep.Code = "multiple_matches"
		rep.Message = fmt.Sprintf("More than one entry matches %q, so Signalith cannot tell who it is. Make the user filter more specific.", login)
	case errors.As(err, &se) && strings.HasPrefix(se.Reason, "wrong password"):
		rep.Code = "wrong_password"
		rep.Message = "The user was found, but the directory refused the password."
		if why := strings.TrimSuffix(strings.TrimPrefix(se.Reason, "wrong password ("), ")"); why != se.Reason {
			rep.Message += " Active Directory says: " + why + "."
		}
	case errors.As(err, &se):
		rep.Code = "refused"
		rep.Message = "Sign-in would be refused: " + se.Reason + "."
	default:
		rep.Code, rep.Message = "failed", err.Error()
	}
	return rep
}
