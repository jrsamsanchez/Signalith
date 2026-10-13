package respond

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// Action kinds.
const (
	// KindDisableUser disables (or enables) a directory account, with the
	// directory settings of the Users page.
	KindDisableUser = "disable_user"
	// KindHTTP sends one HTTP request: a firewall's API, a SOAR webhook.
	KindHTTP = "http"
	// KindScript runs a program from the scripts folder on this server.
	KindScript = "script"
)

// Kinds lists the action kinds.
var Kinds = []string{KindDisableUser, KindHTTP, KindScript}

// Operations of a disable_user action.
const (
	OpDisable = "disable"
	OpEnable  = "enable"
)

// Script timeouts.
const (
	DefaultScriptTimeout = 60  // seconds
	MaxScriptTimeout     = 600 // seconds
)

// HTTPTimeout bounds one request of an HTTP action, connection included.
const HTTPTimeout = 10 // seconds

// Connector is one response action an admin set up, as kept in the
// response actions file. Its kind decides which settings it uses.
type Connector struct {
	// Name identifies it: lower case letters, digits, - and _.
	Name string `yaml:"name" json:"name"`
	// Label is what analysts pick in the Respond menu, such as "Block IP
	// on the edge firewall".
	Label       string `yaml:"label" json:"label"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Kind        string `yaml:"kind" json:"kind"`
	// Target is the kind of value it acts on: ip, domain, user, host or
	// any.
	Target string `yaml:"target" json:"target"`
	// Disruptive actions ask for a reason. Defaults to true, except for
	// enabling an account.
	Disruptive *bool `yaml:"disruptive,omitempty" json:"disruptive"`
	// Enabled offers it in the Respond menu. Defaults to true.
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled"`

	// http: the request.
	Method string `yaml:"method,omitempty" json:"method,omitempty"`
	URL    string `yaml:"url,omitempty" json:"url,omitempty"`
	// Headers are sent with the request; their values are secret.
	Headers map[string]string `yaml:"headers,omitempty" json:"-"`
	// Username and Password sign in with HTTP Basic auth; the password is
	// secret.
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"-"`
	// Body is a template; BodyFormat is json (the default), form or text.
	Body       string `yaml:"body,omitempty" json:"body,omitempty"`
	BodyFormat string `yaml:"body_format,omitempty" json:"body_format,omitempty"`
	// CACert is the PEM certificate of the CA that signed the server's
	// certificate, when the system does not already trust it.
	CACert string `yaml:"ca_cert,omitempty" json:"ca_cert,omitempty"`
	// AllowLoopback lets the request reach this server's own addresses
	// (127.0.0.1, ::1). Link-local and cloud metadata addresses are always
	// refused.
	AllowLoopback bool `yaml:"allow_loopback,omitempty" json:"allow_loopback,omitempty"`

	// script: the program, relative to the scripts folder, and how long
	// it may run.
	Program        string `yaml:"program,omitempty" json:"program,omitempty"`
	TimeoutSeconds int    `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`

	// disable_user: disable or enable, the account that makes the change
	// (empty: the directory's service account) and, for directories other
	// than Active Directory, the attribute and value that switch an
	// account off.
	Operation        string `yaml:"operation,omitempty" json:"operation,omitempty"`
	BindDN           string `yaml:"bind_dn,omitempty" json:"bind_dn,omitempty"`
	BindPassword     string `yaml:"bind_password,omitempty" json:"-"`
	DisableAttribute string `yaml:"disable_attribute,omitempty" json:"disable_attribute,omitempty"`
	DisableValue     string `yaml:"disable_value,omitempty" json:"disable_value,omitempty"`
}

// IsDisruptive reports whether a run needs a reason.
func (c *Connector) IsDisruptive() bool {
	if c.Disruptive != nil {
		return *c.Disruptive
	}
	return !(c.Kind == KindDisableUser && c.Operation == OpEnable)
}

// IsEnabled reports whether analysts may run it.
func (c *Connector) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }

// Clone returns a deep copy.
func (c Connector) Clone() Connector {
	out := c
	if c.Disruptive != nil {
		v := *c.Disruptive
		out.Disruptive = &v
	}
	if c.Enabled != nil {
		v := *c.Enabled
		out.Enabled = &v
	}
	if c.Headers != nil {
		out.Headers = make(map[string]string, len(c.Headers))
		for k, v := range c.Headers {
			out.Headers[k] = v
		}
	}
	return out
}

// Normalize trims values and fills defaults.
func (c *Connector) Normalize() {
	for _, p := range []*string{&c.Name, &c.Label, &c.Description, &c.Kind, &c.Target, &c.Method, &c.URL, &c.Username,
		&c.BodyFormat, &c.Program, &c.Operation, &c.BindDN, &c.DisableAttribute, &c.DisableValue} {
		*p = strings.TrimSpace(*p)
	}
	c.Name = strings.ToLower(c.Name)
	c.Kind = strings.ToLower(c.Kind)
	c.Target = strings.ToLower(c.Target)
	c.CACert = strings.TrimSpace(c.CACert)
	if c.CACert != "" {
		c.CACert += "\n"
	}
	if c.Label == "" {
		c.Label = c.Name
	}
	switch c.Kind {
	case KindHTTP:
		c.Method = strings.ToUpper(c.Method)
		if c.Method == "" {
			c.Method = http.MethodPost
		}
		c.BodyFormat = strings.ToLower(c.BodyFormat)
		if c.BodyFormat == "" {
			c.BodyFormat = BodyJSON
		}
	case KindScript:
		// Either slash separates folders, on every system.
		c.Program = strings.ReplaceAll(c.Program, `\`, "/")
		if c.TimeoutSeconds == 0 {
			c.TimeoutSeconds = DefaultScriptTimeout
		}
	case KindDisableUser:
		c.Operation = strings.ToLower(c.Operation)
		if c.Operation == "" {
			c.Operation = OpDisable
		}
		if c.Target == "" {
			c.Target = TargetUser
		}
	}
	clean := map[string]string{}
	for k, v := range c.Headers {
		if k = strings.TrimSpace(k); k != "" {
			clean[http.CanonicalHeaderKey(k)] = v
		}
	}
	c.Headers = clean
	if len(c.Headers) == 0 {
		c.Headers = nil
	}
}

// Problem is one setting of an action that needs fixing. Field is the
// setting's key.
type Problem struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

var (
	namePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	headerPattern = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$")
	attrPattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,99}$`)
)

// headers Signalith sets itself.
var reservedHeaders = []string{"Host", "Content-Length", "Content-Type", "Transfer-Encoding", "Connection"}

// Problems lists every setting that needs fixing.
func (c *Connector) Problems() []Problem {
	var p []Problem
	add := func(field, format string, args ...any) {
		p = append(p, Problem{Field: field, Message: fmt.Sprintf(format, args...)})
	}
	if !namePattern.MatchString(c.Name) {
		add("name", "the name must be 1-63 lower case letters, digits, - or _, starting with a letter or digit, like block-ip")
	}
	if len(c.Label) > 100 {
		add("label", "the label must be at most 100 characters")
	}
	if len(c.Description) > 500 {
		add("description", "the description must be at most 500 characters")
	}
	if !slices.Contains(append(slices.Clone(TargetKinds), TargetAny), c.Target) {
		add("target", "choose what it acts on: ip, domain, user, host or any")
	}
	for _, s := range []struct{ field, v string }{{"password", c.Password}, {"bind_password", c.BindPassword}} {
		if secrets.IsSealed(s.v) {
			add(s.field, "the password cannot start with enc:v and a number and a colon, which is how encrypted values look")
		}
	}
	switch c.Kind {
	case KindHTTP:
		c.httpProblems(add)
	case KindScript:
		c.scriptProblems(add)
	case KindDisableUser:
		if c.Operation != OpDisable && c.Operation != OpEnable {
			add("operation", "choose disable or enable")
		}
		if c.Target != TargetUser {
			add("target", "disabling an account acts on a user")
		}
		if c.BindDN != "" {
			if _, err := ldap.ParseDN(c.BindDN); err != nil {
				add("bind_dn", "%q is not a DN like CN=svc-respond,OU=Service Accounts,DC=corp,DC=example,DC=com", c.BindDN)
			} else if c.BindPassword == "" {
				add("bind_password", "enter the password of %s", c.BindDN)
			}
		}
		if c.DisableAttribute != "" && !attrPattern.MatchString(c.DisableAttribute) {
			add("disable_attribute", "%q is not an attribute name", c.DisableAttribute)
		}
		if len(c.DisableValue) > 200 {
			add("disable_value", "the value must be at most 200 characters")
		}
	default:
		add("kind", "choose disable_user, http or script")
	}
	return p
}

func (c *Connector) httpProblems(add func(field, format string, args ...any)) {
	switch c.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		add("method", "the method must be GET, POST, PUT, PATCH or DELETE")
	}
	if c.URL == "" {
		add("url", "enter the URL to send the request to")
	} else if len(c.URL) > 2000 {
		add("url", "the URL must be at most 2000 characters")
	} else if err := checkURLTemplate(c.URL); err != nil {
		add("url", "%v", err)
	}
	if _, ok := bodyContentType[c.BodyFormat]; !ok {
		add("body_format", "the body format must be json, form or text")
	}
	if len(c.Body) > 16<<10 {
		add("body", "the body must be at most 16 KB")
	} else if err := checkTemplate(c.Body); err != nil {
		add("body", "%v", err)
	} else if c.BodyFormat == BodyJSON && strings.TrimSpace(c.Body) != "" && !jsonValid(expandBody(c.Body, BodyJSON, sampleValues)) {
		add("body", "the body is not valid JSON once placeholders are filled in; put placeholders between quotes, like \"{{.ip}}\"")
	}
	if strings.TrimSpace(c.Body) != "" && c.Method == http.MethodGet {
		add("body", "a GET request has no body; use POST, or put the values in the URL")
	}
	if !usesAnyTarget(c.URL + c.Body) {
		add("url", "use the target in the URL or the body, such as {{.%s}}", placeholderFor(c.Target))
	}
	if len(c.Headers) > 20 {
		add("headers", "at most 20 headers")
	}
	for k, v := range c.Headers {
		if !headerPattern.MatchString(k) {
			add("headers", "%q is not a header name", k)
		}
		if slices.Contains(reservedHeaders, k) {
			add("headers", "Signalith sets %s itself", k)
		}
		// An Authorization header carries a token ("Bearer ..."); Basic
		// sign-in uses the user name and password fields, never both.
		if k == "Authorization" && c.Username != "" {
			add("headers", "use either an Authorization header or a user name and password, not both")
		}
		if strings.ContainsAny(v, "\r\n") || len(v) > 8000 {
			add("headers", "the value of %s must be one line of at most 8000 characters", k)
		}
	}
	if len(c.Username) > 200 || strings.ContainsAny(c.Username, ":\r\n") {
		add("username", "the user name must be one line without a colon")
	}
	if c.Password != "" && c.Username == "" {
		add("username", "enter the user name the password is for")
	}
	if c.CACert != "" {
		if msg := checkPEM(c.CACert); msg != "" {
			add("ca_cert", "%s", msg)
		}
	}
}

func (c *Connector) scriptProblems(add func(field, format string, args ...any)) {
	if c.Program == "" {
		add("program", "enter the program's file name in the scripts folder, like isolate-host.ps1")
	} else if len(c.Program) > 500 {
		add("program", "the program's name must be at most 500 characters")
	} else if filepath.IsAbs(c.Program) || strings.HasPrefix(filepath.ToSlash(c.Program), "/") || filepath.VolumeName(c.Program) != "" || strings.Contains(c.Program, ":") {
		add("program", "give the program's name relative to the scripts folder, like isolate-host.ps1")
	} else if slices.Contains(strings.Split(filepath.ToSlash(c.Program), "/"), "..") {
		add("program", "the program must be inside the scripts folder; .. is not allowed")
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > MaxScriptTimeout {
		add("timeout_seconds", "the timeout must be 1-%d seconds", MaxScriptTimeout)
	}
}

func usesAnyTarget(text string) bool {
	for _, p := range []string{"target", TargetIP, TargetDomain, TargetUser, TargetHost} {
		if usesPlaceholder(text, p) {
			return true
		}
	}
	return false
}

func placeholderFor(kind string) string {
	if slices.Contains(TargetKinds, kind) {
		return kind
	}
	return "target"
}

func jsonValid(s string) bool {
	return json.Valid([]byte(s))
}

// checkPEM reports what is wrong with a CA certificate, or "".
func checkPEM(text string) string {
	rest := []byte(text)
	n := 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return fmt.Sprintf("the CA certificate holds a %s; paste only certificates", strings.ToLower(b.Type))
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return "the CA certificate could not be read: " + err.Error()
		}
		n++
	}
	if n == 0 {
		return "paste the CA certificate in PEM form, starting with -----BEGIN CERTIFICATE-----"
	}
	return ""
}

// origin returns the scheme, host and port an HTTP action sends to, in
// lower case, for deciding whether a saved secret may go with a changed
// URL.
func origin(rawURL string) string {
	o, _, err := splitURLTemplate(rawURL)
	if err != nil {
		return ""
	}
	u, err := url.Parse(o)
	if err != nil {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[strings.ToLower(u.Scheme)]
	}
	return strings.ToLower(u.Scheme + "://" + u.Hostname() + ":" + port)
}

// secretNames lists the secret settings of c that hold a value, as
// FileField parts: password, bind_password, headers.<name>; headers in
// name order.
func (c *Connector) secretNames() []string {
	var out []string
	if c.Password != "" {
		out = append(out, "password")
	}
	if c.BindPassword != "" {
		out = append(out, "bind_password")
	}
	names := make([]string, 0, len(c.Headers))
	for k, v := range c.Headers {
		if v != "" {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	for _, k := range names {
		out = append(out, "headers."+k)
	}
	return out
}

// secretValues returns c's secret values, to hide them in output.
func (c *Connector) secretValues() []string {
	var out []string
	for _, v := range []string{c.Password, c.BindPassword} {
		if v != "" {
			out = append(out, v)
		}
	}
	for _, v := range c.Headers {
		if v != "" {
			out = append(out, v)
			// A bearer token is often echoed without its scheme.
			if _, tok, ok := strings.Cut(v, " "); ok && len(tok) >= 6 {
				out = append(out, tok)
			}
		}
	}
	return out
}

// eachSecret replaces every secret of c with what fn returns for it. part
// names the secret as FileField does, label for people.
func (c *Connector) eachSecret(fn func(part, label, v string) (string, error)) error {
	for _, part := range c.secretNames() {
		var p *string
		label := part
		switch {
		case part == "password":
			p = &c.Password
		case part == "bind_password":
			p, label = &c.BindPassword, "bind password"
		default:
			name := strings.TrimPrefix(part, "headers.")
			v := c.Headers[name]
			nv, err := fn(part, "header "+name, v)
			if err != nil {
				return err
			}
			c.Headers[name] = nv
			continue
		}
		nv, err := fn(part, label, *p)
		if err != nil {
			return err
		}
		*p = nv
	}
	return nil
}
