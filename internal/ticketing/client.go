package ticketing

import (
	"bytes"
	"cmp"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/redact"
)

// Connections reach the internet or the local network, where Jira and
// ServiceNow live, through notify's client: every address is checked
// after DNS, so a connection cannot be used to reach cloud metadata
// services, Signalith's own OpenSearch, or services on the Signalith
// machine itself unless the connection allows it. Requests never follow
// redirects, are bounded in time and in the size of the answer, and every
// error is written without the connection's secrets.

// Timing and limits of one request.
const (
	// RequestTimeout bounds one request: connecting, sending and the
	// answer.
	RequestTimeout = 20 * time.Second
	// maxAnswer is the most of an answer that is read; a larger one is
	// refused rather than cut, since half a JSON document is no use.
	maxAnswer = 4 << 20
	// maxWaitInline is the longest Retry-After a request waits for before
	// trying again by itself; a longer one pauses the connection.
	maxWaitInline = 5 * time.Second
	// maxPause is the longest a Retry-After pauses a connection.
	maxPause = 15 * time.Minute
)

// Error is a request that failed, in words for people. It never holds a
// secret of the connection.
type Error struct {
	Msg string
	// Code is the HTTP status of the answer, or 0 when there was none.
	Code int
	// Retry is false when trying again cannot help as things are, such
	// as for a refused address or bad credentials.
	Retry bool
	// Until is when a system that asked Signalith to slow down (HTTP 429)
	// takes requests again.
	Until time.Time
	// Fields are the fields Jira said were wrong, such as priority.
	Fields []string
}

func (e *Error) Error() string { return e.Msg }

// errorOf returns err as an *Error, or nil.
func errorOf(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}

// retryable reports whether trying again later could help.
func retryable(err error) bool {
	if e := errorOf(err); e != nil {
		return e.Retry
	}
	return !errors.Is(err, context.Canceled)
}

// tokenCache keeps ServiceNow OAuth access tokens until they expire, so
// each request does not ask for a new one.
type tokenCache struct {
	mu     sync.Mutex
	tokens map[string]cachedToken
}

type cachedToken struct {
	value   string
	expires time.Time
	// creds are the credentials the token was issued for: a token is
	// only used while the connection still has them.
	creds string
}

func (t *tokenCache) get(key, creds string, now time.Time) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if tok, ok := t.tokens[key]; ok && now.Before(tok.expires) && sameCreds(tok.creds, creds) {
		return tok.value
	}
	return ""
}

func (t *tokenCache) put(key, creds, value string, expires time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.tokens == nil {
		t.tokens = map[string]cachedToken{}
	}
	t.tokens[key] = cachedToken{value: value, expires: expires, creds: creds}
}

// sameCreds compares two credential strings in constant time.
func sameCreds(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (t *tokenCache) drop(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.tokens, key)
}

// all returns the tokens in the cache for a connection, for scrub.
func (t *tokenCache) all(prefix string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for k, v := range t.tokens {
		if strings.HasPrefix(k, prefix) {
			out = append(out, v.value)
		}
	}
	return out
}

// client calls one connection's API.
type client struct {
	conn      Connection
	base      *url.URL
	http      *http.Client
	protected notify.Protected
	tokens    *tokenCache
	// quirks remembers what a connection's system refused, such as a
	// field that cannot be set, by connection ID and quirk.
	quirks *sync.Map
	// selves remembers the account each connection signs in as, by
	// selfKey.
	selves *sync.Map
	now    func() time.Time
	sleep  func(context.Context, time.Duration) error
}

// newClient returns the client of a connection.
func (s *Service) newClient(c Connection) (*client, error) {
	if bad := c.Undecrypted(); len(bad) > 0 {
		return nil, &Error{Msg: fmt.Sprintf("The connection's saved %s cannot be decrypted (the master key changed). Edit the connection on the Ticketing page and enter it again.", strings.Join(bad, " and "))}
	}
	if msg := CheckURL(c.URL, c.AllowLoopback); msg != "" {
		return nil, &Error{Msg: sentence(msg)}
	}
	base, err := url.Parse(strings.TrimRight(c.URL, "/"))
	if err != nil {
		return nil, &Error{Msg: "The connection's address is not valid. Edit the connection and enter it again."}
	}
	hc, err := notify.NewClient(notify.ClientOptions{AllowLoopback: c.AllowLoopback, CAPEM: c.CAPEM, Protected: s.Protected, Timeout: RequestTimeout})
	if err != nil {
		return nil, &Error{Msg: "The connection's certificate authority is not a PEM certificate. Edit the connection and paste it again."}
	}
	return &client{conn: c, base: base, http: hc, protected: s.Protected, tokens: &s.tokens, quirks: &s.quirks, selves: &s.selves, now: s.now, sleep: s.sleepFunc()}, nil
}

// system names the connection's system for people.
func (cl *client) system() string { return TypeLabel(cl.conn.Type) }

// cacheKey is a connection's key in the token and account caches.
func (cl *client) cacheKey() string { return cl.conn.ID + ":" }

// tokenCreds are what a connection's OAuth token was issued for: a new
// client secret or address asks for a new token.
func (cl *client) tokenCreds() string {
	return cl.conn.URL + "\x00" + cl.conn.ClientID + "\x00" + cl.conn.ClientSecret
}

// selfCreds are what decide the account a connection signs in as: new
// credentials or a new address may be another account.
func (cl *client) selfCreds() string {
	c := cl.conn
	return strings.Join([]string{c.URL, c.Auth, c.Email, c.Token, c.Username, c.Password, c.ClientID, c.ClientSecret}, "\x00")
}

// request is one API call.
type request struct {
	method string
	path   string // after the base URL, starting with /
	query  url.Values
	body   any // marshalled as JSON when not nil
	form   url.Values
	out    any // the JSON answer is decoded into it when not nil
	// noAuth sends no Authorization header (the OAuth token request
	// carries the client's credentials in its body).
	noAuth bool
}

// do sends r. Its error is always an *Error, or the context's.
func (cl *client) do(ctx context.Context, r request) error {
	for attempt := 0; ; attempt++ {
		err := cl.once(ctx, r)
		e := errorOf(err)
		if e == nil {
			return err
		}
		switch {
		case e.Code == http.StatusUnauthorized && cl.conn.Type == TypeServiceNow && cl.conn.Auth == AuthOAuth && !r.noAuth && attempt == 0:
			// The token may have been revoked or expired early: ask for a
			// new one, once.
			cl.tokens.drop(cl.cacheKey())
			continue
		case !e.Until.IsZero() && attempt < 2:
			wait := e.Until.Sub(cl.now())
			if wait > maxWaitInline {
				return err
			}
			if err := cl.sleep(ctx, max(wait, 0)); err != nil {
				return err
			}
			continue
		}
		return err
	}
}

// once sends r one time.
func (cl *client) once(ctx context.Context, r request) error {
	u := *cl.base
	u.Path = strings.TrimRight(cl.base.Path, "/") + r.path
	u.RawPath = ""
	if r.query != nil {
		u.RawQuery = r.query.Encode()
	}
	if err := cl.protected.Check(&u, cl.conn.AllowLoopback); err != nil {
		return &Error{Msg: blockedText(err)}
	}
	var body io.Reader
	contentType := ""
	switch {
	case r.body != nil:
		raw, err := json.Marshal(r.body)
		if err != nil {
			return &Error{Msg: "Could not write the request: " + err.Error()}
		}
		body, contentType = bytes.NewReader(raw), "application/json"
	case r.form != nil:
		body, contentType = strings.NewReader(r.form.Encode()), "application/x-www-form-urlencoded"
	}
	// Within a pass, the request also ends with the connection's share of
	// it (passTimeout).
	end := passDeadline(ctx, cl.conn.ID)
	if !end.IsZero() && !time.Now().Before(end) {
		return cl.overTime()
	}
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	if !end.IsZero() {
		var cancelPass context.CancelFunc
		ctx, cancelPass = context.WithDeadline(ctx, end)
		defer cancelPass()
	}
	req, err := http.NewRequestWithContext(ctx, r.method, u.String(), body)
	if err != nil {
		return &Error{Msg: "The connection's address is not valid. Edit the connection and enter it again."}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Signalith")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if cl.conn.Type == TypeJira {
		// Jira refuses writes without it from clients it takes for
		// browsers (XSRF check); an API client says it is not one.
		req.Header.Set("X-Atlassian-Token", "no-check")
	}
	if !r.noAuth {
		if err := cl.authorize(ctx, req); err != nil {
			return err
		}
	}
	resp, err := cl.http.Do(req)
	if err != nil {
		if !end.IsZero() && !time.Now().Before(end) {
			return cl.overTime()
		}
		return cl.fail(err)
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		if !end.IsZero() && !time.Now().Before(end) {
			return cl.overTime()
		}
		return cl.fail(err)
	}
	if len(answer) > maxAnswer {
		return &Error{Msg: fmt.Sprintf("%s's answer was larger than %d MB, more than Signalith reads.", cl.system(), maxAnswer>>20), Retry: true}
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return &Error{Msg: fmt.Sprintf("%s redirected the request (HTTP %d) and Signalith does not follow redirects. Check the address: use the site's own address, with https://.", cl.system(), resp.StatusCode), Code: resp.StatusCode}
	}
	if resp.StatusCode >= 400 {
		return cl.answerError(resp, answer)
	}
	if r.out == nil || len(bytes.TrimSpace(answer)) == 0 {
		return nil
	}
	if err := json.Unmarshal(answer, r.out); err != nil {
		return &Error{Msg: fmt.Sprintf("%s's answer could not be read (%v). Check that the address is the site itself, not a sign-in page or proxy.", cl.system(), err), Retry: true}
	}
	return nil
}

// overTime is a request not sent, or cut off, because the connection
// used up its share of a pass.
func (cl *client) overTime() error {
	return &Error{Msg: fmt.Sprintf("%s took longer than one sync pass allows (%d minutes); the rest waits for the next pass.", cl.system(), int(passTimeout.Minutes())), Retry: true}
}

// authorize sets the request's Authorization header.
func (cl *client) authorize(ctx context.Context, req *http.Request) error {
	c := cl.conn
	switch c.Auth {
	case AuthCloud:
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Email+":"+c.Token)))
	case AuthBearer:
		req.Header.Set("Authorization", "Bearer "+c.Token)
	case AuthBasic:
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password)))
	case AuthOAuth:
		tok, err := cl.oauthToken(ctx)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	default:
		return &Error{Msg: "The connection has no way of signing in. Edit it on the Ticketing page."}
	}
	return nil
}

// oauthToken returns an access token from ServiceNow's OAuth endpoint,
// with the client credentials grant.
func (cl *client) oauthToken(ctx context.Context) (string, error) {
	key, creds := cl.cacheKey(), cl.tokenCreds()
	if tok := cl.tokens.get(key, creds, cl.now()); tok != "" {
		return tok, nil
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {cl.conn.ClientID}, "client_secret": {cl.conn.ClientSecret}}
	if err := cl.once(ctx, request{method: http.MethodPost, path: "/oauth_token.do", form: form, out: &out, noAuth: true}); err != nil {
		if e := errorOf(err); e != nil && (e.Code == http.StatusUnauthorized || e.Code == http.StatusBadRequest) {
			return "", &Error{Msg: "ServiceNow refused the OAuth client ID and secret. Check them, and that the application allows the client credentials grant (glide.oauth.inbound.client.credential.grant_type.enabled).", Code: e.Code}
		}
		return "", err
	}
	if out.AccessToken == "" {
		return "", &Error{Msg: "ServiceNow's OAuth endpoint answered without an access token. Check the OAuth application.", Retry: true}
	}
	life := time.Duration(out.ExpiresIn) * time.Second
	if life <= 0 || life > 24*time.Hour {
		life = 30 * time.Minute
	}
	// Renewed a minute early, so a token never expires on the way.
	cl.tokens.put(key, creds, out.AccessToken, cl.now().Add(life-min(time.Minute, life/2)))
	return out.AccessToken, nil
}

// answerError turns an error answer into an *Error.
func (cl *client) answerError(resp *http.Response, answer []byte) error {
	// The answer is scrubbed before it is cut and quoted, so a secret it
	// echoes is hidden whole, whatever characters it holds.
	said, fields := apiMessage(answer, cl.scrub)
	e := &Error{Code: resp.StatusCode, Fields: fields}
	msg := fmt.Sprintf("%s answered %s.", cl.system(), resp.Status)
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		switch cl.conn.Auth {
		case AuthCloud:
			msg += " Check the email address and API token (Atlassian account settings, Security, API tokens)."
		case AuthBearer:
			msg += " Check the personal access token, and that it has not expired."
		case AuthOAuth:
			msg += " Check the OAuth client ID and secret."
		default:
			msg += " Check the user name and password."
		}
	case resp.StatusCode == http.StatusForbidden:
		msg += " The account Signalith signs in as is not allowed to do this; check its permissions."
	case resp.StatusCode == http.StatusNotFound:
		msg += " Check the address, and that the project, table or ticket still exists and the account can see it."
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get("Retry-After") != "":
		e.Until = cl.now().Add(retryAfter(resp.Header.Get("Retry-After"), cl.now()))
		e.Retry = true
		msg += " It limits how often it takes requests; Signalith waits and tries again."
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500:
		e.Retry = true
		msg += fmt.Sprintf(" %s has a problem; Signalith tries again later.", cl.system())
	}
	if said != "" && !strings.EqualFold(said, http.StatusText(resp.StatusCode)) {
		msg += fmt.Sprintf(" It said: %q", said)
	}
	e.Msg = cl.scrub(msg)
	return e
}

// retryAfter reads a Retry-After header, in seconds or as a date. It is
// at least a second and at most maxPause; one that cannot be read is a
// minute.
func retryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	d := time.Minute
	if n, err := strconv.Atoi(v); err == nil {
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	return min(max(d, time.Second), maxPause)
}

// apiMessage reads the message of a Jira or ServiceNow error answer:
// Jira's {"errorMessages": [...], "errors": {"field": "message"}} and
// ServiceNow's {"error": {"message": "...", "detail": "..."}}. It
// returns the message as one line, and the fields Jira named. An answer
// that is not one of those gives its start, when it is text. scrub, when
// not nil, hides secrets in the message before it is cut.
func apiMessage(b []byte, scrub func(string) string) (string, []string) {
	if scrub == nil {
		scrub = func(s string) string { return s }
	}
	var v struct {
		ErrorMessages []string          `json:"errorMessages"`
		Errors        map[string]string `json:"errors"`
		Error         json.RawMessage   `json:"error"`
		Message       string            `json:"message"`
	}
	if err := json.Unmarshal(b, &v); err == nil {
		var parts []string
		var fields []string
		parts = append(parts, v.ErrorMessages...)
		for _, k := range sortedKeys(v.Errors) {
			fields = append(fields, k)
			parts = append(parts, k+": "+v.Errors[k])
		}
		if len(v.Error) > 0 {
			var sn struct {
				Message string `json:"message"`
				Detail  string `json:"detail"`
			}
			if json.Unmarshal(v.Error, &sn) == nil {
				if sn.Message != "" {
					parts = append(parts, sn.Message)
				}
				if sn.Detail != "" && sn.Detail != sn.Message {
					parts = append(parts, sn.Detail)
				}
			} else {
				var s string
				if json.Unmarshal(v.Error, &s) == nil && s != "" {
					parts = append(parts, s)
				}
			}
		}
		if v.Message != "" {
			parts = append(parts, v.Message)
		}
		if len(parts) > 0 {
			return clean(scrub(strings.Join(parts, "; ")), 300), fields
		}
	}
	if !utf8.Valid(b) {
		return "", nil
	}
	s := strings.TrimSpace(string(b))
	if strings.HasPrefix(s, "<") {
		// An HTML error page says nothing a person needs here.
		return "", nil
	}
	return clean(scrub(s), 200), nil
}

// fail describes a request that got no answer.
func (cl *client) fail(err error) error {
	sys := cl.system()
	var msg string
	retry := true
	var be *notify.BlockedError
	var dnsErr *net.DNSError
	var ne net.Error
	switch {
	case errors.As(err, &be):
		msg, retry = blockedText(be), false
	case errors.Is(err, context.Canceled):
		return err
	case errors.Is(err, context.DeadlineExceeded):
		msg = fmt.Sprintf("%s did not answer within %d seconds. Check that this Signalith server can reach it: firewalls must allow it, and a proxy is set with HTTPS_PROXY.", sys, int(RequestTimeout.Seconds()))
	case errors.As(err, &dnsErr):
		if dnsErr.IsNotFound {
			msg = fmt.Sprintf("Could not find the server %s. Check the address, and that this Signalith server can look up names (DNS).", dnsErr.Name)
		} else {
			msg = fmt.Sprintf("Could not look up the server %s (DNS). Check this Signalith server's network settings.", dnsErr.Name)
		}
	case errors.As(err, &ne) && ne.Timeout():
		msg = fmt.Sprintf("%s did not answer in time. Check that this Signalith server can reach it: firewalls must allow it, and a proxy is set with HTTPS_PROXY.", sys)
	case errors.Is(err, syscall.ECONNREFUSED):
		msg = fmt.Sprintf("%s refused the connection. Check the address and port.", sys)
	default:
		if t := describeTLS(err, sys); t != "" {
			msg, retry = t, false
			break
		}
		// Drop the URL the HTTP client puts in its errors.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		msg = fmt.Sprintf("Could not reach %s: %v", sys, err)
	}
	return &Error{Msg: cl.scrub(msg), Retry: retry}
}

// describeTLS explains a certificate problem, or returns "".
func describeTLS(err error, sys string) string {
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	var rh tls.RecordHeaderError
	switch {
	case errors.As(err, &ua):
		return sys + "'s certificate is not from a trusted authority. For a private certificate authority, paste its certificate into the connection; if your network inspects HTTPS, add its certificate to this server's trusted certificates."
	case errors.As(err, &hn):
		return sys + "'s certificate is for another name. Check the address."
	case errors.As(err, &ci):
		return sys + "'s certificate is not valid (" + ci.Error() + ")."
	case errors.As(err, &rh):
		return sys + " did not answer with TLS. Check the address and port."
	}
	return ""
}

// secretValues returns a connection's secrets, and the forms they take
// on the wire, for scrub.
func (cl *client) secretValues() []string {
	c := cl.conn
	out := []string{c.Token, c.Password, c.ClientSecret}
	if c.Token != "" && c.Email != "" {
		out = append(out, base64.StdEncoding.EncodeToString([]byte(c.Email+":"+c.Token)))
	}
	if c.Password != "" {
		out = append(out, base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password)))
	}
	if cl.tokens != nil {
		out = append(out, cl.tokens.all(c.ID+":")...)
	}
	return out
}

// scrub hides the connection's secrets in a message.
func (cl *client) scrub(msg string) string { return scrubValues(msg, cl.secretValues()) }

// scrubValues hides each of values in msg: as it is, and as Go quotes it
// (%q) and JSON escapes it, the forms an error may carry it in. The
// longest are hidden first, so one form never leaves part of another.
func scrubValues(msg string, values []string) string {
	var forms []string
	for _, s := range values {
		if len(s) < 4 {
			continue
		}
		forms = append(forms, s, strings.Trim(strconv.Quote(s), `"`))
		if j, err := json.Marshal(s); err == nil {
			forms = append(forms, strings.Trim(string(j), `"`))
		}
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if enc.Encode(s) == nil {
			forms = append(forms, strings.Trim(strings.TrimSpace(b.String()), `"`))
		}
	}
	slices.SortFunc(forms, func(a, b string) int { return cmp.Or(len(b)-len(a), strings.Compare(a, b)) })
	for _, f := range slices.Compact(forms) {
		if len(f) >= 4 {
			msg = strings.ReplaceAll(msg, f, redact.Mask)
		}
	}
	return msg
}

// Scrub hides a connection's secrets in a message, for errors that did not
// come from its client.
func Scrub(msg string, c Connection) string {
	cl := &client{conn: c}
	return cl.scrub(msg)
}

// sentence starts s with a capital letter and ends it with a period.
func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	s = strings.ToUpper(s[:1]) + s[1:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

// clean makes s one line of at most n characters, without control
// characters.
func clean(s string, n int) string {
	s = strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' || r == '\t' }), " ")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > n {
		r := []rune(s)
		s = string(r[:n-1]) + "…"
	}
	return s
}
