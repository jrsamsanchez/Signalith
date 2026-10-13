package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/redact"
)

// Sender sends a message through a channel.
type Sender interface {
	Send(ctx context.Context, c Channel, m Message) error
}

// Senders sends through every kind of channel, over the network.
type Senders struct {
	// Protected are services channels must never reach, such as
	// Signalith's own OpenSearch, as host:port.
	Protected Protected
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Hostname is the name this server gives mail servers (EHLO); ""
	// is localhost.
	Hostname string
}

func (s *Senders) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// SignatureHeader carries a webhook body's signature when the channel has
// a signing secret: sha256= and the hex HMAC-SHA256 of the body.
const SignatureHeader = "X-Signalith-Signature"

// Sign returns the SignatureHeader value of body for secret.
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Send sends m through c. Its error is written for people and never
// holds the channel's URL or another of its secrets.
func (s *Senders) Send(ctx context.Context, c Channel, m Message) error {
	if bad := c.Undecrypted(); len(bad) > 0 {
		return &SendError{Msg: fmt.Sprintf("The channel's saved %s cannot be decrypted (the master key changed). Edit the channel and enter it again.", joinAnd(bad))}
	}
	var err error
	switch c.Type {
	case TypeEmail:
		err = s.sendMail(ctx, c, m)
	case TypeSlack:
		err = s.post(ctx, c, m.slackBody(c.Label()))
	case TypeTeams:
		err = s.post(ctx, c, m.teamsBody(c.Label()))
	case TypeWebhook:
		err = s.post(ctx, c, m.webhookBody(s.now()))
	default:
		err = &SendError{Msg: fmt.Sprintf("Signalith cannot send to a channel of type %q.", c.Type)}
	}
	if err == nil {
		return nil
	}
	return &SendError{Msg: scrub(describe(err, c), c), Retry: retryable(err)}
}

// SendError is a message that could not be sent, in words for people.
type SendError struct {
	Msg string
	// Retry is false when trying again cannot help as things are, such
	// as for an address channels may not reach.
	Retry bool
}

func (e *SendError) Error() string { return e.Msg }

// AnswerError is a receiver that answered with an error status.
type AnswerError struct {
	Code   int
	Status string
	// Said is a short message from the receiver's answer, if it sent one.
	Said string
}

func (e *AnswerError) Error() string { return "the receiver answered " + e.Status }

// post sends body as JSON to the channel's URL.
func (s *Senders) post(ctx context.Context, c Channel, body any) error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errBadURL
	}
	if err := s.Protected.check(u, c.AllowLoopback); err != nil {
		return err
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	client, err := httpClient(c, s.Protected)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, SendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(raw))
	if err != nil {
		return errBadURL
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Signalith")
	if c.Type == TypeWebhook {
		for k, v := range c.Headers {
			req.Header.Set(k, v)
		}
		if c.SigningSecret != "" {
			req.Header.Set(SignatureHeader, Sign(c.SigningSecret, raw))
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return &AnswerError{Code: resp.StatusCode, Status: resp.Status, Said: said(answer)}
}

var errBadURL = errors.New("the channel's URL is not valid; edit the channel and enter it again")

// said returns the start of a receiver's answer, as one line of text, or
// "" when it is not text.
func said(b []byte) string {
	if !utf8.Valid(b) {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if strings.HasPrefix(s, "<") {
		// An HTML error page says nothing a person needs here.
		return ""
	}
	return clean(s, 200)
}

// retryable reports whether trying again later could help.
func retryable(err error) bool {
	var be *BlockedError
	if errors.As(err, &be) || errors.Is(err, errBadURL) || errors.Is(err, errRedirect) {
		return false
	}
	var ae *AnswerError
	if errors.As(err, &ae) {
		return ae.Code == http.StatusTooManyRequests || ae.Code == http.StatusRequestTimeout || ae.Code >= 500
	}
	var me *mailError
	if errors.As(err, &me) {
		return me.retry
	}
	return true
}

// describe turns a send error into plain words.
func describe(err error, c Channel) string {
	var se *SendError
	if errors.As(err, &se) {
		return se.Msg
	}
	var me *mailError
	if errors.As(err, &me) {
		return me.msg
	}
	var ae *AnswerError
	if errors.As(err, &ae) {
		return describeAnswer(ae, c)
	}
	var be *BlockedError
	if errors.As(err, &be) {
		return be.Error()
	}
	switch {
	case errors.Is(err, errBadURL), errors.Is(err, errRedirect):
		return sentence(err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Sprintf("The receiver did not answer within %d seconds. Check that this Signalith server can reach it: firewalls must allow it, and a proxy is set with HTTPS_PROXY.", int(SendTimeout.Seconds()))
	case errors.Is(err, context.Canceled):
		return "Sending was canceled."
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return fmt.Sprintf("Could not find the server %s. Check the address, and that this Signalith server can look up names (DNS).", dnsErr.Name)
		}
		return fmt.Sprintf("Could not look up the server %s (DNS). Check this Signalith server's network settings.", dnsErr.Name)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "The receiver did not answer in time. Check that this Signalith server can reach it: firewalls must allow it, and a proxy is set with HTTPS_PROXY."
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "The receiver refused the connection. Check the address and port."
	}
	if msg := describeTLS(err); msg != "" {
		return msg
	}
	// Drop the URL the HTTP client puts in its errors.
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return "Sending failed: " + err.Error()
}

// describeTLS explains a certificate problem, or returns "".
func describeTLS(err error) string {
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	var rh tls.RecordHeaderError
	switch {
	case errors.As(err, &ua):
		return "The receiver's certificate is not from a trusted authority. For a private certificate authority, paste its certificate into the channel; if your network inspects HTTPS, add its certificate to this server's trusted certificates."
	case errors.As(err, &hn):
		return "The receiver's certificate is for another name. Check the address."
	case errors.As(err, &ci):
		return "The receiver's certificate is not valid (" + ci.Error() + ")."
	case errors.As(err, &rh):
		return "The receiver did not answer with TLS. Check the address and port, or the connection security."
	}
	return ""
}

func describeAnswer(ae *AnswerError, c Channel) string {
	msg := "The receiver answered " + ae.Status + "."
	switch {
	case ae.Code == http.StatusUnauthorized || ae.Code == http.StatusForbidden:
		if c.Type == TypeWebhook {
			msg += " Check the key or token in the URL or headers."
		} else {
			msg += " Check that the webhook URL is complete and still allowed to post."
		}
	case ae.Code == http.StatusNotFound || ae.Code == http.StatusGone:
		switch c.Type {
		case TypeSlack:
			msg += " The webhook may have been removed, or its Slack channel deleted or archived: make a new one in Slack and enter its URL."
		case TypeTeams:
			msg += " The workflow may have been turned off or deleted: check it in Teams (Workflows) and enter its URL again."
		default:
			msg += " Check the URL."
		}
	case ae.Code == http.StatusBadRequest && c.Type == TypeTeams:
		msg += " Check that the workflow is \"Post to a channel when a webhook request is received\"."
	case ae.Code == http.StatusTooManyRequests:
		msg += " The receiver limits how often it takes messages; Signalith tries again later."
	case ae.Code >= 500:
		msg += " The receiver has a problem; Signalith tries again later."
	}
	if ae.Said != "" && !strings.EqualFold(ae.Said, http.StatusText(ae.Code)) {
		msg += fmt.Sprintf(" It said: %q", ae.Said)
	}
	return msg
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

// secretValues returns a channel's secrets and the parts of its URL that
// may hold a token, for scrub.
func secretValues(c Channel) []string {
	out := []string{c.URL, c.SigningSecret, c.Password}
	for _, v := range c.Headers {
		out = append(out, v)
		if _, after, ok := strings.Cut(v, " "); ok {
			// The token of "Bearer <token>".
			out = append(out, after)
		}
	}
	if u, err := url.Parse(c.URL); err == nil {
		if p, ok := u.User.Password(); ok {
			out = append(out, p)
		}
		for _, seg := range strings.Split(u.Path, "/") {
			if len(seg) >= 8 {
				out = append(out, seg)
			}
		}
		for _, vals := range u.Query() {
			out = append(out, vals...)
		}
		out = append(out, u.RawQuery, u.EscapedPath())
	}
	return out
}

// scrub hides a channel's secrets in a message.
func scrub(msg string, c Channel) string {
	for _, s := range secretValues(c) {
		if len(s) >= 6 {
			msg = strings.ReplaceAll(msg, s, redact.Mask)
		}
	}
	return msg
}
