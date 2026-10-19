package notify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/redact"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestDescribeErrors(t *testing.T) {
	c := Channel{Type: TypeSlack}
	for want, err := range map[string]error{
		"did not answer within":            fmt.Errorf("post: %w", context.DeadlineExceeded),
		"Sending was canceled.":            context.Canceled,
		"Could not find the server x.test": &net.DNSError{Name: "x.test", IsNotFound: true},
		"Could not look up the server y":   &net.DNSError{Name: "y"},
		"did not answer in time":           &url.Error{Op: "Post", URL: "https://x", Err: timeoutErr{}},
		"for another name":                 x509.HostnameError{Certificate: &x509.Certificate{}, Host: "x"},
		"is not valid (":                   x509.CertificateInvalidError{Reason: x509.Expired},
		"did not answer with TLS":          tls.RecordHeaderError{Msg: "bad"},
		"Sending failed: broken pipe":      &url.Error{Op: "Post", URL: "https://secret.example", Err: errors.New("broken pipe")},
		"is not valid; edit the channel":   errBadURL,
		"already said":                     &SendError{Msg: "already said"},
	} {
		got := describe(err, c)
		if !strings.Contains(got, want) {
			t.Errorf("describe(%v) = %q, want %q", err, got, want)
		}
		if strings.Contains(got, "secret.example") {
			t.Errorf("the URL is in %q", got)
		}
	}
	if describeTLS(errors.New("plain")) != "" {
		t.Error("a plain error described as TLS")
	}
	if !retryable(&SendError{Retry: true}) || retryable(&SendError{}) || retryable(errBadURL) || !retryable(errors.New("x")) {
		t.Error("retryable")
	}
}

func TestDescribeAnswers(t *testing.T) {
	for _, c := range []struct {
		typ  string
		code int
		said string
		want string
	}{
		{TypeWebhook, 401, "", "key or token"},
		{TypeTeamsApp, 403, "", "app ID and tenant"},
		{TypeSlack, 403, "", "still allowed to post"},
		{TypeSlack, 404, "", "Slack channel deleted"},
		{TypeTeams, 410, "", "Workflows"},
		{TypeTeamsApp, 404, "", "add the app to a channel"},
		{TypeWebhook, 404, "", "Check the URL."},
		{TypeTeams, 400, "", "Post to a channel when"},
		{TypeWebhook, 429, "", "tries again later"},
		{TypeWebhook, 503, "maintenance", `It said: "maintenance"`},
		{TypeWebhook, 404, "Not Found", "Check the URL."},
	} {
		ae := &AnswerError{Code: c.code, Status: fmt.Sprintf("%d %s", c.code, http.StatusText(c.code)), Said: c.said}
		got := describeAnswer(ae, Channel{Type: c.typ})
		if !strings.Contains(got, c.want) || !strings.HasPrefix(got, "The receiver answered "+ae.Status) {
			t.Errorf("%s %d: %q", c.typ, c.code, got)
		}
		if c.said == "Not Found" && strings.Contains(got, "It said") {
			t.Errorf("the status text was repeated: %q", got)
		}
		if ae.Error() != "the receiver answered "+ae.Status {
			t.Errorf("error = %q", ae.Error())
		}
	}
	if said([]byte{0xff, 0xfe}) != "" || said([]byte("  <html>oops</html>")) != "" || said([]byte(" busy ")) != "busy" {
		t.Error("said")
	}
	if sentence("  ") != "" || sentence("ok") != "Ok." || sentence("Done.") != "Done." {
		t.Error("sentence")
	}
}

func TestSendRefusals(t *testing.T) {
	ctx := context.Background()
	s := &Senders{}
	var se *SendError
	err := s.Send(ctx, Channel{Type: "pager"}, sampleMessage())
	if !errors.As(err, &se) || !strings.Contains(se.Msg, `type "pager"`) {
		t.Errorf("unknown type = %v", err)
	}
	for _, u := range []string{"ftp://hooks.example.com/x", "https://", "::"} {
		err := s.Send(ctx, Channel{Type: TypeSlack, URL: u}, sampleMessage())
		if !errors.As(err, &se) || se.Retry || !strings.Contains(se.Msg, "URL is not valid") {
			t.Errorf("%q = %v", u, err)
		}
	}
	// The receiver's answer is described without the channel's secrets.
	rc := newReceiver(t)
	rc.status, rc.answer = 401, "bad token hdr-secret-77"
	c := Channel{Type: TypeWebhook, URL: rc.URL + "/hooks/path-secret-123?key=query-secret-9", AllowLoopback: true,
		Headers: map[string]string{"Authorization": "Bearer hdr-secret-77"}}
	err = s.Send(ctx, c, sampleMessage())
	if !errors.As(err, &se) || se.Retry || !strings.Contains(se.Msg, "key or token") || !strings.Contains(se.Msg, redact.Mask) {
		t.Fatalf("401 = %v", err)
	}
	for _, secret := range []string{"hdr-secret-77", "path-secret-123", "query-secret-9"} {
		if strings.Contains(se.Msg, secret) {
			t.Errorf("%s in %q", secret, se.Msg)
		}
	}
	u, _ := url.Parse("https://user:pw-secret-1@example.com/a")
	vals := secretValues(Channel{URL: u.String()})
	found := false
	for _, v := range vals {
		found = found || v == "pw-secret-1"
	}
	if !found {
		t.Errorf("URL password not scrubbed: %v", vals)
	}
}
