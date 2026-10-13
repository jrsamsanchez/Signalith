package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// Email goes out with net/smtp. The connection is protected with TLS
// from the start (security tls, usually port 465) or switches to it
// before anything else is sent (starttls, the default, usually port 587;
// a server that does not offer it is refused, never used in plain text).
// Plain text (none) is only for a relay on this machine. A password is
// only ever sent over TLS.

// mailError is a mail problem, in words for people.
type mailError struct {
	msg   string
	retry bool
}

func (e *mailError) Error() string { return e.msg }

// sendMail sends m to the channel's addresses.
func (s *Senders) sendMail(ctx context.Context, c Channel, m Message) error {
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return &mailError{msg: "The channel's From address is not valid; edit the channel.", retry: false}
	}
	var to []*mail.Address
	for _, t := range c.To {
		a, err := mail.ParseAddress(t)
		if err != nil {
			return &mailError{msg: fmt.Sprintf("The address %q is not valid; edit the channel.", t), retry: false}
		}
		to = append(to, a)
	}
	if len(to) == 0 {
		return &mailError{msg: "The channel has no address to send to; edit the channel."}
	}
	data, err := buildMail(from, to, m, c.Label(), s.now())
	if err != nil {
		return &mailError{msg: "The message could not be written: " + err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, MailTimeout)
	defer cancel()
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	if err := (Protected(s.Protected)).checkHostPort(c.Host, c.Port); err != nil {
		return err
	}
	if c.Security == SecurityNone && !isLocalhost(c.Host) {
		return &mailError{msg: "Mail is only sent without TLS to a relay on this machine (localhost). Pick STARTTLS or TLS."}
	}
	d := newDialer(c.AllowLoopback || c.Security == SecurityNone, s.Protected)
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	// The connection ends when ctx does, even in the middle of a reply.
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	conf, err := tlsConfig(c, c.Host)
	if err != nil {
		return err
	}
	if c.Security == SecurityTLS {
		tc := tls.Client(conn, conf)
		if err := tc.HandshakeContext(ctx); err != nil {
			return err
		}
		conn = tc
	}
	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		return smtpErr("The mail server did not greet Signalith", err)
	}
	defer client.Close()
	if err := client.Hello(s.helloName()); err != nil {
		return smtpErr("The mail server refused Signalith's greeting", err)
	}
	if c.Security == SecuritySTARTTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return &mailError{msg: "The mail server does not offer STARTTLS, so Signalith did not send in plain text. Pick TLS (usually port 465), or use a server that offers STARTTLS."}
		}
		if err := client.StartTLS(conf); err != nil {
			return err
		}
	}
	if c.Username != "" {
		if _, ok := client.TLSConnectionState(); !ok {
			return &mailError{msg: "Signalith only sends a password over TLS. Pick STARTTLS or TLS."}
		}
		ok, mechs := client.Extension("AUTH")
		if !ok {
			return &mailError{msg: "The mail server does not ask for a sign-in; clear the user name and password."}
		}
		var auth smtp.Auth
		switch fields := strings.Fields(strings.ToUpper(mechs)); {
		case contains(fields, "PLAIN"):
			auth = smtp.PlainAuth("", c.Username, c.Password, c.Host)
		case contains(fields, "LOGIN"):
			auth = &loginAuth{user: c.Username, pass: c.Password}
		default:
			return &mailError{msg: "The mail server offers no sign-in Signalith can use (PLAIN or LOGIN); it offers " + mechs + "."}
		}
		if err := client.Auth(auth); err != nil {
			return smtpErr("The mail server refused the user name or password", err)
		}
	}
	if err := client.Mail(from.Address); err != nil {
		return smtpErr("The mail server refused the From address "+from.Address, err)
	}
	for _, a := range to {
		if err := client.Rcpt(a.Address); err != nil {
			return smtpErr("The mail server refused the address "+a.Address, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return smtpErr("The mail server refused the message", err)
	}
	if _, err := w.Write(data); err != nil {
		return smtpErr("The message could not be sent", err)
	}
	if err := w.Close(); err != nil {
		return smtpErr("The mail server refused the message", err)
	}
	_ = client.Quit()
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (s *Senders) helloName() string {
	if s.Hostname != "" && validHost(strings.ToLower(s.Hostname)) {
		return s.Hostname
	}
	return "localhost"
}

// checkHostPort refuses a protected host:port, or an IP address channels
// may not reach, before connecting.
func (p Protected) checkHostPort(host string, port int) error {
	hp := strings.ToLower(net.JoinHostPort(strings.TrimSuffix(host, "."), strconv.Itoa(port)))
	for _, x := range p {
		if strings.EqualFold(x, hp) {
			return protectedError(x)
		}
	}
	return nil
}

// smtpErr explains an SMTP reply: 4xx can be tried again, 5xx not.
func smtpErr(what string, err error) error {
	var te *textproto.Error
	if errors.As(err, &te) {
		return &mailError{msg: fmt.Sprintf("%s: %d %s", what, te.Code, clean(te.Msg, 200)), retry: te.Code < 500}
	}
	if msg := describeTLS(err); msg != "" {
		return &mailError{msg: msg, retry: true}
	}
	return fmt.Errorf("%s: %w", strings.ToLower(what[:1])+what[1:], err)
}

// loginAuth is the LOGIN sign-in, which some mail servers (Microsoft 365
// among them) offer instead of PLAIN. Like smtp.PlainAuth it is only
// used over TLS (sendMail checks).
type loginAuth struct{ user, pass string }

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		return "", nil, errors.New("unencrypted connection")
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(string(fromServer))) {
	case "username:", "user name", "username":
		return []byte(a.user), nil
	case "password:", "password":
		return []byte(a.pass), nil
	}
	return nil, fmt.Errorf("unexpected question %q from the mail server", clean(string(fromServer), 40))
}

// buildMail writes the message: headers, then the text as quoted-
// printable UTF-8. Every header value is checked for line breaks, so
// nothing from a finding can add a header.
func buildMail(from *mail.Address, to []*mail.Address, m Message, channel string, now time.Time) ([]byte, error) {
	var b bytes.Buffer
	idb := make([]byte, 12)
	_, _ = rand.Read(idb)
	domain := "signalith.local"
	if at := strings.LastIndex(from.Address, "@"); at >= 0 && validHost(strings.ToLower(from.Address[at+1:])) {
		domain = from.Address[at+1:]
	}
	tos := make([]string, len(to))
	for i, a := range to {
		tos[i] = a.String()
	}
	headers := [][2]string{
		{"From", from.String()},
		{"To", strings.Join(tos, ", ")},
		{"Subject", mime.QEncoding.Encode("utf-8", m.subject())},
		{"Date", now.Format(time.RFC1123Z)},
		{"Message-ID", "<" + hex.EncodeToString(idb) + "@" + domain + ">"},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=utf-8"},
		{"Content-Transfer-Encoding", "quoted-printable"},
		{"Auto-Submitted", "auto-generated"},
		{"X-Signalith-Kind", m.Kind},
	}
	for _, h := range headers {
		if strings.ContainsAny(h[1], "\r\n") {
			return nil, fmt.Errorf("the %s header holds a line break", h[0])
		}
		v := h[1]
		if h[0] == "To" {
			// Long lists are folded onto more lines.
			v = strings.Join(tos, ",\r\n ")
		}
		b.WriteString(h[0] + ": " + v + "\r\n")
	}
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	text := strings.ReplaceAll(m.text(channel), "\n", "\r\n")
	if _, err := qp.Write([]byte(text)); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
