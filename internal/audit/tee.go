// Package audit turns the server's audit log lines into documents in
// OpenSearch, so that the audit trail of every server in a cluster can be
// searched in one place. A log line is an audit line when it carries the
// attribute audit=true. Handler wraps the server's log handler and hands
// those lines, as Events, to a Sink, which keeps them in a bounded spool
// on disk and writes them to monthly audit indices from there, so that
// logging never waits for OpenSearch and a line logged while OpenSearch is
// away is written once it is back.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/safelog"
)

// Limits on what an Event keeps of a log line.
const (
	// MaxValue is the length, in bytes, values and the message are cut to.
	MaxValue = 2048
	// MaxFields is the most attributes an Event keeps in Fields.
	MaxFields = 64
)

// Event is one audit log line as it is stored in OpenSearch.
type Event struct {
	Time     time.Time         `json:"@timestamp"`
	Server   string            `json:"server,omitempty"`
	NodeID   string            `json:"node_id,omitempty"`
	User     string            `json:"user,omitempty"`
	Action   string            `json:"action,omitempty"`
	Target   string            `json:"target,omitempty"`
	Message  string            `json:"message"`
	SourceIP string            `json:"source_ip,omitempty"`
	Level    string            `json:"level,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
	Epoch    int64             `json:"epoch,omitempty"`
	// Seq numbers the events of one Sink, so two events of one server
	// logged at the same instant still get different IDs.
	Seq int64 `json:"seq"`
}

// ID returns the event's document ID: the first 24 hex digits of a
// SHA-256 of its node, sequence number and time. The same event written
// twice has the same ID, so the second write is refused as a conflict
// instead of storing it twice.
func (e Event) ID() string {
	sum := sha256.Sum256([]byte(e.NodeID + "\x00" + strconv.FormatInt(e.Seq, 10) + "\x00" + e.Time.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(sum[:])[:24]
}

// doc returns the event as the document stored in OpenSearch. The time
// is kept to the millisecond, as a date field in OpenSearch is.
func (e Event) doc() map[string]any {
	d := map[string]any{
		"@timestamp": e.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
		"message":    e.Message,
		"seq":        e.Seq,
	}
	for k, v := range map[string]string{"server": e.Server, "node_id": e.NodeID, "user": e.User, "action": e.Action,
		"target": e.Target, "source_ip": e.SourceIP, "level": e.Level} {
		if v != "" {
			d[k] = v
		}
	}
	if len(e.Fields) > 0 {
		f := make(map[string]any, len(e.Fields))
		for k, v := range e.Fields {
			f[k] = v
		}
		d["fields"] = f
	}
	if e.Epoch != 0 {
		d["epoch"] = e.Epoch
	}
	return d
}

// Handler returns a handler that passes every record to next unchanged
// and also gives the audit ones, as Events, to sink. Logging never waits
// for the sink or fails because of it. A nil sink, or a disabled one,
// only passes records on.
func Handler(next slog.Handler, sink *Sink) slog.Handler {
	return &handler{next: next, sink: sink}
}

type handler struct {
	next slog.Handler
	sink *Sink
	// attrs are the attributes added with WithAttrs, flattened, and
	// groups the open groups their keys are prefixed with.
	attrs  []flatAttr
	groups []string
	audit  bool
}

type flatAttr struct {
	key, value string
}

func (h *handler) capturing() bool { return h.sink != nil && h.sink.Enabled() }

// Enabled reports whether next takes records of level l, or the sink
// would: audit lines are logged at Info or above, and are kept even when
// the log itself is set to show only warnings.
func (h *handler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l) || l >= slog.LevelInfo && h.capturing()
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	var err error
	if h.next.Enabled(ctx, r.Level) {
		err = h.next.Handle(ctx, r)
	}
	if r.Level >= slog.LevelInfo && h.capturing() {
		h.capture(r)
	}
	return err
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	n := *h
	n.next = h.next.WithAttrs(attrs)
	n.attrs = append([]flatAttr(nil), h.attrs...)
	prefix := groupPrefix(h.groups)
	for _, a := range attrs {
		if isAuditMark(a) {
			n.audit = true
			continue
		}
		n.attrs = flatten(n.attrs, prefix, a)
	}
	return &n
}

func (h *handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	n := *h
	n.next = h.next.WithGroup(name)
	n.groups = append(append([]string(nil), h.groups...), name)
	return &n
}

func groupPrefix(groups []string) string {
	if len(groups) == 0 {
		return ""
	}
	return strings.Join(groups, ".") + "."
}

// isAuditMark reports whether a is the audit=true mark, in whatever group.
func isAuditMark(a slog.Attr) bool {
	if a.Key != "audit" {
		return false
	}
	v := a.Value.Resolve()
	return v.Kind() == slog.KindBool && v.Bool()
}

// flatten appends a, with groups flattened into dotted keys, to out.
func flatten(out []flatAttr, prefix string, a slog.Attr) []flatAttr {
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		p := prefix
		if a.Key != "" {
			p += a.Key + "."
		}
		for _, g := range v.Group() {
			out = flatten(out, p, g)
		}
		return out
	}
	if a.Key == "" {
		return out
	}
	var s string
	switch v.Kind() {
	case slog.KindTime:
		s = v.Time().UTC().Format(time.RFC3339Nano)
	case slog.KindAny:
		if e, ok := v.Any().(error); ok && e != nil {
			s = e.Error()
		} else {
			s = v.String()
		}
	default:
		s = v.String()
	}
	return append(out, flatAttr{prefix + a.Key, safelog.Cut(s, MaxValue)})
}

// capture turns r into an Event and adds it to the sink, when r or the
// handler carries the audit mark.
func (h *handler) capture(r slog.Record) {
	audit := h.audit
	attrs := append([]flatAttr(nil), h.attrs...)
	prefix := groupPrefix(h.groups)
	r.Attrs(func(a slog.Attr) bool {
		if isAuditMark(a) {
			audit = true
			return true
		}
		attrs = flatten(attrs, prefix, a)
		return true
	})
	if !audit {
		return
	}
	h.sink.Add(eventOf(r, attrs))
}

// eventOf maps a record and its flattened attributes to an Event.
func eventOf(r slog.Record, attrs []flatAttr) Event {
	t := r.Time
	if t.IsZero() {
		t = time.Now()
	}
	ev := Event{Time: t.UTC(), Message: safelog.Cut(r.Message, MaxValue), Level: r.Level.String()}
	get := func(keys ...string) (string, string) {
		for _, k := range keys {
			for _, a := range attrs {
				if a.key == k {
					return k, a.value
				}
			}
		}
		return "", ""
	}
	used := map[string]bool{}
	take := func(keys ...string) string {
		k, v := get(keys...)
		if k != "" {
			used[k] = true
		}
		return v
	}
	_, by := get("by")
	ev.User = take("by", "user", "username")
	if by != "" {
		ev.Target = take("user", "target", "name", "index", "feed")
	} else {
		ev.Target = take("target", "name", "index", "feed")
	}
	ev.SourceIP = take("client", "remote", "ip")
	if a := actionOf(r.Message); a != "" {
		ev.Action = a
	} else {
		ev.Action = take("action")
	}
	for _, a := range attrs {
		if used[a.key] {
			continue
		}
		if ev.Fields == nil {
			ev.Fields = map[string]string{}
		}
		if _, dup := ev.Fields[a.key]; !dup && len(ev.Fields) >= MaxFields {
			break
		}
		ev.Fields[a.key] = a.value
	}
	return ev
}

// actionOf returns the word before the first ":" of a message such as
// "users.create: added alice", or "" when the message does not start so.
func actionOf(msg string) string {
	i := strings.IndexByte(msg, ':')
	if i <= 0 || i > 64 {
		return ""
	}
	tok := msg[:i]
	for _, c := range tok {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
		if !ok {
			return ""
		}
	}
	return tok
}
