// Package safelog keeps the server log bounded when its contents come from
// other people: values in log lines are cut to a sensible length, and the
// log file on Windows rotates by size, so nobody can fill the disk through
// the log (for example by signing in with a megabyte-long user name).
package safelog

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf8"
)

// Lengths values are cut to, in bytes.
const (
	// MaxShort applies to values such as user names, client addresses,
	// host names and paths: anything longer is not a real one.
	MaxShort = 128
	// MaxValue applies to every other value, such as error messages.
	MaxValue = 2048
)

// shortKeys are attribute names whose values are cut to MaxShort.
var shortKeys = map[string]bool{
	"user": true, "username": true, "by": true, "client": true, "sender": true,
	"host": true, "hostname": true, "path": true, "tag": true, "remote": true,
	"peer": true, "forwarded": true,
}

// New returns a handler that cuts long values before passing records to
// next.
func New(next slog.Handler) slog.Handler { return &handler{next: next} }

type handler struct{ next slog.Handler }

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool { return h.next.Enabled(ctx, l) }

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, Cut(r.Message, MaxValue), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(capAttr(a))
		return true
	})
	return h.next.Handle(ctx, out)
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	capped := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		capped[i] = capAttr(a)
	}
	return &handler{next: h.next.WithAttrs(capped)}
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{next: h.next.WithGroup(name)}
}

func capAttr(a slog.Attr) slog.Attr {
	limit := MaxValue
	if shortKeys[strings.ToLower(a.Key)] {
		limit = MaxShort
	}
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		if s := v.String(); len(s) > limit {
			return slog.String(a.Key, Cut(s, limit))
		}
	case slog.KindGroup:
		group := v.Group()
		capped := make([]any, len(group))
		for i, g := range group {
			capped[i] = capAttr(g)
		}
		return slog.Group(a.Key, capped...)
	case slog.KindAny:
		// Errors, slices, structs and the like: as text, then cut.
		var s string
		switch x := v.Any().(type) {
		case error:
			s = x.Error()
		case fmt.Stringer:
			s = x.String()
		default:
			s = fmt.Sprintf("%+v", x)
		}
		if len(s) > limit {
			return slog.String(a.Key, Cut(s, limit))
		}
	}
	return slog.Attr{Key: a.Key, Value: v}
}

// Cut shortens s to at most about max bytes, on a character boundary,
// noting how much was left out.
func Cut(s string, max int) string {
	if len(s) <= max {
		return s
	}
	end := max
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return fmt.Sprintf("%s…[%d more bytes]", s[:end], len(s)-end)
}
