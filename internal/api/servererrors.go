// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/redact"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// A failure on the server (a 5xx answer) is shown to whoever made the
// request, who may have any role. The error below it can say where
// OpenSearch runs, a file path or an internal address, which is for
// admins, so writeError shows such an error only as a fixed sentence with
// a short reference, and logs it in full with the reference. Messages
// written for the person who sees them (userError, and most 503s: "not
// set up on this server", "busy, try again") are shown as they are.

// userError is an error written for the person who sees it: writeError
// shows its message whatever the status.
type userError struct {
	msg string
	err error
}

func (e *userError) Error() string { return e.msg }
func (e *userError) Unwrap() error { return e.err }

// errUser returns an error whose message is safe to show with any status.
func errUser(msg string) error { return &userError{msg: msg} }

// hiddenError is an error from below with a sentence of context: a 5xx
// answer shows the sentence with a reference, and the log has the rest.
type hiddenError struct {
	msg string
	err error
}

func (e *hiddenError) Error() string { return e.msg + ": " + e.err.Error() }
func (e *hiddenError) Unwrap() error { return e.err }

// errHidden adds msg to err; with a 5xx status only msg is shown.
func errHidden(msg string, err error) error { return &hiddenError{msg: msg, err: err} }

// serverErrorBody is what a 5xx answer says about err: its own message
// when that is meant to be shown, else a fixed sentence naming a
// reference that the full error is logged with.
func serverErrorBody(w http.ResponseWriter, status int, err error) map[string]any {
	if msg, ok := shownAsIs(status, err); ok {
		return map[string]any{"error": msg}
	}
	ref := errorRef()
	logServerError(w, ref, status, err)
	what := "Something went wrong on the server"
	var he *hiddenError
	if errors.As(err, &he) {
		what = he.msg
	} else if store.Unreachable(err) {
		what = "OpenSearch is not answering. Signalith keeps trying; the Health page says what is wrong"
	} else if unreachable(err) {
		what = "The server could not reach a service it uses (such as OpenSearch), or it did not answer in time"
	}
	return map[string]any{"error": what + " (ref " + ref + "). An admin can find the details in the server log.", "ref": ref}
}

// shownAsIs returns the message of a 5xx error that is meant to be shown.
func shownAsIs(status int, err error) (string, bool) {
	var ue *userError
	if errors.As(err, &ue) {
		return ue.msg, true
	}
	// The AI model's own error message (a wrong key, an unknown model)
	// says nothing about this server. Raw text in its place may be a
	// proxy's page, so that is logged instead.
	var ae *assistant.APIError
	if errors.As(err, &ae) && ae.Parsed {
		return ae.Error(), true
	}
	for _, e := range []error{search.ErrBusy, search.ErrUserBusy} {
		if errors.Is(err, e) {
			return e.Error(), true
		}
	}
	// 503 is how this server says a part is not set up, busy or starting,
	// in sentences of its own; those that pass on an error from below are
	// told apart by what they hold.
	var he *hiddenError
	if status == http.StatusServiceUnavailable && !errors.As(err, &he) && !internalDetail(err) {
		return err.Error(), true
	}
	return "", false
}

// internalDetail reports whether an error may hold details of where and
// how the server runs: OpenSearch's address or answer, a network address,
// a file path.
func internalDetail(err error) bool {
	var se *store.Error
	var ue *url.Error
	var ne net.Error
	var pe *fs.PathError
	var le *os.LinkError
	var sce *os.SyscallError
	if errors.As(err, &se) || errors.As(err, &ue) || errors.As(err, &ne) || errors.As(err, &pe) || errors.As(err, &le) || errors.As(err, &sce) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{"://", "opensearch unreachable", "opensearch at ", "opensearch request to", "opensearch returned"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// unreachable reports whether an error is a service that could not be
// reached or did not answer.
func unreachable(err error) bool {
	var ue *url.Error
	var ne net.Error
	return store.Unreachable(err) || errors.As(err, &ue) || errors.As(err, &ne) || strings.Contains(strings.ToLower(err.Error()), "opensearch unreachable")
}

// errorRef returns a short random reference for a logged error.
func errorRef() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// errorLogWriter carries the request and the server's log down to
// writeError, which sees only the ResponseWriter, so a hidden error is
// logged with the request it failed.
type errorLogWriter struct {
	http.ResponseWriter
	log *slog.Logger
	r   *http.Request
}

// withErrorLog wraps w for writeError's log.
func (s *Server) withErrorLog(w http.ResponseWriter, r *http.Request) http.ResponseWriter {
	return &errorLogWriter{ResponseWriter: w, log: s.Log, r: r}
}

// Flush keeps streamed answers streaming.
func (e *errorLogWriter) Flush() {
	if f, ok := e.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack is http.Hijacker's, for completeness.
func (e *errorLogWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := e.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.ErrUnsupported
}

// Unwrap lets http.ResponseController reach the connection.
func (e *errorLogWriter) Unwrap() http.ResponseWriter { return e.ResponseWriter }

// logServerError logs an error hidden from the answer, with its
// reference: in the server's log when the request came through the
// server's handler, else in the default log.
//
// The error is logged as redact.Text shows it: an error built from a
// request can hold what the request carried, and a password typed into
// a form or a key in an address must not reach the log.
func logServerError(w http.ResponseWriter, ref string, status int, err error) {
	msg := redact.Text(err.Error())
	for w != nil {
		if e, ok := w.(*errorLogWriter); ok && e.log != nil {
			e.log.Error("request failed", "ref", ref, "status", status, "method", e.r.Method, "path", e.r.URL.Path, "err", msg)
			return
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			break
		}
		w = u.Unwrap()
	}
	slog.Error("request failed", "ref", ref, "status", status, "err", msg)
}
