package store

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
)

// Refusal is the kind of answer OpenSearch turned a request away with, so
// that each place that reports it can say what it means and what to do.
type Refusal string

// The kinds of refusal. NotRefused is an error that is no answer from
// OpenSearch at all (it could not be reached, or did not answer in time:
// see NoAnswer), or no error.
const (
	NotRefused Refusal = ""
	// RefusedNotInitialized is OpenSearch running with its security plugin
	// on, but without its security settings loaded: it answers every
	// request with 503 "OpenSearch Security not initialized." until they
	// are (with securityadmin.sh, which the Docker quick start's
	// opensearch-security step runs). It does not clear by itself.
	RefusedNotInitialized Refusal = "not_initialized"
	// RefusedBusy is OpenSearch too busy to do the request in time: a
	// cluster change that timed out (process_cluster_event_timeout_exception),
	// full queues (429 rejected_execution_exception), a tripped circuit
	// breaker, or a proxy that gave up waiting (504). Trying again later
	// usually works.
	RefusedBusy Refusal = "busy"
	// RefusedBlocked is a write refused by a block, as on every index once
	// OpenSearch's disk passes the flood-stage watermark (IsClusterBlock),
	// or on making an index while index creation is blocked.
	RefusedBlocked Refusal = "blocked"
	// RefusedSignIn is a sign-in OpenSearch did not accept (401).
	RefusedSignIn Refusal = "auth"
	// RefusedPermission is a request the signed-in user may not make (403).
	RefusedPermission Refusal = "forbidden"
	// RefusedUnavailable is any other 5xx: OpenSearch is not ready, for
	// example while it has no cluster manager.
	RefusedUnavailable Refusal = "unavailable"
	// RefusedOther is any other error answer, such as a bad request.
	RefusedOther Refusal = "other"
)

// RefusalOf says how OpenSearch refused the request that failed with err.
// Only RefusedSignIn and RefusedPermission are about Signalith's own
// OpenSearch user; the others are not fixed by giving it more rights.
func RefusalOf(err error) Refusal {
	var e *Error
	if !errors.As(err, &e) {
		return NotRefused
	}
	body := strings.ToLower(e.Body)
	switch {
	case IsClusterBlock(err), e.Status == http.StatusForbidden && strings.Contains(body, "index_create_block_exception"):
		// OpenSearch blocks making indices by itself when its disk is
		// full (cluster.blocks.create_index), even one that exists.
		return RefusedBlocked
	case notInitialized(e.Status, body):
		return RefusedNotInitialized
	case busy(e.Status, body):
		return RefusedBusy
	case e.Status == http.StatusUnauthorized:
		return RefusedSignIn
	case e.Status == http.StatusForbidden:
		return RefusedPermission
	case e.Status >= 500:
		return RefusedUnavailable
	}
	return RefusedOther
}

// notInitialized reports whether an answer is the security plugin's
// before its settings are loaded. Over REST it is plain text, "OpenSearch
// Security not initialized." (Open Distro's said "Open Distro Security");
// a request that got past sign-in fails in JSON with a security_exception
// whose reason starts "OpenSearch Security not initialized for <action>".
func notInitialized(status int, lowerBody string) bool {
	return status == http.StatusServiceUnavailable && strings.Contains(lowerBody, "security not initialized")
}

// busyTypes are the error types of an OpenSearch that has too much to do.
var busyTypes = []string{
	"process_cluster_event_timeout_exception",
	"rejected_execution_exception", // also es_rejected_execution_exception
	"circuit_breaking_exception",
	"too_many_requests",
	"timeout_exception",
}

// busy reports whether an answer says OpenSearch could not do the request
// in time, rather than that it would not.
func busy(status int, lowerBody string) bool {
	if status == http.StatusTooManyRequests || status == http.StatusGatewayTimeout {
		return true
	}
	if status < 500 {
		return false
	}
	for _, t := range busyTypes {
		if strings.Contains(lowerBody, t) {
			return true
		}
	}
	return false
}

// ProblemTimeout is the problem code, beside the Refusal ones, of a
// request OpenSearch received but did not answer in time (NoAnswer).
const ProblemTimeout = "timeout"

// Problem is a code for why a request to OpenSearch failed, for a page to
// word: ProblemTimeout, a Refusal, or "" when OpenSearch could not be
// reached at all.
func Problem(err error) string {
	if NoAnswer(err) {
		return ProblemTimeout
	}
	return string(RefusalOf(err))
}

// noAnswerError is a request that reached OpenSearch, which did not answer
// before the request's time ran out.
type noAnswerError struct {
	msg string
	err error
}

func (e *noAnswerError) Error() string { return e.msg }
func (e *noAnswerError) Unwrap() error { return e.err }

// NoAnswer reports whether err is a request OpenSearch received but did
// not answer in time: it was reached, and is too slow, not out of reach.
func NoAnswer(err error) bool {
	var e *noAnswerError
	return errors.As(err, &e)
}

// timedOut reports whether a request failed because its time ran out.
func timedOut(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
}

// OpenSearchLog says where OpenSearch's log is, after a sentence that
// sends the reader to it.
const OpenSearchLog = "With the Docker quick start, show it with docker compose -f deploy/docker/docker-compose.yml logs opensearch " +
	"from the Signalith folder; otherwise it is in /var/log/opensearch, or in the logs folder where you unpacked OpenSearch."

// NotInitializedFix says how to load OpenSearch's security settings, for
// a message about RefusedNotInitialized that has just said they aren't
// loaded. OpenSearch loads them by itself as it starts, once: if that
// fails, as it can on a slow computer, they stay unloaded until someone
// loads them.
const NotInitializedFix = "If OpenSearch started only a few minutes ago, wait: it loads them as it starts. " +
	"Otherwise, with the Docker quick start, run docker compose -f deploy/docker/docker-compose.yml up -d again " +
	"from the Signalith folder: it re-runs the step that loads OpenSearch's security settings. " +
	"If that doesn't load them, docs/opensearch-security.md#if-opensearchs-security-settings-arent-loaded says what to do. " +
	"Without Docker, load them with securityadmin.sh, as docs/opensearch-security.md#3-load-the-security-settings shows."

// BusyFix says what to do about RefusedBusy, or a request OpenSearch did
// not answer in time, when it goes on.
const BusyFix = "If this lasts more than a few minutes, check that OpenSearch's computer has enough memory and CPU, " +
	"and what OpenSearch's log says. " + OpenSearchLog

// BlockedFix says what to do about RefusedBlocked.
const BlockedFix = "OpenSearch does this when its disk is full, or when someone set a block such as cluster.blocks.read_only: " +
	"give OpenSearch more disk, or remove the block."

// Unusable says why OpenSearch could not be used, for the command line:
// that it could not be reached, or what its answer means, and, where the
// fix is not in Signalith's own settings, what to do.
func Unusable(err error) string {
	if NoAnswer(err) {
		return "OpenSearch didn't answer in time (" + err.Error() + "). Try again in a few minutes. " + BusyFix
	}
	switch RefusalOf(err) {
	case NotRefused:
		return "OpenSearch is not reachable: " + err.Error()
	case RefusedNotInitialized:
		return "OpenSearch is running, but its security settings aren't loaded, so it refuses every request. " + NotInitializedFix
	case RefusedBusy:
		return "OpenSearch is too busy to answer in time (" + err.Error() + "). Try again in a few minutes. " + BusyFix
	case RefusedSignIn:
		return "OpenSearch refused the sign-in: " + err.Error()
	case RefusedPermission:
		return "OpenSearch refused the request: " + err.Error()
	case RefusedBlocked:
		return "OpenSearch refuses writes (" + err.Error() + "). " + BlockedFix
	case RefusedUnavailable:
		return "OpenSearch isn't ready (" + err.Error() + "). Its log says why. " + OpenSearchLog
	}
	return "OpenSearch answered with an error: " + err.Error()
}

// Hint says what to do about err when that is not plain from the error
// itself, for the log of a server that keeps trying; else "".
func Hint(err error) string {
	if NoAnswer(err) {
		return "OpenSearch didn't answer in time. Signalith keeps trying. " + BusyFix
	}
	switch RefusalOf(err) {
	case RefusedNotInitialized:
		return "OpenSearch's security settings aren't loaded. " + NotInitializedFix + " Signalith keeps trying, so it needs no restart."
	case RefusedBusy:
		return "OpenSearch is too busy to answer in time. Signalith keeps trying. " + BusyFix
	case RefusedUnavailable:
		return "OpenSearch isn't ready. Signalith keeps trying. OpenSearch's log says why. " + OpenSearchLog
	}
	return ""
}

// Sentence ends text with a period unless it already ends with one (or
// with another mark that ends a sentence), for an error quoted at the end
// of a message: OpenSearch's own often end with one.
func Sentence(text string) string {
	text = strings.TrimRight(text, " \t\r\n")
	if text == "" || strings.HasSuffix(text, ".") || strings.HasSuffix(text, "!") || strings.HasSuffix(text, "?") {
		return text
	}
	return text + "."
}
