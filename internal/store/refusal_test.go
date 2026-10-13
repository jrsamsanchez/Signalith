package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
)

// jsonErr is an OpenSearch error answer.
func jsonErr(status int, typ, reason string) *Error {
	return &Error{Status: status, Body: fmt.Sprintf(`{"error":{"root_cause":[{"type":%q,"reason":%q}],"type":%q,"reason":%q},"status":%d}`,
		typ, reason, typ, reason, status)}
}

func TestRefusalOf(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want Refusal
	}{
		{"no error", nil, NotRefused},
		{"unreachable", errors.New("opensearch unreachable at https://opensearch:9200: connection refused"), NotRefused},
		// OpenSearch 2.17 answers this, as plain text, to every request
		// before its security settings are loaded.
		{"not initialized", &Error{Status: 503, Body: "OpenSearch Security not initialized."}, RefusedNotInitialized},
		{"not initialized, wrapped", fmt.Errorf("heartbeat: %w", &Error{Status: 503, Body: "OpenSearch Security not initialized."}), RefusedNotInitialized},
		{"not initialized, Open Distro", &Error{Status: 503, Body: "Open Distro Security not initialized."}, RefusedNotInitialized},
		{"not initialized, past sign-in", jsonErr(503, "security_exception", "OpenSearch Security not initialized for indices:data/write/index. See the docs"), RefusedNotInitialized},
		{"cluster event timeout", jsonErr(503, "process_cluster_event_timeout_exception",
			"failed to process cluster event (put-mapping [.opendistro_security/abc]) within 30s"), RefusedBusy},
		{"queue full", jsonErr(429, "rejected_execution_exception", "rejected execution of coordinating operation"), RefusedBusy},
		{"queue full, Elasticsearch name", jsonErr(429, "es_rejected_execution_exception", "rejected execution"), RefusedBusy},
		{"circuit breaker", jsonErr(429, "circuit_breaking_exception", "[parent] Data too large"), RefusedBusy},
		{"circuit breaker, as a 503", jsonErr(503, "circuit_breaking_exception", "[parent] Data too large"), RefusedBusy},
		{"too many requests", &Error{Status: 429, Body: "Too Many Requests"}, RefusedBusy},
		{"proxy gave up", &Error{Status: 504, Body: "<html>Gateway Time-out</html>"}, RefusedBusy},
		// The flood-stage block is 429 in OpenSearch 2, 403 before: never
		// busy, never a permission.
		{"flood stage", jsonErr(429, "cluster_block_exception", "index [s_runtime] blocked by: [TOO_MANY_REQUESTS/12/disk usage exceeded flood-stage watermark, index has read-only-allow-delete block];"), RefusedBlocked},
		{"read-only, older", jsonErr(403, "cluster_block_exception", "blocked by: [FORBIDDEN/12/index read-only / allow delete (api)];"), RefusedBlocked},
		// While index creation is blocked (OpenSearch blocks it by itself
		// on a full disk), even making an index that exists is refused so.
		{"index creation blocked", jsonErr(403, "index_create_block_exception", "blocked by: [FORBIDDEN/10/cluster create-index blocked (api)];"), RefusedBlocked},
		{"sign-in", jsonErr(401, "security_exception", "missing authentication credentials for REST request [/]"), RefusedSignIn},
		{"permission", jsonErr(403, "security_exception", "no permissions for [indices:data/write/index] and User [name=signalith]"), RefusedPermission},
		{"no cluster manager", jsonErr(503, "cluster_manager_not_discovered_exception", "no cluster manager"), RefusedUnavailable},
		{"other 503", &Error{Status: 503, Body: "Service Unavailable"}, RefusedUnavailable},
		{"500", jsonErr(500, "null_pointer_exception", "oops"), RefusedUnavailable},
		{"bad request", jsonErr(400, "mapper_parsing_exception", "failed to parse"), RefusedOther},
		{"bad request about timeouts", jsonErr(400, "illegal_argument_exception", "timeout_exception is not a setting"), RefusedOther},
		{"conflict", jsonErr(409, "version_conflict_engine_exception", "version conflict"), RefusedOther},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := RefusalOf(c.err); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// What the client makes of the security plugin's real answer: a plain
// text body, kept as it is.
func TestNotInitializedThroughTheClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "OpenSearch Security not initialized.")
	}))
	defer srv.Close()
	_, err := New(Config{URL: srv.URL}).Health(context.Background())
	if RefusalOf(err) != RefusedNotInitialized || err.Error() != "opensearch returned 503: OpenSearch Security not initialized." {
		t.Errorf("%v", err)
	}
	// Quoted at the end of a sentence, it gets no second period.
	if got := "The error was: " + Sentence(err.Error()); strings.HasSuffix(got, "..") {
		t.Errorf("%q", got)
	}
}

func TestSentence(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"connection refused":     "connection refused.",
		"not initialized.":       "not initialized.",
		"not initialized. \n":    "not initialized.",
		"cut short...":           "cut short...",
		"really?":                "really?",
		"opensearch returned 1!": "opensearch returned 1!",
	} {
		if got := Sentence(in); got != want {
			t.Errorf("Sentence(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUnusable(t *testing.T) {
	notInit := &Error{Status: 503, Body: "OpenSearch Security not initialized."}
	got := Unusable(notInit)
	if !strings.HasPrefix(got, "OpenSearch is running, but its security settings aren't loaded") ||
		!strings.Contains(got, "run docker compose -f deploy/docker/docker-compose.yml up -d again from the Signalith folder: it re-runs the step that loads OpenSearch's security settings.") ||
		!strings.Contains(got, "docs/opensearch-security.md#if-opensearchs-security-settings-arent-loaded") ||
		!strings.Contains(got, "load them with securityadmin.sh, as docs/opensearch-security.md#3-load-the-security-settings shows.") ||
		strings.Contains(got, "not reachable") || strings.Contains(got, "right to") || strings.Contains(got, "setup step") {
		t.Errorf("not initialized: %q", got)
	}
	if got := Unusable(errors.New("dial tcp: connection refused")); got != "OpenSearch is not reachable: dial tcp: connection refused" {
		t.Errorf("unreachable: %q", got)
	}
	busy := jsonErr(503, "process_cluster_event_timeout_exception", "failed to process cluster event (put-mapping) within 30s")
	if got := Unusable(busy); !strings.HasPrefix(got, "OpenSearch is too busy to answer in time (") || !strings.Contains(got, "Try again in a few minutes.") ||
		!strings.Contains(got, "docker compose -f deploy/docker/docker-compose.yml logs opensearch from the Signalith folder") {
		t.Errorf("busy: %q", got)
	}
	unavailable := jsonErr(503, "cluster_manager_not_discovered_exception", "no cluster manager")
	if got := Unusable(unavailable); !strings.HasPrefix(got, "OpenSearch isn't ready (") || !strings.Contains(got, "Its log says why. With the Docker quick start, show it with") {
		t.Errorf("unavailable: %q", got)
	}
	blocked := jsonErr(429, "cluster_block_exception", "blocked by: [TOO_MANY_REQUESTS/12/disk usage exceeded flood-stage watermark];")
	if got := Unusable(blocked); !strings.HasPrefix(got, "OpenSearch refuses writes (") || !strings.Contains(got, "give OpenSearch more disk, or remove the block.") {
		t.Errorf("blocked: %q", got)
	}
	// Hints are only for what the error doesn't make plain.
	if Hint(notInit) == "" || Hint(busy) == "" || Hint(unavailable) == "" || Hint(jsonErr(403, "security_exception", "no permissions")) != "" || Hint(errors.New("x")) != "" {
		t.Error("hints")
	}
}

// A request OpenSearch took but didn't answer in time is told from one
// that never reached it, and still times out as before for code that
// looks for that.
func TestNoAnswer(t *testing.T) {
	stall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer stall.Close()
	c := New(Config{URL: stall.URL, Timeout: 100 * time.Millisecond})
	_, err := c.Health(context.Background())
	if !NoAnswer(err) || Problem(err) != ProblemTimeout || RefusalOf(err) != NotRefused || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("client timeout: %v", err)
	}
	if want := "opensearch at " + stall.URL + " did not answer in time: "; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("%q", err)
	}
	if got := Unusable(err); !strings.HasPrefix(got, "OpenSearch didn't answer in time (") || strings.Contains(got, "not reachable") {
		t.Errorf("unusable: %q", got)
	}
	if !strings.HasPrefix(Hint(err), "OpenSearch didn't answer in time. Signalith keeps trying.") {
		t.Errorf("hint: %q", Hint(err))
	}
	// The caller's own deadline, too.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := New(Config{URL: stall.URL}).Health(ctx); !NoAnswer(err) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("deadline: %v", err)
	}
	// Wrapped, as the callers do.
	if !NoAnswer(fmt.Errorf("heartbeat: %w", err)) {
		t.Error("wrapped")
	}
	// Nothing listening: not reached, so not an answer that came late.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	if _, err := New(Config{URL: "http://" + closed}).Health(context.Background()); err == nil || NoAnswer(err) || Problem(err) != "" {
		t.Errorf("closed: %v", err)
	}
	// Given up by the caller, not timed out.
	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	if _, err := New(Config{URL: stall.URL}).Health(ctx); err == nil || NoAnswer(err) {
		t.Errorf("canceled: %v", err)
	}
}

// A request on a kept connection to an OpenSearch that has since gone
// away (its computer turned off, its network cut: nothing answers, not
// even a reset) times out after it was written. That is no slow answer:
// OpenSearch can't be reached.
func TestNoAnswerKeptConnectionToNowhere(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":"green"}`)
	}))
	defer srv.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// A forwarder to the server, until gone: then it keeps the
	// connections it has open but passes nothing on, and takes no new ones.
	var gone atomic.Bool
	var conns sync.WaitGroup
	defer conns.Wait()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer conns.Done()
				defer c.Close()
				up, err := net.Dial("tcp", srv.Listener.Addr().String())
				if err != nil {
					return
				}
				defer up.Close()
				go io.Copy(c, up)
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if !gone.Load() {
						up.Write(buf[:n])
					}
				}
			}()
		}
	}()
	c := New(Config{URL: "http://" + ln.Addr().String(), Timeout: 300 * time.Millisecond})
	if _, err := c.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	gone.Store(true)
	ln.Close()
	_, err = c.Health(context.Background())
	if err == nil || NoAnswer(err) || !strings.Contains(err.Error(), "opensearch unreachable") {
		t.Errorf("gone: %v", err)
	}
	c.CloseIdleConnections()

	// Still there but slow, on a kept connection: a late answer.
	var calls atomic.Int32
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) > 1 {
			<-r.Context().Done()
			return
		}
		io.WriteString(w, `{"status":"green"}`)
	}))
	defer slow.Close()
	c = New(Config{URL: slow.URL, Timeout: 300 * time.Millisecond})
	if _, err := c.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Health(context.Background()); !NoAnswer(err) {
		t.Errorf("slow: %v", err)
	}
}

// The docs sections the fixes send people to exist (GitHub's anchors:
// lower case, punctuation dropped, spaces as hyphens).
func TestFixesNameDocsThatExist(t *testing.T) {
	re := regexp.MustCompile(`docs/([a-z-]+\.md)#([a-z0-9-]+)`)
	found := 0
	for _, text := range []string{NotInitializedFix, BusyFix, BlockedFix, OpenSearchLog} {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			found++
			data, err := os.ReadFile(filepath.Join("..", "..", "docs", m[1]))
			if err != nil {
				t.Fatal(err)
			}
			ok := false
			for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
				if !strings.HasPrefix(line, "#") {
					continue
				}
				var b strings.Builder
				for _, r := range strings.ToLower(strings.TrimSpace(strings.TrimLeft(line, "#"))) {
					switch {
					case unicode.IsLetter(r), unicode.IsDigit(r), r == '-', r == '_':
						b.WriteRune(r)
					case r == ' ':
						b.WriteRune('-')
					}
				}
				ok = ok || b.String() == m[2]
			}
			if !ok {
				t.Errorf("docs/%s has no section #%s", m[1], m[2])
			}
		}
	}
	if found != 2 {
		t.Errorf("%d links", found)
	}
}
