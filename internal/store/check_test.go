package store

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

func opensearchHandler(user, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user != "" {
			if u, p, ok := r.BasicAuth(); !ok || u != user || p != password {
				w.WriteHeader(http.StatusUnauthorized)
				io.WriteString(w, `{"error":"unauthorized"}`)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/":
			io.WriteString(w, `{"name":"n1","cluster_name":"prod","version":{"number":"2.15.0","distribution":"opensearch"}}`)
		case "/_cluster/health":
			io.WriteString(w, `{"status":"yellow"}`)
		}
	})
}

func TestCheck(t *testing.T) {
	ctx := context.Background()
	plain := httptest.NewServer(opensearchHandler("signalith", "right"))
	defer plain.Close()
	secure := httptest.NewTLSServer(opensearchHandler("", ""))
	defer secure.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"hello":"world"}`) }))
	defer other.Close()
	// Endless answers: a test must not read them into memory.
	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat("x", 64<<10))
		for i := 0; i < 1<<10; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer huge.Close()
	hugeHealth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			io.WriteString(w, `{"cluster_name":"prod","version":{"number":"2.15.0"}}`)
			return
		}
		io.WriteString(w, `{"status":"`+strings.Repeat("g", 2<<20)+`"}`)
	}))
	defer hugeHealth.Close()
	// OpenSearch with its security settings not loaded answers everyone
	// so, as plain text.
	notInit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "OpenSearch Security not initialized.")
	}))
	defer notInit.Close()
	busy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/" {
			io.WriteString(w, `{"cluster_name":"prod","version":{"number":"2.17.1"}}`)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"error":{"root_cause":[{"type":"process_cluster_event_timeout_exception","reason":"failed to process cluster event (put-mapping) within 30s"}],"type":"process_cluster_event_timeout_exception","reason":"failed to process cluster event (put-mapping) within 30s"},"status":503}`)
	}))
	defer busy.Close()
	// Too slow: takes the request and answers nothing in time.
	stall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer stall.Close()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()

	for _, c := range []struct {
		name    string
		cfg     Config
		ok      bool
		problem string
		message string
	}{
		{"connected", Config{URL: plain.URL, Username: "signalith", Password: secrets.New("opensearch.password", "right")}, true, "", `Connected to OpenSearch 2.15.0, cluster "prod". Health: yellow.`},
		{"no password", Config{URL: plain.URL}, false, "auth", "asks for a username and password"},
		{"wrong password", Config{URL: plain.URL, Username: "signalith", Password: secrets.New("opensearch.password", "wrong")}, false, "auth", "refused the username and password"},
		{"not opensearch", Config{URL: other.URL}, false, "not_opensearch", "it is not OpenSearch"},
		{"endless answer", Config{URL: huge.URL}, false, "not_opensearch", "far more than OpenSearch would"},
		{"endless health", Config{URL: hugeHealth.URL}, false, "not_opensearch", "far more than OpenSearch would"},
		{"password in the address", Config{URL: strings.Replace(plain.URL, "http://", "http://signalith:right@", 1)}, true, "", "Health: yellow"},
		{"nothing there", Config{URL: "http://" + closed}, false, "unreachable", "Nothing answered at " + closed},
		{"self-signed", Config{URL: secure.URL}, false, "tls", "does not trust its certificate"},
		{"skip verify", Config{URL: secure.URL, TLSSkipVerify: true}, true, "", "Health: yellow"},
		{"https to http", Config{URL: strings.Replace(plain.URL, "http://", "https://", 1)}, false, "http", "does not use HTTPS"},
		{"http to https", Config{URL: strings.Replace(secure.URL, "https://", "http://", 1)}, false, "http", "uses HTTPS. Start the address with https://"},
		{"security not loaded", Config{URL: notInit.URL, Username: "signalith", Password: secrets.New("opensearch.password", "right")}, false, "not_initialized",
			"OpenSearch is running, but its security settings aren't loaded, so it refuses every request, whatever the sign-in. " +
				"If OpenSearch started only a few minutes ago, wait: it loads them as it starts. " +
				"Otherwise, with the Docker quick start, run docker compose -f deploy/docker/docker-compose.yml up -d again from the Signalith folder: " +
				"it re-runs the step that loads OpenSearch's security settings."},
		{"no answer in time", Config{URL: stall.URL, Timeout: 200 * time.Millisecond}, false, "timeout",
			"OpenSearch at " + strings.TrimPrefix(stall.URL, "http://") + " took the request but didn't answer within 10 seconds. It may be starting, or too busy: test again in a minute. " +
				"If this lasts more than a few minutes, check that OpenSearch's computer has enough memory and CPU"},
		{"busy", Config{URL: busy.URL}, false, "busy", "OpenSearch answered, but is too busy to do the request in time (503: process_cluster_event_timeout_exception: failed to process cluster event (put-mapping) within 30s). Test again in a minute."},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep := Check(ctx, c.cfg)
			if rep.OK != c.ok || c.problem != "" && rep.Problem != c.problem || !strings.Contains(rep.Message, c.message) {
				t.Errorf("%+v", rep)
			}
			if !rep.OK && rep.Message == "" {
				t.Errorf("no message: %+v", rep)
			}
			if strings.Contains(rep.Message, "..") || strings.Contains(rep.Message, "right to") {
				t.Errorf("message %q", rep.Message)
			}
			if strings.Contains(rep.URL+rep.Message, "right") {
				t.Errorf("the report shows the password: %+v", rep)
			}
		})
	}
}
