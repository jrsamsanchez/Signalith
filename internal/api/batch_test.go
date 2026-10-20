// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// safeBulk counts what it is sent and may take a while to answer.
type safeBulk struct {
	mu    sync.Mutex
	n     int
	delay time.Duration
}

func (b *safeBulk) Bulk(ctx context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	time.Sleep(b.delay)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.n += len(docs)
	return nil, nil
}

func (b *safeBulk) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.n
}

// shortBatchDeadlines shortens the agent batch deadlines for one test.
func shortBatchDeadlines(t *testing.T, read, window, max time.Duration, progress int64) {
	old := []any{ingestReadTimeout, ingestProgressWindow, ingestMaxReadTime, ingestProgressBytes, ingestQueueWait}
	ingestReadTimeout, ingestProgressWindow, ingestMaxReadTime, ingestProgressBytes = read, window, max, progress
	ingestQueueWait = 300 * time.Millisecond
	t.Cleanup(func() {
		ingestReadTimeout, ingestProgressWindow, ingestMaxReadTime = old[0].(time.Duration), old[1].(time.Duration), old[2].(time.Duration)
		ingestProgressBytes, ingestQueueWait = old[3].(int64), old[4].(time.Duration)
	})
}

const sshLine = `{"log":"Oct 11 09:15:02 web1 sshd[811]: Failed password for bob from 192.0.2.4 port 1 ssh2"}`

// batch returns a JSON array of n sshd records.
func batch(n int) string {
	return "[" + strings.TrimSuffix(strings.Repeat(sshLine+",", n), ",") + "]"
}

func ingestHead(n int) string {
	return "POST /api/ingest HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer tok-0123456789abcdef\r\nX-Signalith-Tag: linux.auth\r\n" +
		"Content-Type: application/json\r\nContent-Length: " + fmt.Sprint(n) + "\r\n\r\n"
}

// TestSlowSendersDoNotHoldPipelineSlots reproduces the regression in the
// dos-1 fix: anyone with the ingest token opened more slow connections
// than there are pipeline slots, each trickling a large body, and every
// other agent got 503 until the deadline cut them off. Batches are now
// read before a slot is taken, so a slow sender holds no slot.
func TestSlowSendersDoNotHoldPipelineSlots(t *testing.T) {
	shortBatchDeadlines(t, time.Minute, time.Minute, time.Minute, 16<<10)
	bulk := &safeBulk{}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Pipeline = &ingest.Pipeline{Store: bulk, MaxConcurrent: 2} })
	for range 6 {
		c, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		io.WriteString(c, ingestHead(16_000_000)+`[{"log":"slow`)
	}
	time.Sleep(200 * time.Millisecond) // let the slow requests reach the handler
	start := time.Now()
	code, out, _ := postIngest(t, ts, []byte(batch(3)))
	if code != 200 || time.Since(start) > 2*time.Second {
		t.Errorf("an agent's batch while 6 slow senders were connected: %d %v after %v", code, out, time.Since(start))
	}
	if bulk.count() != 3 {
		t.Errorf("%d events written", bulk.count())
	}
}

// TestSteadyButSlowBatchGetsMoreTime: a batch over a slow link that keeps
// arriving gets past the first deadline (a 1.26 MB batch at 10 KB/s once
// got a raw "i/o timeout" 400 after two minutes).
func TestSteadyButSlowBatchGetsMoreTime(t *testing.T) {
	shortBatchDeadlines(t, 300*time.Millisecond, 300*time.Millisecond, 10*time.Second, 200)
	bulk := &safeBulk{}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Pipeline = &ingest.Pipeline{Store: bulk} })
	body := batch(12) // about 1.3 KB, sent over about 1.3 seconds
	c, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, ingestHead(len(body)))
	for i := 0; i < len(body); i += 100 {
		io.WriteString(c, body[i:min(i+100, len(body))])
		time.Sleep(100 * time.Millisecond)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || bulk.count() != 12 {
		t.Errorf("%d %s, %d written", resp.StatusCode, b, bulk.count())
	}
}

// TestStalledBatchIsCutOffWithAClearMessage: a sender that stops part way,
// or keeps a batch arriving past the longest allowed time, gets 408 with
// a message saying what to change, and the server logs it.
func TestStalledBatchIsCutOffWithAClearMessage(t *testing.T) {
	shortBatchDeadlines(t, 300*time.Millisecond, 200*time.Millisecond, 1500*time.Millisecond, 100)
	var logs syncBuffer
	lastSlowBatchWarning.Store(0)
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Pipeline = &ingest.Pipeline{Store: &safeBulk{}}
		s.Log = slog.New(slog.NewTextHandler(&logs, nil))
	})
	for _, c := range []struct {
		name  string
		pause time.Duration // between 60-byte pieces
		took  time.Duration // roughly when it should be cut off
	}{
		{"stalls after the first bytes", time.Hour, 300 * time.Millisecond},
		{"keeps coming, but for too long", 50 * time.Millisecond, 1500 * time.Millisecond},
	} {
		conn, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		io.WriteString(conn, ingestHead(1_000_000))
		replies := make(chan *http.Response, 1)
		go func() {
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				resp = nil
			}
			replies <- resp
		}()
		var resp *http.Response
	send:
		for {
			select {
			case resp = <-replies:
				break send
			case <-time.After(min(c.pause, 5*time.Second)):
				if time.Since(start) > 5*time.Second {
					break send
				}
				io.WriteString(conn, strings.Repeat(" ", 60))
			}
		}
		took := time.Since(start)
		if resp == nil {
			t.Fatalf("%s: no reply after %v", c.name, took)
		}
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusRequestTimeout || !strings.Contains(string(b), "took too long to arrive") ||
			!strings.Contains(string(b), "Send smaller batches") || strings.Contains(string(b), "i/o timeout") {
			t.Errorf("%s: %d %s", c.name, resp.StatusCode, b)
		}
		if took < c.took-100*time.Millisecond || took > c.took+time.Second {
			t.Errorf("%s: cut off after %v, want about %v", c.name, took, c.took)
		}
		conn.Close()
	}
	if strings.Count(logs.String(), "took too long to arrive") != 1 {
		t.Errorf("log (one line a minute at most): %s", logs.String())
	}
}

// TestSlowWriteAfterTheBatchArrived: once the whole batch is in, writing
// it may take longer than the read deadline without being cut off.
func TestSlowWriteAfterTheBatchArrived(t *testing.T) {
	shortBatchDeadlines(t, 200*time.Millisecond, 200*time.Millisecond, 200*time.Millisecond, 100)
	bulk := &safeBulk{delay: 700 * time.Millisecond}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Pipeline = &ingest.Pipeline{Store: bulk} })
	if code, out, _ := postIngest(t, ts, []byte(batch(2))); code != 200 || bulk.count() != 2 {
		t.Errorf("%d %v", code, out)
	}
}

// TestOneSenderGetsAShareOfIngestMemory: one sender (here a token holder
// with many slow connections) cannot take all the memory for batches
// arriving; other senders, and many agents behind a listed shared
// address, still get through.
func TestOneSenderGetsAShareOfIngestMemory(t *testing.T) {
	for _, shared := range []bool{false, true} {
		bulk := &safeBulk{}
		ts, _ := newTestServerWith(t, func(s *Server) {
			s.Pipeline = &ingest.Pipeline{Store: bulk, MaxReceiving: 512 << 10}
			if shared {
				s.Config.Server.SharedAddresses = []string{"203.0.113.0/24"}
			}
		})
		h := ts.Config.Handler
		send := func(from string, body io.Reader, length int64) *httptest.ResponseRecorder {
			req := httptest.NewRequest("POST", "/api/ingest", body)
			req.ContentLength = length
			req.RemoteAddr = from
			req.Header.Set("Authorization", "Bearer tok-0123456789abcdef")
			req.Header.Set("X-Signalith-Tag", "linux.auth")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			return w
		}
		// A batch still arriving holds this sender's whole share (128 KB).
		pr, pw := io.Pipe()
		held := make(chan *httptest.ResponseRecorder, 1)
		go func() { held <- send("203.0.113.5:4000", pr, -1) }()
		pw.Write(bytes.Repeat([]byte(" "), 100<<10))

		small := batch(2)
		w := send("203.0.113.5:4001", strings.NewReader(small), int64(len(small)))
		if shared {
			if w.Code != 200 {
				t.Errorf("shared address: %d %s", w.Code, w.Body)
			}
		} else if w.Code != 503 || w.Header().Get("Retry-After") == "" || !strings.Contains(w.Body.String(), "this sender") {
			t.Errorf("same sender over its share: %d %v %s", w.Code, w.Header(), w.Body)
		}
		if w := send("198.51.100.7:4000", strings.NewReader(small), int64(len(small))); w.Code != 200 {
			t.Errorf("another sender (shared=%v): %d %s", shared, w.Code, w.Body)
		}
		pw.Write([]byte(batch(1)))
		pw.Close()
		if w := <-held; w.Code != 200 {
			t.Errorf("the slow batch, once complete: %d %s", w.Code, w.Body)
		}
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
