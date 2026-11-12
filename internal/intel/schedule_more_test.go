// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// syncBuf is a log buffer safe for the goroutines that log into it.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func bufLogger() (*slog.Logger, *syncBuf) {
	b := &syncBuf{}
	return slog.New(slog.NewTextHandler(b, nil)), b
}

func TestFingerprintChangesWithFeeds(t *testing.T) {
	_, base := newFeedHost(t, map[string]string{"/a.txt": "203.0.113.9\n"})
	cfg := Feed{Name: "cfg", URL: base + "/a.txt?key=secret", Format: FormatLines, Type: "auto", Interval: time.Hour, MaxAge: 24 * time.Hour, Weight: 1, Enabled: true,
		Headers: map[string]string{"X-B": "1", "X-A": "2"}}
	f := newTestFeeds(t, cfg)
	fp1 := f.Fingerprint()
	if !strings.HasPrefix(fp1, "sha256:") || fp1 != f.Fingerprint() {
		t.Fatalf("fingerprint %q is not stable", fp1)
	}
	if _, err := f.AddFeed(FeedInput{Name: "ui", URL: base + "/a.txt"}); err != nil {
		t.Fatal(err)
	}
	fp2 := f.Fingerprint()
	if fp2 == fp1 {
		t.Fatal("adding a feed did not change the fingerprint")
	}
	// A secret value alone does not show in it: only header names do.
	g := newTestFeeds(t, Feed{Name: "cfg", URL: base + "/a.txt?key=other", Format: FormatLines, Type: "auto", Interval: time.Hour, MaxAge: 24 * time.Hour, Weight: 1, Enabled: true,
		Headers: map[string]string{"x-a": "9", "x-b": "9"}})
	if g.Fingerprint() != fp1 {
		t.Error("a secret value or header case changed the fingerprint")
	}
	// An unreadable feeds file changes it.
	h := newTestFeeds(t, cfg)
	if err := os.WriteFile(h.File, []byte("feeds: [this is: not: yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	if h.Fingerprint() == fp1 {
		t.Error("an unreadable feeds file did not change the fingerprint")
	}
}

type keyedList struct {
	FeedList
	key []byte
}

func (k keyedList) ETagKey() []byte { return k.key }

func TestETag(t *testing.T) {
	ctx := context.Background()
	_, base := newFeedHost(t, map[string]string{"/a.txt": "203.0.113.9\n"})
	f := newTestFeeds(t, Feed{Name: "cfg", URL: base + "/a.txt", Format: FormatLines, Type: "auto", Interval: time.Hour, MaxAge: time.Hour, Weight: 1, Enabled: true})
	if _, ok := f.ETag("cfg"); ok {
		t.Error("a feed from signalith.yaml has an ETag")
	}
	if _, ok := f.ETag("none"); ok {
		t.Error("a missing feed has an ETag")
	}
	if _, err := f.AddFeed(FeedInput{Name: "ui", URL: base + "/a.txt", Username: "u", Password: "p4ssword"}); err != nil {
		t.Fatal(err)
	}
	e1, ok := f.ETag("ui")
	if !ok || !strings.HasPrefix(e1, `"f-`) || strings.Contains(e1, "p4ssword") {
		t.Fatalf("etag %q %v", e1, ok)
	}
	if e, _ := f.ETag("ui"); e != e1 {
		t.Error("etag not stable")
	}
	// A change with the old version goes through once, then is stale.
	in, _ := f.InputFor("ui")
	in.Description = "changed"
	if _, err := f.UpdateFeedIf(ctx, "", "ui", e1, in); err != nil {
		t.Fatal(err)
	}
	e2, _ := f.ETag("ui")
	if e2 == e1 {
		t.Error("etag did not change with the feed")
	}
	if _, err := f.UpdateFeedIf(ctx, "", "ui", e1, in); !errors.Is(err, ErrFeedStale) {
		t.Errorf("stale update: %v", err)
	}
	if _, err := f.RemoveFeedIf(ctx, "", "ui", e1, false); !errors.Is(err, ErrFeedStale) {
		t.Errorf("stale remove: %v", err)
	}
	// Re-entering the password changes it.
	in.Password = "an0ther"
	if _, err := f.UpdateFeedIf(ctx, "", "ui", e2, in); err != nil {
		t.Fatal(err)
	}
	if e3, _ := f.ETag("ui"); e3 == e2 {
		t.Error("a new password kept the etag")
	}

	// Two lists keyed the same agree on versions.
	spec := FeedSpec{Name: "x", URL: "https://example.com/a"}
	a := &Feeds{Saved: keyedList{key: []byte("shared")}}
	b := &Feeds{Saved: keyedList{key: []byte("shared")}}
	c := &Feeds{Saved: keyedList{}}
	if specETag(a.etagKey(), spec) != specETag(b.etagKey(), spec) {
		t.Error("shared key gave different etags")
	}
	if specETag(c.etagKey(), spec) == specETag(a.etagKey(), spec) || len(c.etagKey()) != 32 {
		t.Error("an empty shared key was used")
	}
}

func TestStartRunsTheSchedule(t *testing.T) {
	host, base := newFeedHost(t, map[string]string{"/a.txt": "203.0.113.9\n203.0.113.10\n"})
	f := newTestFeeds(t, Feed{Name: "cfg", URL: base + "/a.txt", Format: FormatLines, Type: "auto", Interval: time.Hour, MaxAge: 24 * time.Hour, Weight: 1, Enabled: true})
	// An indicator of a feed that is gone is removed when the run starts.
	if _, _, err := f.Store.ReplaceSource(context.Background(), "old-feed", []Indicator{{Type: "ip", Value: "198.51.100.7"}}); err != nil {
		t.Fatal(err)
	}
	log, logs := bufLogger()
	f.Log = log
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Start(ctx); close(done) }()
	eventually(t, "the feed to download", func() bool { return f.Store.CountSource("cfg") == 2 })
	eventually(t, "Running", f.Running)
	if f.Store.CountSource("old-feed") != 0 {
		t.Error("indicators of a removed feed were kept")
	}
	if !strings.Contains(logs.String(), "removed indicators of feeds that are no longer configured") {
		t.Errorf("logs: %s", logs)
	}
	// Adding a feed while it runs downloads it at once.
	host.set("/b.txt", "198.51.100.20\n")
	if _, err := f.AddFeed(FeedInput{Name: "ui", URL: base + "/b.txt"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the added feed to download", func() bool { return f.Store.CountSource("ui") == 1 })
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return")
	}
	if f.Running() {
		t.Error("still running after Start returned")
	}
}

func TestStartWaitsForIndicators(t *testing.T) {
	be := &failBackend{Memory: NewMemory(), all: errors.New("opensearch down")}
	log, logs := bufLogger()
	f := &Feeds{Store: NewStore(be), Log: log}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	f.Start(ctx)
	if !strings.Contains(logs.String(), "waiting to read threat intel indicators") || f.Running() {
		t.Errorf("logs: %s", logs)
	}
}

func TestStartReportsCleanUpFailures(t *testing.T) {
	be := &failBackend{Memory: NewMemory()}
	s := NewStore(be)
	ctx := context.Background()
	if err := s.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReplaceSource(ctx, "gone", []Indicator{{Type: "ip", Value: "198.51.100.7", Expires: time.Now().Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	be.del = errors.New("delete refused")
	log, logs := bufLogger()
	f := &Feeds{Store: s, Log: log, Tick: 20 * time.Millisecond}
	// An expired indicator to purge, which fails too.
	s.Now = func() time.Time { return time.Now().Add(1000 * time.Hour) }
	rctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	f.Start(rctx)
	out := logs.String()
	if !strings.Contains(out, "could not remove indicators of removed or disabled feeds") {
		t.Errorf("logs: %s", out)
	}
	if !strings.Contains(out, "could not purge expired indicators") {
		t.Errorf("logs: %s", out)
	}
	// Not allowed: nothing is touched.
	be.del = nil
	f2 := &Feeds{Store: s, Allowed: func() bool { return false }, Tick: 20 * time.Millisecond, Log: log}
	rctx2, cancel2 := context.WithTimeout(ctx, 60*time.Millisecond)
	defer cancel2()
	f2.Start(rctx2)
	if s.CountSource("gone") != 1 {
		t.Error("a server not allowed to run the schedule removed indicators")
	}
}

// verBackend is a Memory whose Version fails while fail is set.
type verBackend struct {
	*Memory
	fail atomic.Bool
}

func (b *verBackend) Version(ctx context.Context) (string, error) {
	if b.fail.Load() {
		return "", errors.New("version unreadable")
	}
	return b.Memory.Version(ctx)
}

func TestWatch(t *testing.T) {
	be := &verBackend{Memory: NewMemory()}
	s := NewStore(be)
	log, logs := bufLogger()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Watch(ctx, 0, log); close(done) }()
	eventually(t, "the first load", s.Loaded)
	// Another server's write shows up after a wake.
	if err := be.Memory.Put(ctx, []Indicator{{ID: "x", Type: "ip", Value: "203.0.113.5", Source: ManualSource}}); err != nil {
		t.Fatal(err)
	}
	s.Wake()
	eventually(t, "the other server's indicator", func() bool { return s.Summary().Total == 1 })
	be.fail.Store(true)
	s.Wake()
	eventually(t, "the warning", func() bool { return strings.Contains(logs.String(), "could not read threat intel indicators") })
	cancel()
	<-done
	if !strings.Contains(logs.String(), "threat intel indicators loaded") {
		t.Errorf("logs: %s", logs)
	}
}

func TestDownloadClientAndOrigins(t *testing.T) {
	var got http.Header
	var hits int
	var mu sync.Mutex
	other := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		hits++
		mu.Unlock()
		io.WriteString(w, "ok")
	})
	// Redirect to a different port: another origin.
	first := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/x", http.StatusFound)
	})
	c := NewDownloadClient(true, nil)
	ctx := WithSecretHeaders(context.Background(), "X-Key")
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, first.URL, nil)
	req.Header.Set("X-Key", "s3cret")
	req.Header.Set("X-Plain", "v")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if hits != 1 || got.Get("X-Key") != "" || got.Get("X-Plain") != "v" {
		t.Errorf("headers after redirect: %v", got)
	}
	// Loopback refused when not allowed.
	if _, err := NewDownloadClient(false, nil).Get(other.URL); err == nil {
		t.Error("loopback allowed")
	}

	u := func(s string) *url.URL { p, _ := url.Parse(s); return p }
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"https://a.example/x", "https://A.example./y", true},
		{"http://a.example/x", "https://a.example/y", true},
		{"http://a.example:8080/x", "https://a.example/y", false},
		{"https://a.example/x", "http://a.example/y", false},
		{"https://a.example/x", "https://b.example/y", false},
		{"https://a.example:443/x", "https://a.example:8443/y", false},
	} {
		if got := SameOrigin(u(c.a), u(c.b)); got != c.want {
			t.Errorf("SameOrigin(%s, %s) = %v", c.a, c.b, got)
		}
	}
}

func TestSmallHelpers(t *testing.T) {
	if (&HTTPError{Code: 404, Status: "404 Not Found"}).Error() != "the server answered 404 Not Found" {
		t.Error("HTTPError")
	}
	inner := os.ErrPermission
	fe := &FileError{Path: "f.yaml", Err: inner}
	if !errors.Is(fe, os.ErrPermission) || !strings.Contains(fe.Error(), "f.yaml") {
		t.Error("FileError does not unwrap")
	}
	for d, want := range map[time.Duration]string{0: "the time allowed", 30 * time.Second: "30 seconds", time.Minute: "a minute", 5 * time.Minute: "5 minutes"} {
		if got := fmtWait(d); got != want {
			t.Errorf("fmtWait(%v) = %q", d, got)
		}
	}
	for d, want := range map[time.Duration]string{0: "", 48 * time.Hour: "2d", 3 * time.Hour: "3h", 90 * time.Minute: "90m"} {
		if got := fmtDuration(d); got != want {
			t.Errorf("fmtDuration(%v) = %q", d, got)
		}
	}
	if plural(1, "page") != "1 page" || plural(3, "page") != "3 pages" {
		t.Error("plural")
	}
	if !slow(context.DeadlineExceeded) || !slow(&net.DNSError{IsTimeout: true}) || slow(errors.New("x")) {
		t.Error("slow")
	}
	for _, c := range []struct{ obj, path, want string }{
		{"ipv4-addr", "value", "ip"},
		{"ipv6-addr", "other", ""},
		{"domain-name", "value", TypeDomain},
		{"domain-name", "x", ""},
		{"url", "value", TypeURL},
		{"url", "x", ""},
		{"email-addr", "value", TypeEmail},
		{"email-addr", "x", ""},
		{"email-message", "from_ref.value", TypeEmail},
		{"email-message", "sender_ref.value", TypeEmail},
		{"email-message", "body", ""},
		{"file", "hashes.'SHA-256'", TypeSHA256},
		{"artifact", "hashes.sha1", TypeSHA1},
		{"file", "hashes.MD5", TypeMD5},
		{"file", "name", ""},
		{"process", "pid", ""},
	} {
		if got := stixType(c.obj, c.path); got != c.want {
			t.Errorf("stixType(%s, %s) = %q, want %q", c.obj, c.path, got, c.want)
		}
	}
	for _, c := range []struct {
		in   string
		n    int
		fail bool
	}{
		{`[{"type":"indicator","id":"a"}]`, 1, false},
		{`[not json`, 0, true},
		{`{"type":"indicator","id":"a","pattern":"[ipv4-addr:value = '203.0.113.1']"}`, 1, false},
		{`{"type":"bundle","objects":[]}`, 0, false},
		{`{"type":"malware"}`, 0, true},
		{`{nope`, 0, true},
	} {
		objs, err := decodeSTIX([]byte(c.in))
		if (err != nil) != c.fail || len(objs) != c.n {
			t.Errorf("decodeSTIX(%s) = %d %v", c.in, len(objs), err)
		}
	}
}
