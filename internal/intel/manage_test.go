// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// feedHost serves feed bodies by path and records the headers it got.
type feedHost struct {
	mu      sync.Mutex
	bodies  map[string]string
	headers http.Header
	hits    map[string]int
}

func newFeedHost(t *testing.T, bodies map[string]string) (*feedHost, string) {
	h := &feedHost{bodies: bodies, hits: map[string]int{}}
	srv := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.headers = r.Header.Clone()
		h.hits[r.URL.Path]++
		body, ok := h.bodies[r.URL.Path]
		switch {
		case r.URL.Path == "/needs-key" && r.Header.Get("X-Api-Key") != "k3y":
			http.Error(w, "missing key", http.StatusForbidden)
		case !ok:
			http.NotFound(w, r)
		case strings.HasPrefix(r.URL.Path, "/chunked"):
			w.Write([]byte(body)) // no Content-Length for large bodies
		default:
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.Write([]byte(body))
		}
	})
	return h, srv.URL
}

func (h *feedHost) set(path, body string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.bodies[path] = body
}

func (h *feedHost) header(name string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.headers.Get(name)
}

func newTestFeeds(t *testing.T, list ...Feed) *Feeds {
	t.Helper()
	s := NewStore(NewMemory())
	if err := s.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	return &Feeds{Store: s, List: list, AllowLoopback: true, Tick: 10 * time.Millisecond,
		File: filepath.Join(dir, "intel_feeds.yaml"), StatusFile: filepath.Join(dir, "intel_feeds.json")}
}

func on(b bool) *bool { return &b }

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestFeedsFilePersistence(t *testing.T) {
	_, base := newFeedHost(t, map[string]string{"/a.txt": "203.0.113.9\n"})
	cfg := Feed{Name: "from-config", URL: base + "/a.txt", Format: FormatLines, Type: "auto", Interval: time.Hour, MaxAge: 24 * time.Hour, Weight: 1, Enabled: true}
	f := newTestFeeds(t, cfg)
	v, err := f.AddFeed(FeedInput{Name: "my-feed", URL: base + "/a.txt", Interval: "2h", Weight: 1.5, Tags: []string{"x", " X ", ""},
		Headers: []HeaderInput{{Name: "X-Api-Key", Value: "k3y"}}, Username: "svc", Password: "pa55word"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Source != SourceUI || v.Format != FormatAuto || v.Type != "auto" || v.Interval != "2h" || v.MaxAge != "7d" ||
		len(v.Tags) != 1 || !v.Password.Set || len(v.Headers) != 1 || v.Headers[0] != (HeaderView{Name: "X-Api-Key", Set: true}) {
		t.Errorf("view = %+v", v)
	}
	// Written privately, with the secrets encrypted, through a temporary
	// file.
	info, err := os.Stat(f.File)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", info.Mode().Perm())
	}
	data, _ := os.ReadFile(f.File)
	if strings.Contains(string(data), "k3y") || strings.Contains(string(data), "pa55word") || strings.Count(string(data), "enc:v1:") != 2 ||
		!strings.Contains(string(data), "# Threat intel feeds added on the Threat intel page") {
		t.Errorf("file = %s", data)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(f.File), ".*.tmp")); len(left) > 0 {
		t.Errorf("temporary files left: %v", left)
	}

	// A restart reads the file and merges it after the config feeds.
	f2 := &Feeds{Store: f.Store, List: []Feed{cfg}, File: f.File}
	if err := f2.Load(); err != nil {
		t.Fatal(err)
	}
	list := f2.Status()
	if len(list) != 2 || list[0].Name != "from-config" || list[0].Source != SourceConfig || list[1].Name != "my-feed" || list[1].Source != SourceUI {
		t.Fatalf("merged = %+v", list)
	}
	got, _ := f2.Get("my-feed")
	if got.Headers["X-Api-Key"] != "k3y" || got.Username != "svc" || got.Password != "pa55word" || got.Interval != 2*time.Hour {
		t.Errorf("reloaded = %+v", got)
	}

	// Names are unique across both, and checked like config feeds.
	_, err = f2.AddFeed(FeedInput{Name: "from-config", URL: base})
	var ie *InputError
	if !errors.As(err, &ie) || !strings.Contains(ie.Fields()["name"], "signalith.yaml") {
		t.Errorf("config name = %v", err)
	}
	_, err = f2.AddFeed(FeedInput{Name: "my-feed", URL: base})
	if !errors.As(err, &ie) || !strings.Contains(ie.Fields()["name"], "already exists") {
		t.Errorf("duplicate name = %v", err)
	}
	_, err = f2.AddFeed(FeedInput{Name: "Bad Name", URL: "ftp://x", Interval: "1m", Weight: 20, Format: "xml", Kind: "rss",
		Username: "", Password: "p"})
	if !errors.As(err, &ie) {
		t.Fatalf("invalid = %v", err)
	}
	for _, field := range []string{"name", "url", "interval", "weight", "format", "kind", "username"} {
		if ie.Fields()[field] == "" {
			t.Errorf("no problem reported for %s: %v", field, ie.Messages())
		}
	}
	_, err = f2.AddFeed(FeedInput{Name: "creds", URL: "https://user:pw@feeds.example/x"})
	if !errors.As(err, &ie) || !strings.Contains(ie.Fields()["url"], "username and password settings") {
		t.Errorf("credentials in URL = %v", err)
	}
	if strings.Contains(err.Error(), "pw@") {
		t.Errorf("error shows the password: %v", err)
	}

	// Feeds from signalith.yaml cannot be changed here.
	if _, err := f2.UpdateFeed(context.Background(), "from-config", FeedInput{}); !errors.Is(err, ErrReadOnly) {
		t.Errorf("update config feed = %v", err)
	}
	if _, err := f2.RemoveFeed(context.Background(), "from-config", true); !errors.Is(err, ErrReadOnly) {
		t.Errorf("delete config feed = %v", err)
	}
	if _, err := f2.RemoveFeed(context.Background(), "nope", true); !errors.Is(err, ErrUnknownFeed) {
		t.Errorf("delete unknown = %v", err)
	}

	// A file feed whose name signalith.yaml now uses is shown with the
	// problem and never downloaded.
	f3 := &Feeds{Store: f.Store, List: []Feed{cfg, {Name: "my-feed", URL: base, Interval: time.Hour, Enabled: true}}, File: f.File, AllowLoopback: true}
	list = f3.Status()
	if len(list) != 3 || list[2].Problem == "" || list[1].Problem != "" {
		t.Errorf("shadowed = %+v", list)
	}
	if _, err := f3.RemoveFeed(context.Background(), "my-feed", true); err != nil {
		t.Errorf("deleting the shadowed copy = %v", err)
	}
	if f3.Len() != 2 {
		t.Errorf("after deleting the copy: %d feeds", f3.Len())
	}
}

func TestUpdateKeepsSecrets(t *testing.T) {
	ctx := context.Background()
	_, base := newFeedHost(t, map[string]string{})
	f := newTestFeeds(t)
	if _, err := f.AddFeed(FeedInput{Name: "keyed", URL: base + "/needs-key", Headers: []HeaderInput{{Name: "X-Api-Key", Value: "k3y"}, {Name: "X-Other", Value: "o"}},
		Username: "svc", Password: "pa55word"}); err != nil {
		t.Fatal(err)
	}
	update := func(change func(*FeedInput)) Feed {
		t.Helper()
		in, ok := f.InputFor("keyed")
		if !ok {
			t.Fatal("no input")
		}
		if in.Password != "" || in.Headers != nil {
			t.Fatalf("InputFor leaks secrets: %+v", in)
		}
		change(&in)
		if _, err := f.UpdateFeed(ctx, "keyed", in); err != nil {
			t.Fatal(err)
		}
		fd, _ := f.Get("keyed")
		return fd
	}
	// Omitted and empty secrets keep their stored values.
	fd := update(func(in *FeedInput) { in.Description = "changed"; in.Headers = []HeaderInput{{Name: "x-api-key"}} })
	if fd.Headers["X-Api-Key"] != "k3y" || fd.Headers["X-Other"] != "o" || fd.Password != "pa55word" || fd.Description != "changed" {
		t.Errorf("kept = %+v", fd)
	}
	// A new value replaces, clear removes.
	fd = update(func(in *FeedInput) {
		in.Headers = []HeaderInput{{Name: "X-Api-Key", Value: "n3w"}, {Name: "X-Other", Clear: true}}
		in.ClearPassword = true
	})
	if fd.Headers["X-Api-Key"] != "n3w" || len(fd.Headers) != 1 || fd.Password != "" {
		t.Errorf("replaced = %+v", fd)
	}
	// A header named without a value it does not have yet is a problem.
	in, _ := f.InputFor("keyed")
	in.Headers = []HeaderInput{{Name: "X-New"}}
	var ie *InputError
	if _, err := f.UpdateFeed(ctx, "keyed", in); !errors.As(err, &ie) || !strings.Contains(err.Error(), "enter a value for header X-New") {
		t.Errorf("empty new header = %v", err)
	}
	// Names cannot change.
	in, _ = f.InputFor("keyed")
	in.Name = "other"
	if _, err := f.UpdateFeed(ctx, "keyed", in); !errors.As(err, &ie) || ie.Fields()["name"] == "" {
		t.Errorf("rename = %v", err)
	}
	// Removing the user name removes the password with it.
	fd = update(func(in *FeedInput) { in.Password = "again" })
	if fd.Password != "again" {
		t.Errorf("password = %q", fd.Password)
	}
	// Saved secrets only go to the server they were entered for: pointing
	// the feed, or a test of it, at another server needs them again.
	elsewhere := strings.Replace(base, "127.0.0.1", "localhost", 1) + "/needs-key"
	in, _ = f.InputFor("keyed")
	in.URL = elsewhere
	_, err := f.UpdateFeed(ctx, "keyed", in)
	if !errors.As(err, &ie) || ie.Fields()["password"] == "" || !strings.Contains(ie.Fields()["headers"], "header X-Api-Key again") {
		t.Errorf("moved = %v", err)
	}
	if res, err := f.TestFeed(ctx, in, "keyed"); res != nil || !errors.As(err, &ie) {
		t.Errorf("test against another server = %+v %v", res, err)
	}
	in.Headers = []HeaderInput{{Name: "X-Api-Key", Clear: true}}
	in.ClearPassword = true
	if _, err := f.TestFeed(ctx, in, "keyed"); err != nil {
		t.Errorf("test against another server without the secrets = %v", err)
	}
	fd = update(func(in *FeedInput) {
		in.URL = elsewhere
		in.Headers = []HeaderInput{{Name: "X-Api-Key", Value: "n3w"}}
		in.Password = "again"
	})
	if fd.URL != elsewhere || fd.Headers["X-Api-Key"] != "n3w" || fd.Password != "again" {
		t.Errorf("moved with the secrets entered again = %+v", fd)
	}
	// Another path on the same server keeps them.
	fd = update(func(in *FeedInput) { in.URL = strings.Replace(elsewhere, "localhost", "LocalHost", 1) + "?v=2" })
	if fd.Headers["X-Api-Key"] != "n3w" || fd.Password != "again" {
		t.Errorf("same server = %+v", fd)
	}
	fd = update(func(in *FeedInput) { in.Username = "" })
	if fd.Password != "" || fd.Username != "" {
		t.Errorf("no user = %+v", fd)
	}
	// Feeds added on the page never read the environment.
	t.Setenv("SIGNALITH_TEST_SECRET", "server-secret")
	fd = update(func(in *FeedInput) {
		in.Headers = []HeaderInput{{Name: "X-Api-Key", Value: "${SIGNALITH_TEST_SECRET}"}}
	})
	if fd.expand(fd.Headers["X-Api-Key"]) != "${SIGNALITH_TEST_SECRET}" {
		t.Error("a page feed expanded an environment variable")
	}
	if (Feed{}).expand("${SIGNALITH_TEST_SECRET}") != "server-secret" {
		t.Error("a config feed did not expand an environment variable")
	}
}

func TestFeedsLiveChanges(t *testing.T) {
	host, base := newFeedHost(t, map[string]string{
		"/one.txt": "203.0.113.1\n203.0.113.2\n",
		"/two.txt": "198.51.100.9\n",
	})
	f := newTestFeeds(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { f.Start(ctx); close(done) }()
	eventually(t, "the runner to start", f.Running)

	// A new feed downloads right away.
	if _, err := f.AddFeed(FeedInput{Name: "live", URL: base + "/one.txt"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the new feed's indicators", func() bool { return f.Store.CountSource("live") == 2 })
	eventually(t, "the status", func() bool { v, _ := f.View("live"); return v.Status.Count == 2 && !v.Status.Running })
	v, _ := f.View("live")
	if v.Format != FormatAuto || v.Status.LastSuccess.IsZero() {
		t.Errorf("view = %+v", v)
	}

	// An edit downloads again with the new settings.
	in, _ := f.InputFor("live")
	in.URL = base + "/two.txt"
	in.Weight = 2
	if _, err := f.UpdateFeed(ctx, "live", in); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the edited feed's indicators", func() bool {
		m := f.Store.Lookup("198.51.100.9")
		return f.Store.CountSource("live") == 1 && len(m) == 1 && m[0].Weight == 2
	})

	// Turning it off removes its indicators and stops downloads.
	in, _ = f.InputFor("live")
	in.Enabled = on(false)
	if v, err := f.UpdateFeed(ctx, "live", in); err != nil || v.Enabled || v.Indicators != 0 || f.Store.CountSource("live") != 0 {
		t.Fatalf("turn off = %+v %v", v, err)
	}
	host.mu.Lock()
	hits := host.hits["/two.txt"]
	host.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	host.mu.Lock()
	if host.hits["/two.txt"] != hits {
		t.Error("a feed that is off was downloaded")
	}
	host.mu.Unlock()

	// On again, then deleted with its indicators kept: they stay until
	// max_age, also across a restart.
	in.Enabled = on(true)
	if _, err := f.UpdateFeed(ctx, "live", in); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the feed back on", func() bool { return f.Store.CountSource("live") == 1 })
	if n, err := f.RemoveFeed(ctx, "live", false); err != nil || n != 0 {
		t.Fatalf("delete keep = %d %v", n, err)
	}
	if _, ok := f.View("live"); ok || f.Store.CountSource("live") != 1 {
		t.Errorf("after delete keep: %d indicators", f.Store.CountSource("live"))
	}
	data, _ := os.ReadFile(f.File)
	if !strings.Contains(string(data), "kept:") || !strings.Contains(string(data), "name: live") {
		t.Errorf("kept list = %s", data)
	}
	cancel()
	<-done
	restart := &Feeds{Store: f.Store, File: f.File, Tick: time.Hour, AllowLoopback: true}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() { restart.Start(ctx2); close(done2) }()
	eventually(t, "the restarted runner", restart.Running)
	cancel2()
	<-done2
	if f.Store.CountSource("live") != 1 {
		t.Error("a restart removed indicators that were kept")
	}

	// Deleted with its indicators removed.
	if _, err := restart.AddFeed(FeedInput{Name: "gone", URL: base + "/one.txt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := restart.Refresh(context.Background(), "gone"); err != nil {
		t.Fatal(err)
	}
	if n, err := restart.RemoveFeed(context.Background(), "gone", true); err != nil || n != 2 || f.Store.CountSource("gone") != 0 {
		t.Errorf("delete remove = %d %v", n, err)
	}
	if _, err := restart.Refresh(context.Background(), "gone"); !errors.Is(err, ErrUnknownFeed) {
		t.Errorf("refresh deleted = %v", err)
	}
}

func TestFeedsFileUnreadable(t *testing.T) {
	f := newTestFeeds(t)
	if err := os.WriteFile(f.File, []byte("feeds: [this is: not: yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.Store.Add(context.Background(), []Indicator{{Type: TypeIP, Value: "203.0.113.5", Source: "page-feed"}}); err != nil {
		t.Fatal(err)
	}
	var fe *FileError
	if err := f.Load(); !errors.As(err, &fe) || !strings.Contains(err.Error(), "Fix or delete it") {
		t.Fatalf("load = %v", err)
	}
	if _, err := f.AddFeed(FeedInput{Name: "x", URL: "https://feeds.example/x"}); !errors.As(err, &fe) {
		t.Errorf("add with a bad file = %v", err)
	}
	// The bad file is not overwritten, and its feeds' indicators stay.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Start(ctx); close(done) }()
	eventually(t, "the runner", f.Running)
	cancel()
	<-done
	if data, _ := os.ReadFile(f.File); string(data) != "feeds: [this is: not: yaml" || f.Store.CountSource("page-feed") != 1 {
		t.Errorf("file = %q, indicators %d", data, f.Store.CountSource("page-feed"))
	}
}

func TestTestFeed(t *testing.T) {
	ctx := context.Background()
	host, base := newFeedHost(t, map[string]string{
		"/ips.txt":         "# list\n203.0.113.1\n203.0.113.2\n10.0.0.1\nnot an ip\n",
		"/feed.csv":        "first_seen_utc,dst_ip,dst_port,malware\n2026-10-01,203.0.113.9,443,QakBot\n2026-10-02,198.51.100.4,80,Pikabot\n",
		"/big.txt":         strings.Repeat("203.0.113.1\n", 2000),
		"/chunked-big.txt": strings.Repeat("203.0.113.1\n", 2000),
		"/page":            "<!DOCTYPE html><html><head><title>Downloads</title></head><body>Feeds</body></html>",
		"/json":            `{"results":[{"ip":"203.0.113.1"}]}`,
		"/junk":            "lorem\nipsum\n",
		"/needs-key":       "203.0.113.77\n",
	})
	f := newTestFeeds(t)
	res, err := f.TestFeed(ctx, FeedInput{URL: base + "/ips.txt"}, "")
	if err != nil || !res.OK || res.Format != FormatLines || res.Type != TypeIP || res.Total != 2 || res.ByType[TypeIP] != 2 ||
		res.Skipped != 1 || res.Reserved != 1 || len(res.Samples) != 2 || res.Samples[0].Value != "203.0.113.1" {
		t.Errorf("lines = %+v %v", res, err)
	}
	// Auto finds the CSV column, so the form can fill it in.
	res, _ = f.TestFeed(ctx, FeedInput{URL: base + "/feed.csv"}, "")
	if !res.OK || res.Format != FormatCSV || res.Column != "dst_ip" || res.Type != TypeIP || res.Total != 2 {
		t.Errorf("csv = %+v", res)
	}
	// Nothing is saved.
	if f.Len() != 0 || f.Store.Summary().Total != 0 {
		t.Error("a test saved something")
	}
	cases := map[string]string{
		"/needs-key": "The server answered 403 Forbidden. This feed may need an API key.",
		"/missing":   "The server answered 404 Not Found. Check the URL.",
		"/page":      "web page, not a feed",
		"/json":      "JSON that is not STIX 2.1",
		"/junk":      `None of the 2 values were valid indicators (the first was "lorem")`,
	}
	for path, want := range cases {
		res, err := f.TestFeed(ctx, FeedInput{URL: base + path}, "")
		if err != nil || res.OK || !strings.Contains(res.Error, want) {
			t.Errorf("%s = %+v %v, want %q", path, res, err, want)
		}
	}
	if res, _ := f.TestFeed(ctx, FeedInput{URL: base + "/needs-key"}, ""); res.HTTPStatus != 403 {
		t.Errorf("status = %d", res.HTTPStatus)
	}
	// Too big for a download is refused; too big to preview is checked in part.
	small := newTestFeeds(t)
	small.MaxBytes = 1000
	if res, _ := small.TestFeed(ctx, FeedInput{URL: base + "/big.txt"}, ""); res.OK || !strings.Contains(res.Error, "larger than 1 KB") {
		t.Errorf("too big = %+v", res)
	}
	if _, _, _, err := small.download(ctx, Feed{Name: "big", URL: base + "/big.txt", Format: FormatLines, Type: "auto"}, time.Now(), 0); err == nil ||
		!strings.Contains(err.Error(), "larger than 1 KB") {
		t.Errorf("download too big = %v", err)
	}
	if _, _, _, err := small.download(ctx, Feed{Name: "big", URL: base + "/chunked-big.txt", Format: FormatLines, Type: "auto"}, time.Now(), 0); err == nil ||
		!strings.Contains(err.Error(), "larger than 1 KB") {
		t.Errorf("download too big without a length = %v", err)
	}
	if res, _ := small.TestFeed(ctx, FeedInput{URL: base + "/chunked-big.txt"}, ""); res.OK || !strings.Contains(res.Error, "larger than 1 KB") {
		t.Errorf("test too big without a length = %+v", res)
	}
	// A feed larger than a test reads, but small enough to download, is
	// previewed from its first part.
	defer func(n int64) { testMaxBytes = n }(testMaxBytes)
	testMaxBytes = 1000
	if res, _ := f.TestFeed(ctx, FeedInput{URL: base + "/chunked-big.txt"}, ""); !res.OK || !res.Truncated || res.Total != 1 ||
		res.Bytes > 1000 || !strings.Contains(res.Note, "Only the first 1 KB were checked") {
		t.Errorf("preview = %+v", res)
	}
	// A saved feed's secrets are reused when testing it by name.
	if _, err := f.AddFeed(FeedInput{Name: "keyed", URL: base + "/needs-key", Enabled: on(false), Headers: []HeaderInput{{Name: "X-Api-Key", Value: "k3y"}}}); err != nil {
		t.Fatal(err)
	}
	in, _ := f.InputFor("keyed")
	if res, err := f.TestFeed(ctx, in, "keyed"); err != nil || !res.OK || host.header("X-Api-Key") != "k3y" {
		t.Errorf("test by name = %+v %v", res, err)
	}
	// ...but not when testing a new feed.
	if res, _ := f.TestFeed(ctx, in, ""); res.OK {
		t.Error("a new feed's test used a saved feed's key")
	}
	// Settings a download does not need are not checked.
	if res, err := f.TestFeed(ctx, FeedInput{URL: base + "/ips.txt", Interval: "1m", Name: "Bad Name"}, ""); err != nil || !res.OK {
		t.Errorf("test with a bad schedule = %+v %v", res, err)
	}
	var ie *InputError
	if _, err := f.TestFeed(ctx, FeedInput{URL: "file:///etc/passwd"}, ""); !errors.As(err, &ie) || ie.Fields()["url"] == "" {
		t.Errorf("file URL = %v", err)
	}
	if _, err := f.TestFeed(ctx, FeedInput{URL: base}, "nope"); !errors.Is(err, ErrUnknownFeed) {
		t.Errorf("unknown feed = %v", err)
	}
}

func TestCatalogAdd(t *testing.T) {
	f := newTestFeeds(t, Feed{Name: "feodo-tracker", URL: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", Interval: time.Hour, Enabled: true})
	views := f.Catalog()
	if len(views) != len(Catalog) || !views[0].Added || views[0].Feed != "feodo-tracker" {
		t.Fatalf("catalog = %+v", views[0])
	}
	var ids []string
	for _, v := range views {
		if v.Recommended {
			ids = append(ids, v.ID)
		}
	}
	added, skipped, err := f.AddCatalog(append(ids, "nope", "urlhaus"))
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != len(ids)-1 || len(skipped) != 3 {
		t.Errorf("added %d, skipped %+v", len(added), skipped)
	}
	for _, v := range added {
		if v.Source != SourceUI || v.Catalog != v.Name || v.Interval == "" || v.Description == "" {
			t.Errorf("added = %+v", v)
		}
	}
	for _, v := range f.Catalog() {
		if v.Recommended && !v.Added {
			t.Errorf("%s not marked added", v.ID)
		}
	}
	// One entry by itself, with settings changed.
	v, err := f.AddFeed(FeedInput{Catalog: "tor-exits", Interval: "6h"})
	if err != nil || v.Name != "tor-exits" || v.URL != "https://check.torproject.org/torbulkexitlist" || v.Interval != "6h" || v.Weight != 0.25 || v.Type != TypeIP {
		t.Errorf("tor = %+v %v", v, err)
	}
	if _, err := f.AddFeed(FeedInput{Catalog: "nope"}); err == nil {
		t.Error("unknown catalog id accepted")
	}
}
