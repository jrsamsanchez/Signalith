// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// A test of a feed from signalith.yaml uses its saved ${ENV_VAR} keys on
// its own server, but values the request sends are used as written: a
// test never sends the server's environment to an address it names.
func TestTestNeverExpandsRequestValues(t *testing.T) {
	t.Setenv("SIGNALITH_TEST_FEED_KEY", "cfg-key-from-env")
	t.Setenv("SIGNALITH_TEST_SECRET", "server-secret")
	var mu sync.Mutex
	var got []http.Header
	srv := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Header.Clone())
		mu.Unlock()
		if strings.Contains(r.URL.Path, "collections") {
			w.Header().Set("Content-Type", TAXIIMediaType)
			w.Write([]byte(`{"collections":[]}`))
			return
		}
		w.Write([]byte("203.0.113.9\n"))
	})
	last := func() http.Header {
		mu.Lock()
		defer mu.Unlock()
		return got[len(got)-1]
	}
	cfg := FeedSpec{Name: "partner", URL: srv.URL + "/ips.txt", Headers: map[string]string{"X-Api-Key": "${SIGNALITH_TEST_FEED_KEY}"}}
	cfg.Defaults()
	f := newTestFeeds(t, cfg.Feed(SourceConfig))
	ctx := context.Background()

	// The saved key is still read from the environment, on its server.
	in, _ := f.InputFor("partner")
	if res, err := f.TestFeed(ctx, in, "partner"); err != nil || !res.OK || last().Get("X-Api-Key") != "cfg-key-from-env" {
		t.Fatalf("test of the saved feed = %+v %v, key %q", res, err, last().Get("X-Api-Key"))
	}
	// Values in the request are sent as typed, on the same server or
	// another one ("localhost" is another server than "127.0.0.1").
	other := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	for _, u := range []string{srv.URL + "/ips.txt", other + "/x"} {
		in, _ := f.InputFor("partner")
		in.URL = u
		in.Headers = []HeaderInput{{Name: "X-Api-Key", Clear: true}, {Name: "X-Leak", Value: "${SIGNALITH_TEST_SECRET}"}}
		in.Username, in.Password = "u", "${SIGNALITH_TEST_SECRET}"
		res, err := f.TestFeed(ctx, in, "partner")
		if err != nil || !res.OK {
			t.Fatalf("%s: test = %+v %v", u, res, err)
		}
		h := last()
		_, pw, _ := (&http.Request{Header: h}).BasicAuth()
		if h.Get("X-Leak") != "${SIGNALITH_TEST_SECRET}" || pw != "${SIGNALITH_TEST_SECRET}" {
			t.Errorf("%s: the request's values were expanded: header %q, password %q", u, h.Get("X-Leak"), pw)
		}
	}
	// The same holds for listing TAXII collections.
	if _, err := f.TAXIICollections(ctx, FeedInput{URL: other + "/api1/", Headers: []HeaderInput{{Name: "X-Api-Key", Clear: true},
		{Name: "X-Leak", Value: "${SIGNALITH_TEST_SECRET}"}}}, "partner"); err != nil {
		t.Fatal(err)
	}
	if h := last(); h.Get("X-Leak") != "${SIGNALITH_TEST_SECRET}" {
		t.Errorf("collections: header %q", h.Get("X-Leak"))
	}
	// The saved key is not sent to another server without being entered
	// again.
	in, _ = f.InputFor("partner")
	in.URL = other + "/x"
	var ie *InputError
	if _, err := f.TestFeed(ctx, in, "partner"); !errors.As(err, &ie) || ie.Fields()["headers"] == "" {
		t.Errorf("moved test = %v", err)
	}
}

// At most MaxTests tests run at once, and a test keeps only a few
// indicators however large the feed.
func TestTestsAreLimited(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 200; i++ {
		fmt.Fprintf(&b, "203.0.%d.%d\n", 113+i/250, i%250+1)
	}
	_, base := newFeedHost(t, map[string]string{"/ips.txt": b.String()})
	f := newTestFeeds(t)
	ctx := context.Background()
	res, err := f.TestFeed(ctx, FeedInput{URL: base + "/ips.txt"}, "")
	if err != nil || !res.OK || res.Total != 200 || res.ByType[TypeIP] != 200 || len(res.Samples) != 10 {
		t.Fatalf("test = %+v %v", res, err)
	}
	r, err := Parse([]byte(b.String()), ParseOptions{Format: FormatLines, Type: "auto", Keep: 10})
	if err != nil || r.Found != 200 || len(r.Indicators) != 10 {
		t.Errorf("parse with keep = found %d, kept %d, %v", r.Found, len(r.Indicators), err)
	}
	var dones []func()
	for range MaxTests {
		done, err := f.startTest()
		if err != nil {
			t.Fatal(err)
		}
		dones = append(dones, done)
	}
	if _, err := f.TestFeed(ctx, FeedInput{URL: base + "/ips.txt"}, ""); !errors.Is(err, ErrBusy) {
		t.Errorf("third test = %v", err)
	}
	if _, err := f.TAXIICollections(ctx, FeedInput{URL: base + "/api1/"}, ""); !errors.Is(err, ErrBusy) {
		t.Errorf("collections while busy = %v", err)
	}
	for _, d := range dones {
		d()
	}
	if res, err := f.TestFeed(ctx, FeedInput{URL: base + "/ips.txt"}, ""); err != nil || !res.OK {
		t.Errorf("test after = %+v %v", res, err)
	}
}

// A feed that is off is never downloaded: not by hand, and not when it
// is turned off while the scheduler downloads others before it.
func TestFeedOffNeverDownloads(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	srv := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/a" {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
		}
		w.Write([]byte("203.0.113.9\n"))
	})
	f := newTestFeeds(t)
	ctx := context.Background()
	if _, err := f.AddFeed(FeedInput{Name: "off", URL: srv.URL + "/b", Enabled: on(false)}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Refresh(ctx, "off"); !errors.Is(err, ErrFeedOff) || f.Store.CountSource("off") != 0 {
		t.Errorf("refresh of a feed that is off = %v, %d stored", err, f.Store.CountSource("off"))
	}
	for _, n := range []string{"aa", "bb"} {
		path := map[string]string{"aa": "/a", "bb": "/b"}[n]
		if _, err := f.AddFeed(FeedInput{Name: n, URL: srv.URL + path}); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() { f.RunDue(ctx); close(done) }()
	<-started
	in, _ := f.InputFor("bb")
	in.Enabled = on(false)
	if _, err := f.UpdateFeed(ctx, "bb", in); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-done
	if n := f.Store.CountSource("bb"); n != 0 || f.Store.CountSource("aa") != 1 {
		t.Errorf("bb is off but has %d indicators (aa %d)", n, f.Store.CountSource("aa"))
	}
}

// A TAXII server that sends a page exactly as large as the size limit
// gets no further requests.
func TestTAXIISizeLimitExactPage(t *testing.T) {
	const limit = 2000
	pad := func(n int, more bool, next string) string {
		head := fmt.Sprintf(`{"more":%v,"next":%q,"objects":[{"type":"indicator","id":"indicator--1","pattern":"[ipv4-addr:value = '203.0.113.9']","pattern_type":"stix","name":"`, more, next)
		tail := `"}]}`
		return head + strings.Repeat("a", n-len(head)-len(tail)) + tail
	}
	var mu sync.Mutex
	var sent []int
	srv := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body := pad(50000, false, "")
		switch r.URL.Query().Get("next") {
		case "":
			body = pad(limit, true, "p2") // exactly the limit
		case "p2":
			body = pad(50000, true, "p3")
		}
		sent = append(sent, len(body))
		w.Write([]byte(body))
	})
	f := newTestFeeds(t)
	f.MaxBytes = limit
	fd := Feed{Name: "t", Kind: KindTAXII, URL: srv.URL + "/api1/", Collection: "c", Format: FormatSTIX, Type: "auto", Source: SourceUI}
	got, err := f.fetch(context.Background(), fd, f.now(), fetchLimits{MaxBytes: f.maxBytes(), Refuse: f.maxBytes()})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got.Bytes > limit || !got.Truncated || len(sent) != 1 || got.Result.Found != 1 {
		t.Errorf("read %d bytes (limit %d), truncated %v, pages sent %v", got.Bytes, limit, got.Truncated, sent)
	}
	// A download never falls back to a larger limit than it was given.
	if _, _, _, err := f.httpGet(context.Background(), fd, srv.URL+"/x", "", fetchLimits{}); err == nil {
		t.Error("a download without a size limit was read")
	}
}

// A slow TAXII server that runs out of time after the first page keeps
// what it sent, and removes nothing.
func TestTAXIISlowServerKeepsPages(t *testing.T) {
	srv := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", TAXIIMediaType)
		if r.URL.Query().Get("next") == "" {
			fmt.Fprintf(w, `{"more":true,"next":"p2","objects":[%s]}`, indicator("1", "[ipv4-addr:value = '203.0.113.1']", ""))
			return
		}
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	defer func(d time.Duration) { taxiiPageTimeout = d }(taxiiPageTimeout)
	for _, c := range []struct {
		name         string
		page, parent time.Duration
	}{
		{"page timeout", 200 * time.Millisecond, time.Minute},
		{"run timeout", time.Minute, 300 * time.Millisecond},
	} {
		taxiiPageTimeout = c.page
		f := newTestFeeds(t)
		if _, err := f.AddFeed(FeedInput{Name: "cti", Kind: KindTAXII, URL: srv.URL + "/api1/", Collection: "c"}); err != nil {
			t.Fatal(err)
		}
		// An indicator from an earlier download.
		if err := f.Store.Add(context.Background(), []Indicator{{Type: TypeIP, Value: "198.51.100.7", Source: "cti"}}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), c.parent)
		st, err := f.Refresh(ctx, "cti")
		cancel()
		if err != nil || !strings.Contains(st.Note, "server was slow") || f.Store.CountSource("cti") != 2 || st.Removed != 0 {
			t.Errorf("%s: refresh = %+v %v, %d stored", c.name, st, err, f.Store.CountSource("cti"))
		}
	}
	// When the first page does not come, nothing changes.
	taxiiPageTimeout = 200 * time.Millisecond
	slowAll := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	f := newTestFeeds(t)
	if _, err := f.AddFeed(FeedInput{Name: "cti", Kind: KindTAXII, URL: slowAll.URL + "/api1/", Collection: "c"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Refresh(context.Background(), "cti"); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("first page timeout = %v", err)
	}
}

// A custom feed that only shares a catalog entry's name is another feed:
// the entry can still be added, under a free name.
func TestCatalogNameTaken(t *testing.T) {
	f := newTestFeeds(t)
	for _, n := range []string{"urlhaus", "feodo-tracker"} {
		if _, err := f.AddFeed(FeedInput{Name: n, URL: "https://feeds.example/" + n + ".txt", Enabled: on(false)}); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range f.Catalog() {
		if v.Added {
			t.Errorf("%s marked added by name only", v.ID)
		}
	}
	v, err := f.AddFeed(FeedInput{Catalog: "urlhaus"})
	if err != nil || v.Name != "urlhaus-2" || v.Catalog != "urlhaus" {
		t.Fatalf("add urlhaus = %+v %v", v, err)
	}
	added, skipped, err := f.AddCatalog([]string{"feodo-tracker", "urlhaus"})
	if err != nil || len(added) != 1 || added[0].Name != "feodo-tracker-2" || len(skipped) != 1 {
		t.Fatalf("add catalog = %+v %+v %v", added, skipped, err)
	}
	for _, v := range f.Catalog() {
		if want := map[string]string{"urlhaus": "urlhaus-2", "feodo-tracker": "feodo-tracker-2"}[v.ID]; want != "" && (!v.Added || v.Feed != want) {
			t.Errorf("%s = added %v by %q", v.ID, v.Added, v.Feed)
		}
	}
}

// Fixing an unreadable feeds file takes effect without a restart.
func TestFeedsFileFixed(t *testing.T) {
	f := newTestFeeds(t)
	if err := os.WriteFile(f.File, []byte("feeds: [this is: not: yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.Load(); err == nil {
		t.Fatal("a broken file loaded")
	}
	if err := os.WriteFile(f.File, []byte("feeds:\n  - name: fixed\n    url: https://feeds.example/x.txt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.Load(); err != nil || f.Len() != 1 {
		t.Fatalf("after the fix = %v, %d feeds", err, f.Len())
	}
	if _, err := f.AddFeed(FeedInput{Name: "another", URL: "https://feeds.example/y.txt", Enabled: on(false)}); err != nil {
		t.Errorf("add after the fix = %v", err)
	}
}

// A feed set to auto shows what its last download was read as.
func TestDetectedFormatInStatus(t *testing.T) {
	_, base := newFeedHost(t, map[string]string{
		"/feed.csv": "first_seen_utc,dst_ip,dst_port,malware\n2026-10-01,203.0.113.9,443,QakBot\n2026-10-02,198.51.100.4,80,Pikabot\n",
	})
	f := newTestFeeds(t)
	if _, err := f.AddFeed(FeedInput{Name: "auto-csv", URL: base + "/feed.csv"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Refresh(context.Background(), "auto-csv"); err != nil {
		t.Fatal(err)
	}
	if v, _ := f.View("auto-csv"); v.Format != FormatAuto || v.Status.Format != FormatCSV || v.Status.Column != "dst_ip" {
		t.Errorf("view = %s, status %+v", v.Format, v.Status)
	}
}
