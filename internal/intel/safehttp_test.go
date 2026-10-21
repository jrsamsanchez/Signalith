// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCheckAddr(t *testing.T) {
	blocked := []string{"127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1", "0.0.0.0", "0.1.2.3", "::",
		"169.254.169.254", "169.254.1.1", "fe80::1", "fd00:ec2::254", "100.100.100.200", "224.0.0.251", "ff02::1",
		"255.255.255.255", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe"}
	for _, a := range blocked {
		if err := CheckAddr(netip.MustParseAddr(a), false); err == nil {
			t.Errorf("%s is allowed", a)
		}
	}
	// Private LAN ranges are allowed: MISP and OpenCTI servers live there.
	for _, a := range []string{"10.0.0.5", "192.168.1.20", "172.16.4.4", "fd12:3456::1", "203.0.113.9", "2001:db8::1", "100.64.0.1"} {
		if err := CheckAddr(netip.MustParseAddr(a), false); err != nil {
			t.Errorf("%s is blocked: %v", a, err)
		}
	}
	err := CheckAddr(netip.MustParseAddr("127.0.0.1"), false)
	var be *BlockedError
	if !errors.As(err, &be) || !be.Loopback || !strings.Contains(err.Error(), "allow_loopback_feeds") {
		t.Errorf("loopback error = %v", err)
	}
	if err := CheckAddr(netip.MustParseAddr("::1"), true); err != nil {
		t.Errorf("loopback allowed by the setting: %v", err)
	}
	if err := CheckAddr(netip.MustParseAddr("169.254.169.254"), true); err == nil {
		t.Error("the loopback setting must not allow link-local")
	}
}

func feedServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestDownloadsRefuseBlockedAddresses(t *testing.T) {
	ctx := context.Background()
	srv := feedServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("203.0.113.9\n")) })
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	f := &Feeds{Store: NewStore(NewMemory())}
	for _, u := range []string{
		srv.URL,                          // 127.0.0.1, refused before connecting
		"http://localhost:" + port + "/", // a name, refused at connect time
		"http://169.254.169.254/latest/meta-data/",
		"http://[fe80::1]/",
		"http://[fd00:ec2::254]/latest/",
		"http://0.0.0.0:" + port + "/",
	} {
		res, err := f.TestFeed(ctx, FeedInput{URL: u}, "")
		if err != nil || res.OK || !strings.Contains(res.Error, "does not download feeds from") {
			t.Errorf("%s: %+v %v", u, res, err)
		}
	}
	// The setting allows a feed server on this machine.
	f = &Feeds{Store: NewStore(NewMemory()), AllowLoopback: true}
	for _, u := range []string{srv.URL, "http://localhost:" + port + "/"} {
		if res, err := f.TestFeed(ctx, FeedInput{URL: u}, ""); err != nil || !res.OK || res.Total != 1 {
			t.Errorf("%s with allow_loopback_feeds: %+v %v", u, res, err)
		}
	}
	// ...but not link-local, even through a redirect.
	redir := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	})
	if res, _ := f.TestFeed(ctx, FeedInput{URL: redir.URL}, ""); res == nil || !strings.Contains(res.Error, "169.254.169.254") {
		t.Errorf("redirect to metadata = %+v", res)
	}
	// Other schemes are refused, in a redirect too.
	ftp := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "ftp://example.com/x", http.StatusFound)
	})
	if res, _ := f.TestFeed(ctx, FeedInput{URL: ftp.URL}, ""); res == nil || !strings.Contains(res.Error, "http or https") {
		t.Errorf("redirect to ftp = %+v", res)
	}
	// At most five redirects.
	loop := feedServer(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, r.URL.Path+"x", http.StatusFound) })
	if res, _ := f.TestFeed(ctx, FeedInput{URL: loop.URL + "/a"}, ""); res == nil || !strings.Contains(res.Error, "more than 5 times") {
		t.Errorf("redirect loop = %+v", res)
	}
}

func TestRedirectDropsRefererAndSignIn(t *testing.T) {
	var mu sync.Mutex
	got := map[string]http.Header{}
	record := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			got[name] = r.Header.Clone()
			mu.Unlock()
			w.Write([]byte("203.0.113.9\n"))
		}
	}
	other := feedServer(t, record("other"))
	_, otherPort, _ := net.SplitHostPort(strings.TrimPrefix(other.URL, "http://"))
	var first *httptest.Server
	first = feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/feed":
			// "localhost" is another host than "127.0.0.1", though Go
			// counts it as close enough to keep Authorization.
			http.Redirect(w, r, "http://localhost:"+otherPort+"/cdn/file.txt", http.StatusFound)
		case "/same":
			http.Redirect(w, r, first.URL+"/list.txt", http.StatusFound)
		default:
			record("first")(w, r)
		}
	})
	f := &Feeds{Store: NewStore(NewMemory()), AllowLoopback: true}
	ctx := context.Background()
	in := FeedInput{URL: first.URL + "/feed?apikey=SECRETKEY123", Username: "u", Password: "pw-secret"}
	if res, err := f.TestFeed(ctx, in, ""); err != nil || !res.OK {
		t.Fatalf("test = %+v %v", res, err)
	}
	in.URL = first.URL + "/same?apikey=SECRETKEY123"
	if res, err := f.TestFeed(ctx, in, ""); err != nil || !res.OK {
		t.Fatalf("test = %+v %v", res, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if h := got["other"]; h.Get("Referer") != "" || h.Get("Authorization") != "" {
		t.Errorf("another host got Referer %q, Authorization %q", h.Get("Referer"), h.Get("Authorization"))
	}
	// On the same server the sign-in stays, still without a Referer.
	if h := got["first"]; h.Get("Referer") != "" || h.Get("Authorization") == "" {
		t.Errorf("same host got Referer %q, Authorization %q", h.Get("Referer"), h.Get("Authorization"))
	}
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"http://feeds.example/a", "https://feeds.example/b", true},
		{"https://feeds.example/a", "http://feeds.example/b", false},
		{"https://feeds.example/a", "https://cdn.feeds.example/b", false},
		{"https://feeds.example/a", "https://feeds.example:8443/b", false},
		{"https://Feeds.Example./a", "https://feeds.example:443/b", true},
	} {
		a, _ := url.Parse(c.a)
		b, _ := url.Parse(c.b)
		if sameOrigin(a, b) != c.same {
			t.Errorf("sameOrigin(%s, %s) = %v", c.a, c.b, !c.same)
		}
	}
}

func TestRedirectDropsSecretHeaders(t *testing.T) {
	var mu sync.Mutex
	var got http.Header
	other := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
		w.Write([]byte("203.0.113.9\n"))
	})
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(other.URL, "http://"))
	first := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "k3y-value" {
			http.Error(w, "no key", http.StatusForbidden)
			return
		}
		// "localhost" is another host than "127.0.0.1".
		http.Redirect(w, r, "http://localhost:"+port+"/list.txt", http.StatusFound)
	})
	f := &Feeds{Store: NewStore(NewMemory()), AllowLoopback: true}
	res, err := f.TestFeed(context.Background(), FeedInput{URL: first.URL, Headers: []HeaderInput{{Name: "X-Api-Key", Value: "k3y-value"}},
		Username: "u", Password: "pw-secret"}, "")
	if err != nil || !res.OK {
		t.Fatalf("test = %+v %v", res, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got.Get("X-Api-Key") != "" || got.Get("Authorization") != "" {
		t.Errorf("secrets followed the redirect to another host: %v", got)
	}
}

func TestSafeDialerProxy(t *testing.T) {
	// A local proxy, the way cntlm, Px or squid run on a Windows desktop.
	var mu sync.Mutex
	var asked []string
	proxySrv := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.URL.String())
		mu.Unlock()
		if r.URL.Host == "feeds.example" {
			w.Write([]byte("203.0.113.9\n"))
			return
		}
		w.Write([]byte("proxy manager page: 203.0.113.250\n"))
	})
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(proxySrv.URL, "http://"))
	proxyURL, _ := url.Parse("http://localhost:" + port)
	// Like http.ProxyFromEnvironment: localhost is never sent through it.
	proxy := func(r *http.Request) (*url.URL, error) {
		if h := r.URL.Hostname(); h == "localhost" || h == "127.0.0.1" {
			return nil, nil
		}
		return proxyURL, nil
	}
	f := &Feeds{Store: NewStore(NewMemory()), HTTP: newFeedClientWith(false, nil, proxy)}
	ctx := context.Background()
	// The proxy itself may be on this machine.
	res, err := f.TestFeed(ctx, FeedInput{URL: "http://feeds.example/list.txt"}, "")
	if err != nil || !res.OK || res.Total != 1 {
		t.Fatalf("through the local proxy = %+v %v", res, err)
	}
	// But a feed at the proxy's address, which Go dials directly, is a
	// loopback address like any other.
	for _, u := range []string{"http://localhost:" + port + "/", "http://127.0.0.1:" + port + "/"} {
		res, err = f.TestFeed(ctx, FeedInput{URL: u}, "")
		if err != nil || res.OK || !strings.Contains(res.Error, "loopback") {
			t.Errorf("%s = %+v %v", u, res, err)
		}
	}
	// Neither reached the server at the proxy's address.
	mu.Lock()
	n := len(asked)
	mu.Unlock()
	if n != 1 {
		t.Errorf("the proxy got %d requests: %v", n, asked)
	}
	// Without a recorded proxy, every dial is checked.
	d := newSafeDialer(false, nil)
	if c, err := d.DialContext(ctx, "tcp", "localhost:"+port); err == nil {
		c.Close()
		t.Error("dialed loopback")
	}
}

func TestProtectedAddress(t *testing.T) {
	srv := feedServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("203.0.113.9\n")) })
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if got := ProtectedAddr("http://OpenSearch:9200/"); got != "opensearch:9200" {
		t.Errorf("ProtectedAddr = %q", got)
	}
	if got := ProtectedAddr("https://os.corp.example"); got != "os.corp.example:443" {
		t.Errorf("ProtectedAddr = %q", got)
	}
	// OpenSearch at localhost:port; loopback feeds are allowed otherwise.
	f := &Feeds{Store: NewStore(NewMemory()), AllowLoopback: true, Protected: []string{ProtectedAddr("http://localhost:" + port)}}
	ctx := context.Background()
	for _, u := range []string{"http://localhost:" + port + "/_search", "http://127.0.0.1:" + port + "/_cat/indices"} {
		res, err := f.TestFeed(ctx, FeedInput{URL: u}, "")
		if err != nil || res.OK || !strings.Contains(res.Error, "OpenSearch") {
			t.Errorf("%s = %+v %v", u, res, err)
		}
	}
	// A redirect there is refused as well.
	jump := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:"+port+"/", http.StatusFound)
	})
	if res, _ := f.TestFeed(ctx, FeedInput{URL: jump.URL}, ""); res.OK || !strings.Contains(res.Error, "OpenSearch") {
		t.Errorf("redirect = %+v", res)
	}
	// Other ports on the same machine still work.
	other := feedServer(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("203.0.113.9\n")) })
	if res, _ := f.TestFeed(ctx, FeedInput{URL: other.URL}, ""); !res.OK {
		t.Errorf("another port = %+v", res)
	}
}

func TestDescribeErrors(t *testing.T) {
	plainFeed := Feed{Name: "f", URL: "https://x.example/a?key=abc"}
	keyed := Feed{Name: "f", URL: "https://x.example/a", Headers: map[string]string{"X-Api-Key": "sup3r-secret"}}
	cases := []struct {
		err  error
		fd   Feed
		want string
	}{
		{&HTTPError{Code: 403, Status: "403 Forbidden"}, plainFeed, "The server answered 403 Forbidden. This feed may need an API key."},
		{&HTTPError{Code: 401, Status: "401 Unauthorized", Said: "invalid key sup3r-secret"}, keyed, "Check that the API key"},
		{&HTTPError{Code: 401, Status: "401 Unauthorized", Said: "Unauthorized"}, Feed{Kind: KindTAXII}, "This server needs you to sign in: enter a user name and password, or an API key."},
		{&HTTPError{Code: 404, Status: "404 Not Found"}, plainFeed, "Check the URL."},
		{&HTTPError{Code: 404, Status: "404 Not Found"}, Feed{Kind: KindTAXII}, "collection ID"},
		{&HTTPError{Code: 429, Status: "429 Too Many Requests"}, plainFeed, "longer interval"},
		{&HTTPError{Code: 503, Status: "503 Service Unavailable"}, plainFeed, "try again later"},
		{&TooBigError{Max: 256 << 20}, plainFeed, "larger than 256 MB"},
		{context.DeadlineExceeded, plainFeed, "did not answer within a minute"},
		{&url.Error{Op: "Get", URL: "https://x.example/a?key=abc", Err: &net.DNSError{Name: "x.example", IsNotFound: true}}, plainFeed, "Could not find the server x.example"},
		{&url.Error{Op: "Get", URL: "https://x.example/a?key=abc", Err: errors.New("boom")}, plainFeed, "Download failed: boom"},
	}
	for _, c := range cases {
		got := describe(c.err, c.fd, time.Minute)
		if strings.Contains(got, "It said: \"Unauthorized\"") {
			t.Errorf("describe(%v) repeats the status: %q", c.err, got)
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("describe(%v) = %q, want %q", c.err, got, c.want)
		}
		if strings.Contains(got, "key=abc") || strings.Contains(got, "sup3r-secret") {
			t.Errorf("describe(%v) shows a secret: %q", c.err, got)
		}
	}
	// A message that only repeats the status is left out; one that says
	// more is kept.
	for said, keep := range map[string]bool{
		"404 page not found":            false,
		"Error 404: Not Found":          false,
		"Not Found.":                    false,
		"Forbidden: API key required":   true,
		"no such feed; see /downloads/": true,
	} {
		got := describe(&HTTPError{Code: 404, Status: "404 Not Found", Said: said}, plainFeed, time.Minute)
		if strings.Contains(got, "It said") != keep {
			t.Errorf("describe with %q = %q", said, got)
		}
	}
	for in, want := range map[string]string{
		"https://u:p@x.example/a/b?key=abc#f": "https://x.example/a/b?…",
		"https://x.example/feed.txt":          "https://x.example/feed.txt",
		"http://x.example/?token=1":           "http://x.example/?…",
		"https://u:p@h.example/x#tok=SECRET":  "https://h.example/x#…",
		"https://h.example/x#":                "https://h.example/x#…",
		// A key in the path cannot be told from the path, and stays.
		"https://h.example/k3y/feed.txt": "https://h.example/k3y/feed.txt",
		// Does not parse (a space in the password): still no password.
		"https://u:pa ss@x.example/a?key=1": "https://***@x.example?…",
	} {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestServerSaid(t *testing.T) {
	for _, c := range []struct{ ct, body, want string }{
		{"text/plain", "missing or wrong API key\nmore", "missing or wrong API key"},
		{"application/taxii+json;version=2.1", `{"title":"Unauthorized","description":"The API key is not valid for this API root."}`, "The API key is not valid for this API root."},
		{"application/json", `{"title":"Collection not found","http_status":"404"}`, "Collection not found"},
		{"application/json", `{"http_status":"500"}`, ""},
		{"application/json", `{not json`, ""},
		{"text/html", "<html><body>Denied</body></html>", ""},
	} {
		if got := serverSaid(c.ct, []byte(c.body)); got != c.want {
			t.Errorf("serverSaid(%q, %q) = %q, want %q", c.ct, c.body, got, c.want)
		}
	}
}
