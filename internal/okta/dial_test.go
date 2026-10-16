package okta

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCheckPublic(t *testing.T) {
	for _, a := range []string{"127.0.0.1", "::1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.169.254",
		"100.64.0.1", "fd00::1", "fe80::1", "0.0.0.0", "64:ff9b::a00:1", "::ffff:127.0.0.1", "224.0.0.1"} {
		if checkPublic(netip.MustParseAddr(a)) == nil {
			t.Errorf("%s allowed", a)
		}
	}
	for _, a := range []string{"8.8.8.8", "2606:4700::1111", "64:ff9b::808:808"} {
		if err := checkPublic(netip.MustParseAddr(a)); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
}

// The poller's client does not connect to this machine, and the proxy
// the environment names is connected to unchecked.
func TestHTTPClientPublicOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "internal secret")
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := NewHTTPClient().Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("connected to a loopback address")
	}
	if !strings.Contains(err.Error(), "not an internet address") {
		t.Errorf("error %v", err)
	}

	addr := strings.TrimPrefix(srv.URL, "http://")
	d := newPublicDialer()
	d.proxy = func(*http.Request) (*url.URL, error) { return url.Parse("http://" + addr) }
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("proxy refused: %v", err)
	}
	c.Close()
}

// An error body that is not Okta's JSON is not passed on.
func TestReadErrorHidesOtherBodies(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{},
		Body: io.NopCloser(strings.NewReader("<html>internal admin page</html>"))}
	if e := readError(resp, time.Now()); strings.Contains(e.Error(), "internal") || e.Message != "Forbidden" {
		t.Errorf("error %q", e.Error())
	}
}
