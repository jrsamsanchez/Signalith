// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// taxiiPaths answers each path with a status and body; others get 404.
func taxiiPaths(t *testing.T, paths map[string]string) string {
	t.Helper()
	srv := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, ok := paths[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(body, "!") {
			code, rest, _ := strings.Cut(body[1:], " ")
			switch code {
			case "401":
				w.WriteHeader(http.StatusUnauthorized)
			case "500":
				w.WriteHeader(http.StatusInternalServerError)
			}
			io.WriteString(w, rest)
			return
		}
		w.Header().Set("Content-Type", TAXIIMediaType)
		io.WriteString(w, body)
	})
	return srv.URL
}

func TestCollectionsDiscovery(t *testing.T) {
	ctx := context.Background()
	f := newTestFeeds(t)
	cols := func(ids ...string) string {
		var parts []string
		for _, id := range ids {
			parts = append(parts, `{"id":"`+id+`","can_read":true}`)
		}
		return `{"collections":[` + strings.Join(parts, ",") + `,{"title":"no id"}]}`
	}

	// Discovery lists two roots; the default comes first and one that
	// is gone is skipped. Collections without a title take their ID.
	base := taxiiPaths(t, map[string]string{
		"/taxii2/":             `{"title":"CTI","default":"/b/","api_roots":["/a/","/b/","/gone/","::bad"]}`,
		"/a/collections/":      cols("a1"),
		"/b/collections/":      cols("b1", "b2"),
		"/other/collections/x": "",
	})
	srv, err := f.Collections(ctx, Feed{URL: base + "/other/"})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range srv.Collections {
		ids = append(ids, c.ID)
		if c.Title != c.ID {
			t.Errorf("title %q for %s", c.Title, c.ID)
		}
	}
	if srv.Title != "CTI" || strings.Join(ids, ",") != "b1,b2,a1" {
		t.Errorf("collections %v, title %q", ids, srv.Title)
	}

	for _, c := range []struct {
		name  string
		paths map[string]string
		url   string
		want  string
	}{
		{"not http", nil, "ftp://cti.example/api/", "Enter the http(s) address"},
		{"no host", nil, "https:///api/", "Enter the http(s) address"},
		{"sign-in at the root", map[string]string{"/api/collections/": "!401 no"}, "/api/", "401"},
		{"discovery not json", map[string]string{"/taxii2/": "<html>"}, "/api/", "No TAXII 2.1 server"},
		{"discovery without roots", map[string]string{"/taxii2/": `{"title":"x","api_roots":[]}`}, "/api/", "No TAXII 2.1 server"},
		{"discovery fails", map[string]string{"/taxii2/": "!500 down"}, "/api/", "500"},
		{"every root refuses", map[string]string{"/taxii2/": `{"api_roots":["/r/"]}`, "/r/collections/": "!401 no"}, "/api/", "401"},
		{"no root is taxii", map[string]string{"/taxii2/": `{"api_roots":["/r/"]}`, "/r/collections/": "not json"}, "/api/", "No TAXII 2.1 server"},
	} {
		t.Run(c.name, func(t *testing.T) {
			u := c.url
			if c.paths != nil {
				u = taxiiPaths(t, c.paths) + c.url
			}
			_, err := f.Collections(ctx, Feed{URL: u})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err %v, want %q", err, c.want)
			}
		})
	}
}

func TestRefreshStoresAndExplains(t *testing.T) {
	ctx := context.Background()
	_, base := newFeedHost(t, map[string]string{
		"/a.txt":    "203.0.113.9\n",
		"/private":  "10.0.0.1\n192.168.1.1\n",
		"/junk.txt": "not-an-ip\n",
	})
	feed := func(name, path string) Feed {
		return Feed{Name: name, URL: base + path, Format: FormatLines, Type: TypeIP, Interval: time.Hour, MaxAge: 24 * time.Hour, Weight: 2,
			Enabled: true, Tags: []string{"abuse", "Abuse", ""}, Description: "feed"}
	}
	be := &failBackend{Memory: NewMemory()}
	s := NewStore(be)
	if err := s.Load(ctx); err != nil {
		t.Fatal(err)
	}
	f := newTestFeeds(t, feed("a", "/a.txt"), feed("private", "/private"), feed("junk", "/junk.txt"),
		Feed{Name: "off", URL: base + "/a.txt", Interval: time.Hour, MaxAge: time.Hour})
	f.Store = s

	st, err := f.Refresh(ctx, "a")
	if err != nil || st.Count != 1 {
		t.Fatalf("refresh %+v %v", st, err)
	}
	inds := s.Lookup("203.0.113.9")
	if len(inds) != 1 || strings.Join(inds[0].Tags, ",") != "abuse" || inds[0].Weight != 2 || inds[0].Description != "feed" {
		t.Errorf("stored %+v", inds)
	}
	if _, err := f.Refresh(ctx, "private"); err == nil || !strings.Contains(err.Error(), "only private or reserved addresses (2)") {
		t.Errorf("private: %v", err)
	}
	if _, err := f.Refresh(ctx, "junk"); err == nil || !strings.Contains(err.Error(), `the first was "not-an-ip"`) {
		t.Errorf("junk: %v", err)
	}
	if _, err := f.Refresh(ctx, "off"); !errors.Is(err, ErrFeedOff) {
		t.Errorf("off: %v", err)
	}
	if _, err := f.Refresh(ctx, "nope"); !errors.Is(err, ErrUnknownFeed) {
		t.Errorf("unknown: %v", err)
	}
	// A store that refuses the write: the error is kept in the status.
	be.put = errors.New("index read-only")
	st, err = f.Refresh(ctx, "a")
	if err == nil || !strings.Contains(err.Error(), "could not store indicators") || !strings.Contains(st.LastError, "could not store indicators") {
		t.Errorf("store failure: %+v %v", st, err)
	}

	for _, c := range []struct {
		got  fetched
		want string
	}{
		{fetched{Result: &ParseResult{}, html: true}, "sent a web page"},
		{fetched{Result: &ParseResult{Format: FormatCSV}, json: true}, "JSON that is not STIX 2.1"},
		{fetched{Result: &ParseResult{}}, "The feed has no indicators."},
	} {
		if got := emptyMessage(&c.got); !strings.Contains(got, c.want) {
			t.Errorf("emptyMessage = %q, want %q", got, c.want)
		}
	}
}
