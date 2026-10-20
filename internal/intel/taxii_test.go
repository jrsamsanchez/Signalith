// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// taxiiServer is a small TAXII 2.1 server with one API root.
type taxiiServer struct {
	mu        sync.Mutex
	requests  []string
	badAccept int
}

func indicator(id, pattern string, extra string) string {
	return fmt.Sprintf(`{"type":"indicator","spec_version":"2.1","id":"indicator--%s","pattern":"%s","pattern_type":"stix","valid_from":"2026-10-01T00:00:00Z"%s}`, id, pattern, extra)
}

func newTAXIIServer(t *testing.T) (*taxiiServer, string) {
	ts := &taxiiServer{}
	srv := feedServer(t, func(w http.ResponseWriter, r *http.Request) {
		ts.mu.Lock()
		ts.requests = append(ts.requests, r.URL.RequestURI())
		if r.Header.Get("Accept") != TAXIIMediaType {
			ts.badAccept++
		}
		ts.mu.Unlock()
		if u, p, ok := r.BasicAuth(); !ok || u != "reader" || p != "s3cret-pw" {
			w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"title":"Unauthorized"}`))
			return
		}
		w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
		q := r.URL.Query()
		switch r.URL.Path {
		case "/taxii2/":
			w.Write([]byte(`{"title":"Test TAXII","default":"/api1/","api_roots":["/api2/","/api1/"]}`))
		case "/api1/":
			w.Write([]byte(`{"title":"Root one","versions":["application/taxii+json;version=2.1"]}`))
		case "/api1/collections/":
			w.Write([]byte(`{"collections":[{"id":"c1","title":"Indicators","can_read":true,"can_write":false,"media_types":["application/stix+json;version=2.1"]},{"id":"c2","title":"Inbox","can_read":false,"can_write":true}]}`))
		case "/api2/collections/":
			http.Error(w, `{"title":"Forbidden"}`, http.StatusForbidden)
		case "/api1/collections/c1/objects/":
			if q.Get("match[type]") != "indicator" || q.Get("limit") == "" {
				http.Error(w, "bad query", http.StatusBadRequest)
				return
			}
			switch q.Get("next") {
			case "":
				fmt.Fprintf(w, `{"more":true,"next":"p2","objects":[%s,%s]}`,
					indicator("1", "[ipv4-addr:value = '203.0.113.1']", `,"name":"C2"`),
					indicator("2", "[domain-name:value = 'evil.example']", ""))
			case "p2":
				fmt.Fprintf(w, `{"more":true,"next":"p3","objects":[%s,%s,{"type":"malware","id":"malware--1"}]}`,
					indicator("3", "[url:value = 'http://evil.example/a']", ""),
					indicator("4", "[ipv4-addr:value = '203.0.113.4']", `,"revoked":true`))
			case "p3":
				fmt.Fprintf(w, `{"more":false,"objects":[%s]}`,
					indicator("5", "[file:hashes.'SHA-256' = '"+strings.Repeat("c", 64)+"']", ""))
			default:
				http.Error(w, "bad next", http.StatusBadRequest)
			}
		case "/api1/collections/c3/objects/":
			// Paged by date, the way some servers did before "next".
			switch q.Get("added_after") {
			case "":
				w.Header().Set("X-TAXII-Date-Added-Last", "2026-10-01T00:00:00.000Z")
				fmt.Fprintf(w, `{"more":true,"objects":[%s]}`, indicator("6", "[ipv4-addr:value = '198.51.100.6']", ""))
			case "2026-10-01T00:00:00.000Z":
				fmt.Fprintf(w, `{"objects":[%s]}`, indicator("7", "[ipv4-addr:value = '198.51.100.7']", ""))
			}
		case "/api1/collections/endless/objects/":
			fmt.Fprintf(w, `{"more":true,"next":"again","objects":[%s]}`, indicator("8", "[ipv4-addr:value = '198.51.100.8']", ""))
		default:
			http.NotFound(w, r)
		}
	})
	return ts, srv.URL
}

func TestTAXIIFeed(t *testing.T) {
	ctx := context.Background()
	ts, base := newTAXIIServer(t)
	f := newTestFeeds(t)
	v, err := f.AddFeed(FeedInput{Name: "our-cti", Kind: KindTAXII, URL: base + "/api1", Collection: "c1", Enabled: on(false),
		Username: "reader", Password: "s3cret-pw"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Kind != KindTAXII || v.Format != FormatSTIX || v.Collection != "c1" || !v.Password.Set {
		t.Errorf("view = %+v", v)
	}
	in, _ := f.InputFor("our-cti")
	in.Enabled = on(true)
	if _, err := f.UpdateFeed(ctx, "our-cti", in); err != nil {
		t.Fatal(err)
	}
	// A full pull follows "next" through every page.
	st, err := f.Refresh(ctx, "our-cti")
	if err != nil || st.Count != 4 || st.Note != "" {
		t.Fatalf("refresh = %+v %v", st, err)
	}
	want := "ip:203.0.113.1 domain:evil.example url:http://evil.example/a sha256:" + strings.Repeat("c", 64)
	list, _ := f.Store.List(Filter{Source: "our-cti"})
	got := map[string]bool{}
	for _, ind := range list {
		got[ind.Type+":"+ind.Value] = true
	}
	for _, w := range strings.Fields(want) {
		if !got[w] {
			t.Errorf("missing %s in %v", w, got)
		}
	}
	if m := f.Store.Lookup("203.0.113.1"); len(m) != 1 || m[0].Description != "C2" {
		t.Errorf("lookup = %+v", m)
	}
	ts.mu.Lock()
	if ts.badAccept != 0 {
		t.Errorf("%d requests without the TAXII Accept header", ts.badAccept)
	}
	ts.mu.Unlock()

	// Paging by date works too.
	if _, err := f.AddFeed(FeedInput{Name: "by-date", Kind: KindTAXII, URL: base + "/api1/", Collection: "c3", Enabled: on(false),
		Username: "reader", Password: "s3cret-pw"}); err != nil {
		t.Fatal(err)
	}
	in, _ = f.InputFor("by-date")
	if res, err := f.TestFeed(ctx, in, "by-date"); err != nil || !res.OK || res.Total != 1 || !strings.Contains(res.Note, "more objects") {
		t.Errorf("test (one page) = %+v %v", res, err)
	}
	in.Enabled = on(true)
	f.UpdateFeed(ctx, "by-date", in)
	if st, err := f.Refresh(ctx, "by-date"); err != nil || st.Count != 2 {
		t.Errorf("date paging = %+v %v", st, err)
	}

	// A server that never stops paging is cut off with a note.
	got2, err := f.fetchTAXII(ctx, Feed{Name: "x", Kind: KindTAXII, URL: base + "/api1/", Collection: "endless", Type: "auto",
		Username: "reader", Password: "s3cret-pw", Source: SourceUI}, time.Now(), fetchLimits{Pages: 5})
	if err != nil || !got2.Truncated || len(got2.Result.Indicators) != 1 || !strings.Contains(got2.Note, "only the first 5") {
		t.Errorf("endless = %+v %v", got2, err)
	}

	// Wrong credentials and a wrong collection, in plain words.
	res, _ := f.TestFeed(ctx, FeedInput{Kind: KindTAXII, URL: base + "/api1/", Collection: "c1", Username: "reader", Password: "wrong"}, "")
	if res.OK || res.HTTPStatus != 401 || !strings.Contains(res.Error, "Check that the API key or password") || strings.Contains(res.Error, "wrong") {
		t.Errorf("bad password = %+v", res)
	}
	res, _ = f.TestFeed(ctx, FeedInput{Kind: KindTAXII, URL: base + "/api1/", Collection: "nope", Username: "reader", Password: "s3cret-pw"}, "")
	if res.OK || !strings.Contains(res.Error, "collection ID") {
		t.Errorf("bad collection = %+v", res)
	}
	var ie *InputError
	if _, err := f.AddFeed(FeedInput{Name: "no-collection", Kind: KindTAXII, URL: base + "/api1/"}); !errors.As(err, &ie) || ie.Fields()["collection"] == "" {
		t.Errorf("no collection = %v", err)
	}
}

func TestTAXIICollections(t *testing.T) {
	ctx := context.Background()
	_, base := newTAXIIServer(t)
	f := newTestFeeds(t)
	creds := FeedInput{Username: "reader", Password: "s3cret-pw"}

	// The API root itself.
	in := creds
	in.URL = base + "/api1/"
	srv, err := f.TAXIICollections(ctx, in, "")
	if err != nil || len(srv.Collections) != 2 || srv.Collections[0].ID != "c1" || !srv.Collections[0].CanRead ||
		srv.Collections[0].APIRoot != base+"/api1/" || srv.Collections[1].CanRead {
		t.Fatalf("api root = %+v %v", srv, err)
	}
	// The server's address: discovery finds the API roots, skipping one
	// that refuses.
	in.URL = base
	srv, err = f.TAXIICollections(ctx, in, "")
	if err != nil || srv.Title != "Test TAXII" || len(srv.Collections) != 2 || srv.Collections[0].APIRoot != base+"/api1/" {
		t.Errorf("discovery = %+v %v", srv, err)
	}
	in.URL = base + "/taxii2/"
	if srv, err = f.TAXIICollections(ctx, in, ""); err != nil || len(srv.Collections) != 2 {
		t.Errorf("discovery URL = %+v %v", srv, err)
	}
	// Saved credentials are reused by name.
	if _, err := f.AddFeed(FeedInput{Name: "cti", Kind: KindTAXII, URL: base + "/api1/", Collection: "c1", Enabled: on(false),
		Username: "reader", Password: "s3cret-pw"}); err != nil {
		t.Fatal(err)
	}
	if srv, err = f.TAXIICollections(ctx, FeedInput{URL: base + "/api1/", Username: "reader"}, "cti"); err != nil || len(srv.Collections) != 2 {
		t.Errorf("saved credentials = %+v %v", srv, err)
	}
	// Errors.
	in.URL, in.Password = base+"/api1/", "nope"
	if _, err := f.TAXIICollections(ctx, in, ""); err == nil || !strings.Contains(err.Error(), "401 Unauthorized") {
		t.Errorf("bad password = %v", err)
	}
	empty := feedServer(t, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	if _, err := f.TAXIICollections(ctx, FeedInput{URL: empty.URL + "/api/"}, ""); err == nil || !strings.Contains(err.Error(), "No TAXII 2.1 server") {
		t.Errorf("no server = %v", err)
	}
	var ie *InputError
	if _, err := f.TAXIICollections(ctx, FeedInput{URL: "https://u:p@cti.example/api1/"}, ""); !errors.As(err, &ie) {
		t.Errorf("credentials in URL = %v", err)
	}
	if b, _ := json.Marshal(srv); strings.Contains(string(b), "s3cret") {
		t.Error("collections answer shows the password")
	}
}
