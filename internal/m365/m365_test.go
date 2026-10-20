// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package m365

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// fakeAPI is a tenant's Management Activity API and sign-in service.
type fakeAPI struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	tokens   int
	started  map[string]bool
	listings []string // contentType start end
	reads    int
	// blobs by content type: when each was made available.
	blobs map[string][]time.Time
	// fail answers listings with this error.
	fail int
}

func newFake(t *testing.T) *fakeAPI {
	f := &fakeAPI{t: t, started: map[string]bool{}, blobs: map[string][]time.Time{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) settings() Settings {
	return Settings{TenantID: "tenant-1", ClientID: "app-1", ClientSecret: "s3cret",
		TokenURL: f.srv.URL + "/tenant-1/oauth2/v2.0/token", APIURL: f.srv.URL}
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/tenant-1/oauth2/v2.0/token" {
		r.ParseForm()
		if r.Form.Get("client_secret") != "s3cret" || r.Form.Get("scope") != f.srv.URL+"/.default" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided.\r\nTrace ID: 1"}`)
			return
		}
		f.tokens++
		fmt.Fprintf(w, `{"access_token": "tok%d", "expires_in": 3599}`, f.tokens)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer tok") || r.URL.Query().Get("PublisherIdentifier") != "tenant-1" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error": {"code": "AF10001", "message": "no token"}}`)
		return
	}
	base := "/api/v1.0/tenant-1/activity/feed/subscriptions/"
	q := r.URL.Query()
	switch {
	case r.URL.Path == base+"start" && r.Method == http.MethodPost:
		ct := q.Get("contentType")
		if f.started[ct] {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error": {"code": "AF20024", "message": "The subscription is already enabled."}}`)
			return
		}
		f.started[ct] = true
		fmt.Fprintf(w, `{"contentType": %q, "status": "enabled"}`, ct)
	case r.URL.Path == base+"list":
		var subs []map[string]string
		for ct := range f.started {
			subs = append(subs, map[string]string{"contentType": ct, "status": "enabled"})
		}
		json.NewEncoder(w).Encode(subs)
	case r.URL.Path == base+"content":
		if f.fail > 0 {
			f.fail--
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"error": {"code": "AF429", "message": "Too many requests."}}`)
			return
		}
		ct := q.Get("contentType")
		start, err1 := time.Parse(apiTime, q.Get("startTime"))
		end, err2 := time.Parse(apiTime, q.Get("endTime"))
		if err1 != nil || err2 != nil || end.Sub(start) > window || start.Before(time.Now().Add(-keep)) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error": {"code": "AF20055", "message": "bad times"}}`)
			return
		}
		f.listings = append(f.listings, ct+" "+q.Get("startTime")+" "+q.Get("endTime"))
		var out []Blob
		for i, at := range f.blobs[ct] {
			if !at.Before(start) && at.Before(end) {
				id := fmt.Sprintf("%s-%d", ct, i)
				out = append(out, Blob{ContentID: id, ContentURI: f.srv.URL + "/blob/" + id, ContentCreated: at.Format(apiTime)})
			}
		}
		// Every listing has a second page, which is empty.
		if q.Get("nextPage") == "" {
			w.Header().Set("NextPageUri", f.srv.URL+r.URL.Path+"?"+q.Encode()+"&nextPage=2")
		}
		json.NewEncoder(w).Encode(out)
	case strings.HasPrefix(r.URL.Path, "/blob/"):
		f.reads++
		id := strings.TrimPrefix(r.URL.Path, "/blob/")
		fmt.Fprintf(w, `[{"Id": "%s-a", "CreationTime": "2026-10-15T10:00:00", "Operation": "UserLoggedIn", "RecordType": 15,
			"Workload": "AzureActiveDirectory", "UserId": "jo@example.com", "ResultStatus": "Success"},
			{"Id": "%s-b", "CreationTime": "2026-10-15T10:00:01", "Operation": "New-InboxRule", "RecordType": 1, "Workload": "Exchange"}]`, id, id)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type sink struct {
	mu   sync.Mutex
	recs []map[string]any
}

func (s *sink) ingest(_ context.Context, tag string, recs []map[string]any) (*ingest.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tag != ingest.O365Tag {
		return nil, fmt.Errorf("tag %s", tag)
	}
	s.recs = append(s.recs, recs...)
	return &ingest.Result{Received: len(recs)}, nil
}

func TestPoller(t *testing.T) {
	f := newFake(t)
	now := time.Now().UTC().Truncate(time.Second)
	f.blobs["Audit.Exchange"] = []time.Time{now.Add(-3 * time.Hour), now.Add(-30 * time.Hour)}
	f.blobs["Audit.AzureActiveDirectory"] = []time.Time{now.Add(-time.Minute)}
	runs := detect.NewMemoryRunStore()
	out := &sink{}
	s := f.settings()
	p := &Poller{Settings: func() Settings { return s }, Store: runs, Index: "signalith_runtime", Ingest: out.ingest,
		HTTP: f.srv.Client(), now: func() time.Time { return now }}
	p.Round(context.Background())
	st := p.Status()
	if st.LastError != "" || !st.On || st.Records != 4 || len(out.recs) != 4 {
		t.Fatalf("status %+v, %d records", st, len(out.recs))
	}
	// The first round reads the last day: the blob 30 hours old is not
	// read.
	if f.reads != 2 || len(f.started) != 4 || f.tokens != 1 {
		t.Errorf("%d reads, %d started, %d tokens", f.reads, len(f.started), f.tokens)
	}
	raw, _, found, _ := runs.Get(context.Background(), "signalith_runtime", cursorID("tenant-1", "Audit.Exchange"))
	var cur Cursor
	if !found || json.Unmarshal(raw, &cur) != nil || !cur.Until.Equal(now) || cur.LastRecords != 2 {
		t.Fatalf("cursor %s", raw)
	}

	// The next round lists from just before the cursor, and reads only
	// what is new.
	f.listings = nil
	now = now.Add(5 * time.Minute)
	f.blobs["Audit.Exchange"] = append(f.blobs["Audit.Exchange"], now.Add(-2*time.Minute), now.Add(-12*time.Minute))
	p.Round(context.Background())
	// The blob 12 minutes old is in the overlap; the one 3 hours old is
	// not read again.
	if f.reads != 4 || len(out.recs) != 8 {
		t.Errorf("%d reads, %d records", f.reads, len(out.recs))
	}
	want := "Audit.Exchange " + now.Add(-5*time.Minute-overlap).Format(apiTime) + " " + now.Format(apiTime)
	if !contains(f.listings, want) {
		t.Errorf("listings %v, want %s", f.listings, want)
	}

	// A listing the API refuses keeps the cursor where it was.
	f.fail = 1
	now = now.Add(5 * time.Minute)
	p.Round(context.Background())
	if st := p.Status(); !strings.Contains(st.LastError, "AF429") {
		t.Errorf("status %+v", st)
	}
	raw, _, _, _ = runs.Get(context.Background(), "signalith_runtime", cursorID("tenant-1", ContentTypes[0]))
	json.Unmarshal(raw, &cur)
	if !cur.Until.Equal(now.Add(-5*time.Minute)) || !strings.Contains(cur.LastError, "AF429") {
		t.Errorf("cursor after a refusal %s", raw)
	}

	// A server that lost the jobs does not write over the newer holder's
	// cursor.
	p2 := &Poller{Settings: func() Settings { return s }, Store: runs, Index: "signalith_runtime", Ingest: out.ingest,
		HTTP: f.srv.Client(), now: func() time.Time { return now }, Epoch: func() int64 { return 2 }}
	p2.Round(context.Background())
	p.Round(context.Background())
	if st := p.Status(); !strings.Contains(st.LastError, ErrStale.Error()) {
		t.Errorf("stale status %+v", st)
	}

	// Without settings, nothing is read.
	s = Settings{}
	p.Round(context.Background())
	if st := p.Status(); st.On {
		t.Errorf("off status %+v", st)
	}
}

func TestPollerCatchesUp(t *testing.T) {
	f := newFake(t)
	now := time.Now().UTC().Truncate(time.Second)
	runs := detect.NewMemoryRunStore()
	// A cursor 10 days old: the API keeps 7, so listings start there and
	// cover a day each.
	runs.Create(context.Background(), "rt", cursorID("tenant-1", "Audit.General"), Cursor{Until: now.Add(-240 * time.Hour)}, false)
	f.blobs["Audit.General"] = []time.Time{now.Add(-6 * 24 * time.Hour)}
	out := &sink{}
	p := &Poller{Settings: f.settings, Store: runs, Index: "rt", Ingest: out.ingest, HTTP: f.srv.Client(), now: func() time.Time { return now }}
	p.Round(context.Background())
	if st := p.Status(); st.LastError != "" || len(out.recs) != 2 {
		t.Fatalf("status %+v, %d records", st, len(out.recs))
	}
	n := 0
	for _, l := range f.listings {
		if strings.HasPrefix(l, "Audit.General ") {
			n++
		}
	}
	// A day per listing, of 2 pages each, caught up in one round.
	if n < 14 || n > 2*maxWindows {
		t.Errorf("%d listings: %v", n, f.listings)
	}
	raw, _, _, _ := runs.Get(context.Background(), "rt", cursorID("tenant-1", "Audit.General"))
	var cur Cursor
	if json.Unmarshal(raw, &cur) != nil || !cur.Until.Equal(now) {
		t.Errorf("cursor %s", raw)
	}
}

func TestClientErrors(t *testing.T) {
	f := newFake(t)
	s := f.settings()
	s.ClientSecret = "wrong"
	_, err := Check(context.Background(), s, f.srv.Client())
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "invalid_client" || strings.Contains(err.Error(), "Trace ID") {
		t.Errorf("err %v", err)
	}
	subs, err := Check(context.Background(), f.settings(), f.srv.Client())
	if err != nil || len(subs) != 0 {
		t.Errorf("%v %v", subs, err)
	}
	// A blob on another host is never sent the token.
	c := &Client{S: f.settings(), HTTP: f.srv.Client()}
	if _, err := c.Read(context.Background(), Blob{ContentURI: "https://evil.example/blob/1"}); err == nil || !strings.Contains(err.Error(), "another host") {
		t.Errorf("read elsewhere: %v", err)
	}
}

func contains(list []string, s string) bool {
	for _, l := range list {
		if l == s {
			return true
		}
	}
	return false
}
