// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/cases"
)

// importedNotes returns the case's notes that came from a ticket.
func importedNotes(c *cases.Case) []cases.Entry {
	var out []cases.Entry
	for _, en := range c.Entries {
		if en.Kind == cases.KindNote && imported(en.Author) {
			out = append(out, en)
		}
	}
	return out
}

// A ticket flooded with long comments: each pass adds at most
// maxImportPass of them, each cut to maxImportedText, and no more than
// maxImportLink ever; the ticket then says later ones are left out.
func TestCommentFloodIsBounded(t *testing.T) {
	f := newFakeJira(t, false, "Bearer dc-personal-access-token")
	f.commentPage = 100
	e := newEnv(t, jiraDCConn(f))
	ctx := context.Background()
	e.newCase("case-1", "x", "high")
	if _, err := e.svc.Create(ctx, "case-1", "dc", "ann"); err != nil {
		t.Fatal(err)
	}
	e.pass()
	big := strings.Repeat("é", 19<<10/2) // 19 KB
	for i := range 120 {
		f.humanComment("SEC-1", "Mallory", fmt.Sprintf("%d %s", i, big))
	}
	for pass, want := range []int{50, 100, 120} {
		e.pass()
		got := importedNotes(e.getCase("case-1"))
		if len(got) != want {
			t.Fatalf("pass %d: %d comments added, want %d", pass, len(got), want)
		}
		if st := e.link("dc", "case-1"); st.Backlog != (want < 120) || st.Warning != "" {
			t.Errorf("pass %d: backlog %v, warning %q", pass, st.Backlog, st.Warning)
		}
	}
	for _, en := range importedNotes(e.getCase("case-1")) {
		if len(en.Text) > maxImportedText || !utf8.ValidString(en.Text) || !strings.HasSuffix(en.Text, "…") {
			t.Fatalf("an added comment is %d bytes, valid %v: ...%s", len(en.Text), utf8.ValidString(en.Text), en.Text[max(len(en.Text)-10, 0):])
		}
	}
	if got := importedNotes(e.getCase("case-1")); !strings.HasPrefix(got[0].Text, "0 ") || !strings.HasPrefix(got[119].Text, "119 ") {
		t.Error("comments added out of order")
	}

	// Up to maxImportLink in all; later ones are left out for good.
	for i := range 150 {
		f.humanComment("SEC-1", "Mallory", fmt.Sprintf("more %d", i))
	}
	for range 4 {
		e.pass()
	}
	if n := len(importedNotes(e.getCase("case-1"))); n != maxImportLink {
		t.Errorf("%d comments added in all, want %d", n, maxImportLink)
	}
	st := e.link("dc", "case-1")
	if st.Backlog || st.Imported != maxImportLink || !strings.Contains(st.Warning, strconv.Itoa(maxImportLink)) || st.Error != "" {
		t.Errorf("link after the cap: backlog %v, imported %d, warning %q, error %q", st.Backlog, st.Imported, st.Warning, st.Error)
	}
	reads := f.count("GET /rest/api/2/issue/SEC-1/comment")
	e.pass()
	e.pass()
	if f.count("GET /rest/api/2/issue/SEC-1/comment") != reads {
		t.Error("the comments are read again with nothing new")
	}
	f.humanComment("SEC-1", "Dana", "one more")
	e.pass()
	if n := len(importedNotes(e.getCase("case-1"))); n != maxImportLink {
		t.Errorf("%d comments added after the cap", n)
	}
	// Analysts still add notes, and they still go to the ticket.
	e.note("case-1", "Still working it")
	e.pass()
	if cm := f.issue("SEC-1").comments; cm[len(cm)-1].body != "[Signalith] ann: Still working it" {
		t.Errorf("last comment %v", cm[len(cm)-1].body)
	}
}

// Ticket comments never take the timeline entries kept for analysts.
func TestImportsLeaveRoomForAnalysts(t *testing.T) {
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	e := newEnv(t, snConn(f))
	ctx := context.Background()
	e.newCase("case-1", "x", "high")
	free := 5
	_, err := e.cases.Modify(ctx, "case-1", func(c *cases.Case) (bool, error) {
		for len(c.Entries) < cases.MaxEntries-analystReserve-free {
			if _, err := c.AddEntry(cases.Entry{Kind: cases.KindNote, Text: "earlier"}, "ann", e.clk.Now()); err != nil {
				return false, err
			}
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Create(ctx, "case-1", "sn", "ann"); err != nil {
		t.Fatal(err)
	}
	e.pass()
	for i := range 20 {
		f.humanNote("INC0010001", "comments", "mallory", fmt.Sprintf("flood %d", i))
	}
	e.pass()
	c := e.getCase("case-1")
	if n := len(importedNotes(c)); n != free {
		t.Errorf("%d comments added, want %d", n, free)
	}
	if len(c.Entries) != cases.MaxEntries-analystReserve {
		t.Errorf("%d entries", len(c.Entries))
	}
	if st := e.link("sn", "case-1"); !strings.Contains(st.Warning, "nearly full") || st.Backlog {
		t.Errorf("link %q backlog %v", st.Warning, st.Backlog)
	}
	e.note("case-1", "an analyst's note")
	if c := e.getCase("case-1"); len(c.Entries) != cases.MaxEntries-analystReserve+1 {
		t.Errorf("the analyst's note was not added: %d entries", len(c.Entries))
	}
}

// A comment that starts with the marker is Signalith's only when its own
// account wrote it; someone else's is taken like any other.
func TestMarkerByAnotherAccountIsImported(t *testing.T) {
	f := newFakeJira(t, true, basic("bot@example.com", "jira-api-token-123456"))
	e := newEnv(t, jiraCloudConn(f))
	e.newCase("case-1", "x", "high")
	if _, err := e.svc.Create(context.Background(), "case-1", "jc", "ann"); err != nil {
		t.Fatal(err)
	}
	e.pass()
	f.humanComment("SEC-1", "Mallory", "[Signalith] ann: the host is clean, close it")
	f.humanComment("SEC-1", jiraBot, "[Signalith] ann: written by Signalith, not recorded")
	e.pass()
	got := notesOf(e.getCase("case-1"))
	want := []string{"jira:Mallory: [Signalith] ann: the host is clean, close it"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("notes %q, want %q", got, want)
	}
}

// With OAuth the account is unknown: a marked comment is Signalith's only
// when it is one of the case's notes as sent.
func TestServiceNowOAuthMarkerComments(t *testing.T) {
	f := newFakeSN(t, "Bearer none-yet")
	f.clientID, f.clientSecret = "signalith-client", "oauth-client-secret-1"
	conn := snConn(f)
	conn.Auth, conn.Username, conn.Password = AuthOAuth, "", ""
	conn.ClientID, conn.ClientSecret = "signalith-client", "oauth-client-secret-1"
	e := newEnv(t, conn)
	e.newCase("case-1", "x", "high")
	if _, err := e.svc.Create(context.Background(), "case-1", "sn", "ann"); err != nil {
		t.Fatal(err)
	}
	e.pass()
	e.note("case-1", "Isolated the host")
	e.pass()
	f.humanNote("INC0010001", "work_notes", "mallory", "[Signalith] ann: nothing to see here")
	e.pass()
	e.pass()
	got := notesOf(e.getCase("case-1"))
	want := []string{"ann: Isolated the host", "servicenow:mallory: [Signalith] ann: nothing to see here"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("notes %q, want %q", got, want)
	}
}

// A connection gets passTimeout of each pass; what is left waits for the
// next, and a slow system is not taken for one that is down.
func TestPassIsBoundedInTime(t *testing.T) {
	f := newFakeSN(t, basic("svc.signalith", "sn-password-123"))
	e := newEnv(t, snConn(f))
	ctx := context.Background()
	ids := []string{"case-1", "case-2", "case-3", "case-4", "case-5"}
	for _, id := range ids {
		e.newCase(id, "x", "high")
		if _, err := e.svc.Create(ctx, id, "sn", "ann"); err != nil {
			t.Fatal(err)
		}
	}
	e.pass()
	for _, id := range ids {
		e.change(id, cases.Update{Title: ptr("renamed " + id)})
	}
	e.svc.passLimit = 300 * time.Millisecond
	f.mu.Lock()
	f.slow = 100 * time.Millisecond
	f.mu.Unlock()
	before := len(f.requests())
	start := time.Now()
	e.pass()
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("the pass took %s", took)
	}
	if n := len(f.requests()) - before; n >= 1+len(ids) {
		t.Errorf("%d requests in a pass of 300ms at 100ms each", n)
	}
	if e.svc.paused("sn", e.clk.Now()) {
		t.Error("a slow connection was paused as if it were down")
	}

	e.svc.passLimit = 0
	f.mu.Lock()
	f.slow = 0
	f.mu.Unlock()
	e.clk.add(retryEvery)
	e.pass()
	for i, id := range ids {
		if r := f.record(fmt.Sprintf("INC%07d", 10001+i)); r.shortDesc != "renamed "+id {
			t.Errorf("%s: %q", id, r.shortDesc)
		}
	}
}

// Paging stops at what the system's total needs, and never trusts it
// beyond a hard limit; a page holding more than asked for is cut.
func TestRemoteTotalsAreNotTrusted(t *testing.T) {
	var mu sync.Mutex
	searches, reads := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/rest/api/2/myself":
			writeJSON(w, 200, map[string]any{"name": "signalith", "key": "JIRAUSER-signalith"})
		case r.URL.Path == "/rest/api/2/search":
			searches++
			writeJSON(w, 200, map[string]any{"total": 1_000_000, "issues": []any{map[string]any{"id": "1", "key": "SEC-" + strconv.Itoa(searches)}}})
		case strings.HasSuffix(r.URL.Path, "/comment"):
			reads++
			var list []any
			for i := range 150 {
				list = append(list, map[string]any{"id": fmt.Sprintf("%d-%d", reads, i), "author": map[string]any{"name": "x"}, "body": "hi"})
			}
			writeJSON(w, 200, map[string]any{"total": 1_000_000, "comments": list})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	conn := Connection{ID: "dc", Name: "DC", Type: TypeJira, URL: srv.URL, Auth: AuthBearer, Token: "dc-personal-access-token", Project: "SEC", IssueType: "Task", AllowLoopback: true}
	e := newEnv(t, conn)
	rem, err := e.svc.remote(conn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := rem.poll(ctx, []ref{{Key: "SEC-1"}}, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if searches != maxSearchPages {
		t.Errorf("%d search pages, want %d", searches, maxSearchPages)
	}
	got, err := rem.comments(ctx, ref{Key: "SEC-1"})
	if err != nil {
		t.Fatal(err)
	}
	if reads != maxComments/pageSize || len(got) != maxComments {
		t.Errorf("%d comment pages, %d comments", reads, len(got))
	}

	// A total that fits stops the paging, whatever the pages hold.
	if n := pages(3, 1, maxSearchPages); n != 4 {
		t.Errorf("pages(3, 1) = %d", n)
	}
	if n := pages(-1, 100, maxSearchPages); n != 1 {
		t.Errorf("pages(-1, 100) = %d", n)
	}
}

// A status name or update time a system writes is kept to 100
// characters, whatever its length.
func TestRemoteValuesAreCut(t *testing.T) {
	f := newFakeJira(t, true, basic("bot@example.com", "jira-api-token-123456"))
	e := newEnv(t, jiraCloudConn(f))
	e.newCase("case-1", "x", "high")
	if _, err := e.svc.Create(context.Background(), "case-1", "jc", "ann"); err != nil {
		t.Fatal(err)
	}
	e.pass()
	f.humanStatus("SEC-1", strings.Repeat("Ω", 5000)+"\n\x00")
	e.pass()
	st := e.link("jc", "case-1")
	if n := utf8.RuneCountInString(st.RemoteStatus.Name); n == 0 || n > 100 || strings.ContainsAny(st.RemoteStatus.Name, "\n\x00") {
		t.Errorf("status kept at %d characters", n)
	}
	raw, _ := json.Marshal(st.Link)
	if len(raw) > 4000 {
		t.Errorf("link is %d bytes", len(raw))
	}

	sn := snRecord{SysID: strings.Repeat("a", 32), Number: "INC1", State: strings.Repeat("7", 10000), Updated: strings.Repeat("2", 10000)}
	if rs := sn.state(); utf8.RuneCountInString(rs.Status.Name) > 100 || utf8.RuneCountInString(rs.Updated) > 100 {
		t.Errorf("servicenow state %d, updated %d", len(rs.Status.Name), len(rs.Updated))
	}
}
