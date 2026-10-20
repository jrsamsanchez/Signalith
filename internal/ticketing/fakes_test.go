// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The fakes below implement the part of Jira's and ServiceNow's APIs the
// sync uses, closely enough to test it end to end: the real services are
// not reachable from tests.

// fault is an answer a fake gives instead of the real one, count times.
type fault struct {
	match      string // "METHOD /path prefix"
	status     int
	retryAfter string
	body       string
	count      int
}

// fakeBase holds what both fakes share: the request log, the expected
// Authorization header and the faults to inject.
type fakeBase struct {
	t    *testing.T
	mu   sync.Mutex
	srv  *httptest.Server
	auth string // the Authorization header every request must carry
	log  []string
	// faults are answered before the real handler, in order.
	faults []*fault
	seq    int
	// now is when the fake says a ticket was created; nil is 09:00 on
	// the test clock's day.
	now func() time.Time
	// slow is how long each answer takes.
	slow time.Duration
}

func (f *fakeBase) URL() string { return f.srv.URL }

// clock returns the fake's time. f.mu is held.
func (f *fakeBase) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
}

// caPEM returns the TLS server's certificate as PEM, for CAPEM.
func (f *fakeBase) caPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}))
}

func (f *fakeBase) inject(ft fault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ft.count == 0 {
		ft.count = 1
	}
	f.faults = append(f.faults, &ft)
}

// requests returns the requests seen, as "METHOD /path?query".
func (f *fakeBase) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

func (f *fakeBase) count(prefix string) int {
	n := 0
	for _, r := range f.requests() {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

// front logs a request, checks its authorization and answers a fault; it
// reports whether the handler should go on. f.mu is held on return when
// it does.
func (f *fakeBase) front(w http.ResponseWriter, r *http.Request, skipAuth bool) bool {
	f.mu.Lock()
	slow := f.slow
	f.mu.Unlock()
	time.Sleep(slow)
	f.mu.Lock()
	line := r.Method + " " + r.URL.Path
	if r.URL.RawQuery != "" {
		line += "?" + r.URL.RawQuery
	}
	f.log = append(f.log, line)
	for _, ft := range f.faults {
		if ft.count > 0 && strings.HasPrefix(r.Method+" "+r.URL.Path, ft.match) {
			ft.count--
			f.mu.Unlock()
			if ft.retryAfter != "" {
				w.Header().Set("Retry-After", ft.retryAfter)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ft.status)
			io.WriteString(w, ft.body)
			return false
		}
	}
	if !skipAuth && f.auth != "" && r.Header.Get("Authorization") != f.auth {
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		// Some systems echo what they were sent; the client must not
		// show it.
		fmt.Fprintf(w, `{"errorMessages":["Client must be authenticated: got %s"]}`, r.Header.Get("Authorization"))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------- Jira ----------

type fakeIssue struct {
	id, key, summary, priority, status, issueType string
	description                                   any
	updated                                       int
	comments                                      []fakeComment
	labels                                        []string
	// creator is who created the issue, by display name; jiraBot is
	// Signalith's account.
	creator string
	created time.Time
}

// jiraBot is the display name of the account Signalith signs in to the
// fake Jira as.
const jiraBot = "Signalith Bot"

// userJSON is an account as Jira writes it: Cloud by accountId, Data
// Center by name and key.
func (f *fakeJira) userJSON(name string) map[string]any {
	id := strings.ToLower(strings.ReplaceAll(name, " ", "."))
	if name == jiraBot {
		id = "signalith"
	}
	if f.cloud {
		return map[string]any{"accountId": "557058:" + id, "displayName": name}
	}
	return map[string]any{"name": id, "key": "JIRAUSER-" + id, "displayName": name}
}

// plant makes an issue with a case's label, as anyone who can create
// issues in the project could.
func (f *fakeJira) plant(caseID, creator string, created time.Time) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.made++
	i := &fakeIssue{id: strconv.Itoa(10000 + f.made), key: "SEC-" + strconv.Itoa(f.made), status: "To Do", summary: "planted",
		labels: []string{jiraLabel(caseID)}, creator: creator, created: created, updated: f.stamp()}
	f.issues[i.key] = i
	return i.key
}

type fakeComment struct {
	id, author string
	body       any
}

// jiraStatuses is the fake's workflow: every status can move to every
// other.
var jiraStatuses = map[string]string{"To Do": "new", "In Progress": "indeterminate", "Waiting for customer": "indeterminate", "Done": "done", "Won't Do": "done"}

type fakeJira struct {
	fakeBase
	cloud       bool
	issues      map[string]*fakeIssue
	noPriority  bool     // the priority field is not on the screen
	noLabels    bool     // nor the labels field
	lastJQL     []string // every search
	pageSize    int      // issues per search page; 0 is 100
	commentPage int      // comments per page; 0 is 2
	made        int      // issues created
}

func newFakeJira(t *testing.T, cloud bool, auth string) *fakeJira {
	f := &fakeJira{fakeBase: fakeBase{t: t, auth: auth}, cloud: cloud, issues: map[string]*fakeIssue{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeJira) stamp() int { f.seq++; return f.seq }

// updated writes an update counter the way Jira writes a time.
func updatedText(n int) string {
	return time.Date(2026, 10, 16, 10, 0, 0, 0, time.UTC).Add(time.Duration(n) * time.Second).Format("2006-01-02T15:04:05.000-0700")
}

func (f *fakeJira) issueJSON(i *fakeIssue) map[string]any {
	return map[string]any{"id": i.id, "key": i.key, "fields": map[string]any{
		"status":   map[string]any{"name": i.status, "statusCategory": map[string]any{"key": jiraStatuses[i.status]}},
		"updated":  updatedText(i.updated),
		"created":  i.created.Format(jiraTime),
		"creator":  f.userJSON(i.creator),
		"reporter": f.userJSON(i.creator),
	}}
}

// human changes an issue as a person in Jira would.
func (f *fakeJira) humanComment(key, author, text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.issues[key]
	var body any = text
	if f.cloud {
		body = adfDoc(strings.Split(text, "\n"))
	}
	i.comments = append(i.comments, fakeComment{id: strconv.Itoa(10000 + f.stamp()), author: author, body: body})
	i.updated = f.stamp()
}

func (f *fakeJira) humanStatus(key, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issues[key].status = status
	f.issues[key].updated = f.stamp()
}

func (f *fakeJira) issue(key string) fakeIssue {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := *f.issues[key]
	i.comments = append([]fakeComment(nil), i.comments...)
	return i
}

func (f *fakeJira) delete(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.issues, key)
}

var (
	jqlKeys  = regexp.MustCompile(`issuekey in \(([^)]*)\)`)
	jqlLabel = regexp.MustCompile(`^project = "([^"]*)" AND labels = "([^"]*)" AND creator = currentUser\(\) ORDER BY created DESC$`)
)

func (f *fakeJira) serve(w http.ResponseWriter, r *http.Request) {
	if !f.front(w, r, false) {
		return
	}
	defer f.mu.Unlock()
	v := "2"
	if f.cloud {
		v = "3"
	}
	api := "/rest/api/" + v
	if r.Header.Get("X-Atlassian-Token") != "no-check" && r.Method != http.MethodGet {
		writeJSON(w, http.StatusForbidden, map[string]any{"errorMessages": []string{"XSRF check failed"}})
		return
	}
	var body map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	p := r.URL.Path
	switch {
	case r.Method == http.MethodGet && p == api+"/myself":
		writeJSON(w, 200, f.userJSON(jiraBot))
	case r.Method == http.MethodGet && p == api+"/project/SEC":
		writeJSON(w, 200, map[string]any{"key": "SEC", "name": "Security"})
	case r.Method == http.MethodGet && strings.HasPrefix(p, api+"/project/"):
		writeJSON(w, 404, map[string]any{"errorMessages": []string{"No project could be found"}})
	case r.Method == http.MethodGet && p == api+"/issue/createmeta/SEC/issuetypes":
		key := "values"
		if f.cloud {
			key = "issueTypes"
		}
		writeJSON(w, 200, map[string]any{key: []any{map[string]any{"name": "Task"}, map[string]any{"name": "Incident"}}})
	case r.Method == http.MethodPost && p == api+"/issue":
		fields, _ := body["fields"].(map[string]any)
		if _, ok := fields["priority"]; ok && f.noPriority {
			writeJSON(w, 400, map[string]any{"errorMessages": []string{}, "errors": map[string]any{"priority": "Field 'priority' cannot be set. It is not on the appropriate screen, or unknown."}})
			return
		}
		if _, ok := fields["labels"]; ok && f.noLabels {
			writeJSON(w, 400, map[string]any{"errorMessages": []string{}, "errors": map[string]any{"labels": "Field 'labels' cannot be set. It is not on the appropriate screen, or unknown."}})
			return
		}
		if fields["project"].(map[string]any)["key"] != "SEC" {
			writeJSON(w, 400, map[string]any{"errors": map[string]any{"project": "valid project is required"}})
			return
		}
		if f.cloud {
			if d, ok := fields["description"].(map[string]any); !ok || d["type"] != "doc" {
				writeJSON(w, 400, map[string]any{"errors": map[string]any{"description": "Operation value must be an Atlassian Document"}})
				return
			}
		} else if _, ok := fields["description"].(string); !ok {
			writeJSON(w, 400, map[string]any{"errors": map[string]any{"description": "Operation value must be a string"}})
			return
		}
		f.made++
		n := f.made
		i := &fakeIssue{id: strconv.Itoa(10000 + n), key: "SEC-" + strconv.Itoa(n), status: "To Do", description: fields["description"], updated: f.stamp(),
			creator: jiraBot, created: f.clock()}
		i.summary, _ = fields["summary"].(string)
		i.issueType, _ = fields["issuetype"].(map[string]any)["name"].(string)
		if pr, ok := fields["priority"].(map[string]any); ok {
			i.priority, _ = pr["name"].(string)
		}
		if ls, ok := fields["labels"].([]any); ok {
			for _, l := range ls {
				s, _ := l.(string)
				if strings.ContainsAny(s, " \t") {
					writeJSON(w, 400, map[string]any{"errors": map[string]any{"labels": "Labels cannot contain spaces."}})
					return
				}
				i.labels = append(i.labels, s)
			}
		}
		f.issues[i.key] = i
		writeJSON(w, 201, map[string]any{"id": i.id, "key": i.key, "self": f.srv.URL + api + "/issue/" + i.id})
	case (r.Method == http.MethodPost && p == "/rest/api/3/search/jql" && f.cloud) || (r.Method == http.MethodPost && p == "/rest/api/2/search" && !f.cloud):
		jql, _ := body["jql"].(string)
		f.lastJQL = append(f.lastJQL, jql)
		var list []any
		m := jqlKeys.FindStringSubmatch(jql)
		if lm := jqlLabel.FindStringSubmatch(jql); m == nil && lm != nil {
			// By label in a project, oldest first, as find asks.
			if lm[1] != "SEC" {
				writeJSON(w, 400, map[string]any{"errorMessages": []string{"The value '" + lm[1] + "' does not exist for the field 'project'."}})
				return
			}
			// Newest first. The creator clause is left to the client's
			// own check, which is what the tests try.
			var found []*fakeIssue
			for n := 1; n <= f.made; n++ {
				if i, ok := f.issues["SEC-"+strconv.Itoa(n)]; ok && slices.Contains(i.labels, lm[2]) {
					found = append(found, i)
				}
			}
			slices.SortStableFunc(found, func(a, b *fakeIssue) int { return b.created.Compare(a.created) })
			for _, i := range found {
				list = append(list, f.issueJSON(i))
			}
			m = []string{"", ""}
		} else if m == nil {
			writeJSON(w, 400, map[string]any{"errorMessages": []string{"bad JQL"}})
			return
		}
		for _, k := range strings.Split(m[1], ",") {
			if m[1] == "" {
				break
			}
			k = strings.TrimSpace(k)
			i, ok := f.issues[k]
			if !ok {
				writeJSON(w, 400, map[string]any{"errorMessages": []string{"An issue with key '" + k + "' does not exist for field 'issuekey'."}})
				return
			}
			list = append(list, f.issueJSON(i))
		}
		size := f.pageSize
		if size == 0 {
			size = 100
		}
		start := 0
		if f.cloud {
			if tok, _ := body["nextPageToken"].(string); tok != "" {
				start, _ = strconv.Atoi(tok)
			}
		} else if s, ok := body["startAt"].(float64); ok {
			start = int(s)
		}
		end := min(start+size, len(list))
		page := list[min(start, len(list)):end]
		if f.cloud {
			res := map[string]any{"issues": page, "isLast": end >= len(list)}
			if end < len(list) {
				res["nextPageToken"] = strconv.Itoa(end)
			}
			writeJSON(w, 200, res)
		} else {
			writeJSON(w, 200, map[string]any{"issues": page, "total": len(list), "startAt": start, "maxResults": size})
		}
	case strings.HasPrefix(p, api+"/issue/"):
		rest := strings.TrimPrefix(p, api+"/issue/")
		key, sub, _ := strings.Cut(rest, "/")
		i, ok := f.issues[key]
		if !ok {
			writeJSON(w, 404, map[string]any{"errorMessages": []string{"Issue does not exist or you do not have permission to see it."}})
			return
		}
		switch {
		case sub == "" && r.Method == http.MethodGet:
			writeJSON(w, 200, f.issueJSON(i))
		case sub == "" && r.Method == http.MethodPut:
			fields, _ := body["fields"].(map[string]any)
			if _, ok := fields["priority"]; ok && f.noPriority {
				writeJSON(w, 400, map[string]any{"errors": map[string]any{"priority": "Field 'priority' cannot be set."}})
				return
			}
			if s, ok := fields["summary"].(string); ok {
				i.summary = s
			}
			if pr, ok := fields["priority"].(map[string]any); ok {
				i.priority, _ = pr["name"].(string)
			}
			i.updated = f.stamp()
			w.WriteHeader(204)
		case sub == "transitions" && r.Method == http.MethodGet:
			var list []any
			n := 0
			for name, cat := range jiraStatuses {
				if name == i.status {
					continue
				}
				n++
				list = append(list, map[string]any{"id": "t-" + name, "name": "Move to " + name, "to": map[string]any{"name": name, "statusCategory": map[string]any{"key": cat}}})
			}
			// A stable order, as Jira's is.
			sortTransitions(list)
			writeJSON(w, 200, map[string]any{"transitions": list})
		case sub == "transitions" && r.Method == http.MethodPost:
			tr, _ := body["transition"].(map[string]any)
			id, _ := tr["id"].(string)
			name := strings.TrimPrefix(id, "t-")
			if _, ok := jiraStatuses[name]; !ok || name == i.status {
				writeJSON(w, 400, map[string]any{"errorMessages": []string{"Transition id '" + id + "' is not valid for this issue."}})
				return
			}
			i.status = name
			i.updated = f.stamp()
			w.WriteHeader(204)
		case sub == "comment" && r.Method == http.MethodPost:
			b := body["body"]
			if f.cloud {
				if d, ok := b.(map[string]any); !ok || d["type"] != "doc" {
					writeJSON(w, 400, map[string]any{"errors": map[string]any{"comment": "Comment body is not valid ADF"}})
					return
				}
			} else if _, ok := b.(string); !ok {
				writeJSON(w, 400, map[string]any{"errors": map[string]any{"comment": "Comment body can not be empty!"}})
				return
			}
			c := fakeComment{id: strconv.Itoa(10000 + f.stamp()), author: jiraBot, body: b}
			i.comments = append(i.comments, c)
			i.updated = f.stamp()
			writeJSON(w, 201, map[string]any{"id": c.id})
		case sub == "comment" && r.Method == http.MethodGet:
			start, _ := strconv.Atoi(r.URL.Query().Get("startAt"))
			size := f.commentPage
			if size == 0 {
				size = 2 // small pages, so paging is tested
			}
			var list []any
			for _, c := range i.comments[min(start, len(i.comments)):min(start+size, len(i.comments))] {
				list = append(list, map[string]any{"id": c.id, "author": f.userJSON(c.author), "body": c.body})
			}
			writeJSON(w, 200, map[string]any{"comments": list, "total": len(i.comments), "startAt": start, "maxResults": size})
		default:
			writeJSON(w, 404, map[string]any{"errorMessages": []string{"no such resource"}})
		}
	default:
		writeJSON(w, 404, map[string]any{"errorMessages": []string{"no such resource: " + p}})
	}
}

func sortTransitions(list []any) {
	name := func(x any) string { return x.(map[string]any)["to"].(map[string]any)["name"].(string) }
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && name(list[j]) < name(list[j-1]); j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
}

// ---------- ServiceNow ----------

type fakeRecord struct {
	sysID, number, shortDesc, description, impact, urgency, state, closeCode, closeNotes, caller string
	correlationID, correlationDisplay                                                            string
	updated                                                                                      int
	createdBy                                                                                    string
	createdOn                                                                                    time.Time
}

// snOAuthUser is the user an OAuth client acts as in the fake.
const snOAuthUser = "signalith.oauth"

// snRequestUser is who a request signs in as: the basic auth user, or
// the OAuth application's user.
func snRequestUser(r *http.Request) string {
	if u, _, ok := r.BasicAuth(); ok {
		return u
	}
	return snOAuthUser
}

// plant makes a ticket with a case's correlation ID, as anyone who can
// open tickets could.
func (f *fakeSN) plant(caseID, by string, created time.Time) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(f.records) + 1
	rec := &fakeRecord{sysID: fmt.Sprintf("%032x", n), number: fmt.Sprintf("INC%07d", 10000+n), state: "1", shortDesc: "planted",
		correlationID: correlationID(caseID), createdBy: by, createdOn: created, updated: f.stamp()}
	f.records[rec.sysID] = rec
	return rec.number
}

type fakeJournal struct {
	sysID, element, value, by, recordID string
}

type fakeSN struct {
	fakeBase
	records map[string]*fakeRecord // by sys_id
	journal []fakeJournal
	// oauth: client credentials and the tokens issued.
	clientID, clientSecret string
	tokens                 []string
	journalForbidden       bool
}

func newFakeSN(t *testing.T, auth string) *fakeSN {
	f := &fakeSN{fakeBase: fakeBase{t: t, auth: auth}, records: map[string]*fakeRecord{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSN) stamp() int { f.seq++; return f.seq }

func (f *fakeSN) recordJSON(r *fakeRecord) map[string]any {
	return map[string]any{"sys_id": r.sysID, "number": r.number, "state": r.state,
		"sys_updated_on": time.Date(2026, 10, 16, 10, 0, 0, 0, time.UTC).Add(time.Duration(r.updated) * time.Second).Format("2006-01-02 15:04:05"),
		"sys_created_by": r.createdBy, "sys_created_on": r.createdOn.UTC().Format(snTime)}
}

func (f *fakeSN) humanNote(number, element, by, text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.records {
		if r.number == number {
			f.journal = append(f.journal, fakeJournal{sysID: fmt.Sprintf("%032x", 1<<40+f.stamp()), element: element, value: text, by: by, recordID: r.sysID})
			r.updated = f.stamp()
		}
	}
}

func (f *fakeSN) humanState(number, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.records {
		if r.number == number {
			r.state = state
			r.updated = f.stamp()
		}
	}
}

func (f *fakeSN) record(number string) fakeRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.records {
		if r.number == number {
			return *r
		}
	}
	return fakeRecord{}
}

func (f *fakeSN) notes(number string) []fakeJournal {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakeJournal
	for _, r := range f.records {
		if r.number != number {
			continue
		}
		for _, j := range f.journal {
			if j.recordID == r.sysID {
				out = append(out, j)
			}
		}
	}
	return out
}

func (f *fakeSN) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/oauth_token.do" {
		if !f.front(w, r, true) {
			return
		}
		defer f.mu.Unlock()
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != f.clientID || r.PostForm.Get("client_secret") != f.clientSecret {
			writeJSON(w, 401, map[string]any{"error": "access_denied", "error_description": "invalid client " + r.PostForm.Get("client_secret")})
			return
		}
		tok := fmt.Sprintf("snow-access-token-%d", len(f.tokens)+1)
		f.tokens = append(f.tokens, tok)
		f.auth = "Bearer " + tok
		writeJSON(w, 200, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 1799})
		return
	}
	if !f.front(w, r, false) {
		return
	}
	defer f.mu.Unlock()
	var body map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	str := func(k string) string { s, _ := body[k].(string); return s }
	p := r.URL.Path
	q := r.URL.Query()
	if q.Get("sysparm_display_value") != "false" {
		writeJSON(w, 400, map[string]any{"error": map[string]any{"message": "expected sysparm_display_value=false"}})
		return
	}
	switch {
	case p == "/api/now/table/incident" && r.Method == http.MethodPost:
		n := len(f.records) + 1
		rec := &fakeRecord{sysID: fmt.Sprintf("%032x", n), number: fmt.Sprintf("INC%07d", 10000+n), state: "1",
			shortDesc: str("short_description"), description: str("description"), impact: str("impact"), urgency: str("urgency"),
			caller: str("caller_id"), correlationID: str("correlation_id"), correlationDisplay: str("correlation_display"), updated: f.stamp(),
			createdBy: snRequestUser(r), createdOn: f.clock()}
		f.records[rec.sysID] = rec
		writeJSON(w, 201, map[string]any{"result": f.recordJSON(rec)})
	case p == "/api/now/table/incident" && r.Method == http.MethodGet:
		query := q.Get("sysparm_query")
		var list []any
		if rest, ok := strings.CutPrefix(query, "correlation_id="); ok {
			// Newest first when asked. The sys_created_by clause is left
			// to the client's own check, which is what the tests try.
			want, _, _ := strings.Cut(rest, "^")
			var found []*fakeRecord
			for n := 1; n <= len(f.records); n++ {
				if rec := f.records[fmt.Sprintf("%032x", n)]; rec != nil && rec.correlationID == want {
					found = append(found, rec)
				}
			}
			if strings.HasSuffix(query, "^ORDERBYDESCsys_created_on") {
				slices.SortStableFunc(found, func(a, b *fakeRecord) int { return b.createdOn.Compare(a.createdOn) })
			}
			if n, err := strconv.Atoi(q.Get("sysparm_limit")); err == nil && n < len(found) {
				found = found[:n]
			}
			list = []any{}
			for _, rec := range found {
				list = append(list, f.recordJSON(rec))
			}
		} else if rest, ok := strings.CutPrefix(query, "sys_idIN"); ok {
			ids, _, _ := strings.Cut(rest, "^")
			for _, id := range strings.Split(ids, ",") {
				if rec, ok := f.records[id]; ok {
					list = append(list, f.recordJSON(rec))
				}
			}
		} else if len(f.records) > 0 || q.Get("sysparm_limit") == "1" {
			list = []any{}
		}
		writeJSON(w, 200, map[string]any{"result": list})
	case strings.HasPrefix(p, "/api/now/table/incident/"):
		id := strings.TrimPrefix(p, "/api/now/table/incident/")
		rec, ok := f.records[id]
		if !ok {
			writeJSON(w, 404, map[string]any{"error": map[string]any{"message": "No Record found", "detail": "Record doesn't exist or ACL restricts the record retrieval"}, "status": "failure"})
			return
		}
		if r.Method == http.MethodPatch {
			if st := str("state"); st != "" {
				if (st == "6" || st == "7") && (str("close_code") == "" || str("close_notes") == "") {
					writeJSON(w, 403, map[string]any{"error": map[string]any{"message": "Operation Failed", "detail": "Data Policy Exception: Resolution code and notes are mandatory"}})
					return
				}
				rec.state, rec.closeCode, rec.closeNotes = st, str("close_code"), str("close_notes")
			}
			if s := str("short_description"); s != "" {
				rec.shortDesc = s
			}
			if s := str("impact"); s != "" {
				rec.impact, rec.urgency = s, str("urgency")
			}
			for _, el := range []string{"work_notes", "comments"} {
				if s := str(el); s != "" {
					f.journal = append(f.journal, fakeJournal{sysID: fmt.Sprintf("%032x", 1<<41+f.stamp()), element: el, value: s, by: snRequestUser(r), recordID: rec.sysID})
				}
			}
			rec.updated = f.stamp()
		}
		writeJSON(w, 200, map[string]any{"result": f.recordJSON(rec)})
	case p == "/api/now/table/sys_journal_field" && r.Method == http.MethodGet:
		if f.journalForbidden {
			writeJSON(w, 403, map[string]any{"error": map[string]any{"message": "User Not Authorized"}})
			return
		}
		query := q.Get("sysparm_query")
		var list []any
		if rest, ok := strings.CutPrefix(query, "element_id="); ok {
			id, _, _ := strings.Cut(rest, "^")
			for _, j := range f.journal {
				if j.recordID == id {
					list = append(list, map[string]any{"sys_id": j.sysID, "element": j.element, "value": j.value, "sys_created_by": j.by})
				}
			}
		}
		writeJSON(w, 200, map[string]any{"result": list})
	default:
		writeJSON(w, 400, map[string]any{"error": map[string]any{"message": "Invalid table " + p}})
	}
}
