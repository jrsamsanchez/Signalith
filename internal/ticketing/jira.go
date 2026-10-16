package ticketing

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// jira talks to Jira Cloud's REST API version 3, whose rich text is
// Atlassian Document Format, or Data Center's version 2, whose rich text
// is plain (wiki) text.
type jira struct{ *client }

// issueKey is the form of a Jira issue key; keys go into JQL only in this
// form.
var issueKey = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,49}-[0-9]{1,12}$`)

// api returns the path of an API resource.
func (j *jira) api(p string) string {
	if j.conn.cloud() {
		return "/rest/api/3" + p
	}
	return "/rest/api/2" + p
}

// richText is a description or comment in the form the API version takes.
func (j *jira) richText(lines []string) any {
	if j.conn.cloud() {
		return adfDoc(lines)
	}
	return strings.Join(lines, "\n")
}

// issuePath returns the path of an issue resource.
func (j *jira) issuePath(r ref, sub string) string {
	return j.api("/issue/" + url.PathEscape(r.Key) + sub)
}

// jiraStatus is a status as Jira writes it.
type jiraStatus struct {
	Name           string `json:"name"`
	StatusCategory struct {
		Key string `json:"key"`
	} `json:"statusCategory"`
}

// remote returns the status as kept on the link: names cut to 100
// characters, as everything stored from the remote is.
func (s jiraStatus) remote() RemoteStatus {
	return RemoteStatus{Name: clean(s.Name, 100), Category: clean(s.StatusCategory.Key, 100)}
}

// jiraIssue is an issue as searched or read, with the fields asked for.
type jiraIssue struct {
	ID     string `json:"id"`
	Key    string `json:"key"`
	Fields struct {
		Status   jiraStatus `json:"status"`
		Updated  string     `json:"updated"`
		Created  string     `json:"created"`
		Creator  *jiraUser  `json:"creator"`
		Reporter *jiraUser  `json:"reporter"`
	} `json:"fields"`
}

// jiraTime is how Jira writes a time, as in an issue's created field.
const jiraTime = "2006-01-02T15:04:05.000-0700"

// jiraUser is an account as Jira writes it: Cloud names it by accountId,
// Data Center by name and key.
type jiraUser struct {
	AccountID   string `json:"accountId"`
	Name        string `json:"name"`
	Key         string `json:"key"`
	DisplayName string `json:"displayName"`
}

// is reports whether u is the account me.
func (u jiraUser) is(me jiraUser) bool {
	return me.AccountID != "" && u.AccountID == me.AccountID ||
		me.Key != "" && u.Key == me.Key ||
		me.Name != "" && u.Name == me.Name
}

// self returns the account the connection signs in as (/myself), asked
// once and then remembered.
func (j *jira) self(ctx context.Context) (jiraUser, error) {
	key := j.selfKey()
	if j.selves != nil {
		if v, ok := j.selves.Load(key); ok {
			return v.(jiraUser), nil
		}
	}
	var me jiraUser
	if err := j.do(ctx, request{method: http.MethodGet, path: j.api("/myself"), out: &me}); err != nil {
		return jiraUser{}, err
	}
	if me.AccountID == "" && me.Key == "" && me.Name == "" {
		return jiraUser{}, &Error{Msg: "Jira did not say which account Signalith signs in as. Check the address."}
	}
	if j.selves != nil {
		j.selves.Store(key, me)
	}
	return me, nil
}

func (i jiraIssue) state() remoteState {
	return remoteState{ref: ref{Key: i.Key, ID: i.ID}, Status: i.Fields.Status.remote(), Updated: clean(i.Fields.Updated, 100)}
}

// quirk reports whether this connection's Jira refused something before,
// such as a field that is not on its screens (no-priority, no-labels), so
// it is no longer sent.
func (j *jira) quirk(name string) bool {
	if j.quirks == nil {
		return false
	}
	_, ok := j.quirks.Load(j.conn.ID + ":" + name)
	return ok
}

func (j *jira) noPriority() bool { return j.quirk("no-priority") }

// fieldRefused reports whether err is Jira refusing a field, and
// remembers it as the quirk no-<field>.
func (j *jira) fieldRefused(err error, field string) bool {
	e := errorOf(err)
	if e == nil || e.Code != http.StatusBadRequest || !slices.Contains(e.Fields, field) {
		return false
	}
	if j.quirks != nil {
		j.quirks.Store(j.conn.ID+":no-"+field, true)
	}
	return true
}

// priorityRefused reports whether err is Jira refusing the priority
// field, and remembers it.
func (j *jira) priorityRefused(err error) bool { return j.fieldRefused(err, "priority") }

func (j *jira) setPriority() bool { return j.conn.SetPriority && !j.noPriority() }

func (j *jira) create(ctx context.Context, t ticketContent) (created, error) {
	fields := map[string]any{
		"project":     map[string]any{"key": j.conn.Project},
		"summary":     truncateRunes(clean(t.Title, 1000), maxSummary),
		"issuetype":   map[string]any{"name": j.conn.IssueType},
		"description": j.richText(t.lines()),
	}
	if j.setPriority() {
		fields["priority"] = map[string]any{"name": j.conn.priority(t.Severity)}
	}
	if !j.quirk("no-labels") {
		// The label find looks for, so an issue opened by a server that
		// stopped before it could record it is found, not opened again.
		fields["labels"] = []string{jiraLabel(t.CaseID)}
	}
	var out struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	err := j.do(ctx, request{method: http.MethodPost, path: j.api("/issue"), body: map[string]any{"fields": fields}, out: &out})
	for tries := 0; err != nil && tries < 2; tries++ {
		// A field that is not on the project's create screen: the issue
		// is made without it.
		if fields["priority"] != nil && j.priorityRefused(err) {
			delete(fields, "priority")
		} else if fields["labels"] != nil && j.fieldRefused(err, "labels") {
			delete(fields, "labels")
		} else {
			break
		}
		err = j.do(ctx, request{method: http.MethodPost, path: j.api("/issue"), body: map[string]any{"fields": fields}, out: &out})
	}
	if err != nil {
		return created{}, err
	}
	if !issueKey.MatchString(out.Key) {
		return created{}, &Error{Msg: "Jira answered without the new issue's key. Check the address.", Retry: true}
	}
	c := created{ref: ref{Key: out.Key, ID: out.ID}, URL: strings.TrimRight(j.conn.URL, "/") + "/browse/" + url.PathEscape(out.Key)}
	var issue jiraIssue
	if err := j.do(ctx, request{method: http.MethodGet, path: j.issuePath(c.ref, ""), query: url.Values{"fields": {"status,updated"}}, out: &issue}); err == nil {
		st := issue.state()
		c.Status, c.Updated = st.Status, st.Updated
	}
	return c, nil
}

func (j *jira) update(ctx context.Context, r ref, title, severity string) error {
	fields := map[string]any{"summary": truncateRunes(clean(title, 1000), maxSummary)}
	if j.setPriority() {
		fields["priority"] = map[string]any{"name": j.conn.priority(severity)}
	}
	err := j.do(ctx, request{method: http.MethodPut, path: j.issuePath(r, ""), body: map[string]any{"fields": fields}})
	if err != nil && fields["priority"] != nil && j.priorityRefused(err) {
		delete(fields, "priority")
		err = j.do(ctx, request{method: http.MethodPut, path: j.issuePath(r, ""), body: map[string]any{"fields": fields}})
	}
	return err
}

// jiraTransition is a move an issue's workflow allows from its status.
type jiraTransition struct {
	ID   string     `json:"id"`
	Name string     `json:"name"`
	To   jiraStatus `json:"to"`
}

func (j *jira) setStatus(ctx context.Context, r ref, caseStatus, _ string) (RemoteStatus, error) {
	var out struct {
		Transitions []jiraTransition `json:"transitions"`
	}
	if err := j.do(ctx, request{method: http.MethodGet, path: j.issuePath(r, "/transitions"), out: &out}); err != nil {
		return RemoteStatus{}, err
	}
	pick := -1
	if names := j.conn.jiraNames(caseStatus); len(names) > 0 {
		for _, n := range names {
			if pick = slices.IndexFunc(out.Transitions, func(t jiraTransition) bool { return strings.EqualFold(t.To.Name, n) }); pick >= 0 {
				break
			}
		}
	} else {
		cat := jiraCategory(caseStatus)
		for i, t := range out.Transitions {
			if t.To.StatusCategory.Key == cat {
				pick = i
				break
			}
		}
	}
	if pick < 0 {
		want := strings.Join(j.conn.jiraNames(caseStatus), " or ")
		if want == "" {
			want = map[string]string{"new": "To Do", "indeterminate": "In Progress", "done": "Done"}[jiraCategory(caseStatus)] + " (or another status of that category)"
		}
		return RemoteStatus{}, &Error{Msg: fmt.Sprintf("Jira's workflow has no transition from %s to %s for issue %s, so it was not moved to match the case (%s). Map the case statuses to statuses the workflow can reach on the Ticketing page.",
			r.Key, want, r.Key, label(caseStatus))}
	}
	t := out.Transitions[pick]
	err := j.do(ctx, request{method: http.MethodPost, path: j.issuePath(r, "/transitions"), body: map[string]any{"transition": map[string]any{"id": t.ID}}})
	if err != nil {
		return RemoteStatus{}, err
	}
	return t.To.remote(), nil
}

func (j *jira) comment(ctx context.Context, r ref, text string) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	lines := strings.Split(text, "\n")
	err := j.do(ctx, request{method: http.MethodPost, path: j.issuePath(r, "/comment"), body: map[string]any{"body": j.richText(lines)}, out: &out})
	return out.ID, err
}

// jql returns the search for some issues by key, changed in the last
// minutes when minutes is above 0. Jira reads a date in a JQL query in the
// time zone of the account's profile, so a relative one ("-15m") is used,
// which needs no time zone.
func jql(keys []string, minutes int) string {
	q := "issuekey in (" + strings.Join(keys, ", ") + ")"
	if minutes > 0 {
		q += fmt.Sprintf(` AND updated >= "-%dm"`, minutes)
	}
	return q + " ORDER BY updated ASC"
}

// sinceMinutes returns how many whole minutes back a poll since a time
// looks, or 0 for all.
func sinceMinutes(since, now time.Time) int {
	if since.IsZero() {
		return 0
	}
	return max(int(now.Sub(since).Minutes())+1, 1)
}

func (j *jira) poll(ctx context.Context, refs []ref, since time.Time) ([]remoteState, error) {
	minutes := sinceMinutes(since, j.now())
	var out []remoteState
	for _, chunk := range chunks(refs, pollChunk) {
		var keys []string
		for _, r := range chunk {
			if issueKey.MatchString(r.Key) {
				keys = append(keys, r.Key)
			}
		}
		if len(keys) == 0 {
			continue
		}
		got, err := j.search(ctx, jql(keys, minutes))
		if e := errorOf(err); e != nil && e.Code == http.StatusBadRequest {
			// Jira refuses a search that names an issue that no longer
			// exists: ask about each one instead.
			got, err = j.each(ctx, keys)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
	}
	return out, nil
}

// maxSearchPages bounds the pages of one search.
const maxSearchPages = 100

// search returns the state of the issues a JQL query finds, every page.
func (j *jira) search(ctx context.Context, q string) ([]remoteState, error) {
	issues, err := j.searchIssues(ctx, q, []string{"status", "updated"}, maxSearchPages)
	if err != nil {
		return nil, err
	}
	out := make([]remoteState, 0, len(issues))
	for _, i := range issues {
		out = append(out, i.state())
	}
	return out, nil
}

// searchIssues returns the issues a JQL query finds, with fields, reading
// at most most pages of pageSize.
func (j *jira) searchIssues(ctx context.Context, q string, fields []string, most int) ([]jiraIssue, error) {
	var out []jiraIssue
	if j.conn.cloud() {
		// Jira Cloud's search pages with a token (the old /search is
		// gone).
		token := ""
		for page := 0; page < most; page++ {
			body := map[string]any{"jql": q, "fields": fields, "maxResults": pageSize}
			if token != "" {
				body["nextPageToken"] = token
			}
			var res struct {
				Issues        []jiraIssue `json:"issues"`
				NextPageToken string      `json:"nextPageToken"`
				IsLast        *bool       `json:"isLast"`
			}
			if err := j.do(ctx, request{method: http.MethodPost, path: "/rest/api/3/search/jql", body: body, out: &res}); err != nil {
				return nil, err
			}
			out = append(out, res.Issues[:min(len(res.Issues), pageSize)]...)
			if res.NextPageToken == "" || (res.IsLast != nil && *res.IsLast) || len(res.Issues) == 0 {
				return out, nil
			}
			token = res.NextPageToken
		}
		return out, nil
	}
	for page, start := 0, 0; page < most; page++ {
		var res struct {
			Issues []jiraIssue `json:"issues"`
			Total  int         `json:"total"`
		}
		body := map[string]any{"jql": q, "fields": fields, "startAt": start, "maxResults": pageSize}
		if err := j.do(ctx, request{method: http.MethodPost, path: "/rest/api/2/search", body: body, out: &res}); err != nil {
			return nil, err
		}
		got := res.Issues[:min(len(res.Issues), pageSize)]
		if page == 0 {
			// Jira may answer with smaller pages than asked for.
			most = pages(res.Total, len(got), most)
		}
		out = append(out, got...)
		start += len(got)
		if len(got) == 0 || start >= res.Total {
			break
		}
	}
	return out, nil
}

// find looks for the issue opened earlier for a case by its label, in the
// connection's project: one the connection's own account created at or
// after since, the newest when there are several. Someone else's issue
// with the label is never taken, nor one older than the case's link.
func (j *jira) find(ctx context.Context, caseID string, since time.Time) (*created, error) {
	if !projectForm.MatchString(j.conn.Project) {
		return nil, nil
	}
	me, err := j.self(ctx)
	if err != nil {
		if retryable(err) {
			return nil, err
		}
		// It cannot tell its own issues, so it takes none.
		return nil, nil
	}
	q := fmt.Sprintf(`project = "%s" AND labels = "%s" AND creator = currentUser() ORDER BY created DESC`, j.conn.Project, jiraLabel(caseID))
	got, err := j.searchIssues(ctx, q, []string{"status", "updated", "created", "creator", "reporter"}, 1)
	if err != nil {
		return nil, err
	}
	for _, i := range got {
		if !issueKey.MatchString(i.Key) {
			continue
		}
		// The creator cannot be changed; only a Jira that does not
		// say who created an issue is asked about its reporter.
		by := i.Fields.Creator
		if by == nil {
			by = i.Fields.Reporter
		}
		if by == nil || !by.is(me) {
			continue
		}
		at, err := time.Parse(jiraTime, i.Fields.Created)
		if err != nil || at.Before(since) {
			continue
		}
		rs := i.state()
		return &created{ref: rs.ref, URL: strings.TrimRight(j.conn.URL, "/") + "/browse/" + url.PathEscape(rs.Key), Status: rs.Status, Updated: rs.Updated}, nil
	}
	return nil, nil
}

// each reads issues one by one; one that is not found is gone.
func (j *jira) each(ctx context.Context, keys []string) ([]remoteState, error) {
	var out []remoteState
	for _, k := range keys {
		var issue jiraIssue
		err := j.do(ctx, request{method: http.MethodGet, path: j.issuePath(ref{Key: k}, ""), query: url.Values{"fields": {"status,updated"}}, out: &issue})
		if e := errorOf(err); e != nil && e.Code == http.StatusNotFound {
			out = append(out, remoteState{ref: ref{Key: k}, Gone: true})
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, issue.state())
	}
	return out, nil
}

// jiraComment is a comment as Jira writes it; its body is ADF (version 3)
// or text (version 2).
type jiraComment struct {
	ID     string          `json:"id"`
	Author jiraUser        `json:"author"`
	Body   json.RawMessage `json:"body"`
}

// text returns the comment's body as plain text.
func (c jiraComment) text() string {
	return bodyText(c.Body)
}

// bodyText returns a rich text field as plain text: a JSON string as it
// is, or the text of an ADF document.
func bodyText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var doc any
	if json.Unmarshal(raw, &doc) != nil {
		return ""
	}
	return adfText(doc)
}

func (j *jira) comments(ctx context.Context, r ref) ([]comment, error) {
	me, err := j.self(ctx)
	if err != nil && retryable(err) {
		return nil, err
	}
	known := err == nil
	var out []comment
	most := maxCommentPages
	for page, start := 0, 0; page < most && start < maxComments; page++ {
		var res struct {
			Comments []jiraComment `json:"comments"`
			Total    int           `json:"total"`
		}
		q := url.Values{"startAt": {strconv.Itoa(start)}, "maxResults": {strconv.Itoa(pageSize)}, "orderBy": {"created"}}
		if err := j.do(ctx, request{method: http.MethodGet, path: j.issuePath(r, "/comment"), query: q, out: &res}); err != nil {
			return nil, err
		}
		got := res.Comments[:min(len(res.Comments), pageSize)]
		if page == 0 {
			most = pages(res.Total, len(got), most)
		}
		for _, c := range got {
			name := c.Author.DisplayName
			if name == "" {
				name = c.Author.Name
			}
			out = append(out, comment{ID: c.ID, Author: name, Text: c.text(), Own: known && c.Author.is(me), OwnUnknown: !known})
		}
		start += len(got)
		if len(got) == 0 || start >= res.Total {
			break
		}
	}
	return out, nil
}

func (j *jira) test(ctx context.Context) (string, error) {
	var me struct {
		DisplayName  string `json:"displayName"`
		Name         string `json:"name"`
		EmailAddress string `json:"emailAddress"`
	}
	if err := j.do(ctx, request{method: http.MethodGet, path: j.api("/myself"), out: &me}); err != nil {
		return "", err
	}
	who := me.DisplayName
	if who == "" {
		who = me.Name
	}
	var project struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}
	err := j.do(ctx, request{method: http.MethodGet, path: j.api("/project/" + url.PathEscape(j.conn.Project)), out: &project})
	if e := errorOf(err); e != nil && e.Code == http.StatusNotFound {
		return "", &Error{Msg: fmt.Sprintf("Signed in as %s, but there is no project %s, or the account cannot see it. Check the project key and the account's permissions.", who, j.conn.Project), Code: e.Code}
	}
	if err != nil {
		return "", err
	}
	msg := fmt.Sprintf("Signed in as %s. Project %s (%s) can be reached.", who, project.Name, project.Key)
	var types struct {
		IssueTypes []struct {
			Name string `json:"name"`
		} `json:"issueTypes"`
		Values []struct {
			Name string `json:"name"`
		} `json:"values"`
	}
	err = j.do(ctx, request{method: http.MethodGet, path: j.api("/issue/createmeta/" + url.PathEscape(j.conn.Project) + "/issuetypes"), out: &types})
	if err != nil {
		// Older Jira versions have no such resource; creating a ticket
		// will tell.
		return msg + " The issue types could not be checked.", nil
	}
	var names []string
	for _, t := range append(types.IssueTypes, types.Values...) {
		names = append(names, t.Name)
	}
	if !slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, j.conn.IssueType) }) {
		return "", &Error{Msg: fmt.Sprintf("%s But the project has no issue type %s that the account can create; it has %s.", msg, j.conn.IssueType, strings.Join(names, ", "))}
	}
	return msg + fmt.Sprintf(" Issues of type %s can be created.", j.conn.IssueType), nil
}
