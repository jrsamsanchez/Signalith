package ticketing

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

// serviceNow talks to ServiceNow's Table API. Comments go to the
// ticket's journal (work_notes or comments) and are read back from the
// sys_journal_field table.
type serviceNow struct{ *client }

// sysID is the form of a ServiceNow record ID; IDs go into queries only
// in this form.
var sysID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// snFields are the fields read of a ticket.
const snFields = "sys_id,number,state,sys_updated_on"

// snRecord is a ticket as the Table API writes it, with the fields asked
// for. The values are strings: sysparm_display_value is false, so state
// is its number and sys_updated_on is in UTC.
type snRecord struct {
	SysID   string `json:"sys_id"`
	Number  string `json:"number"`
	State   string `json:"state"`
	Updated string `json:"sys_updated_on"`
}

func (r snRecord) state() remoteState {
	return remoteState{ref: ref{Key: r.Number, ID: r.SysID}, Status: RemoteStatus{Name: r.State}, Updated: r.Updated}
}

func (s *serviceNow) table(sub string) string {
	return "/api/now/table/" + url.PathEscape(s.conn.Table) + sub
}

// query is the query of every request for records: the values as stored,
// without reference links.
func snQuery(extra url.Values) url.Values {
	q := url.Values{"sysparm_display_value": {"false"}, "sysparm_exclude_reference_link": {"true"}}
	for k, v := range extra {
		q[k] = v
	}
	return q
}

func (s *serviceNow) create(ctx context.Context, t ticketContent) (created, error) {
	impact, urgency := impactUrgency(t.Severity)
	body := map[string]any{
		"short_description": truncateRunes(clean(t.Title, 1000), maxShortDesc),
		"description":       t.text(),
		"impact":            impact,
		"urgency":           urgency,
	}
	if s.conn.CallerID != "" {
		body["caller_id"] = s.conn.CallerID
	}
	if s.conn.AssignmentGroup != "" {
		body["assignment_group"] = s.conn.AssignmentGroup
	}
	var out struct {
		Result snRecord `json:"result"`
	}
	err := s.do(ctx, request{method: http.MethodPost, path: s.table(""), query: snQuery(url.Values{"sysparm_fields": {snFields}}), body: body, out: &out})
	if err != nil {
		return created{}, err
	}
	if !sysID.MatchString(out.Result.SysID) || out.Result.Number == "" {
		return created{}, &Error{Msg: "ServiceNow answered without the new ticket's number. Check the address and the table.", Retry: true}
	}
	st := out.Result.state()
	return created{ref: st.ref, URL: s.recordURL(out.Result.SysID), Status: st.Status, Updated: st.Updated}, nil
}

// recordURL opens a ticket in ServiceNow's interface.
func (s *serviceNow) recordURL(id string) string {
	return strings.TrimRight(s.conn.URL, "/") + "/nav_to.do?uri=" + url.QueryEscape("/"+s.conn.Table+".do?sys_id="+id)
}

func (s *serviceNow) patch(ctx context.Context, r ref, body map[string]any, out any) error {
	if !sysID.MatchString(r.ID) {
		return &Error{Msg: fmt.Sprintf("The ServiceNow ticket %s has no valid sys_id, so it cannot be changed.", r.Key)}
	}
	return s.do(ctx, request{method: http.MethodPatch, path: s.table("/" + r.ID), query: snQuery(url.Values{"sysparm_fields": {snFields}}), body: body, out: out})
}

func (s *serviceNow) update(ctx context.Context, r ref, title, severity string) error {
	impact, urgency := impactUrgency(severity)
	return s.patch(ctx, r, map[string]any{"short_description": truncateRunes(clean(title, 1000), maxShortDesc), "impact": impact, "urgency": urgency}, nil)
}

func (s *serviceNow) setStatus(ctx context.Context, r ref, caseStatus, resolution string) (RemoteStatus, error) {
	state := s.conn.state(caseStatus)
	body := map[string]any{"state": state}
	if caseStatus == findings.StatusResolved || caseStatus == findings.StatusClosed {
		// ServiceNow asks for a close code and notes to resolve or close
		// an incident.
		notes := strings.TrimSpace(resolution)
		if notes == "" {
			notes = "The case was " + strings.ReplaceAll(caseStatus, "_", " ") + " in Signalith."
		}
		body["close_code"] = s.conn.CloseCode
		body["close_notes"] = truncate(notes, maxComment)
	}
	var out struct {
		Result snRecord `json:"result"`
	}
	if err := s.patch(ctx, r, body, &out); err != nil {
		return RemoteStatus{}, err
	}
	if out.Result.State == "" {
		return RemoteStatus{Name: state}, nil
	}
	if out.Result.State != state {
		// A business rule kept the ticket where it was, or moved it
		// elsewhere.
		return RemoteStatus{Name: out.Result.State}, &Error{Msg: fmt.Sprintf("ServiceNow kept ticket %s in state %s instead of moving it to %s to match the case (%s); a business rule or the state model may not allow it. Check the state mapping on the Ticketing page.",
			r.Key, RemoteStatus{Name: out.Result.State}.Label(TypeServiceNow), RemoteStatus{Name: state}.Label(TypeServiceNow), label(caseStatus))}
	}
	return RemoteStatus{Name: out.Result.State}, nil
}

func (s *serviceNow) comment(ctx context.Context, r ref, text string) (string, error) {
	return "", s.patch(ctx, r, map[string]any{s.conn.CommentField: text}, nil)
}

func (s *serviceNow) poll(ctx context.Context, refs []ref, since time.Time) ([]remoteState, error) {
	minutes := sinceMinutes(since, s.now())
	var out []remoteState
	for _, chunk := range chunks(refs, pollChunk) {
		var ids []string
		for _, r := range chunk {
			if sysID.MatchString(r.ID) {
				ids = append(ids, r.ID)
			}
		}
		if len(ids) == 0 {
			continue
		}
		// A relative date needs no time zone: ServiceNow reads a date in
		// a query in the account's own.
		q := "sys_idIN" + strings.Join(ids, ",")
		if minutes > 0 {
			q += "^sys_updated_onRELATIVEGT@minute@ago@" + strconv.Itoa(minutes)
		}
		var res struct {
			Result []snRecord `json:"result"`
		}
		err := s.do(ctx, request{method: http.MethodGet, path: s.table(""),
			query: snQuery(url.Values{"sysparm_query": {q}, "sysparm_fields": {snFields}, "sysparm_limit": {strconv.Itoa(pollChunk)}}), out: &res})
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, r := range res.Result {
			seen[r.SysID] = true
			out = append(out, r.state())
		}
		if minutes > 0 {
			continue
		}
		// Asked about every ticket: one not returned may be deleted, or
		// hidden from the account. Reading it says which.
		for _, r := range chunk {
			if !sysID.MatchString(r.ID) || seen[r.ID] {
				continue
			}
			var one struct {
				Result snRecord `json:"result"`
			}
			err := s.do(ctx, request{method: http.MethodGet, path: s.table("/" + r.ID), query: snQuery(url.Values{"sysparm_fields": {snFields}}), out: &one})
			if e := errorOf(err); e != nil && e.Code == http.StatusNotFound {
				out = append(out, remoteState{ref: r, Gone: true})
				continue
			}
			if err != nil {
				return nil, err
			}
			out = append(out, one.Result.state())
		}
	}
	return out, nil
}

func (s *serviceNow) comments(ctx context.Context, r ref) ([]comment, error) {
	if !sysID.MatchString(r.ID) {
		return nil, nil
	}
	var res struct {
		Result []struct {
			SysID     string `json:"sys_id"`
			Element   string `json:"element"`
			Value     string `json:"value"`
			CreatedBy string `json:"sys_created_by"`
		} `json:"result"`
	}
	q := url.Values{
		"sysparm_query":  {"element_id=" + r.ID + "^elementINcomments,work_notes^ORDERBYsys_created_on"},
		"sysparm_fields": {"sys_id,element,value,sys_created_by,sys_created_on"},
		"sysparm_limit":  {strconv.Itoa(maxComments)},
	}
	if err := s.do(ctx, request{method: http.MethodGet, path: "/api/now/table/sys_journal_field", query: snQuery(q), out: &res}); err != nil {
		return nil, err
	}
	out := make([]comment, 0, len(res.Result))
	for _, j := range res.Result {
		out = append(out, comment{ID: j.SysID, Author: j.CreatedBy, Text: j.Value})
	}
	return out, nil
}

func (s *serviceNow) test(ctx context.Context) (string, error) {
	var res struct {
		Result []snRecord `json:"result"`
	}
	err := s.do(ctx, request{method: http.MethodGet, path: s.table(""), query: snQuery(url.Values{"sysparm_limit": {"1"}, "sysparm_fields": {"sys_id"}}), out: &res})
	if e := errorOf(err); e != nil && (e.Code == http.StatusNotFound || e.Code == http.StatusBadRequest) {
		return "", &Error{Msg: fmt.Sprintf("Signed in, but there is no table %s, or the account cannot read it. Check the table's name and the account's roles.", s.conn.Table), Code: e.Code}
	}
	if err != nil {
		return "", err
	}
	msg := fmt.Sprintf("Signed in. The %s table can be read.", s.conn.Table)
	if !s.conn.SyncNotes {
		return msg, nil
	}
	err = s.do(ctx, request{method: http.MethodGet, path: "/api/now/table/sys_journal_field",
		query: snQuery(url.Values{"sysparm_limit": {"1"}, "sysparm_fields": {"sys_id"}, "sysparm_query": {"elementINcomments,work_notes"}}), out: &res})
	if e := errorOf(err); e != nil && e.Code == http.StatusForbidden {
		return "", &Error{Msg: msg + " But the account cannot read the sys_journal_field table, so comments on tickets cannot come back to cases. Give it read access to that table, or turn off syncing notes.", Code: e.Code}
	}
	if err != nil {
		return "", err
	}
	return msg + " Comments can be read back.", nil
}
