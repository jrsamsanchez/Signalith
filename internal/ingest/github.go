// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// GitHub keeps an audit log for each enterprise and organization (GitHub
// Enterprise Cloud, GitHub Enterprise Server and organizations on
// GitHub.com): repositories created, archived, transferred and deleted,
// members invited and removed, branch protections and rulesets changed,
// secret scanning, Dependabot and two-factor requirements turned off,
// self-hosted runners registered, audit log streams changed. Each event
// is one flat JSON object named by its action (repo.destroy), with who did
// it (actor, actor_ip), where (business, org, repo) and fields of its own
// action. Audit log streaming writes one such object per event (to
// Splunk, Azure Event Hubs, Amazon S3 and others), the REST API's
// audit-log endpoints a JSON array of them per page, and an export from
// the audit log page a JSON array too.
//
// Each event becomes an event with GitHub's own field names, nested
// objects flattened with dots (actor_location.country_code) and a list's
// values by Splunk's names for them (config{}.url), as Splunk's add-on
// for GitHub keeps them (sourcetype github:cloud:audit), every value as
// text. A few of GitHub's names are Signalith's own CIM fields with
// another meaning or type, so those are kept as github_<name>
// (github_actor, github_user, github_document_id), and GitHub's action
// as vendor_action, as Splunk's add-on names it: action is the CIM
// field. Each event also gets the CIM fields of a Change event (most of
// them), an Authentication event (sign-ins to GitHub Enterprise Server)
// or Other (git operations, API requests, workflow runs).
//
// Events come under the github tag as JSON (one object, a JSON array or
// one object per line), are recognized by their shape under any tag, or
// come through the OpenTelemetry Collector as a log record whose body
// holds them (see githubFromOTLP), as an Azure Event Hub that audit log
// streaming writes to passes them on.

// GitHubTag is the tag of GitHub audit log events sent as JSON.
const GitHubTag = "github"

// GitHubSourcetype is Splunk's sourcetype for these events (Splunk's
// add-on for GitHub).
const GitHubSourcetype = "github:cloud:audit"

// GitHubVendor is the vendor_product of GitHub audit log events.
const GitHubVendor = "GitHub"

// GitHubChannel names GitHub audit log events in test events
// (sigmacheck.Case), as a Windows channel names Windows events.
const GitHubChannel = "github"

// GitHubProduct is the Sigma product of GitHub's audit log, and
// GitHubService the category Signalith gives its rules (product: github,
// service: audit).
const (
	GitHubProduct = "github"
	GitHubService = "github.audit"
)

// GitHubAction is the field GitHub's own action (repo.destroy) is kept
// as, as Splunk's add-on names it.
const GitHubAction = "vendor_action"

const (
	// githubMaxLeaves caps the fields one event's values become beyond
	// githubFields; the rest stay in the message.
	githubMaxLeaves = 150
	// githubMaxNodes caps the values of one event read for fields, so an
	// event with a huge object or list costs no more than a normal one.
	githubMaxNodes = 2000
	// githubMaxListValues caps the values kept of one list.
	githubMaxListValues = 64
)

// githubFields are the fields of an event kept whenever it has them,
// before the rest (githubMaxLeaves), by the names they are stored as.
var githubFields = []string{
	GitHubAction, "github_actor", "actor_id", "actor_ip", "actor_is_bot", "actor_location.country_code",
	"actor_location.country_name", "business", "business_id", "org", "org_id", "repo", "repo_id", "repository",
	"repository_id", "github_user", "github_user_id", "github_user_agent", "visibility", "operation_type",
	"created_at", "github_document_id", "github_name", "github_reason", "ruleset_name", "team", "token_id",
	"hashed_token", "programmatic_access_type", "external_identity_nameid", "external_identity_username",
	"request_id", "transport_protocol_name", "public_repo", "permission", "runner_id", "runner_name",
	"runner_group_name", "previous_visibility",
}

// githubMapped are the fields the index template maps (see knownFields):
// what a GitHub search reads first. The rest are mapped as they come.
var githubMapped = []string{
	"github_actor", "actor_id", "actor_ip", "actor_is_bot", "actor_location.country_code", "business", "business_id",
	"org", "org_id", "repo", "repo_id", "github_user", "github_user_id", "github_user_agent", "visibility",
	"operation_type", "created_at", "github_document_id", "github_name", "github_reason", "ruleset_name", "team",
}

// githubActionRe is GitHub's name of an action: a category and what was
// done, dotted (repo.destroy, org.disable_two_factor_requirement).
var githubActionRe = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)

// isGitHubEvent reports whether a decoded object sent as GitHub's (under
// the github tag) is a GitHub audit log event: an action, a time, and who
// or where.
func isGitHubEvent(r map[string]any) bool {
	action, _ := r["action"].(string)
	if len(action) > 200 || !githubActionRe.MatchString(action) {
		return false
	}
	if r["@timestamp"] == nil && r["created_at"] == nil {
		return false
	}
	_, actor := r["actor"].(string)
	_, doc := r["_document_id"].(string)
	return actor || doc || r["business"] != nil || r["org"] != nil
}

// IsGitHubRecord reports whether a decoded object sent under any tag is
// a GitHub audit log event by its own shape: an event (isGitHubEvent)
// that also has GitHub's document ID, as streamed and API events do, or
// an actor ID with an organization, enterprise or repository. Other
// applications' audit logs often have a dotted action, a time and an
// actor, and must not be read as GitHub's.
func IsGitHubRecord(r map[string]any) bool {
	if !isGitHubEvent(r) {
		return false
	}
	if doc, _ := r["_document_id"].(string); doc != "" {
		return true
	}
	return r["actor_id"] != nil && (r["org"] != nil || r["business"] != nil || r["repo"] != nil)
}

// githubSniffTag reports whether events under tag may be read as GitHub's
// by their shape: not when the tag names another source.
func githubSniffTag(tag string) bool {
	for _, p := range []string{"linux.", "windows", "syslog", WebTag, "wazuh", "zeek", "suricata"} {
		if strings.HasPrefix(tag, p) {
			return false
		}
	}
	return true
}

// maxGitHubBody caps the JSON text of the events read at once.
const maxGitHubBody = 64 << 20

// GitHubRecords decodes GitHub audit log events from JSON text: one
// object, objects one per line (as audit log streaming writes them), or a
// JSON array of them (a page of the REST API, or an export). Objects
// that are not events are left out; text that is none of these is an
// error.
func GitHubRecords(b []byte) ([]map[string]any, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || len(b) > maxGitHubBody {
		return nil, fmt.Errorf("GitHub audit log events must be 1 byte to %d MB of JSON", maxGitHubBody>>20)
	}
	if b[0] != '{' && b[0] != '[' {
		return nil, errors.New("not a JSON object or array")
	}
	limit := MaxDepth
	if b[0] == '[' {
		// An array of events is one level deeper than an event.
		limit++
	}
	if depth(b) > limit {
		return nil, fmt.Errorf("the JSON nests more than %d levels deep", MaxDepth)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var list []map[string]any
	if b[0] == '[' {
		if err := d.Decode(&list); err != nil {
			return nil, err
		}
		if d.More() {
			return nil, errors.New("unexpected data after the JSON array")
		}
	} else {
		for {
			var r map[string]any
			err := d.Decode(&r)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			list = append(list, r)
		}
	}
	out := list[:0]
	for _, r := range list {
		if r != nil && isGitHubEvent(r) {
			out = append(out, r)
		}
	}
	return out, nil
}

// githubFromOTLP returns the GitHub audit log events of an OTLP log
// record whose body holds them: text, as an Event Hub or file receiver
// passes it on, or a map.
func githubFromOTLP(body any) []map[string]any {
	switch b := body.(type) {
	case string:
		if len(b) > MaxRecordBytes || !strings.Contains(b, `"action"`) {
			return nil
		}
		// The text sat inside a string, past the body's own depth check;
		// GitHubRecords checks it.
		recs, err := GitHubRecords([]byte(b))
		if err != nil {
			return nil
		}
		// Text from a receiver carries no tag: only events with GitHub's
		// document ID are taken as GitHub's.
		recs = slices.DeleteFunc(recs, func(r map[string]any) bool {
			doc, _ := r["_document_id"].(string)
			return doc == ""
		})
		if len(recs) == 0 {
			return nil
		}
		return recs
	case map[string]any:
		if IsGitHubRecord(b) {
			return []map[string]any{b}
		}
	}
	return nil
}

// githubStoredTop is the name an event keeps one of GitHub's top-level
// fields under, or "" for none: its own, but vendor_action for action,
// and github_<name> for a name Signalith gives a meaning or type of its
// own (actor, user, user_id, user_agent, name, reason, and any other a
// parser sets or the index template maps) or OpenSearch reserves
// (_document_id). @timestamp is the event's time.
func githubStoredTop(k string) string {
	switch {
	case k == "action":
		return GitHubAction
	case k == "@timestamp", k == "", strings.ContainsAny(k, ".{}"):
		return ""
	}
	taken := func(name string) bool { return !githubOwnTop[name] && (KnownField(name) || knownObjects[name]) }
	name := k
	if t := strings.TrimLeft(k, "_@"); t != k || taken(k) {
		name = "github_" + t
	}
	if !validFieldName(name) || taken(name) {
		return ""
	}
	return name
}

// githubOwnTop are the top-level names of githubMapped, which the index
// template maps for GitHub's events.
var githubOwnTop = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range githubMapped {
		top, _, _ := strings.Cut(k, ".")
		m[top] = true
	}
	return m
}()

// GitHubField returns the field an event keeps for one of GitHub's field
// names (action, actor, actor_location.country_code, config{}.url), or
// false when it keeps none.
func GitHubField(name string) (string, bool) {
	top, rest := name, ""
	if i := strings.IndexAny(name, ".{"); i >= 0 {
		top, rest = name[:i], name[i:]
	}
	stored := githubStoredTop(top)
	if stored == "" || rest != "" && stored == GitHubAction {
		return "", false
	}
	if !validFieldName(stored + rest) {
		return "", false
	}
	return stored + rest, true
}

// GitHubName is GitHub's name of a field an event keeps
// (github_actor is actor), the inverse of GitHubField.
func GitHubName(stored string) string {
	top, rest := stored, ""
	if i := strings.IndexAny(stored, ".{"); i >= 0 {
		top, rest = stored[:i], stored[i:]
	}
	if top == GitHubAction && rest == "" {
		return "action"
	}
	if t, ok := strings.CutPrefix(top, "github_"); ok {
		for _, k := range []string{t, "_" + t, "@" + t} {
			if githubStoredTop(k) == top {
				return k + rest
			}
		}
	}
	return stored
}

// GitHubKept reports whether a field is one an event keeps of GitHub's
// fields (a name GitHubField returns).
func GitHubKept(name string) bool {
	f, ok := GitHubField(GitHubName(name))
	return ok && f == name
}

// githubFlatten puts an event's values in out under dotted names, every
// value as text, reading at most *nodes values. A list is kept as its
// JSON text (of its first githubMaxListValues values), and its values
// by Splunk's names for them. An object nested past the deepest field
// name, or where the index template maps a value, is kept as its JSON
// text; a value where the template maps an object is left out.
func githubFlatten(prefix string, v any, out map[string]any, nodes *int) {
	if *nodes <= 0 {
		return
	}
	*nodes--
	switch x := v.(type) {
	case map[string]any:
		if strings.Count(prefix, ".")+1 >= maxFieldDepth || KnownField(prefix) {
			if b, err := json.Marshal(x); err == nil && !knownObjects[prefix] {
				out[prefix] = CapValue(string(b))
			}
			return
		}
		for _, k := range slices.Sorted(maps.Keys(x)) {
			if *nodes <= 0 {
				return
			}
			if k != "" && !strings.ContainsAny(k, ".{}") {
				githubFlatten(prefix+"."+k, x[k], out, nodes)
			}
		}
	case []any:
		if b, err := json.Marshal(x[:min(len(x), githubMaxListValues)]); err == nil && !knownObjects[prefix] {
			out[prefix] = CapValue(string(b))
		}
		objs := map[string]bool{}
		for _, e := range x[:min(len(x), githubMaxListValues)] {
			githubListValue(prefix+"{}", e, out, objs, nodes)
		}
	default:
		if s := o365Text(v); s != "" && !knownObjects[prefix] {
			out[prefix] = CapValue(s)
		}
	}
}

// githubListValue adds a list's value to the values kept under name, as
// azureListValue does, reading at most *nodes values. objs are the names
// a list's objects have fields under: a name holds values or fields, not
// both (a list of 1 and {"a": 2} keeps 1).
func githubListValue(name string, v any, out map[string]any, objs map[string]bool, nodes *int) {
	if *nodes <= 0 || strings.Count(name, ".") >= maxFieldDepth {
		return
	}
	*nodes--
	switch x := v.(type) {
	case map[string]any:
		if out[name] != nil || KnownField(name) {
			return
		}
		objs[name] = true
		for _, k := range slices.Sorted(maps.Keys(x)) {
			if k != "" && !strings.ContainsAny(k, ".{}") {
				githubListValue(name+"."+k, x[k], out, objs, nodes)
			}
		}
		return
	case []any:
		for _, e := range x[:min(len(x), githubMaxListValues)] {
			githubListValue(name+"{}", e, out, objs, nodes)
		}
		return
	}
	s := o365Text(v)
	if s == "" || objs[name] || knownObjects[name] {
		return
	}
	if l, _ := out[name].([]any); len(l) < githubMaxListValues {
		out[name] = append(l, CapValue(s))
	}
}

// githubTime reads an event's time: milliseconds since 1970 as GitHub
// writes @timestamp and created_at, or RFC 3339 text.
func githubTime(v any) (time.Time, bool) {
	s := o365Text(v)
	if s == "" {
		return time.Time{}, false
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n <= 0 || n > 1e14 {
			return time.Time{}, false
		}
		return time.UnixMilli(n).UTC(), true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		if f <= 0 || f > 1e14 {
			return time.Time{}, false
		}
		return time.UnixMilli(int64(f)).UTC(), true
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

// ParseGitHub maps a GitHub audit log event (decoded JSON) onto an event.
func ParseGitHub(r map[string]any) Event {
	if !isGitHubEvent(r) {
		return parseGeneric(r)
	}
	r = githubRedact(r)
	flat := map[string]any{}
	nodes := githubMaxNodes
	seen := map[string]bool{}
	for _, k := range slices.Sorted(maps.Keys(r)) {
		if nodes <= 0 {
			break
		}
		name := githubStoredTop(k)
		if name == "" || seen[name] {
			// Two of GitHub's names kept as one (actor and github_actor):
			// the first.
			continue
		}
		seen[name] = true
		githubFlatten(name, r[k], flat, &nodes)
	}
	f := map[string]any{"sourcetype": GitHubSourcetype, "vendor_product": GitHubVendor}
	// githubFields, then the rest in order, as far as githubMaxLeaves.
	leaves := 0
	for _, k := range slices.Sorted(maps.Keys(flat)) {
		switch {
		case !validFieldName(k):
		case slices.Contains(githubFields, k):
			f[k] = flat[k]
		case leaves < githubMaxLeaves:
			f[k] = flat[k]
			leaves++
		}
	}
	raw, rawErr := json.Marshal(r)
	if rawErr == nil {
		f["message"] = truncateUTF8(string(raw), MaxRecordBytes)
	}
	set := func(k, v string) {
		if v != "" {
			f[k] = CapValue(v)
		}
	}
	text := func(k string) string { return o365Text(r[k]) }
	// The machine that sent the event, when it says (GitHub itself has
	// no host).
	if h, ok := r["hostname"].(string); ok {
		set("host", h)
	}
	action := str(r, "action")
	set("signature", action)
	set("command", action)
	set("id", text("_document_id"))
	// Who acted: the actor's login, from where.
	set("user", text("actor"))
	set("src_user", text("actor"))
	set("src_user_id", text("actor_id"))
	set("src", o365Address(text("actor_ip")))
	set("user_agent", text("user_agent"))
	set("http_user_agent", text("user_agent"))
	set("app", GitHubVendor)
	set("dest", cmp.Or(text("org"), text("business"), GitHubVendor))
	set("vendor_account", cmp.Or(text("business"), text("org")))
	set("reason", text("reason"))

	ev := Event{Fields: f, Model: "Other"}
	if t, ok := githubTime(r["@timestamp"]); ok {
		ev.Time = t
	} else if t, ok := githubTime(r["created_at"]); ok {
		ev.Time = t
	}
	// The same event, read twice, is stored once. The ID covers the whole
	// event, not just its _document_id, so an event sent with a real
	// event's _document_id cannot take its place.
	if rawErr == nil {
		ev.ID = sensorDocID("github", text("_document_id")+"\n"+string(raw))
	}
	failed := GitHubFailed(action)
	status := "success"
	if failed {
		status = "failure"
	}
	set("status", status)
	switch m := GitHubModel(action); m {
	case "Authentication":
		ev.Model = m
		f["action"] = status
	case "Change":
		ev.Model = m
		f["action"] = GitHubChangeAction(action)
		f["result"] = status
		category, _, _ := strings.Cut(action, ".")
		set("change_type", category)
		object, kind := githubObject(r, category)
		set("object", object)
		set("object_category", kind)
	}
	return ev
}

// githubObject is what a change was made to, and its kind: the
// repository, team or user it names, else the organization or
// enterprise.
func githubObject(r map[string]any, category string) (string, string) {
	pick := []struct{ field, kind string }{
		{"repo", "repository"}, {"repository", "repository"}, {"team", "team"}, {"user", "user"},
		{"org", "organization"}, {"business", "enterprise"},
	}
	switch category {
	case "org", "organization":
		// An organization's settings, unless it names a member.
		pick = []struct{ field, kind string }{{"user", "user"}, {"org", "organization"}, {"business", "enterprise"}}
	case "business", "enterprise":
		pick = []struct{ field, kind string }{{"org", "organization"}, {"user", "user"}, {"business", "enterprise"}}
	}
	for _, p := range pick {
		if s := o365Text(r[p.field]); s != "" {
			return s, p.kind
		}
	}
	return "", ""
}

// GitHubModel is the data model of a GitHub action: sign-ins (GitHub
// Enterprise Server's user.login, user.failed_login and two-factor
// challenges) are Authentication, git operations, API requests and
// workflow runs Other, and the rest, which change something, Change.
func GitHubModel(action string) string {
	has := func(prefixes ...string) bool {
		return slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(action, p) })
	}
	switch {
	case has("user.login", "user.failed_login", "user.two_factor_challenge", "user.logout"):
		return "Authentication"
	case has("git.", "api.", "workflows.", "repo.download_zip", "copilot.", "repository_content_analysis."):
		return "Other"
	}
	return "Change"
}

// GitHubFailed reports whether an action says it failed
// (user.failed_login, user.two_factor_challenge_failure).
func GitHubFailed(action string) bool {
	return strings.Contains(action, "failed") || strings.HasSuffix(action, "_failure")
}

// GitHubChangeAction is what a GitHub change did, by the words of its
// action: created (repo.create, org.add_member,
// repo.register_self_hosted_runner), deleted (repo.destroy,
// org.remove_outside_collaborator), or modified (repo.archived,
// org.disable_two_factor_requirement, and anything else).
func GitHubChangeAction(action string) string {
	_, rest, _ := strings.Cut(action, ".")
	for _, w := range strings.FieldsFunc(rest, func(r rune) bool { return r == '.' || r == '_' }) {
		switch w {
		case "create", "created", "add", "added", "invite", "invited", "register", "registered":
			return "created"
		case "destroy", "destroyed", "delete", "deleted", "remove", "removed":
			return "deleted"
		}
	}
	return "modified"
}

// GitHubRecord is a GitHub audit log event with the fields data names, by
// GitHub's names (action, actor, actor_location.country_code), for test
// events (Normalize with GitHubTag), as host sent it: unless data says
// otherwise, an organization owner adding a member to a team, which no
// rule is about.
func GitHubRecord(host string, t time.Time, data map[string]string) map[string]any {
	ms := json.Number(strconv.FormatInt(t.UTC().UnixMilli(), 10))
	r := map[string]any{
		"@timestamp": ms, "created_at": ms, "action": "team.add_member", "operation_type": "modify",
		"actor": "octocat", "actor_id": json.Number("1001"), "actor_ip": "203.0.113.7", "actor_is_bot": false,
		"actor_location": map[string]any{"country_code": "US"},
		"business":       "example-enterprise", "business_id": json.Number("2001"),
		"org": "example-org", "org_id": json.Number("3001"), "team": "example-org/developers",
		"user": "monalisa", "user_id": json.Number("4001"),
		"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "hostname": host,
	}
	for _, k := range slices.Sorted(maps.Keys(data)) {
		name := GitHubName(k)
		if _, ok := GitHubField(name); !ok {
			continue
		}
		v := data[k]
		var val any = v
		if name == "actor_is_bot" && (v == "true" || v == "false") {
			val = v == "true"
		}
		gcpPut(r, name, val)
	}
	// Each test event its own _document_id, as the same event is stored
	// once.
	h := sha256.New()
	fmt.Fprintln(h, host, t.UnixNano())
	for _, k := range slices.Sorted(maps.Keys(data)) {
		fmt.Fprintln(h, k, data[k])
	}
	r["_document_id"] = hex.EncodeToString(h.Sum(nil))[:22]
	return r
}
