package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A repository deleted, as audit log streaming writes it.
const githubRepoDestroy = `{"@timestamp": 1791709951415, "_document_id": "xJJFlFOhQ6b-5vaAFy9Rjw", "action": "repo.destroy",
	"actor": "octocat", "actor_id": 1001, "actor_ip": "203.0.113.7", "actor_is_bot": false,
	"actor_location": {"country_code": "US", "country_name": "United States"},
	"business": "example-enterprise", "business_id": 2001, "created_at": 1791709951415, "operation_type": "remove",
	"org": "example-org", "org_id": 3001, "repo": "example-org/payments", "repo_id": 5001, "visibility": "private",
	"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "request_id": "C0DE:1234:ABCD",
	"config": {"url": "https://hooks.example.com/x", "content_type": "json"},
	"events": ["push", "pull_request"], "secrets_passed": [{"name": "TOKEN"}, {"name": "KEY"}]}`

// An organization owner turned off the two-factor requirement, as the
// REST API returns it.
const githubDisable2FA = `{"@timestamp": 1791713551000, "_document_id": "Ab12cd34", "action": "org.disable_two_factor_requirement",
	"actor": "admin", "created_at": 1791713551000, "org": "example-org", "user": "admin", "user_id": 7,
	"name": "two factor", "reason": "audit"}`

// A failed sign-in to GitHub Enterprise Server.
const githubFailedLogin = `{"@timestamp": "2026-10-11T09:12:31Z", "action": "user.failed_login", "actor": "jdoe",
	"actor_ip": "198.51.100.4", "business": "ghes", "user": "jdoe"}`

func TestGitHubChange(t *testing.T) {
	ev := Normalize(GitHubTag, decode(t, githubRepoDestroy), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Change", "sourcetype": GitHubSourcetype, "vendor_product": "GitHub",
		"vendor_action": "repo.destroy", "github_actor": "octocat", "actor_id": "1001", "actor_ip": "203.0.113.7",
		"actor_is_bot": "false", "actor_location.country_code": "US", "business": "example-enterprise",
		"business_id": "2001", "org": "example-org", "org_id": "3001", "repo": "example-org/payments", "repo_id": "5001",
		"visibility": "private", "github_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		"github_document_id": "xJJFlFOhQ6b-5vaAFy9Rjw", "created_at": "1791709951415", "config.url": "https://hooks.example.com/x",
		"events": `["push","pull_request"]`,
		"action": "deleted", "status": "success", "result": "success", "change_type": "repo", "object": "example-org/payments",
		"object_category": "repository", "user": "octocat", "src_user": "octocat", "src_user_id": "1001", "src": "203.0.113.7",
		"signature": "repo.destroy", "command": "repo.destroy", "app": "GitHub", "dest": "example-org",
		"vendor_account": "example-enterprise", "id": "xJJFlFOhQ6b-5vaAFy9Rjw",
		"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "@timestamp": "2026-10-11T09:12:31.415Z",
	})
	expectLists(t, ev, map[string][]any{"events{}": {"push", "pull_request"}, "secrets_passed{}.name": {"TOKEN", "KEY"}})
	for _, k := range []string{"actor", "_document_id", "github_timestamp"} {
		if _, ok := ev.Fields[k]; ok {
			t.Errorf("%s became a field", k)
		}
	}
	ev = Normalize(GitHubTag, decode(t, githubDisable2FA), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Change", "action": "modified", "vendor_action": "org.disable_two_factor_requirement",
		"github_user": "admin", "github_user_id": "7", "github_name": "two factor", "github_reason": "audit", "reason": "audit",
		"object": "admin", "object_category": "user", "user": "admin", "dest": "example-org", "change_type": "org",
	})
}

func TestGitHubSignIn(t *testing.T) {
	ev := Normalize(GitHubTag, decode(t, githubFailedLogin), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Authentication", "sourcetype": GitHubSourcetype, "action": "failure", "status": "failure",
		"user": "jdoe", "src": "198.51.100.4", "dest": "ghes", "@timestamp": "2026-10-11T09:12:31Z",
	})
}

func TestGitHubModel(t *testing.T) {
	for action, want := range map[string][2]string{
		"repo.create":                             {"Change", "created"},
		"org.add_member":                          {"Change", "created"},
		"org.invite_member":                       {"Change", "created"},
		"repo.register_self_hosted_runner":        {"Change", "created"},
		"org.runner_group_created":                {"Change", "created"},
		"repo.destroy":                            {"Change", "deleted"},
		"business.remove_organization":            {"Change", "deleted"},
		"org.runner_group_runner_removed":         {"Change", "deleted"},
		"repository_ruleset.destroy":              {"Change", "deleted"},
		"repo.archived":                           {"Change", "modified"},
		"org.disable_two_factor_requirement":      {"Change", "modified"},
		"audit_log_streaming.update":              {"Change", "modified"},
		"user.login":                              {"Authentication", ""},
		"user.two_factor_challenge_failure":       {"Authentication", ""},
		"git.clone":                               {"Other", ""},
		"workflows.completed_workflow_run":        {"Other", ""},
		"secret_scanning_push_protection.bypass":  {"Change", "modified"},
		"protected_branch.policy_override":        {"Change", "modified"},
		"environment.create_actions_secret":       {"Change", "created"},
		"dependabot_security_updates.disable":     {"Change", "modified"},
		"private_repository_forking.enable":       {"Change", "modified"},
		"ssh_certificate_requirement.disable":     {"Change", "modified"},
		"business_advanced_security.disabled_for": {"Change", "modified"},
	} {
		if got := GitHubModel(action); got != want[0] {
			t.Errorf("GitHubModel(%s) = %s, want %s", action, got, want[0])
		}
		if want[1] != "" && GitHubChangeAction(action) != want[1] {
			t.Errorf("GitHubChangeAction(%s) = %s, want %s", action, GitHubChangeAction(action), want[1])
		}
	}
}

func TestIsGitHubRecord(t *testing.T) {
	for s, want := range map[string]bool{
		githubRepoDestroy: true, githubDisable2FA: true, githubFailedLogin: false,
		`{"action": "repo.create", "created_at": 1, "org": "o"}`:                false,
		`{"action": "repo.create", "created_at": 1, "org": "o", "actor_id": 3}`: true,
		`{"action": "repo.create", "org": "o"}`:                                 false,
		`{"action": "Create Repo", "created_at": 1, "actor": "a"}`:              false,
		`{"action": "allow", "created_at": 1, "actor": "a"}`:                    false,
		`{"action": "repo.create", "created_at": 1, "actor": {"login": 1}}`:     false,
		`{"action": "repo.create", "created_at": 1, "_document_id": "x"}`:       true,
	} {
		if got := IsGitHubRecord(decode(t, s)); got != want {
			t.Errorf("IsGitHubRecord(%.60s) = %v", s, got)
		}
	}
}

// An array (a page of the REST API, or an export), events one per line
// (audit log streaming) and one event are all read; text that is none of
// these, or nests too deep, is not.
func TestGitHubRecords(t *testing.T) {
	flat := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "\n", ""), "\t", "") }
	page := "[" + githubRepoDestroy + ",\n" + githubDisable2FA + `, {"not": "an event"}, null]`
	if recs, err := GitHubRecords([]byte(page)); err != nil || len(recs) != 2 {
		t.Fatalf("array: %d records, %v", len(recs), err)
	}
	lines := flat(githubRepoDestroy) + "\n" + flat(githubDisable2FA) + "\r\n" + flat(githubFailedLogin) + "\n"
	if recs, err := GitHubRecords([]byte(lines)); err != nil || len(recs) != 3 {
		t.Fatalf("lines: %d records, %v", len(recs), err)
	}
	if recs, err := GitHubRecords([]byte(githubFailedLogin)); err != nil || len(recs) != 1 {
		t.Fatalf("one event: %d records, %v", len(recs), err)
	}
	deep := `{"action": "repo.create", "created_at": 1, "org": "o", "x": ` + strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth) + "}"
	for _, bad := range []string{"", "x", `"text"`, "[" + strings.Repeat("[", MaxDepth+2) + strings.Repeat("]", MaxDepth+2) + "]",
		deep, "[] []", `{"a": 1} [1]`} {
		if _, err := GitHubRecords([]byte(bad)); err == nil {
			t.Errorf("%.40q was read", bad)
		}
	}
	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	if _, err := p.IngestBody(context.Background(), GitHubTag, []byte(lines)); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, d := range fb.docs {
		if d.Doc["sourcetype"] == GitHubSourcetype {
			n++
		}
	}
	if n != 3 {
		t.Errorf("%d GitHub events, want 3", n)
	}
}

// An Event Hub that audit log streaming writes to passes each message on
// as the body's text; a Collector may pass a map.
func TestGitHubFromOTLP(t *testing.T) {
	flat := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "\n", ""), "\t", "") }
	docs := otlpDocs(t, tRes{attrs: []tKV{{"host.name", "collector1"}}, recs: []tRec{
		{observed: uint64(now.UnixNano()), body: flat(githubRepoDestroy)},
		{observed: uint64(now.UnixNano()), body: flat(githubDisable2FA) + "\n" + strings.Replace(flat(githubFailedLogin), "{", `{"_document_id": "z9", `, 1)},
		{observed: uint64(now.UnixNano()), body: `{"action": "x", "created_at": 1}`},
	}})
	if len(docs) != 4 {
		t.Fatalf("%d documents, want 4", len(docs))
	}
	expect(t, docs[0], map[string]any{"datamodel": "Change", "sourcetype": GitHubSourcetype, "host": "collector1",
		"@timestamp": "2026-10-11T09:12:31.415Z"})
	expect(t, docs[2], map[string]any{"datamodel": "Authentication", "sourcetype": GitHubSourcetype})
	if docs[3]["sourcetype"] == GitHubSourcetype {
		t.Errorf("not an event: %v", docs[3])
	}
	// JSON nested in the body's text is checked for depth too.
	deep := `{"action": "repo.create", "created_at": 1, "org": "o", "x": ` + strings.Repeat(`{"a": `, 1000) + "1" + strings.Repeat("}", 1000) + `}`
	if githubFromOTLP(deep) != nil {
		t.Error("a 1,000-deep OTLP body was read")
	}
}

// A field GitHub names as Signalith names a field of its own, with another
// meaning or type, is kept under another name; no field sits under a name
// the index template maps as a value, where OpenSearch would refuse the
// document.
func TestGitHubFieldsUnderNoMappedValue(t *testing.T) {
	r := decode(t, githubRepoDestroy)
	for _, k := range []string{"src", "message", "duration", "category", "properties", "target", "datamodel", "github_actor", "sourcetype", "host"} {
		r[k] = map[string]any{"a": "x", "b": []any{map[string]any{"c": 1}}}
	}
	r["@timestamp"] = map[string]any{"x": 1}
	r["a.b"] = "dotted"
	r["src.x"] = "dotted"
	for _, s := range []map[string]any{r, decode(t, githubDisable2FA), decode(t, githubFailedLogin)} {
		ev := Normalize(GitHubTag, s, now)
		if ev.Fields["sourcetype"] != GitHubSourcetype {
			t.Fatalf("not read: %v", ev.Fields)
		}
		for k, v := range ev.Fields {
			name := strings.ReplaceAll(k, "{}", "")
			for i := range len(name) {
				if name[i] == '.' {
					if typ, ok := knownFields[name[:i]]; ok && typ != "object" {
						t.Errorf("%s is under %s, mapped as %s", k, name[:i], typ)
					}
				}
			}
			if typ := knownFields[k]; typ != "" && typ != "keyword" && typ != "text" && typ != "wildcard" {
				t.Errorf("%s = %v is mapped as %s", k, v, typ)
			}
			if !KnownField(k) && !GitHubKept(k) {
				t.Errorf("field %s is neither mapped nor one of GitHub's", k)
			}
		}
	}
	ev := Normalize(GitHubTag, r, now)
	expect(t, ev.Document(), map[string]any{"github_src.a": "x", "github_message.a": "x", "github_category.a": "x",
		"github_properties.a": "x", "src": "203.0.113.7", "github_actor": "octocat"})
	for _, k := range []string{"a.b", "src.x", "github_src.x", "github_actor.a", "github_github_actor.a"} {
		if _, ok := ev.Fields[k]; ok {
			t.Errorf("%s kept", k)
		}
	}
	// A value where the index template maps an object is left out.
	r = decode(t, githubDisable2FA)
	r["actor_location"] = "US"
	r["target"] = []any{"a", map[string]any{"id": "x"}}
	ev = Normalize(GitHubTag, r, now)
	for k := range ev.Fields {
		if knownObjects[k] {
			t.Errorf("%s = %v is mapped as an object", k, ev.Fields[k])
		}
	}
	if ev.Fields["target"] != `["a",{"id":"x"}]` {
		t.Errorf("target = %v", ev.Fields["target"])
	}
	// An object where GitHub has text is kept as its JSON text.
	r = decode(t, githubDisable2FA)
	r["user"] = map[string]any{"login": "x"}
	if ev := Normalize(GitHubTag, r, now); ev.Fields["github_user"] != `{"login":"x"}` {
		t.Errorf("github_user = %v", ev.Fields["github_user"])
	}
	for name, want := range map[string]string{
		"action": "vendor_action", "actor": "github_actor", "user": "github_user", "user_agent": "github_user_agent",
		"_document_id": "github_document_id", "actor_location.country_code": "actor_location.country_code",
		"config{}.url": "config{}.url", "repo": "repo", "reason": "github_reason",
	} {
		if got, ok := GitHubField(name); !ok || got != want {
			t.Errorf("GitHubField(%s) = %s, %v", name, got, ok)
		}
		if back := GitHubName(want); back != name {
			t.Errorf("GitHubName(%s) = %s, want %s", want, back, name)
		}
	}
	for _, bad := range []string{"@timestamp", "action.x", "", "a b"} {
		if f, ok := GitHubField(bad); ok {
			t.Errorf("GitHubField(%q) = %s", bad, f)
		}
	}
}

// An event with another event's _document_id but other content is stored
// as its own, and the same event read twice once.
func TestGitHubDocumentID(t *testing.T) {
	a := Normalize(GitHubTag, decode(t, githubRepoDestroy), now)
	if again := Normalize(GitHubTag, decode(t, githubRepoDestroy), now.Add(time.Hour)); again.ID != a.ID || a.ID == "" {
		t.Errorf("IDs %q and %q", a.ID, again.ID)
	}
	forged := decode(t, githubRepoDestroy)
	forged["actor"] = "someone-else"
	if Normalize(GitHubTag, forged, now).ID == a.ID {
		t.Error("a changed copy took the event's ID")
	}
}

// A huge event (an object of 200,000 fields, a list of 200,000 values,
// objects nested in lists) becomes no more fields and list values than
// the caps allow, and reads no more of it than githubMaxNodes.
func TestGitHubHugeEventBounded(t *testing.T) {
	r := decode(t, githubRepoDestroy)
	big := map[string]any{}
	for i := range 200000 {
		big[fmt.Sprintf("k%06d", i)] = i
	}
	list := make([]any, 200000)
	for i := range list {
		list[i] = map[string]any{"name": fmt.Sprint(i), "more": []any{1, 2, 3}}
	}
	r["data"] = big
	r["runner_labels"] = list
	for i := range 5000 {
		r[fmt.Sprintf("extra_%05d", i)] = "v"
	}
	ev := Normalize(GitHubTag, r, now)
	if ev.Fields["vendor_action"] != "repo.destroy" || ev.Model != "Change" {
		t.Fatalf("not read: %v", ev.Model)
	}
	if n := len(ev.Fields); n > len(githubFields)+githubMaxLeaves+40 {
		t.Errorf("%d fields", n)
	}
	for k, v := range ev.Fields {
		if l, ok := v.([]any); ok && len(l) > githubMaxListValues {
			t.Errorf("%s has %d values", k, len(l))
		}
		if s, ok := v.(string); ok && len(s) > 2*MaxValueLen && k != "message" {
			t.Errorf("%s is %d bytes", k, len(s))
		}
	}
	flat := map[string]any{}
	nodes := githubMaxNodes
	githubFlatten("data", big, flat, &nodes)
	if len(flat) >= githubMaxNodes || nodes != 0 {
		t.Errorf("flattening read %d values into %d fields", githubMaxNodes-nodes, len(flat))
	}
	nodes = githubMaxNodes
	flat = map[string]any{}
	githubFlatten("runner_labels", list, flat, &nodes)
	var shown []any
	if err := json.Unmarshal([]byte(flat["runner_labels"].(string)), &shown); err == nil && len(shown) > githubMaxListValues {
		t.Errorf("list text of %d values", len(shown))
	}
	if githubMaxNodes-nodes > githubMaxListValues*6+1 {
		t.Errorf("a list read %d values", githubMaxNodes-nodes)
	}
}

// GitHub's names for an event's fields build a test event that keeps them.
func TestGitHubRecord(t *testing.T) {
	data := map[string]string{"action": "repo.destroy", "reason": "User initiated pause", "actor_location.country_code": "FR",
		"vendor_action": "repo.destroy", "github_user": "mona", "repo": "o/r"}
	ev := Normalize(GitHubTag, GitHubRecord("h1", now, data), now)
	expect(t, ev.Document(), map[string]any{
		"host": "h1", "vendor_action": "repo.destroy", "github_reason": "User initiated pause",
		"actor_location.country_code": "FR", "github_user": "mona", "repo": "o/r", "datamodel": "Change",
		"github_actor": "octocat", "@timestamp": now.UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano),
	})
	other := Normalize(GitHubTag, GitHubRecord("h1", now, map[string]string{"action": "repo.create"}), now)
	if other.ID == ev.ID {
		t.Error("two test events share a document ID")
	}
	if base := Normalize(GitHubTag, GitHubRecord("h1", now, nil), now); base.Fields["vendor_action"] != "team.add_member" {
		t.Errorf("base action %v", base.Fields["vendor_action"])
	}
}

// Another application's audit log with GitHub-like names is not read as
// GitHub's, under its own tag or through OTLP.
func TestGitHubShapeNeedsGitHubEvidence(t *testing.T) {
	app := `{"@timestamp": "2026-10-16T12:00:00Z", "action": "user.login", "actor": "bob", "user": "alice",
		"result": "failure", "src_ip": "192.0.2.4"}`
	for _, tag := range []string{"linux.myapp", "app", ""} {
		if ev := Normalize(tag, decode(t, app), now); ev.Fields["sourcetype"] == GitHubSourcetype {
			t.Errorf("tag %q: read as GitHub's: %v", tag, ev.Fields)
		}
	}
	if recs := githubFromOTLP(app); recs != nil {
		t.Errorf("OTLP text read as GitHub's: %v", recs)
	}
	// GitHub's own events still are, by their document ID, or an actor ID
	// with an organization, and under the github tag by the looser shape.
	if ev := Normalize("app", decode(t, githubRepoDestroy), now); ev.Fields["sourcetype"] != GitHubSourcetype {
		t.Error("a streamed event was not read as GitHub's")
	}
	byID := `{"created_at": 1791709951415, "action": "repo.create", "actor": "a", "actor_id": 5, "org": "o"}`
	if ev := Normalize("", decode(t, byID), now); ev.Fields["sourcetype"] != GitHubSourcetype {
		t.Error("an event with an actor ID and organization was not read as GitHub's")
	}
	if ev := Normalize("linux.myapp", decode(t, githubRepoDestroy), now); ev.Fields["sourcetype"] == GitHubSourcetype {
		t.Error("another source's tag was overridden")
	}
	if ev := Normalize(GitHubTag, decode(t, githubFailedLogin), now); ev.Fields["sourcetype"] != GitHubSourcetype {
		t.Error("a GitHub Enterprise Server event under the github tag was not read as GitHub's")
	}
}

// A webhook address's password and token are never kept.
func TestGitHubWebhookURLRedacted(t *testing.T) {
	hook := `{"@timestamp": 1791709951415, "_document_id": "h1", "action": "hook.create", "actor": "admin", "org": "o",
		"config": {"url": "https://ci-user:s3cr3tpw@ci.example.com/hook?token=TOKEN123&x=1", "content_type": "json"},
		"hook_url": "https://hooks.example.com/a?sig=SIG456#frag"}`
	r := decode(t, hook)
	ev := Normalize(GitHubTag, r, now)
	doc, _ := json.Marshal(ev.Document())
	for _, secret := range []string{"s3cr3tpw", "ci-user", "TOKEN123", "SIG456"} {
		if strings.Contains(string(doc), secret) {
			t.Errorf("%s was kept: %s", secret, doc)
		}
	}
	if !strings.Contains(string(doc), "ci.example.com/hook") {
		t.Errorf("the address itself was lost: %s", doc)
	}
	if cfg, _ := r["config"].(map[string]any); !strings.Contains(cfg["url"].(string), "s3cr3tpw") {
		t.Error("the record passed in was changed")
	}
}
