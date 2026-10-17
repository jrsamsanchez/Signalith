package splcheck

import (
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// GitHubNode is the node of GitHub audit log events (the
// github_enterprise and github_organizations macros). A search names no
// event code. Its fields are the event's own (action, actor, repo,
// actor_location.country_code), which Signalith keeps by GitHub's names
// but for a few it keeps as github_<name> (github_actor, github_user,
// github_reason) and action, which it keeps as vendor_action, and the CIM
// fields Signalith gives each event.
const GitHubNode = "GitHub"

// The GitHub macros: github_enterprise searches the events audit log
// streaming sends to Splunk's HTTP Event Collector, as GitHub names them
// (action=repo.destroy); github_organizations the events Splunk's add-on
// for GitHub reads from the REST API, which keeps GitHub's action as
// vendor_action and gives action its CIM meaning.
const (
	githubEnterpriseSource = "github_enterprise"
	githubOrgSource        = "github_organizations"
)

// githubCIM are the CIM fields of a GitHub event that are not also
// GitHub's own names (GitHub's user, user_agent and reason are its own),
// with the Signalith field each is stored as.
var githubCIM = map[string]string{
	"src": "src", "src_ip": "src", "src_user": "src_user", "src_user_id": "src_user_id", "dest": "dest",
	"signature": "signature", "command": "command", "app": "app", "http_user_agent": "http_user_agent",
	"status": "status", "result": "result", "object": "object", "object_category": "object_category",
	"change_type": "change_type", "vendor_product": "vendor_product", "vendor_account": "vendor_account",
	"vendor_action": ingest.GitHubAction, "sourcetype": "sourcetype", "id": "id",
}

// githubField is the stored field of a GitHub search's field: action is
// GitHub's (vendor_action) in the github_enterprise macro's searches and
// the CIM field in github_organizations'.
func githubField(source, name string) (string, bool) {
	if name == "action" && source == githubOrgSource {
		return "action", true
	}
	if f, ok := githubCIM[name]; ok {
		return f, true
	}
	return ingest.GitHubField(name)
}

// githubRecord turns a field-level event into the GitHub audit log event
// that carries it: CIM fields back to GitHub's fields they come from.
func githubRecord(ev map[string]string) sigmacheck.Case {
	data := map[string]string{}
	set := func(k, v string) {
		if v != "" && data[k] == "" {
			data[k] = v
		}
	}
	for k, v := range ev {
		if _, cim := githubCIM[k]; k == ingest.GitHubAction || !cim && ingest.GitHubKept(k) {
			data[ingest.GitHubName(k)] = v
		}
	}
	set("action", ev["signature"])
	set("action", ev["command"])
	set("actor", ev["user"])
	set("actor", ev["src_user"])
	set("actor_id", ev["src_user_id"])
	set("actor_ip", ev["src"])
	set("user_agent", ev["http_user_agent"])
	set("org", ev["dest"])
	set("business", ev["vendor_account"])
	return sigmacheck.Case{Channel: sigmacheck.GitHubChannel, EventID: "audit", Data: data}
}
