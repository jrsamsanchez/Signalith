package respond

import "runtime"

// Template is a ready-made action the add dialog starts from. The admin
// fills in the address, keys and names marked in Fields before saving.
type Template struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Icon        string    `json:"icon"`
	Connector   Connector `json:"connector"`
	// Headers are the secret headers it needs, with a hint for each.
	Headers []TemplateHeader `json:"headers,omitempty"`
	// UsernameLabel and PasswordLabel rename the Basic sign-in fields,
	// such as API key and API secret.
	UsernameLabel string `json:"username_label,omitempty"`
	PasswordLabel string `json:"password_label,omitempty"`
	// Help is how to set up the other side, in a sentence or two.
	Help string `json:"help"`
	// Docs is the section of docs/response-actions.md about it.
	Docs string `json:"docs"`
}

// TemplateHeader is a header a template sends.
type TemplateHeader struct {
	Name string `json:"name"`
	Hint string `json:"hint"`
}

func boolp(v bool) *bool { return &v }

// Templates returns the ready-made actions, with a script name that suits
// the system the server runs on.
func Templates() []Template {
	script := "isolate-host.sh"
	if runtime.GOOS == "windows" {
		script = "isolate-host.ps1"
	}
	return []Template{
		{
			ID: "opnsense-block", Title: "Block IP on OPNsense/pfSense (alias API)", Icon: "shield-x",
			Description: "Adds the IP to a firewall alias that a block rule uses. Takes effect at once.",
			Connector: Connector{Name: "block-ip-firewall", Label: "Block IP on the firewall", Kind: KindHTTP, Target: TargetIP,
				Disruptive: boolp(true), Method: "POST", URL: "https://firewall.example.lan/api/firewall/alias_util/add/signalith_block",
				Body: `{"address": "{{.ip}}"}`, BodyFormat: BodyJSON},
			UsernameLabel: "API key", PasswordLabel: "API secret",
			Help: "In OPNsense, make a Host(s) alias named signalith_block and a rule that blocks it, then an API key for a user allowed to change aliases. On pfSense, install the REST API package and use its alias address endpoint instead.",
			Docs: "block-an-ip-on-opnsense-or-pfsense",
		},
		{
			ID: "opnsense-unblock", Title: "Unblock IP on OPNsense (undo)", Icon: "shield-check",
			Description: "Takes the IP out of the alias again.",
			Connector: Connector{Name: "unblock-ip-firewall", Label: "Unblock IP on the firewall", Kind: KindHTTP, Target: TargetIP,
				Disruptive: boolp(false), Method: "POST", URL: "https://firewall.example.lan/api/firewall/alias_util/delete/signalith_block",
				Body: `{"address": "{{.ip}}"}`, BodyFormat: BodyJSON},
			UsernameLabel: "API key", PasswordLabel: "API secret",
			Help: "Use the same address, alias and API key as the block action.",
			Docs: "block-an-ip-on-opnsense-or-pfsense",
		},
		{
			ID: "webhook-block", Title: "Block IP via generic webhook", Icon: "send",
			Description: "Sends the IP and the finding as JSON to a firewall manager, automation server or SOAR.",
			Connector: Connector{Name: "block-ip-webhook", Label: "Block IP", Kind: KindHTTP, Target: TargetIP,
				Disruptive: boolp(true), Method: "POST", URL: "https://automation.example.lan/hooks/block-ip",
				Body:       `{"action": "block", "ip": "{{.ip}}", "finding_id": "{{.finding_id}}", "case_id": "{{.case_id}}", "requested_by": "{{.actor}}", "reason": "{{.reason}}"}`,
				BodyFormat: BodyJSON},
			Headers: []TemplateHeader{{Name: "Authorization", Hint: "Bearer and the token, or remove it if the webhook needs none"}},
			Help:    "Point it at any service that blocks an address when it receives this request.",
			Docs:    "send-a-webhook",
		},
		{
			ID: "shuffle", Title: "Shuffle workflow webhook", Icon: "network",
			Description: "Starts a Shuffle workflow with the target and the finding. Shuffle runs as its own program.",
			Connector: Connector{Name: "shuffle-workflow", Label: "Run Shuffle workflow", Kind: KindHTTP, Target: TargetAny,
				Disruptive: boolp(true), Method: "POST", URL: "https://shuffle.example.lan/api/v1/hooks/webhook_REPLACE-WITH-ID",
				Body:       `{"target": "{{.target}}", "target_kind": "{{.target_kind}}", "finding_id": "{{.finding_id}}", "case_id": "{{.case_id}}", "requested_by": "{{.actor}}", "reason": "{{.reason}}"}`,
				BodyFormat: BodyJSON},
			Help: "In Shuffle, add a Webhook trigger to the workflow, start it, and copy its URL here. Shuffle is a separate open-source program (AGPL); Signalith only calls its webhook.",
			Docs: "shuffle",
		},
		{
			ID: "isolate-script", Title: "Isolate host with a script", Icon: "terminal",
			Description: "Runs your script on this server with the host name or IP, for example to call your EDR's isolate API.",
			Connector: Connector{Name: "isolate-host", Label: "Isolate host", Kind: KindScript, Target: TargetHost,
				Disruptive: boolp(true), Program: script, TimeoutSeconds: DefaultScriptTimeout},
			Help: "Put the script in the scripts folder on this server first; the page cannot add it. See the examples in the guide.",
			Docs: "run-a-script",
		},
		{
			ID: "ad-disable", Title: "Disable AD user", Icon: "user-x",
			Description: "Switches the Active Directory account off, with the directory set up on the Users page.",
			Connector: Connector{Name: "disable-ad-user", Label: "Disable AD user", Kind: KindDisableUser, Target: TargetUser,
				Disruptive: boolp(true), Operation: OpDisable},
			Help: "Needs LDAPS or StartTLS, and an account delegated \"Read/Write userAccountControl\" on the users' OU.",
			Docs: "disable-a-directory-account",
		},
		{
			ID: "ad-enable", Title: "Enable AD user (undo)", Icon: "user-check",
			Description: "Switches the account on again after it was disabled.",
			Connector: Connector{Name: "enable-ad-user", Label: "Enable AD user", Kind: KindDisableUser, Target: TargetUser,
				Disruptive: boolp(false), Operation: OpEnable},
			Help: "Uses the same directory and account as Disable AD user.",
			Docs: "disable-a-directory-account",
		},
	}
}
