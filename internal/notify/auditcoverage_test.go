// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// notAlerted are the audit records no built-in audit alert is about, on
// purpose: everyday work, records of what a server did on its own, and
// records an alert covers through another message. A record is matched
// by its message, or by the action before the first ":" of it.
var notAlerted = []string{
	"AI first pass failed", "AI first pass stopped: the model searched for a masked value",
	"finding looked at by the AI first pass", "detection.export",
	"AI detection draft failed", "AI investigation search refused", "AI query translation failed",
	"Investigate with AI failed", "Investigate with AI stopped: the model searched for a masked value",
	"Signalith started again", "Slack channel's workspace recorded", "Teams app added to a Teams conversation",
	"Teams app channel move declined", "Teams app channel now posts to a Teams conversation",
	"Teams app removed from the Teams channel it posted to",
	"a session made while OpenSearch could not be written ended: its user changed meanwhile",
	"a sign-in that finished while this server moved to the shared users could not be kept; that browser signs in again",
	"agent host enrolled", "agent token renamed",
	"agents on plain HTTP are refused, so the example ingest token change-this-ingest-token, which the older Docker quick start gave every agent, is refused for good",
	"an agent asked for the key of a computer that has one; refused",
	"an agent line asked for too many computer keys; refused",
	"asked for a ticket for a case; the server that runs the background jobs opens it", "background jobs moved",
	"backup.snapshots", "behavior baseline value forgotten", "case.close_findings", "case.create",
	"case.entity_add", "case.entry_add", "case.entry_remove", "case.file_attach", "case.file_download",
	"case.finding_add", "case.finding_remove", "case.report_export", "case.report_key_revoke",
	"case.report_verify", "case.task_add", "case.task_remove", "case.task_update", "case.template_save",
	"case.ticket_open", "case.update", "chat account not linked", "chat account unlinked",
	"chat button refused", "chat link code made", "chat link code spent", "chat request refused",
	"cluster.join failed after the token was used; the new server needs a new token", "cluster.join refused",
	"cluster.merged", "cluster.name ", "compliance.export", "compliance.history", "content update check",
	"could not open a ticket for a case",
	"could not seal the key of the cluster's next or previous certificate authority with the new cluster key; its old sealed value is kept",
	"detection backtested", "detection drafted with AI", "detection exception approval rolled back",
	"detection exception approval unconfirmed", "detection exception declined", "detection exception proposed",
	"detection exception request expired", "detection.create", "detection.exception_remove",
	"detection.scoped_exception_remove", "directory connection tested", "directory user looked up",
	"ended a directory user's sessions: the directory settings changed and the user could not be checked with the directory",
	"finding investigated with AI", "finding.bulk_update", "finding.create", "finding.update",
	"found the ticket an earlier try opened for a case, and recorded it instead of opening another",
	"founded the cluster: the servers sharing this OpenSearch now keep their shared settings in it",
	"handed OpenSearch's certificate authority to the cluster and deleted its key file",
	"handing the background jobs to another server", "hunting notebook changed by someone other than its owner",
	"hunting notebook created", "hunting notebook linked to a case",
	"hunting notebook owner removed with their account", "hunting notebook sharing changed",
	"hunting notebook unlinked from a case", "intel.feed_add", "intel.feed_change", "intel.feed_refresh",
	"intel.feed_test", "intel.indicator_add", "intel.indicator_upload",
	"kept the built-in admin's new password, changed while the users moved into the shared settings",
	"kept the sign-in sessions made before the users were shared",
	"log sample sent to the AI model", "marked a cluster key a rotation retired",
	"metrics scrape refused", "new web address confirmed: someone reached it", "opened a ticket for a case",
	"osquery enrollment refused: it would replace a host enrolled with its computer's own key (logged once an hour per host)",
	"osquery enrollment refused: the computer has its own key and the request came without it (logged once an hour per host)",
	"osquery host enrolled", "other sessions ended", "password accepted, waiting for the two-step code",
	"password or code entered again", "published this server's certificate authority as the cluster's",
	"question translated with AI",
	"raised the level of the shared settings: every server seen in the last 24 hours reads it, and older versions no longer start",
	"recheck refused", "refused a request to publish this server's certificate authority",
	"refused to remove many detections or dashboards from the shared library: their files are gone from this server's folders; nothing was removed",
	"removed a server from the cluster",
	"removed the file that kept the first admin password, which no longer works", "removing many ",
	"respond.test", "response action started", "response action test sent", "restart failed",
	"restart of servers requested", "restart requested", "restarted with the saved settings",
	"rotated the cluster key", "sample data load failed", "sample data load started", "sample data loaded",
	"sample data record named no load: cleared it, deleted no events, findings or investigations",
	"sample data remove failed", "sample data removed",
	"sample data: the record of the sample data names no load; deleting no events, findings or investigations, only the sample's threat intel, its asset and identity entries and the record",
	"server ", "session ended", "settings tested",
	"signed in while OpenSearch cannot be written; the session works on this server only, for at most an hour",
	"signed out", "started a rotation of the cluster key",
	"the server that founded the cluster has not been seen for 7 days, so this server imports its own files into the shared settings",
	"this server added itself to the cluster's keyring",
	"this server caught up with a rotation of the cluster key it missed",
	"this server could not use shared settings and keeps the values it ran with; the other servers use the shared ones",
	"this server picked up the new cluster key of a key rotation",
	"this server signs in to OpenSearch with its own certificate now",
	"this server was approved to join the cluster and received the cluster key",
	"this server was drained: it wants no traffic and runs no background jobs until it is resumed",
	"this server was resumed", "this server's own settings moved from settings.yaml into the shared settings",
	"ticket sync: added the ticket's new comments to the case",
	"ticket sync: changed the case's status to match the ticket",
	"ticket sync: changed the ticket's title and priority to match the case",
	"ticket sync: moved the ticket to match the case", "ticket sync: sent the case's new notes to the ticket",
	"ticket sync: some of the ticket's comments were not added to the case",
	"ticket sync: the ticket was deleted", "ticketing connection test failed",
	"ticketing connection test passed", "took a step of replacing the cluster's certificate authority",
	"two-step sign-in turned on", "unmarked a cluster key the keyring lists again", "user's sessions ended",
	"vulnerability scan login removed", "vulnerability scan requested", "vulnerability scan stopped",
	"went back to the previous web address", "wrote OpenSearch's revocation list",
	"wrote through a session made while OpenSearch could not be written",
}

// loggedAuditMessages returns the message of every audit record the code
// logs with a message it spells out: s.audit(r, "..."), x.audit("...")
// and log calls that carry "audit", true. For a message built by adding
// strings, it is the first of them.
func loggedAuditMessages(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "..")
	seen := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "site", "web", "docs", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			var msg ast.Expr
			switch sel.Sel.Name {
			case "audit":
				msg = call.Args[0]
				if id, ok := msg.(*ast.Ident); ok && id.Name == "r" && len(call.Args) > 1 {
					msg = call.Args[1]
				}
			case "Info", "Warn", "Error":
				if carriesAuditTrue(call.Args[1:]) {
					msg = call.Args[0]
				}
			}
			if s, ok := firstString(msg); ok && s != "" {
				seen[s] = true
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// carriesAuditTrue reports whether log arguments hold "audit", true,
// directly or in a slice literal among them.
func carriesAuditTrue(args []ast.Expr) bool {
	found := false
	for _, a := range args {
		ast.Inspect(a, func(n ast.Node) bool {
			var list []ast.Expr
			switch n := n.(type) {
			case *ast.CompositeLit:
				list = n.Elts
			case *ast.CallExpr:
				list = n.Args
			default:
				return true
			}
			for i := 0; i+1 < len(list); i++ {
				if lit, ok := list[i].(*ast.BasicLit); ok && lit.Value == `"audit"` {
					if id, ok := list[i+1].(*ast.Ident); ok && id.Name == "true" {
						found = true
					}
				}
			}
			return true
		})
	}
	for i := 0; i+1 < len(args); i++ {
		if lit, ok := args[i].(*ast.BasicLit); ok && lit.Value == `"audit"` {
			if id, ok := args[i+1].(*ast.Ident); ok && id.Name == "true" {
				found = true
			}
		}
	}
	return found
}

// firstString returns a string literal, or the first one of a sum.
func firstString(e ast.Expr) (string, bool) {
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			return firstString(e.X)
		}
	}
	return "", false
}

// actionOfMessage is the action an audit record of a message gets: the
// word before its first ":", as audit.actionOf finds it.
func actionOfMessage(msg string) string {
	i := strings.IndexByte(msg, ':')
	if i <= 0 || i > 64 {
		return ""
	}
	tok := msg[:i]
	for _, c := range tok {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return ""
		}
	}
	return tok
}

// alertLooksFor reports whether an alert looks for records of a message,
// whatever its check then makes of their fields.
func alertLooksFor(a AuditAlert, msg string) bool {
	act := actionOfMessage(msg)
	if slices.Contains(a.messages, msg) || act != "" && slices.Contains(a.actions, act) {
		return true
	}
	for _, p := range a.prefixes {
		if strings.HasPrefix(msg, p) || strings.HasPrefix(p, msg) {
			return true
		}
	}
	for _, p := range a.actionPrefixes {
		if act != "" && strings.HasPrefix(act, p) {
			return true
		}
	}
	return false
}

// TestEveryAuditRecordIsAlertedOrListed keeps the built-in audit alerts
// in step with new audit records: each record the code logs is one an
// alert looks for, or one notAlerted lists on purpose (SRCH-207).
func TestEveryAuditRecordIsAlertedOrListed(t *testing.T) {
	logged := loggedAuditMessages(t)
	if len(logged) < 100 {
		t.Fatalf("found only %d audit messages in the code; the scan is broken", len(logged))
	}
	var missing []string
	for _, m := range logged {
		listed := slices.Contains(notAlerted, m) || slices.Contains(notAlerted, actionOfMessage(m))
		alerted := slices.ContainsFunc(AuditAlerts, func(a AuditAlert) bool { return alertLooksFor(a, m) })
		switch {
		case listed && alerted:
			t.Errorf("%q is on notAlerted, but an alert looks for it", m)
		case !listed && !alerted:
			missing = append(missing, m)
		}
	}
	for _, m := range missing {
		t.Errorf("no audit alert looks for %q: add it to an alert, or to notAlerted if no admin needs to hear of it", m)
	}
	for _, m := range notAlerted {
		if !slices.ContainsFunc(logged, func(l string) bool { return l == m || actionOfMessage(l) == m }) {
			t.Errorf("notAlerted lists %q, which no code logs", m)
		}
	}
}
