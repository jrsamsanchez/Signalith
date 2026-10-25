// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// Capability is something Signalith can show evidence of on its own.
type Capability struct {
	ID          string
	Name        string
	Description string
	// Fix says what to do when the capability is not met.
	Fix string
	// Page is the web UI page where it is set up.
	Page string
	eval func(s *Snapshot, c *controlCtx) (Status, string)
}

// controlCtx collects what a control's capabilities found, for the
// control's evidence. It is nil when a capability is evaluated on its own.
type controlCtx struct {
	framework  string
	control    Control
	detections bool        // a detect-* capability was evaluated
	dets       []Detection // the detections that matched
	checks     *CheckEvidence
}

func fixFor(c Capability, st Status) string {
	if st == Met {
		return ""
	}
	return c.Fix
}

// Capabilities returns every capability.
func Capabilities() []Capability { return slices.Clone(capabilities) }

var capabilities = []Capability{
	// Data arriving.
	{ID: "data-any", Name: "Central log collection", Page: "data",
		Description: "Events from your systems arrive in Signalith.",
		Fix:         "Install the agent or point syslog at Signalith on the Add data page.",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			var models []string
			var n int64
			for m, d := range s.Data {
				if d.Count > 0 && m != "Risk" {
					models = append(models, m)
					n += d.Count
				}
			}
			if len(models) == 0 {
				return Missing, "No events arrived in the last 7 days."
			}
			sort.Strings(models)
			return Met, fmt.Sprintf("%s events in the last 7 days, in %d data models: %s.", count(n), len(models), strings.Join(models, ", "))
		}},
	dataCap("data-auth", "Authentication logs", "Sign-ins and failed sign-ins, from Windows, Linux (SSH, sudo) and other sources.",
		"Collect Windows Security logs or Linux auth logs with the agent (Add data).", "Authentication"),
	dataCap("data-process", "Process and command-line logs", "Programs started and their command lines, from Sysmon, Windows Security 4688, auditd or osquery.",
		"Collect Sysmon or Windows process creation events, or Linux auditd, with the agent (Add data).", "Endpoint", "Script"),
	dataCap("data-change", "Account and system change logs", "Accounts created, changed or deleted, group membership and other changes.",
		"Collect Windows Security logs or Linux auth logs with the agent (Add data).", "Change"),
	dataCap("data-network", "Network traffic logs", "Connections allowed or blocked by firewalls and hosts.",
		"Send firewall logs over syslog, or collect Sysmon network events (Add data).", "Network_Traffic"),
	dataCap("data-dns", "DNS query logs", "Names your hosts look up.",
		"Collect Sysmon DNS events or DNS server logs (Add data).", "Network_Resolution"),
	dataCap("data-malware", "Anti-malware logs", "Detections and protection changes from Microsoft Defender, ClamAV and other antivirus products.",
		"Collect Microsoft Defender or other antivirus logs (Add data > Antivirus).", "Malware"),
	dataCap("data-files", "File integrity monitoring", "Changes to watched files and registry keys, from osquery or Sysmon.",
		"Turn on file integrity monitoring for osquery hosts (Endpoints), or collect Sysmon file and registry events.", "Filesystem", "Registry"),
	dataCap("data-inventory", "Software and system inventory", "Installed software, operating systems and listening ports, from osquery.",
		"Enroll hosts with osquery (Add data > osquery).", "Inventory"),

	// Detections.
	detectCap("detect-any", "Threat detection rules", "Scheduled detections that raise findings from your events.",
		func(Detection) bool { return true }),
	detectCap("detect-auth", "Detections for sign-in attacks", "Detections for brute force, password spraying and other attacks on accounts.",
		func(d Detection) bool {
			return slices.Contains(d.Models, "Authentication") || slices.Contains(d.Tactics, "credential-access")
		}),
	detectCap("detect-privilege", "Detections for privilege misuse", "Detections for privilege escalation and misuse of admin rights.",
		func(d Detection) bool { return slices.Contains(d.Tactics, "privilege-escalation") }),
	detectCap("detect-malware", "Detections for malware", "Detections that raise findings from antivirus events.",
		func(d Detection) bool { return slices.Contains(d.Models, "Malware") }),
	detectCap("detect-network", "Detections for network intrusions", "Detections for command and control, lateral movement and data theft over the network.",
		func(d Detection) bool {
			return slices.Contains(d.Models, "Network_Traffic") || slices.Contains(d.Models, "Network_Resolution") ||
				slices.Contains(d.Tactics, "command-and-control") || slices.Contains(d.Tactics, "lateral-movement") ||
				slices.Contains(d.Tactics, "exfiltration")
		}),
	detectCap("detect-change", "Detections for account and persistence changes", "Detections for new accounts, group changes and other ways attackers stay in.",
		func(d Detection) bool {
			return slices.Contains(d.Models, "Change") || slices.Contains(d.Tactics, "persistence")
		}),

	// Working the findings.
	{ID: "triage", Name: "Findings are reviewed", Page: "findings",
		Description: "New findings are looked at within 7 days.",
		Fix:         "Triage the findings that have waited longest on the Findings page, or tune the detections that raise them.",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			f := s.Findings
			if f == nil {
				return Missing, "The findings queue is off."
			}
			if f.Stale > 0 {
				return Partial, fmt.Sprintf("%s new %s waited more than 7 days for review; %s open in all.", count(int64(f.Stale)), plural(f.Stale, "finding has", "findings have"), count(int64(f.Open)))
			}
			// An empty queue shows no review: there must be findings
			// someone has looked at.
			if f.Total == 0 {
				return Missing, "No finding has been raised yet, so there is no review to show."
			}
			if f.Reviewed == 0 {
				return Partial, fmt.Sprintf("%s %s raised, but none has been looked at yet.", count(int64(f.Total)), plural(f.Total, "finding was", "findings were"))
			}
			return Met, fmt.Sprintf("%s %s looked at, and no new finding has waited more than 7 days; %s open, %s not looked at yet.", count(int64(f.Reviewed)), plural(f.Reviewed, "finding was", "findings were"), count(int64(f.Open)), count(int64(f.New)))
		}},
	{ID: "cases", Name: "Incident investigations", Page: "cases",
		Description: "Cases record each investigation: its findings, notes, evidence and who did what.",
		Fix:         "Open an investigation from a finding on the Findings page; on a server where they are off, turn them on.",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			c := s.Cases
			if c == nil {
				return Missing, "Investigations are off."
			}
			if c.Total == 0 {
				return Partial, "Investigations are on, but none has been recorded yet."
			}
			return Met, fmt.Sprintf("Investigations are on: %s %s, %s open.", count(int64(c.Total)), plural(c.Total, "case", "cases"), count(int64(c.Open)))
		}},
	{ID: "response", Name: "Response actions", Page: "respond",
		Description: "Actions analysts can take on a finding, such as blocking an address or disabling an account, each recorded.",
		Fix:         "Set up at least one response action on the Response actions page.",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			r := s.Response
			if r == nil {
				return Missing, "Response actions are off."
			}
			if r.Actions == 0 {
				return Missing, "No response action is set up."
			}
			d := fmt.Sprintf("%d response %s set up", r.Actions, plural(r.Actions, "action", "actions"))
			if r.Playbooks > 0 {
				d += fmt.Sprintf(", and %d %s", r.Playbooks, plural(r.Playbooks, "playbook", "playbooks"))
			}
			// Set up is not shown to work: a run is (COMP-02).
			if r.Ran == 0 {
				return Partial, d + ", but none has run successfully in the last 90 days. Run one on a test target to show it works."
			}
			return Met, d + fmt.Sprintf("; %d %s succeeded in the last 90 days.", r.Ran, plural(r.Ran, "run", "runs"))
		}},
	{ID: "notify", Name: "Alert notifications", Page: "notify",
		Description: "Findings that matter are sent to email, Slack, Teams or a webhook.",
		Fix:         "Add a channel and a rule on Settings > Notifications.",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			n := s.Notify
			switch {
			case n == nil:
				return Missing, "Notifications are off."
			case n.Rules > 0:
				// An enabled rule is not shown to work: a delivered
				// message is (COMP-02).
				d := fmt.Sprintf("%d %s send findings to %d %s", n.Rules, plural(n.Rules, "rule", "rules"), n.Channels, plural(n.Channels, "channel", "channels"))
				switch {
				case n.Unread:
					return Partial, d + ", but what was sent could not be read."
				case n.Failing > 0:
					return Partial, d + fmt.Sprintf(", but the latest message to %d %s failed.", n.Failing, plural(n.Failing, "channel", "channels"))
				case n.Sent == 0:
					return Partial, d + ", but nothing was delivered in the last 30 days. Send a test from Settings > Notifications."
				}
				return Met, d + fmt.Sprintf("; %d %s delivered in the last 30 days.", n.Sent, plural(n.Sent, "message", "messages"))
			case n.Channels > 0:
				return Partial, fmt.Sprintf("%d %s set up, but no enabled rule sends findings to them.", n.Channels, plural(n.Channels, "channel is", "channels are"))
			}
			return Missing, "No notification channel is set up."
		}},
	{ID: "intel", Name: "Threat intelligence", Page: "intel",
		Description: "Threat intel feeds keep indicators of known attacks current, and findings are matched against them.",
		Fix:         "Add a feed from the catalog on the Threat intel page.",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			in := s.Intel
			switch {
			case in == nil:
				return Missing, "Threat intel is off."
			case in.Fresh > 0:
				return Met, fmt.Sprintf("%d of %d %s downloaded in the last 7 days.", in.Fresh, in.Feeds, plural(in.Feeds, "feed", "feeds"))
			case in.Feeds > 0:
				return Partial, fmt.Sprintf("%d %s on, but none downloaded in the last 7 days.", in.Feeds, plural(in.Feeds, "feed is", "feeds are"))
			}
			return Missing, "No threat intel feed is on."
		}},

	// Checking hosts.
	{ID: "config-checks", Name: "Configuration checks", Page: "endpoints",
		Description: "osquery checks each host's settings against hardening rules based on the SCAP Security Guide.",
		Fix:         "Enroll hosts with osquery (Add data > osquery) and fix the failing checks on the Endpoints page. Where no built-in check covers your hosts' platform, show the setting another way.",
		eval:        evalChecks},
	{ID: "vuln-scan", Name: "Vulnerability scanning", Page: "vulns",
		Description: "Scheduled Nmap scans find hosts, open ports and known vulnerabilities (CVEs).",
		Fix:         "Add your networks on the Vulnerabilities page and scan them at least monthly.",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			v := s.Vulns
			switch {
			case v == nil:
				return Missing, "Vulnerability scanning is off."
			case v.LastScan.IsZero() && v.Networks == 0:
				return Missing, "No network is set up for scanning."
			case v.LastScan.IsZero():
				return Missing, fmt.Sprintf("%d %s set up, but no scan has finished yet.", v.Networks, plural(v.Networks, "network is", "networks are"))
			}
			age := s.Now.Sub(v.LastScan)
			d := fmt.Sprintf("The last scan finished %s (%s).", ago(age), day(v.LastScan))
			switch {
			case age <= 31*24*time.Hour:
				return Met, d
			case age <= 92*24*time.Hour:
				return Partial, d + " Scan at least monthly."
			}
			return Missing, d + " That is more than three months ago."
		}},
	{ID: "assets", Name: "Asset and identity lists", Page: "assets",
		Description: "Lists of your systems and accounts, with owners and priority.",
		Fix:         "Upload or edit the asset list on the Assets & identities page.",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			switch {
			case s.Assets < 0:
				return Missing, "Asset and identity lists are off."
			case s.Assets == 0:
				return Missing, "No assets or identities are listed."
			}
			d := fmt.Sprintf("%s %s listed", count(int64(s.Assets)), plural(s.Assets, "asset or identity", "assets and identities"))
			// A list without owners or priorities is a name list
			// (COMP-02).
			if s.AssetsRated == 0 {
				return Partial, d + ", but none has an owner or a priority."
			}
			return Met, d + fmt.Sprintf(", %s with an owner or a priority.", count(int64(s.AssetsRated)))
		}},

	// Keeping the logs.
	{ID: "retention-90", Name: "Logs searchable for 90 days", Page: "retention",
		Description: "Event data stays searchable for at least 90 days.",
		Fix:         "Set event data to be kept at least 90 days on Settings > Data retention.",
		eval:        func(s *Snapshot, _ *controlCtx) (Status, string) { return evalRetention(s, 90, false) }},
	{ID: "retention-1y", Name: "Logs kept for a year", Page: "retention",
		Description: "Event data is kept at least 12 months, searchable or archived.",
		Fix:         "Keep event data 365 days, or turn on archiving, on Settings > Data retention.",
		eval:        func(s *Snapshot, _ *controlCtx) (Status, string) { return evalRetention(s, 365, true) }},
	{ID: "retention-limit", Name: "Logs are deleted when no longer needed", Page: "retention",
		Description: "Event data, findings and investigations, which hold personal data such as user names and addresses, are deleted after a set time instead of kept forever.",
		Fix:         "On Settings > Data retention, set how many days events, findings and investigations are kept: as long as your purposes and legal duties need, and no longer. Delete archive files on the same schedule.",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			r := s.Retention
			switch {
			case r == nil:
				return Missing, "Data retention could not be read."
			case r.KeepDays == 0:
				return Missing, "Event data is kept until it is deleted by hand."
			}
			st, d := Met, fmt.Sprintf("Event data is deleted after %d days.", r.KeepDays)
			if len(r.Longer) > 0 {
				st = Partial
				d += fmt.Sprintf(" Some data is kept longer: %s.", strings.Join(r.Longer, ", "))
			}
			if r.Archive {
				st = Partial
				d += " It is archived first, and archive files are kept until you delete them."
			}
			return st, d
		}},
	{ID: "storage-guard", Name: "Log storage capacity", Page: "retention",
		Description: "The disk guard deletes the oldest data before the disk fills, so new events keep arriving.",
		Fix:         "Turn the disk guard on, on Settings > Data retention.",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			if s.Retention == nil {
				return Missing, "Data retention is off."
			}
			if !s.Retention.Guard {
				return Missing, "The disk guard is off, so a full disk would stop events arriving."
			}
			if !s.HasData("") {
				return Partial, "The disk guard is on, but no events arrived in the last 7 days, so there is no log storage to show yet."
			}
			return Met, "The disk guard is on: it frees space before the disk fills, and the Health page warns first."
		}},

	// Built into Signalith.
	builtinWithData("timestamps", "Consistent time stamps", "health",
		"Every event's time is stored in UTC alongside the original text, so events from different time zones line up. Hosts still need their clocks synchronized (NTP), which their configuration checks cover."),
	builtinWithData("record-content", "Detailed log records", "search",
		"Events are mapped to data models with the same fields for every source: time, host, user, source, action and outcome, and the original text is kept."),
	builtinWithData("search", "Log search and reports", "search",
		"Search, dashboards and exports filter and summarize events on demand, without changing them."),
	builtinWithData("source-health", "Log source monitoring", "health",
		"The Health page and the posture dashboard list sources that stopped sending, and the disk and OpenSearch state; the built-in detection data-source-stopped raises a finding when a host that sent all day goes quiet."),
	{ID: "siem-access", Name: "Access to the logs is limited", Page: "users",
		Description: "Everyone signs in with their own account and a role (Viewer, Analyst or Admin); events cannot be changed from Signalith.",
		Fix:         "Give each person their own account on Settings > Users, or sign in with your directory (LDAP or Active Directory).",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			u := s.Users
			switch {
			case u == nil:
				return Partial, "Users could not be read."
			case u.Named == 0 && !u.Directory:
				return Partial, "Only the built-in admin account is used, so actions cannot be traced to a person."
			case u.SignedIn == 0:
				// Accounts nobody uses show nothing: sign-ins do
				// (COMP-02).
				return Partial, fmt.Sprintf("%d named %s with roles, but none signed in in the last 90 days.", u.Named, plural(u.Named, "user", "users"))
			case u.Directory:
				return Met, fmt.Sprintf("People sign in with the directory; %d of %d named %s signed in in the last 90 days.", u.SignedIn, u.Named, plural(u.Named, "user", "users"))
			default:
				return Met, fmt.Sprintf("%d of %d named %s with roles, besides the built-in admin, signed in in the last 90 days.", u.SignedIn, u.Named, plural(u.Named, "user", "users"))
			}
		}},
	{ID: "siem-tls", Name: "Logs are encrypted in transit", Page: "security",
		Description: "The web UI, the API, the agents and syslog use encrypted connections.",
		Fix:         "Serve Signalith over HTTPS (it does by default), move syslog senders to syslog over TLS and turn plain syslog off on Add data > Syslog.",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			if !s.HTTPS {
				return Missing, "Signalith is served over plain HTTP."
			}
			if len(s.PlainSyslog) > 0 {
				return Partial, "The web UI, the API and agent ingest use HTTPS, but plain syslog is on (" + strings.Join(s.PlainSyslog, ", ") + "), so devices sending there do so unencrypted."
			}
			return Met, "The web UI, the API and agent ingest use HTTPS, and plain syslog is off."
		}},
	{ID: "siem-mfa", Name: "Two-step sign-in", Page: "settings",
		Description: "People who sign in to Signalith with a password must also enter a code from an authenticator app or use a passkey.",
		Fix:         "Set Require two-step sign-in to Everyone on Settings > General. Single sign-on users get it from their identity provider.",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			switch s.MFA {
			case "everyone":
				return Met, "Everyone who signs in with a password must use two-step sign-in."
			case "admins":
				return Partial, "Only admins must use two-step sign-in; analysts and viewers, who can also read the logs, need not."
			case "off":
				return Missing, "Two-step sign-in is not required."
			}
			return Partial, "The two-step sign-in setting could not be read."
		}},
	builtin("siem-audit", "Audit trail of Signalith itself", "health",
		"Signalith writes an audit line for every sign-in, failed sign-in, search and change to users, roles, settings, agent tokens, response actions and retention, with who did it, when and from where. With several servers the lines are kept in OpenSearch, chained and signed so changes show."),
	builtin("siem-secrets", "Secrets are encrypted at rest", "security",
		"Passwords, API keys and tokens Signalith keeps are encrypted on disk. Encrypt the data disk itself (BitLocker or LUKS) to protect stored events too."),
}

var capabilityByID = func() map[string]Capability {
	m := make(map[string]Capability, len(capabilities))
	for _, c := range capabilities {
		m[c.ID] = c
	}
	return m
}()

// builtinWithData is something Signalith always does to the events it
// receives, so it counts only once events arrive: on a server that has
// none there is nothing to show.
func builtinWithData(id, name, page, desc string) Capability {
	return Capability{ID: id, Name: name, Description: desc, Page: page,
		Fix: "Send events to Signalith (Add data); this is then done for every one of them.",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			if !s.HasData("") {
				return Missing, "Built in, but no events arrived in the last 7 days, so there is nothing to show yet."
			}
			return Met, "Built in, for the events that arrive: " + lowerFirst(desc)
		}}
}

func builtin(id, name, page, desc string) Capability {
	return Capability{ID: id, Name: name, Description: desc, Page: page,
		eval: func(*Snapshot, *controlCtx) (Status, string) { return Met, "Built in: " + lowerFirst(desc) }}
}

func dataCap(id, name, desc, fix string, models ...string) Capability {
	return Capability{ID: id, Name: name, Description: desc, Fix: fix, Page: "data",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			var n int64
			var last time.Time
			for _, m := range models {
				d := s.Data[m]
				n += d.Count
				if d.Last.After(last) {
					last = d.Last
				}
			}
			if n == 0 {
				return Missing, fmt.Sprintf("No %s events in the last 7 days.", strings.Join(models, " or "))
			}
			d := fmt.Sprintf("%s %s events in the last 7 days", count(n), strings.Join(models, " and "))
			if !last.IsZero() {
				d += fmt.Sprintf(", the latest %s", ago(s.Now.Sub(last)))
			}
			if slices.ContainsFunc(models, func(m string) bool { return slices.Contains(HostModels, m) }) {
				return hostCoverage(s, models, d)
			}
			return Met, d + "."
		}}
}

// hostCoverage rates data every computer should send by how many of the
// computers Signalith knows sent it: one host sending is not all of them.
func hostCoverage(s *Snapshot, models []string, d string) (Status, string) {
	if s.HostsErr != "" {
		return Partial, d + ". Which computers sent them could not be read: " + s.HostsErr + "."
	}
	if len(s.Computers) == 0 {
		return Met, d + ". No computer runs the agent or osquery, so Signalith cannot tell whether every computer sends them."
	}
	var missing []string
	for _, c := range s.Computers {
		if !slices.ContainsFunc(models, func(m string) bool { return s.DataHosts[m][c] }) {
			missing = append(missing, c)
		}
	}
	n := len(s.Computers)
	if len(missing) == 0 {
		return Met, fmt.Sprintf("%s, from all %s %s that %s the agent or osquery.", d, count(int64(n)), plural(n, "computer", "computers"), plural(n, "runs", "run"))
	}
	sort.Strings(missing)
	names := strings.Join(missing[:min(len(missing), MaxHosts)], ", ")
	if more := len(missing) - MaxHosts; more > 0 {
		names += fmt.Sprintf(" and %s more", count(int64(more)))
	}
	return Partial, fmt.Sprintf("%s, from %s of the %s %s that %s the agent or osquery; none from %s.", d,
		count(int64(n-len(missing))), count(int64(n)), plural(n, "computer", "computers"), plural(n, "runs", "run"), names)
}

func detectCap(id, name, desc string, match func(Detection) bool) Capability {
	return Capability{ID: id, Name: name, Description: desc, Page: "detections",
		Fix: "Turn on the matching detections on the Detections page, and collect the data they read.",
		eval: func(s *Snapshot, c *controlCtx) (Status, string) {
			if s.Detections == nil {
				return Missing, "Detections are off."
			}
			var matched []Detection
			for _, d := range s.Detections {
				if match(d) {
					matched = append(matched, d)
				}
			}
			if c != nil {
				c.detections = true
				matched = append(matched, taggedDetections(s, c.framework, c.control.ID)...)
			}
			return detectionStatus(s, matched, c)
		}}
}

// detectionStatus rates a set of detections, and adds them to the
// control's evidence.
func detectionStatus(s *Snapshot, matched []Detection, c *controlCtx) (Status, string) {
	seen := map[string]bool{}
	var on, withData, off int
	for _, d := range matched {
		if seen[d.ID] {
			continue
		}
		seen[d.ID] = true
		if !d.Enabled {
			off++
			continue
		}
		on++
		if detectionHasData(s, d) {
			withData++
		}
		if c != nil {
			c.dets = append(c.dets, d)
		}
	}
	more := ""
	if off > 0 {
		more = fmt.Sprintf(" %s more %s available but off.", count(int64(off)), plural(off, "is", "are"))
	}
	switch {
	case len(seen) == 0:
		return Missing, "No detection covers this yet."
	case on == 0:
		return Missing, fmt.Sprintf("%s %s available, but none is on.", count(int64(off)), plural(off, "detection is", "detections are"))
	case !s.SchedulerOn:
		return Partial, fmt.Sprintf("%s %s on, but scheduled detections are turned off on this server.", count(int64(on)), plural(on, "detection is", "detections are"))
	case withData == 0:
		return Partial, fmt.Sprintf("%s %s on, but none of the data %s arrives.%s", count(int64(on)), plural(on, "detection is", "detections are"), plural(on, "it reads", "they read"), more)
	}
	return Met, fmt.Sprintf("%s %s on, %s with data arriving.%s", count(int64(on)), plural(on, "detection is", "detections are"), count(int64(withData)), more)
}

func detectionHasData(s *Snapshot, d Detection) bool {
	if len(d.Models) == 0 {
		return s.HasData("")
	}
	for _, m := range d.Models {
		if s.HasData(m) {
			return true
		}
	}
	return false
}

func evalChecks(s *Snapshot, c *controlCtx) (Status, string) {
	if s.Checks == nil {
		return Missing, "Endpoints are off, so no configuration checks run."
	}
	ev := &CheckEvidence{Failing: []CheckRef{}}
	// covers are the platforms the matching checks are for; only those
	// with a host that runs them count.
	covers := map[string]bool{}
	for _, ch := range s.Checks {
		if c != nil && !slices.ContainsFunc(c.control.NIST, func(n string) bool {
			return slices.ContainsFunc(ch.Refs, func(r string) bool { return refMatches(n, r) })
		}) {
			continue
		}
		covers[ch.Platform] = true
		if s.Platforms != nil && s.Platforms[ch.Platform] == 0 {
			continue
		}
		ev.Checks++
		ev.Pass += ch.Pass
		ev.Fail += ch.Fail
		ev.NA += ch.NA
		ev.Pending += ch.Pending
		ev.Error += ch.Error
		if ch.Fail > 0 {
			hosts := slices.Clone(ch.Failing)
			sort.Slice(hosts, func(i, j int) bool { return strings.ToLower(hosts[i].Hostname) < strings.ToLower(hosts[j].Hostname) })
			if len(hosts) > MaxHosts {
				hosts = hosts[:MaxHosts]
			}
			if hosts == nil {
				hosts = []HostRef{}
			}
			ev.Failing = append(ev.Failing, CheckRef{ID: ch.ID, Title: ch.Title, Platform: ch.Platform, Hosts: ch.Fail, Failing: hosts})
		}
	}
	sort.SliceStable(ev.Failing, func(i, j int) bool { return ev.Failing[i].Hosts > ev.Failing[j].Hosts })
	if c != nil {
		c.checks = ev
	}
	// The hosts no matching check is for are not checked at all.
	var uncovered []string
	for _, p := range sortedKeys(s.Platforms) {
		if !covers[p] && s.Platforms[p] > 0 {
			uncovered = append(uncovered, fmt.Sprintf("%d %s %s", s.Platforms[p], PlatformName(p), plural(s.Platforms[p], "host", "hosts")))
		}
	}
	more := ""
	if ev.Error > 0 {
		more += fmt.Sprintf(" %s %s could not be read on the host.", count(int64(ev.Error)), plural(ev.Error, "result", "results"))
	}
	if !s.HostsSeen[0].IsZero() {
		more += fmt.Sprintf(" Hosts last reported between %s and %s.", ago(s.Now.Sub(s.HostsSeen[0])), ago(s.Now.Sub(s.HostsSeen[1])))
	}
	seen := more
	if len(uncovered) > 0 {
		more = " No check covers your " + strings.Join(uncovered, " or ") + "." + more
	}
	switch {
	case s.Hosts == 0:
		return Missing, "No host runs osquery yet, so no configuration checks run."
	case len(covers) == 0:
		return Missing, "No configuration check covers this yet."
	case ev.Checks == 0:
		var on []string
		for _, p := range sortedKeys(covers) {
			on = append(on, PlatformName(p))
		}
		return Missing, fmt.Sprintf("The checks for this run only on %s, and none of your hosts does.%s", strings.Join(on, " and "), seen)
	case ev.Pass+ev.Fail == 0 && ev.Error > 0 && ev.Pending == 0:
		return Missing, fmt.Sprintf("%d %s apply, but no host could run %s.%s", ev.Checks, plural(ev.Checks, "check", "checks"), plural(ev.Checks, "it", "them"), more)
	case ev.Pass+ev.Fail == 0:
		return Missing, fmt.Sprintf("%d %s apply, but no host has reported results yet.%s", ev.Checks, plural(ev.Checks, "check", "checks"), more)
	case ev.Fail > 0:
		return Partial, fmt.Sprintf("%d %s: %s %s and %s %s across %d %s.%s", ev.Checks, plural(ev.Checks, "check", "checks"),
			count(int64(ev.Pass)), plural(ev.Pass, "pass", "passes"), count(int64(ev.Fail)), plural(ev.Fail, "failure", "failures"), s.Hosts, plural(s.Hosts, "host", "hosts"), more)
	}
	st := Met
	if len(uncovered) > 0 {
		st = Partial
	}
	return st, fmt.Sprintf("%d %s pass on every host that reported (%s %s across %d %s).%s", ev.Checks, plural(ev.Checks, "check", "checks"),
		count(int64(ev.Pass)), plural(ev.Pass, "result", "results"), s.Hosts, plural(s.Hosts, "host", "hosts"), more)
}

// PlatformName is how the report names an osquery platform.
func PlatformName(p string) string {
	switch p {
	case "darwin":
		return "macOS"
	case "linux":
		return "Linux"
	case "windows":
		return "Windows"
	}
	return p
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func evalRetention(s *Snapshot, days int, archiveCounts bool) (Status, string) {
	r := s.Retention
	if r == nil {
		return Missing, "Data retention could not be read."
	}
	var st Status
	var d string
	switch {
	case r.KeepDays == 0 && r.Guard:
		st, d = Partial, "Event data is kept until it is deleted by hand, but the disk guard deletes the oldest days when the disk fills, so how long it is kept depends on disk space."
	case r.KeepDays == 0:
		st, d = Met, "Event data is kept until it is deleted by hand."
	case r.KeepDays >= days:
		st, d = Met, fmt.Sprintf("Event data is kept %d days.", r.KeepDays)
	case archiveCounts && r.Archive:
		st, d = Partial, fmt.Sprintf("Event data is searchable %d days, then archived before it is deleted. Signalith cannot see whether the archive files are kept for the rest of the year.", r.KeepDays)
	default:
		return Missing, fmt.Sprintf("Event data is kept only %d days.", r.KeepDays)
	}
	// The policy is not the data: say how far back events really go.
	if r.OldestRead {
		switch {
		case r.Oldest.IsZero():
			st = Partial
			d += " No event data is stored yet."
		case s.Now.Sub(r.Oldest) < time.Duration(days-1)*24*time.Hour:
			st = Partial
			d += fmt.Sprintf(" The oldest events kept are from %s (%s), so %d days cannot be shown yet.", day(r.Oldest), ago(s.Now.Sub(r.Oldest)), days)
		default:
			d += fmt.Sprintf(" The oldest events kept are from %s.", day(r.Oldest))
		}
	}
	if len(r.Shorter) > 0 {
		st = Partial
		d += fmt.Sprintf(" Some data has a shorter policy: %s.", strings.Join(r.Shorter, ", "))
	}
	if r.MaxSizeGB > 0 {
		st = Partial
		d += fmt.Sprintf(" A size cap of %g GB can delete older data sooner.", r.MaxSizeGB)
	}
	return st, d
}

// ---- wording ----

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// count writes n with thousands separators.
func count(n int64) string {
	s := fmt.Sprint(n)
	if n < 0 {
		return s
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func ago(d time.Duration) string {
	switch {
	case d < 2*time.Minute:
		return "just now"
	case d < 2*time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}
