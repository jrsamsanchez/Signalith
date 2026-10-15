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
			if f.Open == 0 {
				return Met, "No open findings."
			}
			return Met, fmt.Sprintf("No new finding has waited more than 7 days; %s open, %s not looked at yet.", count(int64(f.Open)), count(int64(f.New)))
		}},
	{ID: "cases", Name: "Incident investigations", Page: "cases",
		Description: "Cases record each investigation: its findings, notes, evidence and who did what.",
		Fix:         "Investigations are off on this server.",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			c := s.Cases
			if c == nil {
				return Missing, "Investigations are off."
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
			return Met, d + "."
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
				return Met, fmt.Sprintf("%d %s send findings to %d %s.", n.Rules, plural(n.Rules, "rule", "rules"), n.Channels, plural(n.Channels, "channel", "channels"))
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
		Fix:         "Enroll hosts with osquery (Add data > osquery) and fix the failing checks on the Endpoints page.",
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
			return Met, fmt.Sprintf("%s %s listed.", count(int64(s.Assets)), plural(s.Assets, "asset or identity", "assets and identities"))
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
			return Met, "The disk guard is on: it frees space before the disk fills, and the Health page warns first."
		}},

	// Built into Signalith.
	builtin("timestamps", "Consistent time stamps", "health",
		"Every event's time is stored in UTC alongside the original text, so events from different time zones line up. Hosts still need their clocks synchronized (NTP), which their configuration checks cover."),
	builtin("record-content", "Detailed log records", "search",
		"Events are mapped to data models with the same fields for every source: time, host, user, source, action and outcome, and the original text is kept."),
	builtin("search", "Log search and reports", "search",
		"Search, dashboards and exports filter and summarize events on demand, without changing them."),
	builtin("source-health", "Log source monitoring", "health",
		"The Health page and the posture dashboard list sources that stopped sending, and the disk and OpenSearch state."),
	{ID: "siem-access", Name: "Access to the logs is limited", Page: "users",
		Description: "Everyone signs in with their own account and a role (Viewer, Analyst or Admin); events cannot be changed from Signalith.",
		Fix:         "Give each person their own account on Settings > Users, or sign in with your directory (LDAP or Active Directory).",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			u := s.Users
			switch {
			case u == nil:
				return Partial, "Users could not be read."
			case u.Directory:
				return Met, fmt.Sprintf("People sign in with the directory; %d named %s with roles.", u.Named, plural(u.Named, "user", "users"))
			case u.Named > 0:
				return Met, fmt.Sprintf("%d named %s with roles, besides the built-in admin.", u.Named, plural(u.Named, "user", "users"))
			}
			return Partial, "Only the built-in admin account is used, so actions cannot be traced to a person."
		}},
	{ID: "siem-tls", Name: "Logs are encrypted in transit", Page: "security",
		Description: "The web UI, the API and the agents use HTTPS.",
		Fix:         "Serve Signalith over HTTPS (it does by default); see Settings > Security.",
		eval: func(s *Snapshot, _ *controlCtx) (Status, string) {
			if s.HTTPS {
				return Met, "The web UI, the API and agent ingest use HTTPS."
			}
			return Missing, "Signalith is served over plain HTTP."
		}},
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
			return Met, d + "."
		}}
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
	for _, ch := range s.Checks {
		if c != nil && !slices.ContainsFunc(c.control.NIST, func(n string) bool {
			return slices.ContainsFunc(ch.Refs, func(r string) bool { return refMatches(n, r) })
		}) {
			continue
		}
		ev.Checks++
		ev.Pass += ch.Pass
		ev.Fail += ch.Fail
		ev.NA += ch.NA
		ev.Pending += ch.Pending
		ev.Error += ch.Error
		if ch.Fail > 0 {
			ev.Failing = append(ev.Failing, CheckRef{ID: ch.ID, Title: ch.Title, Platform: ch.Platform, Hosts: ch.Fail})
		}
	}
	sort.SliceStable(ev.Failing, func(i, j int) bool { return ev.Failing[i].Hosts > ev.Failing[j].Hosts })
	if c != nil {
		c.checks = ev
	}
	switch {
	case s.Hosts == 0:
		return Missing, "No host runs osquery yet, so no configuration checks run."
	case ev.Checks == 0:
		return Missing, "No configuration check covers this yet."
	case ev.Pass+ev.Fail == 0:
		return Missing, fmt.Sprintf("%d %s apply, but no host has reported results yet.", ev.Checks, plural(ev.Checks, "check", "checks"))
	case ev.Fail > 0:
		return Partial, fmt.Sprintf("%d %s: %s %s and %s %s across %d %s.", ev.Checks, plural(ev.Checks, "check", "checks"),
			count(int64(ev.Pass)), plural(ev.Pass, "pass", "passes"), count(int64(ev.Fail)), plural(ev.Fail, "failure", "failures"), s.Hosts, plural(s.Hosts, "host", "hosts"))
	}
	return Met, fmt.Sprintf("%d %s pass on every host that reported (%s %s across %d %s).", ev.Checks, plural(ev.Checks, "check", "checks"),
		count(int64(ev.Pass)), plural(ev.Pass, "result", "results"), s.Hosts, plural(s.Hosts, "host", "hosts"))
}

func evalRetention(s *Snapshot, days int, archiveCounts bool) (Status, string) {
	r := s.Retention
	if r == nil {
		return Missing, "Data retention could not be read."
	}
	var st Status
	var d string
	switch {
	case r.KeepDays == 0:
		st, d = Met, "Event data is kept until it is deleted by hand."
	case r.KeepDays >= days:
		st, d = Met, fmt.Sprintf("Event data is kept %d days.", r.KeepDays)
	case archiveCounts && r.Archive:
		st, d = Met, fmt.Sprintf("Event data is searchable %d days, then archived before it is deleted. Keep the archive files for the rest of the year.", r.KeepDays)
	default:
		return Missing, fmt.Sprintf("Event data is kept only %d days.", r.KeepDays)
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
