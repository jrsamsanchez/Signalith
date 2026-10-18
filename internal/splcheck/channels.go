package splcheck

import (
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode/utf16"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// Raw searches of Windows logs other than Sysmon's and the Security log
// whose events the parser reads by name: the Service Control Manager's
// service events in the System log, WMI's permanent event subscriptions,
// app packages deployed and NTLM authentications audited. Each event is
// a node of its own, in the Other data model, whose fields are the
// event's data by Splunk's names (as Windows names them), stored as the
// parser names them (ingest.WindowsEventNames). A rule over one finds
// only the events of its channel (sourcetype WinEventLog:<channel>).

// channelNode is the log a node's events are in, and their code. A node
// of lines is an Application log event, whose data Signalith keeps as
// its values one per line (event_data), not by name.
type channelNode struct {
	channel, provider, event string
	lines                    bool
}

// channelNodes are the nodes of those logs' events.
var channelNodes = map[string]channelNode{
	// A service started or stopped (param1 its name as shown, param2
	// its new state) and its start type changed.
	"ServiceStateChanged":     {ingest.SystemChannel, ingest.ServiceControlManager, "7036", false},
	"ServiceStartTypeChanged": {ingest.SystemChannel, ingest.ServiceControlManager, "7040", false},
	// A WMI event filter bound to a consumer: a permanent event
	// subscription.
	"WmiConsumerBinding": {ingest.WmiChannel, "", "5861", false},
	// An app package deployment started (with its flags, and the
	// program that asked for it) and a package file downloaded.
	"AppxDeploymentStarted": {ingest.AppxChannel, "", "603", false},
	"AppxDownloaded":        {ingest.AppxChannel, "", "854", false},
	// An NTLM authentication to a domain controller audited.
	"NtlmDcAudit": {ingest.NtlmChannel, "", "8004", false},
	// SQL Server's configuration option changed (the option, its old
	// value and its new one), and a startup procedure run.
	"SqlConfigChanged":    {ingest.ApplicationChannel, "MSSQLSERVER", "15457", true},
	"SqlStartupProcedure": {ingest.ApplicationChannel, "MSSQLSERVER", "17135", true},
}

// eventCodeName is the add-on's name of a Windows event's code.
const eventCodeName = "EventCode"

// channelSources are the macros of those logs, with the node of each
// event code they may name.
var channelSources = map[string]map[string]string{
	"wineventlog_system":               {"7036": "ServiceStateChanged", "7040": "ServiceStartTypeChanged"},
	"wmi":                              {"5861": "WmiConsumerBinding"},
	"wineventlog_appxdeploymentserver": {"603": "AppxDeploymentStarted", "854": "AppxDownloaded"},
	"ntlm_audit":                       {"8004": "NtlmDcAudit"},
	"wineventlog_application":          {"15457": "SqlConfigChanged", "17135": "SqlStartupProcedure"},
}

func init() {
	for node, c := range channelNodes {
		names, fields := ingest.WindowsEventNames(c.channel, c.provider, c.event)
		if len(names) == 0 && !c.lines {
			panic("splcheck: the parser reads no data of " + c.channel + " event " + c.event)
		}
		// The event's code, computer and message, as the add-on names
		// them.
		raw := map[string]string{eventCodeName: eventCode, "Computer": "host", "dvc": "host", "Message": "message"}
		for i, n := range names {
			raw[n] = fields[i]
		}
		RawFields[node] = raw
		NodeEvents[node] = []string{c.event}
		NodeModel[node] = "Other"
	}
	for source, codes := range channelSources {
		if rawNodes[source] == nil {
			rawNodes[source] = map[string]string{}
		}
		maps.Copy(rawNodes[source], codes)
	}
}

// IsChannelNode reports whether a node is the events of one of those
// logs.
func IsChannelNode(node string) bool { _, ok := channelNodes[node]; return ok }

// ChannelSourcetype is the sourcetype Signalith stores a channel node's
// events under ("" for another node).
func ChannelSourcetype(node string) string {
	c, ok := channelNodes[node]
	if !ok {
		return ""
	}
	return "WinEventLog:" + c.channel
}

// channelRecord makes the event of a channel node: its data by name, with
// the values the field-level event gives (none for the rest).
func channelRecord(node string, ev map[string]string) sigmacheck.Case {
	c := channelNodes[node]
	names, fields := ingest.WindowsEventNames(c.channel, c.provider, c.event)
	s := map[string]string{}
	if c.lines {
		// Each line of the event's data a value, in order.
		for i, v := range strings.Split(ev["event_data"], "\n") {
			if v != "" && i < 9 {
				s[fmt.Sprintf("Data%d", i+1)] = v
			}
		}
	}
	for i, n := range names {
		if v := ev[fields[i]]; v != "" {
			s[n] = v
		}
	}
	if c.provider != "" {
		s["Provider_Name"] = c.provider
	}
	if c.channel == ingest.SystemChannel && (c.event == "7036" || c.event == "7040") {
		// The service's key name, as the Service Control Manager's
		// binary data holds it: UTF-16LE, ending in a null.
		s["Binary"] = utf16Hex(cmp.Or(ev["system_binary"], "ExampleSvc"))
	}
	return sigmacheck.Case{Channel: c.channel, EventID: c.event, Data: s}
}

// inChannel reports whether a case is an event of a channel node's log
// (true for other nodes).
func inChannel(node string, c sigmacheck.Case) bool {
	n, ok := channelNodes[node]
	return !ok || strings.EqualFold(n.channel, c.Channel) && slices.Contains(NodeEvents[node], c.EventID)
}

// utf16Hex is text as UTF-16LE hex digits, in upper case, with a null at
// the end.
func utf16Hex(s string) string {
	var b strings.Builder
	for _, u := range utf16.Encode([]rune(s + "\x00")) {
		fmt.Fprintf(&b, "%02X%02X", u&0xff, u>>8)
	}
	return b.String()
}

// bareMacroRe is a macro with no arguments.
var bareMacroRe = regexp.MustCompile("`([\\w-]+)`")

// expandStageMacros writes out each macro with no arguments whose
// definition is several stages (normalized_service_binary_field), as
// Splunk expands macros before it reads a search.
func expandStageMacros(s string, macros map[string]*Macro) string {
	return bareMacroRe.ReplaceAllStringFunc(s, func(m string) string {
		mac := macros[strings.Trim(m, "`")]
		if mac == nil || len(mac.Arguments) > 0 || len(pipes(strings.TrimSpace(mac.Definition))) < 2 {
			return m
		}
		return strings.TrimSpace(mac.Definition)
	})
}

// dataRexRe is a rex of an Application event's first data values from
// its XML (<Data>(?<config_name>[^<]+)</Data><Data>...), and dataGroupRe
// one of its groups.
var (
	dataRexRe   = regexp.MustCompile(`^rex\s+field\s*=\s*"?EventData_Xml"?\s+"((?:<Data>\(\?<\w+>\[\^<\]\+\)</Data>)+)"$`)
	dataGroupRe = regexp.MustCompile(`<Data>\(\?<(\w+)>`)
)

// binarySpathRe is a later stage that reads a System event's binary data
// from its XML (spath input=EventData_Xml path=Binary output=...).
var binarySpathRe = regexp.MustCompile(`(?i)^spath\s+input\s*=\s*EventData_Xml\s+path\s*=\s*"?Binary"?\s+output\s*=\s*([A-Za-z_]\w*)$`)

// channelStage is a later stage of a raw search of a channel node as
// Signalith runs it, when it reads the event's XML: a System event's
// binary data is its Binary element, the hex digits Windows writes in
// upper case, which Signalith keeps (system_binary) in lower case.
func channelStage(node, s string) (string, bool) {
	c, ok := channelNodes[node]
	if !ok {
		return "", false
	}
	if m := binarySpathRe.FindStringSubmatch(s); m != nil && c.channel == ingest.SystemChannel {
		return "eval " + m[1] + "=upper(system_binary)", true
	}
	if m := dataRexRe.FindStringSubmatch(s); m != nil && c.lines {
		// The event's first values, each a <Data> element of its XML:
		// its first lines, which hold the values in order. (Signalith
		// leaves out empty values, which these rules' events do not
		// have, and the XML's escapes.)
		var groups []string
		for _, g := range dataGroupRe.FindAllStringSubmatch(m[1], -1) {
			groups = append(groups, `(?<`+g[1]+`>[^\n]+)`)
		}
		return `rex field=event_data "^` + strings.Join(groups, `\n`) + `"`, true
	}
	// A value of the event's user data, read from its XML: the value
	// Signalith keeps by its name.
	if !strings.HasPrefix(strings.ToLower(s), "spath ") {
		return "", false
	}
	args := map[string]string{}
	rest := strings.TrimSpace(s[len("spath "):])
	for _, m := range spathArgRe.FindAllStringSubmatch(rest, -1) {
		args[strings.ToLower(m[1])] = strings.Trim(m[2], `"`)
	}
	if strings.TrimSpace(spathArgRe.ReplaceAllString(rest, "")) != "" || len(args) != 3 || args["input"] != "_raw" {
		return "", false
	}
	parts := strings.Split(args["path"], ".")
	if len(parts) != 4 || parts[0] != "Event" || parts[1] != "UserData" || !plainFieldRe.MatchString(args["output"]) {
		return "", false
	}
	f, ok := RawFields[node][parts[3]]
	if !ok || f == eventCode || f == "host" {
		return "", false
	}
	return "eval " + args["output"] + "=" + f, true
}

// pcreEndRe is \s* then \Z at the end of a regular expression, which Go
// reads only as \z: the end, where PCRE's \Z is also before a newline at
// the end, which \s* takes anyway.
var pcreEndRe = regexp.MustCompile(`\\s\*\\Z`)

// endAnchors writes \s*\Z in a rex stage's pattern as \s*\z, which
// matches the same text.
func endAnchors(s string) string {
	if !strings.HasPrefix(strings.ToLower(s), "rex ") {
		return s
	}
	return pcreEndRe.ReplaceAllString(s, `\s*\z`)
}
