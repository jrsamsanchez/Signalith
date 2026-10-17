package ingest

import "strings"

// WindowsPowerShellChannel is Windows PowerShell's classic log, where
// every PowerShell engine logs starting (400) and stopping (403), its
// providers starting (600) and, with module logging on, the pipelines it
// runs (800). Each event's data are text values, the last one lines of
// Name=value (HostApplication=powershell.exe -nop ...).
const WindowsPowerShellChannel = "Windows PowerShell"

// moduleLogSchema is the order of PowerShell's pipeline execution event
// (Microsoft-Windows-PowerShell/Operational 4103), which module logging
// writes for each command a pipeline runs: lines of "Name = value" about
// the host and the command (ContextInfo), and the command and the values
// bound to its parameters (Payload).
var moduleLogSchema = []string{"ContextInfo", "UserData", "Payload"}

// classicPowerShellEvents are the names of the Windows PowerShell log's
// events.
var classicPowerShellEvents = map[string]string{
	"400": "PowerShell engine started",
	"403": "PowerShell engine stopped",
	"600": "PowerShell provider started",
	"800": "PowerShell pipeline executed",
}

// maxContextLines is how many lines of an event's context the parsers
// below read from each end: a real one has about twenty, so a value made
// of many short lines costs no more than reading its first and last ones.
const maxContextLines = 64

// contextLine is a context line's name and value, ok false for a line
// that is not "Name sep value". Names are as Windows writes them in
// English; another language's are kept but match none the parsers look
// for.
func contextLine(line, sep string) (k, v string, ok bool) {
	k, v, ok = strings.Cut(strings.TrimSpace(line), sep)
	return strings.TrimSpace(k), strings.TrimSpace(v), ok && strings.TrimSpace(k) != ""
}

// contextLines is up to maxContextLines lines of s, from its start or,
// with last, from its end, nearest first.
func contextLines(s string, last bool) []string {
	lines := strings.SplitN(s, "\n", maxContextLines+1)
	if !last {
		return lines[:min(len(lines), maxContextLines)]
	}
	lines = strings.Split(s, "\n")
	var out []string
	for i := len(lines) - 1; i >= 0 && len(out) < maxContextLines; i-- {
		out = append(out, lines[i])
	}
	return out
}

// contextValues reads the names of a context up to the one whose value is
// free text the logged program or script wrote (stop), the first value
// of each; with last, it reads from the context's end back to stop. A
// free-text value can hold lines that look like names, so a name read
// only on the side of stop where it is written, nearest stop's far end,
// is the one Windows wrote: what a value holds can add lines between the
// two, not replace these.
func contextValues(s, sep, stop string, last bool, into map[string]string) {
	for _, line := range contextLines(s, last) {
		k, v, ok := contextLine(line, sep)
		if !ok {
			continue
		}
		if _, seen := into[k]; !seen {
			into[k] = v
		}
		if k == stop {
			return
		}
	}
}

// parseModuleLog reads a pipeline execution event (4103) into Script:
// the payload (the command and its parameters' values) as the text that
// ran, script_block_text, and the context as the event's data,
// event_data, both of which rules search for words inside; and from the
// context the account, the host program's command line and the script
// the command came from. Both are fields a script block or an
// Application event already has, so the events add no field to the
// index. The host program's command line (Host Application), which the
// one who started it wrote, comes before the script and the account, so
// they are read from the context's end.
func parseModuleLog(in []string, ev *Event) {
	ev.Model = "Script"
	f := ev.Fields
	f["vendor_product"] = "Microsoft PowerShell"
	f["signature"] = "Pipeline executed"
	ctx := at(in, 0)
	if ctx != "" {
		f["event_data"] = ctx
	}
	f["script_block_text"] = at(in, 2)
	head, tail := map[string]string{}, map[string]string{}
	contextValues(ctx, " = ", "Host Application", false, head)
	contextValues(ctx, " = ", "Host Application", true, tail)
	if v := tail["User"]; v != "" {
		f["user"] = v
	}
	if v := head["Host Application"]; v != "" {
		f["process"] = v
	}
	if v := tail["Script Name"]; v != "" {
		f["script_path"] = v
	}
}

// classicContext is the data value of a Windows PowerShell log event that
// is its context: the third of an engine or provider event, after the
// new and the previous state (or the provider's name and state); the
// second of a pipeline's, after its command line and before its details.
func classicContext(eventID string, in []string) string {
	if eventID == "800" {
		return at(in, 1)
	}
	return at(in, 2)
}

// parseClassicPowerShell reads an event of the Windows PowerShell log:
// its provider, its data values one per line as event_data (which rules
// search for words inside, as for the Application log), and from its
// context the host program's command line, the script and, for a
// pipeline, the account. The event stays in Other, found by its channel
// and ID. The context's free text, the host program's command line
// (HostApplication) and the pipeline's (CommandLine, last), is written by
// the logged program: the account comes before both and is read from the
// start; the script comes between them, where neither end can place it,
// so it is read only when the context names one script.
func parseClassicPowerShell(eventID, provider string, in []string, ev *Event) {
	parseWindowsEventData(provider, in, ev)
	f := ev.Fields
	f["vendor_product"] = "Microsoft PowerShell"
	if s, ok := classicPowerShellEvents[eventID]; ok {
		f["signature"] = s
	}
	ctx := classicContext(eventID, in)
	head := map[string]string{}
	contextValues(ctx, "=", "HostApplication", false, head)
	if v := head["HostApplication"]; v != "" {
		f["process"] = v
	}
	if v := head["UserId"]; v != "" {
		f["user"] = v
	}
	scripts := 0
	var script string
	for _, line := range strings.Split(ctx, "\n") {
		if k, v, ok := contextLine(line, "="); ok && k == "ScriptName" {
			scripts++
			script = v
		}
	}
	if scripts == 1 && script != "" {
		f["script_path"] = script
	}
}
