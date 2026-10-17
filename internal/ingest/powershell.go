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
// below read: a real one has about twenty, so a value made of many
// short lines costs no more than reading its first ones.
const maxContextLines = 64

// contextValues reads up to maxContextLines lines of "Name sep value"
// (sep " = " for 4103's ContextInfo, "=" for the classic events), the
// first value of each name. Names are as Windows writes them in English;
// another language's are kept but match none the parsers look for.
func contextValues(s, sep string, into map[string]string) {
	for i := 0; i < maxContextLines && s != ""; i++ {
		var line string
		line, s, _ = strings.Cut(s, "\n")
		k, v, ok := strings.Cut(strings.TrimSpace(line), sep)
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if _, seen := into[k]; !seen && k != "" {
			into[k] = v
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
// index.
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
	kv := map[string]string{}
	contextValues(ctx, " = ", kv)
	if v := kv["User"]; v != "" {
		f["user"] = v
	}
	if v := kv["Host Application"]; v != "" {
		f["process"] = v
	}
	if v := kv["Script Name"]; v != "" {
		f["script_path"] = v
	}
}

// parseClassicPowerShell reads an event of the Windows PowerShell log:
// its provider, its data values one per line as event_data (which rules
// search for words inside, as for the Application log), and from them
// the host program's command line, the script and, for a pipeline, the
// account. The event stays in Other, found by its channel and ID.
func parseClassicPowerShell(eventID, provider string, in []string, ev *Event) {
	parseWindowsEventData(provider, in, ev)
	f := ev.Fields
	f["vendor_product"] = "Microsoft PowerShell"
	if s, ok := classicPowerShellEvents[eventID]; ok {
		f["signature"] = s
	}
	kv := map[string]string{}
	for _, v := range in {
		if strings.Contains(v, "=") {
			contextValues(v, "=", kv)
		}
	}
	if v := kv["HostApplication"]; v != "" {
		f["process"] = v
	}
	if v := kv["ScriptName"]; v != "" {
		f["script_path"] = v
	}
	if v := kv["UserId"]; v != "" {
		f["user"] = v
	}
}
