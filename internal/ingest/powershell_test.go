package ingest

import (
	"encoding/json"
	"strings"
	"testing"
)

// moduleLogContext is a pipeline's context as Windows (English) writes it
// in a 4103 event.
const moduleLogContext = "        Severity = Informational\r\n        Host Name = ConsoleHost\r\n        Host Version = 5.1.19041.4648\r\n" +
	"        Host ID = 9e3b7c3a-0d3a-4b8e-9c71-2a5d8e4f9b10\r\n" +
	"        Host Application = C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -nop -c iwr http://x\r\n" +
	"        Engine Version = 5.1.19041.4648\r\n        Runspace ID = 1d2c\r\n        Pipeline ID = 5\r\n" +
	"        Command Name = Invoke-WebRequest\r\n        Command Type = Cmdlet\r\n        Script Name = C:\\temp\\get.ps1\r\n" +
	"        Command Path = \r\n        Sequence Number = 16\r\n        User = CORP\\bob\r\n        Connected User = \r\n" +
	"        Shell ID = Microsoft.PowerShell\r\n"

const moduleLogPayload = "CommandInvocation(Invoke-WebRequest): \"Invoke-WebRequest\"\r\n" +
	"ParameterBinding(Invoke-WebRequest): name=\"Uri\"; value=\"http://x\""

func TestModuleLogEvent(t *testing.T) {
	ev := Normalize("win.events", map[string]any{
		"Channel": PowerShellChannel, "Computer": "WS1", "EventID": "4103", "ProviderName": "Microsoft-Windows-PowerShell",
		"StringInserts": []any{moduleLogContext, "", moduleLogPayload},
	}, now)
	f := ev.Fields
	if ev.Model != "Script" || f["signature_id"] != "4103" || f["sourcetype"] != "WinEventLog:"+PowerShellChannel {
		t.Fatalf("%s %v", ev.Model, f)
	}
	for k, want := range map[string]string{
		"script_block_text": moduleLogPayload,
		"event_data":        moduleLogContext,
		"user":              `CORP\bob`,
		"process":           `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -c iwr http://x`,
		"script_path":       `C:\temp\get.ps1`,
		"vendor_product":    "Microsoft PowerShell",
	} {
		if f[k] != want {
			t.Errorf("%s = %q, want %q", k, f[k], want)
		}
	}
}

// The OpenTelemetry Collector sends a 4103 event's data by name; the
// parser reads it as Fluent Bit's.
func TestModuleLogEventFromOTLP(t *testing.T) {
	ev := otlpWindows(map[string]any{
		"channel": PowerShellChannel, "computer": "WS1", "event_id": map[string]any{"id": "4103"},
		"provider":   map[string]any{"name": "Microsoft-Windows-PowerShell"},
		"event_data": map[string]any{"Payload": moduleLogPayload, "UserData": "", "ContextInfo": moduleLogContext},
	})
	if ev.Model != "Script" || ev.Fields["script_block_text"] != moduleLogPayload || ev.Fields["user"] != `CORP\bob` {
		t.Fatalf("%s %v", ev.Model, ev.Fields)
	}
}

// A localized context keeps its text, and gives no account or command
// line it cannot name.
func TestModuleLogEventLocalized(t *testing.T) {
	ctx := "Gravité = Informational\n        Application hôte = powershell.exe\n        Utilisateur = PC\\frack113"
	ev := Normalize("win.events", map[string]any{
		"Channel": PowerShellChannel, "Computer": "WS1", "EventID": "4103", "StringInserts": []any{ctx, "", "x"},
	}, now)
	if ev.Fields["event_data"] != ctx || ev.Fields["user"] != nil || ev.Fields["process"] != nil {
		t.Fatalf("%v", ev.Fields)
	}
}

func TestClassicPowerShellEvents(t *testing.T) {
	start := "\tNewEngineState=Available\r\n\tPreviousEngineState=None\r\n\r\n\tSequenceNumber=13\r\n\r\n\tHostName=ConsoleHost\r\n" +
		"\tHostVersion=2.0\r\n\tHostId=4d6019f4-a2f2-4ed9-9259-962587b8e7a7\r\n\tHostApplication=powershell.exe -version 2 -c whoami\r\n" +
		"\tEngineVersion=2.0\r\n\tRunspaceId=6e92\r\n\tPipelineId=\r\n\tCommandName=\r\n\tCommandType=\r\n\tScriptName=\r\n" +
		"\tCommandPath=\r\n\tCommandLine="
	ev := Normalize("win.events", map[string]any{
		"Channel": WindowsPowerShellChannel, "Computer": "WS1", "EventID": "400", "ProviderName": "PowerShell",
		"StringInserts": []any{"Available", "None", start},
	}, now)
	f := ev.Fields
	if ev.Model != "Other" || f["sourcetype"] != "WinEventLog:Windows PowerShell" || f["signature"] != "PowerShell engine started" ||
		f["provider"] != "PowerShell" || f["process"] != "powershell.exe -version 2 -c whoami" || f["script_path"] != nil {
		t.Fatalf("%s %v", ev.Model, f)
	}
	if want := "Available\nNone\n" + strings.TrimSpace(start); f["event_data"] != want {
		t.Errorf("event_data = %q", f["event_data"])
	}

	pipeline := "\tDetailSequence=1\r\n\tDetailTotal=1\r\n\r\n\tSequenceNumber=21\r\n\r\n\tUserId=CORP\\bob\r\n\tHostName=ConsoleHost\r\n" +
		"\tHostApplication=powershell.exe\r\n\tScriptName=C:\\temp\\a.ps1\r\n\tCommandLine=Get-Process"
	ev = Normalize("win.events", map[string]any{
		"Channel": WindowsPowerShellChannel, "Computer": "WS1", "EventID": "800",
		"StringInserts": []any{"Get-Process", pipeline, "CommandInvocation(Get-Process): \"Get-Process\""},
	}, now)
	if f := ev.Fields; f["user"] != `CORP\bob` || f["script_path"] != `C:\temp\a.ps1` || f["process"] != "powershell.exe" {
		t.Fatalf("%v", f)
	}
}

// The OpenTelemetry Collector sends a Windows PowerShell event's unnamed
// data as a list; the parser keeps it in order.
func TestClassicPowerShellEventFromOTLP(t *testing.T) {
	var data []any
	for _, v := range []string{"Available", "None", "\tHostApplication=pwsh -c 1"} {
		data = append(data, map[string]any{"": v})
	}
	ev := otlpWindows(map[string]any{
		"channel": WindowsPowerShellChannel, "computer": "WS1", "event_id": map[string]any{"id": "400"},
		"event_data": map[string]any{"data": data},
	})
	if ev.Fields["event_data"] != "Available\nNone\nHostApplication=pwsh -c 1" || ev.Fields["process"] != "pwsh -c 1" {
		b, _ := json.Marshal(ev.Fields)
		t.Fatalf("%s", b)
	}
}
