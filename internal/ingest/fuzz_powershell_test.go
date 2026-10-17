package ingest

import (
	"strings"
	"testing"
)

// FuzzPowerShellEvents parses pipeline (4103) and Windows PowerShell log
// events made of arbitrary data values, which come from any host that
// holds an agent token: it never panics, keeps the values as they came,
// and takes the account, command line and script only from them.
func FuzzPowerShellEvents(f *testing.F) {
	f.Add("4103", "        Host Application = powershell.exe -nop\r\n        Script Name = C:\\s.ps1\r\n        User = CORP\\bob", "",
		"CommandInvocation(Get-Process): \"Get-Process\"")
	f.Add("4103", " = \n=\n User =  \n Host Application = a = b", "x", "")
	f.Add("400", "Available", "None", "\tNewEngineState=Available\r\n\tHostApplication=powershell -c $a=1\r\n\tScriptName=\r\n")
	f.Add("800", "Get-Process", "\tUserId=CORP\\bob\n\tHostApplication=pwsh\n\tScriptName=C:\\x.ps1", strings.Repeat("a=b\n", 100))
	f.Fuzz(func(t *testing.T, id, a, b, c string) {
		in := []string{a, b, c}
		for _, channel := range []string{PowerShellChannel, WindowsPowerShellChannel} {
			rec := map[string]any{"Channel": channel, "Computer": "WS1", "EventID": id, "StringInserts": []any{a, b, c}}
			ev := Normalize("win.events", rec, now)
			fields := ev.Fields
			if channel == PowerShellChannel && id == "4103" {
				if ev.Model != "Script" || fields["script_block_text"] != c || (a != "" && fields["event_data"] != a) {
					t.Fatalf("4103 %q: %s %v", in, ev.Model, fields)
				}
			}
			if channel == WindowsPowerShellChannel && ev.Model != "Other" {
				t.Fatalf("Windows PowerShell %q: %s", in, ev.Model)
			}
			if channel == PowerShellChannel && id != "4103" {
				// Not an event these parsers read (a script block, 4104).
				continue
			}
			for _, k := range []string{"user", "process", "script_path"} {
				v, ok := fields[k].(string)
				if !ok {
					continue
				}
				if v == "" || strings.Contains(v, "\n") || !strings.Contains(a+"\n"+b+"\n"+c, v) {
					t.Fatalf("%s %q not from the data %q", k, v, in)
				}
			}
		}
	})
}
