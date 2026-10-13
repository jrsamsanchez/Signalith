package ingest

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
)

// malwareFieldNames are the names an antivirus parser may write: the
// common fields, the Malware fields and the raw message.
var malwareFieldNames = func() map[string]bool {
	m := map[string]bool{"message": true}
	for _, f := range datamodel.FieldsFor("Malware") {
		m[f.Name] = true
	}
	return m
}()

// checkMalwareEvent checks the invariants every antivirus event keeps,
// whatever the sender wrote. allowed names fields a path adds besides the
// Malware ones (the program of a ClamAV line that stayed Other).
func checkMalwareEvent(t *testing.T, ev Event, allowed ...string) {
	t.Helper()
	for k, v := range ev.Fields {
		if !malwareFieldNames[k] && !slices.Contains(allowed, k) {
			t.Fatalf("field %q is not a Malware field", k)
		}
		if s, ok := v.(string); ok && k != "message" {
			if !utf8.ValidString(s) || len(s) > MaxValueLen {
				t.Fatalf("%s: %d bytes, valid UTF-8 %v", k, len(s), utf8.ValidString(s))
			}
		}
	}
	if ev.Model != "Malware" {
		if ev.Fields["type"] != nil || ev.Fields["action"] != nil {
			t.Fatalf("%s event has type %v action %v", ev.Model, ev.Fields["type"], ev.Fields["action"])
		}
		return
	}
	typ, _ := ev.Fields["type"].(string)
	action, _ := ev.Fields["action"].(string)
	if !ValidMalwareAction(typ, action) {
		t.Fatalf("type %q action %q", typ, action)
	}
	if sig, _ := ev.Fields["signature"].(string); sig == "" {
		t.Fatal("no signature")
	}
	cat, hasCat := ev.Fields["category"].(string)
	if hasCat != (typ == MalwareThreat) {
		t.Fatalf("category %q on %s", cat, typ)
	}
	if hasCat && !strings.Contains(" "+strings.Join(MalwareCategories, " ")+" ", " "+cat+" ") {
		t.Fatalf("category %q", cat)
	}
	if sev, ok := ev.Fields["severity"].(string); ok && MalwareSeverity(sev) != sev {
		t.Fatalf("severity %q", sev)
	}
}

func FuzzDefenderMessage(f *testing.F) {
	for _, s := range []string{
		msg1116,
		msg1116 + " \tAction: Remove\r\n \tError description: The process cannot access the file.\r\n",
		msg1121,
		msg5007("", `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\ProgramData\SyncSvc = 0x0`),
		"Name: X\nPath: webfile:_C:\\a.exe|https://x/|pid:99999999999999999999,1\n",
		"Last AV signature age: 99999999999999999999\n",
		"datamodel: Risk\nsignalith_sample: x\ntype: health\n",
	} {
		for _, id := range []string{"1116", "1117", "1121", "5007", "1151"} {
			f.Add(id, s)
		}
	}
	f.Fuzz(func(t *testing.T, id, msg string) {
		ev := Normalize("win.events", defenderRecord(id, msg), now)
		if ev.Model != "Malware" && ev.Model != "Other" {
			t.Fatalf("model %s", ev.Model)
		}
		// The event ID is the sender's; Other events keep it as it came.
		if ev.Model == "Malware" {
			checkMalwareEvent(t, ev)
		}
	})
}

func FuzzClamAVLine(f *testing.F) {
	for _, c := range clamavRows {
		f.Add(c.program, clamPrefix+c.line)
	}
	f.Add("clamd", "/tmp/a: X(ffffffffffffffffffffffffffffffff:99999999999999999999999) FOUND")
	f.Add("freshclam", "daily.cld updated (version: ")
	f.Fuzz(func(t *testing.T, program, line string) {
		file := "/var/log/clamav/" + program + ".log"
		ev := Normalize("linux.clamav", map[string]any{"log": line, "file": file, "hostname": "db-01"}, now)
		checkMalwareEvent(t, ev, "app")
		ev = ParseProgram("db-01", "clamd", "1", line, "syslog")
		if ev.Model == "Malware" {
			checkMalwareEvent(t, ev)
		}
	})
}
