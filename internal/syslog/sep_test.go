package syslog

import (
	"strings"
	"testing"
)

func TestSplitSEP(t *testing.T) {
	name, pairs := splitSEP("Virus found,IP Address: 192.0.2.27,Description: ,File path: C:\\a, b.exe,Risk name: X,File size (bytes): 68,Group Name: My Company\\Default Group")
	if name != "Virus found" {
		t.Errorf("name %q", name)
	}
	want := map[string]string{"IP Address": "192.0.2.27", "Description": "", "File path": `C:\a, b.exe`, "Risk name": "X", "File size (bytes)": "68", "Group Name": `My Company\Default Group`}
	if len(pairs) != len(want) {
		t.Errorf("pairs %v", pairs)
	}
	for _, p := range pairs {
		if want[p.Name] != p.Value {
			t.Errorf("%s = %q, want %q", p.Name, p.Value, want[p.Name])
		}
	}
	// SEPM quotes a whole pair, or a value, when it holds a comma.
	_, pairs = splitSEP(`x,Category: 2,"Event Description: a, b (0x1), c: d.",Event time: 2020-12-15,File path: "C:\a,b\c.xla",Risk name: R`)
	got := map[string]string{}
	for _, p := range pairs {
		got[p.Name] = p.Value
	}
	if got["Event Description"] != "a, b (0x1), c: d." || got["File path"] != `C:\a,b\c.xla` || got["Event time"] != "2020-12-15" {
		t.Errorf("quoted pairs %v", pairs)
	}
	// A value holding ",Something: " ends there; that is the format.
	_, pairs = splitSEP("Virus found,File path: C:\\x,Weird: y.exe,Risk name: Z")
	if len(pairs) != 3 || pairs[0].Value != `C:\x` || pairs[2].Value != "Z" {
		t.Errorf("pairs %v", pairs)
	}
	// Keys must look like keys.
	for _, s := range []string{",lower: x", ",X" + strings.Repeat("y", 40) + ": x", ",Odd-key: x", ",Key:x"} {
		if _, pairs := splitSEP("Virus found" + s); len(pairs) != 0 {
			t.Errorf("%q split into %v", s, pairs)
		}
	}
}

func TestSEPLimits(t *testing.T) {
	var b strings.Builder
	b.WriteString("Virus found")
	for range 200 {
		b.WriteString(",Occurrences: 1")
	}
	b.WriteString(",Risk name: Late")
	_, pairs := splitSEP(b.String())
	if len(pairs) != sepMaxSegments-1 {
		t.Errorf("%d pairs", len(pairs))
	}
	f, ok := parseSEP(b.String())
	if !ok || f["signature"] != "Unknown threat" {
		t.Errorf("signature %v", f["signature"])
	}
	// Only the first 16 KB are read.
	long := "Virus found,Description: " + strings.Repeat("x", 70<<10) + ",Risk name: Late"
	f, ok = parseSEP(long)
	if !ok || f["signature"] != "Unknown threat" {
		t.Errorf("70 KB: %v", f["signature"])
	}
	// Values are capped.
	f, _ = parseSEP("Virus found,Risk name: " + strings.Repeat("r", 10<<10))
	if s, _ := f["signature"].(string); len(s) != 4096 {
		t.Errorf("signature of %d bytes", len(s))
	}
}

func TestSEPEvents(t *testing.T) {
	for _, c := range []struct {
		line string
		want map[string]any
	}{
		{"<54>Oct 13 09:14:02 sepm-01 SymantecServer: Security risk found,Computer name: ws-1,Risk name: Adware.X,Actual action: Left alone,Category type: Adware",
			map[string]any{"_model": "Malware", "action": "allowed", "category": "adware", "dest": "ws-1"}},
		{"<54>Oct 13 09:14:02 sepm-01 SymantecServer: Potential risk found,Computer name: ws-1,Risk name: WS.Reputation.1,Actual action: Deleted",
			map[string]any{"_model": "Malware", "action": "deleted"}},
		{"<54>Oct 13 09:14:02 sepm-01 SymantecServer: Virus found,Computer name: ws-1,Risk name: X,Actual action: Clean failed : Quarantine failed",
			map[string]any{"_model": "Malware", "action": "failed"}},
		// The program name in the text, as some relays send it.
		{"<54>Oct 13 09:14:02 sepm-01 SymantecServer: SymantecServer: Virus found,Computer name: ws-1,Risk name: X",
			map[string]any{"_model": "Malware", "signature": "X"}},
		// Other SEP events keep the plain syslog mapping.
		{"<54>Oct 13 09:14:02 sepm-01 SymantecServer: Site: Site sepm-01,Server Name: sepm-01,Event Description: Policy has been edited",
			map[string]any{"_model": "Other", "type": nil, "app": "SymantecServer", "severity": "informational"}},
		// Older SEPM versions: the path has no key, and "User" is the user.
		{"<54>Oct 13 09:14:02 sepm-01 SymantecServer: Virus found,Computer name: ws-1,Risk name: X,Occurrences: 1,C:\\Temp\\a.exe,,Actual action: Quarantined,User: bob",
			map[string]any{"_model": "Malware", "file_path": `C:\Temp\a.exe`, "file_name": "a.exe", "user": "bob", "action": "quarantined"}},
		// A client's failed content update.
		{"<54>Oct 13 09:14:02 sepm-01 SymantecServer: ws-1,Category: 2,LiveUpdate Manager,Event Description: Virus and Spyware Definitions update failed to install.,Event time: 2026-10-13 09:14:02",
			map[string]any{"_model": "Malware", "type": "health", "action": "update_failed", "dest": "ws-1", "category": nil}},
		{"<54>Oct 13 09:14:02 sepm-01 SymantecServer: ws-1,Category: 2,LiveUpdate Manager,Event Description: A LiveUpdate session ran successfully.  No new updates were available.,Event time: 2026-10-13 09:14:02",
			map[string]any{"_model": "Other"}},
		// A BOM before the text.
		{"<54>1 2026-10-12T13:14:02Z sepm-01 SymantecServer - - - \ufeffVirus found,Computer name: ws-1,Risk name: Y",
			map[string]any{"_model": "Malware", "signature": "Y", "dest": "ws-1"}},
	} {
		d := doc(c.line)
		if d["_model"] == "Malware" {
			checkMalware(t, c.line, d)
			check(t, c.line, d, map[string]any{"vendor_product": "Symantec Endpoint Protection", "sourcetype": "symantec:sep", "host": "sepm-01"})
		}
		check(t, c.line, d, c.want)
	}
}
