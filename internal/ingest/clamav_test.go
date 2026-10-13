package ingest

import (
	"strings"
	"testing"
)

const clamPrefix = "Tue Oct 13 13:12:40 2026 -> "

var clamavRows = []struct {
	program, line string
	model         string
	want          map[string]any
}{
	{"clamd", "/srv/www/up/x.php: Php.Webshell.Generic-6 FOUND", "Malware",
		map[string]any{"type": "threat", "action": "detected", "file_path": "/srv/www/up/x.php", "file_name": "x.php", "signature": "Php.Webshell.Generic-6", "category": "backdoor", "severity": nil, "vendor_action": nil}},
	{"clamd", "/tmp/a: Win.Test.EICAR_HDB-1(44d88612fea8a8f36de82e1278abb02f:68) FOUND", "Malware",
		map[string]any{"type": "threat", "action": "detected", "file_path": "/tmp/a", "signature": "Win.Test.EICAR_HDB-1", "category": "test",
			"file_hash": "44d88612fea8a8f36de82e1278abb02f", "file_md5": "44d88612fea8a8f36de82e1278abb02f", "file_size": int64(68)}},
	{"clamd", "/tmp/my: odd: name: Unix.Trojan.Sampleminer-1 FOUND", "Malware",
		map[string]any{"file_path": "/tmp/my: odd: name", "signature": "Unix.Trojan.Sampleminer-1", "category": "trojan"}},
	{"clamonacc", "/tmp/.x/kworkerd: moved to '/var/lib/clamav/quarantine/kworkerd'", "Malware",
		map[string]any{"type": "threat", "action": "quarantined", "vendor_action": "moved", "file_path": "/tmp/.x/kworkerd", "signature": "Unknown threat", "category": "other"}},
	{"clamd", "/tmp/a: Removed.", "Malware",
		map[string]any{"type": "threat", "action": "deleted", "file_path": "/tmp/a", "signature": "Unknown threat", "vendor_action": "Removed"}},
	{"clamd", "/tmp/a: Can't move file '/tmp/a'", "Malware",
		map[string]any{"type": "threat", "action": "failed", "file_path": "/tmp/a", "reason": "Can't move file '/tmp/a'", "vendor_action": "Can't move"}},
	{"clamd", "/tmp/a: Can't unlink file", "Malware", map[string]any{"action": "failed", "reason": "Can't unlink file", "vendor_action": "Can't unlink"}},
	{"clamd", "/tmp/a: Can't remove file", "Malware", map[string]any{"action": "failed"}},
	{"freshclam", "ERROR: Database update process failed: Connection failed (2)", "Malware",
		map[string]any{"type": "health", "action": "update_failed", "signature": "Definitions update failed", "reason": "Connection failed (2)", "category": nil}},
	{"freshclam", "daily.cld updated (version: 27421, sigs: 2070130, f-level: 90, builder: raynman)", "Malware",
		map[string]any{"type": "health", "action": "updated", "signature": "Antivirus definitions updated", "signature_version": "27421"}},
	{"freshclam", "daily.cvd database is up-to-date (version: 27421, sigs: 2070130, f-level: 90, builder: raynman)", "Malware",
		map[string]any{"type": "health", "action": "updated", "signature_version": "27421"}},
	{"freshclam", "main.cvd database is up-to-date (version: 62, sigs: 6647427, f-level: 90, builder: sigmgr)", "Other", nil},
	{"clamd", "LibClamAV Warning: *** The virus database is older than 7 days! ***", "Malware",
		map[string]any{"type": "health", "action": "outdated", "signature": "Antivirus definitions out of date"}},
	{"clamd", "SelfCheck: Database status OK.", "Other", map[string]any{"type": nil, "action": nil}},
	{"clamd", "ERROR: Can't open file or directory", "Other", nil},
	{"clamd", "FOUND", "Other", nil},
}

func checkClam(t *testing.T, how string, ev Event, model string, want map[string]any) {
	t.Helper()
	if ev.Model != model {
		t.Errorf("%s: model %s, want %s", how, ev.Model, model)
		return
	}
	d := ev.Document()
	if model == "Malware" {
		if d["vendor_product"] != "ClamAV" || d["dest"] != "db-01" || d["app"] != nil || d["process_id"] != nil {
			t.Errorf("%s: vendor_product %v dest %v app %v process_id %v", how, d["vendor_product"], d["dest"], d["app"], d["process_id"])
		}
		typ, _ := d["type"].(string)
		action, _ := d["action"].(string)
		if !ValidMalwareAction(typ, action) {
			t.Errorf("%s: type %q action %q", how, typ, action)
		}
	}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("%s: %s = %#v, want %#v", how, k, d[k], v)
		}
	}
}

func TestClamAV(t *testing.T) {
	for _, c := range clamavRows {
		// The agent's file tail.
		file := "/var/log/clamav/clamav.log"
		if c.program == "freshclam" {
			file = "/var/log/clamav/freshclam.log"
		} else if c.program == "clamonacc" {
			file = "/var/log/clamav/clamonacc.log"
		}
		ev := Normalize("linux.clamav", map[string]any{"log": clamPrefix + c.line, "file": file, "hostname": "db-01", "date": float64(now.Unix())}, now)
		checkClam(t, "file "+c.line, ev, c.model, c.want)
		d := ev.Document()
		if d["sourcetype"] != "linux:clamav" || d["host"] != "db-01" || !ev.Time.Equal(now) || d["message"] != clamPrefix+c.line {
			t.Errorf("file %s: sourcetype %v host %v time %v message %v", c.line, d["sourcetype"], d["host"], ev.Time, d["message"])
		}
		if c.model == "Other" && d["app"] != c.program {
			t.Errorf("file %s: app %v", c.line, d["app"])
		}

		// The journal.
		ev = Normalize("linux.journal", map[string]any{"SYSLOG_IDENTIFIER": c.program, "_HOSTNAME": "db-01", "_PID": "812", "MESSAGE": c.line}, now)
		checkClam(t, "journal "+c.line, ev, c.model, c.want)
		if d := ev.Document(); d["sourcetype"] != "linux:journal" {
			t.Errorf("journal sourcetype %v", d["sourcetype"])
		}

		// Syslog, as the receiver hands it over.
		ev = ParseProgram("db-01", c.program, "812", c.line, "syslog")
		checkClam(t, "syslog "+c.line, ev, c.model, c.want)
	}
	// clamscan and clamdscan through syslog too.
	for _, p := range []string{"clamscan", "clamdscan"} {
		ev := ParseProgram("db-01", p, "", "/tmp/a: Unix.Trojan.X-1 FOUND", "syslog")
		checkClam(t, p, ev, "Malware", map[string]any{"signature": "Unix.Trojan.X-1"})
	}
	// Other programs keep their old meaning.
	if ev := ParseProgram("db-01", "cron", "", "/tmp/a: Unix.Trojan.X-1 FOUND", "syslog"); ev.Model != "Other" {
		t.Errorf("cron line is %s", ev.Model)
	}
}

func TestClamAVPrefixes(t *testing.T) {
	for _, line := range []string{
		clamPrefix + "ScanOnAccess: /home/a/x.exe: Win.Trojan.Agent-1 FOUND",
		"ClamInotif: /home/a/x.exe: Win.Trojan.Agent-1 FOUND",
		"  /home/a/x.exe: Win.Trojan.Agent-1 FOUND  ",
	} {
		ev := Normalize("linux.clamav", map[string]any{"log": line, "file": "/var/log/clamav/clamonacc.log", "hostname": "db-01"}, now)
		checkClam(t, line, ev, "Malware", map[string]any{"file_path": "/home/a/x.exe", "signature": "Win.Trojan.Agent-1"})
	}
	// A freshclam line in the file tail is told apart by the file name.
	ev := Normalize("linux.clamav", map[string]any{"log": "ERROR: Update failed for database: daily", "file": "/var/log/clamav/freshclam.log", "hostname": "db-01"}, now)
	checkClam(t, "freshclam error", ev, "Malware", map[string]any{"action": "update_failed"})
	ev = Normalize("linux.clamav", map[string]any{"log": "ERROR: Update failed for database: daily", "file": "/var/log/clamav/clamav.log", "hostname": "db-01"}, now)
	checkClam(t, "clamd error", ev, "Other", nil)
}

func TestClamAVLongLines(t *testing.T) {
	long := "/tmp/" + strings.Repeat("a", 9000) + ": Unix.Trojan.X-1 FOUND"
	ev := Normalize("linux.clamav", map[string]any{"log": long, "file": "clamav.log", "hostname": strings.Repeat("h", 300)}, now)
	if ev.Model != "Other" {
		t.Errorf("a line cut at 8 KB still matched: %s", ev.Model)
	}
	if h := ev.Fields["host"].(string); len(h) != 255 {
		t.Errorf("host of %d bytes", len(h))
	}
	long = "/tmp/a: " + strings.Repeat("S", 7000) + " FOUND"
	ev = Normalize("linux.clamav", map[string]any{"log": long, "file": "clamav.log", "hostname": "db-01"}, now)
	if s, _ := ev.Fields["signature"].(string); ev.Model != "Malware" || len(s) != MaxValueLen {
		t.Errorf("model %s signature of %d bytes", ev.Model, len(s))
	}
	// A hash suffix that is not a hash stays part of the name.
	ev = ParseProgram("db-01", "clamd", "", "/tmp/a: Odd.Name(not:hex) FOUND", "syslog")
	if ev.Fields["signature"] != "Odd.Name(not:hex)" || ev.Fields["file_hash"] != nil {
		t.Errorf("signature %v hash %v", ev.Fields["signature"], ev.Fields["file_hash"])
	}
}
