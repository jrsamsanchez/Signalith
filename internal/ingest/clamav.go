package ingest

import (
	"strings"
)

// ClamAV logs through clamd (on-demand and clamdscan scans), clamonacc
// (on-access scanning) and freshclam (definition updates), to files under
// /var/log/clamav, to the system journal, or to syslog. All three reach the
// same line parser: threats found, moved, removed or not, definition
// updates, and definitions out of date. Everything else stays Other.

// ClamAVProduct is the vendor_product of ClamAV events.
const ClamAVProduct = "ClamAV"

// clamavMaxLine is how much of a line is read.
const clamavMaxLine = 8 << 10

// parseClamAVRecord reads a record of the Linux agent's ClamAV log tail:
// {log, file, hostname, date}.
func parseClamAVRecord(r map[string]any) Event {
	program := "clamd"
	base := strings.ToLower(baseName(str(r, "file")))
	switch {
	case strings.HasPrefix(base, "freshclam"):
		program = "freshclam"
	case strings.HasPrefix(base, "clamonacc"):
		program = "clamonacc"
	}
	host := truncateUTF8(CapValue(str(r, "hostname")), maxHostLen)
	f := map[string]any{
		"host":           host,
		"dest":           host,
		"sourcetype":     "linux:clamav",
		"vendor_product": ClamAVProduct,
		"app":            program,
	}
	line := str(r, "log")
	ev := Event{Model: "Other", Fields: f}
	if parseClamAVLine(program, line, f) {
		ev.Model = MalwareModel
		delete(f, "app")
	}
	f["message"] = line
	return ev
}

// parseClamAVLine maps one ClamAV log line onto the Malware data model and
// reports whether it was a Malware event. f already holds host and dest.
func parseClamAVLine(program, line string, f map[string]any) bool {
	line = truncateUTF8(line, clamavMaxLine)
	// "Tue Oct 13 13:12:40 2026 -> " is the local time the log file adds.
	if len(line) >= 28 && line[24:28] == " -> " {
		line = line[28:]
	}
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "ScanOnAccess: ")
	line = strings.TrimPrefix(line, "ClamInotif: ")

	threat := func(action, sig string) bool {
		f["vendor_product"] = ClamAVProduct
		f["type"] = MalwareThreat
		f["action"] = action
		sig = CapValue(sig)
		if sig == "" {
			sig = UnknownThreat
		}
		f["signature"] = sig
		if sig == UnknownThreat {
			f["category"] = "other"
		} else {
			f["category"] = MalwareCategory(sig, "")
		}
		return true
	}
	health := func(action, sig string) bool {
		f["vendor_product"] = ClamAVProduct
		f["type"] = MalwareHealth
		f["action"] = action
		f["signature"] = sig
		return true
	}

	switch {
	case strings.HasSuffix(line, " FOUND"):
		body := strings.TrimSuffix(line, " FOUND")
		i := strings.LastIndex(body, ": ")
		if i < 0 {
			return false
		}
		path, sig := body[:i], strings.TrimSpace(body[i+2:])
		// "Win.Test.EICAR_HDB-1(44d88612fea8a8f36de82e1278abb02f:68)":
		// hash-based signatures carry the file's MD5 and size.
		if strings.HasSuffix(sig, ")") {
			if j := strings.LastIndexByte(sig, '('); j > 0 {
				hash, size, ok := strings.Cut(sig[j+1:len(sig)-1], ":")
				if ok && isHex(hash) && allDigitsStr(size) && len(size) <= 18 {
					SetFileHash(f, hash)
					if n := atoi(size); n != nil {
						f["file_size"] = n
					}
					sig = sig[:j]
				}
			}
		}
		SetFilePath(f, path)
		return threat("detected", sig)
	case strings.Contains(line, ": moved to '"):
		i := strings.Index(line, ": moved to '")
		SetFilePath(f, line[:i])
		f["vendor_action"] = "moved"
		return threat("quarantined", "")
	case strings.HasSuffix(line, ": Removed."):
		SetFilePath(f, strings.TrimSuffix(line, ": Removed."))
		f["vendor_action"] = "Removed"
		return threat("deleted", "")
	case strings.Contains(line, ": Can't move file") || strings.Contains(line, ": Can't unlink file") || strings.Contains(line, ": Can't remove file"):
		i := strings.Index(line, ": Can't ")
		SetFilePath(f, line[:i])
		SetValue(f, "reason", line[i+2:])
		// Every line that says what ClamAV did carries vendor_action;
		// FOUND alone does not (malware-left-clamav counts on that).
		verb, _, _ := strings.Cut(line[i+len(": Can't "):], " ")
		f["vendor_action"] = "Can't " + verb
		return threat("failed", "")
	case strings.HasPrefix(line, "ERROR: Database update process failed") ||
		program == "freshclam" && strings.HasPrefix(line, "ERROR: ") && strings.Contains(strings.ToLower(line), "update"):
		reason := strings.TrimPrefix(line, "ERROR: ")
		if _, after, ok := strings.Cut(reason, "failed: "); ok {
			reason = after
		}
		SetValue(f, "reason", reason)
		return health("update_failed", "Definitions update failed")
	case strings.HasPrefix(line, "daily.") && (strings.Contains(line, " updated (version: ") || strings.Contains(line, " is up-to-date (version: ")):
		v := line[strings.Index(line, "(version: ")+len("(version: "):]
		n := 0
		for n < len(v) && n < 20 && v[n] >= '0' && v[n] <= '9' {
			n++
		}
		SetValue(f, "signature_version", v[:n])
		return health("updated", "Antivirus definitions updated")
	case strings.Contains(line, "The virus database is older than"):
		return health("outdated", "Antivirus definitions out of date")
	}
	return false
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
