package ingest

import (
	"encoding/xml"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Linux sources arrive either as syslog lines (Fluent Bit tail on
// /var/log/auth.log or /var/log/secure, or the syslog input) or as journald
// records (Fluent Bit systemd input). Both reduce to host, program, pid and
// message, and the program decides which parser applies.

var syslogLine = regexp.MustCompile(`^(?:<\d+>)?(?:(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})|(\d{4}-\d{2}-\d{2}T\S+))\s+(\S+)\s+([^\s\[:]+)(?:\[(\d+)\])?:\s?(.*)$`)

func parseSyslogLine(line, sourcetype string, now time.Time) Event {
	m := syslogLine.FindStringSubmatch(line)
	if m == nil {
		return Event{Model: "Other", Fields: map[string]any{"sourcetype": sourcetype, "message": line}}
	}
	var ts time.Time
	if m[1] != "" {
		if t, err := time.ParseInLocation("Jan _2 15:04:05", strings.Join(strings.Fields(m[1]), " "), time.Local); err == nil {
			ts = GuessYear(t, now)
		}
	} else if t, ok := parseTime(m[2]); ok {
		ts = t
	}
	ev := ParseProgram(m[3], m[4], m[5], m[6], sourcetype)
	ev.Fields["message"] = line
	// An audit record has its own, more precise time.
	if ev.Time.IsZero() {
		ev.Time = ts
	}
	return ev
}

// GuessYear gives a timestamp that has no year, as in RFC 3164 syslog
// ("Oct 11 09:15:02"), the current year, or last year when that would put
// it more than a day in the future. The clock time and location of t are
// kept; the result is in UTC.
func GuessYear(t, now time.Time) time.Time {
	y := time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
	if y.After(now.Add(24 * time.Hour)) {
		y = y.AddDate(-1, 0, 0)
	}
	return y.UTC()
}

func parseJournal(r map[string]any) Event {
	program := str(r, "SYSLOG_IDENTIFIER", "_COMM")
	ev := ParseProgram(str(r, "_HOSTNAME"), program, str(r, "_PID"), str(r, "MESSAGE"), "linux:journal")
	if us, err := strconv.ParseInt(str(r, "__REALTIME_TIMESTAMP", "_SOURCE_REALTIME_TIMESTAMP"), 10, 64); err == nil {
		ev.Time = time.UnixMicro(us).UTC()
	}
	ev.Fields["message"] = program + ": " + str(r, "MESSAGE")
	return ev
}

// sshd prints the user name a client sent as it was sent, spaces and all,
// and the client's address after it. A name can itself hold
// " from <addr> port <n>", so the address is the one in the last such
// clause of the line (the user name, greedy, takes the rest), and it is
// kept as src only when it is an IP address.
//
// After its clause sshd writes " ssh2", and for a key ": " and the key.
// For a certificate that includes its key ID, which a client can choose
// freely on a failed attempt, so it too can hold such a clause. So when
// the line has more than one clause and text follows the last one, the
// source cannot be told: src is left out and src_ambiguous is set (see
// ambiguousSSH). The sender can then hide its address, but never choose
// another.
var (
	sshdAuth      = regexp.MustCompile(`^(Accepted|Failed) (\S+) for (invalid user )?(.*) from (\S+) port (\d+)((?:[\s:].*)?)$`)
	sshdClause    = regexp.MustCompile(` from \S+ port \d+`)
	sshdInvalid   = regexp.MustCompile(`^Invalid user (.*) from (\S+?)(?: port (\d+))?(?:\s.*)?$`)
	sudoCommand   = regexp.MustCompile(`^\s*(\S+) : (?:(\d+) incorrect password attempts? ; )?TTY=\S+ ; PWD=\S+ ; USER=(\S+) ; COMMAND=(.*)$`)
	sudoAuthFail  = regexp.MustCompile(`pam_unix\(sudo:auth\): authentication failure;.*\bruser=(\S*).*\buser=(\S+)`)
	suSession     = regexp.MustCompile(`pam_unix\(su(?:-l)?:session\): session opened for user (\S+?)(?:\(uid=\d+\))? by (\S+?)(?:\(uid=\d+\))?$`)
	suFail        = regexp.MustCompile(`pam_unix\(su(?:-l)?:auth\): authentication failure;.*\bruser=(\S*).*\buser=(\S+)`)
	useraddNew    = regexp.MustCompile(`^new user: name=([^,]+),`)
	userdelDelete = regexp.MustCompile(`^delete user '([^']+)'`)
	groupAdd      = regexp.MustCompile(`^add '([^']+)' to (?:shadow )?group '([^']+)'`)
)

// ParseProgram maps one syslog program's message onto a data model: sshd
// (including OpenSSH 9.8+ sshd-session), sudo and su logons become Authentication events; useradd, userdel,
// usermod and gpasswd become Change events; audit records (auditd's
// syslog plugin) are read as from the audit log; ClamAV's threats, definition
// updates and problems become Malware events; anything else is Other. Agent
// logs and the syslog receiver both use it, so the built-in detections fire
// whichever way Linux auth logs arrive.
func ParseProgram(host, program, pid, msg, sourcetype string) Event {
	// Audit records forwarded to syslog (auditd's syslog plugin).
	if ev, ok := parseAuditdLine(msg, host); ok {
		return ev
	}
	f := map[string]any{
		"host":       host,
		"dest":       host,
		"sourcetype": sourcetype,
		"app":        program,
		"process_id": atoi(pid),
	}
	ev := Event{Model: "Other", Fields: f}
	switch program {
	case "sshd", "sshd-session", "sshd-auth":
		// OpenSSH 9.8 and later log logons from sshd-session (and 10.0
		// from sshd-auth); they are still sshd to detections and searches.
		f["app"] = "sshd"
		if m := sshdAuth.FindStringSubmatch(msg); m != nil {
			ev.Model = "Authentication"
			f["action"] = map[string]string{"Accepted": "success", "Failed": "failure"}[m[1]]
			f["authentication_method"] = m[2]
			f["user"] = m[4]
			if ambiguousSSH(msg, m[7]) {
				f["src_ambiguous"] = true
			} else {
				setSSHSource(f, m[5], m[6])
			}
			f["signature"] = "SSH " + strings.ToLower(m[1]) + " " + m[2]
			if m[3] != "" {
				f["reason"] = "unknown user"
			} else if m[1] == "Failed" && m[2] == "password" {
				f["reason"] = "bad password"
			}
		} else if m := sshdInvalid.FindStringSubmatch(msg); m != nil {
			ev.Model = "Authentication"
			f["action"] = "failure"
			f["user"] = m[1]
			setSSHSource(f, m[2], m[3])
			f["reason"] = "unknown user"
			f["signature"] = "SSH invalid user"
		}
	case "sudo":
		if m := sudoCommand.FindStringSubmatch(msg); m != nil {
			ev.Model = "Authentication"
			f["src_user"] = m[1]
			f["user"] = m[3]
			f["process"] = m[4]
			if m[2] != "" {
				f["action"] = "failure"
				f["reason"] = "bad password"
				f["signature"] = "sudo incorrect password"
			} else {
				f["action"] = "success"
				f["signature"] = "sudo command"
			}
		} else if m := sudoAuthFail.FindStringSubmatch(msg); m != nil {
			ev.Model = "Authentication"
			f["action"] = "failure"
			f["src_user"] = m[1]
			f["user"] = m[2]
			f["signature"] = "sudo authentication failure"
		}
	case "su":
		if m := suSession.FindStringSubmatch(msg); m != nil {
			ev.Model = "Authentication"
			f["action"] = "success"
			f["user"] = m[1]
			f["src_user"] = m[2]
			f["signature"] = "su session opened"
		} else if m := suFail.FindStringSubmatch(msg); m != nil {
			ev.Model = "Authentication"
			f["action"] = "failure"
			f["src_user"] = m[1]
			f["user"] = m[2]
			f["signature"] = "su authentication failure"
		}
	case "useradd":
		if m := useraddNew.FindStringSubmatch(msg); m != nil {
			ev.Model = "Change"
			f["action"] = "created"
			f["object"] = m[1]
			f["object_category"] = "user"
			f["signature"] = "User account created"
		}
	case "userdel":
		if m := userdelDelete.FindStringSubmatch(msg); m != nil {
			ev.Model = "Change"
			f["action"] = "deleted"
			f["object"] = m[1]
			f["object_category"] = "user"
			f["signature"] = "User account deleted"
		}
	case "clamd", "clamonacc", "freshclam", "clamscan", "clamdscan":
		f["vendor_product"] = ClamAVProduct
		if parseClamAVLine(program, msg, f) {
			// The program and its process ID are ClamAV's own, not the
			// process the threat was found in.
			ev.Model = MalwareModel
			delete(f, "app")
			delete(f, "process_id")
		}
	case "sysmon":
		parseLinuxSysmon(msg, &ev)
	case "usermod", "gpasswd":
		if m := groupAdd.FindStringSubmatch(msg); m != nil {
			ev.Model = "Change"
			f["action"] = "modified"
			f["member"] = m[1]
			f["object"] = m[2]
			f["object_category"] = "group"
			f["signature"] = "User added to group"
		}
	}
	if ev.Model == "Authentication" || ev.Model == "Change" {
		f["vendor_product"] = "Linux"
	}
	return ev
}

// SysmonLinuxSourcetype is the sourcetype of Sysmon for Linux events.
const SysmonLinuxSourcetype = "sysmon:linux"

// linuxSysmonEvent is the XML event Sysmon for Linux writes to syslog.
type linuxSysmonEvent struct {
	System struct {
		EventID  string `xml:"EventID"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

// parseLinuxSysmon reads a Sysmon for Linux event: the same events and
// fields as Sysmon on Windows (process creation, network connections,
// file creation and deletion), so they land in the same data models.
func parseLinuxSysmon(msg string, ev *Event) {
	msg = strings.TrimSpace(msg)
	if !strings.HasPrefix(msg, "<Event") {
		return
	}
	var x linuxSysmonEvent
	if err := xml.Unmarshal([]byte(msg), &x); err != nil || x.System.EventID == "" {
		return
	}
	kv := make(map[string]string, len(x.Data))
	for _, d := range x.Data {
		// Sysmon for Linux writes - for a value it does not have.
		if d.Value != "-" {
			kv[d.Name] = d.Value
		}
	}
	f := ev.Fields
	f["sourcetype"] = SysmonLinuxSourcetype
	f["signature_id"] = x.System.EventID
	if c := truncateUTF8(x.System.Computer, maxHostLen); c != "" {
		f["host"], f["dest"] = c, c
	}
	// The program and its process ID are Sysmon's own.
	delete(f, "app")
	delete(f, "process_id")
	parseSysmon(x.System.EventID, kv, ev)
	f["vendor_product"] = "Sysmon for Linux"
}

// ambiguousSSH reports whether an Accepted or Failed line's source cannot
// be told: more than one " from <addr> port <n>" clause, and text after
// the last one other than sshd's own " ssh2". With nothing after it, the
// last clause is sshd's, because only key details (which may hold a
// client's text) follow sshd's clause.
func ambiguousSSH(msg, tail string) bool {
	if tail == "" || tail == " ssh2" {
		return false
	}
	return len(sshdClause.FindAllStringIndex(msg, 3)) > 1
}

// setSSHSource sets src and src_port from the address and port sshd
// printed, when the address is an IP address: sshd prints the client's
// address, never a name, so anything else did not come from sshd.
func setSSHSource(f map[string]any, addr, port string) {
	if _, err := netip.ParseAddr(addr); err != nil {
		return
	}
	f["src"] = addr
	f["src_port"] = atoi(port)
}
