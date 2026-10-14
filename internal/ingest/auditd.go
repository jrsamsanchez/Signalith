package ingest

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// AuditdSourcetype is the sourcetype of Linux audit records (auditd).
const AuditdSourcetype = "linux:audit"

// AuditdProduct is the vendor_product of Linux audit records.
const AuditdProduct = "Linux auditd"

// An audit record, as auditd writes it to /var/log/audit/audit.log:
//
//	type=EXECVE msg=audit(1700000000.123:456): argc=2 a0="ls" a1=2D6C61
//
// or as ausearch -i prints it, with values made readable:
//
//	type=EXECVE msg=audit(04/16/2025 08:20:23.552:456) : argc=2 a0=ls a1=-la
//
// Each record is one event; the records of one system call share its
// serial number (auditd_id). auditd's ENRICHED format adds the names of
// numbers (UID="root", SYSCALL=execve) after a 0x1d byte.
var auditdHeader = regexp.MustCompile(`^(?:node=(\S+)\s+)?type=([A-Z0-9_]+)\s+msg=audit\(([^)]*)\)\s*:\s*`)

// IsAuditdLine reports whether a line is an audit record.
func IsAuditdLine(line string) bool {
	return auditdHeader.MatchString(line)
}

// auditdEncoded are the fields whose text auditd writes in hex when it has
// a space, a quote or a control character in it (otherwise in quotes): a
// program's arguments (a0, a1... of an EXECVE record), its command line
// (proctitle), names of files, programs and accounts.
var auditdEncoded = map[string]bool{
	"proctitle": true, "name": true, "cwd": true, "comm": true, "exe": true, "key": true, "acct": true,
	"cmd": true, "data": true, "path": true, "old-name": true, "new-name": true, "unit": true,
}

// maxAuditArgs is how many of a program's arguments are kept as their own
// fields (auditd_a0 to auditd_a31); all of them are in auditd_execve_command.
const maxAuditArgs = 32

// parseAuditdLine reads one audit record into the Other data model. Every
// field is kept as auditd_<name>, as auditd names it (the names of an
// ENRICHED record's numbers as auditd_<name>_name), so rules written for
// auditd's fields read them as written; the program, process and user
// are also in the usual fields.
func parseAuditdLine(line, host string) (Event, bool) {
	m := auditdHeader.FindStringSubmatch(line)
	if m == nil {
		return Event{}, false
	}
	if m[1] != "" {
		host = m[1]
	}
	host = truncateUTF8(CapValue(host), maxHostLen)
	f := map[string]any{
		"host":           host,
		"dest":           host,
		"sourcetype":     AuditdSourcetype,
		"vendor_product": AuditdProduct,
		"app":            "auditd",
		"auditd_type":    m[2],
		"signature":      m[2],
		"message":        line,
	}
	ev := Event{Model: "Other", Fields: f}
	rec, _ := ReadAuditd(line)
	f["auditd_id"] = rec.Serial
	ev.Time = rec.Time
	for k, v := range rec.Fields {
		name := "auditd_" + k
		if k != strings.ToLower(k) {
			// An ENRICHED record's name of a number (UID="root").
			name = "auditd_" + strings.ToLower(k) + "_name"
		}
		// The header's type and serial stay, whatever a user-space
		// record's own text says.
		if _, ok := f[name]; !ok {
			f[name] = CapValue(v)
		}
	}
	execve := rec.Type == "EXECVE"
	if execve {
		argc, _ := strconv.Atoi(str(f, "auditd_argc"))
		var args []string
		for i := 0; i < argc; i++ {
			name := "auditd_a" + strconv.Itoa(i)
			a, ok := f[name].(string)
			if !ok {
				break
			}
			args = append(args, a)
			if i >= maxAuditArgs {
				delete(f, name)
			}
		}
		f["auditd_execve_command"] = CapValue(strings.Join(args, " "))
		f["process"] = f["auditd_execve_command"]
	}
	if p, ok := f["auditd_proctitle"]; ok {
		f["process"] = p
	}
	if exe := str(f, "auditd_exe"); exe != "" && exe != "(null)" {
		f["process_path"] = exe
		f["process_name"] = baseName(exe)
	}
	if comm := str(f, "auditd_comm"); comm != "" && f["process_name"] == nil {
		f["process_name"] = comm
	}
	if n, err := strconv.ParseInt(str(f, "auditd_pid"), 10, 64); err == nil {
		f["process_id"] = n
	}
	if n, err := strconv.ParseInt(str(f, "auditd_ppid"), 10, 64); err == nil {
		f["parent_process_id"] = n
	}
	// The account logged in (auid), which stays the same through sudo
	// and su: its name, when the record has it.
	user := str(f, "auditd_auid_name")
	if user == "" && rec.Interpreted {
		user = str(f, "auditd_auid")
	}
	if user == "" || user == "unset" || user == "?" {
		user = str(f, "auditd_acct")
	}
	if user != "" && user != "unset" && user != "?" {
		f["user"] = user
	}
	return ev, true
}

// parseAuditdRecord reads a line Fluent Bit tailed from the audit log,
// with the host name Fluent Bit adds (the records carry none unless
// auditd's name_format is set). A line that is not an audit record stays
// as it is, in Other.
func parseAuditdRecord(r map[string]any) Event {
	line := str(r, "log")
	if ev, ok := parseAuditdLine(line, str(r, "hostname")); ok {
		return ev
	}
	host := truncateUTF8(CapValue(str(r, "hostname")), maxHostLen)
	return Event{Model: "Other", Fields: map[string]any{"host": host, "dest": host, "sourcetype": AuditdSourcetype, "message": line}}
}

// AuditdRecord is one audit record's parts.
type AuditdRecord struct {
	Type, Serial string
	Time         time.Time
	// Interpreted is true for ausearch -i output.
	Interpreted bool
	// Fields are the record's values by auditd's names, decoded; the
	// names an ENRICHED record adds are in capitals (UID, SYSCALL).
	Fields map[string]string
}

// ReadAuditd reads an audit record line.
func ReadAuditd(line string) (AuditdRecord, bool) {
	m := auditdHeader.FindStringSubmatch(line)
	if m == nil {
		return AuditdRecord{}, false
	}
	stamp, serial, _ := cutLast(m[3], ":")
	rec := AuditdRecord{Type: m[2], Serial: serial, Fields: map[string]string{}}
	// ausearch -i writes a date (04/16/2025 08:20:23.552) and readable
	// values; auditd writes seconds since 1970 and encodes text.
	rec.Interpreted = strings.Contains(stamp, "/")
	if rec.Interpreted {
		if t, err := time.ParseInLocation("01/02/2006 15:04:05.000", stamp, time.Local); err == nil {
			rec.Time = t.UTC()
		}
	} else if sec, frac, ok := strings.Cut(stamp, "."); ok {
		s, err1 := strconv.ParseInt(sec, 10, 64)
		ms, err2 := strconv.ParseInt(frac, 10, 64)
		if err1 == nil && err2 == nil {
			rec.Time = time.Unix(s, ms*int64(time.Millisecond)).UTC()
		}
	}
	body := line[len(m[0]):]
	enriched := ""
	if i := strings.IndexByte(body, 0x1d); i >= 0 {
		body, enriched = body[:i], body[i+1:]
	}
	set := func(k, v string) {
		if _, ok := rec.Fields[k]; !ok {
			rec.Fields[k] = v
		}
	}
	execve := rec.Type == "EXECVE"
	pieces := map[string]string{}
	for _, kv := range auditdFields(body) {
		k, v := strings.ToLower(kv[0]), kv[1]
		if k == "msg" {
			// A user-space record's own fields (msg='unit=sshd comm=...').
			for _, kv := range auditdFields(strings.Trim(v, "'")) {
				k := strings.ToLower(kv[0])
				set(k, auditdValue(k, kv[1], rec.Interpreted, false))
			}
			continue
		}
		// A long argument comes in pieces: a1_len=..., a1[0]=..., a1[1]=...
		if p := auditArgPiece.FindStringSubmatch(k); execve && p != nil {
			pieces[p[1]] += auditdValue(k, v, rec.Interpreted, true)
			continue
		}
		set(k, auditdValue(k, v, rec.Interpreted, execve && isAuditArg(k)))
	}
	for n, a := range pieces {
		set("a"+n, a)
	}
	for _, kv := range auditdFields(enriched) {
		set(strings.ToUpper(kv[0]), strings.Trim(kv[1], `"`))
	}
	return rec, true
}

// isAuditArg reports whether an EXECVE field is one of the program's
// arguments (a0, a1, ...; a long one comes in pieces, a1[0], a1[1]).
func isAuditArg(k string) bool {
	if len(k) < 2 || k[0] != 'a' {
		return false
	}
	_, err := strconv.Atoi(k[1:])
	return err == nil
}

// auditdValue reads one value: quoted text as is, and text auditd encoded
// in hex decoded, with the zero bytes between a command line's arguments
// as spaces. Readable (ausearch -i) records are already decoded.
func auditdValue(k, v string, interpreted, arg bool) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	if interpreted || !(arg || auditdEncoded[strings.ToLower(k)]) || v == "(null)" || len(v)%2 != 0 {
		return v
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return v
	}
	return strings.TrimRight(strings.ReplaceAll(string(b), "\x00", " "), " ")
}

// auditdFields splits a record's body into its key=value pairs. A value
// runs to the next " key=", so an unquoted one with spaces in it (op=adding
// user) stays whole; a quoted one runs to its closing quote.
func auditdFields(s string) [][2]string {
	var out [][2]string
	s = strings.TrimSpace(s)
	for s != "" {
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			break
		}
		k := s[:eq]
		if strings.ContainsAny(k, " \t") {
			// Text that is not key=value: skip a word.
			_, s, _ = strings.Cut(s, " ")
			s = strings.TrimSpace(s)
			continue
		}
		rest := s[eq+1:]
		var v string
		if k == "proctitle" && rest != "" && rest[0] != '"' {
			// A readable command line (ausearch -i) has spaces and = in
			// it, and is the record's only field.
			v, rest = rest, ""
		} else if rest != "" && (rest[0] == '"' || rest[0] == '\'') {
			end := strings.IndexByte(rest[1:], rest[0])
			if end < 0 {
				v, rest = rest, ""
			} else {
				v, rest = rest[:end+2], rest[end+2:]
			}
		} else if loc := auditdNextKey.FindStringIndex(rest); loc != nil {
			v, rest = rest[:loc[0]], rest[loc[0]:]
		} else {
			v, rest = rest, ""
		}
		out = append(out, [2]string{k, strings.TrimSpace(v)})
		s = strings.TrimSpace(rest)
	}
	return out
}

var auditArgPiece = regexp.MustCompile(`^a(\d+)\[\d+\]$`)

var auditdNextKey = regexp.MustCompile(`\s+[A-Za-z_][\w\-\[\]]*=`)

// cutLast splits s around the last sep.
func cutLast(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

// AuditdChannel names audit records among test events, whose event ID is
// the record type (EXECVE, SYSCALL).
const AuditdChannel = "Linux-auditd"

// AuditdLine builds the line auditd writes for a record of type typ with
// the given fields, by auditd's names: text in quotes, or in hex when it
// has a space, a quote or a control character in it (a command line's
// spaces as the zero bytes between its arguments), and the names in
// capitals (UID, SYSCALL) after 0x1d, as an ENRICHED record has them. A
// field "_raw" is a recorded line, returned as it is.
func AuditdLine(typ string, t time.Time, fields map[string]string) string {
	if raw, ok := fields["_raw"]; ok {
		return raw
	}
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	argIndex := func(k string) int {
		if !isAuditArg(k) {
			return -1
		}
		n, _ := strconv.Atoi(k[1:])
		return n
	}
	slices.SortFunc(names, func(a, b string) int {
		ia, ib := argIndex(a), argIndex(b)
		if ia >= 0 && ib >= 0 {
			return ia - ib
		}
		return strings.Compare(a, b)
	})
	var body, enriched []string
	execve := typ == "EXECVE"
	for _, k := range names {
		v := fields[k]
		if k != strings.ToLower(k) {
			enriched = append(enriched, k+"="+strconv.Quote(v))
			continue
		}
		if execve && isAuditArg(k) || auditdEncoded[k] {
			if strings.ContainsAny(v, "\" \t\r\n") || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
				if k == "proctitle" {
					v = strings.ReplaceAll(v, " ", "\x00")
				}
				v = strings.ToUpper(hex.EncodeToString([]byte(v)))
			} else {
				v = `"` + v + `"`
			}
		}
		body = append(body, k+"="+v)
	}
	line := fmt.Sprintf("type=%s msg=audit(%d.%03d:4242): %s", typ, t.Unix(), t.Nanosecond()/int(time.Millisecond), strings.Join(body, " "))
	if len(enriched) > 0 {
		line += "\x1d" + strings.Join(enriched, " ")
	}
	return line
}

// AuditdRecordFor is the record Fluent Bit sends for an audit log line,
// with its tag (linux.audit).
func AuditdRecordFor(line, host string) map[string]any {
	return map[string]any{"log": line, "hostname": host}
}

// AuditdField is the stored field of an audit record field by auditd's
// name (exe is auditd_exe), or of a name an ENRICHED record gives a
// number, in capitals (UID is auditd_uid_name). Splunk's add-on also
// joins a program's arguments as execve_command. Other names are not
// audit record fields.
func AuditdField(name string) (string, bool) {
	if !auditdFieldName.MatchString(name) {
		return "", false
	}
	if lower := strings.ToLower(name); lower != name {
		if name != strings.ToUpper(name) {
			return "", false
		}
		return "auditd_" + lower + "_name", true
	}
	return "auditd_" + name, true
}

var auditdFieldName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
