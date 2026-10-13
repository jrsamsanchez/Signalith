// Package syslog receives syslog over UDP, TCP and TLS from systems that
// cannot run an agent (firewalls, switches, routers, appliances and
// servers), reads RFC 5424, RFC 3164 with its common real-world variants,
// CEF and LEEF, and hands the events to the ingest pipeline in batches.
package syslog

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// Message is one parsed syslog message. Parts the message did not have are
// empty.
type Message struct {
	// Format is how the header was read: rfc5424, rfc3164, or raw when
	// nothing recognizable was found and the whole line is the message.
	Format string
	// Priority is the <PRI> value (facility*8 + severity), or -1 when the
	// message had none.
	Priority int
	// Time is the timestamp in the message; zero when it had none or the
	// sender marked its clock as not set (Cisco "*").
	Time     time.Time
	Hostname string
	AppName  string
	ProcID   string
	MsgID    string
	// Data is RFC 5424 structured data.
	Data []Element
	// Text is the free-text part after the header.
	Text string
	// Sequence is the Cisco message sequence number.
	Sequence string
	// Cisco is the "%FACILITY-SEVERITY-MNEMONIC" tag of Cisco messages.
	Cisco *CiscoTag
	// CEF is set when the text is a Common Event Format record.
	CEF *CEF
	// LEEF is set when the text is a Log Event Extended Format record.
	LEEF *LEEF
	// Raw is the message as received, without trailing NUL, CR or LF.
	Raw string
}

// Element is one RFC 5424 structured data element, such as
// [origin ip="192.0.2.1"].
type Element struct {
	ID     string
	Params []Param
}

// Param is one name="value" pair of structured data or a CEF extension.
type Param struct {
	Name, Value string
}

// CiscoTag is the "%ASA-6-302013" or "%SYS-5-CONFIG_I" tag Cisco devices
// put before the message text.
type CiscoTag struct {
	Facility string
	Severity int
	Mnemonic string
}

// Parse reads one syslog message. It never fails: input it cannot make
// sense of becomes a raw message whose text is the whole line. now is used
// to give RFC 3164 timestamps, which have no year, the right one.
func Parse(b []byte, now time.Time) Message {
	raw := clean(b)
	m := Message{Format: "raw", Priority: -1, Raw: raw}
	rest := raw
	if pri, n, ok := parsePRI(rest); ok {
		m.Priority = pri
		m.Format = "rfc3164"
		rest = rest[n:]
	}
	if !parse5424(&m, rest) {
		parse3164(&m, rest, now)
	}
	m.Text = strings.TrimPrefix(m.Text, "\ufeff")
	if c, ok := parseCEF(m.Text); ok {
		m.CEF = c
	} else if l, ok := parseLEEF(m.Text); ok {
		m.LEEF = l
	}
	return m
}

// clean drops trailing NUL, CR, LF and spaces and leading blanks, and
// replaces invalid UTF-8.
func clean(b []byte) string {
	s := strings.TrimRight(string(b), "\x00\r\n\t ")
	s = strings.TrimLeft(s, "\x00\r\n\t ")
	return strings.ToValidUTF8(s, "\uFFFD")
}

// parsePRI reads "<PRI>" with a value from 0 to 191.
func parsePRI(s string) (pri, n int, ok bool) {
	if len(s) < 3 || s[0] != '<' {
		return 0, 0, false
	}
	i := 1
	for i < len(s) && i <= 4 && isDigit(s[i]) {
		i++
	}
	if i == 1 || i > 4 || i >= len(s) || s[i] != '>' {
		return 0, 0, false
	}
	v, err := strconv.Atoi(s[1:i])
	if err != nil || v > 191 || (s[1] == '0' && i > 2) {
		return 0, 0, false
	}
	return v, i + 1, true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// ---- RFC 5424 ----

// parse5424 reads "VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG".
// It reports false, changing nothing, when the text is not RFC 5424.
func parse5424(m *Message, s string) bool {
	i := 0
	for i < len(s) && i < 3 && isDigit(s[i]) {
		i++
	}
	if i == 0 || s[0] == '0' || i >= len(s) || s[i] != ' ' {
		return false
	}
	rest := s[i+1:]
	stamp, rest := token(rest)
	var t time.Time
	if stamp != "-" {
		var ok bool
		var n int
		if t, n, ok = parseISO(stamp); !ok || n != len(stamp) {
			return false
		}
	}
	m.Format = "rfc5424"
	m.Time = t
	var host, app, proc, msgid string
	host, rest = token(rest)
	app, rest = token(rest)
	proc, rest = token(rest)
	msgid, rest = token(rest)
	m.Hostname, m.AppName, m.ProcID, m.MsgID = nilValue(host), nilValue(app), nilValue(proc), nilValue(msgid)
	switch {
	case rest == "-" || strings.HasPrefix(rest, "- "):
		rest = strings.TrimPrefix(rest[1:], " ")
	case strings.HasPrefix(rest, "["):
		if data, after, ok := parseSD(rest); ok {
			m.Data = data
			rest = strings.TrimPrefix(after, " ")
		}
	}
	m.Text = rest
	return true
}

// token returns the text up to the next space and what follows it.
func token(s string) (tok, rest string) {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

func nilValue(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// parseSD reads one or more [ID name="value" ...] elements. Values may
// escape '"', '\' and ']' with a backslash.
func parseSD(s string) ([]Element, string, bool) {
	var out []Element
	for strings.HasPrefix(s, "[") {
		s = s[1:]
		end := strings.IndexAny(s, " ]")
		if end <= 0 {
			return nil, "", false
		}
		el := Element{ID: s[:end]}
		s = s[end:]
		for {
			s = strings.TrimLeft(s, " ")
			if s == "" {
				return nil, "", false
			}
			if s[0] == ']' {
				s = s[1:]
				break
			}
			eq := strings.IndexByte(s, '=')
			if eq <= 0 || eq+1 >= len(s) || s[eq+1] != '"' || strings.ContainsAny(s[:eq], " ]\"") {
				return nil, "", false
			}
			name := s[:eq]
			s = s[eq+2:]
			var v strings.Builder
			closed := false
			for i := 0; i < len(s); i++ {
				c := s[i]
				if c == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\' || s[i+1] == ']') {
					v.WriteByte(s[i+1])
					i++
					continue
				}
				if c == '"' {
					s = s[i+1:]
					closed = true
					break
				}
				v.WriteByte(c)
			}
			if !closed {
				return nil, "", false
			}
			el.Params = append(el.Params, Param{Name: name, Value: v.String()})
		}
		out = append(out, el)
	}
	return out, s, true
}

// ---- RFC 3164 and real-world variants ----

var (
	ciscoSeq   = regexp.MustCompile(`^(\d{1,12}): `)
	hostColon  = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]{0,254}): `)
	programTag = regexp.MustCompile(`^([^\s\[\]:%][^\s\[\]:]{0,63})(?:\[([^\]\s]{0,64})\])?:(?:\s|$)`)
	pidTag     = regexp.MustCompile(`^[^\s\[\]:%][^\s\[\]:]{0,63}\[[^\]\s]{0,64}\]:(?:\s|$)`)
	ciscoTag   = regexp.MustCompile(`^%([A-Za-z0-9_][A-Za-z0-9_-]{0,63}?)-([0-7])-([A-Za-z0-9_]{1,64})\s?:\s?`)
	// xrNode is the "[host ]RP/0/RSP0/CPU0:" IOS XR puts before its
	// timestamp.
	xrNode = regexp.MustCompile(`^(?:([A-Za-z0-9][A-Za-z0-9._-]{0,254}) )?[A-Z0-9]{1,16}/[A-Za-z0-9/]{1,64}:`)
	// unifiTag is the "model,mac,version: " UniFi access points and
	// switches put before the program tag.
	unifiTag = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63},[0-9A-Fa-f]{12},[^\s:,]{1,64}: `)
)

// head is the start of s that header patterns look at, so a long message
// costs no more to parse than a short one.
func head(s string) string {
	if len(s) > 512 {
		return s[:512]
	}
	return s
}

// parse3164 reads "TIMESTAMP HOSTNAME TAG[PID]: MSG" leniently: any part
// may be missing, the timestamp may be ISO 8601 or carry a year, and Cisco
// devices add sequence numbers, a host name before the timestamp, and
// %FACILITY-SEVERITY-MNEMONIC tags.
func parse3164(m *Message, s string, now time.Time) {
	// Cisco NX-OS writes "<PRI>: 2026 Oct 12 ...".
	s = strings.TrimPrefix(strings.TrimLeft(s, " "), ": ")
	if g := ciscoSeq.FindStringSubmatch(head(s)); g != nil {
		m.Sequence = g[1]
		s = s[len(g[0]):]
	}
	if host, rest, ok := ciscoPrefix(s, now); ok {
		if host != "" {
			m.Hostname = host
		}
		s = rest
	}
	t, after, hasTime := parseStamp(s, now)
	if hasTime {
		m.Format = "rfc3164"
		m.Time = t
		s = after
	}
	// Host name: the first word after the timestamp, unless it is already
	// the program tag. Without a timestamp, only "host prog[pid]: ..." and
	// Cisco ASA's "host %ASA-..." or "host : %ASA-..." (logging device-id
	// without logging timestamp) are clear enough to read a host name from.
	if m.Hostname == "" && s != "" && s[0] != '%' && !strings.HasPrefix(s, "CEF:") && !strings.HasPrefix(s, "LEEF:") && !programTag.MatchString(head(s)) {
		tok, rest := token(s)
		if hasTime || pidTag.MatchString(head(rest)) || ciscoTag.MatchString(head(strings.TrimPrefix(rest, ": "))) {
			m.Hostname = tok
			s = strings.TrimLeft(rest, " ")
			m.Format = "rfc3164"
		}
	}
	// Cisco ASA writes "host : %ASA-..."; IOS relayed through another
	// syslog server repeats its own sequence number and timestamp.
	s = strings.TrimPrefix(s, ": ")
	if g := ciscoSeq.FindStringSubmatch(head(s)); g != nil && m.Sequence == "" {
		m.Sequence = g[1]
		s = s[len(g[0]):]
	}
	if t, after, ok := parseStamp(s, now); ok {
		if !hasTime {
			m.Time = t
			hasTime = true
		}
		s = after
	}
	// UniFi devices write "model,mac,version: prog: ..."; the program is
	// the tag, and the device stays known by its address.
	if g := unifiTag.FindString(head(s)); g != "" && programTag.MatchString(head(s[len(g):])) {
		s = s[len(g):]
	}
	if !strings.HasPrefix(s, "%") && !strings.HasPrefix(s, "CEF:") && !strings.HasPrefix(s, "LEEF:") {
		if g := programTag.FindStringSubmatch(head(s)); g != nil {
			m.AppName = g[1]
			m.ProcID = g[2]
			m.Format = "rfc3164"
			s = strings.TrimPrefix(s[len(g[0]):], " ")
		}
	}
	// The Cisco tag comes first, or after the program as in IOS XR's
	// "config[65738]: %MGBL-CONFIG-6-DB_COMMIT : ...".
	if strings.HasPrefix(s, "%") {
		if g := ciscoTag.FindStringSubmatch(head(s)); g != nil {
			sev, _ := strconv.Atoi(g[2])
			m.Cisco = &CiscoTag{Facility: g[1], Severity: sev, Mnemonic: g[3]}
			m.Format = "rfc3164"
			s = s[len(g[0]):]
		}
	}
	if hasTime {
		m.Format = "rfc3164"
	}
	m.Text = s
}

// ciscoPrefix reads what Cisco devices put between the sequence number and
// the timestamp: IOS "host: " (logging origin-id) and "000048: " (service
// sequence-numbers), in that order and each optional, or IOS XR's
// "[host ]RP/0/RSP0/CPU0:". It reports false, changing nothing, unless a
// timestamp follows.
func ciscoPrefix(s string, now time.Time) (host, rest string, ok bool) {
	rest = s
	if g := hostColon.FindStringSubmatch(head(rest)); g != nil && !allDigits(g[1]) {
		host, rest = g[1], rest[len(g[0]):]
	} else if g := xrNode.FindStringSubmatch(head(rest)); g != nil {
		host, rest = g[1], rest[len(g[0]):]
	}
	if g := ciscoSeq.FindString(head(rest)); g != "" {
		rest = rest[len(g):]
	}
	if len(rest) == len(s) {
		return "", s, false
	}
	if _, _, ok := parseStamp(rest, now); !ok {
		return "", s, false
	}
	return host, rest, true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return s != ""
}

var months = map[string]time.Month{
	"jan": time.January, "feb": time.February, "mar": time.March, "apr": time.April,
	"may": time.May, "jun": time.June, "jul": time.July, "aug": time.August,
	"sep": time.September, "oct": time.October, "nov": time.November, "dec": time.December,
}

var (
	bsdStamp = regexp.MustCompile(`^([A-Za-z]{3})\s+(\d{1,2})\s+(?:(\d{4})\s+)?(\d{1,2}):(\d{2}):(\d{2})(\.\d{1,9})?`)
	// yearFirst is the Cisco NX-OS "2026 Oct 12 13:59:00".
	yearFirst  = regexp.MustCompile(`^(\d{4}) ([A-Za-z]{3})\s+(\d{1,2}) (\d{1,2}):(\d{2}):(\d{2})(\.\d{1,9})?`)
	stampYear  = regexp.MustCompile(`^ ((?:19|20)\d{2})(?:\s|$)`)
	stampZone  = regexp.MustCompile(`^ ([A-Z]{3,5})(:|\s|$)`)
	isoPattern = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|[+-]\d{2}:?\d{2})?`)
)

// parseStamp reads a timestamp at the start of s: "Oct 11 09:15:02",
// "Oct 11 2026 09:15:02", "Oct 11 09:15:02.123 UTC", ISO 8601, with a
// Cisco "*" (clock not set) or "." prefix. It returns the rest after the
// timestamp, an optional ':' and spaces. A "*" timestamp parses but comes
// back as the zero time, so the receive time is used instead.
func parseStamp(s string, now time.Time) (time.Time, string, bool) {
	unset := false
	p := s
	if strings.HasPrefix(p, "*") {
		unset = true
		p = p[1:]
	} else if strings.HasPrefix(p, ".") {
		p = p[1:]
	}
	var t time.Time
	var n int
	var ok bool
	if p != "" && isDigit(p[0]) {
		if t, n, ok = parseISO(p); !ok {
			t, n, ok = parseBSD(p, now)
		}
	} else {
		t, n, ok = parseBSD(p, now)
	}
	if !ok {
		return time.Time{}, s, false
	}
	rest := p[n:]
	if !strings.HasPrefix(rest, ":") && rest != "" && rest[0] != ' ' {
		return time.Time{}, s, false
	}
	rest = strings.TrimPrefix(rest, ":")
	rest = strings.TrimLeft(rest, " ")
	if unset {
		t = time.Time{}
	}
	return t, rest, true
}

// parseBSD reads "Mmm dd [yyyy] hh:mm:ss[.frac] [yyyy] [UTC|ZONE:]", or
// "yyyy Mmm dd hh:mm:ss[.frac] [UTC|ZONE:]" as Cisco NX-OS writes it. Times
// without a zone, or with a zone other than UTC, are taken as this server's
// local time; times without a year get the one ingest.GuessYear picks.
func parseBSD(s string, now time.Time) (time.Time, int, bool) {
	// g holds month, day, year, hours, minutes, seconds and fraction.
	var g [7]string
	n := 0
	if b := bsdStamp.FindStringSubmatch(head(s)); b != nil {
		g = [7]string{b[1], b[2], b[3], b[4], b[5], b[6], b[7]}
		n = len(b[0])
	} else if y := yearFirst.FindStringSubmatch(head(s)); y != nil {
		g = [7]string{y[2], y[3], y[1], y[4], y[5], y[6], y[7]}
		n = len(y[0])
	} else {
		return time.Time{}, 0, false
	}
	mon, ok := months[strings.ToLower(g[0])]
	if !ok {
		return time.Time{}, 0, false
	}
	day, _ := strconv.Atoi(g[1])
	hh, _ := strconv.Atoi(g[3])
	mm, _ := strconv.Atoi(g[4])
	ss, _ := strconv.Atoi(g[5])
	if day < 1 || day > 31 || hh > 23 || mm > 59 || ss > 60 {
		return time.Time{}, 0, false
	}
	if ss == 60 {
		ss = 59
	}
	nsec := fraction(g[6])
	year := 0
	if g[2] != "" {
		year, _ = strconv.Atoi(g[2])
	} else if y := stampYear.FindStringSubmatch(head(s[n:])); y != nil {
		year, _ = strconv.Atoi(y[1])
		n += 1 + len(y[1])
	}
	loc := time.Local
	if z := stampZone.FindStringSubmatch(head(s[n:])); z != nil {
		switch {
		case z[1] == "UTC" || z[1] == "GMT":
			loc = time.UTC
			n += 1 + len(z[1])
		case z[2] == ":" && z[1] != "CEF" && z[1] != "LEEF":
			// Other zone names are ambiguous (CST is three different
			// zones), so skip the name and use local time. Only "ZONE:" is
			// read as a zone; "Oct 11 09:15:02 MAIL" is a host named MAIL,
			// and "CEF:" and "LEEF:" start a record.
			n += 1 + len(z[1])
		}
	}
	t := time.Date(year, mon, day, hh, mm, ss, nsec, loc)
	if t.Day() != day {
		return time.Time{}, 0, false // Feb 30 and the like
	}
	if year == 0 {
		return ingest.GuessYear(t, now), n, true
	}
	return t.UTC(), n, true
}

// parseISO reads an RFC 3339 or ISO 8601 timestamp at the start of s and
// returns how many bytes it used. Without a zone it is local time.
func parseISO(s string) (time.Time, int, bool) {
	g := isoPattern.FindStringSubmatch(head(s))
	if g == nil {
		return time.Time{}, 0, false
	}
	year, _ := strconv.Atoi(g[1])
	mon, _ := strconv.Atoi(g[2])
	day, _ := strconv.Atoi(g[3])
	hh, _ := strconv.Atoi(g[4])
	mm, _ := strconv.Atoi(g[5])
	ss, _ := strconv.Atoi(g[6])
	if mon < 1 || mon > 12 || day < 1 || day > 31 || hh > 23 || mm > 59 || ss > 60 {
		return time.Time{}, 0, false
	}
	if ss == 60 {
		ss = 59
	}
	loc := time.Local
	switch z := g[8]; {
	case z == "Z":
		loc = time.UTC
	case z != "":
		z = strings.ReplaceAll(z[1:], ":", "")
		h, _ := strconv.Atoi(z[:2])
		mi, _ := strconv.Atoi(z[2:])
		if h > 23 || mi > 59 {
			return time.Time{}, 0, false
		}
		off := h*3600 + mi*60
		if g[8][0] == '-' {
			off = -off
		}
		loc = time.FixedZone("", off)
	}
	t := time.Date(year, time.Month(mon), day, hh, mm, ss, fraction(g[7]), loc)
	if t.Day() != day {
		return time.Time{}, 0, false
	}
	return t.UTC(), len(g[0]), true
}

// fraction turns ".123" into nanoseconds.
func fraction(f string) int {
	if len(f) < 2 {
		return 0
	}
	digits := f[1:]
	for len(digits) < 9 {
		digits += "0"
	}
	n, _ := strconv.Atoi(digits[:9])
	return n
}
