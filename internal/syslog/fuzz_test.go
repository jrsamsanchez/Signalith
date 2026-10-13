package syslog

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

var fuzzSeeds = []string{
	"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - \ufeff'su root' failed for lonvick on /dev/pts/8",
	`<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - [exampleSDID@32473 iut="3" eventSource="Application"][x a="q\"\]\\"] msg`,
	"<38>Oct 12 13:59:00 web1 sshd[811]: Failed password for root from 192.0.2.4 port 40122 ssh2",
	"<86>2026-10-12T13:59:00.123+02:00 web1 useradd[900]: new user: name=backdoor, UID=1002",
	"<166>Oct 12 2026 13:59:00 asa1 : %ASA-6-302013: Built inbound TCP connection",
	"<189>45: router1: *Mar  1 00:01:02.345 UTC: %LINEPROTO-5-UPDOWN: Line protocol",
	"<187>Oct 12 13:59:00 rtr2 1234: Oct 12 13:58:59 EST: %MGBL-CONFIG-6-DB_COMMIT : x",
	"<189>48: rtr1: 000048: *Oct 12 13:59:00.123 UTC: %SYS-5-CONFIG_I: x",
	"<187>: 2026 Oct 12 13:59:00 UTC: %ETHPORT-3-IF_DOWN_LINK_FAILURE: x",
	"<189>1234: xr1 RP/0/RSP0/CPU0:Oct 12 13:59:00.123 UTC: config[65738]: %MGBL-CONFIG-6-DB_COMMIT : x",
	"<4>Oct 12 13:59:00 U7PG2,b4fbe4aabbcc,v4.3.20.11298: hostapd: ath0: x",
	"<13>1 2001-01-01T12:00:00Z h app - - - old",
	"CEF:0|V|P|1|1|N|3|rt=Oct 12 13:00:00.123 +02:00 end=1",
	`<134>Oct 12 13:59:00 fw1 CEF:0|Ven\|dor|P|1|sig|N|5|rt=1791813540000 src=10.0.0.1 dst=10.0.0.2 msg=a\=b c\\d\n request=http://x/?a=b`,
	"CEF:0|V|P|1|1|N|Very-High|spt=abc in=5 out=x act=Deny proto=6",
	"<134>Oct 13 09:14:02 eset-01 LEEF:1.0|ESET|PROTECT|11.1.0|Threat_Event|cat=ESET Threat Event\tsev=7\thostname=ws-1\tthreat_name=Win32/Agent.ABC\tobject_uri=file:///C:/a.exe\taction_taken=Cleaned by deleting\tthreat_handled=false",
	"LEEF:2.0|V|P|1|E|0x7C|src=10.0.0.1|dst=10.0.0.2|devTime=1791813540000|usrName=x|cat=virus|fileName=a",
	"LEEF:2.0|V|P|1|E|^|a=1^b=2",
	"<54>Oct 13 09:14:02 sepm-01 SymantecServer: Virus found,IP Address: 192.0.2.27,Computer name: ws-1,Risk name: Trojan.Gen.2,File path: C:\\a.exe,Actual action: Quarantined,Application hash: 9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08,File size (bytes): 68",
	"<29>1 2026-10-13T09:14:02.0Z epo-01 EPOEvents - EventFwd - <EPOevent><SoftwareInfo ProductName=\"T &amp; E\"><ThreatCategory>av.detect</ThreatCategory><ThreatName>X</ThreatName><ThreatActionTaken>IDS_ALERT_ACT_TAK_DEL</ThreatActionTaken><TargetHostName>ws</TargetHostName></SoftwareInfo></EPOevent>",
	"CEF:0|Trend Micro|Apex Central|2019|AV:X|X|3|act=File deleted cs3Label=Virus_Malware_Name cs3=X dhost=ws filePath=C:\\a\\ fname=b.exe",
	"CEF:0|sophos|sophos central|1.0|Event::Endpoint::Threat::Detected|Malware detected: 'M' at 'C:\\a'|9|dhost=ws",
	"CEF:0|Bitdefender|GravityZone|6|av|Malware found|9|BitdefenderGZModule=av BitdefenderGZMalwareName=T dvc=192.0.2.1",
	"hello world\x00\r\n",
	"\xff\xfe\x00<13>",
}

func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m := Parse(b, now)
		if !utf8.ValidString(m.Raw) || !utf8.ValidString(m.Text) {
			t.Fatalf("invalid UTF-8 kept: %q", m.Raw)
		}
		if strings.Trim(string(b), "\x00\r\n\t ") != "" && m.Raw == "" {
			t.Fatalf("message lost: %q", b)
		}
		ev := m.Event(sender, now, 0)
		// The event time, and so the daily index, stays in the window.
		if ev.Model == "" || ev.Time.Before(now.Add(-DefaultMaxAge)) || ev.Time.After(now.Add(ingest.MaxEventAhead)) {
			t.Fatalf("model %q time %v", ev.Model, ev.Time)
		}
		avFieldsOK(t, ev)
		d := ev.Document()
		if _, err := json.Marshal(d); err != nil {
			t.Fatal(err)
		}
		extras := 0
		for k := range d {
			if isExtra(k) {
				extras++
			}
		}
		if extras > 4+maxExtraFields {
			t.Fatalf("%d extra fields", extras)
		}
	})
}

// frame is one result of framer.Next: a message, or what went wrong.
type frame struct {
	msg  string
	kind string // "", "too large", "bad framing" or "did not finish"
}

func readAll(r io.Reader, max, limit int) []frame {
	f := newFramer(r, max)
	var out []frame
	for range limit {
		msg, err := f.Next()
		switch {
		case err == nil:
			out = append(out, frame{msg: string(msg)})
		case errors.Is(err, errTooLarge):
			out = append(out, frame{kind: "too large"})
		case errors.Is(err, errFraming):
			return append(out, frame{kind: "bad framing"})
		default:
			return out
		}
	}
	return append(out, frame{kind: "did not finish"})
}

func FuzzFramer(f *testing.F) {
	f.Add([]byte("6 <13>hi\n<13>line\n6 <13>yo<13>last"), uint16(16))
	f.Add([]byte("16 <13>0123456789ab6 <13>ok\x00\r\n12 x\n"), uint16(10))
	f.Add([]byte("123456789 <13>x"), uint16(100))
	f.Fuzz(func(t *testing.T, b []byte, size uint16) {
		max := int(size%2048) + 1
		// Every call consumes at least one byte, so this many always ends.
		limit := len(b) + 2
		whole := readAll(bytes.NewReader(b), max, limit)
		for _, fr := range whole {
			if fr.kind == "did not finish" {
				t.Fatalf("framer did not finish on %q", b)
			}
			if len(fr.msg) > max {
				t.Fatalf("frame of %d bytes over the %d limit", len(fr.msg), max)
			}
		}
		// Reading in tiny pieces must give the same frames.
		bytewise := readAll(iotest.OneByteReader(bytes.NewReader(b)), max, limit)
		if !slices.Equal(whole, bytewise) {
			t.Fatalf("partial reads differ:\n%q\n%q", whole, bytewise)
		}
	})
}

// avFieldsOK checks what every antivirus event keeps, whatever was sent:
// fixed field names (known fields or prefixed extras), type and action
// from the closed lists, and bounded values.
func avFieldsOK(t *testing.T, ev ingest.Event) {
	t.Helper()
	for k, v := range ev.Fields {
		if !ingest.KnownField(k) && !isExtra(k) {
			t.Fatalf("field %q", k)
		}
		if s, ok := v.(string); ok && k != "message" && (!utf8.ValidString(s) || ev.Model == ingest.MalwareModel && len(s) > ingest.MaxValueLen) {
			t.Fatalf("%s: %d bytes", k, len(s))
		}
	}
	if ev.Model != ingest.MalwareModel {
		if ev.Fields["type"] != nil {
			t.Fatalf("%s event with type %v", ev.Model, ev.Fields["type"])
		}
		return
	}
	typ, _ := ev.Fields["type"].(string)
	action, _ := ev.Fields["action"].(string)
	if !ingest.ValidMalwareAction(typ, action) {
		t.Fatalf("type %q action %q", typ, action)
	}
	if s, _ := ev.Fields["signature"].(string); s == "" {
		t.Fatal("no signature")
	}
	if c, ok := ev.Fields["category"].(string); ok != (typ == ingest.MalwareThreat) || ok && !slices.Contains(ingest.MalwareCategories, c) {
		t.Fatalf("category %q on %s", c, typ)
	}
	if s, ok := ev.Fields["severity"].(string); ok && !slices.Contains(ingest.MalwareSeverities, s) {
		t.Fatalf("severity %q", s)
	}
	for _, k := range []string{"datamodel", ingest.SampleField} {
		if ev.Fields[k] != nil {
			t.Fatalf("%s set to %v", k, ev.Fields[k])
		}
	}
}

func FuzzLEEF(f *testing.F) {
	for _, s := range fuzzSeeds {
		if i := strings.Index(s, "LEEF:"); i >= 0 {
			f.Add(s[i:])
		}
	}
	f.Add("LEEF:2.0|V|P|1|E|x0|a=1")
	f.Add("LEEF:2.0|V|P|1|E|0xFFFF|a=1\uffffb=2")
	f.Fuzz(func(t *testing.T, s string) {
		l, ok := parseLEEF(s)
		if !ok {
			return
		}
		if len(l.Attributes) > maxLEEFAttributes || len(l.Vendor) > maxLEEFHeader || len(l.EventID) > maxLEEFHeader {
			t.Fatalf("%d attributes", len(l.Attributes))
		}
		for _, p := range l.Attributes {
			if !validLEEFKey(p.Name) {
				t.Fatalf("key %q", p.Name)
			}
		}
		m := Parse([]byte(s), now)
		avFieldsOK(t, m.Event(sender, now, 0))
	})
}

func FuzzSEP(f *testing.F) {
	for _, s := range fuzzSeeds {
		if i := strings.Index(s, "SymantecServer: "); i >= 0 {
			f.Add(s[i+len("SymantecServer: "):])
		}
	}
	f.Add("Security risk found,Risk name: ,Actual action: ,File size (bytes): -1")
	f.Fuzz(func(t *testing.T, s string) {
		name, pairs := splitSEP(s)
		if len(pairs) >= sepMaxSegments || len(name) > sepMaxText {
			t.Fatalf("%d pairs", len(pairs))
		}
		for _, p := range pairs {
			if sepKeyLen(p.Name+": ") != len(p.Name) {
				t.Fatalf("key %q", p.Name)
			}
		}
		m := Parse([]byte("<54>Oct 13 09:14:02 sepm-01 SymantecServer: "+s), now)
		ev := m.Event(sender, now, 0)
		avFieldsOK(t, ev)
	})
}

func FuzzEPO(f *testing.F) {
	for _, s := range fuzzSeeds {
		if i := strings.Index(s, "<EPOevent>"); i >= 0 {
			f.Add(s[i:])
		}
	}
	f.Add("<EPOevent><ThreatCategory>ops.update</ThreatCategory><ThreatName>fail &amp;#1;</ThreatName><TargetFileName>&lt;</TargetFileName></EPOevent>")
	f.Fuzz(func(t *testing.T, s string) {
		model, fields := parseEPO(s)
		avFieldsOK(t, ingest.Event{Model: model, Fields: fields})
		m := Parse([]byte("<29>1 2026-10-13T09:14:02.0Z epo-01 EPOEvents - - - "+s), now)
		avFieldsOK(t, m.Event(sender, now, 0))
	})
}
