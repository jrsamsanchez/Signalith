package syslog

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParseLEEF(t *testing.T) {
	for _, c := range []struct {
		name, in string
		want     []Param
	}{
		{"1.0 tabs", "LEEF:1.0|IBM|QRadar|7.5|Login|src=192.0.2.1\tdst=192.0.2.2\tusrName=bob", []Param{{"src", "192.0.2.1"}, {"dst", "192.0.2.2"}, {"usrName", "bob"}}},
		{"1.0 spaces", "LEEF:1.0|IBM|QRadar|7.5|Login|src=192.0.2.1 dst=192.0.2.2 msg=hello world", []Param{{"src", "192.0.2.1"}, {"dst", "192.0.2.2"}, {"msg", "hello world"}}},
		{"version 1", "LEEF:1|V|P|1|E|a=1\tb=2", []Param{{"a", "1"}, {"b", "2"}}},
		{"2.0 caret", "LEEF:2.0|V|P|1|E|^|a=1^b=x y^c=", []Param{{"a", "1"}, {"b", "x y"}, {"c", ""}}},
		{"2.0 x09", "LEEF:2.0|V|P|1|E|x09|a=1\tb=2", []Param{{"a", "1"}, {"b", "2"}}},
		{"2.0 0x7C", "LEEF:2.0|V|P|1|E|0x7C|a=1|b=2", []Param{{"a", "1"}, {"b", "2"}}},
		{"2.0 empty delimiter", "LEEF:2.0|V|P|1|E||a=1\tb=2", []Param{{"a", "1"}, {"b", "2"}}},
		{"2.0 no delimiter field", "LEEF:2.0|V|P|1|E|a=1\tb=2|3", []Param{{"a", "1"}, {"b", "2|3"}}},
		{"2.0 letter delimiter is tab", "LEEF:2.0|V|P|1|E|x|a=1\tb=2", []Param{{"a", "1"}, {"b", "2"}}},
		{"2.0 equals delimiter is tab", "LEEF:2.0|V|P|1|E|x3D|a=1\tb=2", []Param{{"a", "1"}, {"b", "2"}}},
		{"bad keys skipped", "LEEF:1.0|V|P|1|E|a b=1\t=2\tnovalue\t" + strings.Repeat("k", 65) + "=3\tok=4\tk-x=5", []Param{{"ok", "4"}}},
		{"value with =", "LEEF:1.0|V|P|1|E|url=http://x/?a=b\tc= d ", []Param{{"url", "http://x/?a=b"}, {"c", "d"}}},
		{"no attributes", "LEEF:1.0|V|P|1|E|", []Param{}},
	} {
		l, ok := parseLEEF(c.in)
		if !ok {
			t.Errorf("%s: not LEEF", c.name)
			continue
		}
		if l.Vendor != strings.Split(c.in, "|")[1] || l.EventID != strings.Split(c.in, "|")[4] {
			t.Errorf("%s: header %+v", c.name, l)
		}
		if fmt.Sprint(l.Attributes) != fmt.Sprint(c.want) {
			t.Errorf("%s: %v, want %v", c.name, l.Attributes, c.want)
		}
	}
	for _, in := range []string{
		"LEEF:1.0|V|P|1",         // missing EventID
		"LEEF:1.0|V|P|1|E",       // no | after EventID
		"LEEF:3.0|V|P|1|E|a=1",   // bad version
		"LEEF:1.0a|V|P|1|E|a=1",  // bad version
		"LEEF:|V|P|1|E|a=1",      // no version
		"leef:1.0|V|P|1|E|a=1",   // case matters
		"XLEEF:1.0|V|P|1|E|a=1",  // not at the start
		"CEF:0|V|P|1|E|N|1|a=1 ", // CEF is CEF
	} {
		if _, ok := parseLEEF(in); ok {
			t.Errorf("%q read as LEEF", in)
		}
	}
	// Header fields are trimmed and capped.
	l, _ := parseLEEF("LEEF:1.0| V |" + strings.Repeat("p", 300) + "|1|E|a=1")
	if l.Vendor != "V" || len(l.Product) != 256 {
		t.Errorf("vendor %q product of %d bytes", l.Vendor, len(l.Product))
	}
}

func TestLEEFHeaderEscapes(t *testing.T) {
	l, ok := parseLEEF(`LEEF:1.0|Vendor\|X|P\\|1|Threat_Event|threatname=Foo` + "\tsrc=192.0.2.1")
	if !ok {
		t.Fatal("not LEEF")
	}
	if l.Vendor != "Vendor|X" || l.Product != `P\` || l.DeviceVersion != "1" || l.EventID != "Threat_Event" {
		t.Errorf("header %+v", l)
	}
	if fmt.Sprint(l.Attributes) != fmt.Sprint([]Param{{"threatname", "Foo"}, {"src", "192.0.2.1"}}) {
		t.Errorf("attributes %v", l.Attributes)
	}
	// An escape at the very end leaves the header unfinished.
	if _, ok := parseLEEF(`LEEF:1.0|V|P|1|E\|`); ok {
		t.Error("escaped last pipe read as a header end")
	}
}

func TestLEEFAttributeCap(t *testing.T) {
	var tabs, spaces []string
	for i := range 300 {
		tabs = append(tabs, fmt.Sprintf("k%d=v", i))
		spaces = append(spaces, fmt.Sprintf("k%d=v", i))
	}
	for _, in := range []string{
		"LEEF:1.0|V|P|1|E|" + strings.Join(tabs, "\t"),
		"LEEF:1.0|V|P|1|E|" + strings.Join(spaces, " "),
		"LEEF:2.0|V|P|1|E|^|" + strings.Join(tabs, "^"),
	} {
		l, ok := parseLEEF(in)
		if !ok || len(l.Attributes) != 256 || l.Attributes[255].Name != "k255" {
			t.Errorf("%.30q: %d attributes", in, len(l.Attributes))
		}
	}
}

func TestLEEFEvent(t *testing.T) {
	d := doc("<134>Oct 12 13:59:00 qradar LEEF:2.0|Lancope|StealthWatch|1.0|41|^|src=10.0.6.40^dst=10.0.6.1^srcPort=50000^dstPort=443^proto=6^usrName=alice^srcBytes=100^dstBytes=200^sev=6^devTime=1791813540000^cat=Flow^identHostName=ws-1^custom=x")
	check(t, "leef", d, map[string]any{
		"_model": "Network_Traffic", "sourcetype": "leef", "vendor_product": "Lancope StealthWatch", "signature": "41", "signature_id": "41",
		"leef_version": "2.0", "leef_vendor": "Lancope", "leef_product": "StealthWatch", "leef_device_version": "1.0",
		"src": "10.0.6.40", "dest": "10.0.6.1", "src_port": int64(50000), "dest_port": int64(443), "transport": "tcp", "user": "alice",
		"bytes_out": int64(100), "bytes_in": int64(200), "bytes": int64(300), "severity": "medium", "severity_id": int64(6),
		"category": "Flow", "src_host": "ws-1", "leef_custom": "x", "host": "qradar", "@timestamp": "2026-10-12T13:59:00Z",
	})
	// devTime as text.
	d = doc("<134>Oct 12 13:59:00 qradar LEEF:1.0|V|P|1|E|devTime=Oct 12 2026 13:58:30\tdevTimeFormat=MMM dd yyyy HH:mm:ss\tsrc=192.0.2.1")
	check(t, "devTime text", d, map[string]any{"@timestamp": "2026-10-12T13:58:30Z", "_model": "Other", "leef_devtimeformat": nil})
	// No syslog header at all.
	d = doc("LEEF:1.0|V|P|1|E|src=192.0.2.1\tdst=192.0.2.2")
	check(t, "bare", d, map[string]any{"_model": "Network_Traffic", "sourcetype": "leef", "host": "192.0.2.50"})
}

func TestLEEFReservedKeys(t *testing.T) {
	d := doc("LEEF:1.0|V|P|1|E|datamodel=Risk\tsignalith_sample=x\ttype=threat\t_id=1\tmessage=m\t@timestamp=2001")
	check(t, "reserved", d, map[string]any{"datamodel": "Other", "signalith_sample": nil, "type": nil,
		"leef_datamodel": "Risk", "leef_signalith_sample": "x", "leef_type": "threat", "leef_id": "1", "leef_message": "m"})
	if d["@timestamp"] == "2001" {
		t.Error("sender set @timestamp")
	}
}

func TestLEEFHeaderWithoutHostname(t *testing.T) {
	// RFC 3164 with no host name: the record must not be split into a host
	// name or a program tag.
	for _, line := range []string{
		"<134>Oct 12 13:59:00 LEEF:1.0|ESET|PROTECT|11|Threat_Event|threat_name=X\thostname=ws-1",
		"<134>LEEF:1.0|ESET|PROTECT|11|Threat_Event|threat_name=X\thostname=ws-1",
	} {
		m := Parse([]byte(line), now)
		if m.LEEF == nil || m.Hostname != "" || m.AppName != "" {
			t.Errorf("%q: LEEF %v host %q app %q", line, m.LEEF != nil, m.Hostname, m.AppName)
		}
		d := doc(line)
		check(t, line, d, map[string]any{"_model": "Malware", "host": "192.0.2.50", "dest": "ws-1", "signature": "X"})
	}
}

func TestLEEFExtrasAreCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString("LEEF:1.0|V|P|1|E|")
	for i := range 200 {
		fmt.Fprintf(&b, "key%d=v\t", i)
	}
	m := Parse([]byte(b.String()), now)
	ev := m.Event(sender, now, 0)
	extras := 0
	for k := range ev.Fields {
		if strings.HasPrefix(k, "leef_") {
			extras++
		}
	}
	// leef_version, leef_vendor, leef_product and leef_device_version are
	// known fields on top of the budget.
	if extras > 4+maxExtraFields || extras < maxExtraFields {
		t.Errorf("%d leef_ fields", extras)
	}
	if !isExtra("leef_x") {
		t.Error("leef_ is not an extra")
	}
}

func TestLEEFTimeIsBounded(t *testing.T) {
	m := Parse([]byte("LEEF:1.0|V|P|1|E|devTime=1"), now)
	ev := m.Event(sender, now, 0)
	if !ev.Time.Equal(now) || ev.DeviceTime.IsZero() {
		t.Errorf("time %v device time %v", ev.Time, ev.DeviceTime)
	}
	m = Parse([]byte("LEEF:1.0|V|P|1|E|devTime="+fmt.Sprint(now.Add(-time.Minute).UnixMilli())), now)
	ev = m.Event(sender, now, 0)
	if !ev.Time.Equal(now.Add(-time.Minute)) {
		t.Errorf("time %v", ev.Time)
	}
}
