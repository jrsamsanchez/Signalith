package syslog

import (
	"strings"
	"testing"
)

func TestEPOValues(t *testing.T) {
	s := `<A>x &lt;y&gt; &amp;amp; &quot;q&quot; &apos;a&apos; &#65; &#x41;</A><B>one</B><B>two</B><C>open<D attr="1" ProductName="P &amp; Q">`
	if got := epoValue(s, "A"); got != `x <y> &amp; "q" 'a' &#65; &#x41;` {
		t.Errorf("entities: %q", got)
	}
	if got := epoValue(s, "B"); got != "one" {
		t.Errorf("duplicate tags: %q", got)
	}
	if got := epoValue(s, "C"); got != "" {
		t.Errorf("unclosed tag: %q", got)
	}
	if got := epoValue(s, "Z"); got != "" {
		t.Errorf("missing tag: %q", got)
	}
	if got := epoAttr(s, "ProductName"); got != "P & Q" {
		t.Errorf("attribute: %q", got)
	}
	if got := epoValue("<A>"+strings.Repeat("v", 10<<10)+"</A>", "A"); len(got) != 4096 {
		t.Errorf("value of %d bytes", len(got))
	}
}

func epoEvent(common string) string {
	return `<29>1 2026-10-12T13:14:02.0Z epo-01 EPOEvents - EventFwd - <?xml version="1.0"?><EPOevent><MachineInfo><MachineName>WS-2</MachineName></MachineInfo><SoftwareInfo ProductName="McAfee Endpoint Security"><Event><EventID>1059</EventID><CommonFields>` +
		common + `</CommonFields></Event></SoftwareInfo></EPOevent>`
}

func TestEPOEvents(t *testing.T) {
	for _, c := range []struct {
		common string
		want   map[string]any
	}{
		{`<ThreatCategory>av.detect</ThreatCategory><ThreatName>EICAR test file</ThreatName><ThreatActionTaken>IDS_ALERT_ACT_TAK_CLE</ThreatActionTaken><ThreatSeverity>0</ThreatSeverity>`,
			map[string]any{"_model": "Malware", "type": "threat", "action": "cleaned", "category": "test", "severity": "critical", "dest": "WS-2", "vendor_product": "McAfee Endpoint Security"}},
		{`<ThreatCategory>av.detect</ThreatCategory><ThreatName>X</ThreatName><ThreatActionTaken>IDS_ALERT_ACT_TAK_DEN</ThreatActionTaken><ThreatSeverity>5</ThreatSeverity>`,
			map[string]any{"action": "blocked", "severity": "low"}},
		{`<ThreatCategory>av.detect</ThreatCategory><ThreatName>X</ThreatName><ThreatActionTaken>IDS_ALERT_ACT_TAK_MOV</ThreatActionTaken><ThreatSeverity>9</ThreatSeverity>`,
			map[string]any{"action": "quarantined", "severity": nil, "vendor_severity": "9"}},
		{`<ThreatCategory>av.detect</ThreatCategory><ThreatName>X</ThreatName><ThreatActionTaken>Would delete</ThreatActionTaken>`,
			map[string]any{"action": "detected"}},
		{`<ThreatCategory>av.detect</ThreatCategory><ThreatName>X</ThreatName><ThreatActionTaken>IDS_ALERT_ACT_TAK_DEL</ThreatActionTaken><ThreatHandled>false</ThreatHandled>`,
			map[string]any{"action": "failed"}},
		{`<ThreatCategory>av.detect</ThreatCategory><SourceIPV4>203.0.113.5</SourceIPV4><SourceHostName>file-01</SourceHostName><TargetHash>44D88612FEA8A8F36DE82E1278ABB02F</TargetHash><SourceUserName>bob</SourceUserName>`,
			map[string]any{"signature": "Unknown threat", "src": "203.0.113.5", "src_host": "file-01", "file_md5": "44d88612fea8a8f36de82e1278abb02f", "user": "bob"}},
		{`<ThreatCategory>ops.update.end</ThreatCategory><ThreatName>Update Failed</ThreatName>`,
			map[string]any{"_model": "Malware", "type": "health", "action": "update_failed", "signature": "Definitions update failed", "category": nil}},
		{`<ThreatCategory>ops.update.end</ThreatCategory><ThreatName>Update succeeded</ThreatName>`,
			map[string]any{"_model": "Other", "type": nil, "signature": "Update succeeded", "app": "EPOEvents"}},
		{`<ThreatCategory>fw.block</ThreatCategory><ThreatName>Blocked</ThreatName>`,
			map[string]any{"_model": "Other", "type": nil}},
	} {
		d := doc(epoEvent(c.common))
		if d["_model"] == "Malware" {
			checkMalware(t, c.common, d)
		}
		check(t, c.common, d, map[string]any{"sourcetype": "trellix:epo", "host": "epo-01", "signature_id": "1059"})
		check(t, c.common, d, c.want)
	}
}

func TestEPOFraming(t *testing.T) {
	// A BOM before the XML, and a program name the relay changed.
	d := doc("<29>1 2026-10-12T13:14:02.0Z epo-01 relay - - - \ufeff" + epoExample)
	check(t, "bom", d, map[string]any{"_model": "Malware", "signature": "Generic.abc", "vendor_product": "Trellix Endpoint Security"})
	// No ProductName.
	d = doc(`<29>1 2026-10-12T13:14:02.0Z epo-01 EPOEvents - - - <EPOevent><ThreatCategory>av.detect</ThreatCategory></EPOevent>`)
	check(t, "no product", d, map[string]any{"vendor_product": "Trellix ePO"})
	// Truncated XML.
	d = doc(epoExample[:len(epoExample)/2])
	check(t, "truncated", d, map[string]any{"sourcetype": "trellix:epo"})
	// Tags past the first 64 KB are not read.
	d = doc(`<29>1 2026-10-12T13:14:02.0Z epo-01 EPOEvents - - - <EPOevent><Pad>` + strings.Repeat("x", 70<<10) + `</Pad><ThreatCategory>av.detect</ThreatCategory></EPOevent>`)
	check(t, "70 KB", d, map[string]any{"_model": "Other", "type": nil})
	// Reserved names inside the XML are just text.
	d = doc(epoEvent(`<ThreatCategory>av.detect</ThreatCategory><datamodel>Risk</datamodel><signalith_sample>x</signalith_sample><type>health</type>`))
	check(t, "reserved", d, map[string]any{"datamodel": "Malware", "signalith_sample": nil, "type": "threat"})
}
