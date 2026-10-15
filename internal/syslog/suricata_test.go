package syslog

import (
	"testing"
)

// pfSense and OPNsense send Suricata's EVE log over syslog, one JSON event
// after the program's tag.
const eveAlert = `{"timestamp":"2026-10-12T13:58:59.250311+0000","flow_id":1805461738637437123,"in_iface":"igb1","event_type":"alert",` +
	`"src_ip":"203.0.113.80","src_port":80,"dest_ip":"192.168.1.20","dest_port":50112,"proto":"TCP",` +
	`"alert":{"action":"allowed","gid":1,"signature_id":2014520,"rev":7,"signature":"ET INFO EXE - Served Attached HTTP",` +
	`"category":"Misc activity","severity":1},"app_proto":"http","payload":"R0VU","host":"fw-01"}`

const eveAlertNoHost = `{"timestamp":"2026-10-12T13:58:59.250311+0000","flow_id":7,"event_type":"alert","src_ip":"192.168.1.20",` +
	`"src_port":50112,"dest_ip":"203.0.113.80","dest_port":443,"proto":"TCP","alert":{"action":"blocked","signature_id":2033966,` +
	`"signature":"ET MALWARE Observed Malicious SSL Cert","category":"Domain Observed Used for C2 Detected","severity":2}}`

func TestSuricataSyslogEVE(t *testing.T) {
	for _, line := range []string{
		"<133>Oct 12 13:59:00 pfsense suricata[48211]: " + eveAlert,
		"<133>1 2026-10-12T13:59:00Z pfsense suricata 48211 - - " + eveAlert,
	} {
		d := doc(line)
		check(t, line, d, map[string]any{
			"_model": "Intrusion_Detection", "signature_id": "2014520", "severity": "high", "severity_id": int64(1),
			"src": "203.0.113.80", "dest": "192.168.1.20", "vendor_product": "Suricata", "sourcetype": "suricata:alert",
			// The time is the event's, the host its sensor-name, and dvc
			// the address that sent it.
			"@timestamp": "2026-10-12T13:58:59.250311Z", "host": "fw-01", "dvc": "192.0.2.50",
			"session_id": "1805461738637437123", "payload": nil, "facility": "local0",
		})
		if m := d["message"].(string); m[0] != '{' || len(m) >= len(eveAlert) {
			t.Errorf("%s: message is not the EVE JSON without its payload: %s", line, m)
		}
	}
	// No sensor-name: the syslog header's host name, else the sender.
	line := "<133>Oct 12 13:59:00 opnsense suricata[1]: " + eveAlertNoHost
	check(t, line, doc(line), map[string]any{"_model": "Intrusion_Detection", "host": "opnsense", "action": "blocked", "severity": "medium"})
	line = "<133>" + eveAlertNoHost
	check(t, line, doc(line), map[string]any{"_model": "Intrusion_Detection", "host": "192.0.2.50"})
	m := Parse([]byte("<133>Oct 12 13:59:00 pfsense suricata[48211]: "+eveAlert), now)
	if ev := m.Event(sender, now, 0); ev.ID == "" {
		t.Error("no document ID: a resent message would be stored twice")
	}
}

func TestSuricataSyslogNotEVE(t *testing.T) {
	for _, line := range []string{
		`<134>Oct 12 13:59:00 app1 svc: {"level":"info","msg":"started","event_type":"login"}`,
		"<133>Oct 12 13:59:00 pfsense suricata[48211]: " + eveAlert[:len(eveAlert)/2],
		"<133>Oct 12 13:59:00 pfsense suricata[48211]: 10/12/2026-13:58:59.250311  [**] [1:2014520:7] ET INFO EXE [**]",
	} {
		d := doc(line)
		if d["vendor_product"] == "Suricata" || d["_model"] == "Intrusion_Detection" || d["message"].(string)[0] != '<' {
			t.Errorf("%s: %v", line, d)
		}
	}
}
