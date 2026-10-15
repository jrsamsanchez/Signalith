package ingest

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

func TestNetDirection(t *testing.T) {
	for _, c := range []struct{ src, dest, lo, lr, want string }{
		{"192.168.1.5", "198.51.100.1", "", "", "outbound"},
		{"198.51.100.1", "10.0.0.5", "", "", "inbound"},
		{"10.0.0.1", "172.16.4.4", "", "", "internal"},
		{"198.51.100.1", "203.0.113.5", "", "", "external"},
		{"100.64.1.1", "fd00::1", "", "", "internal"},
		{"fe80::1%eth0", "2001:db8::1", "", "", "outbound"},
		{"::ffff:192.168.1.1", "8.8.8.8", "", "", "outbound"},
		// Zeek's flags win over the addresses: Site::local_nets knows.
		{"198.51.100.1", "203.0.113.5", "T", "F", "outbound"},
		{"192.168.1.5", "192.168.1.6", "false", "true", "inbound"},
		{"192.168.1.5", "", "", "", ""},
		{"", "192.168.1.5", "", "", ""},
		{"not an ip", "192.168.1.5", "", "", "inbound"},
	} {
		if got := netDirection(c.src, c.dest, c.lo, c.lr); got != c.want {
			t.Errorf("netDirection(%q, %q, %q, %q) = %q, want %q", c.src, c.dest, c.lo, c.lr, got, c.want)
		}
	}
	for ip, want := range map[string]bool{"127.0.0.1": true, "169.254.1.1": true, "::1": true, "100.127.255.255": true,
		"100.128.0.0": false, "172.32.0.1": false, "192.0.2.1": false, "": false} {
		if localAddr(ip) != want {
			t.Errorf("localAddr(%q) = %v", ip, !want)
		}
	}
}

func TestDecodeSensorLine(t *testing.T) {
	r, ok := decodeSensorLine(` {"flow_id":1805461738637437123,"a":{"b":1.5}} `)
	if !ok || r["flow_id"].(json.Number).String() != "1805461738637437123" {
		t.Fatalf("decode: %v %v", r, ok)
	}
	for _, s := range []string{"", "{", "[1]", `{"a":1}{"b":2}`, `{"a":1} x`, "null", `"x"`,
		"{" + strings.Repeat(`"a":[`, 40) + strings.Repeat("]", 40) + "}",
		`{"a":"` + strings.Repeat("x", maxSensorLine) + `"}`} {
		if _, ok := decodeSensorLine(s); ok {
			t.Errorf("decoded %.40q", s)
		}
	}
}

func TestScrubSensitive(t *testing.T) {
	r := map[string]any{
		"password": "x", "payload": "x", "packet": "x", "keep": 1,
		"http":   map[string]any{"http_request_body": "x", "http_response_body": "x", "http_response_body_printable": "x", "url": "/"},
		"app":    map[string]any{"password": "x"},
		"list":   []any{map[string]any{"password": "x", "ok": 1}},
		"nested": map[string]any{"deeper": map[string]any{"packet": "x"}},
		// One that is not a whole character at the cut.
		"payload_printable": strings.Repeat("a", maxPayloadPrintable-1) + "é" + "tail",
	}
	if !scrubSensitive(r) {
		t.Fatal("nothing changed")
	}
	b, _ := json.Marshal(r)
	for _, k := range []string{"password", `"payload"`, "packet", "body"} {
		if strings.Contains(string(b), k) {
			t.Errorf("%s left: %s", k, b)
		}
	}
	if p := r["payload_printable"].(string); len(p) != maxPayloadPrintable-1 || r["keep"] != 1 {
		t.Errorf("payload_printable %d bytes", len(p))
	}
	// Suricata's ftp PASS argument and VNC challenge and response.
	r = map[string]any{
		"ftp": map[string]any{"command": "PASS", "command_data": "s3cret"},
		"rfb": map[string]any{"authentication": map[string]any{"vnc": map[string]any{"challenge": "c", "response": "r"}, "security_type": 2}},
	}
	if !scrubSensitive(r) {
		t.Fatal("ftp and rfb: nothing changed")
	}
	if b, _ := json.Marshal(r); strings.Contains(string(b), "s3cret") || strings.Contains(string(b), "challenge") || strings.Contains(string(b), "response") {
		t.Errorf("ftp or rfb secret left: %s", b)
	}
	if scrubSensitive(map[string]any{"ftp": map[string]any{"command": "USER", "command_data": "anonymous"}}) {
		t.Error("changed an ftp USER record")
	}
	if scrubSensitive(map[string]any{"a": 1, "payload_printable": "short"}) {
		t.Error("changed a record with nothing to drop")
	}
}

func TestSensorHelpers(t *testing.T) {
	if a, b := sensorDocID("zeek:conn", "x"), sensorDocID("zeek:dns", "x"); a == b || len(a) != 32 || strings.ToLower(a) != a {
		t.Errorf("IDs %q %q", a, b)
	}
	if sensorDocID("zeek:conn", "x") != sensorDocID("zeek:conn", "x") {
		t.Error("ID not stable")
	}
	for _, c := range []struct {
		r    map[string]any
		want string
	}{
		{map[string]any{"hostname": "nsm-01", "host": "web.example"}, "nsm-01"},
		{map[string]any{"host": "web.example", "_node_name": "worker-1"}, "worker-1"}, // Zeek http.log's host is the web server
		{map[string]any{"host": "nsm-02", "event_type": "alert"}, "nsm-02"},
		{map[string]any{"peer": "zeek"}, "zeek"},
		{map[string]any{"host": "web.example"}, ""},
	} {
		if got := sensorHost(c.r); got != c.want {
			t.Errorf("sensorHost(%v) = %q", c.r, got)
		}
	}
	for in, want := range map[string]string{
		"2001:0db8:0000:0000:0000:0000:0000:0010": "2001:db8::10", "::ffff:192.0.2.1": "192.0.2.1",
		"192.0.2.1": "192.0.2.1", "not an ip": "not an ip", "": "",
	} {
		if got := canonIP(in); got != want {
			t.Errorf("canonIP(%q) = %q", in, got)
		}
	}
	if lowerHash(" AA:bb:0C ") != "aabb0c" {
		t.Error("lowerHash")
	}
	for v, want := range map[any]any{json.Number("12"): int64(12), json.Number("0.5"): 0.5, "7": int64(7), 3.0: int64(3),
		2.5: 2.5, "x": nil, true: nil, json.Number("1e400"): nil} {
		if got := numberOf(v); got != want {
			t.Errorf("numberOf(%#v) = %#v", v, got)
		}
	}
	for dn, want := range map[string]string{
		"CN=www.example.com,O=Example Ltd,C=US":  "www.example.com",
		"C=US, O=Acme, CN=c2.example":            "c2.example",
		`CN=a\, b,O=x`:                           `a\, b`,
		"/C=US/O=Example/CN=old.example.com":     "old.example.com",
		"O=No Common Name":                       "",
		"emailAddress=a@example.com,cn=lower.ex": "lower.ex",
	} {
		if got := commonName(dn); got != want {
			t.Errorf("commonName(%q) = %q", dn, got)
		}
	}
	for _, c := range []struct {
		host, uri string
		port      any
		want      string
	}{
		{"a.example", "/x?y=1", json.Number("80"), "http://a.example/x?y=1"},
		{"a.example", "/x", int64(8080), "http://a.example:8080/x"},
		{"a.example:81", "/x", nil, "http://a.example:81/x"},
		{"a.example", "x", nil, "http://a.example/x"},
		{"a.example", "http://b.example/p", nil, "http://b.example/p"},
		{"", "/x", nil, ""},
	} {
		if got := webURL("http", c.host, c.uri, c.port); got != c.want {
			t.Errorf("webURL(%q, %q, %v) = %q", c.host, c.uri, c.port, got)
		}
	}
	if replyCode("nxdomain") != "NXDomain" || replyCode("NOERROR") != "NoError" || replyCode("BADVERS") != "BADVERS" {
		t.Error("replyCode")
	}
}

func TestNormalizeDispatchSensor(t *testing.T) {
	zeekLine := sensorLines(t, "zeek", "conn.json")[0]
	eveLine := sensorLines(t, "suricata", "eve.json")[0]
	for _, c := range []struct {
		name, tag string
		rec       map[string]any
		model, st string
	}{
		{"zeek tag", "zeek.conn", map[string]any{"log": zeekLine}, "Network_Traffic", "zeek:conn"},
		{"suricata tag", "suricata.eve", map[string]any{"log": eveLine}, "Intrusion_Detection", "suricata:alert"},
		// The tag wins over the shape: an EVE line under a Zeek tag is
		// not guessed into something else, and the other way round.
		{"eve under zeek tag", "zeek.conn", map[string]any{"log": eveLine}, "Network_Traffic", "zeek:conn"},
		{"zeek under suricata tag", "suricata.eve", map[string]any{"log": zeekLine}, "Other", "suricata:unknown"},
		// Decoded records are recognized by their shape under any tag.
		{"zeek shape, no tag", "", decode(t, zeekLine), "Network_Traffic", "zeek:conn"},
		{"zeek shape, other tag", "http", decode(t, zeekLine), "Network_Traffic", "zeek:conn"},
		{"eve shape, no tag", "", decode(t, eveLine), "Intrusion_Detection", "suricata:alert"},
		{"eve shape, other tag", "http", decode(t, eveLine), "Intrusion_Detection", "suricata:alert"},
		// A syslog line is still a syslog line.
		{"linux auth", "linux.auth", map[string]any{"log": "Oct 11 09:15:02 web1 sshd[811]: Failed password for bob from 192.0.2.4 port 1 ssh2"}, "Authentication", "linux:auth"},
		{"linux auth with JSON", "linux.auth", map[string]any{"log": zeekLine}, "Other", ""},
	} {
		ev := Normalize(c.tag, c.rec, now)
		if ev.Model != c.model || (c.st != "" && ev.Fields["sourcetype"] != c.st) {
			t.Errorf("%s: %s %v", c.name, ev.Model, ev.Fields["sourcetype"])
		}
	}
}

// idBulk records the IDs of the documents it is sent and refuses a second
// document with the same ID, as OpenSearch's create does.
type idBulk struct {
	ids  []string
	seen map[string]bool
}

func (b *idBulk) Bulk(_ context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	if b.seen == nil {
		b.seen = map[string]bool{}
	}
	var errs []store.BulkItemError
	for i, d := range docs {
		b.ids = append(b.ids, d.ID)
		if d.ID != "" && b.seen[d.Index+"/"+d.ID] {
			errs = append(errs, store.BulkItemError{Index: d.Index, Pos: i, Status: 409, Type: "version_conflict_engine_exception"})
			continue
		}
		b.seen[d.Index+"/"+d.ID] = true
	}
	return errs, nil
}

func TestIngestSensorIDs(t *testing.T) {
	b := &idBulk{}
	p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}
	lines := sensorLines(t, "zeek", "conn.json")
	records := []map[string]any{{"log": lines[0]}, {"log": lines[1]}, {"msg": "a JSON record from a script"}}
	res, err := p.Ingest(context.Background(), "zeek.conn", records[:2])
	if err != nil || res.Indexed != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := p.Ingest(context.Background(), "app", records[2:]); err != nil {
		t.Fatal(err)
	}
	if len(b.ids) != 3 || b.ids[0] == "" || b.ids[1] == "" || b.ids[0] == b.ids[1] || b.ids[2] != "" {
		t.Fatalf("ids = %q", b.ids)
	}
	if b.ids[0] != Normalize("zeek.conn", records[0], now).ID {
		t.Error("ID is not the event's")
	}
	// Fluent Bit sends the batch again after a 503: nothing is stored twice.
	res, err = p.Ingest(context.Background(), "zeek.conn", records[:2])
	if err != nil || res.Duplicates != 2 || res.Rejected != 0 || res.Indexed != 2 {
		t.Fatalf("resend: %+v %v", res, err)
	}
	// So through IngestBody, whatever position the line has in a body.
	body, _ := json.Marshal([]map[string]any{{"log": "unrelated"}, records[1]})
	res, err = p.IngestBody(context.Background(), "zeek.conn", body)
	if err != nil || res.Duplicates != 1 || res.Indexed != 2 {
		t.Fatalf("body: %+v %v", res, err)
	}
	if got := b.ids[len(b.ids)-1]; got != b.ids[1] {
		t.Errorf("IngestBody used %q, not the sensor ID %q", got, b.ids[1])
	}
}
