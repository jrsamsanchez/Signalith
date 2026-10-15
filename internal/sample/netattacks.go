package sample

import (
	"fmt"
	"time"
)

// Stories the network sensor tells. Each is built from the recipe of one
// or more of the built-in network detections, as Zeek and Suricata log
// lines that go through the real parsers.

// Addresses of the network stories, in the documentation range used for
// the internet (outside the sample threat intel's 203.0.113.0/24).
const (
	ipFTPPartner = "198.51.100.91" // a partner's FTP server, ftp.partner.example
	ipScanner    = "198.51.100.66" // an internet host that finds a new service
)

// dgaLetters are the characters a domain generation algorithm uses.
const dgaLetters = "abcdefghijklmnopqrstuvwxyz"

// base32Letters are the characters of a DNS tunnel's encoded labels.
const base32Letters = "abcdefghijklmnopqrstuvwxyz234567"

func (g *gen) randomLabel(chars string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[g.rng.intn(len(chars))]
	}
	return string(b)
}

// zeekLookup adds a dns.log line of a lookup of qtype, answered with
// answer (a TXT or A record), or NXDOMAIN when nx is set.
func (g *gen) zeekLookup(src, query, qtype, answer string, nx bool, t time.Time) {
	dc := g.org.host("dc-01")
	fl := g.newFlow(src, dc.IP, 53)
	qtypes := map[string]int{"A": 1, "TXT": 16}
	rec := fl.ids(map[string]any{
		"proto": "udp", "trans_id": g.rng.intn(65536), "rtt": 0.0011 + float64(g.rng.intn(40))/10000,
		"query": query, "qclass": 1, "qclass_name": "C_INTERNET", "qtype": qtypes[qtype], "qtype_name": qtype,
		"AA": false, "TC": false, "RD": true, "RA": true, "Z": 0, "rejected": false,
	})
	switch {
	case nx:
		rec["rcode"], rec["rcode_name"] = 3, "NXDOMAIN"
	default:
		rec["rcode"], rec["rcode_name"] = 0, "NOERROR"
		if answer != "" {
			rec["answers"] = []any{answer}
			rec["TTLs"] = []any{60.0}
		}
	}
	g.b.zeek("dns", t, rec)
}

// dnsTunnel: an engineering workstation runs malware that first tries
// generated domain names until one resolves (a burst of NXDOMAIN), then
// talks to its server through DNS (TXT lookups with long encoded labels),
// then scans the internal network for SMB, which Zeek also notices.
func (g *gen) dnsTunnel() {
	ws := g.org.host("eng-ws-02")
	t0 := g.day(3, 10, 40)

	// The DGA: 32 generated names in about three minutes, none of which
	// exist, then one that does.
	for i := 0; i < 32; i++ {
		name := g.randomLabel(dgaLetters, 12+g.rng.intn(7)) + ".example"
		g.zeekLookup(ws.IP, name, "A", "", true, t0.Add(time.Duration(i*6)*time.Second))
	}
	const c2Name = "kqzvtrwplmnxab.example"
	g.zeekLookup(ws.IP, c2Name, "A", ipC2Beacon, false, t0.Add(200*time.Second))

	// The tunnel: 18 TXT lookups under one domain, each carrying 48
	// characters of base32 in its first label.
	tt := t0.Add(5 * time.Minute)
	for i := 0; i < 18; i++ {
		name := g.randomLabel(base32Letters, 48) + ".t.corp-sync.example"
		g.zeekLookup(ws.IP, name, "TXT", g.randomLabel(base32Letters, 32), false, tt.Add(time.Duration(i*17)*time.Second))
	}

	// The internal scan: SMB on 26 addresses in under a minute, most of
	// which do not answer (S0) or refuse (REJ).
	ts := t0.Add(12 * time.Minute)
	for i := 0; i < 26; i++ {
		dest := fmt.Sprintf("%s%d", netCompany, 70+i)
		fl := g.newFlow(ws.IP, dest, 445)
		state := "S0"
		if i%3 == 0 {
			state = "REJ"
		}
		g.zeekConnLog(fl, ts.Add(time.Duration(i*2)*time.Second), "", state, 0, 0, 0, true)
	}
	g.b.zeek("notice", ts.Add(55*time.Second), map[string]any{
		"note": "Scan::Address_Scan", "msg": ws.IP + " scanned at least 25 unique hosts on port 445/tcp in 0m50s",
		"sub": "local", "src": ws.IP, "p": 445, "peer_descr": "worker-1",
		"actions": []any{"Notice::ACTION_LOG"}, "suppress_for": 3600.0,
	})

	g.story(Story{
		ID:         "dns-tunnel-and-scan",
		Title:      "DNS tunnelling and an internal scan",
		Summary:    fmt.Sprintf("Malware on the engineering workstation %s looks for its server by trying 32 generated domain names that do not exist, finds %s, then hides its traffic in DNS: TXT lookups whose names carry 48 characters of encoded data. It then scans the internal network for SMB, which Zeek also reports as an address scan. Seen only by the network sensor.", ws.Name, c2Name),
		Detections: []string{"network-dns-nxdomain-burst", "network-dns-tunneling", "network-internal-scan", "network-zeek-scan-notice"},
	}, ts.Add(2*time.Minute), ws.Name, ws.IP)
}

// networkHygiene: everyday weaknesses the sensor shows: an admin signs in
// to the bastion over Telnet (the service the vulnerability scan also
// reports), a printer's admin page uses HTTP basic authentication, the
// file server uploads a report to a partner over FTP, the sensor drops
// packets during the nightly backup, and a test service on the web server
// answers the internet.
func (g *gen) networkHygiene() {
	t0 := g.day(1, 9, 5)
	jump := g.org.host("jump-01")
	itws := g.org.host("ws-it-03")

	// Telnet to the bastion: answered, so the password crossed the wire.
	fl := g.newFlow(itws.IP, jump.IP, 23)
	g.zeekConnLog(fl, t0, "", "SF", 820, 14200, 412.5, true)

	// The printer's admin page with basic authentication.
	ops := g.org.host("ws-ops-02")
	printer := netCompany + "240"
	fp := g.newFlow(ops.IP, printer, 80)
	tp := t0.Add(7 * time.Minute)
	g.b.zeek("http", tp, fp.ids(map[string]any{
		"trans_depth": 1, "method": "GET", "host": "printer-2f.corp.example", "uri": "/admin/network.html", "version": "1.1",
		"user_agent": userAgents[0], "request_body_len": 0, "response_body_len": 5120,
		"status_code": 200, "status_msg": "OK", "username": "admin", "password": "printer-default", "tags": []any{},
	}))
	g.zeekConnLog(fp, tp, "http", "SF", 640, 6200, 0.4, true)

	// A report uploaded to a partner over FTP.
	file := g.org.host("file-01")
	ff := g.newFlow(file.IP, ipFTPPartner, 21)
	tf := t0.Add(12 * time.Minute)
	for i, c := range [][2]string{{"USER", "northwind-upload"}, {"PASS", "<hidden>"}, {"STOR", "ftp://" + ipFTPPartner + "/inbound/q3-forecast.csv"}} {
		rec := ff.ids(map[string]any{
			"user": "northwind-upload", "password": "Summer2026!", "command": c[0], "arg": c[1],
			"reply_code": 230, "reply_msg": "Login successful.",
		})
		if c[0] == "STOR" {
			rec["reply_code"], rec["reply_msg"] = 226, "Transfer complete."
			rec["file_size"], rec["mime_type"] = 48213, "text/csv"
		}
		if c[0] == "USER" {
			rec["reply_code"], rec["reply_msg"] = 331, "Please specify the password."
		}
		g.b.zeek("ftp", tf.Add(time.Duration(i)*time.Second), rec)
	}
	g.zeekConnLog(ff, tf, "ftp", "SF", 610, 1400, 3.1, false)

	// The nightly backup floods the mirror port: Zeek misses 7.8% of
	// the traffic for an hour.
	tl := g.day(2, 1, 30)
	g.b.zeek("capture_loss", tl, map[string]any{
		"ts_delta": 3600.0, "peer": "worker-1", "gaps": 61022, "acks": 782300, "percent_lost": 7.8,
	})

	// A test service on web-01 answers the internet on 8443 (matching data
	// for network-new-inbound-service, which is off by default).
	web := g.org.host("web-01")
	fi := g.newFlow(ipScanner, web.IP, 8443)
	g.zeekConnLog(fi, t0.Add(20*time.Minute), "ssl", "SF", 520, 3400, 0.8, true)

	g.story(Story{
		ID:         "network-hygiene",
		Title:      "Clear-text sign-ins and a blind spot",
		Summary:    "Everyday weaknesses the network sensor shows: an admin signs in to the bastion jump-01 over Telnet (the service the vulnerability scan also reports), a user opens a printer's admin page with HTTP basic authentication, and the file server uploads a report to a partner over FTP, all sending passwords in clear text. During the nightly backup the sensor misses 7.8% of the traffic. A test service on web-01 also answers the internet on port 8443.",
		Detections: []string{"network-cleartext-credentials", "network-sensor-packet-loss"},
	}, tf.Add(2*time.Minute), "jump-01", "ws-it-03", "file-01", "nsm-01")
	g.addRunTime(tl.Add(time.Minute))
}
