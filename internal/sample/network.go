package sample

import (
	"encoding/base64"
	"time"
)

// The network sensor: a Linux box (nsm-01) on a mirror port that runs
// Zeek and Suricata and sends their logs through Fluent Bit. Its events
// are built as the real log lines and go through the real parsers, so
// they fill the network data models (Network_Traffic, Network_Resolution,
// Web, Certificates, File_Transfers, Intrusion_Detection) and the Network
// dashboard the way a live sensor does.

// webSites are the ordinary internet sites the workstations visit, each
// with its address in the upper half of TEST-NET-2 (clear of the sample's
// malicious addresses) and a certificate issuer.
var webSites = []struct{ name, ip, issuer string }{
	{"portal.saas.example", "198.51.100.110", "CN=Example Issuing CA 1,O=Example Trust,C=US"},
	{"mail.provider.example", "198.51.100.121", "CN=Example Issuing CA 1,O=Example Trust,C=US"},
	{"cdn.assets.example", "198.51.100.134", "CN=Example Web CA,O=Example PKI,C=GB"},
	{"docs.office.example", "198.51.100.142", "CN=Example Issuing CA 2,O=Example Trust,C=US"},
	{"meet.video.example", "198.51.100.157", "CN=Example Web CA,O=Example PKI,C=GB"},
	{"crm.sales.example", "198.51.100.163", "CN=Example Issuing CA 2,O=Example Trust,C=US"},
	{"news.media.example", "198.51.100.178", "CN=Example Web CA,O=Example PKI,C=GB"},
	{"files.share.example", "198.51.100.189", "CN=Example Issuing CA 1,O=Example Trust,C=US"},
}

// updatesHost is a benign update service fetched over plain HTTP.
const updatesHost = "updates.vendor.example"

// nxNames are names nobody answers for: stale shortcuts and mistyped
// shares, the usual NXDOMAIN noise of an office.
var nxNames = []string{"oldshare.corp.example", "printer-3f.corp.example", "wpad.corp.example", "intranet2.corp.example"}

// userAgents are the browsers and tools seen in the sample's web requests.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.90 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
	"Microsoft-Delivery-Optimization/10.0",
	"SampleUpdater/3.2",
}

// sampleSensorAlerts are the INFO and POLICY style rules that fire now and
// then on ordinary traffic. Their SIDs (9100001-9100010) are made up.
var sampleSensorAlerts = []struct {
	sid      int
	sig, cat string
	sev      int
}{
	{9100001, "SAMPLE POLICY curl User-Agent Outbound", "Attempted Information Leak", 2},
	{9100002, "SAMPLE INFO TLS certificate expiring soon", "Misc activity", 3},
	{9100003, "SAMPLE POLICY Software update check over HTTP", "Potential Corporate Privacy Violation", 3},
	{9100004, "SAMPLE INFO Observed DNS query to a dynamic DNS domain", "Potentially Bad Traffic", 2},
	{9100005, "SAMPLE POLICY Cleartext password over HTTP", "Potential Corporate Privacy Violation", 2},
	{9100006, "SAMPLE INFO Packed executable download", "Misc activity", 3},
}

// workstations returns the company's Windows workstations, the usual
// clients on the sensor's link.
func (g *gen) workstations() []Host {
	var out []Host
	for _, h := range g.org.windowsHosts() {
		if h.Category == "workstation" {
			out = append(out, h)
		}
	}
	return out
}

// zeekUID returns a Zeek connection UID: "C" and 17 letters and digits.
func (g *gen) zeekUID(prefix byte) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 18)
	b[0] = prefix
	for i := 1; i < len(b); i++ {
		b[i] = chars[g.rng.intn(len(chars))]
	}
	return string(b)
}

// communityID returns a Community ID ("1:" and a base64 SHA-1). Here it is
// random, not computed from the flow: it only has to tie the events of one
// flow together, which it does.
func (g *gen) communityID() string {
	b := make([]byte, 20)
	for i := range b {
		b[i] = byte(g.rng.intn(256))
	}
	return "1:" + base64.StdEncoding.EncodeToString(b)
}

// flowID returns a Suricata flow ID, a large positive integer.
func (g *gen) flowID() int64 {
	return int64(g.rng.next() >> 12)
}

// sensorFlow is one connection the sensor saw: its 4-tuple, Zeek UID and
// Community ID, shared by the events about it.
type sensorFlow struct {
	src, dest         string
	srcPort, destPort int
	uid, cid          string
}

func (g *gen) newFlow(src, dest string, destPort int) sensorFlow {
	return sensorFlow{src: src, dest: dest, srcPort: 49152 + g.rng.intn(16000), destPort: destPort,
		uid: g.zeekUID('C'), cid: g.communityID()}
}

// ids returns a Zeek record with the flow's id.* keys, UID and Community
// ID, plus extra. It also says which ends are in Site::local_nets
// (local_orig, local_resp), as conn.log does: the sample's own addresses
// are a documentation range, which the parser would otherwise count as
// outside, so every log of a flow says it, and the web, TLS and DNS
// events get the same direction as the connection.
func (f sensorFlow) ids(extra map[string]any) map[string]any {
	r := map[string]any{"uid": f.uid, "id.orig_h": f.src, "id.orig_p": f.srcPort,
		"id.resp_h": f.dest, "id.resp_p": f.destPort, "community_id": f.cid,
		"local_orig": Internal(f.src), "local_resp": Internal(f.dest)}
	for k, v := range extra {
		r[k] = v
	}
	return r
}

// zeekConnLog adds the conn.log line of a finished flow that started at
// t. The sample's own addresses are a documentation range, so the sensor
// is told they are in Site::local_nets: the client is when it is one of
// the company's, and localResp says whether the server is.
func (g *gen) zeekConnLog(fl sensorFlow, t time.Time, service, state string, out, in int, dur float64, localResp bool) {
	rec := fl.ids(map[string]any{
		"proto": "tcp", "duration": dur, "orig_bytes": out, "resp_bytes": in,
		"conn_state": state, "local_orig": Internal(fl.src), "local_resp": localResp, "missed_bytes": 0,
		"orig_pkts": 4 + out/1000, "resp_pkts": 3 + in/1400,
		"orig_ip_bytes": out + 200, "resp_ip_bytes": in + 160,
	})
	if service != "" {
		rec["service"] = service
	}
	switch state {
	case "SF":
		rec["history"] = "ShADadFf"
	case "S0":
		rec["history"] = "S"
	case "REJ":
		rec["history"] = "Sr"
	}
	g.b.zeek("conn", t, rec)
}

// zeekDNSLog adds a dns.log line: src asked the domain controller, which
// answered with answer, or NXDOMAIN when answer is empty.
func (g *gen) zeekDNSLog(src, query, answer string, t time.Time) {
	dc := g.org.host("dc-01")
	fl := sensorFlow{src: src, dest: dc.IP, srcPort: 49152 + g.rng.intn(16000), destPort: 53, uid: g.zeekUID('C'), cid: g.communityID()}
	rec := fl.ids(map[string]any{
		"proto": "udp", "trans_id": g.rng.intn(65536), "rtt": 0.0009 + float64(g.rng.intn(40))/10000,
		"query": query, "qclass": 1, "qclass_name": "C_INTERNET", "qtype": 1, "qtype_name": "A",
		"AA": false, "TC": false, "RD": true, "RA": true, "Z": 0, "rejected": false,
	})
	if answer == "" {
		rec["rcode"], rec["rcode_name"] = 3, "NXDOMAIN"
	} else {
		rec["rcode"], rec["rcode_name"] = 0, "NOERROR"
		rec["answers"] = []any{answer}
		rec["TTLs"] = []any{300.0}
	}
	g.b.zeek("dns", t, rec)
}

// zeekTLS adds the ssl.log line of a TLS session, with the certificate's
// names and Zeek's validation status (ssl/validate-certs loaded).
func (g *gen) zeekTLS(fl sensorFlow, t time.Time, sni, subject, issuer, status string) {
	g.b.zeek("ssl", t, fl.ids(map[string]any{
		"version": "TLSv13", "cipher": "TLS_AES_128_GCM_SHA256", "curve": "x25519",
		"server_name": sni, "resumed": false, "established": true, "next_protocol": "h2",
		"subject": subject, "issuer": issuer, "validation_status": status,
		"cert_chain_fps": []any{g.hexString(64)},
		"ja3":            "e7d705a3286e19ea42f587b344ee6865", "ja3s": "f4febc55ea12b31ae17cfb7e614afda8",
	}))
}

// zeekCert adds the x509.log line of a certificate.
func (g *gen) zeekCert(t time.Time, subject, issuer, san string, from, to time.Time) {
	g.b.zeek("x509", t, map[string]any{
		"fingerprint":         g.hexString(64),
		"certificate.version": 3, "certificate.serial": g.hexString(16),
		"certificate.subject": subject, "certificate.issuer": issuer,
		"certificate.not_valid_before": float64(from.Unix()), "certificate.not_valid_after": float64(to.Unix()),
		"certificate.key_alg": "rsaEncryption", "certificate.sig_alg": "sha256WithRSAEncryption",
		"certificate.key_type": "rsa", "certificate.key_length": 2048,
		"san.dns": []any{san}, "basic_constraints.ca": false,
		"host_cert": true, "client_cert": false,
	})
}

func (g *gen) hexString(n int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hex[g.rng.intn(16)]
	}
	return string(b)
}

// zeekWeb adds an HTTP request: its http.log line, and the files.log line
// of the response body when mime is set.
func (g *gen) zeekWeb(fl sensorFlow, t time.Time, method, host, uri string, status int, ua, mime string, size int, sha256 string) {
	rec := fl.ids(map[string]any{
		"trans_depth": 1, "method": method, "host": host, "uri": uri, "version": "1.1",
		"user_agent": ua, "request_body_len": 0, "response_body_len": size,
		"status_code": status, "status_msg": statusText(status), "tags": []any{},
	})
	if mime != "" {
		fuid := g.zeekUID('F')
		rec["resp_fuids"] = []any{fuid}
		rec["resp_mime_types"] = []any{mime}
		file := fl.ids(map[string]any{
			"fuid": fuid, "source": "HTTP", "depth": 0, "analyzers": []any{"SHA256", "MD5", "SHA1"},
			"mime_type": mime, "duration": 0.12, "is_orig": false, "seen_bytes": size, "total_bytes": size,
			"missing_bytes": 0, "overflow_bytes": 0, "timedout": false,
			"md5": g.hexString(32), "sha1": g.hexString(40),
		})
		if sha256 == "" {
			sha256 = g.hexString(64)
		}
		file["sha256"] = sha256
		if i := lastSlash(uri); i >= 0 && i+1 < len(uri) {
			file["filename"] = uri[i+1:]
		}
		g.b.zeek("files", t.Add(200*time.Millisecond), file)
	}
	g.b.zeek("http", t, rec)
}

func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}

func statusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 304:
		return "Not Modified"
	case 404:
		return "Not Found"
	}
	return ""
}

// eveAlert adds a Suricata alert on a flow. Alerts on a response (a
// download) go from the server to the client, as Suricata writes them.
func (g *gen) eveAlert(fl sensorFlow, t time.Time, toClient bool, sid int, sig, category string, severity int, mitre []string, app string, extra map[string]any) {
	src, sport, dest, dport, dir := fl.src, fl.srcPort, fl.dest, fl.destPort, "to_server"
	if toClient {
		src, sport, dest, dport, dir = fl.dest, fl.destPort, fl.src, fl.srcPort, "to_client"
	}
	meta := map[string]any{"signature_severity": []any{map[int]string{1: "Major", 2: "Minor", 3: "Informational"}[severity]}}
	if len(mitre) > 0 {
		meta["mitre_technique_id"] = toAny(mitre)
	}
	rec := map[string]any{
		"flow_id": g.flowID(), "in_iface": "ens192", "event_type": "alert",
		"src_ip": src, "src_port": sport, "dest_ip": dest, "dest_port": dport, "proto": "TCP",
		"pkt_src": "wire/pcap", "community_id": fl.cid, "direction": dir, "app_proto": app,
		"alert": map[string]any{
			"action": "allowed", "gid": 1, "signature_id": sid, "rev": 1, "signature": sig,
			"category": category, "severity": severity, "metadata": meta,
		},
	}
	for k, v := range extra {
		rec[k] = v
	}
	g.b.eve(t, rec)
}

// networkBackground adds a day of what the sensor sees on an ordinary
// office network: web browsing over TLS (DNS lookup, connection, TLS
// session), update checks over HTTP, file share and directory traffic to
// the servers, failed lookups, the sensor's own health every hour, and a
// few low and medium IDS alerts. Nothing here fires a detection.
func (g *gen) networkBackground(day window) {
	ws := g.workstations()
	n := 400
	if g.size == SizeSmall {
		n = 40
	}
	for k := 0; k < n; k++ {
		t := g.rng.timeIn(day.start, day.end)
		h := ws[g.rng.intn(len(ws))]
		switch r := g.rng.intn(20); {
		case r < 11: // browsing over TLS
			site := webSites[g.rng.intn(len(webSites))]
			g.zeekDNSLog(h.IP, site.name, site.ip, t)
			fl := g.newFlow(h.IP, site.ip, 443)
			ts := t.Add(40 * time.Millisecond)
			g.zeekTLS(fl, ts, site.name, "CN="+site.name, site.issuer, "ok")
			out, in := 900+g.rng.intn(4000), 4000+g.rng.intn(400000)
			g.zeekConnLog(fl, ts, "ssl", "SF", out, in, float64(1+g.rng.intn(900))/10, false)
		case r < 14: // update checks over plain HTTP
			g.zeekDNSLog(h.IP, updatesHost, ipUpdates, t)
			fl := g.newFlow(h.IP, ipUpdates, 80)
			ts := t.Add(30 * time.Millisecond)
			ua := userAgents[2+g.rng.intn(2)]
			if g.rng.chance(1, 3) {
				g.zeekWeb(fl, ts, "GET", updatesHost, "/v2/packages/catalog.cab", 200, ua, "application/vnd.ms-cab-compressed", 180000+g.rng.intn(90000), "")
			} else if g.rng.chance(1, 4) {
				g.zeekWeb(fl, ts, "GET", updatesHost, "/v2/manifest-old.json", 404, ua, "", 0, "")
			} else {
				g.zeekWeb(fl, ts, "GET", updatesHost, "/v2/manifest.json", 200, ua, "", 1200+g.rng.intn(800), "")
			}
			g.zeekConnLog(fl, ts, "http", "SF", 420, 1600+g.rng.intn(200000), 1.8, false)
		case r < 19: // file share and directory traffic, inside the company
			srv, port, svc := g.org.host("file-01"), 445, "smb,gssapi"
			if g.rng.chance(1, 3) {
				srv, port, svc = g.org.host("dc-01"), 389, "ldap"
			}
			fl := g.newFlow(h.IP, srv.IP, port)
			g.zeekConnLog(fl, t, svc, "SF", 2000+g.rng.intn(90000), 3000+g.rng.intn(900000), float64(5+g.rng.intn(6000))/10, true)
		default: // a name nobody answers for
			g.zeekDNSLog(h.IP, nxNames[g.rng.intn(len(nxNames))], "", t)
		}
	}

	// The odd low or medium alert on ordinary traffic.
	alerts := 12
	if g.size == SizeSmall {
		alerts = 3
	}
	for k := 0; k < alerts; k++ {
		t := g.rng.timeIn(day.start, day.end)
		h := ws[g.rng.intn(len(ws))]
		a := sampleSensorAlerts[g.rng.intn(len(sampleSensorAlerts))]
		site := webSites[g.rng.intn(len(webSites))]
		fl := g.newFlow(h.IP, site.ip, 80)
		g.eveAlert(fl, t, false, a.sid, a.sig, a.cat, a.sev, nil, "http", map[string]any{
			"http": map[string]any{"hostname": site.name, "url": "/", "http_method": "GET", "protocol": "HTTP/1.1",
				"http_user_agent": "curl/8.5.0", "status": 200, "length": 512},
		})
	}

	// A printer's management page with a self-signed certificate, the
	// usual benign entry on the self-signed list.
	if g.rng.chance(1, 2) {
		h := ws[g.rng.intn(len(ws))]
		t := g.rng.timeIn(day.start, day.end)
		fl := g.newFlow(h.IP, netCompany+"240", 443)
		g.zeekTLS(fl, t, "printer-2f.corp.example", "CN=printer-2f.corp.example,O=Printer", "CN=printer-2f.corp.example,O=Printer", "self signed certificate")
		g.zeekConnLog(fl, t, "ssl", "SF", 1400, 22000, 3.9, true)
	}

	// The sensor's health, every hour: Zeek's capture loss and stats, and
	// Suricata's stats.
	var pkts int64
	for t := day.start.Truncate(time.Hour).Add(time.Hour); t.Before(day.end); t = t.Add(time.Hour) {
		loss := float64(g.rng.intn(50)) / 100 // 0 - 0.49 percent
		g.b.zeek("capture_loss", t, map[string]any{
			"ts_delta": 3600.0, "peer": "worker-1", "gaps": g.rng.intn(40), "acks": 90000 + g.rng.intn(40000), "percent_lost": loss,
		})
		got := int64(800000 + g.rng.intn(400000))
		pkts += got
		g.b.zeek("stats", t, map[string]any{
			"peer": "worker-1", "mem": 412, "pkts_proc": got, "bytes_recv": got * 700, "pkts_dropped": int64(g.rng.intn(200)),
			"pkts_link": got, "pkt_lag": 0.004, "events_proc": got * 3, "events_queued": got * 3, "active_tcp_conns": 180 + g.rng.intn(90),
		})
		drops := int64(g.rng.intn(int(got / 400)))
		g.b.eve(t, map[string]any{
			"event_type": "stats",
			"stats": map[string]any{
				"uptime":  int(t.Sub(g.start).Seconds()),
				"capture": map[string]any{"kernel_packets": pkts, "kernel_drops": drops},
				"decoder": map[string]any{"pkts": pkts, "bytes": pkts * 700},
			},
		})
	}
}

// sensorDownload is the network side of the phishing story's download:
// the workstation fetches the implant over plain HTTP from the address
// that served the phishing document. Zeek logs the request and the file
// (whose SHA-256 is in the sample threat intel) and Suricata raises a
// high alert.
func (g *gen) sensorDownload(ws Host, t time.Time) {
	fl := g.newFlow(ws.IP, ipPhishHost, 80)
	ua := "Microsoft-CryptoAPI/10.0" // certutil's user agent
	g.zeekWeb(fl, t, "GET", ipPhishHost, "/update.exe", 200, ua, "application/x-dosexec", 73802, hashBeacon)
	g.zeekConnLog(fl, t, "http", "SF", 310, 74400, 1.6, false)
	g.eveAlert(fl, t.Add(400*time.Millisecond), true, 9100101, "SAMPLE MALWARE Executable download from a known bad host",
		"A Network Trojan was detected", 1, []string{"T1105"}, "http", map[string]any{
			"http": map[string]any{"hostname": ipPhishHost, "url": "/update.exe", "http_user_agent": ua,
				"http_content_type": "application/x-dosexec", "http_method": "GET", "protocol": "HTTP/1.1", "status": 200, "length": 73802},
		})
	g.b.eve(t.Add(500*time.Millisecond), map[string]any{
		"flow_id": g.flowID(), "in_iface": "ens192", "event_type": "fileinfo",
		"src_ip": ipPhishHost, "src_port": 80, "dest_ip": ws.IP, "dest_port": fl.srcPort, "proto": "TCP",
		"community_id": fl.cid, "app_proto": "http",
		"http": map[string]any{"hostname": ipPhishHost, "url": "/update.exe", "http_method": "GET", "status": 200},
		"fileinfo": map[string]any{"filename": "/update.exe", "magic": "PE32+ executable (GUI) x86-64, for MS Windows",
			"gaps": false, "state": "CLOSED", "sha256": hashBeacon, "stored": false, "size": 73802, "tx_id": 0},
	})
}

// sensorBeacon is the network side of the implant's command and control:
// a lookup of the C2 domain, then a TLS session to the C2 address with a
// self-signed certificate every ten minutes or so for an hour, and a
// Suricata alert on the beacon.
func (g *gen) sensorBeacon(ws Host, t time.Time) {
	const c2Name = "updates.corp-sync.example"
	g.zeekDNSLog(ws.IP, c2Name, ipC2Beacon, t.Add(-2*time.Second))
	subject := "CN=" + c2Name + ",O=Default Company Ltd,C=XX"
	g.zeekCert(t, subject, subject, c2Name, t.AddDate(0, 0, -3), t.AddDate(1, 0, -3))
	for i := 0; i < 6; i++ {
		ts := t.Add(time.Duration(i*10)*time.Minute + time.Duration(g.rng.intn(40))*time.Second)
		fl := g.newFlow(ws.IP, ipC2Beacon, 443)
		g.zeekTLS(fl, ts, c2Name, subject, subject, "self signed certificate")
		g.zeekConnLog(fl, ts, "ssl", "SF", 1800+g.rng.intn(400), 900+g.rng.intn(300), 2.9, false)
		if i == 0 {
			g.eveAlert(fl, ts.Add(300*time.Millisecond), false, 9100102, "SAMPLE MALWARE Beacon to command and control server",
				"A Network Trojan was detected", 1, []string{"T1071.001"}, "tls", map[string]any{
					"tls": map[string]any{"sni": c2Name, "version": "TLS 1.3", "subject": subject, "issuerdn": subject},
				})
		}
	}
}
