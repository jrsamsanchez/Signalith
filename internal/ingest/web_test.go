package ingest

import (
	"testing"
	"time"
)

func TestWebAccessLog(t *testing.T) {
	// Nginx's combined format.
	line := `203.0.113.7 - - [11/Oct/2026:11:58:01 +0000] "GET /index.php?page=../../etc/passwd HTTP/1.1" 404 153 "-" "sqlmap/1.8"`
	ev := Normalize(WebTag, WebRecord(line, "/var/log/nginx/access.log", "web-01", now), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Web", "sourcetype": "nginx:access", "vendor_product": "Nginx", "app": "nginx",
		"host": "web-01", "dest": "web-01", "src": "203.0.113.7", "http_method": "GET",
		"url": "/index.php?page=../../etc/passwd", "uri_path": "/index.php", "uri_query": "page=../../etc/passwd",
		"url_length": int64(32), "status": "404", "bytes_out": int64(153), "http_user_agent": "sqlmap/1.8",
		"http_user_agent_length": int64(10), "http_version": "1.1", "message": line,
		"@timestamp": "2026-10-11T11:58:01Z",
	})
	if _, ok := ev.Fields["http_referrer"]; ok {
		t.Errorf("- kept as a referrer: %v", ev.Fields)
	}
	// Apache's vhost_combined, with an escaped quote and a user.
	line = `shop.example.com:443 198.51.100.4 - alice [11/Oct/2026:13:58:01 +0200] "POST /login HTTP/2.0" 302 - "https://shop.example.com/" "Mozilla/5.0 \"x\""`
	ev = Normalize(WebTag, WebRecord(line, "/var/log/apache2/other_vhosts_access.log", "web-02", now), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Web", "sourcetype": "apache:access", "vendor_product": "Apache HTTP Server", "host": "web-02",
		"dest": "shop.example.com", "dest_port": int64(443), "src": "198.51.100.4", "user": "alice", "http_method": "POST",
		"url": "/login", "status": "302", "http_referrer": "https://shop.example.com/", "http_user_agent": `Mozilla/5.0 "x"`,
		"@timestamp": "2026-10-11T11:58:01Z",
	})
	if _, ok := ev.Fields["bytes_out"]; ok {
		t.Errorf("- kept as a size: %v", ev.Fields)
	}
	// The common format, a request that is not HTTP, and a line that is
	// not an access log line.
	line = `192.0.2.1 - - [11/Oct/2026:11:58:01 +0000] "\x16\x03\x01" 400 157`
	ev = Normalize(WebTag, WebRecord(line, "/var/log/httpd/access_log", "web-03", now), now)
	expect(t, ev.Document(), map[string]any{"datamodel": "Web", "url": `\x16\x03\x01`, "status": "400"})
	if _, ok := ev.Fields["http_method"]; ok {
		t.Errorf("method of a request that is not HTTP: %v", ev.Fields)
	}
	ev = Normalize(WebTag, WebRecord("AH00558: apache2: Could not reliably determine the server's name", "/var/log/apache2/access.log", "web-03", now), now)
	if ev.Model != "Other" || ev.Fields["sourcetype"] != "apache:access" {
		t.Errorf("not an access line = %s %v", ev.Model, ev.Fields)
	}
	// A request with a space in its target, as a client sent it.
	line = AccessLine(time.Date(2026, 10, 11, 11, 0, 0, 0, time.UTC), map[string]string{"http_method": "GET", "url": `/a b?q="1"`, "http_user_agent": `x\y`, "status": "200"})
	ev = Normalize(WebTag, WebRecord(line, "/var/log/nginx/access.log", "web-01", now), now)
	expect(t, ev.Document(), map[string]any{"datamodel": "Web", "url": `/a b?q="1"`, "http_method": "GET", "http_user_agent": `x\y`, "status": "200"})
	// Without a method or a status: the target alone, and -.
	line = AccessLine(time.Date(2026, 10, 11, 11, 0, 0, 0, time.UTC), map[string]string{"url": "/x"})
	ev = Normalize(WebTag, WebRecord(line, "/var/log/nginx/access.log", "web-01", now), now)
	expect(t, ev.Document(), map[string]any{"datamodel": "Web", "url": "/x", "http_method": nil, "status": nil, "src": nil})
}
