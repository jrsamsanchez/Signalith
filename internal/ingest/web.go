package ingest

import (
	"cmp"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Web server access logs: Apache's and Nginx's own files, in the
// combined format both write by default (or the common format, which
// lacks the referrer and user agent, or Apache's vhost_combined, which
// starts with the virtual host). The Linux agent tails them; each line
// becomes a Web event with the fields of Splunk's Web data model.

// WebModel is the data model of web server requests.
const WebModel = "Web"

// WebTag is the Fluent Bit tag of the Linux agent's web access log tail.
const WebTag = "linux.web"

// WebChannel names web access log lines in test events (sigmacheck.Case),
// as a Windows channel names Windows events.
const WebChannel = "web:access"

// WebFields are the stored fields of the W3C names of web server log
// fields (lower case), which Sigma's webserver rules use. The rules put
// whole request targets (path and query) in cs-uri-query, so it is the
// url, as c-uri is in proxy logs.
var WebFields = map[string]string{
	"cs-method": "http_method", "cs-uri-query": "url", "c-uri": "url", "cs-uri": "url", "cs-uri-stem": "uri_path",
	"sc-status": "status", "cs-user-agent": "http_user_agent", "c-useragent": "http_user_agent",
	"cs-referer": "http_referrer", "cs-referrer": "http_referrer", "c-ip": "src", "cs-username": "user",
	"cs-version": "http_version", "sc-bytes": "bytes_out", "cs-host": "dest", "s-port": "dest_port",
}

// webMaxLine is how much of a line is read.
const webMaxLine = 16 << 10

// accessLineRe is a combined, common or vhost_combined line: [vhost[:port]]
// client ident user [time] "request" status bytes ["referrer" "agent"].
// Apache escapes " and \ in quoted values with a backslash.
var accessLineRe = regexp.MustCompile(`^(?:(\S+?)(?::(\d+))? )?(\S+) (\S+) (\S+) \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}|-) (\d+|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?`)

// parseWebRecord reads a record of the Linux agent's web access log tail:
// {log, file, hostname, date}.
func parseWebRecord(r map[string]any) Event {
	file := strings.ToLower(str(r, "file"))
	app, product := "apache", "Apache HTTP Server"
	if strings.Contains(file, "nginx") {
		app, product = "nginx", "Nginx"
	}
	host := truncateUTF8(CapValue(str(r, "hostname")), maxHostLen)
	line := truncateUTF8(str(r, "log"), webMaxLine)
	f := map[string]any{
		"host":           host,
		"dest":           host,
		"sourcetype":     app + ":access",
		"vendor_product": product,
		"app":            app,
		"message":        line,
	}
	ev := Event{Model: "Other", Fields: f}
	if t, ok := parseAccessLine(line, f); ok {
		ev.Model = WebModel
		ev.Time = t
	}
	return ev
}

// parseAccessLine maps an access log line onto the Web data model's
// fields, and returns the request's time.
func parseAccessLine(line string, f map[string]any) (time.Time, bool) {
	m := accessLineRe.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
	if m == nil {
		return time.Time{}, false
	}
	vhost, port, client, user, ts, request, status, size := m[1], m[2], m[3], m[5], m[6], unescapeAccess(m[7]), m[8], m[9]
	set := func(k, v string) {
		if v != "" && v != "-" {
			f[k] = CapValue(v)
		}
	}
	if vhost != "" {
		set("dest", vhost)
		if n, err := strconv.ParseInt(port, 10, 64); err == nil {
			f["dest_port"] = n
		}
	}
	set("src", client)
	set("user", user)
	set("status", status)
	if n, err := strconv.ParseInt(size, 10, 64); err == nil {
		f["bytes_out"] = n
	}
	if m[10] != "" || m[11] != "" {
		set("http_referrer", unescapeAccess(m[10]))
		if ua := unescapeAccess(m[11]); ua != "" && ua != "-" {
			f["http_user_agent"] = CapValue(ua)
			f["http_user_agent_length"] = int64(len(ua))
		}
	}
	// "GET /index.php?id=1 HTTP/1.1", whose target may hold spaces when a
	// client sent them; a request that is not one (a TLS handshake sent
	// to a plain HTTP port) is kept whole as the URL.
	method, url := "", request
	if m, rest, ok := strings.Cut(request, " "); ok && isHTTPMethod(m) {
		method, url = m, rest
		if i := strings.LastIndex(rest, " HTTP/"); i >= 0 {
			url = rest[:i]
			set("http_version", rest[i+len(" HTTP/"):])
		}
	}
	set("http_method", method)
	if url != "" && url != "-" {
		f["url"] = CapValue(url)
		f["url_length"] = int64(len(url))
		path, query, _ := strings.Cut(url, "?")
		set("uri_path", path)
		set("uri_query", query)
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", ts)
	if err != nil {
		return time.Time{}, true
	}
	return t, true
}

// isHTTPMethod reports whether a request line's first word is a method:
// letters (GET, PROPFIND, or get from a careless client).
func isHTTPMethod(s string) bool {
	if s == "" || len(s) > 20 {
		return false
	}
	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
			return false
		}
	}
	return true
}

// unescapeAccess undoes Apache's escaping of " and \ in a quoted value.
func unescapeAccess(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// escapeAccess is how Apache writes a quoted value.
func escapeAccess(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

// AccessLine is the combined-format line of a request, from Web data
// model fields (src, user, http_method, url, status, bytes_out,
// http_referrer, http_user_agent), for test events. A field left out is
// written as -, and a request without a method as its target alone.
func AccessLine(t time.Time, data map[string]string) string {
	or := func(k string) string {
		if v := data[k]; v != "" {
			return v
		}
		return "-"
	}
	request := data["url"]
	if m := data["http_method"]; m != "" {
		request = m + " " + cmp.Or(request, "/") + " HTTP/1.1"
	}
	return or("src") + " - " + or("user") + " [" + t.Format("02/Jan/2006:15:04:05 -0700") + `] "` +
		escapeAccess(request) + `" ` + or("status") + " " + or("bytes_out") + ` "` +
		escapeAccess(or("http_referrer")) + `" "` + escapeAccess(or("http_user_agent")) + `"`
}

// WebRecord is the record the Linux agent sends for an access log line
// (Normalize with WebTag).
func WebRecord(line, file, host string, t time.Time) map[string]any {
	return map[string]any{"log": line, "file": file, "hostname": host, "date": float64(t.Unix())}
}
