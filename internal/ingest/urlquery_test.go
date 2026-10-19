// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRedactQuery(t *testing.T) {
	for in, want := range map[string]string{
		"os=win&ver=10":       "os=REDACTED&ver=REDACTED",
		"token=abc&empty=":    "token=REDACTED&empty=",
		"justavalue":          "REDACTED",
		"a=1&&b=2":            "a=REDACTED&&b=REDACTED",
		"q=a%3Db&next=/x?y=z": "q=REDACTED&next=REDACTED",
	} {
		if got := redactQuery(in); got != want {
			t.Errorf("redactQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

// urlQueryDocs sends a Zeek http.log line, an Apache line and a Suricata
// http event through a pipeline in mode, and returns their documents.
func urlQueryDocs(t *testing.T, mode string) []map[string]any {
	t.Helper()
	fs := &fakeBulk{}
	p := &Pipeline{Store: fs, Prefix: "t", Now: func() time.Time { return now }}
	p.SetURLQuery(mode)
	zeek := `{"ts":1791720030.0,"uid":"Cq1","id.orig_h":"192.168.10.21","id.orig_p":50000,"id.resp_h":"198.51.100.7","id.resp_p":80,"method":"GET","host":"app.example.com","uri":"/login?user=bob&token=s3cr3tT0ken","referrer":"http://app.example.com/start?session=abc123","status_code":200}`
	if _, err := p.Ingest(context.Background(), "zeek.opt.zeek.logs.current.http.log", []map[string]any{{"log": zeek, "hostname": "nsm-01"}}); err != nil {
		t.Fatal(err)
	}
	apache := `203.0.113.9 - - [11/Oct/2026:12:00:00 +0000] "GET /reset.php?key=hunter2&id=7 HTTP/1.1" 200 512 "https://www.example.com/a?ref=mail" "curl/8.5.0"`
	if _, err := p.Ingest(context.Background(), WebTag, []map[string]any{{"log": apache, "hostname": "web-01", "file": "/var/log/apache2/access.log"}}); err != nil {
		t.Fatal(err)
	}
	eve := `{"timestamp":"2026-10-11T12:00:00.000000+0000","flow_id":1234,"event_type":"http","src_ip":"192.168.10.21","src_port":50001,"dest_ip":"198.51.100.7","dest_port":80,"proto":"TCP","http":{"hostname":"app.example.com","url":"/api?apikey=AKIA0000SECRET","http_method":"GET","status":200}}`
	if _, err := p.Ingest(context.Background(), "suricata.eve", []map[string]any{{"log": eve, "hostname": "nsm-01"}}); err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, d := range fs.docs {
		out = append(out, d.Doc)
	}
	if len(out) != 3 {
		t.Fatalf("%d documents", len(out))
	}
	return out
}

func TestURLQueryModes(t *testing.T) {
	secrets := []string{"s3cr3tT0ken", "abc123", "hunter2", "ref=mail", "AKIA0000SECRET", "bob"}
	keep := urlQueryDocs(t, URLQueryKeep)
	expect(t, keep[0], map[string]any{"url": "http://app.example.com/login?user=bob&token=s3cr3tT0ken", "uri_query": "user=bob&token=s3cr3tT0ken"})

	red := urlQueryDocs(t, URLQueryRedact)
	expect(t, red[0], map[string]any{
		"url": "http://app.example.com/login?user=REDACTED&token=REDACTED", "uri_query": "user=REDACTED&token=REDACTED",
		"uri_path": "/login", "http_referrer": "http://app.example.com/start?session=REDACTED",
	})
	expect(t, red[1], map[string]any{"url": "/reset.php?key=REDACTED&id=REDACTED", "uri_query": "key=REDACTED&id=REDACTED",
		"http_referrer": "https://www.example.com/a?ref=REDACTED", "url_length": int64(len("/reset.php?key=REDACTED&id=REDACTED"))})
	expect(t, red[2], map[string]any{"url": "http://app.example.com/api?apikey=REDACTED"})
	if msg := red[0]["message"].(string); !strings.Contains(msg, `/login?user=REDACTED&token=REDACTED`) &&
		!strings.Contains(msg, `/login?user=REDACTED&token=REDACTED`) {
		t.Errorf("Zeek raw: %s", msg)
	}
	if msg := red[1]["message"].(string); !strings.Contains(msg, `"GET /reset.php?key=REDACTED&id=REDACTED HTTP/1.1"`) {
		t.Errorf("Apache raw: %s", msg)
	}

	drop := urlQueryDocs(t, URLQueryDrop)
	expect(t, drop[0], map[string]any{"url": "http://app.example.com/login", "uri_query": nil, "uri_path": "/login",
		"http_referrer": "http://app.example.com/start"})
	expect(t, drop[1], map[string]any{"url": "/reset.php", "uri_query": nil, "http_referrer": "https://www.example.com/a"})
	expect(t, drop[2], map[string]any{"url": "http://app.example.com/api"})
	if msg := drop[1]["message"].(string); !strings.Contains(msg, `"GET /reset.php HTTP/1.1"`) {
		t.Errorf("Apache raw: %s", msg)
	}

	for _, docs := range [][]map[string]any{red, drop} {
		for _, d := range docs {
			for k, v := range d {
				s, _ := v.(string)
				for _, sec := range secrets {
					if sec == "bob" && k != "message" && k != "url" && k != "uri_query" {
						continue
					}
					if strings.Contains(s, sec) {
						t.Errorf("%s %s keeps %q: %s", d["sourcetype"], k, sec, s)
					}
				}
			}
		}
	}
}

func TestURLQueryRawForms(t *testing.T) {
	// The query written in two forms in one raw event: both go.
	f := map[string]any{"url": "http://a.example/x?token=abc", "message": `{"u":"http://a.example/x?token=abc","v":"x?token=abc"}`}
	ApplyURLQuery(f, URLQueryDrop)
	if strings.Contains(f["message"].(string), "abc") {
		t.Errorf("message = %v", f["message"])
	}
	// A payload that carries the request again is cleaned too.
	f = map[string]any{"url": "/x?pw=hunter2", "suricata_payload_printable": "GET /x?pw=hunter2 HTTP/1.1\r\n", "message": "{}"}
	ApplyURLQuery(f, URLQueryRedact)
	if p := f["suricata_payload_printable"].(string); strings.Contains(p, "hunter2") {
		t.Errorf("payload = %q", p)
	}
	// Keep and unknown modes change nothing; an address without a query
	// or an empty one is left as it is.
	for _, m := range []string{URLQueryKeep, "", "bogus"} {
		f = map[string]any{"url": "/x?pw=1", "message": "/x?pw=1"}
		ApplyURLQuery(f, m)
		if f["url"] != "/x?pw=1" || f["message"] != "/x?pw=1" {
			t.Errorf("%q: %v", m, f)
		}
	}
	f = map[string]any{"url": "/x?", "message": "a?b /x?"}
	ApplyURLQuery(f, URLQueryDrop)
	if f["url"] != "/x" || f["message"] != "a?b /x?" {
		t.Errorf("empty query: %v", f)
	}
}

func TestURLQueryRawEscapes(t *testing.T) {
	// CEF writes = as \= inside a value: the raw line holds the query
	// in that form.
	f := map[string]any{"sourcetype": "cef", "url": "http://x.example/a?token=abc&u=1",
		"message": `CEF:0|Zscaler|NSS|1|1|Allowed|3|request=http://x.example/a?token\=abc&u\=1 cs1=web`}
	ApplyURLQuery(f, URLQueryRedact)
	if msg := f["message"].(string); strings.Contains(msg, "abc") || !strings.Contains(msg, `?token\=REDACTED&u\=REDACTED cs1=web`) {
		t.Errorf("CEF redact: %s", msg)
	}
	f = map[string]any{"sourcetype": "cef", "url": "http://x.example/a?token=abc",
		"message": `CEF:0|Zscaler|NSS|1|1|Allowed|3|request=http://x.example/a?token\=abc cs1=web`}
	ApplyURLQuery(f, URLQueryDrop)
	if msg := f["message"].(string); msg != `CEF:0|Zscaler|NSS|1|1|Allowed|3|request=http://x.example/a cs1=web` {
		t.Errorf("CEF drop: %s", msg)
	}
	// Apache writes " and \ as \" and \\.
	line := `1.2.3.4 - - [11/Oct/2026:12:00:00 +0000] "GET /a?q=say\"hi\"&pw=x\\y HTTP/1.1" 200 1 "-" "-"`
	f = map[string]any{"sourcetype": "apache:access", "url": `/a?q=say"hi"&pw=x\y`, "message": line}
	ApplyURLQuery(f, URLQueryRedact)
	if msg := f["message"].(string); strings.Contains(msg, "hi") || strings.Contains(msg, `x\\y`) ||
		!strings.Contains(msg, `"GET /a?q=REDACTED&pw=REDACTED HTTP/1.1"`) {
		t.Errorf("Apache: %s", msg)
	}
	// A query cut short in its field goes whole from the raw text.
	long := strings.Repeat("J", 6000)
	raw := `"GET /sso?SAMLRequest=` + long + `&next=1 HTTP/1.1"`
	for _, m := range []string{URLQueryRedact, URLQueryDrop} {
		f = map[string]any{"sourcetype": "nginx:access", "url": CapValue("/sso?SAMLRequest=" + long + "&next=1"), "message": raw}
		ApplyURLQuery(f, m)
		msg := f["message"].(string)
		if strings.Contains(msg, "JJJ") {
			t.Errorf("%s: the cut query's end stays: %.80s", m, msg)
		}
		if m == URLQueryRedact && msg != `"GET /sso?SAMLRequest=REDACTED&next=REDACTED HTTP/1.1"` {
			t.Errorf("redact: %s", msg)
		}
		if m == URLQueryDrop && msg != `"GET /sso HTTP/1.1"` {
			t.Errorf("drop: %s", msg)
		}
	}
	// JSON inside JSON: the escaped quote that ends the address stays.
	f = map[string]any{"sourcetype": "suricata:alert", "message": `{"x":"{\"url\":\"/a?k=v\"}"}`}
	ApplyURLQuery(f, URLQueryRedact)
	if msg := f["message"].(string); msg != `{"x":"{\"url\":\"/a?k=REDACTED\"}"}` {
		t.Errorf("nested JSON: %s", msg)
	}
	// Other names of web addresses, and query strings no field holds.
	f = map[string]any{"url_original": "https://a.example/cb?code=abc", "url_query": "code=abc", "http_url": "/x?sid=abc",
		"http_target": "/y?sid=abc", "request": "GET /z?sid=abc HTTP/1.1", "http_redirect": "https://a.example/?code=abc",
		"zeek_uri": "/w?sid=abc", "suricata_detail": `{"uri":"/v?sid=abc","method":"GET"}`, "sourcetype": "zeek:http2",
		"message": `{"uri":"/w?sid=abc"}`}
	ApplyURLQuery(f, URLQueryRedact)
	for k, v := range f {
		if s, _ := v.(string); strings.Contains(s, "abc") {
			t.Errorf("%s keeps the value: %s", k, s)
		}
	}
	if f["request"] != "GET /z?sid=REDACTED HTTP/1.1" || f["url_query"] != "code=REDACTED" {
		t.Errorf("request %v, url_query %v", f["request"], f["url_query"])
	}
	// A question in other events' raw text is theirs.
	f = map[string]any{"sourcetype": "WinEventLog:Security", "message": "powershell iwr http://a.example/x?k=v"}
	ApplyURLQuery(f, URLQueryDrop)
	if f["message"] != "powershell iwr http://a.example/x?k=v" {
		t.Errorf("Windows: %v", f["message"])
	}
}

func TestURLQuerySuricataWithoutHost(t *testing.T) {
	fs := &fakeBulk{}
	p := &Pipeline{Store: fs, Prefix: "t", Now: func() time.Time { return now }}
	p.SetURLQuery(URLQueryRedact)
	eve := `{"timestamp":"2026-10-11T12:00:00.000000+0000","flow_id":1,"event_type":"alert","src_ip":"203.0.113.9","src_port":4000,"dest_ip":"192.168.10.5","dest_port":80,"proto":"TCP",` +
		`"alert":{"signature":"ET WEB test","signature_id":1,"severity":2},` +
		`"http":{"url":"/admin?token=tok3n","http_refer":"http://evil.example/r?sid=s1d","redirect":"https://idp.example/cb?code=c0de"},` +
		`"payload_printable":"GET /admin?token=tok3n HTTP/1.0\r\n\r\n"}`
	if _, err := p.Ingest(context.Background(), "suricata.eve", []map[string]any{{"log": eve, "hostname": "nsm-01"}}); err != nil {
		t.Fatal(err)
	}
	d := fs.docs[0].Doc
	expect(t, d, map[string]any{"uri_query": "token=REDACTED", "http_referrer": "http://evil.example/r?sid=REDACTED",
		"http_redirect": "https://idp.example/cb?code=REDACTED"})
	for k, v := range d {
		if s, _ := v.(string); strings.Contains(s, "tok3n") || strings.Contains(s, "s1d") || strings.Contains(s, "c0de") {
			t.Errorf("%s keeps a value: %s", k, s)
		}
	}
}
