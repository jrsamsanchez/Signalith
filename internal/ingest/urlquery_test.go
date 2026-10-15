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
