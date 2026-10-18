package ingest

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestIngestHEC(t *testing.T) {
	b := &countingBulk{keep: true}
	p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}
	at := now.Add(-time.Hour).Truncate(time.Second)
	body := `{"time": ` + itoa(at.Unix()) + `.25, "host": "web1", "sourcetype": "linux_secure", "index": "main",
		"event": "Oct 11 09:15:02 web1 sshd[811]: Failed password for bob from 192.0.2.4 port 50022 ssh2"}
{"event": {"action": "login", "user": "amy"}, "sourcetype": "myapp:json", "source": "api", "fields": {"env": "prod", "tags": ["a", 1]}}
{"event": "plain text", "host": "h2", "sourcetype": "custom", "fields": {"datamodel": "Risk", "host": "evil"}}`
	res, err := p.IngestHEC(context.Background(), []byte(body))
	if err != nil || res.Received != 3 || res.Indexed != 3 || len(b.docs) != 3 {
		t.Fatalf("%+v %v %d", res, err, len(b.docs))
	}
	auth, app, text := b.docs[0].Doc, b.docs[1].Doc, b.docs[2].Doc
	if auth["datamodel"] != "Authentication" || auth["user"] != "bob" || auth["orig_sourcetype"] != "linux_secure" ||
		auth["orig_index"] != "main" || auth[IntakeField] != nil {
		t.Errorf("auth %v", auth)
	}
	if ts, _ := auth["@timestamp"].(string); !strings.HasPrefix(ts, at.UTC().Format("2006-01-02T15:04:05")+".25") {
		t.Errorf("time %v, want %v", auth["@timestamp"], at)
	}
	if app["datamodel"] != "Other" || app["user"] != "amy" || app["sourcetype"] != "myapp:json" || app["source"] != "api" || app["env"] != "prod" {
		t.Errorf("app %v", app)
	}
	if tags, _ := app["tags"].([]any); len(tags) != 2 || tags[1] != "1" {
		t.Errorf("tags %v", app["tags"])
	}
	// An indexed field cannot name what Signalith sets, or replace the
	// event's own fields.
	if text["datamodel"] != "Other" || text["message"] != "plain text" || text["host"] != "h2" || text["sourcetype"] != "custom" {
		t.Errorf("text %v", text)
	}
	// The same request sent again gives the same document IDs.
	b2 := &countingBulk{keep: true}
	p2 := &Pipeline{Store: b2, Prefix: "sig", Now: func() time.Time { return now }}
	if _, err := p2.IngestHEC(context.Background(), []byte(body)); err != nil {
		t.Fatal(err)
	}
	for i := range b.docs {
		if b.docs[i].ID == "" || b.docs[i].ID != b2.docs[i].ID {
			t.Errorf("ids %q %q", b.docs[i].ID, b2.docs[i].ID)
		}
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestIngestHECRefused(t *testing.T) {
	for _, c := range []struct {
		body       string
		code, at   int
		wantStatus int
	}{
		{"", HECNoData, -1, 400},
		{`{"event":"ok"} {"host":"x"}`, HECEventRequired, 1, 400},
		{`{"event":"  "}`, HECEventBlank, 0, 400},
		{`{"event":{}}`, HECEventBlank, 0, 400},
		{`{"event":"ok"} [1]`, HECInvalidFormat, 1, 400},
		{`{"event":"ok"} {"event":`, HECInvalidFormat, 1, 400},
		{`{"event":"ok","host":5}`, HECInvalidFormat, 0, 400},
		{`{"event":"ok","fields":{"a":{"b":1}}}`, HECBadFields, 0, 400},
		{`{"event":"ok","fields":[1]}`, HECBadFields, 0, 400},
		{`{"event":"` + strings.Repeat("x", MaxRecordBytes) + `"}`, HECInvalidFormat, 0, 413},
		{`{"event":` + strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1) + `}`, HECInvalidFormat, 0, 400},
	} {
		b := &countingBulk{keep: true}
		p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}
		_, err := p.IngestHEC(context.Background(), []byte(c.body))
		var he *HECError
		if !errors.As(err, &he) || he.Code != c.code || he.Event != c.at || he.Status != c.wantStatus || len(b.calls) != 0 {
			t.Errorf("%.40q: %v %+v, %d writes", c.body, err, he, len(b.calls))
		}
	}
}

func TestIngestHECRaw(t *testing.T) {
	b := &countingBulk{keep: true}
	p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}
	body := "127.0.0.1 - - [11/Oct/2026:09:15:02 +0000] \"GET /admin HTTP/1.1\" 404 12 \"-\" \"curl\"\r\n\n  \nsecond line\n"
	res, err := p.IngestHECRaw(context.Background(), []byte(body), HECMeta{Host: " www ", Sourcetype: "access_combined", Index: "web"})
	if err != nil || res.Indexed != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	web := b.docs[0].Doc
	if web["datamodel"] != "Web" || web["orig_index"] != "web" || web["host"] != "www" {
		t.Errorf("web %v", web)
	}
	if _, err := p.IngestHECRaw(context.Background(), []byte(" \n"), HECMeta{}); err == nil {
		t.Error("empty raw body accepted")
	}
	// A JSON sourcetype reads each line as an object.
	b.docs = nil
	if _, err := p.IngestHECRaw(context.Background(), []byte(`{"user":"zed","action":"x"}`), HECMeta{Sourcetype: "_json"}); err != nil {
		t.Fatal(err)
	}
	if d := b.docs[0].Doc; d["user"] != "zed" || d["sourcetype"] != "_json" {
		t.Errorf("json line %v", d)
	}
}

var hecSeeds = []string{
	`{"event":"hello","time":"1791720000.5","host":"a","source":"b","sourcetype":"syslog","index":"main"}`,
	`{"event":{"eventVersion":"1.08","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin"},"sourcetype":"aws:cloudtrail"}`,
	`{"event":{"EventID":4625,"Channel":"Security","Computer":"DC1"},"sourcetype":"XmlWinEventLog"}{"event":1}{"event":[1,"a"]}`,
	`{"event":"x","fields":{"a":"b","c":["d",2,true]}}`,
	`{"event":"x","time":-1}{"event":"y","time":1e300}{"event":"z","time":"soon"}`,
	`{"event":"{\"a\":1}","sourcetype":"_json"}`,
	`{"event":"x","fields":{"signalith_token":"forged","@timestamp":"1"}}`,
}

func FuzzHEC(f *testing.F) {
	for _, s := range hecSeeds {
		f.Add([]byte(s), false, "")
		f.Add([]byte(s), true, "_json")
	}
	f.Add([]byte("line one\nline two\r\n"), true, "linux_secure")
	f.Add([]byte("1.2.3.4 - - [x] \"GET / HTTP/1.1\" 200 1\n"), true, "access_combined")
	f.Fuzz(func(t *testing.T, body []byte, raw bool, st string) {
		b := &countingBulk{keep: true}
		p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}
		var res *Result
		var err error
		if raw {
			res, err = p.IngestHECRaw(context.Background(), body, HECMeta{Sourcetype: st, Host: st, Index: st})
		} else {
			res, err = p.IngestHEC(context.Background(), body)
		}
		if err != nil {
			var he *HECError
			if !errors.As(err, &he) || len(b.calls) != 0 || p.Stats().Received != 0 {
				t.Fatalf("refused with %v, %d writes", err, len(b.calls))
			}
			return
		}
		starts := 0
		for _, d := range b.docs {
			if strings.HasSuffix(d.ID, processStartSuffix) && d.Doc["datamodel"] == ProcessStartModel {
				starts++
			}
		}
		if res.Indexed != len(b.docs) || len(b.docs)-starts > res.Received {
			t.Fatalf("%+v, %d documents", res, len(b.docs))
		}
		ids := map[string]bool{}
		for _, d := range b.docs {
			if d.ID == "" || ids[d.ID] {
				t.Fatalf("document ID %q missing or repeated", d.ID)
			}
			ids[d.ID] = true
			checkDocTime(t, d.Doc)
			for k := range d.Doc {
				if Reserved(k) && k != "@timestamp" && k != "datamodel" && k != "device_time" && k != "dropped_fields" && k != IntakeField {
					t.Fatalf("sender set %q", k)
				}
			}
		}
	})
}
