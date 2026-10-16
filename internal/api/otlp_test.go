package api

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// otlpProtoRequest is an ExportLogsServiceRequest with one log record per
// line, from host web1.
func otlpProtoRequest(lines ...string) []byte {
	str := func(s string) []byte { return pbBytesField(nil, 1, []byte(s)) } // AnyValue.string_value
	kv := pbBytesField(pbBytesField(nil, 1, []byte("host.name")), 2, str("web1"))
	resource := pbBytesField(nil, 1, kv)
	var scope []byte
	for _, l := range lines {
		rec := binary.LittleEndian.AppendUint64(binary.AppendUvarint(nil, 1<<3|1), uint64(time.Now().UnixNano()))
		rec = pbBytesField(rec, 5, str(l))
		scope = pbBytesField(scope, 2, rec)
	}
	rl := pbBytesField(pbBytesField(nil, 1, resource), 2, scope)
	return pbBytesField(nil, 1, rl)
}

func gz(b []byte) []byte {
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return out.Bytes()
}

func postOTLP(t *testing.T, url string, body []byte, header map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", url+"/api/otlp/v1/logs", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok-0123456789abcdef")
	req.Header.Set("Content-Type", "application/x-protobuf")
	for k, v := range header {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func TestOTLPLogs(t *testing.T) {
	ts, fos := newTestServer(t)
	auth := "Oct 11 09:15:02 web1 sshd[811]: Failed password for bob from 192.0.2.4 port 50022 ssh2"

	// What the Collector's otlphttp exporter sends: protobuf, gzip.
	resp, body := postOTLP(t, ts.URL, gz(otlpProtoRequest(auth, "app started")), map[string]string{"Content-Encoding": "gzip"})
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-protobuf" || len(body) != 0 {
		t.Fatalf("protobuf: %d %q %q", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	if len(fos.bulk) != 2 || fos.bulk[0].Doc["datamodel"] != "Authentication" || fos.bulk[0].Doc["user"] != "bob" ||
		fos.bulk[1].Doc["message"] != "app started" || fos.bulk[1].Doc["host"] != "web1" {
		t.Fatalf("stored %+v", fos.bulk)
	}

	// JSON, as SDKs and curl send it.
	js := `{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"api"}}]},
		"scopeLogs":[{"logRecords":[{"severityText":"ERROR","body":{"stringValue":"boom"}}]}]}]}`
	resp, body = postOTLP(t, ts.URL, []byte(js), map[string]string{"Content-Type": "application/json; charset=utf-8"})
	if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != "{}" {
		t.Fatalf("json: %d %s", resp.StatusCode, body)
	}
	if d := fos.bulk[2].Doc; d["service"] != "api" || d["severity"] != "ERROR" || d["message"] != "boom" {
		t.Errorf("json stored %v", d)
	}

	for _, c := range []struct {
		name   string
		body   []byte
		header map[string]string
		code   int
		msg    string
	}{
		{"no token", otlpProtoRequest("x"), map[string]string{"Authorization": ""}, 401, "agent token"},
		{"wrong token", otlpProtoRequest("x"), map[string]string{"Authorization": "Bearer nope-nope-nope-nope"}, 401, "agent token"},
		{"not OTLP", []byte("x"), map[string]string{"Content-Type": "text/plain"}, 415, "application/x-protobuf"},
		{"zstd", otlpProtoRequest("x"), map[string]string{"Content-Encoding": "zstd"}, 415, "gzip"},
		{"bad gzip", []byte("not gzip"), map[string]string{"Content-Encoding": "gzip"}, 400, "gzip"},
		{"bad protobuf", []byte{0x0a, 0x7f}, nil, 400, "invalid protobuf"},
		{"bad JSON", []byte("{"), map[string]string{"Content-Type": "application/json"}, 400, "OTLP/JSON"},
		{"too large unzipped", gz(bytes.Repeat([]byte{0}, ingest.MaxBodyBytes+1)), map[string]string{"Content-Encoding": "gzip"}, 413, "uncompressed"},
	} {
		n := len(fos.bulk)
		resp, body := postOTLP(t, ts.URL, c.body, c.header)
		msg := string(body)
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
			var st struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			if json.Unmarshal(body, &st) != nil || st.Code == 0 {
				t.Errorf("%s: not a Status: %s", c.name, body)
			}
			msg = st.Message
		}
		if resp.StatusCode != c.code || !strings.Contains(msg, c.msg) || len(fos.bulk) != n {
			t.Errorf("%s: %d %q", c.name, resp.StatusCode, msg)
		}
	}
}

// TestOTLPPartialSuccess checks that records OpenSearch rejects are
// reported as an OTLP partial success.
func TestOTLPPartialSuccess(t *testing.T) {
	var w httptest.ResponseRecorder
	w.Body = new(bytes.Buffer)
	writeOTLPSuccess(&w, false, 2, "mapper_parsing_exception")
	b := w.Body.Bytes()
	// field 1 (partial_success) { field 1: 2, field 2: "..." }
	if len(b) < 4 || b[0] != 0x0a || b[2] != 0x08 || b[3] != 2 || !bytes.Contains(b, []byte("mapper_parsing_exception")) {
		t.Errorf("protobuf partial success = %x", b)
	}
	w2 := httptest.NewRecorder()
	writeOTLPSuccess(w2, true, 2, "x")
	if !strings.Contains(w2.Body.String(), `"rejectedLogRecords":"2"`) {
		t.Errorf("json partial success = %s", w2.Body)
	}
}

// TestOTLPPlainHTTP checks OTLP over plain HTTP to the HTTPS port follows
// server.tls.plaintext_ingest, as agent ingest does.
func TestOTLPPlainHTTP(t *testing.T) {
	ts, s := newPlainSide(t, nil)
	if resp, body := postOTLP(t, ts.URL, otlpProtoRequest("hello"), nil); resp.StatusCode != 200 {
		t.Fatalf("allowed: %d %s", resp.StatusCode, body)
	}
	if len(s.Pipeline.PlaintextSenders(time.Time{})) != 1 {
		t.Error("the sender was not noted as plain HTTP")
	}
	ts, s = newPlainSide(t, func(s *Server) {
		s.Config.Server.TLS = &config.ServerTLS{Mode: "auto", PlaintextIngest: "deny"}
	})
	resp, _ := postOTLP(t, ts.URL, otlpProtoRequest("hello"), nil)
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" || s.Pipeline.Stats().Received != 0 {
		t.Errorf("denied: %d", resp.StatusCode)
	}
}
