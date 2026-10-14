package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// session runs a server on pipes and returns a function that sends one
// message and one that reads the next answer.
func session(t *testing.T, s *Server) (send func(string), recv func() map[string]any) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), inR, outW); outW.Close() }()
	t.Cleanup(func() {
		inW.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after its input closed")
		}
	})
	sc := bufio.NewScanner(outR)
	sc.Buffer(nil, 1<<20)
	lines := make(chan string)
	go func() {
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	send = func(m string) {
		if _, err := io.WriteString(inW, m+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	recv = func() map[string]any {
		t.Helper()
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatal("no more answers")
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(l), &m); err != nil {
				t.Fatalf("answer %q: %v", l, err)
			}
			return m
		case <-time.After(5 * time.Second):
			t.Fatal("no answer")
		}
		return nil
	}
	return send, recv
}

func TestProtocol(t *testing.T) {
	block := make(chan struct{})
	var once sync.Once
	s := &Server{Name: "signalith", Version: "test", Instructions: "hi", Tools: []Tool{
		{Name: "echo", Schema: map[string]any{"type": "object"}, Call: func(_ context.Context, a json.RawMessage) (any, error) {
			return map[string]any{"got": json.RawMessage(a)}, nil
		}},
		{Name: "fail", Schema: map[string]any{"type": "object"}, Call: func(context.Context, json.RawMessage) (any, error) {
			return nil, io.ErrUnexpectedEOF
		}},
		{Name: "slow", Schema: map[string]any{"type": "object"}, Call: func(ctx context.Context, _ json.RawMessage) (any, error) {
			once.Do(func() { close(block) })
			<-ctx.Done()
			return nil, ctx.Err()
		}},
	}}
	send, recv := session(t, s)

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"t"}}}`)
	m := recv()
	res := m["result"].(map[string]any)
	if res["protocolVersion"] != "2025-03-26" || res["instructions"] != "hi" || res["serverInfo"].(map[string]any)["name"] != "signalith" {
		t.Errorf("initialize = %v", m)
	}
	send(`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`)
	if v := recv()["result"].(map[string]any)["protocolVersion"]; v != protocolVersions[0] {
		t.Errorf("unknown version answered with %v", v)
	}
	// Notifications get no answer; the next answer is the ping's.
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":"p","method":"ping"}`)
	if m := recv(); m["id"] != "p" || m["result"] == nil {
		t.Errorf("ping = %v", m)
	}

	send(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	tools := recv()["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("tools = %v", tools)
	}
	ann := tools[0].(map[string]any)["annotations"].(map[string]any)
	if ann["readOnlyHint"] != true || ann["destructiveHint"] != false {
		t.Errorf("annotations = %v", ann)
	}

	send(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"a":1}}}`)
	m = recv()
	content := m["result"].(map[string]any)["content"].([]any)[0].(map[string]any)
	if m["result"].(map[string]any)["isError"] != false || !strings.Contains(content["text"].(string), `"a": 1`) {
		t.Errorf("echo = %v", m)
	}
	send(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"fail"}}`)
	if r := recv()["result"].(map[string]any); r["isError"] != true {
		t.Errorf("fail = %v", r)
	}
	send(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nope"}}`)
	if e := recv()["error"].(map[string]any); e["code"] != float64(codeInvalidParams) {
		t.Errorf("unknown tool = %v", e)
	}
	send(`{"jsonrpc":"2.0","id":7,"method":"resources/read"}`)
	if e := recv()["error"].(map[string]any); e["code"] != float64(codeNoMethod) {
		t.Errorf("unknown method = %v", e)
	}
	send(`not json`)
	if e := recv()["error"].(map[string]any); e["code"] != float64(codeParse) {
		t.Errorf("bad json = %v", e)
	}

	// A cancelled call gets no answer, and does not hold up others.
	send(`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"slow"}}`)
	<-block
	send(`{"jsonrpc":"2.0","id":9,"method":"ping"}`)
	if m := recv(); m["id"] != float64(9) {
		t.Errorf("ping during a slow call = %v", m)
	}
	send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":8}}`)
	send(`[{"jsonrpc":"2.0","id":10,"method":"ping"},{"jsonrpc":"2.0","id":11,"method":"ping"}]`)
	if a, b := recv(), recv(); a["id"] != float64(10) || b["id"] != float64(11) {
		t.Errorf("batch = %v %v", a, b)
	}
}

func TestTooLargeMessage(t *testing.T) {
	send, recv := session(t, &Server{})
	send(`{"x":"` + strings.Repeat("a", maxMessage) + `"}`)
	if e := recv()["error"].(map[string]any); e["code"] != float64(codeInvalidRequest) {
		t.Errorf("too large = %v", e)
	}
	send(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if m := recv(); m["id"] != float64(1) {
		t.Errorf("after a large message: %v", m)
	}
}

func TestClientOnlyReads(t *testing.T) {
	var calls []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if u, p, _ := r.BasicAuth(); u != "vera" || p != "pw" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{}`)
	}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	c := &Client{BaseURL: u, User: "vera", Password: "pw"}
	ctx := context.Background()
	if err := c.Post(ctx, "/api/cases", map[string]string{}, nil); err == nil {
		t.Error("POST to a route that changes things was sent")
	}
	if err := c.Get(ctx, "/api/../login", nil, nil); err == nil {
		t.Error("path outside the API was read")
	}
	if len(calls) != 0 {
		t.Errorf("calls = %v", calls)
	}
	if err := c.Post(ctx, "/api/search", map[string]string{"query": "*"}, nil); err != nil {
		t.Error(err)
	}
	c.Password = "wrong"
	err := c.Get(ctx, "/api/me", nil, nil)
	if ae, ok := err.(*APIError); !ok || ae.Status != 401 || !strings.Contains(ae.Msg, "SIGNALITH_PASSWORD") {
		t.Errorf("wrong password = %v", err)
	}
}

func TestShrink(t *testing.T) {
	list := make([]any, maxList+5)
	for i := range list {
		list[i] = strings.Repeat("é", maxString+1)
	}
	out := shrink(map[string]any{"l": list}).(map[string]any)["l"].([]any)
	if len(out) != maxList+1 || !strings.Contains(out[maxList].(string), "5 more items") {
		t.Errorf("list not cut: %d", len(out))
	}
	if s := out[0].(string); !strings.HasSuffix(s, "[1 more characters cut]") {
		t.Errorf("string not cut: %q", s[len(s)-40:])
	}
}
