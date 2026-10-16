package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/mcp"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// recorder notes every request the MCP server sends.
type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (rc *recorder) RoundTrip(r *http.Request) (*http.Response, error) {
	rc.mu.Lock()
	rc.calls = append(rc.calls, r.Method+" "+r.URL.Path)
	rc.mu.Unlock()
	return http.DefaultTransport.RoundTrip(r)
}

// mcpArgs are arguments for each MCP tool that get past its own checks.
var mcpArgs = map[string]string{
	"query_help":    `{}`,
	"check_query":   `{"query":"datamodel=Authentication | stats count by user"}`,
	"search":        `{"query":"datamodel=Authentication | stats count by user","max_rows":5}`,
	"list_findings": `{"status":"new","since":"7d","limit":5}`,
	"get_finding":   `{"id":"f1"}`,
	"list_cases":    `{"status":"new"}`,
	"get_case":      `{"id":"c1"}`,
	"list_assets":   `{"kind":"assets"}`,
	"lookup_entity": `{"kind":"user","value":"alice"}`,
	"risk_object":   `{"object":"alice","type":"user"}`,
	"intel_lookup":  `{"value":"203.0.113.9"}`,
	"get_detection": `{"id":"x"}`,
}

// TestMCPOnlyUsesViewerRoutes calls every MCP tool against a real server
// as a viewer. Each request it sends must be to a route a viewer may use
// that only reads, so the MCP server can neither change anything nor need
// more than the viewer role for its tools.
func TestMCPOnlyUsesViewerRoutes(t *testing.T) {
	ts, s := newRoleServer(t)
	rc := &recorder{}
	u, _ := url.Parse(ts.URL)
	srv := mcp.NewServer(&mcp.Client{BaseURL: u, User: "vera", Password: "role-password", HTTP: &http.Client{Transport: rc}}, "test")
	ctx := context.Background()
	for _, tool := range srv.Tools {
		a := mcpArgs[tool.Name]
		if a == "" {
			a = "{}"
		}
		if _, err := tool.Call(ctx, json.RawMessage(a)); err != nil {
			t.Logf("%s: %v", tool.Name, err)
			// Not found and such are fine; refusals are not.
			if strings.Contains(err.Error(), "role") || strings.Contains(err.Error(), "did not accept") {
				t.Errorf("%s: %v", tool.Name, err)
			}
		}
	}

	wildcard := regexp.MustCompile(`\{[^}]+\}`)
	routeOf := func(call string) *route {
		for _, r := range s.routes {
			if r.Pattern == call {
				return &r
			}
		}
		for _, r := range s.routes {
			if regexp.MustCompile("^" + wildcard.ReplaceAllString(r.Pattern, "[^/]+") + "$").MatchString(call) {
				return &r
			}
		}
		return nil
	}
	readOnlyPost := map[string]bool{"POST /api/search": true, "POST /api/parse": true}
	if len(rc.calls) < len(srv.Tools) {
		t.Fatalf("only %d requests for %d tools: %v", len(rc.calls), len(srv.Tools), rc.calls)
	}
	for _, call := range rc.calls {
		if !strings.HasPrefix(call, "GET ") && !readOnlyPost[call] {
			t.Errorf("%s is not a read-only request", call)
		}
		matched := routeOf(call)
		if matched == nil {
			t.Errorf("%s is not a registered route", call)
		} else if matched.Role != users.Viewer {
			t.Errorf("%s needs the %s role", call, matched.Role)
		}
	}
}

// TestMCPRefusedSignIn reports a wrong password in plain words.
func TestMCPRefusedSignIn(t *testing.T) {
	ts, _ := newRoleServer(t)
	u, _ := url.Parse(ts.URL)
	srv := mcp.NewServer(&mcp.Client{BaseURL: u, User: "vera", Password: "wrong"}, "test")
	for _, tool := range srv.Tools {
		if tool.Name != "whoami" {
			continue
		}
		_, err := tool.Call(context.Background(), json.RawMessage(`{}`))
		if err == nil || !strings.Contains(err.Error(), "did not accept the username and password") {
			t.Errorf("wrong password = %v", err)
		}
	}
}
