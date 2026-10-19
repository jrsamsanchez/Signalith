package api

import (
	"net/http"
	"strings"
	"testing"
)

// The scope already in use is not saved again; a step the CA's state
// does not allow is a 409.
func TestSecurityCASteps(t *testing.T) {
	ts, srv, logs := newSecurityServer(t, nil)
	ca := func(body string) (int, map[string]any) { return do(t, ts, "POST", "/api/security/ca", body, true) }
	if code, _ := ca(`{`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	if code, out := ca(`{"action":"prune"}`); code != http.StatusConflict {
		t.Errorf("prune with no old CA: %d %v", code, out)
	}
	scope := srv.conf().Server.CAScope()
	code, out := ca(`{"action":"prepare","scope":"` + scope + `"}`)
	if next, _ := out["ca"].(map[string]any)["next"].(map[string]any); code != http.StatusOK || next["scope"] != scope || srv.TLS.Next() == nil {
		t.Fatalf("prepare: %d %v", code, out)
	}
	if srv.conf().Server.CAScope() != scope || strings.Contains(logs.String(), "settings saved") {
		t.Errorf("the scope in use was saved again:\n%s", logs.String())
	}
	if code, _ := ca(`{"action":"rollback"}`); code != http.StatusConflict {
		t.Errorf("rollback with nothing to go back to: %d", code)
	}
	if code, _ := ca(`{"action":"discard"}`); code != http.StatusOK || srv.TLS.Next() != nil {
		t.Errorf("discard: %d", code)
	}
}
