package agentinv

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// An agent whose configuration trusts only a retired certificate
// authority needs a new configuration; one that trusts the current one
// too, or never trusted a retired one, does not.
func TestNeedsConfigForARetiredCA(t *testing.T) {
	const pinC = "00112233aabbccdd"
	clk := &clock{t: time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)}
	v := newInv(nil, "n1", clk, pinB)
	v.Retired = func() []string { return []string{pinA} }
	v.Note(Contact{Name: "old-only", Address: "192.0.2.10", TLS: true, Config: "ca=" + pinA + ";v=1.4.0", Events: 1})
	v.Note(Contact{Name: "both", Address: "192.0.2.11", TLS: true, Config: "ca=" + pinA + "," + pinB + ";v=1.4.0", Events: 1})
	v.Note(Contact{Name: "current", Address: "192.0.2.12", TLS: true, Config: "ca=" + pinB + ";v=1.4.0", Events: 1})
	v.Note(Contact{Name: "other", Address: "192.0.2.13", TLS: true, Config: "ca=" + pinC + ";v=1.4.0", Events: 1})
	v.Note(Contact{Name: "nopin", Address: "192.0.2.14", TLS: true, Events: 1})
	got := map[string]Agent{}
	for _, a := range list(t, v) {
		got[a.Name] = a
	}
	if a := got["old-only"]; !a.NeedsConfig || a.Reason != ReasonRetiredCA {
		t.Errorf("old-only: %+v", a)
	}
	for _, name := range []string{"both", "current", "other", "nopin"} {
		if a := got[name]; a.NeedsConfig || a.Reason != "" {
			t.Errorf("%s flagged: %+v", name, a)
		}
	}
	raw, _ := json.Marshal(got["old-only"])
	if !strings.Contains(string(raw), `"needs_config":true`) || !strings.Contains(string(raw), `"reason":"retired_ca"`) {
		t.Errorf("json %s", raw)
	}
	raw, _ = json.Marshal(got["both"])
	if strings.Contains(string(raw), "needs_config") {
		t.Errorf("json %s", raw)
	}
	// Without Retired, nothing is flagged.
	v.Retired = nil
	for _, a := range list(t, v) {
		if a.NeedsConfig {
			t.Errorf("flagged without retired CAs: %+v", a)
		}
	}
}
