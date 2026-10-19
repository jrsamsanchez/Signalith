package shared

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

// A cluster document that is not an envelope, or one changed outside
// Signalith, makes a server with the key degraded rather than a member.
func TestEvaluateRefusesABadClusterDocument(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	k := a.key()
	good := e.os.Source(testIndex, ClusterDocID)

	// Changed outside Signalith: the body no longer matches its MAC.
	changed := map[string]any{}
	for key, v := range good {
		changed[key] = v
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(good["body"].(string)), &body); err != nil {
		t.Fatal(err)
	}
	body["name"] = "forged"
	raw, _ := json.Marshal(body)
	changed["body"] = string(raw)
	e.os.Put(testIndex, ClusterDocID, changed)
	b := e.server("siem-b", nil)
	b.give(k)
	b.step()
	if m, why := b.rt.Mode(); m != ModeDegraded || !strings.Contains(why, "changed outside Signalith") {
		t.Errorf("mode %s (%s)", m, why)
	}
	mustContain(t, "log", b.logs.String(), "config.tamper")

	// Not an envelope at all.
	e.os.Put(testIndex, ClusterDocID, map[string]any{"body": 5})
	c := e.server("siem-c", nil)
	c.give(k)
	c.step()
	if m, why := c.rt.Mode(); m != ModeDegraded || !strings.Contains(why, "not one Signalith wrote") {
		t.Errorf("mode %s (%s)", m, why)
	}
}

// A cluster key file in the state folder that cannot be opened is a
// missing key, not a server outside the cluster.
func TestEvaluateWithAKeyFileThatCannotBeOpened(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	b := e.server("siem-b", nil)
	b.give(a.key())
	if err := os.WriteFile(ClusterKeyPath(b.dir, a.key().ID()), []byte("not a key file"), 0o600); err != nil {
		t.Fatal(err)
	}
	b.step()
	if m, why := b.rt.Mode(); m != ModeKeyMissing || !strings.Contains(why, "cannot be opened") {
		t.Errorf("mode %s (%s)", m, why)
	}
}

// OpenSearch that refuses the read of the cluster document leaves a
// server that never reached it on its own files (legacy a).
func TestEvaluateWhenTheClusterDocumentCannotBeRead(t *testing.T) {
	e := newEnv(t)
	e.os.SetFault(func(method, path string) *ostest.Fault {
		if method == http.MethodGet && strings.Contains(path, "/_doc/"+ClusterDocID) {
			return &ostest.Fault{Status: http.StatusServiceUnavailable, Type: "unavailable"}
		}
		return nil
	})
	a := e.server("siem-a", nil)
	if m, why := a.rt.Mode(); m != ModeLegacyA || !strings.Contains(why, "OpenSearch cannot be reached") {
		t.Errorf("mode %s (%s)", m, why)
	}
}
