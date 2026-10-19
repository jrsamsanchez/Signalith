package clustercfg

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// failWrites makes the fake refuse every write to a document whose id
// has id in it.
func failWrites(o *testOS, id string) {
	o.fake.SetFault(func(method, path string) *ostest.Fault {
		if method != http.MethodGet && strings.Contains(path, "/_doc/"+id) {
			return &ostest.Fault{Status: http.StatusInternalServerError, Type: "internal_error"}
		}
		return nil
	})
}

// A save is refused when its change has problems, is of settings.yaml,
// or cannot be written; a save that changes nothing writes nothing.
func TestSaveRefusals(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dir, authConfig(t, dir, ""), nil)
	ctx := context.Background()

	bad := &config.SharedEditResult{Scope: config.ScopeCluster}
	bad.Problems = []string{"x"}
	if _, err := Save(ctx, a.rt, a.docs, "alice", "n_siem-a", a.layer(), bad, nil); err == nil || !strings.Contains(err.Error(), "has problems") {
		t.Errorf("a change with problems: %v", err)
	}
	boot := &config.SharedEditResult{Scope: config.ScopeBootstrap, Shared: a.layer()}
	if _, err := Save(ctx, a.rt, a.docs, "alice", "n_siem-a", a.layer(), boot, nil); err == nil || !strings.Contains(err.Error(), "kept in settings.yaml") {
		t.Errorf("settings.yaml: %v", err)
	}
	same := &config.SharedEditResult{Scope: config.ScopeServer, Shared: a.layer(), Touched: []string{"server.listen"}}
	if revs, err := Save(ctx, a.rt, a.docs, "alice", "n_siem-a", a.layer(), same, nil); err != nil || len(revs) != 0 {
		t.Errorf("no change: %v %v", revs, err)
	}

	for _, c := range []struct {
		id    string
		scope config.Scope
		key   string
		value any
	}{
		{SettingsID, config.ScopeCluster, "search.max_events", float64(700)},
		{"cluster", config.ScopeCluster, "cluster.name", "prod"},
		{"nodecfg:n_siem-a", config.ScopeServer, "server.listen", "0.0.0.0:7443"},
	} {
		failWrites(o, c.id)
		if _, err := a.edit("n_siem-a", a.layer(), c.scope, config.Edit{Values: map[string]any{c.key: c.value}, By: "alice"}, nil); err == nil {
			t.Errorf("%s saved while %s cannot be written", c.key, c.id)
		}
		o.fake.SetFault(nil)
		a.cycle()
		revs, err := a.edit("n_siem-a", a.layer(), c.scope, config.Edit{Values: map[string]any{c.key: c.value}, By: "alice"}, nil)
		if err != nil {
			t.Errorf("%s: %v", c.key, err)
			continue
		}
		if _, ok := revs[c.key]; !ok {
			t.Errorf("%s: revisions %v", c.key, revs)
		}
		a.cycle()
	}
	if cb, _ := a.rt.Cluster().Get(); cb.Name != "prod" {
		t.Errorf("cluster name %q", cb.Name)
	}
	if v, _ := a.setting("search.max_events"); rawString(v.Value) != "700" || v.From.By != "alice" {
		t.Errorf("max events %+v", v)
	}
	if nc, _ := a.rt.NodeCfg().Get(); rawString(nc.Values["server.listen"].Value) != `"0.0.0.0:7443"` {
		t.Errorf("listen %+v", nc.Values["server.listen"])
	}

	// Another server's own settings that moved on since they were read.
	if _, err := a.edit("n_siem-a", a.layer(), config.ScopeServer, config.Edit{Values: map[string]any{"server.listen": "0.0.0.0:7444"}, By: "bob"},
		map[string]int64{"server.listen": 99}); !isStale(err) {
		t.Errorf("an old revision: %v", err)
	}
}

func isStale(err error) bool {
	_, ok := err.(*shared.StaleError)
	return ok
}

// The values of a server's own settings in nodecfg, read back as the
// page's entries, and the refusals of what cannot be one.
func TestPageValues(t *testing.T) {
	if v := valueOf("search.max_events", json.RawMessage(`600`)); v != 600 {
		t.Errorf("a number: %#v", v)
	}
	if v := valueOf("search.max_events", json.RawMessage(`"many"`)); v != "many" {
		t.Errorf("not of the setting's type: %#v", v)
	}
	if v := valueOf("no.such", json.RawMessage(`{"a":1}`)); v.(map[string]any)["a"] != float64(1) {
		t.Errorf("an unknown setting: %#v", v)
	}
	if v := valueOf("no.such", json.RawMessage(`not json`)); v != "not json" {
		t.Errorf("not JSON: %#v", v)
	}
	sealed := "enc:v1:x"
	if _, err := pageValueOf("server.listen", &config.PageEntry{Secret: &sealed}, "siem-a"); err == nil {
		t.Error("a secret as a server's own setting")
	}
	e := pageEntryOf("search.max_events", shared.PageValue{Value: json.RawMessage(`"many"`)})
	if _, err := pageValueOf("search.max_events", e, "siem-a"); err == nil {
		t.Error("text taken as a number")
	}
	e = pageEntryOf("server.listen", shared.PageValue{Value: json.RawMessage(`"0.0.0.0:7443"`), From: shared.From{By: "bob"}})
	pv, err := pageValueOf("server.listen", e, "siem-a")
	if err != nil || rawString(pv.Value) != `"0.0.0.0:7443"` || pv.From.Source != FromPage || pv.From.Node != "siem-a" || pv.From.By != "bob" {
		t.Errorf("round trip %+v %v", pv, err)
	}
	if _, err := sealFor(nil, "assistant.api_key", "k", ""); err == nil {
		t.Error("sealed without a cluster key")
	}
	v := config.SharedValue{Value: json.RawMessage(`5`)}
	if RefusalHash(nil, "search.max_events", v) != config.SharedHash("search.max_events", v) {
		t.Error("the hash without a cluster key")
	}
}
