package clustercfg

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

func (m *authMember) path() string { return filepath.Join(m.dir, "signalith.yaml") }

// layer is this server's shared layer, as a member with shared settings
// loads its configuration with.
func (m *authMember) layer() *config.Shared {
	m.t.Helper()
	cb, _ := m.rt.Cluster().Get()
	nc, _ := m.rt.NodeCfg().Get()
	return Layer(m.docs, cb, nc, m.name)
}

// load loads this server's configuration with its shared layer.
func (m *authMember) load() *config.Config {
	m.t.Helper()
	c, err := config.LoadShared(m.path(), m.layer())
	if err != nil {
		m.t.Fatal(err)
	}
	m.cfg.Store(c)
	return c
}

// rewrite rewrites this server's signalith.yaml with authExtra (see
// authConfig) and loads it with the shared layer.
func (m *authMember) rewrite(authExtra string) *config.Config {
	m.t.Helper()
	authConfig(m.t, m.dir, authExtra)
	return m.load()
}

// edit checks e of scope against base, on this server's files, and saves
// it as server's (a node id).
func (m *authMember) edit(server string, base *config.Shared, scope config.Scope, e config.Edit, versions map[string]int64) (map[string]int64, error) {
	m.t.Helper()
	if e.At.IsZero() {
		e.At = time.Now()
	}
	res, err := config.CheckEditShared(m.path(), base, scope, e)
	if err != nil {
		m.t.Fatal(err)
	}
	if !res.OK() {
		m.t.Fatalf("the edit has problems: %v %v", res.Fields, res.Problems)
	}
	return Save(context.Background(), m.rt, m.docs, e.By, server, base, res, versions)
}

// setting returns the shared value of key.
func (m *member) setting(key string) (SettingValue, bool) {
	b, ok := m.docs.Settings().Get()
	if !ok {
		return SettingValue{}, false
	}
	v, ok := b.Values[key]
	return v, ok
}

func rawString(v json.RawMessage) string { return string(compact(v)) }

func mustContain(t *testing.T, what, s, part string) {
	t.Helper()
	if !strings.Contains(s, part) {
		t.Errorf("%s lacks %q:\n%s", what, part, s)
	}
}

// tokensOf opens the shared agent tokens by server and source.
func tokensOf(t *testing.T, m *member) map[string][]string {
	t.Helper()
	b, _ := m.docs.Settings().Get()
	out := map[string][]string{}
	for _, tok := range b.IngestTokens {
		p, err := openFor(m.rt.Hub().Keys(), "ingest.tokens", tok.Secret, "")
		if err != nil {
			t.Fatal(err)
		}
		out[tok.Node+"/"+tok.Source] = append(out[tok.Node+"/"+tok.Source], p)
	}
	return out
}

// TestImportSettings (W20): the founder's shared settings from its
// settings.yaml, signalith.yaml and environment go into the settings
// document, a password re-sealed with the cluster key for its address, a
// change the page set aside left out; running it again changes nothing.
// Then its own import moves its own settings into its nodecfg and leaves
// settings.yaml with the connection settings, a copy kept; again it is
// done once, and a start after a crash before the rewrite only rewrites.
func TestImportSettings(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	master := secrets.NewKeyring(dir)
	secrets.SetDefault(master)
	t.Cleanup(func() { secrets.SetDefault(nil) })
	t.Setenv("SIGNALITH_INGEST_TOKEN", "tok-env-0123456789ab")
	const extra = "dashboards:\n  stale_after: 2h\n"
	c := authConfig(t, dir, extra)
	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	p := &config.PageSettings{}
	for _, s := range []struct {
		key string
		v   any
		by  string
	}{{"search.max_events", 500, "alice"}, {"server.listen", "0.0.0.0:9443", "bob"}, {"opensearch.username", "svc", "bob"},
		{"search.default_earliest", "-7d", "alice"}, {"assistant.provider", "anthropic", "alice"}} {
		if err := p.Set(s.key, s.v, s.by, at); err != nil {
			t.Fatal(err)
		}
	}
	p.Settings["search.default_earliest"].Refused = "it broke the start"
	if err := p.SetSecret("assistant.api_key", "sk-page-secret", "https://api.anthropic.com:443", "alice", at); err != nil {
		t.Fatal(err)
	}
	pageFile := c.SettingsFile()
	if err := config.WritePageSettings(pageFile, p); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(pageFile)
	if err != nil {
		t.Fatal(err)
	}
	c = authConfig(t, dir, extra)
	if c.Source("search.max_events").Kind != config.FromPage {
		t.Fatalf("the page is not in use: %+v", c.Source("search.max_events"))
	}
	a := newAuthMember(t, o, "siem-a", dir, c, nil)
	if !a.rt.SharedSettings() {
		t.Fatal("settings are not shared after founding")
	}

	v, ok := a.setting("search.max_events")
	if !ok || rawString(v.Value) != "500" || v.Rev != 1 || v.From.Source != FromImport || v.From.By != "alice" || v.From.Node != "siem-a" || !v.From.At.Equal(at) {
		t.Errorf("search.max_events %+v", v)
	}
	if v, _ := a.setting("assistant.provider"); rawString(v.Value) != `"anthropic"` || v.From.By != "alice" {
		t.Errorf("assistant.provider %+v", v)
	}
	if v, _ := a.setting("dashboards.stale_after"); rawString(v.Value) != `"2h"` || v.From.Source != FromImport || v.From.By != "" {
		t.Errorf("dashboards.stale_after %+v", v)
	}
	for _, key := range []string{"search.default_earliest", "server.listen", "opensearch.username", "auth.session_timeout"} {
		if v, ok := a.setting(key); ok {
			t.Errorf("%s imported: %+v", key, v)
		}
	}
	mustContain(t, "the log", a.logs.String(), "search.default_earliest")
	key, _ := a.setting("assistant.api_key")
	if key.SentTo != "https://api.anthropic.com:443" || key.Secret == "" || key.Value != nil {
		t.Fatalf("assistant.api_key %+v", key)
	}
	if got, err := openFor(a.rt.Hub().Keys(), "assistant.api_key", key.Secret, key.SentTo); err != nil || got != "sk-page-secret" {
		t.Errorf("the key opens to %q (%v)", got, err)
	}
	if _, err := master.Open("settings.assistant.api_key", key.Secret); err == nil {
		t.Error("the shared key opens with the master key")
	}
	if _, err := openFor(a.rt.Hub().Keys(), "assistant.api_key", key.Secret, "https://evil.example.org:443"); err == nil {
		t.Error("the key opens for another address")
	}
	toks := tokensOf(t, a.member)
	if !reflect.DeepEqual(toks, map[string][]string{"n_siem-a/yaml": {"tok-0123456789abcdef"}, "n_siem-a/env": {"tok-env-0123456789ab"}}) {
		t.Errorf("tokens %v", toks)
	}

	// The founder runs with them.
	ec := a.load()
	if ec.Search.MaxEvents != 500 || ec.Assistant.APIKey != "sk-page-secret" || ec.Source("search.max_events").Kind != config.FromShared {
		t.Errorf("effective: max_events %d, key %q, source %+v", ec.Search.MaxEvents, ec.Assistant.APIKey, ec.Source("search.max_events"))
	}
	if !slices.Contains(ec.Ingest.Tokens, "tok-env-0123456789ab") || !slices.Contains(ec.Ingest.Tokens, "tok-0123456789abcdef") {
		t.Errorf("tokens accepted %v", ec.Ingest.Tokens)
	}
	// What its files say was recorded: nothing applies.
	if res := a.apply(); len(res.Applied) != 0 {
		t.Errorf("the founder's first apply %+v", res.Applied)
	}

	// Running it again changes nothing.
	before, _ := a.docs.Settings().Get()
	if err := a.importer(shared.ImportSettings).Run(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	a.cycle()
	after, _ := a.docs.Settings().Get()
	if !reflect.DeepEqual(before.Values, after.Values) || !reflect.DeepEqual(before.IngestTokens, after.IngestTokens) {
		t.Errorf("a second run changed the settings:\n%+v\n%+v", before, after)
	}

	// Its own import.
	ctx := context.Background()
	changed, err := ImportOwn(ctx, a.rt, a.docs, ec, a.log)
	if err != nil || !changed {
		t.Fatalf("own import: %v %v", changed, err)
	}
	nc, _ := a.rt.NodeCfg().Get()
	listen := nc.Values["server.listen"]
	if rawString(listen.Value) != `"0.0.0.0:9443"` || listen.Rev != 1 || listen.From.Source != FromImport || listen.From.By != "bob" || nc.SettingsImported == "" {
		t.Errorf("nodecfg values %+v", nc.Values)
	}
	if len(nc.Migrated) != 0 {
		t.Errorf("the founder's own values differ: %+v", nc.Migrated)
	}
	left, err := config.ReadPageSettings(pageFile)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(left.Keys(), []string{"opensearch.username"}) {
		t.Errorf("settings.yaml keeps %v", left.Keys())
	}
	copies, _ := filepath.Glob(pageFile + ".imported-*")
	if len(copies) != 1 {
		t.Fatalf("copies %v", copies)
	}
	if got, _ := os.ReadFile(copies[0]); string(got) != string(original) {
		t.Error("the copy is not the original")
	}
	ec = a.load()
	if ec.Server.Listen != "0.0.0.0:9443" || ec.Source("server.listen").Kind != config.FromPage || ec.OpenSearch.Username != "svc" {
		t.Errorf("after the own import: listen %q (%+v), username %q", ec.Server.Listen, ec.Source("server.listen"), ec.OpenSearch.Username)
	}
	if changed, err := ImportOwn(ctx, a.rt, a.docs, ec, a.log); err != nil || changed {
		t.Errorf("a second own import: %v %v", changed, err)
	}

	// A crash after nodecfg was written, before settings.yaml was: the
	// next start only rewrites it, and keeps a value changed since.
	if err := os.WriteFile(pageFile, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.rt.NodeCfg().Mutate(ctx, "sam", func(n *shared.NodeCfg) error {
		v := n.Values["server.listen"]
		v.Value, v.Rev = json.RawMessage(`"0.0.0.0:8444"`), 2
		n.Values["server.listen"] = v
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if changed, err := ImportOwn(ctx, a.rt, a.docs, ec, a.log); err != nil || !changed {
		t.Fatalf("resumed own import: %v %v", changed, err)
	}
	nc, _ = a.rt.NodeCfg().Get()
	if v := nc.Values["server.listen"]; rawString(v.Value) != `"0.0.0.0:8444"` || v.Rev != 2 {
		t.Errorf("the resumed import changed nodecfg: %+v", v)
	}
	if left, _ := config.ReadPageSettings(pageFile); !reflect.DeepEqual(left.Keys(), []string{"opensearch.username"}) {
		t.Errorf("settings.yaml keeps %v", left.Keys())
	}
}

// TestImportOwnSecondServer (W21): a server that joins later moves its
// own settings into its nodecfg, lists its shared settings that differ
// from the shared values (a password as set, never its value), and
// reduces its settings.yaml.
func TestImportOwnSecondServer(t *testing.T) {
	o := newOS(t)
	dirA := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dirA, authConfig(t, dirA, ""), nil)
	if _, err := a.edit("n_siem-a", a.layer(), config.ScopeCluster, config.Edit{Values: map[string]any{"search.max_events": float64(2000)}, By: "alice"}, nil); err != nil {
		t.Fatal(err)
	}

	dirB := t.TempDir()
	secrets.SetDefault(secrets.NewKeyring(dirB))
	cb := authConfig(t, dirB, "")
	p := &config.PageSettings{}
	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	for k, v := range map[string]any{"server.listen": "0.0.0.0:7443", "search.max_events": 300, "search.default_earliest": "-24h", "detections.scheduler": false} {
		if err := p.Set(k, v, "bob", at); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.SetSecret("vulns.nvd_api_key", "nvd-of-b", "https://services.nvd.nist.gov:443", "bob", at); err != nil {
		t.Fatal(err)
	}
	if err := config.WritePageSettings(cb.SettingsFile(), p); err != nil {
		t.Fatal(err)
	}
	cb = authConfig(t, dirB, "")
	b := newAuthMember(t, o, "siem-b", dirB, cb, a.key())
	b.cycle()

	ctx := context.Background()
	if changed, err := ImportOwn(ctx, b.rt, b.docs, cb, b.log); err != nil || !changed {
		t.Fatalf("own import: %v %v", changed, err)
	}
	// Another server reads it.
	nc, err := NodeCfgOf(ctx, a.rt, "n_siem-b")
	if err != nil {
		t.Fatal(err)
	}
	if rawString(nc.Values["server.listen"].Value) != `"0.0.0.0:7443"` || rawString(nc.Values["cluster.leader_eligible"].Value) != "false" {
		t.Errorf("B's values %+v", nc.Values)
	}
	if _, ok := nc.Values["detections.scheduler"]; ok {
		t.Error("the old name was kept")
	}
	got := map[string]string{}
	for _, m := range nc.Migrated {
		got[m.Key] = rawString(m.Value) + " / " + rawString(m.Shared)
	}
	want := map[string]string{"search.max_events": "300 / 2000", "vulns.nvd_api_key": `{"set":true} / `}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("migrated %v, want %v", got, want)
	}
	if _, err := os.Stat(cb.SettingsFile()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("settings.yaml is still there: %v", err)
	}
	if copies, _ := filepath.Glob(cb.SettingsFile() + ".imported-*"); len(copies) != 1 {
		t.Errorf("copies %v", copies)
	}
	if ec := b.load(); ec.Search.MaxEvents != 2000 || ec.Server.Listen != "0.0.0.0:7443" || ec.LeaderEligible() {
		t.Errorf("B runs with max_events %d, listen %q, eligible %v", ec.Search.MaxEvents, ec.Server.Listen, ec.LeaderEligible())
	}
}

// TestSaveVersions (W6, store level): two saves of the same setting from
// pages that read the same revision: the second is refused naming who
// changed it where; saves of different settings both stay. A change of
// another server's own settings lands in its nodecfg, and that server's
// own writes there cause no conflict.
func TestSaveVersions(t *testing.T) {
	o := newOS(t)
	dirA, dirB := t.TempDir(), t.TempDir()
	a := newAuthMember(t, o, "siem-a", dirA, authConfig(t, dirA, ""), nil)
	b := newAuthMember(t, o, "siem-b", dirB, authConfig(t, dirB, ""), a.key())
	b.cycle()
	la, lb := a.layer(), b.layer()
	read := map[string]int64{"auth.session_timeout": 0, "search.max_events": 0}

	revs, err := a.edit("n_siem-a", la, config.ScopeCluster, config.Edit{Values: map[string]any{"auth.session_timeout": "8h"}, By: "alice"}, read)
	if err != nil || revs["auth.session_timeout"] != 1 {
		t.Fatalf("A's save: %v %v", revs, err)
	}
	b.cycle()
	_, err = b.edit("n_siem-b", lb, config.ScopeCluster, config.Edit{Values: map[string]any{"auth.session_timeout": "12h"}, By: "bob"}, read)
	var se *shared.StaleError
	if !errors.As(err, &se) || se.By != "alice" || se.Node != "siem-a" || se.At == "" {
		t.Fatalf("B's save of the same setting: %v", err)
	}
	if _, err := b.edit("n_siem-b", lb, config.ScopeCluster, config.Edit{Values: map[string]any{"search.max_events": float64(777)}, By: "bob"}, read); err != nil {
		t.Fatalf("B's save of another setting: %v", err)
	}
	a.cycle()
	if v, _ := a.setting("auth.session_timeout"); rawString(v.Value) != `"8h"` || v.Rev != 1 || v.From.By != "alice" || v.From.Source != FromPage {
		t.Errorf("session timeout %+v", v)
	}
	if v, _ := a.setting("search.max_events"); rawString(v.Value) != "777" || v.Rev != 1 || v.From.Node != "siem-b" {
		t.Errorf("max events %+v", v)
	}
	if c := a.load(); c.Auth.SessionTimeout != "8h" || c.Search.MaxEvents != 777 {
		t.Errorf("A runs with %q and %d", c.Auth.SessionTimeout, c.Search.MaxEvents)
	}
	// A fresh read, but the page read an older revision.
	if _, err := b.edit("n_siem-b", b.layer(), config.ScopeCluster, config.Edit{Values: map[string]any{"search.max_events": float64(900)}, By: "bob"},
		map[string]int64{"search.max_events": 0}); !errors.As(err, &se) {
		t.Errorf("a save from an older page: %v", err)
	}
	// Reset takes it back to its default, and its revision goes on.
	revs, err = a.edit("n_siem-a", a.layer(), config.ScopeCluster, config.Edit{Reset: []string{"search.max_events"}, By: "alice"}, map[string]int64{"search.max_events": 1})
	if err != nil || revs["search.max_events"] != 2 {
		t.Fatalf("reset: %v %v", revs, err)
	}
	if _, ok := a.setting("search.max_events"); ok {
		t.Error("the reset setting is still shared")
	}
	// A-B-A: a page read at revision 1, before the reset and another
	// change to the same value, is refused all the same.
	a.cycle()
	if revs, err = a.edit("n_siem-a", a.layer(), config.ScopeCluster, config.Edit{Values: map[string]any{"search.max_events": float64(777)}, By: "carol"},
		map[string]int64{"search.max_events": 2}); err != nil || revs["search.max_events"] != 3 {
		t.Fatalf("set again after the reset: %v %v", revs, err)
	}
	if _, err := b.edit("n_siem-b", b.layer(), config.ScopeCluster, config.Edit{Values: map[string]any{"search.max_events": float64(900)}, By: "bob"},
		map[string]int64{"search.max_events": 1}); !errors.As(err, &se) || se.By != "carol" {
		t.Errorf("a save from a page read before the reset: %v", err)
	}
	if revs, err = a.edit("n_siem-a", a.layer(), config.ScopeCluster, config.Edit{Reset: []string{"search.max_events"}, By: "alice"}, nil); err != nil || revs["search.max_events"] != 4 {
		t.Fatalf("reset again: %v %v", revs, err)
	}

	// B's own settings, changed on A's page.
	ctx := context.Background()
	baseB := func() *config.Shared {
		cb, _ := a.rt.Cluster().Get()
		nc, err := NodeCfgOf(ctx, a.rt, "n_siem-b")
		if err != nil {
			t.Fatal(err)
		}
		return Layer(a.docs, cb, nc, "siem-a")
	}
	old := baseB()
	revs, err = a.edit("n_siem-b", old, config.ScopeServer, config.Edit{Values: map[string]any{"server.listen": "0.0.0.0:7443"}, By: "alice"}, nil)
	if err != nil || revs["server.listen"] != 1 {
		t.Fatalf("B's listen address from A: %v %v", revs, err)
	}
	// B writes what it runs meanwhile.
	if _, err := b.rt.NodeCfg().Mutate(ctx, "signalith", func(n *shared.NodeCfg) error {
		n.Running = map[string]shared.RunningValue{"server.listen": {Value: json.RawMessage(`"0.0.0.0:8443"`), Source: "default"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.edit("n_siem-b", baseB(), config.ScopeServer, config.Edit{Values: map[string]any{"server.max_connections": float64(50)}, By: "alice"},
		map[string]int64{"server.max_connections": 0}); err != nil {
		t.Fatalf("a save after B's own write: %v", err)
	}
	// A page that read B's listen address before it changed.
	if _, err := a.edit("n_siem-b", old, config.ScopeServer, config.Edit{Values: map[string]any{"server.listen": "0.0.0.0:6443"}, By: "carol"}, nil); !errors.As(err, &se) || se.By != "alice" {
		t.Errorf("a stale save of B's listen address: %v", err)
	}
	nc, err := NodeCfgOf(ctx, a.rt, "n_siem-b")
	if err != nil {
		t.Fatal(err)
	}
	if v := nc.Values["server.listen"]; rawString(v.Value) != `"0.0.0.0:7443"` || v.From.By != "alice" || v.From.Node != "siem-a" || len(nc.Running) != 1 {
		t.Errorf("B's nodecfg %+v", nc)
	}
	b.cycle()
	if c := b.load(); c.Server.Listen != "0.0.0.0:7443" || c.Server.MaxConnections != 50 {
		t.Errorf("B's settings %q %d", c.Server.Listen, c.Server.MaxConnections)
	}

	// A-B-A on B's own setting: reset, then saved again with the value a
	// page read at revision 1; that page's save is refused all the same.
	if revs, err = a.edit("n_siem-b", baseB(), config.ScopeServer, config.Edit{Reset: []string{"server.listen"}, By: "bob"}, nil); err != nil || revs["server.listen"] != 2 {
		t.Fatalf("reset of B's listen address: %v %v", revs, err)
	}
	if revs, err = a.edit("n_siem-b", baseB(), config.ScopeServer, config.Edit{Values: map[string]any{"server.listen": "0.0.0.0:7443"}, By: "dave"}, nil); err != nil || revs["server.listen"] != 3 {
		t.Fatalf("B's listen address again: %v %v", revs, err)
	}
	if _, err := a.edit("n_siem-b", baseB(), config.ScopeServer, config.Edit{Values: map[string]any{"server.listen": "0.0.0.0:6443"}, By: "carol"},
		map[string]int64{"server.listen": 1}); !errors.As(err, &se) || se.By != "dave" {
		t.Errorf("a save from a page read before the reset: %v", err)
	}

	// A shared value B could not use, tried again on its page.
	sv := b.layer().Cluster["auth.session_timeout"]
	if _, err := b.rt.NodeCfg().Mutate(ctx, "signalith", func(n *shared.NodeCfg) error {
		n.Refused = map[string]shared.Refusal{"auth.session_timeout": {Hash: RefusalHash(b.rt.Hub().Keys(), "auth.session_timeout", sv),
			Kept: json.RawMessage(`"1h"`), Reason: "it broke", At: time.Now()}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if c := b.load(); c.Auth.SessionTimeout != "1h" || c.Source("auth.session_timeout").Kind != config.FromKept {
		t.Fatalf("B keeps %q (%+v)", c.Auth.SessionTimeout, c.Source("auth.session_timeout"))
	}
	if _, err := b.edit("n_siem-b", b.layer(), config.ScopeCluster, config.Edit{Retry: []string{"auth.session_timeout"}, By: "bob"}, nil); err != nil {
		t.Fatal(err)
	}
	if nc, _ := b.rt.NodeCfg().Get(); len(nc.Refused) != 0 {
		t.Errorf("still refused: %+v", nc.Refused)
	}
	if v, _ := b.setting("auth.session_timeout"); v.Rev != 1 {
		t.Errorf("trying again changed the shared value: %+v", v)
	}
	if c := b.load(); c.Auth.SessionTimeout != "8h" {
		t.Errorf("B runs with %q", c.Auth.SessionTimeout)
	}

	// The cluster's name is kept with the cluster.
	if _, err := a.edit("n_siem-a", a.layer(), config.ScopeCluster, config.Edit{Values: map[string]any{"cluster.name": "Production"}, By: "alice"}, nil); err != nil {
		t.Fatal(err)
	}
	if cb, _ := a.rt.Cluster().Get(); cb.Name != "Production" {
		t.Errorf("cluster name %q", cb.Name)
	}
	if _, ok := a.setting("cluster.name"); ok {
		t.Error("cluster.name is in the settings document")
	}
}

// TestSettingsAppliedWhenChanged (W9): an unchanged environment variable
// does not undo a change made on the page; a changed one applies once, and
// is audited; a setting removed from signalith.yaml changes nothing; and a
// server's first start with shared settings only records what its files
// say.
func TestSettingsAppliedWhenChanged(t *testing.T) {
	o := newOS(t)
	t.Setenv("SIGNALITH_PUBLIC_URL", "https://siem.example.org:8443")
	dirA := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dirA, authConfig(t, dirA, "search:\n  max_events: 500\n"), nil)
	if v, _ := a.setting("server.public_url"); rawString(v.Value) != `"https://siem.example.org:8443"` {
		t.Fatalf("not imported: %+v", v)
	}
	a.load()
	if res := a.apply(); len(res.Applied) != 0 {
		t.Fatalf("first apply %+v", res)
	}
	if _, err := a.edit("n_siem-a", a.layer(), config.ScopeCluster, config.Edit{Values: map[string]any{"server.public_url": "https://page.example.org:8443"}, By: "alice"}, nil); err != nil {
		t.Fatal(err)
	}
	a.cycle()
	a.load()
	if res := a.apply(); len(res.Applied) != 0 {
		t.Fatalf("an unchanged environment applied %v", res.Applied)
	}
	if v, _ := a.setting("server.public_url"); rawString(v.Value) != `"https://page.example.org:8443"` {
		t.Fatalf("an unchanged environment undid the page: %+v", v)
	}

	t.Setenv("SIGNALITH_PUBLIC_URL", "https://new.example.org:8443")
	a.load()
	if res := a.apply(); !reflect.DeepEqual(res.Applied, []string{"server.public_url"}) {
		t.Fatalf("a changed environment %+v", res)
	}
	a.cycle()
	v, _ := a.setting("server.public_url")
	if rawString(v.Value) != `"https://new.example.org:8443"` || v.From.Source != FromEnv || v.From.Node != "siem-a" || v.Rev != 3 {
		t.Errorf("after the change %+v", v)
	}
	mustContain(t, "the audit", a.logs.String(), "server.public_url applied from the environment on siem-a")
	if c := a.load(); c.Value("server.public_url") != "https://new.example.org:8443" || c.Source("server.public_url").Applied != "env" {
		t.Errorf("runs with %q (%+v)", c.Value("server.public_url"), c.Source("server.public_url"))
	}
	if res := a.apply(); len(res.Applied) != 0 {
		t.Fatalf("applied twice: %v", res.Applied)
	}

	// Removed from signalith.yaml: the shared value stays.
	a.rewrite("")
	if res := a.apply(); len(res.Applied) != 0 {
		t.Fatalf("a removed setting applied %v", res.Applied)
	}
	if v, _ := a.setting("search.max_events"); rawString(v.Value) != "500" {
		t.Errorf("max events %+v", v)
	}

	// B joins with its own value: its first start only records it.
	t.Setenv("SIGNALITH_PUBLIC_URL", "")
	dirB := t.TempDir()
	b := newAuthMember(t, o, "siem-b", dirB, authConfig(t, dirB, "search:\n  max_events: 777\n"), a.key())
	b.cycle()
	b.load()
	if res := b.apply(); !reflect.DeepEqual(res.Applied, []string{"ingest.tokens"}) {
		t.Fatalf("B's first apply %+v", res)
	}
	if v, _ := b.setting("search.max_events"); rawString(v.Value) != "500" {
		t.Errorf("B's first start changed max events: %+v", v)
	}
	if nc, _ := b.rt.NodeCfg().Get(); nc.SettingsApplied == "" {
		t.Error("B's first start is not recorded")
	}
	b.rewrite("search:\n  max_events: 888\n")
	if res := b.apply(); !reflect.DeepEqual(res.Applied, []string{"search.max_events"}) {
		t.Fatalf("B's change %+v", res)
	}
	a.cycle()
	if v, _ := a.setting("search.max_events"); rawString(v.Value) != "888" || v.From.Source != FromYAML || v.From.Node != "siem-b" {
		t.Errorf("max events %+v", v)
	}
	if c := a.load(); c.Search.MaxEvents != 888 || c.Value("server.public_url") != "https://new.example.org:8443" {
		t.Errorf("A runs with %d and %q", c.Search.MaxEvents, c.Value("server.public_url"))
	}
}

// TestIngestTokensUnion (W10): every server accepts the agent tokens of
// every server's files, added at a server's first start; an unchanged
// SIGNALITH_INGEST_TOKEN does not bring back a token taken out, and a
// changed one replaces that server's, once, audited.
func TestIngestTokensUnion(t *testing.T) {
	o := newOS(t)
	dirA := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dirA, authConfig(t, dirA, ""), nil)
	t.Setenv("SIGNALITH_INGEST_TOKEN", "tok-bbbb-0123456789ab")
	dirB := t.TempDir()
	b := newAuthMember(t, o, "siem-b", dirB, authConfig(t, dirB, ""), a.key())
	b.cycle()
	b.load()
	if res := b.apply(); !slices.Contains(res.Applied, "ingest.tokens") {
		t.Fatalf("B's first apply %+v", res)
	}
	a.cycle()
	want := map[string][]string{"n_siem-a/yaml": {"tok-0123456789abcdef"}, "n_siem-b/yaml": {"tok-0123456789abcdef"}, "n_siem-b/env": {"tok-bbbb-0123456789ab"}}
	if got := tokensOf(t, a.member); !reflect.DeepEqual(got, want) {
		t.Fatalf("tokens %v", got)
	}
	if c := a.load(); !slices.Contains(c.Ingest.Tokens, "tok-bbbb-0123456789ab") {
		t.Errorf("A does not accept B's token: %v", c.Ingest.Tokens)
	}
	if res := b.apply(); len(res.Applied) != 0 {
		t.Fatalf("unchanged tokens applied %v", res.Applied)
	}

	// Taken out: an unchanged environment does not bring it back.
	ctx := context.Background()
	if _, err := a.docs.Settings().Mutate(ctx, "alice", func(sb *SettingsBody) error {
		sb.IngestTokens = slices.DeleteFunc(sb.IngestTokens, func(t IngestToken) bool { return t.Node == "n_siem-b" && t.Source == "env" })
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	b.load()
	if res := b.apply(); len(res.Applied) != 0 {
		t.Fatalf("an unchanged environment applied %v", res.Applied)
	}
	if got := tokensOf(t, b.member); len(got["n_siem-b/env"]) != 0 {
		t.Errorf("the token came back: %v", got)
	}

	t.Setenv("SIGNALITH_INGEST_TOKEN", "tok-cccc-0123456789ab")
	b.load()
	if res := b.apply(); !reflect.DeepEqual(res.Applied, []string{"ingest.tokens"}) {
		t.Fatalf("a changed token %+v", res)
	}
	mustContain(t, "the audit", b.logs.String(), "ingest.tokens applied from the environment on siem-b")
	a.cycle()
	want["n_siem-b/env"] = []string{"tok-cccc-0123456789ab"}
	if got := tokensOf(t, a.member); !reflect.DeepEqual(got, want) {
		t.Errorf("tokens %v", got)
	}
	c := a.load()
	if !slices.Contains(c.Ingest.Tokens, "tok-cccc-0123456789ab") || slices.Contains(c.Ingest.Tokens, "tok-bbbb-0123456789ab") {
		t.Errorf("A accepts %v", c.Ingest.Tokens)
	}
	// Add data names the server whose files brought each one.
	if i := slices.Index(c.Ingest.Tokens, "tok-cccc-0123456789ab"); i < 0 || c.IngestTokenSource(i) != "the environment of siem-b" {
		t.Errorf("B's token is said to come from %q", c.IngestTokenSource(i))
	}
	if res := b.apply(); len(res.Applied) != 0 {
		t.Fatalf("applied twice: %v", res.Applied)
	}
}

// An address with a user name and password in it, in a server's
// signalith.yaml, is neither imported into the shared settings nor
// applied when it changes: they are kept unencrypted and shown on every
// server's page. The same address without them is.
func TestAddressWithPasswordNotShared(t *testing.T) {
	o := newOS(t)
	dirA := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dirA, authConfig(t, dirA, "assistant:\n  url: https://user:pw@llm.internal/v1\n"), nil)
	if v, ok := a.setting("assistant.url"); ok {
		t.Fatalf("imported: %+v", v)
	}
	mustContain(t, "the log", a.logs.String(), "not imported into the shared settings")
	a.load()
	a.apply()
	a.rewrite("assistant:\n  url: https://user:other@llm.internal/v1\n")
	if res := a.apply(); len(res.Applied) != 0 {
		t.Fatalf("applied %v", res.Applied)
	}
	if v, ok := a.setting("assistant.url"); ok {
		t.Fatalf("shared: %+v", v)
	}
	mustContain(t, "the log", a.logs.String(), `"settings":"assistant.url"`)
	a.rewrite("assistant:\n  url: https://llm.internal/v1\n")
	if res := a.apply(); !slices.Contains(res.Applied, "assistant.url") {
		t.Fatalf("the address without a password %+v", res)
	}
	a.cycle()
	if v, _ := a.setting("assistant.url"); rawString(v.Value) != `"https://llm.internal/v1"` {
		t.Errorf("shared %+v", v)
	}
}

// TestSettingsDrift (W11): a value in a server's files that differs from
// the shared one without having changed is drift, auth.admin_user too
// (it is never applied); passwords from the environment never are.
func TestSettingsDrift(t *testing.T) {
	o := newOS(t)
	dirA := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dirA, authConfig(t, dirA, ""), nil)
	t.Setenv("SIGNALITH_ASSISTANT_API_KEY", "sk-env-of-b")
	dirB := t.TempDir()
	b := newAuthMember(t, o, "siem-b", dirB, authConfig(t, dirB, "  admin_user: root\nsearch:\n  max_events: 777\n  default_earliest: -24h\n"), a.key())
	b.cycle()
	b.load()
	res := b.apply()
	if !reflect.DeepEqual(res.Drift, []string{"search.max_events", "auth.admin_user"}) {
		t.Errorf("drift %v", res.Drift)
	}
	if slices.Contains(res.Applied, "auth.admin_user") || slices.Contains(res.Applied, "assistant.api_key") {
		t.Errorf("applied %v", res.Applied)
	}
	if name, _, _ := a.auth.Builtin(); name != "admin" {
		t.Errorf("the built-in admin is %q", name)
	}
	// Changed later: still never applied.
	b.rewrite("  admin_user: root2\nsearch:\n  max_events: 777\n  default_earliest: -24h\n")
	if res := b.apply(); slices.Contains(res.Applied, "auth.admin_user") {
		t.Errorf("auth.admin_user applied: %v", res.Applied)
	}
	if name, _, _ := a.auth.Builtin(); name != "admin" {
		t.Errorf("the built-in admin is %q", name)
	}
}

// TestForgedSettingsDoc (W24): a settings document changed in OpenSearch
// without the cluster key is refused and reported, and the last good copy
// stays in use.
func TestForgedSettingsDoc(t *testing.T) {
	o := newOS(t)
	dirA, dirB := t.TempDir(), t.TempDir()
	a := newAuthMember(t, o, "siem-a", dirA, authConfig(t, dirA, ""), nil)
	b := newAuthMember(t, o, "siem-b", dirB, authConfig(t, dirB, ""), a.key())
	if _, err := a.edit("n_siem-a", a.layer(), config.ScopeCluster, config.Edit{Values: map[string]any{"server.trusted_proxies": []any{"10.0.0.5"}}, By: "alice"}, nil); err != nil {
		t.Fatal(err)
	}
	b.cycle()
	if c := b.load(); !slices.Equal(c.Server.TrustedProxies, []string{"10.0.0.5"}) {
		t.Fatalf("B's proxies %v", c.Server.TrustedProxies)
	}
	index := shared.ConfigIndex(testPrefix)
	src := o.fake.Source(index, SettingsID)
	src["body"] = strings.Replace(src["body"].(string), "10.0.0.5", "0.0.0.0/0", 1)
	o.fake.Put(index, SettingsID, src)
	b.cycle()
	if !slices.Contains(b.rt.Hub().Tamper(), SettingsID) {
		t.Errorf("not reported: %v", b.rt.Hub().Tamper())
	}
	if c := b.load(); !slices.Equal(c.Server.TrustedProxies, []string{"10.0.0.5"}) {
		t.Errorf("B took the forged copy: %v", c.Server.TrustedProxies)
	}
}
