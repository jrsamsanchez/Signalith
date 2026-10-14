package config

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// clusterKey is a cluster's key for the tests, and sealing gives a layer
// its Open and Seal with it.
func clusterKey(t *testing.T) *secrets.Key {
	t.Helper()
	k, err := secrets.NewKey(bytes.Repeat([]byte{7}, 32), "cluster key")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sealing(sh *Shared, k *secrets.Key) *Shared {
	sh.Open = func(key, sealed, sentTo string) (string, error) { return k.Open(SharedField(key, sentTo), sealed) }
	sh.Seal = func(key, plain, sentTo string) (string, error) { return k.Seal(SharedField(key, sentTo), plain) }
	return sh
}

func jsonOf(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func pageEntry(t *testing.T, v any) *PageEntry {
	t.Helper()
	p := &PageSettings{}
	if err := p.Set("x", v, "bob", time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	return p.Settings["x"]
}

// TestSharedKeysAndScopes (W1): the settings the servers share in one
// document are the shared ones, and every setting has exactly one home:
// that document, a document of its own, a server's own settings or
// settings.yaml.
func TestSharedKeysAndScopes(t *testing.T) {
	keys := SharedKeys()
	for _, k := range keys {
		if ScopeOf(k) != ScopeCluster {
			t.Errorf("%s is shared but its scope is %q", k, ScopeOf(k))
		}
	}
	for _, k := range []string{"retention.interval", "ingest.tokens", "auth.session_timeout", "server.public_url", "cluster.opensearch_url", "assistant.api_key"} {
		if !slices.Contains(keys, k) {
			t.Errorf("SharedKeys lacks %s", k)
		}
	}
	// Kept with documents of their own: the cluster's name with the
	// cluster, the retention policies, the feeds, directory sign-in and
	// the built-in admin.
	own := []string{"cluster.name", "retention.days", "retention.default", "retention.policies", "retention.guard",
		"intel.feeds", "auth.ldap", "auth.admin_user", "auth.admin_password_hash"}
	for _, k := range LeafKeys() {
		homes := 0
		if slices.Contains(keys, k) {
			homes++
		}
		if slices.Contains(own, k) {
			homes++
			if ScopeOf(k) != ScopeCluster {
				t.Errorf("%s has a shared document but scope %q", k, ScopeOf(k))
			}
		}
		if sc := ScopeOf(k); sc == ScopeServer || sc == ScopeBootstrap {
			homes++
		}
		if homes != 1 {
			t.Errorf("%s has %d places it is kept, want 1", k, homes)
		}
	}
	if slices.Contains(keys, "cluster.name") {
		t.Error("cluster.name is in the settings document; it is kept with the cluster")
	}
	if s, _ := Lookup("ingest.max_event_age"); !s.Live() {
		t.Error("ingest.max_event_age waits for a restart")
	}
	if got := SharedField("assistant.api_key", "https://api.anthropic.com:443"); got != "settings.assistant.api_key@https://api.anthropic.com:443" {
		t.Errorf("SharedField %q", got)
	}
	if got := SharedField("ingest.tokens", ""); got != "settings.ingest.tokens" {
		t.Errorf("SharedField %q", got)
	}
	// Each page shows one of the two names of the same setting.
	for _, c := range []struct {
		key            string
		legacy, shared bool
	}{
		{"detections.scheduler", true, false}, {"cluster.leader_eligible", false, true},
		{"cluster.name", false, true}, {"server.node_url", false, true}, {"search.max_events", true, true},
	} {
		s, ok := Lookup(c.key)
		if !ok || s.OnPage(false) != c.legacy || s.OnPage(true) != c.shared {
			t.Errorf("%s on the page: %v %v", c.key, s.OnPage(false), s.OnPage(true))
		}
	}
}

// TestLeaderEligibleAlias (W1): cluster.leader_eligible reads
// detections.scheduler, its old name, and both say the value in effect.
func TestLeaderEligibleAlias(t *testing.T) {
	load := func(extra string) *Config {
		t.Helper()
		c, err := Load(writeConfig(t, extra))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := load("detections:\n  scheduler: false\n")
	if c.LeaderEligible() || c.Value("cluster.leader_eligible") != false || c.Source("cluster.leader_eligible").Kind != FromFile {
		t.Errorf("old name: %v %v %+v", c.LeaderEligible(), c.Value("cluster.leader_eligible"), c.Source("cluster.leader_eligible"))
	}
	if c := load(""); !c.LeaderEligible() || !c.Detections.Scheduler {
		t.Error("off by default")
	}
	c = load("detections:\n  scheduler: false\ncluster:\n  leader_eligible: true\n")
	if !c.LeaderEligible() || !c.Detections.Scheduler {
		t.Errorf("the new name does not win: %v %v", c.LeaderEligible(), c.Detections.Scheduler)
	}
	if w := strings.Join(c.Warnings(), "\n"); !strings.Contains(w, "detections.scheduler (false) in signalith.yaml is the old name of cluster.leader_eligible") {
		t.Errorf("no warning:\n%s", w)
	}
	if w := strings.Join(load("detections:\n  scheduler: true\ncluster:\n  leader_eligible: true\n").Warnings(), "\n"); strings.Contains(w, "old name") {
		t.Errorf("a warning for the same value:\n%s", w)
	}
	t.Setenv("SIGNALITH_LEADER_ELIGIBLE", "false")
	c = load("cluster:\n  leader_eligible: true\n")
	for _, k := range []string{"cluster.leader_eligible", "detections.scheduler"} {
		if c.Value(k) != false || c.Source(k).Env != "SIGNALITH_LEADER_ELIGIBLE" {
			t.Errorf("%s from the environment: %v %+v", k, c.Value(k), c.Source(k))
		}
	}
	t.Setenv("SIGNALITH_LEADER_ELIGIBLE", "maybe")
	if _, err := Load(writeConfig(t, "")); err == nil || !strings.Contains(err.Error(), "SIGNALITH_LEADER_ELIGIBLE") {
		t.Errorf("a bad value is taken: %v", err)
	}
	t.Setenv("SIGNALITH_LEADER_ELIGIBLE", "")

	// On a server that keeps its settings to itself, the page saves the
	// old name, which wins over the new one in signalith.yaml.
	path := writeConfig(t, "cluster:\n  leader_eligible: true\n")
	res, err := CheckEdit(path, Edit{Values: map[string]any{"detections.scheduler": false, "cluster.leader_eligible": false, "server.node_url": "https://10.0.0.5:8080"}, By: "ann"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Fields["cluster.leader_eligible"] == "" || res.Fields["server.node_url"] == "" || res.Fields["detections.scheduler"] != "" {
		t.Fatalf("fields %v", res.Fields)
	}
	if res.Config.LeaderEligible() || res.Config.Detections.Scheduler || !slices.Equal(res.Changed, []string{"detections.scheduler"}) {
		t.Errorf("after %v %v %v", res.Config.LeaderEligible(), res.Config.Detections.Scheduler, res.Changed)
	}
	if err := WritePageSettings(res.Config.SettingsFile(), res.Page); err != nil {
		t.Fatal(err)
	}
	if c, err := Load(path); err != nil || c.LeaderEligible() || c.Source("cluster.leader_eligible").Kind != FromPage {
		t.Errorf("saved %v %+v", err, c.Source("cluster.leader_eligible"))
	}
}

// sharedFixture is a server whose signalith.yaml, environment and
// settings.yaml set settings of every scope.
func sharedFixture(t *testing.T) (string, *Shared) {
	t.Helper()
	path := writeConfig(t, "server:\n  listen: 0.0.0.0:8080\n  public_url: https://yaml.example:8080\n"+
		"search:\n  max_events: 500\nopensearch:\n  index_prefix: fromyaml\ningest:\n  tokens: [yaml-token-0123456789abcdef]\n")
	t.Setenv("SIGNALITH_PUBLIC_URL", "https://env.example:8080")
	t.Setenv("SIGNALITH_LISTEN", "0.0.0.0:9090")
	t.Setenv("SIGNALITH_INGEST_TOKEN", "env-token-0123456789abcdef")
	writePage(t, path, "settings:\n  auth.session_timeout:\n    value: 2h\n  opensearch.index_prefix:\n    value: pageprefix\n  syslog.udp:\n    value: 0.0.0.0:5514\n")
	k := clusterKey(t)
	token, err := k.Seal(SharedField("ingest.tokens", ""), "shared-token-0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	sh := sealing(&Shared{Self: "siem-b",
		Cluster: map[string]SharedValue{
			"server.public_url":    {Value: jsonOf(t, "https://shared.example:8443"), Rev: 3, From: Source{Kind: FromPage, Node: "siem-a", By: "bob", At: at}},
			"auth.session_timeout": {Value: jsonOf(t, "8h"), Rev: 1, From: Source{Kind: "env", Node: "siem-a", At: at}},
			"cluster.name":         {Value: jsonOf(t, "SOC")},
			"ingest.tokens":        {Value: jsonOf(t, []string{token})},
		},
		Server:    map[string]*PageEntry{"syslog.tcp": pageEntry(t, "0.0.0.0:6514"), "server.listen": pageEntry(t, "0.0.0.0:7070")},
		TokenFrom: []string{"the environment of siem-a"},
	}, k)
	return path, sh
}

// TestLoadSharedPrecedence (W2): a shared setting takes the shared value
// whatever signalith.yaml, the environment and settings.yaml say, or its
// default; a server's own setting keeps env > its values in the layer >
// signalith.yaml > default; one needed to reach OpenSearch is as before.
// Without a layer nothing changes.
func TestLoadSharedPrecedence(t *testing.T) {
	path, sh := sharedFixture(t)
	c, err := LoadShared(path, sh)
	if err != nil {
		t.Fatal(err)
	}
	if !c.SharedSettings() {
		t.Error("not built with a shared layer")
	}
	for _, w := range []struct {
		key  string
		val  any
		kind string
	}{
		{"server.public_url", "https://shared.example:8443", FromShared},
		{"auth.session_timeout", "8h", FromShared},
		{"cluster.name", "SOC", FromShared},
		{"search.max_events", 10000, FromDefault},
		{"ingest.tokens", []string{"shared-token-0123456789abcdef"}, FromShared},
		{"opensearch.index_prefix", "pageprefix", FromPage},
		{"syslog.udp", "", FromDefault},
		{"syslog.tcp", "0.0.0.0:6514", FromPage},
		{"server.listen", "0.0.0.0:9090", FromEnv},
	} {
		if got := c.Value(w.key); !reflect.DeepEqual(got, w.val) || c.Source(w.key).Kind != w.kind {
			t.Errorf("%s: %v from %+v, want %v from %s", w.key, got, c.Source(w.key), w.val, w.kind)
		}
	}
	if src := c.Source("server.public_url"); src.Node != "siem-a" || src.By != "bob" || src.Applied != "" {
		t.Errorf("public address from %+v", src)
	}
	if src := c.Source("auth.session_timeout"); src.Applied != "env" {
		t.Errorf("session timeout from %+v", src)
	}
	// Each shared token is said to come from the server that brought it.
	if c.IngestTokenSource(0) != "the environment of siem-a" || len(c.Ingest.Tokens) != 1 {
		t.Errorf("tokens %v from %q", c.Ingest.Tokens, c.IngestTokenSource(0))
	}
	w := strings.Join(c.SettingsWarnings(), "\n")
	for _, k := range []string{"auth.session_timeout", "syslog.udp"} {
		if !strings.Contains(w, "has "+k+", which the servers keep in OpenSearch now") {
			t.Errorf("no warning for %s in settings.yaml:\n%s", k, w)
		}
	}
	if strings.Contains(w, "opensearch.index_prefix") {
		t.Errorf("a warning for a connection setting:\n%s", w)
	}
	// Reset goes back to the default for a shared setting.
	if b := c.Base(); b.Auth.SessionTimeout != "" || b.Server.Listen != "0.0.0.0:9090" {
		t.Errorf("base %q %q", b.Auth.SessionTimeout, b.Server.Listen)
	}
	// A shared value taken away gives the default.
	delete(sh.Cluster, "auth.session_timeout")
	if c, err := LoadShared(path, sh); err != nil || c.Auth.SessionTimeout != "" || c.SessionIdle() != 12*time.Hour {
		t.Errorf("without the shared value: %v %q", err, c.Auth.SessionTimeout)
	}

	// Without a layer: as before.
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]any{
		"server.public_url": "https://env.example:8080", "auth.session_timeout": "2h", "search.max_events": 500,
		"ingest.tokens": []string{"yaml-token-0123456789abcdef", "env-token-0123456789abcdef"},
		"syslog.udp":    "0.0.0.0:5514", "server.listen": "0.0.0.0:9090", "opensearch.index_prefix": "pageprefix",
	} {
		if got := c.Value(k); !reflect.DeepEqual(got, v) {
			t.Errorf("without a layer %s: %v, want %v", k, got, v)
		}
	}
	if c.SharedSettings() {
		t.Error("shared without a layer")
	}
	// LoadShared without a layer is Load, setting by setting.
	n, err := LoadShared(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range LeafKeys() {
		if !reflect.DeepEqual(c.Value(k), n.Value(k)) || c.Source(k) != n.Source(k) {
			t.Errorf("%s: %v %+v, with no layer %v %+v", k, c.Value(k), c.Source(k), n.Value(k), n.Source(k))
		}
	}
}

// TestSharedRefusalKeepsTheValue: a shared value this server refused is
// not used here until it changes; the value it kept is.
func TestSharedRefusalKeepsTheValue(t *testing.T) {
	path := writeConfig(t, "server:\n  tls:\n    names: [yaml.example]\n")
	v := SharedValue{Value: jsonOf(t, []string{"new.example"}), Rev: 2}
	sh := &Shared{Cluster: map[string]SharedValue{"server.tls.names": v},
		Refused: map[string]SharedRefusal{"server.tls.names": {Hash: SharedHash("server.tls.names", v), Kept: jsonOf(t, []string{"kept.example"}), Reason: "no", At: time.Now()}}}
	c, err := LoadShared(path, sh)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Server.TLSNames(), []string{"kept.example"}) || c.Source("server.tls.names").Kind != FromKept {
		t.Errorf("kept %v %+v", c.Server.TLSNames(), c.Source("server.tls.names"))
	}
	if _, ok := c.SharedKept("server.tls.names"); !ok {
		t.Error("SharedKept")
	}
	// Who changed it is not part of the value: the refusal still holds.
	v.Rev, v.From = 3, Source{Kind: FromPage, By: "ann"}
	sh.Cluster["server.tls.names"] = v
	if c, _ := LoadShared(path, sh); !slices.Equal(c.Server.TLSNames(), []string{"kept.example"}) {
		t.Errorf("same value, new rev: %v", c.Server.TLSNames())
	}
	// Another value is used again.
	sh.Cluster["server.tls.names"] = SharedValue{Value: jsonOf(t, []string{"other.example"})}
	if c, _ := LoadShared(path, sh); !slices.Equal(c.Server.TLSNames(), []string{"other.example"}) || c.Source("server.tls.names").Kind != FromShared {
		t.Errorf("a new value %v", c.Server.TLSNames())
	}
	// A value that is not of the setting's type is left out and reported.
	sh.Cluster["server.tls.names"] = SharedValue{Value: jsonOf(t, 5)}
	c, err = LoadShared(path, sh)
	if err != nil || len(c.Server.TLSNames()) != 0 || !strings.Contains(strings.Join(c.SettingsWarnings(), "\n"), "server.tls.names: the shared value cannot be read") {
		t.Errorf("a bad value: %v %v %v", err, c.Server.TLSNames(), c.SettingsWarnings())
	}
}

// TestSharedSecrets (W3): a shared password or key is sealed with the
// cluster's key for its setting and the address it is sent to; when the
// address moves, it is not used until it is entered again.
func TestSharedSecrets(t *testing.T) {
	path := writeConfig(t, "assistant:\n  api_key: sk-yaml\n")
	t.Setenv("SIGNALITH_ASSISTANT_API_KEY", "sk-env")
	k := clusterKey(t)
	sealed, err := k.Seal(SharedField("assistant.api_key", "https://llm.example:443"), "sk-shared")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Open(SharedField("assistant.api_key", "https://other.example:443"), sealed); err == nil {
		t.Fatal("a key sealed for one address opens for another")
	}
	sh := sealing(&Shared{Self: "siem-a", Cluster: map[string]SharedValue{
		"assistant.provider": {Value: jsonOf(t, "openai")},
		"assistant.url":      {Value: jsonOf(t, "https://llm.example/v1")},
		"assistant.model":    {Value: jsonOf(t, "m1")},
		"assistant.api_key":  {Secret: sealed, SentTo: "https://llm.example:443", Rev: 4},
	}}, k)
	c, err := LoadShared(path, sh)
	if err != nil {
		t.Fatal(err)
	}
	if c.Assistant.APIKey != "sk-shared" || c.Source("assistant.api_key").Kind != FromShared {
		t.Fatalf("key %q %+v", c.Assistant.APIKey, c.Source("assistant.api_key"))
	}
	// Without the cluster's key it cannot be read, and the field says so.
	noKey := sh.Clone()
	noKey.Open = nil
	if c, err := LoadShared(path, noKey); err != nil || c.Assistant.APIKey != "" || !strings.Contains(c.PageSecretProblem("assistant.api_key"), "cluster's key") {
		t.Errorf("without the key: %v %q %q", err, c.Assistant.APIKey, c.PageSecretProblem("assistant.api_key"))
	}
	// The address moved without the key entered again: not used.
	moved := sh.Clone()
	moved.Cluster["assistant.url"] = SharedValue{Value: jsonOf(t, "https://other.example/v1")}
	c, err = LoadShared(path, moved)
	if err != nil || c.Assistant.APIKey != "" || !strings.Contains(strings.Join(c.SettingsWarnings(), "\n"), "assistant.api_key is not used: it is only sent to https://llm.example:443") {
		t.Errorf("moved: %v %q %v", err, c.Assistant.APIKey, c.SettingsWarnings())
	}
	// Moving it on the page asks for the key again...
	res, err := CheckEditShared(path, sh, ScopeCluster, Edit{Values: map[string]any{"assistant.url": "https://third.example/v1"}, By: "ann"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Fields["assistant.api_key"], "Enter the API key again") {
		t.Errorf("fields %v", res.Fields)
	}
	// ...which is then sealed for the new address.
	res, err = CheckEditShared(path, sh, ScopeCluster, Edit{Values: map[string]any{"assistant.url": "https://third.example/v1", "assistant.api_key": "sk-new"}, By: "ann"})
	if err != nil || !res.OK() {
		t.Fatalf("%v %v %v", err, res.Fields, res.Problems)
	}
	v := res.Shared.Cluster["assistant.api_key"]
	if v.SentTo != "https://third.example:443" || v.Rev != 4 || v.From.By != "ann" || v.From.Node != "siem-a" {
		t.Errorf("saved %+v", v)
	}
	if plain, err := k.Open(SharedField("assistant.api_key", v.SentTo), v.Secret); err != nil || plain != "sk-new" {
		t.Errorf("sealed %q %v", plain, err)
	}
	if !slices.Equal(res.Touched, []string{"assistant.api_key", "assistant.url"}) || res.Config.Assistant.APIKey != "sk-new" {
		t.Errorf("touched %v, key %q", res.Touched, res.Config.Assistant.APIKey)
	}
	if sh.Cluster["assistant.api_key"].Secret != sealed {
		t.Error("the layer checked was changed")
	}
	// A key cleared on the page is none.
	res, err = CheckEditShared(path, sh, ScopeCluster, Edit{Clear: []string{"assistant.api_key"}, By: "ann"})
	if err != nil || res.Shared.Cluster["assistant.api_key"].Secret != "" || res.Config.Assistant.APIKey != "" {
		t.Errorf("cleared %v %+v", err, res.Shared.Cluster["assistant.api_key"])
	}
}

// TestSourceValues (W4): what signalith.yaml and the environment each
// set for a setting, decrypted, only where they set it.
func TestSourceValues(t *testing.T) {
	path := writeConfig(t, "")
	c0, err := LoadUnchecked(path)
	if err != nil {
		t.Fatal(err)
	}
	useKeyring(t, c0.Keyring())
	key, err := c0.Keyring().Seal("assistant.api_key", "sk-yaml")
	if err != nil {
		t.Fatal(err)
	}
	token, err := c0.Keyring().Seal("ingest.tokens", "yaml-token-0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	data = append(data, []byte("assistant:\n  provider: anthropic\n  api_key: "+key+"\nserver:\n  public_url: https://yaml.example:8080\ningest:\n  tokens: ["+token+"]\n")...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_ASSISTANT_API_KEY", "sk-env")
	t.Setenv("SIGNALITH_INGEST_TOKEN", "env-token-0123456789abcdef")
	legacy, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := LoadShared(path, &Shared{})
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]*Config{"without a layer": legacy, "with one": shared} {
		want := map[string][]SourceValue{
			"assistant.api_key": {{Source: "yaml", Value: "sk-yaml"}, {Source: "env", Value: "sk-env", Env: "SIGNALITH_ASSISTANT_API_KEY"}},
			"server.public_url": {{Source: "yaml", Value: "https://yaml.example:8080"}},
			"ingest.tokens":     {{Source: "yaml", Value: []string{"yaml-token-0123456789abcdef"}}, {Source: "env", Value: []string{"env-token-0123456789abcdef"}, Env: "SIGNALITH_INGEST_TOKEN"}},
			"search.max_events": nil,
		}
		for k, w := range want {
			if got := c.SourceValues(k); !reflect.DeepEqual(got, w) {
				t.Errorf("%s: %s %+v, want %+v", name, k, got, w)
			}
		}
	}
	// With a layer, neither is in effect.
	if shared.Assistant.APIKey != "" || len(shared.Ingest.Tokens) != 0 || shared.Server.PublicURL == "https://yaml.example:8080" {
		t.Errorf("files in effect: %q %v %q", shared.Assistant.APIKey, shared.Ingest.Tokens, shared.Server.PublicURL)
	}
}

// TestServerSettingsHandEdited (W12, config part): a server's own setting
// changed in signalith.yaml applies when its page never changed it; when
// the page did, the page's value is used, and the file's is still known.
func TestServerSettingsHandEdited(t *testing.T) {
	path := writeConfig(t, "server:\n  listen: 0.0.0.0:8080\n")
	sh := &Shared{}
	if c, err := LoadShared(path, sh); err != nil || c.Server.Listen != "0.0.0.0:8080" || c.Source("server.listen").Kind != FromFile {
		t.Fatalf("%v %+v", err, c)
	}
	if err := os.WriteFile(path, bytes.Replace(mustRead(t, path), []byte("0.0.0.0:8080"), []byte("0.0.0.0:8181"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := LoadShared(path, sh); err != nil || c.Server.Listen != "0.0.0.0:8181" {
		t.Errorf("hand edit: %v %q", err, c.Server.Listen)
	}
	sh.Server = map[string]*PageEntry{"server.listen": pageEntry(t, "0.0.0.0:7070")}
	c, err := LoadShared(path, sh)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Listen != "0.0.0.0:7070" || c.Source("server.listen").Kind != FromPage {
		t.Errorf("page: %q %+v", c.Server.Listen, c.Source("server.listen"))
	}
	if sv := c.SourceValues("server.listen"); len(sv) != 1 || sv[0].Value != "0.0.0.0:8181" {
		t.Errorf("file's value %+v", sv)
	}
	// A server's own value that breaks the start is left out, with the
	// shared settings kept.
	sh.Server["server.listen"] = pageEntry(t, "nowhere")
	sh.Cluster = map[string]SharedValue{"search.max_events": {Value: jsonOf(t, 42)}}
	c, err = LoadShared(path, sh)
	if err != nil || c.Server.Listen != "0.0.0.0:8181" || c.Search.MaxEvents != 42 || !strings.Contains(c.SettingsProblem(), "server.listen") {
		t.Errorf("broken: %v %q %d %q", err, c.Server.Listen, c.Search.MaxEvents, c.SettingsProblem())
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCheckEditSharedScopes: each scope's edit lands in its own place,
// and a setting of another scope is refused at its field.
func TestCheckEditSharedScopes(t *testing.T) {
	path, sh := sharedFixture(t)
	res, err := CheckEditShared(path, sh, ScopeServer, Edit{Values: map[string]any{
		"syslog.tls": "0.0.0.0:6515", "detections.scheduler": false, "search.max_events": float64(5), "server.listen": "0.0.0.0:1",
	}, Reset: []string{"syslog.tcp"}, By: "ann"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Fields["search.max_events"], "every server shares") || !strings.Contains(res.Fields["server.listen"], "SIGNALITH_LISTEN") {
		t.Errorf("fields %v", res.Fields)
	}
	if e := res.Shared.Server["syslog.tls"]; e == nil || e.ChangedBy != "ann" || res.Shared.Server["syslog.tcp"] != nil {
		t.Errorf("server %v", res.Shared.Server)
	}
	if res.Shared.Server["cluster.leader_eligible"] == nil || res.Config.LeaderEligible() {
		t.Errorf("old name: %v", res.Shared.Server)
	}
	if !slices.Equal(res.Touched, []string{"cluster.leader_eligible", "syslog.tcp", "syslog.tls"}) || res.Page != nil {
		t.Errorf("touched %v page %v", res.Touched, res.Page)
	}
	if !slices.Contains(res.Changed, "cluster.leader_eligible") || slices.Contains(res.Changed, "detections.scheduler") {
		t.Errorf("changed %v", res.Changed)
	}
	if sh.Server["syslog.tcp"] == nil {
		t.Error("the layer checked was changed")
	}

	res, err = CheckEditShared(path, sh, ScopeCluster, Edit{Values: map[string]any{"search.max_events": float64(5), "auth.session_timeout": "8h", "syslog.udp": "0.0.0.0:1"}, By: "ann"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Fields["syslog.udp"] == "" || len(res.Fields) != 1 {
		t.Errorf("fields %v", res.Fields)
	}
	// The session timeout is 8h already: no change.
	if v := res.Shared.Cluster["search.max_events"]; string(v.Value) != "5" || v.From.Kind != FromPage || !slices.Equal(res.Touched, []string{"search.max_events"}) {
		t.Errorf("cluster %+v touched %v", v, res.Touched)
	}

	res, err = CheckEditShared(path, sh, ScopeBootstrap, Edit{Values: map[string]any{"opensearch.index_prefix": "other"}, By: "ann"})
	if err != nil || !res.OK() {
		t.Fatal(err, res.Fields)
	}
	if res.Page == nil || res.Page.Settings["opensearch.index_prefix"] == nil || len(res.Touched) != 0 || res.Config.OpenSearch.IndexPrefix != "other" {
		t.Errorf("bootstrap page %v touched %v", res.Page, res.Touched)
	}

	// Try again takes this server's refusal of a shared value away.
	v := sh.Cluster["auth.session_timeout"]
	sh.Refused = map[string]SharedRefusal{"auth.session_timeout": {Hash: SharedHash("auth.session_timeout", v), Kept: jsonOf(t, "1h")}}
	res, err = CheckEditShared(path, sh, ScopeCluster, Edit{Retry: []string{"auth.session_timeout"}, By: "ann"})
	if err != nil || len(res.Shared.Refused) != 0 || res.Config.Auth.SessionTimeout != "8h" || !slices.Equal(res.Touched, []string{"auth.session_timeout"}) {
		t.Errorf("retry %v %v %q %v", err, res.Shared.Refused, res.Config.Auth.SessionTimeout, res.Touched)
	}
	// Reset all of them leaves the agent tokens alone.
	res, err = CheckEditShared(path, sh, ScopeCluster, Edit{ResetAll: true, By: "ann"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.Shared.Cluster["ingest.tokens"]; !ok || res.Shared.Cluster["server.public_url"].Value != nil {
		t.Errorf("reset all %v", res.Shared.Cluster)
	}
}
