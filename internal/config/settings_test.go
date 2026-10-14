package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// TestRegistryCoversEveryConfigSetting fails when a setting of Config is
// neither on the Settings page nor listed in Excluded with a reason, or
// has no scope. A branch that adds a setting must decide both, so the
// page never misses one and servers that share one OpenSearch know
// whether to share it.
func TestRegistryCoversEveryConfigSetting(t *testing.T) {
	leaves := LeafKeys()
	if len(leaves) < 30 {
		t.Fatalf("only %d settings found in Config; is LeafKeys still working?", len(leaves))
	}
	scopes := []Scope{ScopeCluster, ScopeServer, ScopeBootstrap}
	for _, k := range leaves {
		set, onPage := Lookup(k)
		ex, excluded := Excluded[k]
		switch {
		case onPage && excluded:
			t.Errorf("%s is both on the Settings page and in Excluded", k)
		case !onPage && !excluded:
			t.Errorf("%s is a new setting: add it to Registry in settings.go (for the Settings page) or to Excluded with the reason it is not there", k)
		case excluded && strings.TrimSpace(ex.Reason) == "":
			t.Errorf("%s is in Excluded without a reason", k)
		case excluded && !slices.Contains(scopes, ex.Scope):
			t.Errorf("%s is in Excluded without a Scope: say whether every server shares it (ScopeCluster), it is one server's own (ScopeServer), or it is needed before OpenSearch can be reached (ScopeBootstrap)", k)
		case onPage && !slices.Contains(scopes, set.Scope):
			t.Errorf("%s is in Registry without a Scope: say whether every server shares it (ScopeCluster), it is one server's own (ScopeServer), or it is needed before OpenSearch can be reached (ScopeBootstrap)", k)
		}
		if ScopeOf(k) == "" {
			t.Errorf("ScopeOf(%s) is empty", k)
		}
	}
	seen := map[string]bool{}
	sections := map[string]bool{}
	for _, s := range Sections {
		sections[s.ID] = true
	}
	for _, s := range Registry {
		if seen[s.Key] {
			t.Errorf("%s is in Registry twice", s.Key)
		}
		seen[s.Key] = true
		if !slices.Contains(leaves, s.Key) {
			t.Errorf("Registry has %s, which is not a setting of Config", s.Key)
		}
		if !sections[s.Section] {
			t.Errorf("%s is in section %q, which is not in Sections", s.Key, s.Section)
		}
		if s.Label == "" || s.Help == "" {
			t.Errorf("%s needs a label and help", s.Key)
		}
		if s.Type == TypeSecret && (s.sentTo == nil || len(s.SentWith) == 0) {
			t.Errorf("secret %s must say where it is sent (sentTo and SentWith)", s.Key)
		}
		if s.ConfirmWhen != "" && (s.Type != TypeBool || s.Confirm == "") {
			t.Errorf("%s: ConfirmWhen is for switches with a Confirm text", s.Key)
		}
		v, _ := field(&Config{}, s.Key)
		if v.Kind() == reflect.Pointer {
			// A setting that may be left unset, such as
			// cluster.leader_eligible.
			v = reflect.New(v.Type().Elem()).Elem()
		}
		want := map[string]reflect.Kind{TypeNumber: reflect.Int, TypeBool: reflect.Bool, TypeList: reflect.Slice}[s.Type]
		if want == 0 {
			want = reflect.String
		}
		if v.Kind() != want {
			t.Errorf("%s is a %s setting but its field is a %s", s.Key, s.Type, v.Kind())
		}
	}
	for k := range Excluded {
		if !slices.Contains(leaves, k) {
			t.Errorf("Excluded has %s, which is not a setting of Config", k)
		}
	}
	if len(Sections) != 10 {
		t.Errorf("sections: %d", len(Sections))
	}
}

// TestRegistryEnvMatchesTheEnvironment checks that each setting's Env is
// the variable that really overrides it, and that every variable that
// overrides a setting on the page is listed.
func TestRegistryEnvMatchesTheEnvironment(t *testing.T) {
	path := writeConfig(t, "")
	values := map[string]string{
		"SIGNALITH_OPENSEARCH_URL": "https://os.example:9200", "SIGNALITH_OPENSEARCH_USERNAME": "u",
		"SIGNALITH_OPENSEARCH_PROXY":    "http://proxy.example:3128",
		"SIGNALITH_OPENSEARCH_PASSWORD": "p", "SIGNALITH_LISTEN": "0.0.0.0:8081",
		"SIGNALITH_PUBLIC_URL": "http://siem.example:8081", "SIGNALITH_ASSISTANT_API_KEY": "k",
		"SIGNALITH_SYSLOG_UDP": "0.0.0.0:5514", "SIGNALITH_SYSLOG_TCP": "0.0.0.0:5514",
		"SIGNALITH_NVD_API_KEY": "nvd-key", "SIGNALITH_NVD_URL": "https://nvd-mirror.example/rest/json/cves/2.0",
		"SIGNALITH_NODE_URL": "https://10.0.0.5:8081", "SIGNALITH_LEADER_ELIGIBLE": "false",
	}
	for k, v := range values {
		t.Setenv(k, v)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range Registry {
		src := c.Source(s.Key)
		if s.Env != "" && (src.Kind != FromEnv || src.Env != s.Env) {
			t.Errorf("%s: source %+v, want env %s", s.Key, src, s.Env)
		}
		if s.Env == "" && src.Kind == FromEnv {
			t.Errorf("%s is set by %s but Registry has no Env for it", s.Key, src.Env)
		}
	}
}

// TestScopes pins the scope of the settings whose scope matters most: a
// setting that belongs to one server must never be copied to another as
// if every server shared it.
func TestScopes(t *testing.T) {
	want := map[string]Scope{
		"detections.scheduler":    ScopeServer,
		"server.listen":           ScopeServer,
		"server.node_url":         ScopeServer,
		"syslog.udp":              ScopeServer,
		"retention.archive_dir":   ScopeServer,
		"server.public_url":       ScopeCluster,
		"retention.policies":      ScopeCluster,
		"assistant.api_key":       ScopeCluster,
		"opensearch.replicas":     ScopeCluster,
		"opensearch.url":          ScopeBootstrap,
		"opensearch.index_prefix": ScopeBootstrap,
		"cluster.node_name":       ScopeBootstrap,
		"lookups.dir":             ScopeBootstrap,
	}
	for k, sc := range want {
		if got := ScopeOf(k); got != sc {
			t.Errorf("%s: scope %q, want %q", k, got, sc)
		}
	}
	if ScopeOf("no.such") != "" {
		t.Error("an unknown key has a scope")
	}
	// Every file path on the page is marked as one, and only those.
	for _, s := range Registry {
		file := strings.HasSuffix(s.Key, "_file") || strings.HasSuffix(s.Key, "tls_cert") || strings.HasSuffix(s.Key, "tls_key")
		if s.File != file {
			t.Errorf("%s: File %v", s.Key, s.File)
		}
	}
}

// TestNodeNameAndAddress checks the two settings that name this server
// among others: from signalith.yaml, from the environment, and what
// Validate refuses.
func TestNodeNameAndAddress(t *testing.T) {
	path := writeConfig(t, "cluster:\n  node_name: siem-a\nserver:\n  node_url: https://10.0.0.5:8443\n")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Cluster.NodeName != "siem-a" || c.Server.NodeURL != "https://10.0.0.5:8443" {
		t.Fatalf("from the file: %q %q", c.Cluster.NodeName, c.Server.NodeURL)
	}
	t.Setenv("SIGNALITH_NODE_NAME", "siem-b")
	t.Setenv("SIGNALITH_NODE_URL", "https://10.0.0.6:8443")
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Cluster.NodeName != "siem-b" || c.Server.NodeURL != "https://10.0.0.6:8443" {
		t.Fatalf("from the environment: %q %q", c.Cluster.NodeName, c.Server.NodeURL)
	}
	if src := c.Source("cluster.node_name"); src.Kind != FromEnv || src.Env != "SIGNALITH_NODE_NAME" {
		t.Errorf("source %+v", src)
	}
	t.Setenv("SIGNALITH_NODE_URL", "10.0.0.6:8443")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "SIGNALITH_NODE_URL") {
		t.Errorf("a node address without http(s):// is taken: %v", err)
	}
	t.Setenv("SIGNALITH_NODE_URL", "")
	t.Setenv("SIGNALITH_NODE_NAME", "")
	for _, bad := range []string{"-a", "a b", "siem/a", strings.Repeat("a", 64)} {
		c := Default()
		c.Auth.AdminPasswordHash = "$2a$10$0123456789012345678901uJmAeTkM1bLCuQZ5gYk1yJw3bJ1Q2W"
		c.Cluster.NodeName = bad
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "cluster.node_name") {
			t.Errorf("node name %q: %v", bad, err)
		}
	}
	for _, good := range []string{"siem-a", "SIEM_01", "a", "siem.plant.local"} {
		if !ValidNodeName(good) {
			t.Errorf("%q is refused", good)
		}
	}
}

// writeConfig writes a signalith.yaml with a password and a lookups
// folder in a temporary folder, plus extra YAML.
func writeConfig(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	h, err := HashPassword("long-enough-password")
	if err != nil {
		t.Fatal(err)
	}
	body := "auth:\n  admin_password_hash: " + h + "\n" + extra
	path := filepath.Join(dir, "signalith.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writePage writes the Settings page's file for the config at path.
func writePage(t *testing.T, path, body string) string {
	t.Helper()
	file := filepath.Join(filepath.Dir(path), "lookups", "settings.yaml")
	if err := os.MkdirAll(filepath.Dir(file), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestPrecedenceAndSources(t *testing.T) {
	path := writeConfig(t, "server:\n  listen: 0.0.0.0:8080\n  public_url: http://file.example:8080\nsearch:\n  max_events: 500\n")
	at := time.Date(2026, 10, 12, 9, 30, 0, 0, time.UTC)
	writePage(t, path, `settings:
  search.max_events:
    value: 2000
    changed_by: alice
    changed_at: 2026-10-12T09:30:00Z
  auth.session_timeout:
    value: 8h
    changed_by: alice
    changed_at: 2026-10-12T09:30:00Z
  server.public_url:
    value: http://page.example:8080
    changed_by: alice
    changed_at: 2026-10-12T09:30:00Z
`)
	t.Setenv("SIGNALITH_PUBLIC_URL", "http://env.example:8080")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.SettingsProblem() != "" {
		t.Fatal(c.SettingsProblem())
	}
	for key, want := range map[string]struct {
		value any
		src   Source
	}{
		"server.public_url":       {"http://env.example:8080", Source{Kind: FromEnv, Env: "SIGNALITH_PUBLIC_URL"}},
		"search.max_events":       {2000, Source{Kind: FromPage, By: "alice", At: at}},
		"auth.session_timeout":    {"8h", Source{Kind: FromPage, By: "alice", At: at}},
		"server.listen":           {"0.0.0.0:8080", Source{Kind: FromFile}},
		"search.default_earliest": {"-24h", Source{Kind: FromDefault}},
	} {
		if got := c.Value(key); !reflect.DeepEqual(got, want.value) {
			t.Errorf("%s = %v, want %v", key, got, want.value)
		}
		if got := c.Source(key); got != want.src {
			t.Errorf("%s source = %+v, want %+v", key, got, want.src)
		}
	}
	if c.SessionIdle() != 8*time.Hour {
		t.Errorf("session idle %v", c.SessionIdle())
	}
	// public_url comes from the environment, so it is not in use from the page.
	if got := c.PageKeys(); !reflect.DeepEqual(got, []string{"auth.session_timeout", "search.max_events"}) {
		t.Errorf("page keys %v", got)
	}
	if b := c.Base(); b.Search.MaxEvents != 500 || b.Auth.SessionTimeout != "" {
		t.Errorf("base %+v %+v", b.Search, b.Auth)
	}
	// LoadFile leaves the page out, and Save refuses a config with it.
	f, err := LoadFile(path)
	if err != nil || f.Search.MaxEvents != 500 {
		t.Fatalf("LoadFile: %v %d", err, f.Search.MaxEvents)
	}
	if err := c.Save(filepath.Join(t.TempDir(), "out.yaml")); err == nil {
		t.Error("Save wrote the page's settings into signalith.yaml")
	}
}

func TestSettingsFileFromEnvironment(t *testing.T) {
	path := writeConfig(t, "")
	file := filepath.Join(t.TempDir(), "elsewhere.yaml")
	os.WriteFile(file, []byte("settings:\n  search.max_events:\n    value: 42\n"), 0o600)
	t.Setenv("SIGNALITH_SETTINGS_FILE", file)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.SettingsFile() != file || !c.SettingsFileFromEnv() || c.Search.MaxEvents != 42 {
		t.Errorf("file %s env %v max %d", c.SettingsFile(), c.SettingsFileFromEnv(), c.Search.MaxEvents)
	}
}

// A settings file that cannot be used never stops Signalith: it starts
// with signalith.yaml alone and says why.
func TestBrokenSettingsFileDoesNotStopStart(t *testing.T) {
	for name, tc := range map[string]struct{ page, want string }{
		"not yaml":      {"settings: [oops\n", "cannot be read"},
		"wrong type":    {"settings:\n  search.max_events:\n    value: lots\n", "search.max_events"},
		"no value":      {"settings:\n  search.max_events:\n    changed_by: x\n", "has no value"},
		"invalid":       {"settings:\n  search.max_events:\n    value: 0\n", "search.max_events must be between 1 and 100000"},
		"do not mix":    {"settings:\n  server.tls.mode:\n    value: files\n", "server.tls.mode is files, so set server.tls_cert"},
		"bad listen":    {"settings:\n  server.listen:\n    value: nowhere\n", `server.listen "nowhere" must be host:port`},
		"session short": {"settings:\n  auth.session_timeout:\n    value: 1m\n", "auth.session_timeout"},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, "search:\n  max_events: 700\n")
			writePage(t, path, tc.page)
			c, err := Load(path)
			if err != nil {
				t.Fatalf("Load failed: %v", err)
			}
			if c.Search.MaxEvents != 700 || len(c.PageKeys()) != 0 {
				t.Errorf("not signalith.yaml alone: max %d, page %v", c.Search.MaxEvents, c.PageKeys())
			}
			if p := c.SettingsProblem(); !strings.Contains(p, tc.want) || !strings.Contains(p, "signalith settings reset") {
				t.Errorf("problem %q, want %q", p, tc.want)
			}
			s, err := LoadSaved(path)
			if err != nil {
				t.Fatal(err)
			}
			if s.PageErr == nil && len(s.Problems) == 0 {
				t.Error("LoadSaved shows no problem")
			}
		})
	}
	// A file that is broken on its own still fails, with its own problems.
	path := writeConfig(t, "search:\n  max_events: 0\n")
	writePage(t, path, "settings:\n  search.max_events:\n    value: 10\n")
	if _, err := Load(path); err != nil {
		t.Errorf("the page fixes the file's problem, so it should load: %v", err)
	}
	path = writeConfig(t, "search:\n  max_events: 0\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "max_events") {
		t.Errorf("broken signalith.yaml: %v", err)
	}
}

func TestUnknownPageSettingIsSkipped(t *testing.T) {
	path := writeConfig(t, "")
	writePage(t, path, "settings:\n  search.max_events:\n    value: 99\n  retention.days:\n    value: 3\n")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Search.MaxEvents != 99 || c.Retention.Days != 90 || c.SettingsProblem() != "" {
		t.Errorf("max %d days %d problem %q", c.Search.MaxEvents, c.Retention.Days, c.SettingsProblem())
	}
	if w := c.SettingsWarnings(); len(w) != 1 || !strings.Contains(w[0], "retention.days") {
		t.Errorf("warnings %v", w)
	}
}

func TestCheckEditReportsProblemsByField(t *testing.T) {
	path := writeConfig(t, "")
	t.Setenv("SIGNALITH_LISTEN", "127.0.0.1:8080")
	res, err := CheckEdit(path, Edit{By: "alice", Values: map[string]any{
		"server.listen":           "0.0.0.0:9000",
		"search.max_events":       float64(0),
		"syslog.udp":              "nowhere",
		"auth.session_timeout":    "1m",
		"retention.days":          float64(7),
		"no.such":                 "x",
		"opensearch.replicas":     "two",
		"search.default_earliest": "+1h",
	}})
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"server.listen":           "SIGNALITH_LISTEN",
		"search.max_events":       "from 1 to 100000",
		"syslog.udp":              "Must be host:port",
		"auth.session_timeout":    "Must be a duration of at least 5m",
		"retention.days":          "Data retention has its own page",
		"no.such":                 "There is no setting",
		"opensearch.replicas":     "Enter auto, or a whole number",
		"search.default_earliest": "not a time in the past",
	} {
		if !strings.Contains(res.Fields[key], want) {
			t.Errorf("%s: %q, want %q", key, res.Fields[key], want)
		}
	}
	if res.OK() {
		t.Error("edit with problems is OK")
	}
	// A good edit lists what changes and who changed it.
	res, err = CheckEdit(path, Edit{By: "alice", Values: map[string]any{"search.max_events": float64(5000), "syslog.allow": []any{" 10.0.0.0/8 ", ""}, "search.default_earliest": "-24h"}})
	if err != nil || !res.OK() {
		t.Fatalf("%v %v %v", err, res.Fields, res.Problems)
	}
	if !reflect.DeepEqual(res.Changed, []string{"search.max_events", "syslog.allow"}) {
		t.Errorf("changed %v", res.Changed)
	}
	if e := res.Page.Settings["search.max_events"]; e == nil || e.ChangedBy != "alice" || e.ChangedAt.IsZero() {
		t.Errorf("entry %+v", e)
	}
	if res.Page.Settings["search.default_earliest"] != nil {
		t.Error("an unchanged value was stored")
	}
	if got := res.Config.Syslog.Allow; !reflect.DeepEqual(got, []string{"10.0.0.0/8"}) {
		t.Errorf("allow %v", got)
	}
	// Two settings that clash are both marked.
	res, _ = CheckEdit(path, Edit{Values: map[string]any{"syslog.tcp": "0.0.0.0:8080"}})
	if !strings.Contains(res.Fields["syslog.tcp"], "“Listen address”") {
		t.Errorf("clash %v", res.Fields)
	}
}

func TestSecretsAreOnlySentWhereTheyWereEntered(t *testing.T) {
	path := writeConfig(t, "opensearch:\n  url: https://os1.example:9200\n  username: signalith\n  password: from-file\n")
	edit := func(e Edit) *EditResult {
		t.Helper()
		res, err := CheckEdit(path, e)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	save := func(res *EditResult) {
		t.Helper()
		if !res.OK() {
			t.Fatalf("problems %v %v", res.Fields, res.Problems)
		}
		if err := WritePageSettings(res.Config.SettingsFile(), res.Page); err != nil {
			t.Fatal(err)
		}
	}
	// Moving OpenSearch to another server needs the password again: the
	// one in signalith.yaml is only sent to os1.
	res := edit(Edit{Values: map[string]any{"opensearch.url": "https://os2.example:9200"}})
	if !strings.Contains(res.Fields["opensearch.password"], "only sent to https://os1.example:9200") {
		t.Fatalf("fields %v", res.Fields)
	}
	// Another way of writing the same server is the same server.
	res = edit(Edit{Values: map[string]any{"opensearch.url": "HTTPS://OS1.example:9200/"}})
	if !res.OK() {
		t.Errorf("same server refused: %v", res.Fields)
	}
	// With the password typed, it is saved for os2 only.
	res = edit(Edit{By: "alice", Values: map[string]any{"opensearch.url": "https://os2.example:9200", "opensearch.password": "new-secret"}})
	save(res)
	e := res.Page.Settings["opensearch.password"]
	if e == nil || e.Secret == nil || e.SentTo != "https://os2.example:9200" {
		t.Fatalf("entry %+v", e)
	}
	// Kept encrypted, for this setting of the page only.
	if pw, err := secrets.Open("settings.opensearch.password", *e.Secret); !secrets.IsSealed(*e.Secret) || err != nil || pw != "new-secret" {
		t.Fatalf("saved secret %q: %q %v", *e.Secret, pw, err)
	}
	if data, _ := os.ReadFile(res.Config.SettingsFile()); strings.Contains(string(data), "new-secret") {
		t.Fatalf("the settings file holds the password as it was typed:\n%s", data)
	}
	c, err := Load(path)
	if err != nil || c.OpenSearch.Password != "new-secret" || c.Source("opensearch.password").Kind != FromPage {
		t.Fatalf("load %v %q", err, c.OpenSearch.Password)
	}
	// An empty password keeps the saved one.
	res = edit(Edit{Values: map[string]any{"opensearch.password": "", "opensearch.username": "other"}})
	save(res)
	if c, _ := Load(path); c.OpenSearch.Password != "new-secret" {
		t.Errorf("empty password did not keep the saved one: %q", c.OpenSearch.Password)
	}
	// Resetting the address alone would send it to os1.
	res = edit(Edit{Reset: []string{"opensearch.url"}})
	if !strings.Contains(res.Fields["opensearch.password"], "only sent to https://os2.example:9200") {
		t.Errorf("reset url: %v", res.Fields)
	}
	// Resetting both goes back to signalith.yaml's pair.
	res = edit(Edit{Reset: []string{"opensearch.url", "opensearch.password"}})
	if !res.OK() || res.Config.OpenSearch.Password != "from-file" {
		t.Errorf("reset both: %v %q", res.Fields, res.Config.OpenSearch.Password)
	}
	// Clear removes it, even the one in signalith.yaml.
	res = edit(Edit{Clear: []string{"opensearch.password"}})
	save(res)
	if c, _ := Load(path); c.OpenSearch.Password != "" || c.Source("opensearch.password").Kind != FromPage {
		t.Errorf("clear: %q %v", c.OpenSearch.Password, c.Source("opensearch.password"))
	}
	if res := edit(Edit{Clear: []string{"opensearch.url"}}); !strings.Contains(res.Fields["opensearch.url"], "Only passwords") {
		t.Errorf("clear non-secret %v", res.Fields)
	}

	// The address moving outside the page (here the environment) leaves a
	// saved password unused, with a warning, until it is entered again.
	save(edit(Edit{Values: map[string]any{"opensearch.password": "for-os2"}}))
	t.Setenv("SIGNALITH_OPENSEARCH_URL", "https://os3.example:9200")
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.OpenSearch.Password != "" || len(c.SettingsWarnings()) != 1 || !strings.Contains(c.SettingsWarnings()[0], "only sent to https://os2.example:9200") {
		t.Errorf("moved: %q %v", c.OpenSearch.Password, c.SettingsWarnings())
	}
}

func TestAssistantKeyFollowsProvider(t *testing.T) {
	path := writeConfig(t, "assistant:\n  provider: anthropic\n  api_key: sk-from-file\n")
	res, err := CheckEdit(path, Edit{Values: map[string]any{"assistant.provider": "openai", "assistant.model": "gpt-4.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Fields["assistant.api_key"], "Enter the API key again") || !strings.Contains(res.Fields["assistant.api_key"], "only sent to https://api.anthropic.com:443") {
		t.Errorf("fields %v", res.Fields)
	}
	// Turning the assistant off sends the key nowhere, so it is kept, and
	// turning it back on with the same provider uses it again.
	res, err = CheckEdit(path, Edit{Values: map[string]any{"assistant.provider": ""}})
	if err != nil || !res.OK() {
		t.Fatalf("turn off: %v %v %v", err, res.Fields, res.Problems)
	}
	if err := WritePageSettings(res.Config.SettingsFile(), res.Page); err != nil {
		t.Fatal(err)
	}
	if c, err := Load(path); err != nil || c.Assistant.APIKey != "sk-from-file" || len(c.SettingsWarnings()) != 0 {
		t.Fatalf("off: %v %v", err, c.SettingsWarnings())
	}
	res, _ = CheckEdit(path, Edit{Reset: []string{"assistant.provider"}})
	if !res.OK() || res.Config.Assistant.APIKey != "sk-from-file" {
		t.Errorf("back on: %v %q", res.Fields, res.Config.Assistant.APIKey)
	}
	// The environment's key cannot be typed again, so the page says where
	// to change things.
	t.Setenv("SIGNALITH_ASSISTANT_API_KEY", "sk-from-env")
	res, _ = CheckEdit(path, Edit{Values: map[string]any{"assistant.provider": "anthropic", "assistant.url": "http://evil.example/v1"}})
	if !strings.Contains(res.Fields["assistant.url"], "SIGNALITH_ASSISTANT_API_KEY") {
		t.Errorf("env key fields %v", res.Fields)
	}
	if res.OK() {
		t.Errorf("should not be OK: %v", res.Fields)
	}
}

func TestResetAndResetAll(t *testing.T) {
	path := writeConfig(t, "search:\n  max_events: 300\n")
	file := writePage(t, path, "settings:\n  search.max_events:\n    value: 50\n  auth.session_timeout:\n    value: 1h\n")
	res, err := CheckEdit(path, Edit{Reset: []string{"search.max_events"}})
	if err != nil || !res.OK() {
		t.Fatal(err, res.Fields)
	}
	if res.Config.Search.MaxEvents != 300 || res.Page.Settings["search.max_events"] != nil || !reflect.DeepEqual(res.Changed, []string{"search.max_events"}) {
		t.Errorf("reset: %d %v", res.Config.Search.MaxEvents, res.Changed)
	}
	// A file that cannot be read stops edits, except resetting it all.
	os.WriteFile(file, []byte("settings: [broken\n"), 0o600)
	if _, err := CheckEdit(path, Edit{Values: map[string]any{"search.max_events": float64(10)}}); !errors.Is(err, ErrPageFile) {
		t.Errorf("edit of a broken file: %v", err)
	}
	res, err = CheckEdit(path, Edit{ResetAll: true})
	if err != nil || !res.OK() || !res.Page.Empty() {
		t.Fatalf("reset all: %v", err)
	}
	if err := WritePageSettings(file, res.Page); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("empty settings left a file: %v", err)
	}
}

func TestWritePageSettingsIsPrivate(t *testing.T) {
	file := filepath.Join(t.TempDir(), "lookups", "settings.yaml")
	p := &PageSettings{}
	p.Set("search.max_events", 10, "alice", time.Now())
	p.SetSecret("opensearch.password", "pw", "https://os:9200", "alice", time.Now())
	if err := WritePageSettings(file, p); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %v %v", fi.Mode(), err)
		}
	}
	data, _ := os.ReadFile(file)
	if !strings.HasPrefix(string(data), "# Settings changed on the Settings page") || !strings.Contains(string(data), "sent_to: https://os:9200") {
		t.Errorf("file:\n%s", data)
	}
	back, err := ReadPageSettings(file)
	if err != nil || !reflect.DeepEqual(back.Keys(), []string{"opensearch.password", "search.max_events"}) {
		t.Errorf("read back %v %v", err, back.Keys())
	}
	// No temporary files are left behind.
	entries, _ := os.ReadDir(filepath.Dir(file))
	if len(entries) != 1 {
		t.Errorf("files: %v", entries)
	}
	// One that others can read, such as one copied in by hand, is made
	// private by the next save.
	if runtime.GOOS != "windows" {
		os.Chmod(file, 0o644)
		p.Set("search.max_events", 20, "alice", time.Now())
		if err := WritePageSettings(file, p); err != nil {
			t.Fatal(err)
		}
		if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("mode after saving over a 0644 file %v %v", fi.Mode(), err)
		}
	}
}

func TestProblemKeysAndPlainProblem(t *testing.T) {
	for problem, want := range map[string][]string{
		`server.listen "x" must be host:port, for example 0.0.0.0:8080`:                                  {"server.listen"},
		"server.tls_cert and server.tls_key must be set together":                                        {"server.tls_cert", "server.tls_key"},
		"syslog.allow[2] \"x\" must be an IP address or a CIDR such as 10.0.0.0/8":                       {"syslog.allow"},
		"auth.ldap.url: enter the server address":                                                        {"auth.ldap"},
		"opensearch.index_prefix must be lowercase with no spaces or wildcards":                          {"opensearch.index_prefix"},
		"search.max_events must be between 1 and 100000":                                                 {"search.max_events"},
		"intel.feeds[0] (x): url is required":                                                            {"intel.feeds"},
		"syslog.tls needs server.tls_cert and server.tls_key; syslog over TLS uses the same certificate": {"syslog.tls", "server.tls_cert", "server.tls_key"},
	} {
		if got := ProblemKeys(problem); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v, want %v", problem, got, want)
		}
	}
	for _, c := range []struct{ key, problem, want string }{
		{"server.listen", `server.listen "x" must be host:port, for example 0.0.0.0:8080`, "Must be host:port, for example 0.0.0.0:8080"},
		{"server.tls_key", "server.tls_cert and server.tls_key must be set together", "“Certificate file” and “Key file” must be set together"},
		{"syslog.tls", "syslog.tls needs server.tls_cert and server.tls_key", "Needs “Certificate file” and “Key file”"},
	} {
		if got := PlainProblem(c.key, c.problem); got != c.want {
			t.Errorf("%s: %q, want %q", c.key, got, c.want)
		}
	}
}

func TestParseValue(t *testing.T) {
	get := func(key string) *Setting { s, _ := Lookup(key); return s }
	for _, c := range []struct {
		key  string
		raw  any
		want any
		err  bool
	}{
		{"search.max_events", float64(10), 10, false},
		{"search.max_events", "25", 25, false},
		{"search.max_events", 1.5, nil, true},
		{"search.max_events", float64(100001), nil, true},
		{"syslog.public_port", float64(0), 0, false},
		{"detections.scheduler", true, true, false},
		{"detections.scheduler", "yes", nil, true},
		{"syslog.allow", "10.0.0.0/8, 192.0.2.1\n", []string{"10.0.0.0/8", "192.0.2.1"}, false},
		{"syslog.allow", nil, []string{}, false},
		{"server.public_url", "  http://x:1  ", "http://x:1", false},
		{"opensearch.password", " spaced ", " spaced ", false},
		{"server.listen", float64(8080), nil, true},
	} {
		got, err := ParseValue(get(c.key), c.raw)
		if (err != nil) != c.err || (!c.err && !reflect.DeepEqual(got, c.want)) {
			t.Errorf("%s %v: %v %v", c.key, c.raw, got, err)
		}
	}
}

func TestNoun(t *testing.T) {
	for label, want := range map[string]string{"API key": "API key", "Password": "password", "TLS address": "TLS address", "Index prefix": "index prefix", "OpenSearch address": "OpenSearch address", "": ""} {
		if got := (&Setting{Label: label}).Noun(); got != want {
			t.Errorf("%q: %q, want %q", label, got, want)
		}
	}
}

func TestOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://OS.example:9200/path": "https://os.example:9200",
		"https://os.example":           "https://os.example:443",
		"http://os.example":            "http://os.example:80",
		"http://[::1]:9200":            "http://[::1]:9200",
		"ftp://x":                      "",
		"nonsense":                     "",
		"":                             "",
	} {
		if got := Origin(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// Every bad entry of an address list is named, in plain words.
func TestAddressListProblem(t *testing.T) {
	for _, c := range []struct {
		list []string
		want string
	}{
		{[]string{"10.0.0.0/8", "192.168.1.5"}, ""},
		{[]string{"10.0.0.0/8", "printer"}, "“printer” isn't an IP address or a range like 10.0.0.0/8."},
		{[]string{"10.0.0.0/8", "192.168.1.0/33", "printer"}, "“192.168.1.0/33” and “printer” aren't IP addresses or ranges like 10.0.0.0/8."},
	} {
		if got := addressListProblem(c.list); got != c.want {
			t.Errorf("%v: %q", c.list, got)
		}
	}
	// On the page, the field says it without an index or the key.
	path := writeConfig(t, "")
	res, err := CheckEdit(path, Edit{Values: map[string]any{"syslog.allow": []any{"10.0.0.0/8", "192.168.1.0/33", "printer"}}, By: "ann"})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Fields["syslog.allow"]; strings.Contains(got, "[1]") || !strings.Contains(got, "“printer”") {
		t.Errorf("field problem %q", got)
	}
}

// AdminPasswordVersion stays the same for the same password from the
// environment, which each process hashes with a new salt, and follows the
// password changed with signalith passwd once there is one.
func TestAdminPasswordVersion(t *testing.T) {
	path := writeConfig(t, "")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "env-password-one")
	a, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	envHash.Lock()
	envHash.password, envHash.hash = "", "" // as in a new process
	envHash.Unlock()
	b, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if a.Auth.AdminPasswordHash == b.Auth.AdminPasswordHash || a.AdminPasswordVersion() != b.AdminPasswordVersion() {
		t.Errorf("versions %q and %q for the same password", a.AdminPasswordVersion(), b.AdminPasswordVersion())
	}
	if strings.Contains(a.AdminPasswordVersion(), "env-password-one") {
		t.Error("the version shows the password")
	}
	h, err := HashPassword("changed-with-passwd")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(b.AdminHashFile()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.AdminHashFile(), []byte(h+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.AdminPasswordVersion() != "hash:"+h {
		t.Errorf("version after signalith passwd = %q", c.AdminPasswordVersion())
	}
}
