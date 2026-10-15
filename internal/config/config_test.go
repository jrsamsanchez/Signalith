package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInitSaveLoadRoundTrip(t *testing.T) {
	c := Default()
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	c.Auth.AdminPasswordHash = h
	c.Ingest.Tokens = []string{RandomToken(16)}
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.CheckPassword("admin", "correct horse") || got.CheckPassword("admin", "wrong") {
		t.Error("password check failed")
	}
	if got.Server.PublicURL != "https://127.0.0.1:9000" {
		t.Errorf("public url = %s", got.Server.PublicURL)
	}
}

func TestValidationListsEveryProblem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(path, []byte("server:\n  listen: nonsense\nopensearch:\n  url: ftp://x\n  index_prefix: Bad Prefix\nretention:\n  days: -1\n"), 0o600)
	_, err := Load(path)
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{"server.listen", "opensearch.url", "index_prefix", "retention.days", "admin_password_hash"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q:\n%v", want, err)
		}
	}
}

func TestUnknownKeysAreRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "typo.yaml")
	os.WriteFile(path, []byte("retension:\n  days: 30\n"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "retension") {
		t.Errorf("typo not reported: %v", err)
	}
}

func TestEnvOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env.yaml")
	os.WriteFile(path, []byte("search:\n  max_events: 500\n"), 0o600)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "from-the-env")
	t.Setenv("SIGNALITH_OPENSEARCH_URL", "https://os.internal:9200")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.CheckPassword("admin", "from-the-env") || c.OpenSearch.URL != "https://os.internal:9200" || c.Search.MaxEvents != 500 {
		t.Errorf("env not applied: %+v", c)
	}
}

func TestPublicURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "url.yaml")
	os.WriteFile(path, []byte("server:\n  listen: 0.0.0.0:8080\n  public_url: http://localhost:8080\n"), 0o600)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	t.Setenv("SIGNALITH_PUBLIC_URL", "http://192.168.1.20:8080")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// A config from before HTTPS was the default: the same port serves
	// HTTPS now, so the address is upgraded.
	if c.Server.PublicURL != "https://192.168.1.20:8080" {
		t.Errorf("SIGNALITH_PUBLIC_URL not applied: %s", c.Server.PublicURL)
	}
	// The environment value is checked like the file's, so a line break
	// can never reach a generated agent config.
	for _, bad := range []string{"http://192.168.1.20:8080\n[OUTPUT]", "192.168.1.20:8080", "http://192.168.1.20:8080/siem"} {
		t.Setenv("SIGNALITH_PUBLIC_URL", bad)
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "SIGNALITH_PUBLIC_URL") {
			t.Errorf("SIGNALITH_PUBLIC_URL=%q: want an error naming it, got %v", bad, err)
		}
	}
	t.Setenv("SIGNALITH_PUBLIC_URL", "")
	os.WriteFile(path, []byte("server:\n  public_url: \"http://siem:8080\\n[OUTPUT]\"\n"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "server.public_url") {
		t.Errorf("line break in public_url: want an error, got %v", err)
	}
}

func TestAssistantSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ai.yaml")
	os.WriteFile(path, []byte("assistant:\n  provider: openia\n  url: localhost:11434\n"), 0o600)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	_, err := Load(path)
	for _, want := range []string{"assistant.provider", "assistant.url"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
	os.WriteFile(path, []byte("assistant:\n  provider: anthropic\n"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "SIGNALITH_ASSISTANT_API_KEY") {
		t.Errorf("missing key not reported: %v", err)
	}
	t.Setenv("SIGNALITH_ASSISTANT_API_KEY", "sk-test")
	c, err := Load(path)
	if err != nil || c.Assistant.APIKey != "sk-test" {
		t.Errorf("env key: %v %+v", err, c)
	}
}

func TestIntelFeeds(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	good := filepath.Join(dir, "good.yaml")
	os.WriteFile(good, []byte(`intel:
  feeds:
    - name: feodo-tracker
      url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
    - name: urlhaus
      url: https://urlhaus.abuse.ch/downloads/csv_recent/
      format: csv
      column: url
      type: url
      interval: 30m
      weight: 1.5
      enabled: false
`), 0o600)
	c, err := Load(good)
	if err != nil {
		t.Fatal(err)
	}
	f := c.Intel.Feeds[0]
	if f.Format != "lines" || f.Type != "auto" || f.Interval != "1h" || f.MaxAge != "7d" || f.Weight != 1 || !f.IsEnabled() {
		t.Errorf("defaults = %+v", f)
	}
	if c.Intel.Feeds[1].IsEnabled() {
		t.Error("enabled: false ignored")
	}
	if d, err := ParseFeedDuration("2w"); err != nil || d.Hours() != 336 {
		t.Errorf("2w = %v %v", d, err)
	}

	bad := filepath.Join(dir, "bad.yaml")
	os.WriteFile(bad, []byte(`intel:
  feeds:
    - name: Bad Name
      url: ftp://x
      format: xml
      type: ipv4
    - name: csvfeed
      url: https://example.com/a.csv
      format: csv
      interval: 1m
      max_age: 30s
      weight: 20
      headers: {Authorization: "Bearer ${SIGNALITH_TEST_UNSET_KEY}"}
    - name: csvfeed
      url: https://example.com/b
    - name: manual
      url: https://example.com/c
      column: "2"
`), 0o600)
	_, err = Load(bad)
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{
		"intel.feeds[0] (Bad Name): name must be", `url "ftp://x"`, `format "xml"`, `type "ipv4"`,
		"csv feeds need a column", "interval must be at least 5m", "max_age:", "weight must be",
		"${SIGNALITH_TEST_UNSET_KEY}", "intel.feeds[2] (csvfeed): name is used", `name "manual" is reserved`,
		"column only applies to format: csv",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
}

func TestDashboardSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dash.yaml")
	os.WriteFile(path, []byte("dashboards:\n  dir: \"\"\n  stale_after: soon\n"), 0o600)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	_, err := Load(path)
	for _, want := range []string{"dashboards.dir", "dashboards.stale_after"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
	os.WriteFile(path, []byte("dashboards:\n  stale_after: 1d\n"), 0o600)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.DashboardsDir() != filepath.Join(dir, "dashboards") || c.StaleAfter().Hours() != 24 {
		t.Errorf("dir %s stale %v", c.DashboardsDir(), c.StaleAfter())
	}
	other := filepath.Join(t.TempDir(), "dash")
	t.Setenv("SIGNALITH_DASHBOARDS_DIR", other)
	if c, err := Load(path); err != nil || c.DashboardsDir() != other {
		t.Errorf("env dir: %v %v", err, c)
	}
}

func TestSyslogSettings(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	path := filepath.Join(dir, "syslog.yaml")

	// Absent means off, so existing configs keep working as before.
	os.WriteFile(path, []byte("search:\n  max_events: 500\n"), 0o600)
	c, err := Load(path)
	if err != nil || c.Syslog.Enabled() {
		t.Fatalf("absent syslog section: %v %+v", err, c.Syslog)
	}
	// Turning syslog on then means adding the section, not editing it.
	if c.HasSection("syslog") || !c.HasSection("search") {
		t.Errorf("sections: syslog %v, search %v", c.HasSection("syslog"), c.HasSection("search"))
	}

	os.WriteFile(path, []byte(`syslog:
  udp: 0.0.0.0:514
  tcp: 127.0.0.1:1514
  allow: [10.0.0.0/8, 192.0.2.7, "::ffff:198.51.100.0/120", "2001:db8::/32"]
`), 0o600)
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range c.Syslog.AllowList() {
		got = append(got, p.String())
	}
	if !c.Syslog.Enabled() || strings.Join(got, " ") != "10.0.0.0/8 192.0.2.7/32 198.51.100.0/24 2001:db8::/32" {
		t.Errorf("allow = %v, syslog %+v", got, c.Syslog)
	}

	os.WriteFile(path, []byte(`server:
  listen: 0.0.0.0:6514
syslog:
  udp: "514"
  tcp: 0.0.0.0:99999
  tls: 0.0.0.0:6514
  allow: [10.0.0.0/33, not-an-ip]
`), 0o600)
	_, err = Load(path)
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{
		`syslog.udp "514" must be host:port`, `syslog.tcp port "99999"`, "server.listen and syslog.tls both use 0.0.0.0:6514",
		`syslog.allow[0] "10.0.0.0/33"`, `syslog.allow[1] "not-an-ip"`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}

	// Docker: listen on 5514, devices send to the 514 published for it.
	os.WriteFile(path, []byte("syslog:\n  udp: 0.0.0.0:5514\n  tcp: 0.0.0.0:5514\n  public_port: 514\n"), 0o600)
	if c, err := Load(path); err != nil || c.Syslog.PublicPort != 514 {
		t.Errorf("public_port: %v %+v", err, c.Syslog)
	}
	os.WriteFile(path, []byte("syslog:\n  udp: 0.0.0.0:5514\n  public_port: 70000\n"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "syslog.public_port 70000 must be 1-65535") {
		t.Errorf("public_port 70000: %v", err)
	}

	os.WriteFile(path, []byte("syslog:\n  udp: myhost:514\n  tcp: 0.0.0.0:514\n  tls: :514\n"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), `syslog.udp host "myhost"`) || !strings.Contains(err.Error(), "syslog.tcp and syslog.tls both use :514") {
		t.Errorf("err = %v", err)
	}
}

func TestSyslogEnvOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env.yaml")
	os.WriteFile(path, []byte("syslog:\n  udp: 0.0.0.0:514\n  tcp: 0.0.0.0:514\n"), 0o600)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	t.Setenv("SIGNALITH_SYSLOG_UDP", "0.0.0.0:5514")
	t.Setenv("SIGNALITH_SYSLOG_TCP", "off")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Syslog.UDP != "0.0.0.0:5514" || c.Syslog.TCP != "" {
		t.Errorf("syslog = %+v", c.Syslog)
	}
}

func TestSavedFileExplainsSyslog(t *testing.T) {
	c := Default()
	h, _ := HashPassword("correct horse")
	c.Auth.AdminPasswordHash = h
	c.Syslog.UDP, c.Syslog.TCP = "0.0.0.0:514", "0.0.0.0:514"
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	text := string(data)
	for _, want := range []string{"# syslog.udp, .tcp", "# appliances, servers). Point them at this server on UDP or TCP port 514, or\n# TLS port 6514", "sender.\nsyslog:\n", "udp: 0.0.0.0:514"} {
		if !strings.Contains(text, want) {
			t.Errorf("saved file lacks %q:\n%s", want, text)
		}
	}
	got, err := Load(path)
	if err != nil || got.Syslog.UDP != "0.0.0.0:514" || got.Syslog.TCP != "0.0.0.0:514" || !got.HasSection("syslog") {
		t.Errorf("reload: %v %+v", err, got.Syslog)
	}

	// Off is written as empty settings, so the section is there to edit.
	c.Syslog.UDP, c.Syslog.TCP = "", ""
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(path); err != nil || got.Syslog.Enabled() || !got.HasSection("syslog") {
		t.Errorf("off: %v %+v, section %v", err, got.Syslog, got != nil && got.HasSection("syslog"))
	}
}

func TestUsersAndDirectorySettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "from-the-env")
	os.WriteFile(path, []byte("lookups:\n  dir: lists\n"), 0o600)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.UsersFile() != filepath.Join(dir, "lists", "users.json") || c.DirectoryFile() != filepath.Join(dir, "lists", "directory.json") {
		t.Errorf("users file = %s, directory file = %s", c.UsersFile(), c.DirectoryFile())
	}
	if s, err := c.LDAP(); s != nil || err != nil {
		t.Errorf("no auth.ldap = %v %v", s, err)
	}
	if !c.CheckPassword("ADMIN", "from-the-env") {
		t.Error("the built-in admin's name should ignore case")
	}
	t.Setenv("SIGNALITH_USERS_FILE", filepath.Join(dir, "elsewhere", "people.json"))
	if c, _ := Load(path); c.UsersFile() != filepath.Join(dir, "elsewhere", "people.json") {
		t.Errorf("env users file = %s", c.UsersFile())
	}

	// auth.ldap: problems are listed with their keys.
	os.WriteFile(path, []byte("auth:\n  ldap:\n    type: ad\n    url: http://dc1\n    bind_dn: CN=svc,DC=corp,DC=example,DC=com\n"), 0o600)
	_, err = Load(path)
	for _, want := range []string{"auth.ldap.url", "auth.ldap.bind_password: set auth.ldap.bind_password, or the SIGNALITH_LDAP_BIND_PASSWORD", "auth.ldap.user_base_dn", "auth.ldap.admin_groups"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q:\n%v", want, err)
		}
	}
	// A complete block: on by default, Active Directory unless type says
	// otherwise, preset defaults filled in, the password from the
	// environment and never written back to the file.
	os.WriteFile(path, []byte(`auth:
  ldap:
    url: ldaps://dc1.corp.example.com
    bind_dn: CN=svc,DC=corp,DC=example,DC=com
    user_base_dn: DC=corp,DC=example,DC=com
    admin_groups:
      - CN=Signalith Admins,OU=Groups,DC=corp,DC=example,DC=com
`), 0o600)
	t.Setenv("SIGNALITH_LDAP_BIND_PASSWORD", "bind-secret")
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.LDAP()
	if err != nil || !s.IsEnabled() || s.Type != "ad" || s.BindPassword != "bind-secret" || s.UsernameAttribute != "sAMAccountName" || !s.Nested() {
		t.Errorf("ldap = %+v %v", s, err)
	}
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "bind-secret") || strings.Contains(string(raw), "sAMAccountName") {
		t.Errorf("saved file has the env password or filled defaults:\n%s", raw)
	}
}

func TestRetentionSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	os.WriteFile(path, []byte(`retention:
  days: 30
  interval: 30m
  default:
    keep_days: 60
    compact_after_days: 7
  policies:
    authentication:
      keep_days: 365
      archive: true
    findings:
      keep_days: 730
  guard:
    max_disk_percent: 80
`), 0o600)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	rc := c.RetentionPolicies()
	if rc.Days != 30 || rc.Default.KeepDays != 60 || !rc.Policies["authentication"].Archive || rc.Policies["findings"].KeepDays != 730 ||
		rc.Guard.MaxDiskPercent != 80 || !rc.Guard.IsEnabled() || c.RetentionInterval().Minutes() != 30 {
		t.Errorf("retention = %+v interval %v", rc, c.RetentionInterval())
	}
	// The archive defaults to a folder next to the lookups folder.
	if got, want := c.ArchiveDir(), filepath.Join(dir, "archive"); got != want {
		t.Errorf("archive dir = %s, want %s", got, want)
	}
	state := filepath.Join(t.TempDir(), "signalith")
	t.Setenv("SIGNALITH_LOOKUPS_DIR", filepath.Join(state, "lookups"))
	if c, _ := Load(path); c.ArchiveDir() != filepath.Join(state, "archive") {
		t.Errorf("archive dir next to lookups = %s", c.ArchiveDir())
	}
	cold := filepath.Join(t.TempDir(), "cold")
	t.Setenv("SIGNALITH_ARCHIVE_DIR", cold)
	if c, _ := Load(path); c.ArchiveDir() != cold {
		t.Errorf("SIGNALITH_ARCHIVE_DIR = %s", c.ArchiveDir())
	}

	// Defaults: retention.days, hourly, no policies.
	d := Default()
	if d.RetentionInterval().Hours() != 1 || d.RetentionPolicies().Days != 90 || d.RetentionPolicies().Default != nil {
		t.Errorf("defaults = %+v", d.Retention)
	}

	os.WriteFile(path, []byte(`retention:
  interval: 1m
  policies:
    authentcation: {keep_days: 30}
    intel: {keep_days: 30}
    endpoint: {keep_days: 7, compact_after_days: 10}
    cases: {keep_days: 30, archive: true}
  guard: {max_disk_percent: 97}
`), 0o600)
	_, err = Load(path)
	for _, want := range []string{"retention.interval", "retention.policies.authentcation: unknown category",
		"retention.policies.intel", "retention.policies.endpoint.compact_after_days", "retention.policies.cases",
		"retention.guard.max_disk_percent"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q:\n%v", want, err)
		}
	}
	os.WriteFile(path, []byte("retention:\n  policies:\n    endpoint: {keep: 30}\n"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "keep") {
		t.Errorf("unknown policy key: %v", err)
	}
}

func TestMaxEventAge(t *testing.T) {
	day := 24 * time.Hour
	// Unset: a week, or the retention period when that is shorter.
	for days, want := range map[int]time.Duration{0: 7 * day, 90: 7 * day, 7: 7 * day, 3: 3 * day, 1: day} {
		if got := Default().MaxEventAge(days); got != want {
			t.Errorf("retention %d days: %v, want %v", days, got, want)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "age.yaml")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	os.WriteFile(path, []byte("ingest:\n  max_event_age: 30d\n"), 0o600)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxEventAge(1) != 30*day {
		t.Errorf("set: %v", c.MaxEventAge(1))
	}
	for _, bad := range []string{"soon", "10m", "4000d"} {
		os.WriteFile(path, []byte("ingest:\n  max_event_age: "+bad+"\n"), 0o600)
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "ingest.max_event_age") {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

// A server that joined a cluster has no built-in admin password of its
// own: the cluster's users sign in. One that did not still needs one.
func TestJoinedServerNeedsNoAdminPassword(t *testing.T) {
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD_FILE", "")
	dir := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", dir)
	path := filepath.Join(dir, "signalith.yaml")
	if err := os.WriteFile(path, []byte("server:\n  listen: 0.0.0.0:8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "admin_password_hash") {
		t.Fatalf("a server outside a cluster without a password: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys", "cluster-k1.key"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("a joined server without a password: %v", err)
	}
	if !c.JoinedCluster() || c.CheckPassword("admin", "") {
		t.Error("the built-in admin signs in without a password")
	}
}
