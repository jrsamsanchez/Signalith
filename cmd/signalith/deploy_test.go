package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/ospki"
	"github.com/jrsamsanchez/signalith/internal/store"
	"gopkg.in/yaml.v3"
)

// The Docker quick start cannot be run in unit tests, so these check that
// its files agree with each other and with what bootstrap-docker makes.

var dockerDir = filepath.Join("..", "..", "deploy", "docker")

type composeService struct {
	User        string            `yaml:"user"`
	Restart     string            `yaml:"restart"`
	NetworkMode string            `yaml:"network_mode"`
	Command     []string          `yaml:"command"`
	Environment []string          `yaml:"environment"`
	Volumes     []string          `yaml:"volumes"`
	Ports       []string          `yaml:"ports"`
	ReadOnly    bool              `yaml:"read_only"`
	Tmpfs       []string          `yaml:"tmpfs"`
	CapDrop     []string          `yaml:"cap_drop"`
	CapAdd      []string          `yaml:"cap_add"`
	SecurityOpt []string          `yaml:"security_opt"`
	Ulimits     map[string]any    `yaml:"ulimits"`
	DependsOn   map[string]dep    `yaml:"depends_on"`
	Healthcheck map[string]any    `yaml:"healthcheck"`
	Image       string            `yaml:"image"`
	Build       map[string]string `yaml:"build"`
	PullPolicy  string            `yaml:"pull_policy"`
	Hostname    string            `yaml:"hostname"`
}

type dep struct {
	Condition string `yaml:"condition"`
}

func readCompose(t *testing.T) (map[string]composeService, map[string]any, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dockerDir, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Services map[string]composeService `yaml:"services"`
		Volumes  map[string]any            `yaml:"volumes"`
	}
	if err := yaml.Unmarshal(raw, &f); err != nil {
		t.Fatalf("docker-compose.yml: %v", err)
	}
	return f.Services, f.Volumes, string(raw)
}

func flagValue(args []string, name string) string {
	if i := slices.Index(args, name); i >= 0 && i+1 < len(args) {
		return args[i+1]
	}
	return ""
}

func TestDockerCompose(t *testing.T) {
	svc, vols, raw := readCompose(t)
	for _, name := range []string{"opensearch-data", "opensearch-certs", "signalith-data", "signalith-secrets"} {
		if _, ok := vols[name]; !ok {
			t.Errorf("volume %s is not declared", name)
		}
	}
	for _, s := range []string{"change-me", "change-this", "DISABLE_SECURITY_PLUGIN", "OPENSEARCH_INITIAL_ADMIN_PASSWORD", "memory_lock"} {
		if strings.Contains(raw, s) {
			t.Errorf("docker-compose.yml contains %q", s)
		}
	}

	// setup writes into the two volumes the others read.
	setup := svc["setup"]
	osDir, sigDir := flagValue(setup.Command, "-opensearch-dir"), flagValue(setup.Command, "-signalith-dir")
	if setup.Command[0] != "bootstrap-docker" || osDir == "" || sigDir == "" {
		t.Fatalf("setup command %v", setup.Command)
	}
	if !slices.Contains(setup.Volumes, "opensearch-certs:"+osDir) || !slices.Contains(setup.Volumes, "signalith-secrets:"+sigDir) {
		t.Errorf("setup volumes %v", setup.Volumes)
	}
	// The CA's key has a volume of its own that only setup mounts, and
	// setup can hand it over in Signalith's state folder and ask for the
	// security settings to load again.
	if _, ok := vols["opensearch-ca"]; !ok {
		t.Error("volume opensearch-ca is not declared")
	}
	for flag, vol := range map[string]string{"-ca-dir": "opensearch-ca", "-state-dir": "signalith-data", "-loaded-dir": "opensearch-security-loaded"} {
		dir := flagValue(setup.Command, flag)
		if dir == "" || !slices.Contains(setup.Volumes, vol+":"+dir) {
			t.Errorf("setup: %s %q, volumes %v", flag, dir, setup.Volumes)
		}
	}
	// Runs by hand replace the command, so the same folders come from
	// the environment too.
	for flag, env := range map[string]string{"-opensearch-dir": "SIGNALITH_SETUP_OPENSEARCH_DIR", "-signalith-dir": "SIGNALITH_SETUP_SIGNALITH_DIR",
		"-ca-dir": "SIGNALITH_SETUP_CA_DIR", "-state-dir": "SIGNALITH_SETUP_STATE_DIR", "-loaded-dir": "SIGNALITH_SETUP_LOADED_DIR"} {
		if !slices.Contains(setup.Environment, env+"="+flagValue(setup.Command, flag)) {
			t.Errorf("setup environment %v lacks %s for %s", setup.Environment, env, flag)
		}
	}
	for name, s := range svc {
		for _, v := range s.Volumes {
			if strings.HasPrefix(v, "opensearch-ca:") && name != "setup" {
				t.Errorf("%s mounts the CA's key: %s", name, v)
			}
		}
	}
	if setup.User != "0:0" || setup.Restart != "no" || setup.NetworkMode != "none" {
		t.Errorf("setup: user %q restart %q network %q", setup.User, setup.Restart, setup.NetworkMode)
	}
	// bootstrap-docker needs to change owners (CHOWN), write in folders
	// it gave away (DAC_OVERRIDE) and set modes on files it gave away
	// (FOWNER), and nothing else.
	if !slices.Equal(setup.CapDrop, []string{"ALL"}) || !slices.Equal(setup.CapAdd, []string{"CHOWN", "DAC_OVERRIDE", "FOWNER"}) {
		t.Errorf("setup capabilities: drop %v add %v", setup.CapDrop, setup.CapAdd)
	}
	// setup and signalith run the same image: the one GitHub built, fetched
	// again on every `up`, or with docker-compose.build.yml the one built
	// from the checked-out code on every `up`.
	const image = "ghcr.io/jrsamsanchez/signalith:${SIGNALITH_VERSION:-main}"
	for _, name := range []string{"setup", "signalith"} {
		if s := svc[name]; s.Image != image || s.PullPolicy != "always" || len(s.Build) != 0 {
			t.Errorf("%s: image %q pull %q build %v", name, s.Image, s.PullPolicy, s.Build)
		}
	}
	rawBuild, err := os.ReadFile(filepath.Join(dockerDir, "docker-compose.build.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var build struct {
		Services map[string]composeService `yaml:"services"`
	}
	if err := yaml.Unmarshal(rawBuild, &build); err != nil {
		t.Fatalf("docker-compose.build.yml: %v", err)
	}
	if len(build.Services) != 2 {
		t.Errorf("docker-compose.build.yml changes %d services, want setup and signalith", len(build.Services))
	}
	for _, name := range []string{"setup", "signalith"} {
		b := build.Services[name]
		if b.Image != "signalith:local" || b.PullPolicy != "build" || b.Build["context"] != "../.." || b.Build["dockerfile"] != "deploy/docker/Dockerfile" {
			t.Errorf("docker-compose.build.yml %s: image %q pull %q build %v", name, b.Image, b.PullPolicy, b.Build)
		}
	}

	// OpenSearch: our settings and security files, the certificates
	// read-only, demo setup off, nothing published.
	o := svc["opensearch"]
	if o.DependsOn["setup"].Condition != "service_completed_successfully" {
		t.Errorf("opensearch depends on %v", o.DependsOn)
	}
	if !slices.Contains(o.Environment, "DISABLE_INSTALL_DEMO_CONFIG=true") || !slices.Contains(o.Environment, "discovery.type=single-node") ||
		!slices.Contains(o.Environment, "DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI=true") {
		t.Errorf("opensearch environment %v", o.Environment)
	}
	if len(o.Ports) != 0 {
		t.Errorf("opensearch publishes %v", o.Ports)
	}
	want := []string{
		"opensearch-data:/usr/share/opensearch/data",
		"opensearch-certs:/usr/share/opensearch/config/certs:ro",
		"./opensearch/opensearch.yml:/usr/share/opensearch/config/opensearch.yml:ro",
	}
	for name := range ospki.SecurityFiles() {
		want = append(want, "./opensearch/security/"+name+":/usr/share/opensearch/config/opensearch-security/"+name+":ro")
	}
	for _, v := range want {
		if !slices.Contains(o.Volumes, v) {
			t.Errorf("opensearch lacks volume %s", v)
		}
	}
	for _, v := range o.Volumes {
		if src, _, _ := strings.Cut(v, ":"); strings.HasPrefix(src, "./") {
			if _, err := os.Stat(filepath.Join(dockerDir, src)); err != nil {
				t.Errorf("opensearch mounts %s: %v", src, err)
			}
		}
	}
	health := strings.Join(anyStrings(o.Healthcheck["test"]), " ")
	for _, f := range []string{ospki.RootCAFile, ospki.AdminCertFile, ospki.AdminKeyFile} {
		if !strings.Contains(health, "/usr/share/opensearch/config/certs/"+f) {
			t.Errorf("health check does not use %s: %s", f, health)
		}
	}
	// Healthy only once its security settings are loaded.
	if !strings.Contains(health, "https://localhost:9200/") || !strings.Contains(health, "/_plugins/_security/health") {
		t.Errorf("health check: %s", health)
	}

	// The step that loads OpenSearch's security settings: the same files
	// as OpenSearch's, the certificates and its script read-only, and
	// hardened. It waits for OpenSearch to start, not to be healthy, since
	// OpenSearch turns healthy only once it has done its job.
	l := svc["opensearch-security"]
	if l.DependsOn["setup"].Condition != "service_completed_successfully" || l.DependsOn["opensearch"].Condition != "service_started" {
		t.Errorf("opensearch-security depends on %v", l.DependsOn)
	}
	if _, ok := vols["opensearch-security-loaded"]; !ok {
		t.Error("volume opensearch-security-loaded is not declared")
	}
	want = []string{
		"opensearch-certs:/usr/share/opensearch/config/certs:ro",
		"./opensearch/load-security.sh:/usr/share/opensearch/load-security.sh:ro",
		"opensearch-security-loaded:/usr/share/opensearch/data",
	}
	for name := range ospki.SecurityFiles() {
		want = append(want, "./opensearch/security/"+name+":/usr/share/opensearch/config/opensearch-security/"+name+":ro")
	}
	for _, v := range want {
		if !slices.Contains(l.Volumes, v) {
			t.Errorf("opensearch-security lacks volume %s", v)
		}
	}
	if _, err := os.Stat(filepath.Join(dockerDir, "opensearch", "load-security.sh")); err != nil {
		t.Error(err)
	}
	if l.User != "1000:1000" || l.Restart != "no" || !l.ReadOnly || !slices.Contains(l.Tmpfs, "/tmp") || !slices.Equal(l.CapDrop, []string{"ALL"}) ||
		len(l.CapAdd) != 0 || !slices.Contains(l.SecurityOpt, "no-new-privileges:true") || len(l.Ports) != 0 {
		t.Errorf("opensearch-security: user %q restart %q read_only %v tmpfs %v cap_drop %v cap_add %v security_opt %v ports %v",
			l.User, l.Restart, l.ReadOnly, l.Tmpfs, l.CapDrop, l.CapAdd, l.SecurityOpt, l.Ports)
	}

	// Signalith: secrets only as files from setup, and hardened. It starts
	// once OpenSearch's security settings are loaded.
	s := svc["signalith"]
	if s.DependsOn["setup"].Condition != "service_completed_successfully" || s.DependsOn["opensearch"].Condition != "service_healthy" ||
		s.DependsOn["opensearch-security"].Condition != "service_completed_successfully" {
		t.Errorf("signalith depends on %v", s.DependsOn)
	}
	secretsAt := ""
	for _, v := range s.Volumes {
		if after, ok := strings.CutPrefix(v, "signalith-secrets:"); ok {
			secretsAt = strings.TrimSuffix(after, ":ro")
			if !strings.HasSuffix(v, ":ro") {
				t.Errorf("secrets are writable: %s", v)
			}
		}
	}
	for _, v := range []string{"SIGNALITH_ADMIN_PASSWORD_FILE=" + secretsAt + "/" + initialPasswordFile, "SIGNALITH_INGEST_TOKEN_FILE=" + secretsAt + "/" + ingestTokenFile} {
		if !slices.Contains(s.Environment, v) {
			t.Errorf("signalith environment lacks %s: %v", v, s.Environment)
		}
	}
	for _, e := range s.Environment {
		name, _, _ := strings.Cut(e, "=")
		if (strings.Contains(name, "PASSWORD") || strings.Contains(name, "TOKEN") || strings.Contains(name, "KEY")) && !strings.HasSuffix(name, "_FILE") {
			t.Errorf("a secret in the environment: %s", name)
		}
	}
	for _, v := range []string{"./signalith.yaml:/etc/signalith/signalith.yaml:ro", "signalith-data:/var/lib/signalith"} {
		if !slices.Contains(s.Volumes, v) {
			t.Errorf("signalith lacks volume %s", v)
		}
	}
	if !s.ReadOnly || !slices.Contains(s.Tmpfs, "/tmp") || !slices.Equal(s.CapDrop, []string{"ALL"}) || len(s.CapAdd) != 0 ||
		!slices.Contains(s.SecurityOpt, "no-new-privileges:true") || s.Ulimits["core"] != 0 {
		t.Errorf("signalith hardening: read_only %v tmpfs %v cap_drop %v cap_add %v security_opt %v ulimits %v",
			s.ReadOnly, s.Tmpfs, s.CapDrop, s.CapAdd, s.SecurityOpt, s.Ulimits)
	}
	for _, p := range []string{"8080:8080", "514:5514/udp", "514:5514/tcp", "6514:6514"} {
		if !slices.Contains(s.Ports, p) {
			t.Errorf("signalith does not publish %s", p)
		}
	}
	// A fixed host name for the certificate and its CA, not the
	// container's ID.
	if s.Hostname != "signalith" {
		t.Errorf("signalith hostname %q", s.Hostname)
	}
}

// TestDockerConfigLoads loads the Docker quick start's signalith.yaml the
// way the container does, with the files bootstrap-docker makes.
func TestDockerConfigLoads(t *testing.T) {
	svc, _, _ := readCompose(t)
	root := t.TempDir()
	osDir, sigDir, data := filepath.Join(root, "certs"), filepath.Join(root, "secrets"), filepath.Join(root, "data")
	bootstrap(t, osDir, sigDir)
	raw, err := os.ReadFile(filepath.Join(dockerDir, "signalith.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "change-me") || strings.Contains(string(raw), "password:") {
		t.Error("signalith.yaml holds a secret")
	}
	// The container's paths, here in temporary folders.
	secretsAt := "/run/signalith-secrets"
	for _, v := range svc["signalith"].Volumes {
		if after, ok := strings.CutPrefix(v, "signalith-secrets:"); ok {
			secretsAt = strings.TrimSuffix(after, ":ro")
		}
	}
	for _, f := range []string{ospki.ClientCAFile, ospki.ClientCertFile, ospki.ClientKeyFile} {
		if !strings.Contains(string(raw), secretsAt+"/"+f) {
			t.Errorf("signalith.yaml does not use %s/%s", secretsAt, f)
		}
	}
	text := strings.ReplaceAll(string(raw), secretsAt, filepath.ToSlash(sigDir))
	text = strings.ReplaceAll(text, "/var/lib/signalith", filepath.ToSlash(data))
	path := filepath.Join(root, "signalith.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	for _, e := range svc["signalith"].Environment {
		k, v, _ := strings.Cut(e, "=")
		env[k] = strings.Replace(v, secretsAt, sigDir, 1)
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	t.Setenv("SIGNALITH_STATE_DIR", data)
	t.Setenv("SIGNALITH_PUBLIC_URL", "")
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := os.ReadFile(filepath.Join(sigDir, initialPasswordFile))
	token, _ := os.ReadFile(filepath.Join(sigDir, ingestTokenFile))
	if !c.CheckPassword("admin", strings.TrimSpace(string(pw))) || !slices.Equal(c.Ingest.Tokens, []string{strings.TrimSpace(string(token))}) {
		t.Errorf("secrets not taken from the files: tokens %v", c.Ingest.Tokens)
	}
	// A new install refuses agents on plain HTTP: no plaintext_ingest is
	// set, and nothing says it was upgraded.
	if c.Server.TLSMode() != config.TLSAuto || c.Server.PlaintextIngest() || c.Server.PublicURL != "https://localhost:8080" {
		t.Errorf("server: mode %s plaintext %v url %s", c.Server.TLSMode(), c.Server.PlaintextIngest(), c.Server.PublicURL)
	}
	if c.OpenSearch.URL != "https://opensearch:9200" || c.OpenSearch.Username != "" || c.Syslog.TLS != "0.0.0.0:6514" {
		t.Errorf("opensearch %s user %q syslog.tls %q", c.OpenSearch.URL, c.OpenSearch.Username, c.Syslog.TLS)
	}
	if w := c.Warnings(); len(w) != 0 {
		t.Errorf("warnings: %v", w)
	}
	setup, err := os.Stat(filepath.Join(sigDir, ingestTokenFile))
	if err != nil {
		t.Fatal(err)
	}
	dockerNew(t, path, setup.ModTime())
	dockerUpgrade(t, path, setup.ModTime())
}

// dockerOpenSearch is an OpenSearch that answers _cat/indices for
// Signalith's event indices, with when it made each one.
func dockerOpenSearch(t *testing.T, made map[string]time.Time) *store.Client {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_cat/indices/signalith-*" || r.URL.Query().Get("h") != "index,creation.date" {
			http.Error(w, `{"error":"unexpected"}`, http.StatusBadRequest)
			return
		}
		rows := []map[string]string{}
		for name, at := range made {
			rows = append(rows, map[string]string{"index": name, "creation.date": strconv.FormatInt(at.UnixMilli(), 10)})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rows)
	}))
	t.Cleanup(ts.Close)
	return store.New(store.Config{URL: ts.URL})
}

// dockerServer serves c as the Docker quick start's container does, over
// plain HTTP and HTTPS on the same port, and posts a batch of one
// Windows event with a token.
type dockerServer struct {
	srv           *api.Server
	plain, secure *httptest.Server
}

func newDockerServer(t *testing.T, c *config.Config) *dockerServer {
	t.Helper()
	d := &dockerServer{srv: &api.Server{
		Config:   c,
		Pipeline: &ingest.Pipeline{Store: nopBulk{}},
		Log:      slog.New(slog.DiscardHandler),
		Runtime:  &api.Runtime{OS: "linux", Container: true, Addresses: []string{}},
	}}
	d.plain = httptest.NewServer(d.srv.PlainHandler(d.srv.Handler()))
	d.secure = httptest.NewTLSServer(d.srv.Handler())
	t.Cleanup(d.plain.Close)
	t.Cleanup(d.secure.Close)
	return d
}

func (d *dockerServer) post(t *testing.T, https bool, token string) int {
	t.Helper()
	ts := d.plain
	if https {
		ts = d.secure
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/ingest", strings.NewReader(`[{"Computer":"WIN-01","EventID":4624,"Channel":"Security"}]`))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// decideAt makes the decision about the example token for the quick
// start whose setup step ran at setup, as its first start does.
func decideAt(t *testing.T, path string, setup time.Time, cat indexLister) *config.DockerUpgrade {
	t.Helper()
	old := dockerSetup
	dockerSetup = func() (time.Time, error) { return setup, nil }
	defer func() { dockerSetup = old }()
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	u, err := decideDockerUpgradeOnce(context.Background(), c, cat, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// restart loads the config again, as the next start does, and runs what
// each start runs about the example token.
func restart(t *testing.T, path string, cat indexLister) (*config.Config, *dockerServer) {
	t.Helper()
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	d := newDockerServer(t, c)
	settleDockerUpgrade(context.Background(), c, cat, d.srv, slog.New(slog.DiscardHandler))
	return d.srv.Running(), d
}

// dockerNew checks a quick start installed new with its own config. The
// example token change-this-ingest-token, which older quick starts gave
// every agent and anyone can look up, is a wrong token there: 401, even
// over plain HTTP. Events stored right after setup, by a test or by
// sample data dated a week back, do not make it look upgraded, and the
// decision is kept: OpenSearch holding older events later changes
// nothing.
func dockerNew(t *testing.T, path string, setup time.Time) {
	t.Helper()
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	week := setup.AddDate(0, 0, -6).UTC().Format("2006.01.02")
	made := map[string]time.Time{
		"signalith-windows-" + setup.UTC().Format("2006.01.02"): setup.Add(time.Minute),
		"signalith-authentication-" + week:                      setup.Add(3 * time.Minute),
	}
	cat := dockerOpenSearch(t, made)
	if u := decideAt(t, path, setup, cat); u.Upgraded || u.Index != "" || !u.Setup.Equal(setup.UTC()) {
		t.Fatalf("new install decided %+v", u)
	}
	c, d := restart(t, path, cat)
	if c.OldToken() != config.OldTokenRefused || c.Server.PlaintextIngest() {
		t.Errorf("new install: old token %v, plain %v", c.OldToken(), c.Server.PlaintextIngest())
	}
	if code := d.post(t, false, "change-this-ingest-token"); code != http.StatusUnauthorized {
		t.Errorf("new install, old token over plain HTTP: %d", code)
	}
	if code := d.post(t, true, "change-this-ingest-token"); code != http.StatusUnauthorized {
		t.Errorf("new install, old token over HTTPS: %d", code)
	}
	if code := d.post(t, true, c.Ingest.Tokens[0]); code != http.StatusOK {
		t.Errorf("new install, its own token over HTTPS: %d", code)
	}
	// Its own token over plain HTTP: refused, as a batch the agent keeps.
	if code := d.post(t, false, c.Ingest.Tokens[0]); code != http.StatusServiceUnavailable {
		t.Errorf("new install, its own token over plain HTTP: %d", code)
	}
	if got := d.srv.Pipeline.Stats().Received; got != 1 {
		t.Errorf("received %d events", got)
	}
	// Decided once: with older events in OpenSearch now, the next start
	// keeps the decision.
	before, _ := os.ReadFile(config.DockerUpgradeFileIn(c.StateDir()))
	made["signalith-linux-2026.01.01"] = setup.AddDate(0, -3, 0)
	c, d = restart(t, path, cat)
	if after, _ := os.ReadFile(config.DockerUpgradeFileIn(c.StateDir())); string(after) != string(before) || c.OldToken() != config.OldTokenRefused {
		t.Errorf("the decision changed:\n%s\n%s", before, after)
	}
	if code := d.post(t, false, "change-this-ingest-token"); code != http.StatusUnauthorized {
		t.Errorf("new install after a restart, old token over plain HTTP: %d", code)
	}
}

// dockerUpgrade checks a quick start upgraded from the older one, whose
// OpenSearch held events from before the setup step first ran. Its
// agents sent the example token change-this-ingest-token over plain HTTP,
// which the new docker-compose.yml no longer sets: they keep sending, and
// agents on plain HTTP are accepted, until those are refused, which ends
// the token for good. New agents get the server's own token, even if the
// old one is put back in the environment.
func dockerUpgrade(t *testing.T, path string, setup time.Time) {
	t.Helper()
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	made := map[string]time.Time{
		"signalith-windows-2026.09.30": setup.AddDate(0, 0, -13),
		"signalith-windows-2026.10.01": setup.AddDate(0, 0, -12),
		// Today's, made after the upgrade.
		"signalith-windows-" + setup.UTC().Format("2006.01.02"): setup.Add(time.Minute),
	}
	cat := dockerOpenSearch(t, made)
	if u := decideAt(t, path, setup, cat); !u.Upgraded || u.Index != "signalith-windows-2026.09.30" || !u.IndexMade.Equal(setup.AddDate(0, 0, -13).Truncate(time.Millisecond).UTC()) {
		t.Fatalf("upgrade decided %+v", u)
	}
	// Stable across restarts, even once retention has deleted the old days.
	delete(made, "signalith-windows-2026.09.30")
	delete(made, "signalith-windows-2026.10.01")
	c, d := restart(t, path, cat)
	if c.OldToken() != config.OldTokenAccepted || !c.Server.PlaintextIngest() {
		t.Fatalf("upgraded: old token %v, plain %v", c.OldToken(), c.Server.PlaintextIngest())
	}
	if code := d.post(t, false, "change-this-ingest-token"); code != http.StatusOK {
		t.Errorf("an old agent over plain HTTP: %d", code)
	}
	if got := d.srv.Pipeline.PlaintextSenders(time.Time{}); len(got) != 1 || !slices.Equal(got[0].Hosts, []string{"WIN-01"}) {
		t.Errorf("plain-text senders %+v", got)
	}
	// Over HTTPS the old token is refused, with a status Fluent Bit
	// retries; the server's own token works.
	if code := d.post(t, true, "change-this-ingest-token"); code != http.StatusServiceUnavailable {
		t.Errorf("the old token over HTTPS: %d", code)
	}
	if code := d.post(t, true, c.Ingest.Tokens[0]); code != http.StatusOK {
		t.Errorf("the new token over HTTPS: %d", code)
	}
	// Put back in the environment, the old token is not handed to new
	// agents, and neither is the shared one: they get a placeholder the
	// Add data page fills with a token of their own.
	c.Ingest.Tokens = append(c.Ingest.Tokens, "change-this-ingest-token")
	slices.Reverse(c.Ingest.Tokens)
	h, _ := config.HashPassword("an admin password")
	c.Auth.AdminPasswordHash = h
	req, _ := http.NewRequest("GET", d.secure.URL+"/api/agents/config?os=windows", nil)
	req.SetBasicAuth("admin", "an admin password")
	resp, err := d.secure.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || strings.Contains(string(b), "change-this-ingest-token") || strings.Contains(string(b), c.Ingest.Tokens[1]) ||
		!strings.Contains(string(b), "Bearer @@AGENT_TOKEN@@") {
		t.Errorf("agent config: %d %s", resp.StatusCode, b)
	}

	// Agents on plain HTTP refused in signalith.yaml: the next start ends
	// the old token for good.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	setPlain := func(v string) {
		t.Helper()
		text := strings.Replace(string(raw), "    mode: auto\n", "    mode: auto\n    plaintext_ingest: "+v+"\n", 1)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	defer os.WriteFile(path, raw, 0o600)
	setPlain("deny")
	if c, d = restart(t, path, cat); c.OldToken() != config.OldTokenEnded {
		t.Errorf("after refusing agents on plain HTTP: %v", c.OldToken())
	}
	if code := d.post(t, false, "change-this-ingest-token"); code != http.StatusServiceUnavailable {
		t.Errorf("an old agent, refused: %d", code)
	}
	// Accepted again later: the old token stays refused, as a batch the
	// agent keeps; agents with the server's own token are accepted.
	setPlain("allow")
	c, d = restart(t, path, cat)
	if c.OldToken() != config.OldTokenEnded || !c.Server.PlaintextIngest() {
		t.Errorf("accepted again: old token %v, plain %v", c.OldToken(), c.Server.PlaintextIngest())
	}
	if code := d.post(t, false, "change-this-ingest-token"); code != http.StatusServiceUnavailable {
		t.Errorf("an old agent after the token ended: %d", code)
	}
	if code := d.post(t, false, c.Ingest.Tokens[0]); code != http.StatusOK {
		t.Errorf("the new token over plain HTTP, accepted: %d", code)
	}
}

// nopBulk stores nothing and says every event was stored.
type nopBulk struct{}

func (nopBulk) Bulk(context.Context, []store.IndexedDoc) ([]store.BulkItemError, error) {
	return nil, nil
}

func anyStrings(v any) []string {
	var out []string
	if list, ok := v.([]any); ok {
		for _, x := range list {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
