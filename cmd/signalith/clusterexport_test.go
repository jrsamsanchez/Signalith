package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tenants"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Every importer of the shared settings has an exporter of the same
// name, or says in exportSkipped why it has none, so a downgrade after a
// raise never loses a feature's settings silently.
func TestEveryImporterHasExporter(t *testing.T) {
	d := newSharedDocs(clusterauth.NewDocs())
	c := config.Default()
	files := clustercfg.Files{Config: func() *config.Config { return c }, Node: "siem-a", NodeID: "n_a"}
	exporters := map[string]bool{}
	for _, ex := range sharedExporters(d, files) {
		if ex.Run == nil {
			t.Errorf("exporter %s does nothing", ex.Name)
		}
		if exporters[ex.Name] {
			t.Errorf("two exporters named %s", ex.Name)
		}
		exporters[ex.Name] = true
	}
	importers := map[string]bool{}
	for _, im := range sharedImporters(d, files) {
		importers[im.Name] = true
		_, skipped := exportSkipped[im.Name]
		switch {
		case exporters[im.Name] && skipped:
			t.Errorf("%s has an exporter and is listed as skipped", im.Name)
		case !exporters[im.Name] && !skipped:
			t.Errorf("the importer %s has no exporter: add one to sharedExporters, or say why in exportSkipped", im.Name)
		case skipped && exportSkipped[im.Name] == "":
			t.Errorf("%s is skipped without a reason", im.Name)
		}
	}
	for name := range exporters {
		if !importers[name] {
			t.Errorf("the exporter %s inverts no importer", name)
		}
	}
}

// The export folder's layout follows this server's folders.
func TestExportLayout(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "etc", "signalith.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	conf := "detections:\n  dir: " + filepath.ToSlash(filepath.Join(base, "rules")) + "\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_STATE_DIR", filepath.Join(base, "state"))
	c, err := config.LoadUnchecked(path)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "out")
	l := newExportLayout(root, &clusterCLI{c: c})
	for in, want := range map[string]string{
		filepath.Join(base, "rules", "a.yaml"):          filepath.Join(root, "detections", "a.yaml"),
		filepath.Join(base, "state", "tls", "ca.pem"):   filepath.Join(root, "state", "tls", "ca.pem"),
		filepath.Join(base, "etc", "lookups", "x.json"): filepath.Join(root, "config", "lookups", "x.json"),
		filepath.Join(base, "elsewhere", "users.json"):  "",
	} {
		got := l.under(in)
		if want == "" {
			if rel, ok := relWithin(filepath.Join(root, "other"), got); !ok || !strings.HasSuffix(filepath.ToSlash(rel), "elsewhere/users.json") {
				t.Errorf("%s -> %s", in, got)
			}
			continue
		}
		if got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}

// signalith cluster export --to-files writes the files a server on its
// own reads, which hold what the shared settings held; -retire puts the
// shared settings aside with every server stopped, and a cluster founded
// from the files has them again.
func TestClusterExportToFiles(t *testing.T) {
	fake := ostest.New(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "a-test-admin-password")
	t.Setenv(clusterKeyFileEnv, "")
	lookups, rules, boards := filepath.Join(dir, "lookups"), filepath.Join(dir, "rules"), filepath.Join(dir, "boards")
	conf := "opensearch:\n  url: " + fake.URL + "\n  index_prefix: cx\nlookups:\n  dir: " + filepath.ToSlash(lookups) +
		"\ndetections:\n  dir: " + filepath.ToSlash(rules) + "\ndashboards:\n  dir: " + filepath.ToSlash(boards) + "\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	old := cliWatch
	cliWatch = 10 * time.Millisecond
	t.Cleanup(func() { cliWatch = old })
	run := func(args ...string) (string, error) {
		t.Helper()
		in, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer in.Close()
		w.Close()
		var out, errOut bytes.Buffer
		err = runCluster(append(args, "-c", path), in, &out, &errOut)
		return out.String() + errOut.String(), err
	}
	stateA := filepath.Join(dir, "state-a")
	clusterServerDir(t, stateA, "siem-a")

	// This server's files before the cluster.
	hash, err := config.HashPassword("jlee-password")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if err := os.MkdirAll(lookups, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := users.WriteFile(filepath.Join(lookups, "users.json"), map[string]users.Record{"jlee": {
		User: users.User{Username: "jlee", Role: users.Analyst, Source: users.SourceLocal, Created: now, Updated: now}, Hash: hash, Epoch: 1}}, nil); err != nil {
		t.Fatal(err)
	}
	feeds := "feeds:\n  - name: mine\n    url: https://mine.example.com/list\n    format: lines\n    type: ip\n    username: u\n    password: feed-pass\n"
	if err := os.WriteFile(filepath.Join(lookups, "intel_feeds.yaml"), []byte(feeds), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := retention.NewStore(filepath.Join(lookups, "retention.yaml")).Update(func(s *retention.Saved) {
		s.Policies = map[string]retention.Policy{retention.Findings: {KeepDays: 45}}
	}); err != nil {
		t.Fatal(err)
	}
	rule := &detect.Detection{ID: "my-rule", Title: "Mine", Severity: "medium", Query: "event.action=failure", Schedule: "5m", Lookback: "5m", Enabled: true}
	rule.Defaults()
	ruleYAML, err := detect.Encode(rule)
	if err != nil {
		t.Fatal(err)
	}
	board := &dashboards.Dashboard{ID: "ops", Title: "Ops", Panels: []dashboards.Panel{{Title: "Events", Query: "* | stats count", Viz: dashboards.VizSingle}}}
	board.Defaults()
	boardYAML, err := dashboards.Encode(board)
	if err != nil {
		t.Fatal(err)
	}
	for p, data := range map[string][]byte{filepath.Join(rules, "my-rule.yaml"): ruleYAML, filepath.Join(boards, "ops.yaml"): boardYAML} {
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Its tenants, one turned off.
	tenantsFile := tenants.File(stateA)
	if err := tenants.WriteFile(tenantsFile, []tenants.Tenant{{ID: "acme", Name: "Acme", Created: now}, {ID: "contoso", Name: "Contoso", Disabled: true, Created: now}}); err != nil {
		t.Fatal(err)
	}
	if out, err := run("found", "-name", "Plant"); err != nil {
		t.Fatalf("found: %v\n%s", err, out)
	}

	// Not into a folder this server uses, nor one that holds anything.
	if _, err := run("export", "--to-files", filepath.Join(stateA, "keys", "out")); err == nil || !strings.Contains(err.Error(), "a folder this server uses") {
		t.Errorf("export into the state folder: %v", err)
	}
	full := filepath.Join(t.TempDir(), "full")
	if err := os.MkdirAll(full, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run("export", "--to-files", full); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("export into a folder that is not empty: %v", err)
	}

	out1 := filepath.Join(t.TempDir(), "export")
	out, err := run("export", "--to-files", out1)
	if err != nil || !strings.Contains(out, "README.txt") {
		t.Fatalf("export --to-files: %v\n%s", err, out)
	}
	m := readManifest(t, out1)
	byName := map[string]manifestFile{}
	for _, f := range m.Files {
		byName[f.Name] = f
		if _, err := os.Stat(filepath.Join(out1, filepath.FromSlash(f.Path))); err != nil {
			t.Errorf("%s is listed but not written: %v", f.Path, err)
		}
	}
	for name, dest := range map[string]string{
		"users": filepath.Join(lookups, "users.json"), "feeds": filepath.Join(lookups, "intel_feeds.yaml"),
		"retention": filepath.Join(lookups, "retention.yaml"), "detections": filepath.Join(rules, "my-rule.yaml"),
		"dashboards": filepath.Join(boards, "ops.yaml"), "tenants": tenantsFile,
	} {
		if f, ok := byName[name]; !ok || f.Dest != dest {
			t.Errorf("%s: %+v, want it to go to %s", name, f, dest)
		}
	}
	exported, err := tenants.Open(filepath.Join(out1, filepath.FromSlash(byName["tenants"].Path)))
	if err != nil {
		t.Fatal(err)
	}
	if list, _ := exported.List(); len(list) != 2 || list[0].ID != "acme" || list[1].ID != "contoso" || !list[1].Disabled {
		t.Errorf("exported tenants: %+v", list)
	}
	if !byName["users"].Secret || !byName["feeds"].Secret {
		t.Errorf("files with secrets are not marked: %+v", m.Files)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(filepath.Join(out1, filepath.FromSlash(byName["feeds"].Path)))
		if err != nil || st.Mode().Perm()&0o077 != 0 {
			t.Errorf("the feeds file: %v %v", st, err)
		}
	}
	if !slices.ContainsFunc(m.Skipped, func(s manifestSkipped) bool { return s.Name == shared.ImportArchives }) {
		t.Errorf("the archives are not listed as skipped: %+v", m.Skipped)
	}
	readme, err := os.ReadFile(filepath.Join(out1, "README.txt"))
	wantCopy := "sudo install -D -o signalith -g signalith"
	if runtime.GOOS == "windows" {
		wantCopy = "Copy-Item"
	}
	if err != nil || !strings.Contains(string(readme), wantCopy) || !strings.Contains(string(readme), "import-key") {
		t.Errorf("README.txt: %v\n%s", err, readme)
	}
	if len(exportMarks(stateA)) != 1 {
		t.Errorf("no mark of the export in the state folder: %v", exportMarks(stateA))
	}
	raw, _ := os.ReadFile(filepath.Join(out1, filepath.FromSlash(byName["feeds"].Path)))
	if strings.Contains(string(raw), "feed-pass") {
		t.Error("the feed's password is in the clear")
	}

	// -retire refuses while a server's heartbeat moves.
	hb := cluster.Heartbeat{Kind: "node", NodeID: "n_other", Name: "siem-z", State: cluster.StateReady, LeaderEligible: true, HeartbeatAt: time.Now().UTC()}
	// It reads every level this version does, so the cluster founded
	// again later is at the level of the first.
	hb.LevelMax = shared.LevelMax
	fake.Put("cx_runtime", "node:n_other", asMap(t, hb))
	beating, beat := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(beat)
		for {
			select {
			case <-beating:
				return
			case <-time.After(2 * time.Millisecond):
			}
			hb.HeartbeatAt = time.Now().UTC()
			fake.Put("cx_runtime", "node:n_other", asMap(t, hb))
		}
	}()
	_, err = run("export", "-retire", "--to-files", filepath.Join(t.TempDir(), "r"), "-yes")
	close(beating)
	<-beat
	if err == nil || !strings.Contains(err.Error(), "siem-z is running") {
		t.Fatalf("-retire with a running server: %v", err)
	}
	hb.State = cluster.StateStopped
	fake.Put("cx_runtime", "node:n_other", asMap(t, hb))
	if _, err := run("export", "-retire", "-yes"); err == nil || !strings.Contains(err.Error(), "--to-files") {
		t.Errorf("-retire on the first server without --to-files: %v", err)
	}

	// The other server keeps a copy of the cluster key.
	stateB := filepath.Join(dir, "state-b")
	keys := shared.ClusterKeyFiles(stateA)
	if len(keys) == 0 {
		t.Fatal("no cluster key")
	}
	clusterServerDir(t, stateB, "siem-b")
	copyTo(t, keys[0], filepath.Join(stateB, "keys", filepath.Base(keys[0])))
	// It exported its own files first (its copy of the key here is not
	// sealed with its own master key, so only the mark is made).
	if err := os.WriteFile(exportMarkPath(stateB, "c1"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_STATE_DIR", stateA)

	before := len(fakeDocs(t, fake, shared.ConfigIndex("cx")))
	out2 := filepath.Join(t.TempDir(), "retire")
	out, err = run("export", "-retire", "--to-files", out2, "-yes")
	if err != nil {
		t.Fatalf("-retire: %v\n%s", err, out)
	}
	indices := fake.Indices()
	if slices.Contains(indices, shared.ConfigIndex("cx")) {
		t.Fatalf("the config index is still there: %v", indices)
	}
	var retiredIndex string
	for _, ix := range indices {
		if strings.HasPrefix(ix, "cx_config_retired_") {
			retiredIndex = ix
		}
	}
	if retiredIndex == "" || len(fakeDocs(t, fake, retiredIndex)) != before || before == 0 {
		t.Fatalf("retired copy %q of %d documents: %v", retiredIndex, before, indices)
	}
	stamp := strings.TrimPrefix(retiredIndex, "cx_config_retired_")
	if len(shared.ClusterKeyFiles(stateA)) != 0 {
		t.Error("the cluster key was not put aside")
	}
	if _, err := os.Stat(filepath.Join(stateA, "retired-"+stamp, filepath.Base(keys[0]))); err != nil {
		t.Errorf("the cluster key is not in the retired folder: %v", err)
	}
	if _, err := cluster.ReadIdentity(stateA); err != nil {
		t.Errorf("node.id was moved: %v", err)
	}

	// A later server only puts its own files aside, in the same folder.
	t.Setenv("SIGNALITH_STATE_DIR", stateB)
	if _, err := run("export", "-retire", "--to-files", filepath.Join(t.TempDir(), "b"), "-yes"); err == nil || !strings.Contains(err.Error(), "put aside already") {
		t.Errorf("-retire --to-files on a later server: %v", err)
	}
	// Not on one that never exported its files, unless -force.
	marks := exportMarks(stateB)
	for _, mk := range marks {
		if err := os.Rename(mk, mk+".aside"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := run("export", "-retire", "-yes"); err == nil || !strings.Contains(err.Error(), "never ran") {
		t.Errorf("-retire on a server that never exported: %v", err)
	}
	for _, mk := range marks {
		if err := os.Rename(mk+".aside", mk); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := run("export", "-retire", "-yes"); err != nil || len(shared.ClusterKeyFiles(stateB)) != 0 {
		t.Fatalf("-retire on a later server: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(stateB, "retired-"+stamp, filepath.Base(keys[0]))); err != nil {
		t.Errorf("siem-b's cluster key is not in the retired folder: %v", err)
	}

	// The files go where README.txt says, as on a downgrade, and this
	// server's configuration reads them back.
	t.Setenv("SIGNALITH_STATE_DIR", stateA)
	for _, d := range []string{lookups, rules, boards} {
		if err := os.RemoveAll(d); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range readManifest(t, out2).Files {
		copyTo(t, filepath.Join(out2, filepath.FromSlash(f.Path)), f.Dest)
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	secrets.SetDefault(c.Keyring())
	recs, _, err := users.ReadFile(c.UsersFile())
	if err != nil || recs["jlee"].Hash != hash || recs["jlee"].Role != users.Analyst {
		t.Errorf("users read back: %+v %v", recs, err)
	}
	set, err := (&intel.FileList{Path: c.IntelFeedsFile()}).Load()
	if err != nil || len(set.UI) != 1 || set.UI[0].Password != "feed-pass" || set.UI[0].Username != "u" {
		t.Errorf("feeds read back: %+v %v", set, err)
	}
	saved, err := retention.NewStore(filepath.Join(c.LookupsDir(), "retention.yaml")).Get()
	if err != nil || saved.Policies[retention.Findings].KeepDays != 45 {
		t.Errorf("retention read back: %+v %v", saved, err)
	}
	if got, err := os.ReadFile(filepath.Join(c.DetectionsDir(), "my-rule.yaml")); err != nil || !sameLines(got, ruleYAML) {
		t.Errorf("detection read back: %v\n%s", err, got)
	}

	// The previous version founds a new cluster from them.
	out, err = run("found", "-name", "Again")
	if err != nil || !strings.Contains(out, `Founded cluster "Again"`) {
		t.Fatalf("found from the files: %v\n%s", err, out)
	}
	out, err = run("export")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"jlee", "mine.example.com", "my-rule", "keep_days: 45"} {
		if !strings.Contains(out, want) {
			t.Errorf("the new cluster lacks %s:\n%s", want, out)
		}
	}
}

func readManifest(t *testing.T, dir string) exportManifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m exportManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func copyTo(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeDocs lists the ids of the documents of index on the fake.
func fakeDocs(t *testing.T, fake *ostest.Server, index string) []string {
	t.Helper()
	cl := newStore(&config.Config{OpenSearch: config.OpenSearch{URL: fake.URL}})
	docs, err := cl.SearchDocs(t.Context(), index, map[string]any{"match_all": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(docs))
	for _, d := range docs {
		ids = append(ids, d.ID)
	}
	return ids
}

// sameLines compares two texts whatever their line ends.
func sameLines(a, b []byte) bool {
	return bytes.Equal(bytes.ReplaceAll(a, []byte("\r\n"), []byte("\n")), bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
}

// The cluster's certificate authority is written as the tls folder of a
// server on its own keeps it, which tlsauto reads back.
func TestTLSExporter(t *testing.T) {
	fake := ostest.New(t)
	cl := newStore(&config.Config{OpenSearch: config.OpenSearch{URL: fake.URL}})
	ctx := t.Context()
	if err := shared.EnsureConfig(ctx, cl, "tx"); err != nil {
		t.Fatal(err)
	}
	key, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	h := shared.NewHub(shared.Options{NodeName: "siem-a"})
	h.SetKeys(shared.NewKeySet(key))
	h.Use(cl, "tx")
	d := newSharedDocs(clusterauth.NewDocs())
	d.tls.tls.Track(h)
	if err := h.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", state)
	c := config.Default()
	files := clustercfg.Files{Config: func() *config.Config { return c }, Node: "siem-a", NodeID: "n_a"}
	root := t.TempDir()
	target := shared.ExportTarget{Under: func(p string) string {
		rel, err := filepath.Rel(state, p)
		if err != nil || !filepath.IsLocal(rel) {
			t.Fatalf("%s is not in the state folder %s", p, state)
		}
		return filepath.Join(root, rel)
	}}
	// None published: nothing written.
	if list, err := tlsExporter(d, files).Run(ctx, target); err != nil || len(list) != 0 {
		t.Fatalf("with no certificate authority: %+v %v", list, err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Signalith CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.tls.tls.Publish(ctx, "admin", "siem-a", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), caKey, nil); err != nil {
		t.Fatal(err)
	}
	list, err := tlsExporter(d, files).Run(ctx, target)
	if err != nil || len(list) != 2 || list[0].Dest != filepath.Join(c.TLSDir(), "ca.pem") || !list[1].Secret {
		t.Fatalf("written %+v %v", list, err)
	}
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(list[1].Path); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("ca.key: %v %v", st, err)
		}
	}
	cert, signer, _ := tlsauto.LocalFiles(filepath.Dir(list[0].Path))
	if cert == nil || !bytes.Equal(cert.Raw, der) || signer == nil || !caKey.Public().(*ecdsa.PublicKey).Equal(signer.Public()) {
		t.Fatalf("read back %v %v", cert, signer)
	}
}

// README.txt gives the commands of the platform the export ran on only.
func TestExportReadmePlatforms(t *testing.T) {
	m := &exportManifest{Server: "siem-a", NodeID: "n_a", Version: "1.6.0", ClusterID: "c1",
		Folders: []manifestFolder{{Path: "state", Dest: "/var/lib/signalith"}, {Path: "config", Dest: "/etc/signalith"}},
		Files: []manifestFile{{Name: "users", Path: "state/lookups/users.json", Dest: "/var/lib/signalith/lookups/users.json", Secret: true},
			{Name: "settings", Path: "config/settings.yaml", Dest: "/etc/signalith/settings.yaml"}}}
	for platform, want := range map[string][]string{
		"linux":   {"sudo install -D -o signalith -g signalith -m 0600", "/etc/signalith/settings.yaml\"", "sudo signalith cluster export"},
		"windows": {"Copy-Item", "signalith.exe"},
		"docker":  {"run --rm --entrypoint cp signalith", "not in the signalith-data volume", "--user 0 --entrypoint chown", "docker-compose.server.yml"},
	} {
		got := exportReadme(m, "/var/lib/signalith/export", readmeEnv{platform: platform, state: "/var/lib/signalith"})
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: no %q in\n%s", platform, w, got)
			}
		}
		for other, words := range map[string]string{"linux": "sudo install", "windows": "Copy-Item", "docker": "docker compose"} {
			if other != platform && strings.Contains(got, words) {
				t.Errorf("%s: %q of %s in\n%s", platform, words, other, got)
			}
		}
		if strings.Contains(got, "chown -R signalith") {
			t.Errorf("%s: a whole folder changes owner:\n%s", platform, got)
		}
	}
}
