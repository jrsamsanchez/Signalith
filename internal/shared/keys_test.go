package shared

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

func TestClusterKey(t *testing.T) {
	k, err := NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(k.ID()) {
		t.Errorf("id %q", k.ID())
	}
	// Each use has its own key.
	subs := [][]byte{k.MACKey(), k.CookieKey(), k.ArchiveKey(), k.KnownBrowserKey()}
	for i := range subs {
		for j := range i {
			if bytes.Equal(subs[i], subs[j]) {
				t.Errorf("sub-keys %d and %d are the same", i, j)
			}
		}
	}
	// Shared secrets look like the master key's, under the cluster key id.
	sealed, err := k.SecretsKey().Seal("intel.feeds[otx].headers.X-OTX-API-KEY@https://otx.example.com", "s3cret")
	if err != nil || !strings.HasPrefix(sealed, "enc:v1:"+k.ID()+":") {
		t.Fatalf("sealed %q %v", sealed, err)
	}
	if _, err := k.SecretsKey().Open("intel.feeds[otx].headers.X-OTX-API-KEY@https://evil.example.com", sealed); err == nil {
		t.Error("opened for another destination")
	}

	// The key file of SIGNALITH_CLUSTER_KEY_FILE.
	path := filepath.Join(t.TempDir(), "cluster.key")
	os.WriteFile(path, []byte("# made with openssl rand -base64 32\n"+k.Text()+"\n"), 0o600)
	k2, err := KeyFromFile(path)
	if err != nil || k2.ID() != k.ID() || !bytes.Equal(k2.MACKey(), k.MACKey()) {
		t.Fatalf("from file: %v", err)
	}
	if w := KeyFileWarning(path); w != "" {
		t.Errorf("private key file: %s", w)
	}
	if runtime.GOOS != "windows" {
		os.Chmod(path, 0o644)
		if w := KeyFileWarning(path); !strings.Contains(w, "The cluster key file "+path+" is not private") {
			t.Errorf("readable key file: %q", w)
		}
	}
	os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString([]byte("too short"))), 0o600)
	if _, err := KeyFromFile(path); err == nil {
		t.Error("short key accepted")
	}

	set := NewKeySet(k, k2)
	if set.Active() != k || set.Get(k.ID()) == nil || set.Get("00000000") != nil || len(set.IDs()) != 1 {
		t.Errorf("set %v", set.IDs())
	}
	var none *KeySet
	if none.Active() != nil || none.Get("x") != nil {
		t.Error("nil set")
	}
}

func TestSealToNode(t *testing.T) {
	n, err := NewNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^([0-9A-F]{4}-){7}[0-9A-F]{4}$`).MatchString(n.Fingerprint()) {
		t.Errorf("fingerprint %q", n.Fingerprint())
	}
	k, _ := NewClusterKey()
	sealed, err := SealToNode(n.Public(), "n_4f2a", k.ID(), []byte(k.Text()))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := n.OpenFromNode("n_4f2a", k.ID(), sealed)
	if err != nil || string(plain) != k.Text() {
		t.Fatalf("open: %v", err)
	}
	other, _ := NewNodeKey()
	for name, open := range map[string]func() ([]byte, error){
		"other node key": func() ([]byte, error) { return other.OpenFromNode("n_4f2a", k.ID(), sealed) },
		"other node id":  func() ([]byte, error) { return n.OpenFromNode("n_9a00", k.ID(), sealed) },
		"other kid":      func() ([]byte, error) { return n.OpenFromNode("n_4f2a", "00000000", sealed) },
		"changed": func() ([]byte, error) {
			return n.OpenFromNode("n_4f2a", k.ID(), sealed[:len(sealed)-4]+"AAAA")
		},
		"not sealed": func() ([]byte, error) { return n.OpenFromNode("n_4f2a", k.ID(), "hello") },
	} {
		if _, err := open(); !errors.Is(err, ErrNotForNode) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := SealToNode([]byte("short"), "n", "k", nil); err == nil {
		t.Error("sealed to a bad key")
	}
}

func TestKeyStore(t *testing.T) {
	state := t.TempDir()
	ks := KeyStore{Dir: state, Master: secrets.NewKeyring(state)}
	if _, err := ks.LoadNodeKey(); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("no node key: %v", err)
	}
	n, err := ks.NodeKey()
	if err != nil {
		t.Fatal(err)
	}
	n2, err := ks.NodeKey()
	if err != nil || !bytes.Equal(n2.Public(), n.Public()) {
		t.Fatalf("second NodeKey made another: %v", err)
	}
	raw, _ := os.ReadFile(NodeKeyPath(state))
	if !strings.Contains(string(raw), `"key": "enc:v1:`) || !strings.Contains(string(raw), n.PublicText()) {
		t.Errorf("node.key:\n%s", raw)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(NodeKeyPath(state)); st.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", st.Mode())
		}
	}

	if keys, err := ks.ClusterKeys(); len(keys) != 0 || err != nil {
		t.Errorf("no cluster keys: %v %v", keys, err)
	}
	k1, _ := NewClusterKey()
	k2, _ := NewClusterKey()
	for _, k := range []*ClusterKey{k1, k2} {
		if err := ks.SaveClusterKey(k); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := ks.ClusterKeys()
	if err != nil || len(keys) != 2 || len(ClusterKeyFiles(state)) != 2 {
		t.Fatalf("cluster keys %v %v", keys, err)
	}
	found := map[string]bool{}
	for _, k := range keys {
		found[k.ID()] = true
	}
	if !found[k1.ID()] || !found[k2.ID()] {
		t.Errorf("found %v", found)
	}
	raw, _ = os.ReadFile(ClusterKeyPath(state, k1.ID()))
	if strings.Contains(string(raw), k1.Text()) {
		t.Error("the cluster key is stored in clear")
	}

	// A file renamed to another key's name is refused: the field binds it.
	os.Rename(ClusterKeyPath(state, k2.ID()), ClusterKeyPath(state, "0000aaaa"))
	data, _ := os.ReadFile(ClusterKeyPath(state, "0000aaaa"))
	os.WriteFile(ClusterKeyPath(state, "0000aaaa"), []byte(strings.Replace(string(data), k2.ID(), "0000aaaa", 1)), 0o600)
	if _, err := ks.ClusterKeys(); err == nil {
		t.Error("a key under another id was accepted")
	}
	os.Remove(ClusterKeyPath(state, "0000aaaa"))

	// Another master key cannot open them.
	other := KeyStore{Dir: state, Master: secrets.NewKeyring(t.TempDir())}
	if _, err := other.LoadNodeKey(); err == nil {
		t.Error("node key opened with another master key")
	}
	if _, err := other.ClusterKeys(); err == nil {
		t.Error("cluster key opened with another master key")
	}

	// signalith secrets lists them by field.
	for path, reseal := range map[string]func([]byte, secrets.Reseal) ([]byte, int, error){
		NodeKeyPath(state):             ResealNodeKeyFile,
		ClusterKeyPath(state, k1.ID()): ResealClusterKeyFile,
	} {
		data, _ := os.ReadFile(path)
		var fields []string
		out, n, err := reseal(data, func(s secrets.Stored) (string, error) {
			fields = append(fields, s.Field)
			return s.Value, nil
		})
		if err != nil || n != 0 || !bytes.Equal(out, data) || len(fields) != 1 {
			t.Errorf("%s: %d %v %v", path, n, fields, err)
		}
		if path == NodeKeyPath(state) && fields[0] != "cluster.node_key" || path != NodeKeyPath(state) && fields[0] != "cluster.key/"+k1.ID() {
			t.Errorf("%s: fields %v", path, fields)
		}
	}
}

func TestExportImportKey(t *testing.T) {
	old := scryptN
	scryptN = 1 << 10
	defer func() { scryptN = old }()
	k, _ := NewClusterKey()
	text, err := ExportKey(k, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, k.Text()) || !strings.Contains(text, k.ID()) {
		t.Errorf("export:\n%s", text)
	}
	k2, err := ImportKey(text, []byte("correct horse battery staple"))
	if err != nil || k2.ID() != k.ID() {
		t.Fatalf("import: %v", err)
	}
	if _, err := ImportKey(text, []byte("wrong")); !errors.Is(err, ErrPassphrase) {
		t.Errorf("wrong passphrase: %v", err)
	}
	if _, err := ImportKey(strings.Replace(text, k.ID(), "0000aaaa", 1), []byte("correct horse battery staple")); !errors.Is(err, ErrPassphrase) {
		t.Errorf("changed kid: %v", err)
	}
	if _, err := ImportKey("not json", nil); err == nil {
		t.Error("garbage accepted")
	}
	// A cost read from the text that would take gigabytes is refused
	// before scrypt runs.
	for _, cost := range []string{`"n": 4194304`, `"r": 32`, `"p": 16`} {
		var f map[string]any
		_ = json.Unmarshal([]byte(text), &f)
		name, v, _ := strings.Cut(cost, ": ")
		f["kdf"].(map[string]any)[strings.Trim(name, `"`)], _ = strconv.Atoi(v)
		big, _ := json.Marshal(f)
		if _, err := ImportKey(string(big), []byte("correct horse battery staple")); err == nil || errors.Is(err, ErrPassphrase) {
			t.Errorf("%s: %v", cost, err)
		}
	}
	if _, err := ExportKey(k, nil); err == nil {
		t.Error("empty passphrase accepted")
	}
}

func TestSeenHash(t *testing.T) {
	k, _ := NewClusterKey()
	h1, _ := SeenHash(k, "retention.days", 90)
	h2, _ := SeenHash(k, "retention.days", 90)
	h3, _ := SeenHash(k, "retention.days", 30)
	h4, _ := SeenHash(k, "retention.guard", 90)
	other, _ := NewClusterKey()
	h5, _ := SeenHash(other, "retention.days", 90)
	if h1 != h2 || h1 == h3 || h1 == h4 || h1 == h5 || !strings.HasPrefix(h1, "h1:") {
		t.Errorf("%s %s %s %s %s", h1, h2, h3, h4, h5)
	}
	var n NodeCfg
	if n.Changed("retention.days", SourceYAML, h1, true) {
		t.Error("first start applies")
	}
	n.Record("retention.days", SourceYAML, h1)
	if n.Changed("retention.days", SourceYAML, h1, false) {
		t.Error("unchanged value applies")
	}
	if !n.Changed("retention.days", SourceYAML, h3, false) {
		t.Error("changed value does not apply")
	}
	if !n.Changed("retention.guard", SourceYAML, h4, false) {
		t.Error("a value set since the last start does not apply")
	}
	if n.Changed("retention.days", SourceEnv, h1, true) {
		t.Error("first start applies from the environment")
	}
	// After a new cluster key (reset-key, rotation) the old hashes cannot
	// be compared: values are recorded again, not applied.
	h6, _ := SeenHash(other, "retention.days", 30)
	if n.Changed("retention.days", SourceYAML, h5, false) || n.Changed("retention.days", SourceYAML, h6, false) {
		t.Error("a hash under another key applies")
	}
	if NodeCfgID("n_4f") != "nodecfg:n_4f" {
		t.Error(NodeCfgID("n_4f"))
	}
}

func TestEnvelopeCanonical(t *testing.T) {
	k, _ := NewClusterKey()
	set := NewKeySet(k)
	e := &Envelope{Kind: "user", ID: "user:jlee", Format: 1, Rev: 7, UpdatedAt: "2026-10-12T09:14:03Z",
		UpdatedBy: By{User: "sam", Node: "siem-a"}, Body: `{"role":"analyst"}`}
	if err := Sign(k, "user:jlee", e); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(e.MAC, "m1:"+k.ID()+":") || Verify(set, "user:jlee", e) != nil {
		t.Fatalf("mac %q", e.MAC)
	}
	e.WriteID = "w_anything"
	if err := Verify(set, "user:jlee", e); err != nil {
		t.Errorf("write_id is signed: %v", err)
	}
	// Each signed field counts, the _id too.
	for name, change := range map[string]func(*Envelope){
		"kind":       func(e *Envelope) { e.Kind = "admins" },
		"format":     func(e *Envelope) { e.Format = 2 },
		"rev":        func(e *Envelope) { e.Rev = 6 },
		"deleted":    func(e *Envelope) { e.Deleted = true },
		"updated_at": func(e *Envelope) { e.UpdatedAt = "2026-10-12T09:14:04Z" },
		"user":       func(e *Envelope) { e.UpdatedBy.User = "bob" },
		"node":       func(e *Envelope) { e.UpdatedBy.Node = "siem-b" },
		"body":       func(e *Envelope) { e.Body = `{"role":"admin"}` },
	} {
		c := *e
		change(&c)
		if err := Verify(set, "user:jlee", &c); !errors.Is(err, ErrBadMAC) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := Verify(set, "user:mallory", e); !errors.Is(err, ErrBadMAC) {
		t.Errorf("copied to another id: %v", err)
	}
	// A zero byte cannot move text from one field to the next.
	z := *e
	z.UpdatedBy.User = "sam\x00siem-a"
	if err := Sign(k, "user:jlee", &z); err == nil {
		t.Error("signed a field with a zero byte")
	}
	// Unknown fields are kept apart and written back.
	raw := []byte(`{"kind":"user","id":"user:jlee","format":1,"rev":7,"deleted":false,"updated_at":"x","updated_by":{"user":"a","node":"b"},"body":"{}","mac":"m1:x:y","shard_hint":3}`)
	var got Envelope
	if err := got.UnmarshalJSON(raw); err != nil || string(got.Extra["shard_hint"]) != "3" || len(got.Extra) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	out, _ := got.MarshalJSON()
	if !strings.Contains(string(out), `"shard_hint":3`) {
		t.Errorf("%s", out)
	}
}
