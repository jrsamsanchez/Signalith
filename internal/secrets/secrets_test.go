// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// keyring returns a keyring for dir that ignores this process's
// environment, with env as its environment instead.
func keyring(dir string, env map[string]string) *Keyring {
	k := NewKeyring(dir)
	k.getenv = func(name string) string { return env[name] }
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	k := keyring(dir, nil)
	var made []Source
	k.OnCreate = func(s Source) { made = append(made, s) }
	sealed, err := k.Seal("opensearch.password", "S3cr3t pass")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^enc:v1:[0-9a-f]{8}:[A-Za-z0-9_-]+$`).MatchString(sealed) || strings.Contains(sealed, "S3cr3t") {
		t.Fatalf("sealed = %q", sealed)
	}
	if again, _ := k.Seal("opensearch.password", "S3cr3t pass"); again == sealed {
		t.Error("two seals of one value should differ (random nonce)")
	}
	if got, err := k.Open("opensearch.password", sealed); err != nil || got != "S3cr3t pass" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if len(made) != 1 || !made[0].Created || made[0].Kind != FromDefault || made[0].Path != filepath.Join(dir, "keys", defaultName) {
		t.Fatalf("OnCreate got %+v", made)
	}
	if KeyID(sealed) != made[0].KeyID {
		t.Errorf("value key id %s, key %s", KeyID(sealed), made[0].KeyID)
	}
	// Plain and empty values pass through.
	if got, err := k.Open("x", "plain text"); err != nil || got != "plain text" {
		t.Errorf("plain Open = %q, %v", got, err)
	}
	if got, err := k.Seal("x", ""); err != nil || got != "" {
		t.Errorf("empty Seal = %q, %v", got, err)
	}
	if got, err := k.Seal("x", sealed); err != nil || got != sealed {
		t.Errorf("sealing a sealed value should keep it: %q, %v", got, err)
	}
	// A second keyring finds the same key and does not make another.
	k2 := keyring(dir, nil)
	k2.OnCreate = func(Source) { t.Error("a second key was made") }
	if got, err := k2.Open("opensearch.password", sealed); err != nil || got != "S3cr3t pass" {
		t.Fatalf("second keyring Open = %q, %v", got, err)
	}
	src, err := k2.Source()
	if err != nil || src.Created || src.KeyID != made[0].KeyID {
		t.Errorf("Source = %+v, %v", src, err)
	}
}

func TestDefaultKeyFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses an access list; see the Windows tests")
	}
	dir := t.TempDir()
	k := keyring(dir, nil)
	if _, err := k.Seal("a", "b"); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "keys", "master.key")
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %v, want 0600", st.Mode().Perm())
	}
	dst, err := os.Stat(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	if dst.Mode().Perm() != 0o700 {
		t.Errorf("keys folder mode %v, want 0700", dst.Mode().Perm())
	}
	data, _ := os.ReadFile(p)
	if !bytes.HasPrefix(data, []byte("# Signalith master key")) {
		t.Errorf("key file should explain itself:\n%s", data)
	}
	raw, err := parseKey(data)
	if err != nil || len(raw) != 32 {
		t.Fatalf("parseKey = %d bytes, %v", len(raw), err)
	}
}

func TestFieldsCannotBeSwapped(t *testing.T) {
	k := keyring(t.TempDir(), nil)
	sealed, err := k.Seal("opensearch.password", "pw")
	if err != nil {
		t.Fatal(err)
	}
	_, err = k.Open("assistant.api_key", sealed)
	var oe *OpenError
	if !errors.As(err, &oe) || oe.Field != "assistant.api_key" || oe.Reason == "" {
		t.Fatalf("Open with another field: %v", err)
	}
	if !strings.Contains(err.Error(), "assistant.api_key cannot be decrypted") || !strings.Contains(err.Error(), "copied from another setting") {
		t.Errorf("error = %v", err)
	}
	// A changed byte fails the same way.
	b := []byte(sealed)
	b[len(b)-3] ^= 1
	if b[len(b)-3] == '-' || b[len(b)-3] == '_' {
		b[len(b)-3] = 'A'
	}
	if _, err := k.Open("opensearch.password", string(b)); err == nil {
		t.Error("a changed value was accepted")
	}
	for _, bad := range []string{"enc:v1:zz", "enc:v1:0011aabb:!!!", "enc:v2:0011aabb:AAAA"} {
		if st, err := k.Check("f", bad); st != Unreadable || err == nil {
			t.Errorf("Check(%q) = %v, %v", bad, st, err)
		}
	}
}

func TestWrongMasterKeyNamesTheField(t *testing.T) {
	a := keyring(t.TempDir(), nil)
	b := keyring(t.TempDir(), nil)
	sealed, err := a.Seal("intel.feeds[otx].headers.X-OTX-API-KEY", "k")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Seal("other", "v"); err != nil {
		t.Fatal(err)
	}
	_, err = b.Open("intel.feeds[otx].headers.X-OTX-API-KEY", sealed)
	var oe *OpenError
	if !errors.As(err, &oe) {
		t.Fatalf("err = %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"intel.feeds[otx].headers.X-OTX-API-KEY", "master key " + a.KeyID(), b.KeyID(), "never events"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q lacks %q", msg, want)
		}
	}
	// With no key at all, the error says so.
	none := keyring(t.TempDir(), nil)
	_, err = none.Open("opensearch.password", sealed)
	if !errors.As(err, &oe) || !strings.Contains(err.Error(), "no master key was found") {
		t.Errorf("no key: %v", err)
	}
	// A keyring without folders cannot make a key.
	if _, err := keyring("", nil).Seal("x", "y"); !errors.Is(err, ErrNoKey) {
		t.Errorf("Seal without folders: %v", err)
	}
}

func TestKeySourcesInOrder(t *testing.T) {
	keyBytes := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	idOf := func(raw []byte) string {
		m, err := newMasterKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		return m.id
	}
	dir := t.TempDir()
	creds := t.TempDir()
	keyFile := filepath.Join(t.TempDir(), "signalith.key")
	// The default file (written as Signalith writes it).
	defData, err := encodeDefault(keyBytes(1))
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(dir, "keys"), 0o700)
	os.WriteFile(filepath.Join(dir, "keys", defaultName), defData, 0o600)
	// A key file as raw bytes, and a credential as base64 text.
	os.WriteFile(keyFile, keyBytes(2), 0o600)
	os.WriteFile(filepath.Join(creds, "master.key"), []byte(base64.StdEncoding.EncodeToString(keyBytes(3))+"\n"), 0o600)
	envKey := base64.StdEncoding.EncodeToString(keyBytes(4))

	for _, tc := range []struct {
		env  map[string]string
		kind string
		id   string
	}{
		{map[string]string{"CREDENTIALS_DIRECTORY": creds, "SIGNALITH_MASTER_KEY_FILE": keyFile, "SIGNALITH_MASTER_KEY": envKey}, FromCredential, idOf(keyBytes(3))},
		{map[string]string{"CREDENTIALS_DIRECTORY": t.TempDir(), "SIGNALITH_MASTER_KEY_FILE": keyFile, "SIGNALITH_MASTER_KEY": envKey}, FromKeyFile, idOf(keyBytes(2))},
		{map[string]string{"SIGNALITH_MASTER_KEY": envKey}, FromEnv, idOf(keyBytes(4))},
		{nil, FromDefault, idOf(keyBytes(1))},
	} {
		k := keyring(dir, tc.env)
		src, err := k.Source()
		if err != nil || src.Kind != tc.kind || src.KeyID != tc.id {
			t.Errorf("env %v: source %+v, %v; want %s %s", tc.env, src, err, tc.kind, tc.id)
		}
		if src.Weak() != (tc.kind == FromEnv) {
			t.Errorf("%s: Weak = %v", tc.kind, src.Weak())
		}
		if !strings.Contains(src.String(), map[string]string{FromCredential: "systemd credential", FromKeyFile: "SIGNALITH_MASTER_KEY_FILE",
			FromEnv: "SIGNALITH_MASTER_KEY environment variable", FromDefault: defaultName}[tc.kind]) {
			t.Errorf("%s: String = %q", tc.kind, src)
		}
	}
	// A key file that is named but missing, or not a key, is an error,
	// not a reason to make a new key somewhere else.
	k := keyring(dir, map[string]string{"SIGNALITH_MASTER_KEY_FILE": filepath.Join(dir, "missing")})
	if _, err := k.Seal("a", "b"); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing key file: %v", err)
	}
	os.WriteFile(keyFile, []byte("short"), 0o600)
	k = keyring(dir, map[string]string{"SIGNALITH_MASTER_KEY_FILE": keyFile})
	if _, err := k.Source(); err == nil || !strings.Contains(err.Error(), "openssl rand -base64 32") {
		t.Errorf("bad key file: %v", err)
	}
	k = keyring(dir, map[string]string{"SIGNALITH_MASTER_KEY": "not base64!"})
	if _, err := k.Source(); err == nil || !strings.Contains(err.Error(), "SIGNALITH_MASTER_KEY") {
		t.Errorf("bad env key: %v", err)
	}
}

func TestFallbackFolders(t *testing.T) {
	state, confDir := t.TempDir(), t.TempDir()
	// A key made next to signalith.yaml (by init, before the service had a
	// state folder) is found from the state folder's keyring.
	first := keyring(confDir, nil)
	sealed, err := first.Seal("f", "v")
	if err != nil {
		t.Fatal(err)
	}
	k := keyring(state, nil)
	k.dirs = append(k.dirs, confDir)
	if got, err := k.Open("f", sealed); err != nil || got != "v" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if k.DefaultPath() != filepath.Join(state, "keys", defaultName) {
		t.Errorf("DefaultPath = %s", k.DefaultPath())
	}
	if u := k.Unused(); len(u) != 0 {
		t.Errorf("Unused = %v", u)
	}
	// A second key file is reported as unused.
	if _, err := keyring(state, nil).Seal("x", "y"); err != nil {
		t.Fatal(err)
	}
	k2 := keyring(state, nil)
	k2.dirs = append(k2.dirs, confDir)
	if u := k2.Unused(); len(u) != 1 || u[0] != filepath.Join(confDir, "keys", defaultName) {
		t.Errorf("Unused = %v", u)
	}
}

func TestParseKey(t *testing.T) {
	raw := bytes.Repeat([]byte{7}, 32)
	for _, in := range [][]byte{
		raw,
		[]byte(base64.StdEncoding.EncodeToString(raw)),
		[]byte("# comment\n\n" + base64.RawURLEncoding.EncodeToString(raw) + "\r\n"),
		[]byte(hex.EncodeToString(raw) + "\n"),
		keyText(raw),
	} {
		got, err := parseKey(in)
		if err != nil || !bytes.Equal(got, raw) {
			t.Errorf("parseKey(%q) = %x, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "abc", base64.StdEncoding.EncodeToString(raw[:16]), "a\nb"} {
		if _, err := parseKey([]byte(bad)); err == nil {
			t.Errorf("parseKey(%q) accepted", bad)
		}
	}
}

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	k := keyring(dir, nil)
	before, err := k.Seal("f", "old secret")
	if err != nil {
		t.Fatal(err)
	}
	oldID := k.KeyID()
	path := filepath.Join(dir, "keys", defaultName)
	oldFile, _ := os.ReadFile(path)

	// Discard changes nothing.
	r, err := k.BeginRotation()
	if err != nil {
		t.Fatal(err)
	}
	r.Discard()
	if now, _ := os.ReadFile(path); !bytes.Equal(now, oldFile) || k.KeyID() != oldID {
		t.Fatal("Discard changed the key")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "keys", ".*")); len(left) != 0 {
		t.Errorf("Discard left %v", left)
	}

	// Undo after Commit puts the old key back and removes .old.
	r, err = k.BeginRotation()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Commit(); err != nil {
		t.Fatal(err)
	}
	if k.KeyID() == oldID {
		t.Fatal("Commit did not change the key")
	}
	if err := r.Undo(); err != nil {
		t.Fatal(err)
	}
	if now, _ := os.ReadFile(path); !bytes.Equal(now, oldFile) || k.KeyID() != oldID {
		t.Fatal("Undo did not put the old key back")
	}
	if _, err := os.Stat(path + ".old"); !os.IsNotExist(err) {
		t.Errorf(".old after Undo: %v", err)
	}

	// A running server's keyring notices the new key by itself.
	server := keyring(dir, nil)
	if _, err := server.Open("f", before); err != nil {
		t.Fatal(err)
	}
	r, err = k.BeginRotation()
	if err != nil {
		t.Fatal(err)
	}
	after, err := r.Seal("f", "old secret")
	if err != nil || KeyID(after) != r.KeyID() || r.KeyID() == oldID {
		t.Fatalf("Rotation.Seal = %q, %v", after, err)
	}
	if err := r.Commit(); err != nil {
		t.Fatal(err)
	}
	r.Done()
	if k.KeyID() != r.KeyID() {
		t.Errorf("key id after commit %s, want %s", k.KeyID(), r.KeyID())
	}
	if kept, _ := os.ReadFile(path + ".old"); !bytes.Equal(kept, oldFile) {
		t.Error("the previous key was not kept as .old")
	}
	src, _ := k.Source()
	if src.OldKeyID != oldID || src.OldPath != path+".old" {
		t.Errorf("source after rotation %+v", src)
	}
	for _, kr := range []*Keyring{k, server} {
		if st, err := kr.Check("f", before); st != Previous || err != nil {
			t.Errorf("old value: %v, %v", st, err)
		}
		if st, err := kr.Check("f", after); st != Current || err != nil {
			t.Errorf("new value: %v, %v", st, err)
		}
	}
	if s, err := server.Seal("g", "new"); err != nil || KeyID(s) != r.KeyID() {
		t.Errorf("the server still seals with %s", KeyID(s))
	}
	// A second rotation waits for the first to be pruned.
	if _, err := k.BeginRotation(); err == nil || !strings.Contains(err.Error(), "-prune") {
		t.Errorf("second rotation: %v", err)
	}
	removed, err := k.RemoveOld()
	if err != nil || removed != path+".old" {
		t.Fatalf("RemoveOld = %q, %v", removed, err)
	}
	if st, _ := server.Check("f", before); st != Unreadable {
		t.Errorf("old value after prune: %v", st)
	}
	if removed, err := k.RemoveOld(); err != nil || removed != "" {
		t.Errorf("second RemoveOld = %q, %v", removed, err)
	}
}

func TestRotationNeedsAFile(t *testing.T) {
	env := map[string]string{"SIGNALITH_MASTER_KEY": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))}
	if _, err := keyring(t.TempDir(), env).BeginRotation(); err == nil || !strings.Contains(err.Error(), "SIGNALITH_MASTER_KEY_FILE") {
		t.Errorf("env key: %v", err)
	}
	if _, err := keyring(t.TempDir(), nil).BeginRotation(); err == nil || !strings.Contains(err.Error(), "no master key yet") {
		t.Errorf("no key: %v", err)
	}
	// A key file named by SIGNALITH_MASTER_KEY_FILE rotates in place.
	f := filepath.Join(t.TempDir(), "mk")
	os.WriteFile(f, bytes.Repeat([]byte{5}, 32), 0o600)
	k := keyring(t.TempDir(), map[string]string{"SIGNALITH_MASTER_KEY_FILE": f})
	r, err := k.BeginRotation()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Commit(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(f); !bytes.HasPrefix(data, []byte("# Signalith master key")) {
		t.Errorf("rotated key file:\n%s", data)
	}
	if _, err := os.Stat(f + ".old"); err != nil {
		t.Error(err)
	}
}

func TestSecretRedaction(t *testing.T) {
	s := New("opensearch.password", "hunter2-secret")
	type holder struct {
		Name     string
		Password Secret
	}
	h := holder{"x", s}
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	log.Info("connect", "password", s, "holder", h)
	jlog := slog.New(slog.NewJSONHandler(&buf, nil))
	jlog.Info("connect", "password", s)
	js, _ := json.Marshal(h)
	outs := []string{
		fmt.Sprint(s), fmt.Sprintf("%v %s %q %+v %#v", s, s, s, h, h), string(js), buf.String(), s.String(),
	}
	for _, o := range outs {
		if strings.Contains(o, "hunter2") {
			t.Errorf("secret leaked: %s", o)
		}
		if !strings.Contains(o, Redacted) {
			t.Errorf("no %s in %s", Redacted, o)
		}
	}
	if s.Reveal() != "hunter2-secret" || !s.IsSet() || s.Encrypted() {
		t.Errorf("Reveal/IsSet/Encrypted wrong")
	}
	if (Secret{}).IsSet() {
		t.Error("zero Secret is set")
	}
}

func TestSecretYAML(t *testing.T) {
	k := keyring(t.TempDir(), nil)
	SetDefault(k)
	defer SetDefault(NewKeyring())
	type file struct {
		Password Secret `yaml:"password"`
		Key      Secret `yaml:"key"`
	}
	sealed, err := Seal("key", "api-key-1")
	if err != nil {
		t.Fatal(err)
	}
	var f file
	if err := yaml.Unmarshal([]byte("password: plain-pw\nkey: "+sealed+"\n"), &f); err != nil {
		t.Fatal(err)
	}
	if f.Password.Reveal() != "plain-pw" || f.Password.Encrypted() {
		t.Errorf("plain value: %q", f.Password.Reveal())
	}
	if !f.Key.Encrypted() || f.Key.Reveal() != "" {
		t.Error("an encrypted value is not revealed before Open")
	}
	if err := f.Password.Open("password"); err != nil {
		t.Fatal(err)
	}
	if err := f.Key.Open("key"); err != nil || f.Key.Reveal() != "api-key-1" {
		t.Fatalf("Open = %q, %v", f.Key.Reveal(), err)
	}
	out, err := yaml.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "plain-pw") || strings.Contains(string(out), "api-key-1") || strings.Count(string(out), "enc:v1:") != 2 {
		t.Fatalf("written:\n%s", out)
	}
	var back file
	yaml.Unmarshal(out, &back)
	back.Password.Open("password")
	back.Key.Open("key")
	if back.Password.Reveal() != "plain-pw" || back.Key.Reveal() != "api-key-1" {
		t.Errorf("round trip: %q %q", back.Password.Reveal(), back.Key.Reveal())
	}
	// A value that cannot be decrypted is written back as it was.
	other := keyring(t.TempDir(), nil)
	foreign, _ := other.Seal("key", "x")
	var g file
	yaml.Unmarshal([]byte("key: "+foreign+"\n"), &g)
	if err := g.Key.Open("key"); err == nil {
		t.Fatal("foreign value opened")
	}
	out, _ = yaml.Marshal(g)
	if !strings.Contains(string(out), foreign) {
		t.Errorf("foreign value not kept:\n%s", out)
	}
	// A Secret without a setting name refuses to be written.
	if _, err := yaml.Marshal(file{Password: Secret{plain: "x"}}); err == nil {
		t.Error("a Secret without a field was written")
	}
}

func TestPackageDefault(t *testing.T) {
	SetDefault(NewKeyring())
	if _, err := Seal("x", "y"); !errors.Is(err, ErrNoKey) {
		t.Errorf("default keyring without folders: %v", err)
	}
	k := keyring(t.TempDir(), nil)
	SetDefault(k)
	defer SetDefault(NewKeyring())
	s, err := Seal("x", "y")
	if err != nil {
		t.Fatal(err)
	}
	if v, err := Open("x", s); err != nil || v != "y" || Default() != k {
		t.Errorf("Open = %q, %v", v, err)
	}
}

// A password that happens to start with enc: is still a password: it is
// encrypted, not stored as it is.
func TestPlainValuesStartingWithEnc(t *testing.T) {
	k := keyring(t.TempDir(), nil)
	for _, pw := range []string{"enc:", "enc:hunter2", "enc:V1:x", "encrypted!"} {
		if IsSealed(pw) {
			t.Errorf("IsSealed(%q)", pw)
		}
		sealed, err := k.Seal("directory.bind_password", pw)
		if err != nil || sealed == pw || !IsSealed(sealed) {
			t.Errorf("Seal(%q) = %q, %v", pw, sealed, err)
			continue
		}
		if got, err := k.Open("directory.bind_password", sealed); err != nil || got != pw {
			t.Errorf("Open = %q, %v; want %q", got, err, pw)
		}
	}
	for _, v := range []string{"enc:v1:0011aabb:AAAA", "enc:v2:anything"} {
		if !IsSealed(v) {
			t.Errorf("IsSealed(%q) = false", v)
		}
	}
}

// A value that does not decrypt with the key that made it was changed or
// moved; the key is fine, so the error does not ask for another one.
func TestChangedValueDoesNotBlameTheKey(t *testing.T) {
	k := keyring(t.TempDir(), nil)
	sealed, _ := k.Seal("opensearch.password", "pw")
	_, err := k.Open("assistant.api_key", sealed)
	if err == nil || strings.Contains(err.Error(), "Restore the master key") || !strings.Contains(err.Error(), "Enter the value again") {
		t.Errorf("error = %v", err)
	}
}

// A key file that is there but cannot be read is an error, not a missing
// key, so no second key is made beside it.
func TestUnreadableKeyIsNotMissing(t *testing.T) {
	// A file where the keys folder should be: the key path cannot be
	// looked at (not a folder).
	blocked := t.TempDir()
	os.WriteFile(filepath.Join(blocked, "keys"), []byte("x"), 0o600)
	k := keyring(blocked, nil)
	if _, err := k.Seal("a", "b"); err == nil || errors.Is(err, ErrNoKey) || !strings.Contains(err.Error(), "cannot read the master key") {
		t.Errorf("Seal with an unreadable key path: %v", err)
	}
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		return // permissions do not stop root, and Windows uses access lists
	}
	dir := t.TempDir()
	first := keyring(dir, nil)
	if _, err := first.Seal("a", "b"); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(dir, "keys")
	os.Chmod(keys, 0)
	defer os.Chmod(keys, 0o700)
	k = keyring(dir, nil)
	_, err := k.Seal("c", "d")
	if err == nil || errors.Is(err, ErrNoKey) || !strings.Contains(err.Error(), "permission denied") || !strings.Contains(err.Error(), "chown") {
		t.Errorf("Seal with a key it may not read: %v", err)
	}
	if u := k.Unused(); len(u) != 1 {
		t.Errorf("Unused = %v; the unreadable key is still a key", u)
	}
}

// A folder added with LookAlsoIn is used when it holds a key, never gets
// a new one, and is passed over when this account may not look into it
// (another install's state folder).
func TestLookAlsoIn(t *testing.T) {
	own, other := t.TempDir(), t.TempDir()
	theirs := keyring(other, nil)
	if _, err := theirs.Seal("a", "b"); err != nil {
		t.Fatal(err)
	}
	k := keyring(own, nil)
	k.LookAlsoIn(other)
	if src, err := k.Source(); err != nil || src.Path != filepath.Join(other, "keys", defaultName) {
		t.Errorf("Source = %+v, %v; want the key in the other folder", src, err)
	}

	empty := t.TempDir()
	k = keyring(own, nil)
	k.LookAlsoIn(empty)
	if _, err := k.Seal("a", "b"); err != nil {
		t.Fatal(err)
	}
	if src, _ := k.Source(); src.Path != filepath.Join(own, "keys", defaultName) {
		t.Errorf("new key made in %s, want the first folder", src.Path)
	}
	if _, err := os.Stat(filepath.Join(empty, "keys")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a key folder was made in the also folder: %v", err)
	}

	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		return // permissions do not stop root, and Windows uses access lists
	}
	os.Chmod(other, 0)
	defer os.Chmod(other, 0o700)
	fresh := t.TempDir()
	k = keyring(fresh, nil)
	k.LookAlsoIn(other)
	if _, err := k.Seal("a", "b"); err != nil {
		t.Errorf("Seal with another install's folder closed to this account: %v", err)
	}
	if u := k.Unused(); len(u) != 0 {
		t.Errorf("Unused = %v; a folder that cannot be looked into is not a key", u)
	}
	// The same folder as one of this config's own is not passed over.
	k = keyring(other, nil)
	k.LookAlsoIn(other)
	if _, err := k.Source(); err == nil || errors.Is(err, ErrNoKey) {
		t.Errorf("Source with its own folder closed: %v; want a permission error", err)
	}
}

// 32 characters of text are a typed passphrase, not a random key.
func TestTypedKeysAreRefused(t *testing.T) {
	typed := "ChangeMeChangeMeChangeMeChangeMe"
	if _, err := parseKey([]byte(typed)); !errors.Is(err, errTypedKey) {
		t.Errorf("parseKey(typed) = %v", err)
	}
	if _, err := parseKey([]byte("correct horse battery staple 12\n")); err == nil {
		t.Error("a 31-character passphrase and a newline was accepted")
	}
	k := keyring(t.TempDir(), map[string]string{"SIGNALITH_MASTER_KEY": typed})
	if _, err := k.Source(); err == nil || !strings.Contains(err.Error(), "openssl rand -base64 32") {
		t.Errorf("typed SIGNALITH_MASTER_KEY: %v", err)
	}
	// Random bytes are still read as they are, from a file.
	raw := bytes.Repeat([]byte{0x80, 0x01}, 16)
	if got, err := parseKey(raw); err != nil || !bytes.Equal(got, raw) {
		t.Errorf("parseKey(raw bytes) = %x, %v", got, err)
	}
	// SIGNALITH_MASTER_KEY is base64 or hex only.
	if _, err := parseKeyText(raw); err == nil {
		t.Error("raw bytes accepted as text")
	}
}

// A key file other accounts can read is reported, and rotating it makes
// the new key private.
func TestKeyFilePermissionWarning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not apply on Windows")
	}
	dir := t.TempDir()
	k := keyring(dir, nil)
	if _, err := k.Seal("a", "b"); err != nil {
		t.Fatal(err)
	}
	if src, _ := k.Source(); src.Warning != "" {
		t.Errorf("a new key is private, but: %s", src.Warning)
	}
	p := filepath.Join(dir, "keys", defaultName)
	os.Chmod(p, 0o644)
	k = keyring(dir, nil)
	src, err := k.Source()
	if err != nil || !strings.Contains(src.Warning, "chmod 600") {
		t.Fatalf("Source = %+v, %v", src, err)
	}
	r, err := k.BeginRotation()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Commit(); err != nil {
		t.Fatal(err)
	}
	r.Done()
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("rotated key mode %v, want 0600", st.Mode().Perm())
	}
	if st, _ := os.Stat(p + ".old"); st.Mode().Perm() != 0o600 {
		t.Errorf("previous key mode %v, want 0600", st.Mode().Perm())
	}
}

// BeginNew makes the first key only when it is committed, and leaves
// nothing behind otherwise.
func TestBeginNew(t *testing.T) {
	dir := t.TempDir()
	k := keyring(dir, nil)
	r, err := k.BeginNew()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := r.Seal("opensearch.password", "pw")
	if err != nil || KeyID(sealed) != r.KeyID() {
		t.Fatalf("Seal = %q, %v", sealed, err)
	}
	r.Discard()
	if _, err := os.Stat(filepath.Join(dir, "keys")); !os.IsNotExist(err) {
		t.Errorf("Discard left the keys folder: %v", err)
	}
	if _, err := k.Source(); !errors.Is(err, ErrNoKey) {
		t.Errorf("a key after Discard: %v", err)
	}

	r, _ = k.BeginNew()
	sealed, _ = r.Seal("opensearch.password", "pw")
	if err := r.Commit(); err != nil {
		t.Fatal(err)
	}
	if got, err := k.Open("opensearch.password", sealed); err != nil || got != "pw" {
		t.Errorf("Open after Commit = %q, %v", got, err)
	}
	if _, err := k.BeginNew(); err == nil {
		t.Error("BeginNew with a key already there")
	}
	if err := r.Undo(); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Source(); !errors.Is(err, ErrNoKey) {
		t.Errorf("a key after Undo: %v", err)
	}

	// Someone else making a key meanwhile wins; Commit says so.
	r, _ = k.BeginNew()
	if _, err := keyring(dir, nil).Seal("x", "y"); err != nil {
		t.Fatal(err)
	}
	if err := r.Commit(); err == nil || !strings.Contains(err.Error(), "meanwhile") {
		t.Errorf("Commit after another key was made: %v", err)
	}
}
