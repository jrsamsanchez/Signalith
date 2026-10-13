package respond

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

func httpAction(name string) Connector {
	return Connector{Name: name, Label: "Block IP", Kind: KindHTTP, Target: TargetIP, Method: "POST",
		URL: "https://fw.example.lan/api/alias/add", Body: `{"address": "{{.ip}}"}`,
		Headers: map[string]string{"X-Api-Key": "key-0123456789"}, Username: "apikey", Password: "api-secret-987"}
}

func TestFileSealsSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "response.yaml")
	a := &Actions{File: path}
	if err := a.Save([]Connector{httpAction("block-ip"), {Name: "off", Kind: KindDisableUser, BindDN: "CN=svc,DC=corp,DC=example,DC=com", BindPassword: "bind-pass-1234"}}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	for _, plain := range []string{"key-0123456789", "api-secret-987", "bind-pass-1234"} {
		if strings.Contains(string(data), plain) {
			t.Errorf("the file holds %q in plain text:\n%s", plain, data)
		}
	}
	if !strings.Contains(string(data), "X-Api-Key: enc:v") {
		t.Errorf("file:\n%s", data)
	}
	// A new reader decrypts them.
	b := &Actions{File: path}
	c, ok, err := b.Get("block-ip")
	if err != nil || !ok || c.Headers["X-Api-Key"] != "key-0123456789" || c.Password != "api-secret-987" {
		t.Fatalf("read back %+v %v %v", c, ok, err)
	}
	d, _, _ := b.Get("off")
	if d.BindPassword != "bind-pass-1234" {
		t.Errorf("bind password %q", d.BindPassword)
	}
	// Every secret is listed for signalith secrets and reseals with a new
	// key.
	var fields []string
	_, n, err := ResealFile(data, func(s secrets.Stored) (string, error) {
		fields = append(fields, s.Field)
		return s.Value, nil
	})
	if err != nil || n != 0 || strings.Join(fields, " ") != "response[block-ip].password response[block-ip].headers.X-Api-Key response[off].bind_password" {
		t.Errorf("fields %v n %d err %v", fields, n, err)
	}
	out, n, err := ResealFile(data, func(s secrets.Stored) (string, error) {
		plain, err := secrets.Open(s.Field, s.Value)
		if err != nil {
			return "", err
		}
		return "plain:" + plain, nil
	})
	if err != nil || n != 3 || !strings.Contains(string(out), "plain:key-0123456789") || !strings.HasPrefix(string(out), "# Response actions") {
		t.Errorf("resealed %d %v:\n%s", n, err, out)
	}
}

func TestFileUndecryptableSecretLocksAction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "response.yaml")
	a := &Actions{File: path}
	if err := a.Save([]Connector{httpAction("block-ip")}); err != nil {
		t.Fatal(err)
	}
	prev := secrets.Default()
	secrets.SetDefault(secrets.NewKeyring(t.TempDir()))
	defer secrets.SetDefault(prev)
	b := &Actions{File: path}
	if _, err := b.List(); err != nil {
		t.Fatal(err)
	}
	if l := b.Locked("block-ip"); len(l) != 2 {
		t.Errorf("locked %v", l)
	}
	r := &Runner{Actions: b, Store: &Memory{}}
	_, err := r.Run(t.Context(), Request{Action: "block-ip", Target: "203.0.113.7", Reason: "x", Actor: Actor{Name: "ann"}})
	if err == nil || !strings.Contains(err.Error(), "enters its") {
		t.Errorf("run with a locked secret: %v", err)
	}
}

func TestFileReadAgainWhenChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "response.yaml")
	a := &Actions{File: path}
	if l, err := a.List(); err != nil || len(l) != 0 {
		t.Fatalf("no file: %v %v", l, err)
	}
	if err := os.WriteFile(path, []byte("actions:\n  - name: iso\n    kind: script\n    target: host\n    program: iso.sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := a.List()
	if err != nil || len(l) != 1 || l[0].TimeoutSeconds != DefaultScriptTimeout || !l[0].IsDisruptive() {
		t.Fatalf("after a hand edit: %+v %v", l, err)
	}
	if err := os.WriteFile(path, []byte("actions: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.List(); err == nil {
		t.Error("a broken file reads")
	}
	if err := a.Save(nil); err == nil {
		t.Error("saving over a broken file is allowed")
	}
}

func TestSaveChecksActions(t *testing.T) {
	a := &Actions{}
	bad := httpAction("Block IP!")
	if err := a.Save([]Connector{bad}); err == nil {
		t.Error("a bad name is saved")
	}
	if err := a.Save([]Connector{httpAction("a"), httpAction("a")}); err == nil {
		t.Error("two actions with one name are saved")
	}
	sneaky := httpAction("b")
	sneaky.Headers = map[string]string{"Host": "other.example.com"}
	if err := a.Save([]Connector{sneaky}); err == nil {
		t.Error("a Host header is saved")
	}
	// A token in Authorization is fine; with Basic sign-in as well it is not.
	token := httpAction("t")
	token.Username, token.Password = "", ""
	token.Headers = map[string]string{"Authorization": "Bearer tok-123"}
	if err := a.Save([]Connector{token}); err != nil {
		t.Errorf("an Authorization header is refused: %v", err)
	}
	token.Username, token.Password = "u", "p"
	if err := a.Save([]Connector{token}); err == nil {
		t.Error("an Authorization header is saved with Basic sign-in too")
	}
	for _, p := range []string{"/bin/sh", "../x.sh", "a/../../x.sh", `C:\x.ps1`} {
		s := Connector{Name: "s", Kind: KindScript, Target: TargetHost, Program: p}
		if err := a.Save([]Connector{s}); err == nil {
			t.Errorf("program %q is saved", p)
		}
	}
	s := Connector{Name: "s", Kind: KindScript, Target: TargetHost, Program: "iso.sh", TimeoutSeconds: 601}
	if err := a.Save([]Connector{s}); err == nil {
		t.Error("an 11-minute timeout is saved")
	}
	// Every template is valid once saved as it is.
	for _, tp := range Templates() {
		c := tp.Connector.Clone()
		if c.Kind == KindHTTP && tp.UsernameLabel != "" {
			c.Username, c.Password = "key", "secret"
		}
		for _, h := range tp.Headers {
			if c.Headers == nil {
				c.Headers = map[string]string{}
			}
			c.Headers[h.Name] = "Bearer x"
		}
		c.Normalize()
		if p := c.Problems(); len(p) > 0 {
			t.Errorf("template %s: %v", tp.ID, p)
		}
	}
}

func TestMergeKeepsSecretsOnlyForTheSameServer(t *testing.T) {
	saved := []Connector{httpAction("block-ip")}
	saved[0].Normalize()
	in := Input{Connector: saved[0].Clone(), Headers: []HeaderInput{{Name: "x-api-key", Keep: true}}, Password: SecretInput{Keep: true}}
	in.URL = "https://fw.example.lan/api/alias/add2"
	out, err := Merge(saved, []Input{in})
	if err != nil || out[0].Headers["X-Api-Key"] != "key-0123456789" || out[0].Password != "api-secret-987" {
		t.Fatalf("same server: %+v %v", out, err)
	}
	in.URL = "https://attacker.example.com/collect"
	if _, err := Merge(saved, []Input{in}); err == nil || !strings.Contains(err.Error(), "somewhere else") {
		t.Errorf("moved server kept the secret: %v", err)
	}
	in.URL = "http://fw.example.lan/api/alias/add"
	if _, err := Merge(saved, []Input{in}); err == nil {
		t.Error("a move to http kept the secret")
	}
	in = Input{Connector: saved[0].Clone(), Headers: []HeaderInput{{Name: "X-Api-Key", Keep: true}}}
	in.Name = "renamed"
	if _, err := Merge(saved, []Input{in}); err == nil {
		t.Error("a renamed action kept the secret")
	}
	// A new value replaces; settings of another kind are dropped.
	in = Input{Connector: saved[0].Clone(), Headers: []HeaderInput{{Name: "X-Api-Key", Value: "new-key"}}}
	in.Program = "x.sh"
	out, err = Merge(saved, []Input{in})
	if err != nil || out[0].Headers["X-Api-Key"] != "new-key" || out[0].Password != "" || out[0].Program != "" {
		t.Errorf("replaced: %+v %v", out, err)
	}
}
