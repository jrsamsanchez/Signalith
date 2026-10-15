package opensearchcheck

import (
	"context"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// fake starts a fake OpenSearch over HTTPS and returns it with the file
// of its certificate.
func fake(t *testing.T) (*ostest.Server, string) {
	t.Helper()
	s, h := ostest.NewHandler()
	s.Server = httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0o666); err != nil {
		t.Fatal(err)
	}
	return s, ca
}

func failed(fs []Finding) string {
	var out []string
	for _, f := range fs {
		if !f.OK {
			out = append(out, f.What)
		}
	}
	return strings.Join(out, "; ")
}

func TestCheck(t *testing.T) {
	ctx := context.Background()
	s, ca := fake(t)
	s.Secure(&ostest.Account{User: "signalith", Password: "pw"})
	good := store.Config{URL: s.URL, Username: "signalith", Password: secrets.New("opensearch.password", "pw"), CAFile: ca}
	if fs := Check(ctx, good); Failed(fs) || len(fs) != 4 {
		t.Fatalf("a good OpenSearch: %+v", fs)
	}

	cases := []struct {
		name string
		cfg  func(store.Config) store.Config
		want string
	}{
		{"untrusted", func(c store.Config) store.Config { c.CAFile = ""; return c }, "not trusted"},
		{"skip verify", func(c store.Config) store.Config { c.CAFile, c.TLSSkipVerify = "", true; return c }, "not checked"},
		{"wrong password", func(c store.Config) store.Config { c.Password = secrets.New("opensearch.password", "nope"); return c }, "refused"},
		{"bad address", func(c store.Config) store.Config { c.URL = "::"; return c }, "cannot be read"},
	}
	for _, tc := range cases {
		fs := Check(ctx, tc.cfg(good))
		if !Failed(fs) || !strings.Contains(failed(fs), tc.want) {
			t.Errorf("%s: %+v", tc.name, fs)
		}
		for _, f := range fs {
			if !f.OK && f.Fix == "" {
				t.Errorf("%s: %q has no fix", tc.name, f.What)
			}
		}
	}

	// A clock 5 s off.
	s.Offset = 5 * time.Second
	if fs := Check(ctx, good); !strings.Contains(failed(fs), "clock") {
		t.Errorf("clock: %+v", fs)
	}
	s.Offset = 0

	// Without security: anyone gets in.
	s.Secure(nil)
	if fs := Check(ctx, good); !strings.Contains(failed(fs), "security plugin is off") {
		t.Errorf("no security: %+v", fs)
	}

	// Nothing answers.
	s.Close()
	if fs := Check(ctx, good); !strings.Contains(failed(fs), "does not answer") || len(fs) != 1 {
		t.Errorf("closed: %+v", fs)
	}
}

func TestCheckPlainHTTP(t *testing.T) {
	s := ostest.New(t)
	fs := Check(context.Background(), store.Config{URL: s.URL})
	if !strings.Contains(failed(fs), "plain http") || !strings.Contains(failed(fs), "security plugin is off") {
		t.Errorf("plain http: %+v", fs)
	}
}
