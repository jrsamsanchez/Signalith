package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// A token is added to ingest.tokens whatever shape the file has, and a
// file whose shape cannot take one is refused.
func TestSetSecretTextTokens(t *testing.T) {
	const tok = "enc:v1:test-token"
	for name, c := range map[string]struct {
		in, err string
		want    []string
	}{
		"empty":            {in: "", want: []string{tok}},
		"no ingest":        {in: "search:\n  max_events: 5\n", want: []string{tok}},
		"ingest no tokens": {in: "ingest:\n  hec: true\n", want: []string{tok}},
		"null tokens":      {in: "ingest:\n  tokens:\n", want: []string{tok}},
		"flow list":        {in: "ingest:\n  tokens: [a-token-0123456789abc]\n", want: []string{"a-token-0123456789abc", tok}},
		"one per line":     {in: "ingest:\n  tokens:\n    - a-token-0123456789abc\n", want: []string{"a-token-0123456789abc", tok}},
		"not yaml":         {in: "ingest: [\n", err: "not valid YAML"},
		"not a mapping":    {in: "- a\n- b\n", err: "not a YAML mapping"},
		"ingest a list":    {in: "ingest:\n  - a\n", err: "ingest is not a section"},
		"tokens a map":     {in: "ingest:\n  tokens:\n    a: b\n", err: "ingest.tokens is not a list"},
	} {
		out, err := SetSecretText([]byte(c.in), "ingest.tokens", tok)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := tokenList(out); strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: tokens %v in\n%s", name, got, out)
		}
	}
	if _, err := SetSecretText([]byte("search: {}\n"), "auth.ldap.bind_password", "x"); err == nil || !strings.Contains(err.Error(), "no auth.ldap section") {
		t.Errorf("bind password without a section: %v", err)
	}
	if _, err := SetSecretText([]byte("auth: [\n"), "auth.ldap.bind_password", "x"); err == nil {
		t.Error("bind password in a file that is not YAML")
	}
	if _, err := SetSecretText([]byte(""), "search.max_events", "x"); err == nil || !strings.Contains(err.Error(), "cannot be set this way") {
		t.Errorf("not a secret: %v", err)
	}
}

// ResealFile reports a file that is not YAML and a reseal that fails,
// and leaves an empty file alone.
func TestResealFileRefusals(t *testing.T) {
	fn := func(s secrets.Stored) (string, error) { return s.Value, nil }
	if _, _, err := ResealFile([]byte("a: [\n"), fn); err == nil {
		t.Error("resealed a file that is not YAML")
	}
	if out, n, err := ResealFile(nil, fn); err != nil || n != 0 || len(out) != 0 {
		t.Errorf("empty: %q %d %v", out, n, err)
	}
	boom := errors.New("boom")
	if _, _, err := ResealFile([]byte("opensearch:\n  password: pw\n"), func(secrets.Stored) (string, error) { return "", boom }); !errors.Is(err, boom) {
		t.Errorf("a failing reseal: %v", err)
	}
	if _, _, err := MoveURLPassword([]byte("opensearch: [\n")); err == nil {
		t.Error("moved a password in a file that is not YAML")
	}
	data := []byte("opensearch:\n  url: https://os.internal:9200\n")
	if out, moved, err := MoveURLPassword(data); err != nil || moved || string(out) != string(data) {
		t.Errorf("no password: %q %v %v", out, moved, err)
	}
}
