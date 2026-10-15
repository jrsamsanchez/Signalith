package config

import (
	"strings"
	"testing"
)

func TestOpenSearchURLs(t *testing.T) {
	s, ok := Lookup("opensearch.urls")
	if !ok || s.Scope != ScopeBootstrap || s.Type != TypeList || !s.Restart || s.Env != "SIGNALITH_OPENSEARCH_URLS" {
		t.Fatalf("registry entry: %+v", s)
	}

	c, err := loadYAML(t, "opensearch:\n  url: https://os1.example:9200\n  urls:\n    - https://os2.example:9200\n    - https://os3.example:9200\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.OpenSearchConnection().URLs; got != "https://os2.example:9200,https://os3.example:9200" {
		t.Fatalf("connection urls %q", got)
	}

	t.Setenv("SIGNALITH_OPENSEARCH_URLS", " https://os4.example:9200, ,https://os5.example:9200 ")
	c, err = loadYAML(t, "opensearch:\n  url: https://os1.example:9200\n")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.OpenSearch.URLs, " ") != "https://os4.example:9200 https://os5.example:9200" || c.Source("opensearch.urls").Env != "SIGNALITH_OPENSEARCH_URLS" {
		t.Fatalf("from the environment: %q %+v", c.OpenSearch.URLs, c.Source("opensearch.urls"))
	}
}

func TestOpenSearchURLsValidation(t *testing.T) {
	for _, tc := range []struct {
		urls []string
		user string
		want string
	}{
		{[]string{"https://os2.example:9200"}, "signalith", ""},
		{[]string{"os2.example:9200"}, "", "must be http(s)://host:port"},
		{[]string{"https://admin:SECRET@os2.example:9200"}, "", "user name or password"},
		{[]string{"http://os2.example:9200"}, "", "must use https"},
		{[]string{"https://os2.example:9200/?key=1"}, "", "query string"},
	} {
		c := validConfig(t)
		c.OpenSearch.URL, c.OpenSearch.URLs, c.OpenSearch.Username = "https://os1.example:9200", tc.urls, tc.user
		err := c.Validate()
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%v: %v", tc.urls, err)
		}
		if err != nil && strings.Contains(err.Error(), "SECRET") {
			t.Errorf("password shown: %v", err)
		}
	}
	// The plain-http password rule applies to each address.
	c := validConfig(t)
	c.OpenSearch.URL, c.OpenSearch.URLs = "http://127.0.0.1:9200", []string{"http://10.0.0.6:9200"}
	c.OpenSearch.Username, c.OpenSearch.Password = "signalith", "pw"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "unencrypted") {
		t.Errorf("plain http to another machine: %v", err)
	}
	s, _ := Lookup("opensearch.urls")
	if err := s.check([]string{"https://u:p@os2:9200"}); err == nil {
		t.Error("page check took a password")
	}
	if err := s.check([]string{"not an address"}); err == nil {
		t.Error("page check took a bad address")
	}
}

// The OpenSearch password is sent to every address: adding one on the
// page needs the password again.
func TestOpenSearchPasswordFollowsURLs(t *testing.T) {
	path := writeConfig(t, "opensearch:\n  url: https://os1.example:9200\n  username: signalith\n  password: from-file\n")
	res, err := CheckEdit(path, Edit{Values: map[string]any{"opensearch.urls": []any{"https://evil.example:9200"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Fields["opensearch.password"], "only sent to https://os1.example:9200") {
		t.Fatalf("fields %v", res.Fields)
	}
	res, err = CheckEdit(path, Edit{Values: map[string]any{"opensearch.urls": []any{"https://os2.example:9200"}, "opensearch.password": "again"}})
	if err != nil || !res.OK() {
		t.Fatalf("%v %v %v", err, res.Fields, res.Problems)
	}
	if e := res.Page.Settings["opensearch.password"]; e == nil || e.SentTo != "https://os1.example:9200,https://os2.example:9200" {
		t.Fatalf("entry %+v", e)
	}
}
