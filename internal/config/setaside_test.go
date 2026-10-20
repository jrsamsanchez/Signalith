// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
)

// Setting a change aside takes along only the changes its problems name:
// a model set aside leaves the provider, whose problem names the model
// alone, on the page or in the shared settings.
func TestSetAsideAlongNamedOnly(t *testing.T) {
	path := writeConfig(t, "")
	writePage(t, path, "settings:\n  assistant.provider:\n    value: openai\n  assistant.model:\n    value: gpt-test\n  search.max_events:\n    value: 600\n")
	if got := SetAsideAlong(path, []string{"assistant.model"}); !slices.Equal(got, []string{"assistant.model"}) {
		t.Errorf("set aside along: %v", got)
	}
	if got := SetAsideAlong(path, []string{"search.max_events"}); !slices.Equal(got, []string{"search.max_events"}) {
		t.Errorf("set aside alone: %v", got)
	}

	shared := writeConfig(t, "")
	sh := &Shared{Cluster: map[string]SharedValue{
		"assistant.provider": {Value: jsonOf(t, "openai")},
		"assistant.model":    {Value: jsonOf(t, "gpt-test")},
	}}
	if got := SetAsideAlongShared(shared, sh, []string{"assistant.model"}); !slices.Equal(got, []string{"assistant.model"}) {
		t.Errorf("shared set aside along: %v", got)
	}
	if _, ok := sh.Refused["assistant.model"]; ok {
		t.Error("the layer passed in was changed")
	}
}

// The SCIM token is checked against its SHA-256 only.
func TestSCIMToken(t *testing.T) {
	sum := sha256.Sum256([]byte("test-scim-token"))
	c := &Config{}
	c.Auth.SCIM.TokenSHA256 = hex.EncodeToString(sum[:])
	if !c.SCIMToken("test-scim-token") || c.SCIMToken("other") || c.SCIMToken("") {
		t.Error("token check")
	}
	c.Auth.SCIM.TokenSHA256 = "not hex"
	if c.SCIMToken("test-scim-token") {
		t.Error("a bad hash took a token")
	}
	problemsHave(t, "bad hash", c.scimProblems(), true, "auth.scim.token_sha256: must be the SHA-256")
	c.Auth.SCIM.TokenSHA256, c.Auth.SCIM.Enabled = "", true
	problemsHave(t, "on without a token", c.scimProblems(), true, "create a token")
	if sha256Hex("xyz") == nil || sha256Hex("") != nil || sha256Hex(hex.EncodeToString(sum[:])) != nil {
		t.Error("the page's check of the hash")
	}
}

// Each ingest token says where it came from.
func TestIngestTokenSource(t *testing.T) {
	c := &Config{}
	c.Ingest.Tokens = []string{"a", "b", "c"}
	c.envTokens = []string{"SIGNALITH_INGEST_TOKEN"}
	for i, want := range []string{"signalith.yaml", "signalith.yaml", "SIGNALITH_INGEST_TOKEN"} {
		if got := c.IngestTokenSource(i); got != want {
			t.Errorf("token %d from %q", i, got)
		}
	}
	c.sharedTokenFrom = []string{"siem-a", ""}
	for i, want := range []string{"siem-a", "the shared settings", "the shared settings"} {
		if got := c.IngestTokenSource(i); got != want {
			t.Errorf("shared token %d from %q", i, got)
		}
	}
}

// An edit naming the old detections.scheduler key is taken as
// cluster.leader_eligible, without taking over a value given for both
// and without changing the edit it came from.
func TestRenameAliases(t *testing.T) {
	in := Edit{
		Values: map[string]any{"detections.scheduler": false, "search.max_events": 5},
		Clear:  []string{"assistant.api_key"},
		Reset:  []string{"detections.scheduler", "cluster.leader_eligible"},
		Retry:  []string{"detections.scheduler"},
	}
	out := renameAliases(in)
	if _, old := out.Values["detections.scheduler"]; old || out.Values["cluster.leader_eligible"] != false || out.Values["search.max_events"] != 5 {
		t.Errorf("values %v", out.Values)
	}
	if _, kept := in.Values["detections.scheduler"]; !kept {
		t.Error("the edit passed in was changed")
	}
	if !slices.Equal(out.Reset, []string{"cluster.leader_eligible"}) || !slices.Equal(out.Retry, []string{"cluster.leader_eligible"}) || !slices.Equal(out.Clear, in.Clear) {
		t.Errorf("lists %v %v %v", out.Reset, out.Retry, out.Clear)
	}
	if in.Reset[0] != "detections.scheduler" {
		t.Error("the reset list passed in was changed")
	}
	both := renameAliases(Edit{Values: map[string]any{"detections.scheduler": false, "cluster.leader_eligible": true}})
	if len(both.Values) != 1 || both.Values["cluster.leader_eligible"] != true {
		t.Errorf("both given: %v", both.Values)
	}
}

// The admin password is seen from signalith.yaml and from the
// environment, each with where it came from.
func TestSeenAdminPassword(t *testing.T) {
	path := writeConfig(t, "")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	seen := c.SeenAdminPassword()
	if len(seen) != 1 || seen[0].Source != "yaml" || seen[0].Hash == "" || seen[0].Seen != "hash:"+seen[0].Hash {
		t.Fatalf("from the file: %+v", seen)
	}
	sum := sha256.Sum256([]byte(t.Name()))
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "env-test-"+hex.EncodeToString(sum[:8]))
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var env []SeenPassword
	for _, s := range c.SeenAdminPassword() {
		if s.Source == "env" {
			env = append(env, s)
		}
	}
	if len(env) != 1 || !strings.HasPrefix(env[0].Seen, "env:") || env[0].Hash == "" || env[0].Hash != c.Auth.AdminPasswordHash {
		t.Errorf("from the environment: %+v", c.SeenAdminPassword())
	}
	if c.PublicAdminPassword() {
		t.Error("a generated password taken as the public example")
	}
}
