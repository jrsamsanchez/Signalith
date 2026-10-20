// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clustercfg

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// settingsFile writes body as a settings file and reads it as signalith
// cluster apply does.
func (m *authMember) settingsFile(body string) *config.Config {
	m.t.Helper()
	path := filepath.Join(m.t.TempDir(), "apply.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		m.t.Fatal(err)
	}
	f, err := config.ReadSettingsFile(path, m.master)
	if err != nil {
		m.t.Fatal(err)
	}
	return f
}

func changeKeys(p *FilePlan) []string {
	var out []string
	for _, c := range p.Changes {
		out = append(out, c.Key)
	}
	return out
}

// signalith cluster apply -f: a file's shared settings are planned
// against those in use, applied, and planning the same file again
// changes nothing.
func TestApplyFile(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dir, authConfig(t, dir, ""), nil)
	a.cycle()
	ctx := context.Background()
	cur := a.load()

	f := a.settingsFile("search:\n  max_events: 777\ncluster:\n  name: prod\nassistant:\n  api_key: test-assistant-key\n")
	p, err := PlanFile(a.rt, a.docs, cur, f)
	if err != nil {
		t.Fatal(err)
	}
	if p.Empty() || p.AdminUser() != "" {
		t.Fatalf("plan = %+v", p.Changes)
	}
	byKey := map[string]FileChange{}
	for _, c := range p.Changes {
		byKey[c.Key] = c
	}
	if c := byKey["search.max_events"]; c.Want != "777" || c.Have == "777" || c.Secret {
		t.Errorf("search.max_events change = %+v", c)
	}
	if c := byKey["cluster.name"]; c.Want != `"prod"` {
		t.Errorf("cluster.name change = %+v", c)
	}
	if c := byKey["assistant.api_key"]; !c.Secret || c.Have != "" || c.Want != "" {
		t.Errorf("assistant.api_key change = %+v (a secret shows neither value)", c)
	}

	applied, err := p.Apply(ctx, a.rt, a.docs, f, "admin", "siem-a", a.log)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"search.max_events", "cluster.name", "assistant.api_key"} {
		if !contains(applied, k) {
			t.Errorf("applied %v, not %s", applied, k)
		}
	}
	a.cycle()
	if cb, _ := a.rt.Cluster().Get(); cb == nil || cb.Name != "prod" {
		t.Errorf("cluster name = %+v", cb)
	}
	if v, ok := a.setting("search.max_events"); !ok || rawString(v.Value) != "777" {
		t.Errorf("search.max_events = %+v %v", v, ok)
	}
	mustContain(t, "log", a.logs.String(), "applied with signalith cluster apply on siem-a by admin")

	// The same file again: nothing to change, the secret included.
	cur = a.load()
	p, err = PlanFile(a.rt, a.docs, cur, f)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Empty() {
		t.Errorf("planned again: %v", changeKeys(p))
	}
}

func TestApplyFileRenamesTheBuiltinAdmin(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dir, authConfig(t, dir, ""), nil)
	a.cycle()
	f := a.settingsFile("auth:\n  admin_user: root\n")
	p, err := PlanFile(a.rt, a.docs, a.load(), f)
	if err != nil {
		t.Fatal(err)
	}
	if p.AdminUser() != "root" || len(p.Changes) != 1 || p.Changes[0].Have != `"admin"` || p.Changes[0].Want != `"root"` {
		t.Errorf("plan = %+v, admin %q", p.Changes, p.AdminUser())
	}
}

func TestApplyFileRefusals(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dir, authConfig(t, dir, ""), nil)
	a.cycle()
	cur := a.load()
	for _, c := range []struct {
		name, body string
		want       []string
	}{
		{"own and bootstrap settings", "opensearch:\n  url: https://os.example.com:9200\nretention:\n  archive_dir: /var/archive\n",
			[]string{"take them out of it", "opensearch.url: each server needs it", "retention.archive_dir: it is a folder on each server"}},
		{"password hash", "auth:\n  admin_password_hash: not-a-hash\n", []string{"signalith passwd"}},
		{"tokens", "ingest:\n  tokens: [tok-0123456789abcdef]\n", []string{"ingest.tokens"}},
		{"leader", "cluster:\n  leader_eligible: false\n", []string{"that server's own setting"}},
		{"bad value", "search:\n  max_events: -5\n", []string{"have problems; nothing was changed", "search.max_events"}},
	} {
		f := a.settingsFile(c.body)
		_, err := PlanFile(a.rt, a.docs, cur, f)
		if err == nil {
			t.Errorf("%s: planned", c.name)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: %v, want %q", c.name, err, w)
			}
		}
	}
	for _, c := range []struct {
		key string
		ok  bool
	}{
		{"retention.policies", true}, {"intel.feeds", true}, {"auth.ldap.url", true}, {"auth.admin_user", true},
		{"no.such.setting", false}, {"detections.scheduler", false},
	} {
		if ok, why := applyKey(c.key); ok != c.ok || ok == (why != "") {
			t.Errorf("applyKey(%s) = %v, %q", c.key, ok, why)
		}
	}
	if got := asJSON(func() {}); got == "" {
		t.Error("asJSON of a value JSON cannot hold")
	}
}
