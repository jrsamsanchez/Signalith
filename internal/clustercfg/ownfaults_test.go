// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clustercfg

import (
	"context"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// The move of a server's own settings.yaml reports a file it cannot read
// and a write that fails, and finishes on the next start: the copy of the
// file is kept before it is rewritten.
func TestImportOwnRefusals(t *testing.T) {
	o := newOS(t)
	dirA := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dirA, authConfig(t, dirA, ""), nil)

	dirB := t.TempDir()
	secrets.SetDefault(secrets.NewKeyring(dirB))
	cb := authConfig(t, dirB, "")
	b := newAuthMember(t, o, "siem-b", dirB, cb, a.key())
	b.cycle()
	ctx := context.Background()
	path := cb.SettingsFile()
	if err := os.MkdirAll(path, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportOwn(ctx, b.rt, b.docs, cb, b.log); err == nil {
		t.Error("imported a settings.yaml that is a folder")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("settings: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ImportOwn(ctx, b.rt, b.docs, cb, b.log); err == nil {
		t.Error("imported a settings.yaml that is not YAML")
	}

	at := time.Now().Add(-time.Hour)
	p := &config.PageSettings{}
	for k, v := range map[string]any{"server.listen": "0.0.0.0:7443", "detections.scheduler": false, "cluster.leader_eligible": true,
		"search.max_events": 300, "search.default_earliest": "-24h"} {
		if err := p.Set(k, v, "bob", at); err != nil {
			t.Fatal(err)
		}
	}
	p.Settings["search.default_earliest"].Refused = "a restart set it aside"
	bogus := "enc:v1:not-a-key:AAAA"
	p.Settings["assistant.api_key"] = &config.PageEntry{Secret: &bogus, ChangedBy: "bob", ChangedAt: at}
	if err := config.WritePageSettings(path, p); err != nil {
		t.Fatal(err)
	}

	o.fake.SetFault(func(method, path string) *ostest.Fault {
		if method != http.MethodGet && strings.Contains(path, "nodecfg:n_siem-b") {
			return &ostest.Fault{Status: http.StatusInternalServerError, Type: "internal_error"}
		}
		return nil
	})
	if _, err := ImportOwn(ctx, b.rt, b.docs, cb, b.log); err == nil {
		t.Error("the own settings were not written, and no error")
	}
	o.fake.SetFault(nil)
	if nc, _ := b.rt.NodeCfg().Get(); nc != nil && nc.SettingsImported != "" {
		t.Fatal("recorded as imported")
	}

	// The copy cannot be kept: the import is recorded, the file stays.
	var blocked []string
	for _, d := range []time.Time{time.Now(), time.Now().Add(time.Hour)} {
		backup := path + ".imported-" + d.UTC().Format("20060102")
		if err := os.MkdirAll(backup, 0o750); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(blocked, backup) {
			blocked = append(blocked, backup)
		}
	}
	if _, err := ImportOwn(ctx, b.rt, b.docs, cb, b.log); err == nil || !strings.Contains(err.Error(), "could not keep a copy") {
		t.Errorf("no copy kept: %v", err)
	}
	if _, err := config.ReadPageSettings(path); err != nil {
		t.Fatalf("settings.yaml changed: %v", err)
	}
	nc, _ := b.rt.NodeCfg().Get()
	if nc == nil || nc.SettingsImported == "" {
		t.Fatal("not recorded as imported")
	}
	if _, ok := nc.Values["detections.scheduler"]; ok || rawString(nc.Values["cluster.leader_eligible"].Value) != "true" {
		t.Errorf("the new name does not win: %+v", nc.Values)
	}
	if _, ok := nc.Values["search.default_earliest"]; ok {
		t.Error("a shared setting was taken as the server's own")
	}
	mustContain(t, "the log", b.logs.String(), "cannot be compared with the shared value")
	mustContain(t, "the log", b.logs.String(), "search.default_earliest")

	for _, d := range blocked {
		if err := os.Remove(d); err != nil {
			t.Fatal(err)
		}
	}
	if changed, err := ImportOwn(ctx, b.rt, b.docs, cb, b.log); err != nil || !changed {
		t.Fatalf("the next start: %v %v", changed, err)
	}
	if after, _ := b.rt.NodeCfg().Get(); after.SettingsImported != nc.SettingsImported || len(after.Values) != len(nc.Values) {
		t.Errorf("imported again: %+v", after)
	}
	// The file rewritten is not imported again.
	if changed, err := ImportOwn(ctx, b.rt, b.docs, cb, b.log); err != nil || changed {
		t.Errorf("once more: %v %v", changed, err)
	}
}
