// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clustercfg

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// Each importer reports a shared document it cannot write, and a file of
// this server's it cannot read.
func TestImportersRefusals(t *testing.T) {
	o := newOS(t)
	a, _ := exportFixture(t, o)
	ctx := context.Background()
	o.fake.SetFault(func(method, path string) *ostest.Fault {
		if method != http.MethodGet && !strings.Contains(path, "_search") {
			return &ostest.Fault{Status: http.StatusInternalServerError, Type: "internal_error"}
		}
		return nil
	})
	for _, name := range []string{ImportFeeds, "feed_status", ImportRetention, shared.ImportUsers, shared.ImportDirectory, shared.ImportSettings} {
		if err := a.importer(name).Run(ctx, "sam"); err == nil {
			t.Errorf("%s ran with every write refused", name)
		}
	}
	o.fake.SetFault(nil)

	c := a.cfg.Load()
	for name, file := range map[string]string{
		ImportFeeds:            c.IntelFeedsFile(),
		ImportRetention:        RetentionFile(c),
		shared.ImportUsers:     c.UsersFile(),
		shared.ImportDirectory: c.DirectoryFile(),
		shared.ImportTenants:   c.TenantsFile(),
	} {
		if err := os.MkdirAll(filepath.Dir(file), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("{[ not this file's format\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := a.importer(name).Run(ctx, "sam"); err == nil {
			t.Errorf("%s imported a file it cannot read", name)
		}
	}
}

// The settings export leaves out what it cannot write as a change of the
// Settings page: a setting of a later version, a password this server
// cannot open and a value removed. The server's own settings come along.
func TestExportSettingsLeavesOut(t *testing.T) {
	o := newOS(t)
	dir := t.TempDir()
	a := newAuthMember(t, o, "siem-a", dir, authConfig(t, dir, ""), nil)
	ctx := context.Background()
	if _, err := a.edit("n_siem-a", a.layer(), config.ScopeServer, config.Edit{Values: map[string]any{"server.listen": "0.0.0.0:7443"}, By: "bob"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.docs.Settings().Mutate(ctx, "test", func(b *SettingsBody) error {
		if b.Values == nil {
			b.Values = map[string]SettingValue{}
		}
		b.Values["later.setting"] = SettingValue{Value: json.RawMessage(`1`)}
		b.Values["assistant.api_key"] = SettingValue{Secret: "enc:v1:sealed-elsewhere:AAAA", SentTo: "https://api.anthropic.com:443"}
		b.Values["search.default_earliest"] = SettingValue{}
		b.Values["search.max_events"] = SettingValue{Value: json.RawMessage(`900`), From: shared.From{By: "alice"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	logs := &logBuffer{}
	target := exportUnder(t, dir, t.TempDir())
	target.Log = slog.New(slog.NewTextHandler(logs, nil))
	files, err := exporter(t, a, shared.ImportSettings).Run(ctx, target)
	if err != nil || len(files) != 1 || files[0].Secret {
		t.Fatalf("export %+v %v", files, err)
	}
	mustContain(t, "the log", logs.String(), "cannot be opened with this server's cluster keys")
	page, err := config.ReadPageSettings(files[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"later.setting", "assistant.api_key", "search.default_earliest"} {
		if _, ok := page.Settings[key]; ok {
			t.Errorf("%s was exported", key)
		}
	}
	if e := page.Settings["search.max_events"]; e == nil || e.ChangedBy != "alice" {
		t.Errorf("max events %+v", e)
	}
	if e := page.Settings["server.listen"]; e == nil || e.ChangedBy != "bob" {
		t.Errorf("the server's own listen %+v", e)
	}
}
