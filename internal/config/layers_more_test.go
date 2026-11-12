// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/shared"
)

// A config made in code, not loaded, has no layers: every value is the
// default's, it is its own base, and the page has nothing to say.
func TestConfigWithoutLayers(t *testing.T) {
	c := &Config{}
	if s := c.Source("server.listen"); s.Kind != FromDefault {
		t.Errorf("Source = %+v", s)
	}
	if c.Base() != c {
		t.Error("Base is not the config itself")
	}
	if c.SettingsProblem() != "" || c.SettingsWarnings() != nil || c.SettingsFileFromEnv() {
		t.Error("a config without layers has a settings problem")
	}
	var p *PageSettings
	if p.Remove("server.listen") {
		t.Error("removed from no page")
	}
	p = &PageSettings{}
	if p.Remove("server.listen") {
		t.Error("removed a setting not on the page")
	}
	if orNone("") != "no address" || orNone("https://a") != "https://a" {
		t.Error("orNone")
	}
}

// A secret file that is a folder is listed among the errors; a cluster
// key kept in the state folder is one of the secret files.
func TestSecretInventoryUnreadable(t *testing.T) {
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	path := writeConfig(t, "")
	c, err := LoadFileOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(c.UsersFile(), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, errs := c.SecretInventory(); errs[c.UsersFile()] == nil {
		t.Errorf("errors = %v", errs)
	}
	k, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	ks := shared.KeyStore{Dir: c.StateDir(), Master: c.Keyring()}
	if err := ks.SaveClusterKey(k); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range c.SecretFiles() {
		if f.Path == shared.ClusterKeyPath(c.StateDir(), k.ID()) {
			found = true
		}
	}
	if !found {
		t.Error("the cluster key file is not a secret file")
	}
}
