// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"testing"
)

// A value applied at once from another configuration brings where it
// came from: the shared value, or none when the other has it from
// elsewhere.
func TestCopyValueBringsTheSharedSource(t *testing.T) {
	path, sh := sharedFixture(t)
	c1, err := LoadShared(path, sh)
	if err != nil {
		t.Fatal(err)
	}
	sh2 := sh.Clone()
	v := sh2.Cluster["server.public_url"]
	v.Value, v.Rev, v.From.By = json.RawMessage(`"https://moved.example:8443"`), 4, "cy"
	sh2.Cluster["server.public_url"] = v
	c2, err := LoadShared(path, sh2)
	if err != nil {
		t.Fatal(err)
	}
	if err := c1.CopyValue("server.public_url", c2); err != nil {
		t.Fatal(err)
	}
	if c1.Server.PublicURL != "https://moved.example:8443" || c1.Source("server.public_url").By != "cy" {
		t.Errorf("after the copy: %s from %+v", c1.Server.PublicURL, c1.Source("server.public_url"))
	}
	if c2.Source("server.public_url").By != "cy" || sh.Cluster["server.public_url"].From.By == "cy" {
		t.Error("the copy changed the configuration it came from")
	}
	// The same again changes nothing.
	if err := c1.CopyValue("server.public_url", c2); err != nil || c1.Source("server.public_url").By != "cy" {
		t.Errorf("again: %v %+v", err, c1.Source("server.public_url"))
	}

	// The other runs it at its default: no shared source comes along.
	sh3 := sh.Clone()
	delete(sh3.Cluster, "server.public_url")
	c3, err := LoadShared(path, sh3)
	if err != nil {
		t.Fatal(err)
	}
	if err := c1.CopyValue("server.public_url", c3); err != nil {
		t.Fatal(err)
	}
	if c1.Source("server.public_url").Kind == FromShared {
		t.Errorf("source after copying a value that is not shared: %+v", c1.Source("server.public_url"))
	}
}

// A secret saved on the page that cannot be decrypted is reported, and
// the report moves with the value copied from another configuration.
func TestCopyValueBringsThePageSecretProblem(t *testing.T) {
	path := writeConfig(t, "")
	writePage(t, path, "settings:\n  assistant.api_key:\n    secret: enc:v1:deadbeef:AAAA\n")
	bad, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if bad.PageSecretProblem("assistant.api_key") == "" {
		t.Fatal("a secret that cannot be decrypted is not reported")
	}
	good := validConfig(t)
	if err := good.CopyValue("assistant.api_key", bad); err != nil {
		t.Fatal(err)
	}
	if good.PageSecretProblem("assistant.api_key") == "" {
		t.Error("the problem did not come with the value")
	}
	if err := good.CopyValue("assistant.api_key", validConfig(t)); err != nil {
		t.Fatal(err)
	}
	if p := good.PageSecretProblem("assistant.api_key"); p != "" {
		t.Errorf("the problem stays after a good value: %q", p)
	}
}
