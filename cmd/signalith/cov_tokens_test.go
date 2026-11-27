// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/config"
)

// tokens hosts lists, revokes and releases the keys of computers.
func TestTokensHostsCommands(t *testing.T) {
	noServiceSettings(t)
	path := tokensConfig(t)
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	run := func(args ...string) (string, error) {
		var out, errOut bytes.Buffer
		err := runTokens(append(args, "-c", path), devnull, &out, &errOut)
		return out.String(), err
	}
	// No hosts yet: "tokens hosts" alone lists them.
	t.Setenv("SIGNALITH_CONFIG", path)
	var out, errOut bytes.Buffer
	if err := runTokens([]string{"hosts"}, devnull, &out, &errOut); err != nil || !strings.Contains(out.String(), "No computer has a key") {
		t.Errorf("hosts: %v %s", err, out.String())
	}
	if o, err := run("hosts", "list", "-json"); err != nil || strings.TrimSpace(o) != "[]" {
		t.Errorf("hosts JSON: %v %q", err, o)
	}
	for _, args := range [][]string{{"hosts", "revoke"}, {"hosts", "release", "a", "b"}} {
		if _, err := run(args...); err == nil || !strings.Contains(err.Error(), "usage: signalith tokens "+strings.Join(args[:2], " ")) {
			t.Errorf("%v: %v", args, err)
		}
	}
	if _, err := run("hosts", "revoke", "nobody"); err == nil {
		t.Error("revoked a computer with no key")
	}

	// Enroll two computers with a token of the agent's.
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	reg, err := cliTokens(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := reg.Create(ctx, "Agents", "agent", "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"web-01", "db-01"} {
		if _, _, err := reg.Enroll(ctx, tok.ID, h, "10.0.0.1", ""); err != nil {
			t.Fatal(err)
		}
	}
	o, err := run("hosts", "list")
	if err != nil || !strings.Contains(o, "COMPUTER") || !strings.Contains(o, "web-01") || !strings.Contains(o, "Agents") {
		t.Errorf("list: %v\n%s", err, o)
	}
	o, err = run("hosts", "list", "-json")
	var hosts []agenttokens.HostKey
	if err != nil || json.Unmarshal([]byte(o), &hosts) != nil || len(hosts) != 2 {
		t.Errorf("JSON list: %v %s", err, o)
	}
	if o, err := run("hosts", "revoke", "web-01"); err != nil || !strings.Contains(o, "Revoked the key of web-01") {
		t.Errorf("revoke: %v %s", err, o)
	}
	if o, err := run("hosts", "release", "web-01"); err != nil || !strings.Contains(o, "Released web-01") {
		t.Errorf("release: %v %s", err, o)
	}
	// Revoking the token says how many osquery hosts went with it.
	if o, err := run("revoke", "-yes", tok.ID); err != nil || !strings.Contains(o, `Revoked "Agents"`) {
		t.Errorf("revoke token: %v %s", err, o)
	}
}
