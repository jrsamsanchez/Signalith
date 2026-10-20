// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
	"github.com/jrsamsanchez/signalith/internal/keytrust"
)

// rootKey makes a root key the only one keytrust trusts.
func rootKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := keytrust.Roots
	keytrust.Roots = []ed25519.PublicKey{pub}
	t.Cleanup(func() { keytrust.Roots = old })
	return priv
}

// revocationList is a list signed by root, issued at issued, revoking the
// keys of privs.
func revocationList(t *testing.T, root ed25519.PrivateKey, issued time.Time, privs ...ed25519.PrivateKey) ([]byte, []byte) {
	t.Helper()
	l := keytrust.List{Format: keytrust.Format, Issued: issued}
	for _, p := range privs {
		l.Revoked = append(l.Revoked, keytrust.RevokedKey{ID: keytrust.KeyID(p.Public().(ed25519.PublicKey)), Note: "leaked"})
	}
	data, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	return data, keytrust.Sign(root, data)
}

func TestAgentRefusesUpdatesSignedWithRevokedKey(t *testing.T) {
	root := rootKey(t)
	priv := releaseKey(t)
	t.Setenv("AGENTD_FAKE_AGENT_VERSION", "2.0.0")
	prog, sum := fakeProgram(t, "2.0.0")
	data, sig := signedManifest(t, priv, "2.0.0", sum)
	c := newStageCase(t, agentproto.Update{Version: "2.0.0", SHA256: sum}, prog, data, sig)
	now := time.Now()
	list, listSig := revocationList(t, root, now, priv)
	c.srv.manifest.Revocation, c.srv.manifest.RevocationSignature = string(list), string(listSig)
	c.agent.checkUpdate(context.Background())
	if comp := c.component(); comp == nil || comp.State != agentproto.StateFailed || !strings.Contains(comp.Error, "revoked") {
		t.Fatalf("component = %+v, want failed as revoked", comp)
	}
	if c.started != 0 || c.srv.gets != 0 {
		t.Fatal("an update signed with a revoked key was fetched or handed to the updater")
	}
	// A server that later hands out an older list, or none, does not take
	// the revocation back.
	old, oldSig := revocationList(t, root, now.Add(-time.Hour))
	for _, l := range [][2]string{{string(old), string(oldSig)}, {"", ""}} {
		c.srv.manifest.Revocation, c.srv.manifest.RevocationSignature = l[0], l[1]
		c.agent.updateTried = nil
		c.agent.checkUpdate(context.Background())
		if comp := c.component(); comp == nil || comp.State != agentproto.StateFailed || !strings.Contains(comp.Error, "revoked") {
			t.Fatalf("component = %+v, want still failed as revoked", comp)
		}
	}
}

func TestAgentStagesRevocationListForUpdater(t *testing.T) {
	root := rootKey(t)
	priv := releaseKey(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("AGENTD_FAKE_AGENT_VERSION", "2.0.0")
	prog, sum := fakeProgram(t, "2.0.0")
	data, sig := signedManifest(t, priv, "2.0.0", sum)
	c := newStageCase(t, agentproto.Update{Version: "2.0.0", SHA256: sum}, prog, data, sig)
	list, listSig := revocationList(t, root, time.Now(), other)
	c.srv.manifest.Revocation, c.srv.manifest.RevocationSignature = string(list), string(listSig)
	c.agent.checkUpdate(context.Background())
	if c.started != 1 {
		t.Fatalf("component = %+v, want the update staged", c.component())
	}
	if b, _ := os.ReadFile(filepath.Join(c.agent.Paths.updateDir(), keytrust.ListFile)); !bytes.Equal(b, list) {
		t.Fatal("the revocation list was not staged for the updater")
	}
}

func TestUpdaterRefusesRevokedKey(t *testing.T) {
	root := rootKey(t)
	priv := releaseKey(t)
	c := newUpdaterCase(t, priv, "2.0.0")
	p := c.u.Paths
	list, listSig := revocationList(t, root, time.Now(), priv)
	for f, b := range map[string][]byte{keytrust.ListFile: list, keytrust.SignatureFile: listSig} {
		if err := os.WriteFile(filepath.Join(p.updateDir(), f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.u.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("err = %v, want revoked", err)
	}
	if !bytes.Equal(c.installed(t), c.old) {
		t.Fatal("the program was replaced")
	}
	// The updater keeps its own copy where the agent cannot write, so the
	// agent dropping the list does not undo it.
	if _, b, _, _ := (&keytrust.Store{Dir: p.rootTrustDir()}).Load(); !bytes.Equal(b, list) {
		t.Fatal("the updater did not keep the list")
	}
	for _, f := range []string{keytrust.ListFile, keytrust.SignatureFile} {
		os.Remove(filepath.Join(p.updateDir(), f))
	}
	if err := os.WriteFile(p.readyFile(), []byte("2.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.u.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("without the staged list: err = %v, want revoked", err)
	}
}

// breakKeptList keeps a list in dir and then breaks the file it is kept in.
func breakKeptList(t *testing.T, root ed25519.PrivateKey, dir string) {
	t.Helper()
	list, sig := revocationList(t, root, time.Now())
	if _, err := (&keytrust.Store{Dir: dir}).Offer(list, sig); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("kept files: %v %v", entries, err)
	}
	if err := os.WriteFile(filepath.Join(dir, entries[0].Name()), []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A kept revocation list that cannot be read refuses updates rather than
// forget a revoked key.
func TestAgentRefusesUpdatesWithUnreadableList(t *testing.T) {
	root := rootKey(t)
	priv := releaseKey(t)
	t.Setenv("AGENTD_FAKE_AGENT_VERSION", "2.0.0")
	prog, sum := fakeProgram(t, "2.0.0")
	data, sig := signedManifest(t, priv, "2.0.0", sum)
	c := newStageCase(t, agentproto.Update{Version: "2.0.0", SHA256: sum}, prog, data, sig)
	breakKeptList(t, root, c.agent.Paths.trustDir())
	c.agent.checkUpdate(context.Background())
	if comp := c.component(); comp == nil || comp.State != agentproto.StateFailed || !strings.Contains(comp.Error, "revocation list") {
		t.Fatalf("component = %+v, want failed for the unreadable list", comp)
	}
	if c.started != 0 || c.srv.gets != 0 {
		t.Fatal("an update was fetched or handed to the updater")
	}
}

func TestUpdaterRefusesWithUnreadableList(t *testing.T) {
	root := rootKey(t)
	priv := releaseKey(t)
	c := newUpdaterCase(t, priv, "2.0.0")
	breakKeptList(t, root, c.u.Paths.rootTrustDir())
	if err := c.u.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "revocation list") {
		t.Fatalf("err = %v, want refused for the unreadable list", err)
	}
	if !bytes.Equal(c.installed(t), c.old) {
		t.Fatal("the program was replaced")
	}
}

// The largest answer a server can send fits what the agent reads.
func TestManifestAnswerFits(t *testing.T) {
	ans := agentproto.ManifestAnswer{
		Manifest:            strings.Repeat("<", agentproto.MaxManifestBytes),
		Signature:           strings.Repeat("<", 1024),
		Revocation:          strings.Repeat("<", keytrust.MaxList),
		RevocationSignature: strings.Repeat("<", 1024),
	}
	b, err := json.Marshal(ans)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > agentproto.MaxManifestAnswer {
		t.Fatalf("answer is %d bytes, the agent reads %d", len(b), agentproto.MaxManifestAnswer)
	}
}
