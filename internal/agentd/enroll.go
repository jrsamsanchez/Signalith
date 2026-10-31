// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
)

// The agent trades its install line's token for a key of the computer's
// own (agentproto.RouteEnroll) and sends with that key from then on: the
// agent's requests, Fluent Bit and osquery's enrollment. The line's
// token stays in its file, for the next install and in case the key is
// released.

// enrollRetry is how long the agent waits before asking for a key again
// after the server refused or could not answer.
var enrollRetry = time.Hour

// errHostKeyUnknown is a server that does not know the computer's key: an
// admin released the name, or the server is older than the key. The
// agent drops the key and goes back to its line's token.
var errHostKeyUnknown = errors.New("Signalith does not know this computer's key")

// secret is what the agent and its collectors send with: the computer's
// key once it has one, else the line's token.
func (s Settings) secret() string {
	if s.HostKey != "" {
		return s.HostKey
	}
	return s.Token
}

// lineID is the ID of a line's token, as the server lists it: the start
// of its SHA-256.
func lineID(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])[:12]
}

// enrollSecretFile is the file osquery enrolls with: the key's once the
// agent has one.
func (p Paths) enrollSecretFile() string {
	tok, err := os.ReadFile(p.tokenFile())
	if err != nil {
		return p.tokenFile()
	}
	if _, current := p.readHostKey(strings.TrimSpace(string(tok))); current {
		return p.hostKeyFile()
	}
	return p.tokenFile()
}

// readHostKey reads the computer's key, "" when it has none, and whether
// it was got for the line's token token (hostkey.line holds the ID of the
// token it was got for).
func (p Paths) readHostKey(token string) (key string, current bool) {
	b, err := os.ReadFile(p.hostKeyFile())
	if err != nil {
		return "", false
	}
	key = strings.TrimSpace(string(b))
	if !agentproto.IsHostKey(key) {
		return "", false
	}
	line, err := os.ReadFile(p.hostLineFile())
	return key, err == nil && strings.TrimSpace(string(line)) == lineID(token)
}

// enroll asks for the computer's key when it has none, at most once an
// hour after a refusal.
func (a *Agent) enroll(ctx context.Context) {
	if a.Settings.HostKey != "" || a.idle || a.now().Before(a.enrollNext) {
		return
	}
	a.enrollNext = a.now().Add(enrollRetry)
	key, err := a.askKey(ctx)
	if err != nil {
		switch {
		case errorCode(err) == "":
			// An older server, or none: the line's token works as before.
			a.Log.Info("the server gives no computer key; the agent keeps sending with its line's token", "err", err)
		default:
			a.Log.Warn("Signalith refused a key for this computer; the agent keeps sending with its line's token and asks again in an hour", "err", err)
		}
		return
	}
	// The line first: a key with no line, or another's, is only shown to
	// get a new one.
	if err := writePrivate(a.Paths.hostLineFile(), lineID(a.Settings.Token)+"\n"); err != nil {
		a.Log.Warn("could not keep this computer's key; the agent keeps its line's token", "err", err)
		return
	}
	if err := writePrivate(a.Paths.hostKeyFile(), key+"\n"); err != nil {
		a.Log.Warn("could not keep this computer's key; the agent keeps its line's token", "err", err)
		return
	}
	a.Settings.HostKey, a.Settings.OldHostKey = key, ""
	a.Log.Info("this computer has its own key now; the collectors start again with it")
	a.restartCollectors()
}

// askKey asks the server for the computer's key.
func (a *Agent) askKey(ctx context.Context) (string, error) {
	req, err := a.request(ctx, http.MethodPost, agentproto.RouteEnroll, nil, []byte("{}"))
	if err != nil {
		return "", err
	}
	if a.Settings.OldHostKey != "" {
		req.Header.Set(agentproto.HeaderHostKey, a.Settings.OldHostKey)
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", serverError(resp)
	}
	var e agentproto.Enrolled
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&e); err != nil {
		return "", err
	}
	if !agentproto.IsHostKey(e.Key) {
		return "", errors.New("the server's answer holds no computer key")
	}
	return e.Key, nil
}

// forgetHostKey drops a key the server no longer knows and goes back to
// the line's token, which asks for a new key at once.
func (a *Agent) forgetHostKey() {
	a.Log.Warn("Signalith no longer knows this computer's key (it was released, or the server is older); the agent goes back to its line's token")
	for _, f := range []string{a.Paths.hostKeyFile(), a.Paths.hostLineFile()} {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			a.Log.Warn("removing the computer's key", "err", err)
		}
	}
	a.Settings.HostKey = ""
	a.enrollNext = time.Time{}
	a.restartCollectors()
}

// restartCollectors starts the collectors again with the secret in use,
// unless they are stopped for a refused token.
func (a *Agent) restartCollectors() {
	a.mu.Lock()
	cfg := a.cfg
	a.mu.Unlock()
	if cfg == nil || a.idle {
		return
	}
	if err := a.writeOsquery(cfg); err != nil {
		a.Log.Warn("osquery's flags", "err", err)
	}
	a.osqueryRun = ""
	a.runFluentBit(cfg)
	a.runOsquery(cfg)
}

// writePrivate writes a file only its owner can read, whole or not at
// all.
func writePrivate(path, text string) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(text), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
