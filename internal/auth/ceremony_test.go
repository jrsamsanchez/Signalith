// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestCeremonyState(t *testing.T) {
	k, other := NewBrowserKey(), NewBrowserKey()
	now := time.Unix(1_800_000_000, 0)
	data := []byte(`{"challenge":"abc"}`)
	tok := k.SealState("passkey\x00login", data, now.Add(5*time.Minute))
	if got, ok := k.OpenState("passkey\x00login", tok, now.Add(5*time.Minute-time.Second)); !ok || !bytes.Equal(got, data) {
		t.Fatalf("fresh token: %q %v", got, ok)
	}
	for name, try := range map[string]func() bool{
		"expired":       func() bool { _, ok := k.OpenState("passkey\x00login", tok, now.Add(5*time.Minute)); return ok },
		"other purpose": func() bool { _, ok := k.OpenState("passkey\x00step", tok, now); return ok },
		"other key":     func() bool { _, ok := other.OpenState("passkey\x00login", tok, now); return ok },
		"tampered":      func() bool { _, ok := k.OpenState("passkey\x00login", flip(tok, 6), now); return ok },
		"no prefix": func() bool {
			_, ok := k.OpenState("passkey\x00login", strings.TrimPrefix(tok, statePrefix), now)
			return ok
		},
		"empty": func() bool { _, ok := k.OpenState("passkey\x00login", "", now); return ok },
		"too long": func() bool {
			_, ok := k.OpenState("x", k.SealState("x", make([]byte, stateMax+1), now.Add(time.Hour)), now)
			return ok
		},
		// Purposes are length-prefixed, so moving bytes between purpose
		// and data does not make another valid token.
		"shifted": func() bool {
			_, ok := k.OpenState("passkey", k.SealState("passkey\x00login", nil, now.Add(time.Hour)), now)
			return ok
		},
		"browser cookie": func() bool { _, ok := k.OpenState("ann", statePrefix+k.Issue("ann", "", now), now); return ok },
	} {
		if try() {
			t.Errorf("%s accepted", name)
		}
	}
}

// FuzzOpenState feeds the ceremony token reader anything: it must refuse
// what this key did not seal, never panic.
func FuzzOpenState(f *testing.F) {
	k := NewBrowserKey()
	now := time.Unix(1_800_000_000, 0)
	f.Add("passkey\x00login", k.SealState("passkey\x00login", []byte(`{"challenge":"abc"}`), now.Add(time.Minute)))
	f.Add("x", "1.")
	f.Add("", "1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Fuzz(func(t *testing.T, purpose, token string) {
		if data, ok := k.OpenState(purpose, token, now); ok && len(data) > stateMax {
			t.Fatalf("%d bytes of data", len(data))
		}
	})
}
