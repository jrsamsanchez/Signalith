package api

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

// FuzzPasskeyAnswer feeds what a browser sends back from a passkey
// ceremony, as the sign-in and add routes read it, with anything: it
// must be refused, never panic.
func FuzzPasskeyAnswer(f *testing.F) {
	f.Add([]byte(`{"id":"AQ","rawId":"AQ","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AA","signature":"AA","userHandle":"AQ"}}`))
	f.Add([]byte(`{"id":"AQ","rawId":"AQ","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"oA"}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > passkeyAnswerMax {
			return
		}
		_, _ = protocol.ParseCredentialRequestResponseBytes(raw)
		_, _ = protocol.ParseCredentialCreationResponseBytes(raw)
	})
}
