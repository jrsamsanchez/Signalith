// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"slices"
	"testing"
	"time"
)

// The security checks count the active API tokens and name those that
// never expire; a revoked one is not counted. Without shared users there
// are no API tokens to check.
func TestAPITokenFacts(t *testing.T) {
	if f := (&Server{}).apiTokenFacts(time.Now()); f != nil {
		t.Errorf("without shared users: %+v", f)
	}
	c := newMemberCluster(t, nil)
	admin, code := c.a.signIn("admin", "s3cret-pass")
	if admin == nil {
		t.Fatalf("sign in: %d", code)
	}
	var revoke string
	for _, body := range []string{
		`{"name":"forever","role":"viewer","never":true}`,
		`{"name":"monthly","role":"viewer","expires_in_days":30}`,
		`{"name":"gone","role":"viewer","expires_in_days":30}`,
	} {
		code, out, _ := c.a.call("POST", "/api/api-tokens", body, admin, nil)
		if code != http.StatusCreated {
			t.Fatalf("create %s: %d %v", body, code, out)
		}
		revoke, _ = out["id"].(string)
	}
	if code, out, _ := c.a.call("POST", "/api/api-tokens/"+revoke+"/revoke", "", admin, nil); code != http.StatusOK {
		t.Fatalf("revoke: %d %v", code, out)
	}
	f := c.a.srv.apiTokenFacts(time.Now())
	if f == nil || f.Active != 2 || !slices.Equal(f.NeverExpire, []string{"forever"}) {
		t.Errorf("facts %+v", f)
	}
}
