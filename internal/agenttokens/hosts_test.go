// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agenttokens

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

func TestHostKeyFormat(t *testing.T) {
	re := regexp.MustCompile(`^` + strings.TrimSuffix(strings.TrimPrefix(HostScannerPattern, `\b`), `\b`) + `$`)
	k, err := newHostKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != Length || !re.MatchString(k) || !IsHostKey(k) || IsToken(k) {
		t.Fatalf("bad key %q", k)
	}
	for _, bad := range []string{"", "sgh_", "sgl_" + k[4:], "sgh_" + strings.Repeat("A", 52), "sgh_" + strings.Repeat("a", 51)} {
		if IsHostKey(bad) {
			t.Errorf("%q is a key", bad)
		}
	}
}

func TestEnrollCheckRevokeRelease(t *testing.T) {
	fake := ostest.New(t)
	ctx := context.Background()
	r := newReg(t, fake.URL, "n1")
	line, lineSecret, err := r.Create(ctx, "Web servers", PurposeAgent, "sam")
	if err != nil {
		t.Fatal(err)
	}
	k, key, err := r.Enroll(ctx, line.ID, "Web-01", "10.0.0.5", "")
	if err != nil {
		t.Fatal(err)
	}
	if k.Host != "web-01" || k.TokenID != line.ID || k.TokenName != "Web servers" || k.Status != StateActive || k.EnrolledFrom != "10.0.0.5" || !IsHostKey(key) {
		t.Fatalf("enrolled %+v %q", k, key)
	}
	// Only the fingerprint is stored.
	raw, _ := json.Marshal(fake.Source("tt_runtime", hostDocID("web-01")))
	if strings.Contains(string(raw), key[4:]) {
		t.Fatalf("stored: %s", raw)
	}
	id, res := r.Check(key)
	if res != Valid || id.ID != line.ID || id.Name != "Web servers" || id.Purpose != PurposeAgent || id.Host != "web-01" || id.HostKey != k.ID {
		t.Fatalf("check %+v %v", id, res)
	}
	if !r.Enrolled("WEB-01") || r.Enrolled("web-02") {
		t.Error("Enrolled")
	}
	if !r.Active(k.ID) {
		t.Error("key not active")
	}
	if l, ok := r.Lookup(k.ID); !ok || l.ID != line.ID || l.Host != "web-01" {
		t.Errorf("lookup %+v", l)
	}
	forged := key[:len(key)-1] + map[bool]string{true: "b", false: "a"}[key[len(key)-1] == 'a']
	if _, res := r.Check(forged); res != Unknown {
		t.Errorf("forged: %v", res)
	}
	// The line's token still works, and is still the line's.
	if id, res := r.Check(lineSecret); res != Valid || id.Host != "" {
		t.Fatalf("line %+v %v", id, res)
	}

	// The name has one key: no second one, from any server.
	_, _, err = r.Enroll(ctx, line.ID, "web-01", "10.0.0.9", "")
	wantCode(t, err, CodeHostEnrolled)
	r2 := newReg(t, fake.URL, "n2")
	if err := r2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, res := r2.Check(key); res != Valid {
		t.Fatalf("other server: %v", res)
	}
	_, _, err = r2.Enroll(ctx, line.ID, "web-01", "10.0.0.9", "")
	wantCode(t, err, CodeHostEnrolled)

	// Revoked: refused, and the name stays taken.
	var hooked []string
	r.OnRevoke(func(_ context.Context, id string) (int, error) {
		hooked = append(hooked, id)
		return 1, nil
	})
	rk, n, err := r.RevokeHost(ctx, "web-01", "sam")
	if err != nil || rk.Status != StateRevoked || rk.RevokedBy != "sam" || n != 1 || len(hooked) != 1 || hooked[0] != k.ID {
		t.Fatalf("revoke %+v %d %v %v", rk, n, err, hooked)
	}
	if _, res := r.Check(key); res != Revoked {
		t.Fatalf("after revoke: %v", res)
	}
	if r.Active(k.ID) {
		t.Error("active after revoke")
	}
	_, _, err = r.Enroll(ctx, line.ID, "web-01", "10.0.0.9", "")
	wantCode(t, err, CodeHostRevoked)
	if err := r2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, res := r2.Check(key); res != Revoked {
		t.Fatalf("other server after revoke: %v", res)
	}

	// Released: the key is unknown and the name enrolls again.
	if _, _, err := r.ReleaseHost(ctx, "web-01", "sam"); err != nil {
		t.Fatal(err)
	}
	if _, res := r.Check(key); res != Unknown || r.Enrolled("web-01") {
		t.Fatalf("after release: %v", res)
	}
	k2, key2, err := r.Enroll(ctx, line.ID, "web-01", "10.0.0.9", "")
	if err != nil || key2 == key || k2.ID == k.ID {
		t.Fatalf("enroll again: %+v %v", k2, err)
	}
	_, _, err = r.ReleaseHost(ctx, "nobody", "sam")
	wantCode(t, err, CodeNotFound)

	// Installed again with another line: holding its key, the computer
	// moves to the new line; without it, it is refused.
	line2, _, err := r.Create(ctx, "Web servers (new)", PurposeAgent, "sam")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = r.Enroll(ctx, line2.ID, "web-01", "", key)
	wantCode(t, err, CodeHostEnrolled)
	hooked = nil
	k3, key3, err := r.Enroll(ctx, line2.ID, "web-01", "", key2)
	if err != nil || k3.TokenID != line2.ID {
		t.Fatalf("moved: %+v %v", k3, err)
	}
	if _, res := r.Check(key2); res != Unknown {
		t.Errorf("old key after the move: %v", res)
	}
	if id, res := r.Check(key3); res != Valid || id.ID != line2.ID || len(hooked) != 1 || hooked[0] != k2.ID {
		t.Errorf("new key: %+v %v %v", id, res, hooked)
	}
	if _, _, err := r.Revoke(ctx, line2.ID, "sam"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.ReleaseHost(ctx, "web-01", "sam"); err != nil {
		t.Fatal(err)
	}
	k2, key2, err = r.Enroll(ctx, line.ID, "web-01", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Revoking the line cuts off its keys, and removes their osquery hosts.
	hooked = nil
	if _, _, err := r.Revoke(ctx, line.ID, "sam"); err != nil {
		t.Fatal(err)
	}
	if _, res := r.Check(key2); res != Revoked {
		t.Fatalf("after line revoke: %v", res)
	}
	if len(hooked) != 2 || hooked[0] != line.ID || hooked[1] != k2.ID {
		t.Errorf("line revoke hooks %v", hooked)
	}
	if h, ok := r.Host("web-01"); !ok || h.Status != StateRevoked {
		t.Errorf("listed %+v", h)
	}
	_, _, err = r.Enroll(ctx, line.ID, "web-02", "", "")
	wantCode(t, err, CodeRevoked)
}

func TestEnrollLoadsWithHosts(t *testing.T) {
	fake := ostest.New(t)
	ctx := context.Background()
	r := newReg(t, fake.URL, "n1")
	line, _, err := r.Create(ctx, "Agents", PurposeAgent, "sam")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"b", "a", "c"} {
		if _, _, err := r.Enroll(ctx, line.ID, h, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	r2 := newReg(t, fake.URL, "n2")
	if err := r2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	hosts := r2.Hosts()
	if len(hosts) != 3 || hosts[0].Host != "a" || hosts[2].Host != "c" {
		t.Fatalf("hosts %+v", hosts)
	}
	_, _, err = r2.Enroll(ctx, line.ID, "", "", "")
	wantCode(t, err, CodeNameInvalid)
}

// SEC-576-2: a server that has not read a key made on another server yet
// reads the keys again instead of refusing it, and a computer whose name
// was released enrolls again while showing its old key.
func TestHostKeyFromAnotherServer(t *testing.T) {
	fake := ostest.New(t)
	ctx := context.Background()
	defer func(d time.Duration) { missReload = d }(missReload)
	missReload = 0
	a, b := newReg(t, fake.URL, "n1"), newReg(t, fake.URL, "n2")
	line, _, err := a.Create(ctx, "Agents", PurposeAgent, "sam")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Load(ctx); err != nil {
		t.Fatal(err)
	}
	_, key, err := a.Enroll(ctx, line.ID, "web-01", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if id, res := b.Check(key); res != Valid || id.Host != "web-01" {
		t.Fatalf("other server: %+v %v", id, res)
	}
	// Within missReload of a read, an unknown key is refused without one.
	missReload = time.Hour
	if _, res := b.Check("sgh_" + strings.Repeat("a", 52)); res != Unknown {
		t.Errorf("unknown key: %v", res)
	}
	missReload = 0
	if _, _, err := a.ReleaseHost(ctx, "web-01", "sam"); err != nil {
		t.Fatal(err)
	}
	if _, key2, err := b.Enroll(ctx, line.ID, "web-01", "", key); err != nil || key2 == key {
		t.Fatalf("enroll after release with the old key: %v", err)
	}
}
