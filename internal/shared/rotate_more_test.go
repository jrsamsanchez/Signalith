package shared

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

// A live member that does not pick up the new key stops the rotation
// after MemberWait, naming it; asked again, the rotation goes on from
// where it stopped once the member runs again.
func TestKeyRotationWaitsForALiveMember(t *testing.T) {
	rc := newRotationCluster(t)
	old := rc.a.key().ID()
	done := make(chan error, 1)
	go func() {
		_, err := rc.a.rt.RotateKey(context.Background(), RotateOptions{By: "admin", Reason: "rotate-key", Poll: time.Second, MemberWait: 5 * time.Second})
		done <- err
	}()
	var err error
wait:
	for range 500 {
		rc.b.step()
		rc.heartbeats()
		select {
		case err = <-done:
			break wait
		case <-time.After(5 * time.Millisecond):
		}
		if rc.e.clock.Waiting() > 0 {
			rc.e.clock.Advance(time.Second)
		}
	}
	if err == nil || !strings.Contains(err.Error(), "siem-c did not pick up the new cluster key in time") {
		t.Fatalf("RotateKey = %v", err)
	}
	kr, _ := rc.a.rt.Keyring().Get()
	n, _ := kr.Rotation()
	if n == nil || n.Phase != PhaseDistribute || kr.Active != old {
		t.Fatalf("rotation %+v, active %s", n, kr.Active)
	}
	if st := rc.a.rt.Rotation(); st.InProgress == nil || st.InProgress.KID != n.KID {
		t.Errorf("status = %+v", st)
	}

	res, err := rc.rotate(RotateOptions{By: "admin", Reason: "rotate-key"})
	if err != nil {
		t.Fatal(err)
	}
	if res.KID != n.KID || len(res.Skipped) != 0 {
		t.Errorf("result %+v, want the rotation to %s", res, n.KID)
	}
	mustContain(t, "log", rc.c.logs.String(), "picked up the new cluster key")
}

// Only the member that runs the background jobs rotates.
func TestKeyRotationRefusals(t *testing.T) {
	rc := newRotationCluster(t)
	ctx := context.Background()
	if _, err := rc.b.rt.RotateKey(ctx, RotateOptions{By: "admin"}); err == nil || !strings.Contains(err.Error(), "lost the job lease") {
		t.Errorf("a rotation without the lease = %v", err)
	}
	ro := rc.e.server("siem-r", func(o *RuntimeOptions) {
		o.ReadOnly = true
		o.KeyFile = writeKeyFile(t, rc.a.key())
		o.Peers = rc.peers.get
	})
	ro.step()
	if m := ro.mode(); m == ModeMember {
		if _, err := ro.rt.RotateKey(ctx, RotateOptions{By: "admin"}); err == nil || !strings.Contains(err.Error(), "runs on the server that runs the background jobs") {
			t.Errorf("a rotation on a read-only server = %v", err)
		}
	}
	e := newEnv(t)
	lone := e.server("siem-z", nil)
	var paused *PausedError
	if _, err := lone.rt.RotateKey(ctx, RotateOptions{By: "admin"}); !errors.As(err, &paused) {
		t.Errorf("a rotation on a server not in a cluster = %v", err)
	}
}

func TestJoinNames(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
	}{
		{nil, ""}, {[]string{"a"}, "a"}, {[]string{"a", "b"}, "a and b"}, {[]string{"a", "b", "c"}, "a, b and c"},
	} {
		if got := joinNames(c.in); got != c.want {
			t.Errorf("joinNames(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Signing again stops at a write OpenSearch refuses, naming the document,
// and leaves a document no key signed as it is.
func TestResignOldFaults(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	d := NewDoc[testBody](a, "users", "users", 1)
	if _, err := d.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "jlee"; return nil }); err != nil {
		t.Fatal(err)
	}
	stranger, err := NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	e.putSigned(stranger, "forged", "settings", 1, 1, `{"x":1}`, nil)
	k, err := NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	e.os.SetFault(func(method, path string) *ostest.Fault {
		if method == http.MethodPut && strings.Contains(path, "/_doc/users") {
			return &ostest.Fault{Status: http.StatusInternalServerError, Type: "internal_error"}
		}
		return nil
	})
	_, _, err = resignOld(ctx, e.c, testPrefix, k, NewKeySet(e.key), "siem-a")
	if err == nil || !strings.Contains(err.Error(), "users") {
		t.Errorf("resignOld = %v", err)
	}
	e.os.SetFault(nil)
	n, refused, err := resignOld(ctx, e.c, testPrefix, k, NewKeySet(e.key), "siem-a")
	if err != nil || n == 0 || len(refused) != 1 || refused[0] != "forged" {
		t.Errorf("resignOld = %d, %v, %v", n, refused, err)
	}
	// Signed already: nothing to do.
	if n, _, err := resignOld(ctx, e.c, testPrefix, k, NewKeySet(k, e.key), "siem-a"); err != nil || n != 0 {
		t.Errorf("again = %d, %v", n, err)
	}
	e.os.SetFault(func(method, path string) *ostest.Fault {
		if strings.Contains(path, "_search") {
			return &ostest.Fault{Status: http.StatusInternalServerError, Type: "internal_error"}
		}
		return nil
	})
	if _, _, err := resignOld(ctx, e.c, testPrefix, k, NewKeySet(e.key), "siem-a"); err == nil {
		t.Error("resignOld with the search failing")
	}
}
