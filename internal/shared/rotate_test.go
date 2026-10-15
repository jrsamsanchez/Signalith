package shared

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// rotationCluster is three members on the fake: siem-a runs the
// background jobs, siem-b is live, and siem-c is the one a test takes
// offline or removes.
type rotationCluster struct {
	t       *testing.T
	e       *testEnv
	a, b, c *testServer
	peers   peerList
	// cOffline is how long siem-c's heartbeat has been stopped, 0 while
	// it is live.
	cOffline time.Duration
}

func rotationImporters() []Importer {
	return []Importer{{Name: ImportUsers, MinLevel: LevelSharedUsers}, {Name: ImportDirectory, MinLevel: LevelSharedUsers},
		{Name: ImportSettings, MinLevel: LevelSharedSettings}}
}

func newRotationCluster(t *testing.T) *rotationCluster {
	t.Helper()
	rc := &rotationCluster{t: t, e: newEnv(t)}
	opts := func(key *ClusterKey) func(o *RuntimeOptions) {
		return func(o *RuntimeOptions) {
			o.Peers = rc.peers.get
			o.Importers = rotationImporters()
			if key != nil {
				o.KeyFile = writeKeyFile(t, key)
			}
		}
	}
	rc.a = rc.e.server("siem-a", opts(nil))
	rc.a.holds.Store(true)
	rc.a.step()
	rc.a.wantMode(ModeMember)
	k := rc.a.key()
	rc.b = rc.e.server("siem-b", opts(k))
	rc.c = rc.e.server("siem-c", opts(k))
	for range 2 {
		rc.b.step()
		rc.c.step()
		rc.a.step()
	}
	kr, _ := rc.a.rt.Keyring().Get()
	for _, id := range []string{"n_siem-a", "n_siem-b", "n_siem-c"} {
		if _, ok := kr.Members[id]; !ok {
			t.Fatalf("%s is not in the keyring: %+v", id, kr.Members)
		}
	}
	if !rc.a.rt.KeyRotation() {
		t.Fatal("key rotation is off at the level a new cluster starts at")
	}
	rc.heartbeats()
	return rc
}

func peerOf(s *testServer) Peer {
	st := s.rt.Status()
	return Peer{NodeID: s.rt.opts.Self.NodeID, Name: s.rt.opts.Self.Name, Live: true, LevelMax: LevelMax,
		KeyIDs: st.KeyIDs, ClusterKID: st.ClusterKID}
}

// heartbeats sets the peers from each server's status.
func (rc *rotationCluster) heartbeats() {
	c := peerOf(rc.c)
	if rc.cOffline > 0 {
		c.Live, c.SeenAgo = false, rc.cOffline
	}
	rc.peers.set(peerOf(rc.a), peerOf(rc.b), c)
}

// rotate runs a key rotation on siem-a while siem-b (and siem-c while it
// is live) run their loops and heartbeats.
func (rc *rotationCluster) rotate(o RotateOptions) (*RotateResult, error) {
	rc.t.Helper()
	o.Poll, o.MemberWait = time.Second, time.Minute
	type out struct {
		res *RotateResult
		err error
	}
	done := make(chan out, 1)
	go func() {
		res, err := rc.a.rt.RotateKey(context.Background(), o)
		done <- out{res, err}
	}()
	for range 500 {
		rc.b.step()
		if rc.cOffline == 0 {
			rc.c.step()
		}
		rc.heartbeats()
		select {
		case r := <-done:
			return r.res, r.err
		case <-time.After(5 * time.Millisecond):
		}
		if rc.e.clock.Waiting() > 0 {
			rc.e.clock.Advance(time.Second)
		}
	}
	rc.t.Fatal("the key rotation did not end")
	return nil, nil
}

// R1: a rotation hands the new key to every live member, makes it the one
// that signs, signs every shared document again and retires the old key;
// a member that was offline catches up from its copy when it is back.
func TestKeyRotation(t *testing.T) {
	rc := newRotationCluster(t)
	old := rc.a.key().ID()
	rc.cOffline = OfflineSkip + time.Minute
	rc.heartbeats()

	var steps []string
	res, err := rc.rotate(RotateOptions{By: "admin", Reason: "rotate-key",
		Progress: func(step string, done, total int) { steps = append(steps, step) }})
	if err != nil {
		t.Fatal(err)
	}
	if res.From != old || res.KID == old || !slices.Equal(res.Skipped, []string{"siem-c"}) || res.Resigned == 0 {
		t.Fatalf("result = %+v", res)
	}
	if len(steps) != len(rotationSteps)+1 {
		t.Errorf("progress = %v", steps)
	}
	kr, _ := rc.a.rt.Keyring().Get()
	if kr.Active != res.KID || len(kr.Keys) != 1 || kr.Keys[0].KID != res.KID {
		t.Fatalf("keyring active %s, keys %+v", kr.Active, kr.Keys)
	}
	if n, _ := kr.Rotation(); n != nil {
		t.Errorf("the rotation is still in progress: %+v", n)
	}
	if kr.CatchUp == nil || kr.CatchUp.KID != res.KID || len(kr.CatchUp.Copies) != 3 {
		t.Fatalf("catch up = %+v", kr.CatchUp)
	}
	env, _ := clusterBody(t, rc.e)
	if macKID(env.MAC) != res.KID {
		t.Errorf("the cluster document is signed with %s", macKID(env.MAC))
	}
	rc.a.step()
	rc.b.step()
	for _, s := range []*testServer{rc.a, rc.b} {
		s.wantMode(ModeMember)
		if s.key().ID() != res.KID || slices.Contains(s.rt.Hub().Keys().IDs(), old) {
			t.Errorf("%s signs with %s and accepts %v", s.rt.opts.Self.Name, s.key().ID(), s.rt.Hub().Keys().IDs())
		}
		// The retired key still passes the cookie check while the
		// copies are kept.
		if s.rt.Hub().Keys().CookieKey(old) == nil {
			t.Errorf("%s no longer checks cookies made with the retired key", s.rt.opts.Self.Name)
		}
	}
	if st := rc.a.rt.Rotation(); !st.On || st.Active != res.KID || st.InProgress != nil || st.CatchUpUntil == "" {
		t.Errorf("rotation status = %+v", st)
	}

	// siem-c is back with only the old key.
	rc.cOffline = 0
	for range 3 {
		rc.c.step()
	}
	rc.c.wantMode(ModeMember)
	if rc.c.key().ID() != res.KID {
		t.Fatalf("siem-c signs with %s after catching up", rc.c.key().ID())
	}
	mustContain(t, "log", rc.c.logs.String(), "caught up with a rotation of the cluster key")
}

// R2: a removed server gets no copy of the new key: once the rotation is
// done its copy of the old key opens nothing, and it never adds itself
// back to the keyring.
func TestKeyRotationAfterRemove(t *testing.T) {
	rc := newRotationCluster(t)
	rc.cOffline = OfflineSkip + time.Minute
	rc.heartbeats()
	rec, err := rc.a.rt.RemoveMember(context.Background(), "n_siem-c", "", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Name != "siem-c" || rec.Fingerprint == "" {
		t.Errorf("removed = %+v", rec)
	}
	res, err := rc.rotate(RotateOptions{By: "admin", Reason: "remove siem-c"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("skipped %v: a removed server is not waited for", res.Skipped)
	}
	if err := rc.a.rt.MarkRotated(context.Background(), "n_siem-c"); err != nil {
		t.Fatal(err)
	}
	kr, _ := rc.a.rt.Keyring().Get()
	if _, ok := kr.CatchUp.Copies["n_siem-c"]; ok {
		t.Fatal("the removed server got a copy of the new key")
	}
	if rm := rc.a.rt.Removed(); len(rm) != 1 || !rm[0].Rotated {
		t.Errorf("removed list = %+v", rm)
	}

	rc.cOffline = 0
	for range 3 {
		rc.c.step()
	}
	rc.c.wantMode(ModeKeyMissing)
	if why := rc.c.rt.NotEligible(); why == "" {
		t.Error("the removed server may run the background jobs")
	}
	if slices.Contains(rc.c.rt.Hub().Keys().IDs(), res.KID) {
		t.Fatal("the removed server holds the new key")
	}
	kr, _ = rc.a.rt.Keyring().Get()
	if _, ok := kr.Members["n_siem-c"]; ok {
		t.Error("the removed server added itself back to the keyring")
	}

	// The last member cannot be removed.
	if _, err := rc.a.rt.RemoveMember(context.Background(), "n_siem-b", "", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := rc.a.rt.RemoveMember(context.Background(), "n_siem-a", "", "admin"); !errors.Is(err, ErrLastMember) {
		t.Errorf("removing the last member: %v", err)
	}
}

// R3: a resealer that fails stops the rotation before the old key is
// retired, so everything sealed with it still opens; asked again, the
// rotation goes on from where it stopped.
func TestKeyRotationResealerFails(t *testing.T) {
	rc := newRotationCluster(t)
	old := rc.a.key().ID()
	var fail atomic.Bool
	fail.Store(true)
	var runs atomic.Int32
	rs := func(context.Context) error {
		runs.Add(1)
		if fail.Load() {
			return errors.New("cannot reach OpenSearch")
		}
		return nil
	}
	res, err := rc.rotate(RotateOptions{By: "admin", Resealers: []Resealer{rs}})
	if err == nil {
		t.Fatal("the rotation finished although a resealer failed")
	}
	kr, _ := rc.a.rt.Keyring().Get()
	n, _ := kr.Rotation()
	if n == nil || n.Phase != PhaseResign || kr.Active != res.KID || !slices.Contains(kr.KIDs(), old) {
		t.Fatalf("keyring after the failure: active %s, keys %v, next %+v", kr.Active, kr.KIDs(), n)
	}
	if st := rc.a.rt.Rotation(); st.InProgress == nil || st.InProgress.Copies != nil {
		t.Errorf("status shows %+v", st.InProgress)
	}

	fail.Store(false)
	again, err := rc.rotate(RotateOptions{By: "admin", Resealers: []Resealer{rs}})
	if err != nil {
		t.Fatal(err)
	}
	if again.KID != res.KID || runs.Load() != 2 {
		t.Errorf("the second run rotated to %s (first %s), resealer ran %d times", again.KID, res.KID, runs.Load())
	}
	kr, _ = rc.a.rt.Keyring().Get()
	if slices.Contains(kr.KIDs(), old) {
		t.Error("the old key is still listed")
	}
}

// A copy of the new key is opened only with a proof made with the old
// key, and only by the member it was sealed to.
func TestKeyCopyProof(t *testing.T) {
	old, _ := NewClusterKey()
	k, _ := NewClusterKey()
	forger, _ := NewClusterKey()
	nk, _ := NewNodeKey()
	m := KeyringMember{Name: "siem-b", NodePub: nk.PublicText()}
	c, err := sealCopy(k, old, "n_siem-b", m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := openCopy(nk, "n_siem-b", k.ID(), c, old)
	if err != nil || got.ID() != k.ID() {
		t.Fatalf("open = %v, %v", got, err)
	}
	if _, err := openCopy(nk, "n_siem-b", k.ID(), c, forger); err == nil {
		t.Error("opened a copy whose proof another key made")
	}
	forged, _ := sealCopy(forger, forger, "n_siem-b", m)
	if _, err := openCopy(nk, "n_siem-b", forger.ID(), forged, old); err == nil {
		t.Error("opened a copy of a key slipped in without the old key")
	}
	if _, err := openCopy(nk, "n_siem-c", k.ID(), c, nil); err == nil {
		t.Error("another member opened the copy")
	}
}

func TestReseal(t *testing.T) {
	old, _ := NewClusterKey()
	k, _ := NewClusterKey()
	sealed, err := old.SecretsKey().Seal("feeds.token", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	keys := NewKeySet(k, old)
	again, err := Reseal(keys, "feeds.token", sealed)
	if err != nil {
		t.Fatal(err)
	}
	if again == sealed {
		t.Fatal("the value was not sealed again")
	}
	if plain, err := k.SecretsKey().Open("feeds.token", again); err != nil || plain != "s3cret" {
		t.Fatalf("open with the new key = %q, %v", plain, err)
	}
	if same, err := Reseal(keys, "feeds.token", again); err != nil || same != again {
		t.Errorf("a value sealed with the active key changed: %v", err)
	}
	if empty, err := Reseal(keys, "feeds.token", ""); err != nil || empty != "" {
		t.Errorf("an empty value: %q, %v", empty, err)
	}
	if _, err := Reseal(NewKeySet(k), "feeds.token", sealed); err == nil {
		t.Error("resealed a value sealed with a key it does not have")
	}
	if _, err := Reseal(keys, "other.field", sealed); err == nil {
		t.Error("resealed a value under another field")
	}
}
