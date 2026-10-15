package shared

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Rotating the cluster key (signalith cluster rotate-key, the Rotate
// cluster key button, and by default every removal of a server) gives the
// cluster a new key, so a copy of the old one, such as a removed server's,
// opens and signs nothing new. The server that runs the background jobs
// does it, in steps recorded in the keyring's next, so another server
// that takes the jobs over goes on from where it stopped:
//
//  1. distribute: it makes the new key, keeps it, lists it in the
//     keyring's keys (so every member accepts what it signs) and writes a
//     copy sealed to each member's node key in next. Each member opens its
//     copy, keeps it, and lists it in its heartbeat (key_ids).
//  2. switch: once every live member has it (one offline for more than 10
//     minutes is not waited for), the keyring makes the new key active,
//     and every member signs with it (cluster_kid in its heartbeat).
//  3. resign: once every live member signs with it, each feature that
//     seals values with the cluster key seals them again (Resealer), and
//     every document of the shared settings and every session is signed
//     again with the new key.
//  4. finish: the old key leaves the keyring. Only the new key verifies
//     from then on. The old key's file stays, to open archives sealed with
//     it, and the session cookies it made pass the cookie check for 7 more
//     days (the sessions behind them now carry new-key MACs). The copies
//     move to catch_up for 7 days.
//
// A member that was offline finds the shared settings signed with a key
// it lacks: it reads its copy from next or catch_up, checks the proof
// made with the old key, which it has, opens the copy with its node key,
// checks the keyring with the new key and goes on. A removed server is no
// longer a member, so it gets no copy.

// Rotation phases, in RotationNext.Phase.
const (
	PhaseDistribute = "distribute"
	PhaseSwitch     = "switch"
	PhaseResign     = "resign"
)

// CatchUpFor is how long the copies of the last rotation's key are kept.
const CatchUpFor = 7 * 24 * time.Hour

// KeyCopy is the new cluster key sealed to one member's node key
// (SealToNode), with Proof, an HMAC under the old key's MAC key over the
// member, the new key's id and the sealed copy: whoever can write to
// OpenSearch but has no cluster key cannot slip a key of their own to a
// member that missed the rotation.
type KeyCopy struct {
	Sealed string `json:"sealed"`
	Proof  string `json:"proof"`
}

// RotationNext is a rotation of the cluster key in progress, the
// keyring's next.
type RotationNext struct {
	// KID is the new key's id, and From the key it replaces.
	KID   string `json:"kid"`
	From  string `json:"from"`
	Phase string `json:"phase"`
	// Copies holds each member's copy of the new key, by node id.
	Copies    map[string]KeyCopy `json:"copies"`
	StartedBy string             `json:"started_by"`
	StartedAt string             `json:"started_at"`
	Reason    string             `json:"reason,omitempty"`
}

// CatchUp keeps the copies of the last rotation's key, until Until, for
// the members that were offline during it.
type CatchUp struct {
	KID    string             `json:"kid"`
	From   string             `json:"from"`
	Copies map[string]KeyCopy `json:"copies"`
	Until  string             `json:"until"`
}

// Rotation returns the rotation in progress, nil when there is none.
func (k *KeyringBody) Rotation() (*RotationNext, error) {
	if len(k.Next) == 0 || string(k.Next) == "null" {
		return nil, nil
	}
	var n RotationNext
	if err := json.Unmarshal(k.Next, &n); err != nil {
		return nil, fmt.Errorf("the key rotation in progress cannot be read: %w", err)
	}
	if n.KID == "" {
		return nil, nil
	}
	return &n, nil
}

// setRotation records n as the rotation in progress; nil ends it.
func (k *KeyringBody) setRotation(n *RotationNext) error {
	if n == nil {
		k.Next = nil
		return nil
	}
	raw, err := json.Marshal(n)
	if err != nil {
		return err
	}
	k.Next = raw
	return nil
}

// catchUpLive returns the catch-up copies while they are kept.
func (k *KeyringBody) catchUpLive(now time.Time) *CatchUp {
	if k.CatchUp == nil {
		return nil
	}
	until, err := time.Parse(time.RFC3339Nano, k.CatchUp.Until)
	if err != nil || !now.Before(until) {
		return nil
	}
	return k.CatchUp
}

// copyProof is the proof of a copy, under the old key.
func copyProof(old *ClusterKey, nodeID, kid, sealed string) string {
	m := hmac.New(sha256.New, old.macKey)
	m.Write([]byte("sgl-key-copy-v1\x00" + nodeID + "\x00" + kid + "\x00" + sealed))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// sealCopy seals k to a member, with the proof under old.
func sealCopy(k, old *ClusterKey, nodeID string, m KeyringMember) (KeyCopy, error) {
	pub, err := base64.StdEncoding.DecodeString(m.NodePub)
	if err != nil {
		return KeyCopy{}, fmt.Errorf("the node key of %s cannot be read: %w", cmp.Or(m.Name, nodeID), err)
	}
	sealed, err := SealToNode(pub, nodeID, k.ID(), k.raw)
	if err != nil {
		return KeyCopy{}, fmt.Errorf("the node key of %s: %w", cmp.Or(m.Name, nodeID), err)
	}
	return KeyCopy{Sealed: sealed, Proof: copyProof(old, nodeID, k.ID(), sealed)}, nil
}

// openCopy opens this server's copy c of the key kid with its node key,
// after checking its proof with old (skipped when old is nil: the copy
// was read from a keyring this server verified).
func openCopy(nk *NodeKey, nodeID, kid string, c KeyCopy, old *ClusterKey) (*ClusterKey, error) {
	if old != nil {
		want := copyProof(old, nodeID, kid, c.Sealed)
		if !hmac.Equal([]byte(want), []byte(c.Proof)) {
			return nil, errors.New("its copy of the new cluster key does not carry a proof made with the previous key")
		}
	}
	raw, err := nk.OpenFromNode(nodeID, kid, c.Sealed)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	k, err := ClusterKeyFrom(raw)
	if err != nil {
		return nil, err
	}
	if k.ID() != kid {
		return nil, fmt.Errorf("its copy holds cluster key %s, not %s", k.ID(), kid)
	}
	return k, nil
}

// pickUpKey keeps this server's copy of the key a rotation in progress
// moves to, from a keyring it verified, and reports whether it kept one.
func (rt *Runtime) pickUpKey(kr *KeyringBody) bool {
	n, err := kr.Rotation()
	if err != nil || n == nil || rt.opts.ReadOnly {
		return false
	}
	self := rt.opts.Self.NodeID
	c, ok := n.Copies[self]
	if !ok {
		return false
	}
	keys, err := rt.readKeys()
	if err != nil || keys.get(n.KID) != nil {
		return false
	}
	nk, err := rt.nodeKey()
	if err != nil {
		return false
	}
	k, err := openCopy(nk, self, n.KID, c, nil)
	if err != nil {
		rt.log.Warn("could not open this server's copy of the new cluster key", "kid", n.KID, "err", err)
		return false
	}
	if err := rt.keyStore().SaveClusterKey(k); err != nil {
		rt.log.Warn("could not keep the new cluster key", "kid", n.KID, "err", err)
		return false
	}
	rt.log.Info("this server picked up the new cluster key of a key rotation", "audit", true, "kid", n.KID)
	return true
}

// catchUp is for a member that finds the shared settings signed with a
// key it lacks: it reads the keyring as stored, takes its copy from a
// rotation in progress or the last one's catch-up copies, checks the
// copy's proof with the old key, which it must have, opens it, checks
// the keyring with the new key, and keeps the key. It reports whether it
// kept one.
func (rt *Runtime) catchUp(ctx context.Context) bool {
	c, prefix := rt.target()
	if c == nil || rt.opts.ReadOnly {
		return false
	}
	keys, err := rt.readKeys()
	if err != nil || len(keys.all) == 0 {
		return false
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	src, _, found, err := c.Get(rctx, ConfigIndex(prefix), KeyringDocID)
	cancel()
	if err != nil || !found {
		return false
	}
	var e Envelope
	if json.Unmarshal(src, &e) != nil || e.ID != KeyringDocID || e.Deleted {
		return false
	}
	var kr KeyringBody
	if json.Unmarshal([]byte(e.Body), &kr) != nil {
		return false
	}
	self := rt.opts.Self.NodeID
	type offer struct {
		kid, from string
		c         KeyCopy
	}
	var offers []offer
	if n, _ := kr.Rotation(); n != nil {
		if cp, ok := n.Copies[self]; ok {
			offers = append(offers, offer{n.KID, n.From, cp})
		}
	}
	if cu := kr.catchUpLive(rt.clock.Now()); cu != nil {
		if cp, ok := cu.Copies[self]; ok {
			offers = append(offers, offer{cu.KID, cu.From, cp})
		}
	}
	if len(offers) == 0 {
		return false
	}
	nk, err := rt.nodeKey()
	if err != nil {
		return false
	}
	for _, o := range offers {
		if keys.get(o.kid) != nil {
			continue
		}
		old := keys.get(o.from)
		if old == nil {
			continue
		}
		k, err := openCopy(nk, self, o.kid, o.c, old)
		if err != nil {
			rt.log.Warn("could not catch up with a rotation of the cluster key", "kid", o.kid, "err", err)
			continue
		}
		if err := Verify(NewKeySet(k, keys.all...), KeyringDocID, &e); err != nil {
			rt.log.Warn("could not catch up with a rotation of the cluster key: the keyring does not verify", "kid", o.kid, "err", err)
			continue
		}
		if err := rt.keyStore().SaveClusterKey(k); err != nil {
			rt.log.Warn("could not keep the new cluster key", "kid", o.kid, "err", err)
			return false
		}
		rt.log.Info("this server caught up with a rotation of the cluster key it missed", "audit", true, "kid", o.kid)
		// The keyring in memory is the one before the rotation, which
		// does not list the new key: use the one just verified.
		rt.useListed(kr.KIDs())
		if now, err := rt.readKeys(); err == nil && rt.Hub().Keys().Active() != nil {
			rt.setKeys(k, now, kr.KIDs())
		}
		return true
	}
	return false
}

// Resealer seals again, with the active cluster key, the values one
// feature seals with the cluster key, and signs again what it signs
// outside the shared documents (the sessions). It opens with any key the
// server accepts. A key rotation runs every resealer between making the
// new key active and dropping the old one.
type Resealer func(ctx context.Context) error

// RotateOptions are how a key rotation runs.
type RotateOptions struct {
	// By is who asked for it, and Reason why ("rotate-key", or the
	// removal of a server).
	By, Reason string
	// Resealers seal the features' values again.
	Resealers []Resealer
	// Progress hears of each step: its name, and how many of the steps
	// are done.
	Progress func(step string, done, total int)
	// MemberWait is how long a live member may take to pick up the key
	// and to sign with it (0: 10 minutes); Poll how often the members'
	// heartbeats are looked at (0: 2 seconds).
	MemberWait, Poll time.Duration
}

// OfflineSkip is how long a member must have been offline for a key
// rotation not to wait for it: it catches up when it is back.
const OfflineSkip = 10 * time.Minute

// RotateResult is how a key rotation went.
type RotateResult struct {
	KID  string `json:"kid"`
	From string `json:"from"`
	// Skipped names the members that were offline: they catch up when
	// they are back, within CatchUpFor.
	Skipped  []string `json:"skipped,omitempty"`
	Resigned int      `json:"resigned"`
}

// rotationSteps names the steps, for Progress.
var rotationSteps = []string{"make the new key", "hand it to every server", "sign with it", "seal and sign everything again", "retire the old key"}

// ErrNoRotation is a rotation asked of a cluster below LevelKeyRotation.
var ErrNoRotation = errors.New("rotating the cluster key needs every server on a version that supports it: upgrade them first")

// RotateKey rotates the cluster key, or goes on with the rotation in
// progress. Only the server that runs the background jobs does it.
func (rt *Runtime) RotateKey(ctx context.Context, o RotateOptions) (*RotateResult, error) {
	if m, why := rt.Mode(); m != ModeMember {
		return nil, &PausedError{Why: cmp.Or(why, m.Text())}
	}
	if !rt.KeyRotation() {
		return nil, ErrNoRotation
	}
	if rt.opts.ReadOnly {
		return nil, errors.New("a key rotation runs on the server that runs the background jobs")
	}
	if o.MemberWait == 0 {
		o.MemberWait = 10 * time.Minute
	}
	if o.Poll == 0 {
		o.Poll = 2 * time.Second
	}
	progress := func(i int) {
		if o.Progress != nil {
			o.Progress(rotationSteps[min(i, len(rotationSteps)-1)], i, len(rotationSteps))
		}
	}
	check := func() error {
		if rt.opts.LeaseCheck != nil {
			return rt.opts.LeaseCheck(ctx)
		}
		return nil
	}
	if err := check(); err != nil {
		return nil, err
	}
	progress(0)
	n, err := rt.startRotation(ctx, o)
	if err != nil {
		return nil, err
	}
	res := &RotateResult{KID: n.KID, From: n.From}
	if n.Phase == PhaseDistribute {
		progress(1)
		if res.Skipped, err = rt.waitMembers(ctx, o, n.KID, func(p Peer) bool { return slices.Contains(p.KeyIDs, n.KID) }); err != nil {
			return res, err
		}
		if err := check(); err != nil {
			return res, err
		}
		if n, err = rt.advance(ctx, o.By, n.KID, PhaseSwitch); err != nil {
			return res, err
		}
	}
	if n.Phase == PhaseSwitch {
		progress(2)
		if res.Skipped, err = rt.waitMembers(ctx, o, n.KID, func(p Peer) bool { return p.ClusterKID == n.KID }); err != nil {
			return res, err
		}
		if err := check(); err != nil {
			return res, err
		}
		if n, err = rt.advance(ctx, o.By, n.KID, PhaseResign); err != nil {
			return res, err
		}
	}
	progress(3)
	for _, rs := range o.Resealers {
		if err := rs(ctx); err != nil {
			return res, fmt.Errorf("sealing the shared secrets again with the new key: %w", err)
		}
	}
	k := rt.Hub().Keys().Get(n.KID)
	if k == nil {
		return res, errors.New("this server does not have the new cluster key")
	}
	c, prefix := rt.target()
	if res.Resigned, err = resignOld(ctx, c, prefix, k, rt.Hub().opts.NodeName); err != nil {
		return res, err
	}
	if err := check(); err != nil {
		return res, err
	}
	progress(4)
	if err := rt.finishRotation(ctx, o.By, n); err != nil {
		return res, err
	}
	progress(len(rotationSteps))
	rt.log.Info("rotated the cluster key", "audit", true, "by", o.By, "reason", o.Reason, "kid", n.KID, "from", n.From,
		"skipped", strings.Join(res.Skipped, ", "), "resigned", res.Resigned)
	return res, nil
}

// startRotation makes the new key and records the rotation, or returns
// the one in progress, making sure this server has its key.
func (rt *Runtime) startRotation(ctx context.Context, o RotateOptions) (*RotationNext, error) {
	kdoc := rt.Keyring()
	kr, ok := kdoc.Get()
	if !ok {
		return nil, errors.New("the keyring cannot be read")
	}
	if n, err := kr.Rotation(); err != nil {
		return nil, err
	} else if n != nil {
		if rt.Hub().Keys().Get(n.KID) == nil {
			if !rt.pickUpKey(kr) {
				return nil, fmt.Errorf("a rotation to cluster key %s is in progress, and this server has no copy of that key", n.KID)
			}
			rt.newKeys()
		}
		return n, nil
	}
	old := rt.Hub().Keys().Active()
	if old == nil {
		return nil, errors.New("this server has no cluster key")
	}
	k, err := NewClusterKey()
	if err != nil {
		return nil, err
	}
	n := &RotationNext{KID: k.ID(), From: old.ID(), Phase: PhaseDistribute, Copies: map[string]KeyCopy{},
		StartedBy: o.By, StartedAt: rt.Hub().now(), Reason: o.Reason}
	for id, m := range kr.Members {
		c, err := sealCopy(k, old, id, m)
		if err != nil {
			return nil, err
		}
		n.Copies[id] = c
	}
	if _, listed := kr.Members[rt.opts.Self.NodeID]; !listed {
		return nil, errors.New("this server is not in the keyring yet; try again in a moment")
	}
	// Kept before anyone may sign with it.
	if err := rt.keyStore().SaveClusterKey(k); err != nil {
		return nil, err
	}
	errBusy := errors.New("another rotation of the cluster key started meanwhile")
	_, err = kdoc.Mutate(ctx, "signalith", func(b *KeyringBody) error {
		if cur, err := b.Rotation(); err != nil || cur != nil {
			return errBusy
		}
		if b.Active != old.ID() {
			return errBusy
		}
		for id := range b.Members {
			if _, ok := n.Copies[id]; !ok {
				return errBusy
			}
		}
		b.Keys = append(slices.DeleteFunc(b.Keys, func(ki KeyInfo) bool { return ki.KID == k.ID() }),
			KeyInfo{KID: k.ID(), CreatedAt: n.StartedAt, CreatedBy: rt.opts.Self.Name})
		b.CatchUp = nil
		return b.setRotation(n)
	})
	if err != nil {
		return nil, err
	}
	rt.useListed(append(kr.KIDs(), k.ID()))
	rt.newKeys()
	rt.log.Info("started a rotation of the cluster key", "audit", true, "by", o.By, "reason", o.Reason, "kid", k.ID(), "from", old.ID())
	return n, nil
}

// advance moves the rotation to the key kid on to phase, making the new
// key active from the switch on.
func (rt *Runtime) advance(ctx context.Context, by, kid, phase string) (*RotationNext, error) {
	var out *RotationNext
	_, err := rt.Keyring().Mutate(ctx, "signalith", func(b *KeyringBody) error {
		n, err := b.Rotation()
		if err != nil {
			return err
		}
		if n == nil || n.KID != kid {
			return errors.New("the rotation of the cluster key was changed meanwhile")
		}
		n.Phase = phase
		if phase == PhaseSwitch || phase == PhaseResign {
			b.Active = kid
		}
		out = n
		return b.setRotation(n)
	})
	if err != nil {
		return nil, err
	}
	rt.newKeys()
	return out, nil
}

// finishRotation drops the old key from the keyring and keeps the
// copies for catching up.
func (rt *Runtime) finishRotation(ctx context.Context, by string, n *RotationNext) error {
	until := rt.clock.Now().Add(CatchUpFor).UTC().Format(time.RFC3339Nano)
	_, err := rt.Keyring().Mutate(ctx, "signalith", func(b *KeyringBody) error {
		cur, err := b.Rotation()
		if err != nil {
			return err
		}
		if cur == nil || cur.KID != n.KID {
			return errors.New("the rotation of the cluster key was changed meanwhile")
		}
		b.Active = n.KID
		b.Keys = slices.DeleteFunc(b.Keys, func(ki KeyInfo) bool { return ki.KID != n.KID })
		copies := map[string]KeyCopy{}
		for id, c := range cur.Copies {
			// Only for servers still members: one removed meanwhile gets
			// none.
			if _, ok := b.Members[id]; ok {
				copies[id] = c
			}
		}
		b.CatchUp = &CatchUp{KID: n.KID, From: n.From, Copies: copies, Until: until}
		return b.setRotation(nil)
	})
	if err != nil {
		return err
	}
	if kr, ok := rt.Keyring().Get(); ok {
		rt.useListed(kr.KIDs())
	}
	rt.newKeys()
	return nil
}

// waitMembers waits until every member of the keyring that is live meets
// done, and returns the names of those offline long enough not to wait
// for.
func (rt *Runtime) waitMembers(ctx context.Context, o RotateOptions, kid string, done func(Peer) bool) ([]string, error) {
	deadline := rt.clock.Now().Add(o.MemberWait)
	for {
		skipped, waiting := rt.membersBehind(done)
		if len(waiting) == 0 {
			return skipped, nil
		}
		if !rt.clock.Now().Before(deadline) {
			return skipped, fmt.Errorf("%s did not pick up the new cluster key in time; the rotation goes on from here when it is asked again",
				joinNames(waiting))
		}
		select {
		case <-ctx.Done():
			return skipped, ctx.Err()
		case <-rt.clock.After(o.Poll):
		}
	}
}

// membersBehind sorts the keyring's members that do not meet done yet:
// skipped, offline for OfflineSkip or never seen, and waiting.
func (rt *Runtime) membersBehind(done func(Peer) bool) (skipped, waiting []string) {
	kr, ok := rt.Keyring().Get()
	if !ok {
		return nil, []string{"the keyring"}
	}
	peers := map[string]Peer{}
	if rt.opts.Peers != nil {
		for _, p := range rt.opts.Peers() {
			peers[p.NodeID] = p
		}
	}
	for id, m := range kr.Members {
		name := cmp.Or(m.Name, id)
		if id == rt.opts.Self.NodeID {
			continue
		}
		p, seen := peers[id]
		switch {
		case !seen, !p.Live && p.SeenAgo >= OfflineSkip:
			skipped = append(skipped, name)
		case !p.Live:
			waiting = append(waiting, name)
		case !done(p):
			waiting = append(waiting, name)
		}
	}
	slices.Sort(skipped)
	slices.Sort(waiting)
	return skipped, waiting
}

func joinNames(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// resignOld signs every document of the config index that is not signed
// with k again with k, as it is (a compare-and-set on the version read;
// one changed meanwhile is read again), then bumps the watch documents so
// every server reads them again. It returns how many it signed.
func resignOld(ctx context.Context, c *store.Client, prefix string, k *ClusterKey, node string) (int, error) {
	index := ConfigIndex(prefix)
	n := 0
	for pass := range 5 {
		docs, _, err := ReadAll(ctx, c, prefix)
		if err != nil {
			return n, err
		}
		left := 0
		for _, d := range docs {
			if macKID(d.Envelope.MAC) == k.ID() {
				continue
			}
			e := d.Envelope
			e.WriteID, e.MAC = "", ""
			if err := Sign(k, d.ID, &e); err != nil {
				return n, err
			}
			if _, err := c.PutIf(ctx, index, d.ID, &e, d.Version, false); err != nil {
				if store.IsConflict(err) {
					left++
					continue
				}
				return n, fmt.Errorf("%s: %w", d.ID, err)
			}
			n++
		}
		if left == 0 {
			break
		}
		if pass == 4 {
			return n, fmt.Errorf("%d shared documents kept changing while they were signed again; the rotation goes on from here when it is asked again", left)
		}
		if err := retryWait(ctx, pass+1); err != nil {
			return n, err
		}
	}
	h := NewHub(Options{NodeName: node})
	h.Use(c, prefix)
	watches, err := c.SearchVersions(ctx, index, map[string]any{"term": map[string]any{"kind": "watch"}})
	if err != nil {
		return n, err
	}
	var errs []error
	for _, w := range watches {
		if _, err := h.bump(ctx, w.ID, nil); err != nil {
			errs = append(errs, err)
		}
	}
	return n, errors.Join(errs...)
}

// RotationStatus is the key rotation as the Servers page shows it.
type RotationStatus struct {
	// On is false below LevelKeyRotation.
	On bool `json:"on"`
	// Active is the id of the key that signs.
	Active string `json:"active,omitempty"`
	// InProgress is the rotation under way, nil when none is.
	InProgress *RotationNext `json:"in_progress,omitempty"`
	// Last is when the last rotation finished copies are kept until, ""
	// when none is kept.
	CatchUpUntil string `json:"catch_up_until,omitempty"`
}

// Rotation returns the state of key rotations.
func (rt *Runtime) Rotation() RotationStatus {
	st := RotationStatus{On: rt.KeyRotation()}
	kr, ok := rt.Keyring().Get()
	if !ok {
		return st
	}
	st.Active = kr.Active
	if n, err := kr.Rotation(); err == nil && n != nil {
		cp := *n
		cp.Copies = nil
		st.InProgress = &cp
	}
	if cu := kr.catchUpLive(rt.clock.Now()); cu != nil {
		st.CatchUpUntil = cu.Until
	}
	return st
}

// keysBehind reports whether this server accepts a key the keyring kr no
// longer lists (a rotation retired it), so its keys must be set again.
func (rt *Runtime) keysBehind(kr *KeyringBody) bool {
	listed := kr.KIDs()
	if len(listed) == 0 {
		return false
	}
	for _, id := range rt.Hub().Keys().IDs() {
		if !slices.Contains(listed, id) {
			return true
		}
	}
	return false
}

// Reseal opens sealed, a value sealed with a cluster key for field, with
// any key of keys, and seals it again with the active key; "" and a value
// sealed with the active key already are returned as they are. A
// Resealer uses it on each value its feature seals.
func Reseal(keys *KeySet, field, sealed string) (string, error) {
	active := keys.Active()
	if sealed == "" {
		return "", nil
	}
	if active == nil {
		return "", errors.New("this server has no cluster key")
	}
	if strings.HasPrefix(sealed, "enc:v1:"+active.ID()+":") {
		return sealed, nil
	}
	var plain string
	var err error = errors.New("it is sealed with a cluster key this server does not have")
	for _, id := range keys.IDs() {
		if plain, err = keys.Get(id).SecretsKey().Open(field, sealed); err == nil {
			break
		}
	}
	if err != nil {
		return "", err
	}
	return active.SecretsKey().Seal(field, plain)
}
