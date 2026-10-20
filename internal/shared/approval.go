// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// A server that finds a cluster it has no key to (legacy b) asks to join
// it: it writes <prefix>_runtime/pending:<its node id> every
// PendingEvery, with its node public key and fingerprint, and looks for
// <prefix>_runtime/approval:<its node id> at each step of its loop. An
// admin compares the fingerprint the Servers page shows with the one this
// server shows on its sign-in page and in its log, and approves it
// (clusterjoin.Approver): the approval holds the cluster key sealed to
// this server's node key (SealToNode), which only it can open. It keeps
// the key, deletes the approval, and joins at its next step.
//
// Neither document is signed: a forged pending document at most adds a
// row an admin should not approve, and a forged approval holds a key that
// does not verify the cluster document: the server checks that before it
// keeps the key, and deletes such an approval.

// Kinds of the documents in the runtime index.
const (
	PendingKind  = "pending"
	ApprovalKind = "approval"
)

// PendingEvery is how often a waiting server writes its pending
// document, and PendingStale how long one may go unwritten before the
// server that runs the background jobs removes it.
const (
	PendingEvery = 60 * time.Second
	PendingStale = 24 * time.Hour
)

// PendingDoc is a server that waits for approval to join.
type PendingDoc struct {
	Kind        string `json:"kind"`
	NodeID      string `json:"node_id"`
	Name        string `json:"name"`
	NodePub     string `json:"node_pub"`
	Fingerprint string `json:"fingerprint"`
	Version     string `json:"version,omitempty"`
	OS          string `json:"os,omitempty"`
	Arch        string `json:"arch,omitempty"`
	// Addresses are the server's own addresses, NodeURL its
	// server.node_url, to tell the admin which machine it is.
	Addresses []string `json:"addresses,omitempty"`
	NodeURL   string   `json:"node_url,omitempty"`
	// RequestedAt is when it first asked, At when it last wrote.
	RequestedAt time.Time `json:"requested_at"`
	At          time.Time `json:"at"`
}

// ApprovalDoc gives a waiting server the cluster key: Sealed is the key's
// text sealed to the server's node key for KID.
type ApprovalDoc struct {
	Kind   string    `json:"kind"`
	NodeID string    `json:"node_id"`
	KID    string    `json:"kid"`
	Sealed string    `json:"sealed"`
	By     string    `json:"user"`
	At     time.Time `json:"at"`
}

// PendingID and ApprovalID are the documents' ids.
func PendingID(nodeID string) string  { return PendingKind + ":" + nodeID }
func ApprovalID(nodeID string) string { return ApprovalKind + ":" + nodeID }

// NodePubBytes returns the node public key of a pending document, or an
// error when it is not 32 bytes of base64.
func (p *PendingDoc) NodePubBytes() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(p.NodePub)
	if err != nil || len(b) != 32 {
		return nil, errors.New("the waiting server's node key is not one")
	}
	return b, nil
}

// approvalState is what the waiting server keeps between steps.
type approvalState struct {
	// wroteAt is when it last wrote its pending document, on the
	// monotonic clock; requestedAt when it first did.
	wroteAt     *time.Duration
	requestedAt time.Time
	// refused is the last approval it could not open, so the log says it
	// once.
	refused string
	// waiting is what the sign-in page says while it waits.
	waiting string
}

// awaitApproval is a step of a server in legacy b: it writes its pending
// document when due, and takes the cluster key from an approval.
func (rt *Runtime) awaitApproval(ctx context.Context) {
	if rt.opts.ReadOnly {
		return
	}
	nk, err := rt.nodeKey()
	if err != nil {
		return
	}
	c, prefix := rt.target()
	if c == nil {
		return
	}
	idx := runtimeIndex(prefix)
	self := rt.opts.Self
	actx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	src, ver, found, err := c.Get(actx, idx, ApprovalID(self.NodeID))
	if err == nil && found {
		if rt.takeApproval(actx, nk, src, ver) {
			return
		}
	}
	rt.mu.Lock()
	now := rt.clock.Mono()
	due := rt.approval.wroteAt == nil || now-*rt.approval.wroteAt >= PendingEvery
	if rt.approval.requestedAt.IsZero() {
		rt.approval.requestedAt = rt.clock.Now().UTC()
	}
	requested := rt.approval.requestedAt
	rt.mu.Unlock()
	if !due {
		return
	}
	var d PendingDoc
	if rt.opts.JoinInfo != nil {
		d = rt.opts.JoinInfo()
	}
	d.Kind, d.NodeID, d.Name = PendingKind, self.NodeID, self.Name
	d.NodePub, d.Fingerprint = nk.PublicText(), nk.Fingerprint()
	d.OS, d.Arch = cmpOr(d.OS, runtime.GOOS), cmpOr(d.Arch, runtime.GOARCH)
	d.RequestedAt, d.At = requested, rt.clock.Now().UTC()
	if err := putRuntime(actx, c, idx, PendingID(self.NodeID), d); err != nil {
		rt.log.Debug("could not ask to join the cluster; trying again", "err", err)
		return
	}
	rt.mu.Lock()
	first := rt.approval.wroteAt == nil
	rt.approval.wroteAt = &now
	rt.mu.Unlock()
	if first {
		name := "the cluster"
		if b, ok := rt.peekClusterName(actx); ok {
			name = fmt.Sprintf("cluster '%s'", b)
		}
		rt.mu.Lock()
		rt.approval.waiting = fmt.Sprintf("This server waits to join %s. Approve it on the Servers page of another server, or with signalith cluster approve there: fingerprint %s", name, d.Fingerprint)
		rt.mu.Unlock()
		rt.log.Warn(fmt.Sprintf("This server waits to join %s. Approve it on another server (Servers page, or signalith cluster approve): fingerprint %s", name, d.Fingerprint),
			"fingerprint", d.Fingerprint)
	}
}

// Waiting is what the sign-in page of a server that waits for approval
// says: the cluster it waits to join and its fingerprint. It is "" on
// any other server.
func (rt *Runtime) Waiting() string {
	if m, _ := rt.Mode(); m != ModeLegacyB {
		return ""
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.approval.waiting
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// peekClusterName reads the cluster's name from the cluster document,
// which this server cannot verify: it is only for the waiting message.
func (rt *Runtime) peekClusterName(ctx context.Context) (string, bool) {
	c, prefix := rt.target()
	src, _, found, err := c.Get(ctx, ConfigIndex(prefix), ClusterDocID)
	if err != nil || !found {
		return "", false
	}
	var e Envelope
	var b ClusterBody
	if json.Unmarshal(src, &e) != nil || json.Unmarshal([]byte(e.Body), &b) != nil || b.Name == "" {
		return "", false
	}
	return b.Name, true
}

// takeApproval opens an approval and keeps the cluster key in it. It
// reports whether it did; the next step joins with the key.
func (rt *Runtime) takeApproval(ctx context.Context, nk *NodeKey, src json.RawMessage, ver store.Version) bool {
	self := rt.opts.Self
	var a ApprovalDoc
	k, err := func() (*ClusterKey, error) {
		if err := json.Unmarshal(src, &a); err != nil || a.KID == "" {
			return nil, errors.New("it is not an approval Signalith wrote")
		}
		plain, err := nk.OpenFromNode(self.NodeID, a.KID, a.Sealed)
		if err != nil {
			return nil, err
		}
		defer clear(plain)
		raw, err := base64.StdEncoding.DecodeString(string(plain))
		if err != nil {
			return nil, errors.New("the key in it is damaged")
		}
		defer clear(raw)
		k, err := ClusterKeyFrom(raw)
		if err != nil {
			return nil, err
		}
		if k.ID() != a.KID {
			return nil, fmt.Errorf("it holds cluster key %s, not %s", k.ID(), a.KID)
		}
		return k, nil
	}()
	if err != nil {
		rt.mu.Lock()
		again := rt.approval.refused == string(src)
		rt.approval.refused = string(src)
		rt.mu.Unlock()
		if !again {
			rt.log.Warn("an approval for this server cannot be used: "+err.Error()+"; approve it again on the Servers page", "approval", ApprovalID(self.NodeID))
		}
		return false
	}
	c, prefix := rt.target()
	idx := runtimeIndex(prefix)
	// Only a key that verifies the cluster document is kept: anyone who
	// can write the runtime index could seal a key of their own to this
	// server's public node key.
	switch err := rt.verifiesCluster(ctx, k); {
	case errors.Is(err, errNotThisCluster):
		rt.log.Warn("an approval for this server holds a key that does not verify the cluster's settings, so it was deleted: it was not written by a member. Approve this server again on the Servers page",
			"approval", ApprovalID(self.NodeID), "kid", k.ID())
		if err := c.DeleteIf(ctx, idx, ApprovalID(self.NodeID), ver, true); err != nil && !errors.Is(err, store.ErrNotFound) {
			rt.log.Debug("could not delete the approval", "err", err)
		}
		return false
	case err != nil:
		rt.log.Debug("could not check the approval against the cluster's settings; trying again", "err", err)
		return false
	}
	if err := rt.keyStore().SaveClusterKey(k); err != nil {
		rt.log.Warn("could not keep the cluster key this server was approved with; trying again", "err", err)
		return false
	}
	if err := c.DeleteIf(ctx, idx, ApprovalID(self.NodeID), ver, true); err != nil && !errors.Is(err, store.ErrNotFound) {
		rt.log.Debug("could not delete the approval this server used", "err", err)
	}
	deleteRuntime(ctx, c, idx, PendingID(self.NodeID))
	rt.mu.Lock()
	rt.approval = approvalState{}
	rt.mu.Unlock()
	rt.log.Info("this server was approved to join the cluster and received the cluster key", "audit", true, "kid", k.ID(), "approved_by", a.By)
	rt.Kick()
	return true
}

// errNotThisCluster: a key that does not verify the cluster document.
var errNotThisCluster = errors.New("the key does not verify the cluster's document")

// verifiesCluster checks that the key k signs the cluster document in
// OpenSearch now: errNotThisCluster when it does not, another error when
// the document cannot be read.
func (rt *Runtime) verifiesCluster(ctx context.Context, k *ClusterKey) error {
	c, prefix := rt.target()
	src, _, found, err := c.Get(ctx, ConfigIndex(prefix), ClusterDocID)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("the cluster document is not there")
	}
	var e Envelope
	if json.Unmarshal(src, &e) != nil || Verify(NewKeySet(k), ClusterDocID, &e) != nil {
		return errNotThisCluster
	}
	return nil
}

// Approved lists the servers with an approval that waits to be taken.
func (rt *Runtime) Approved(ctx context.Context) (map[string]bool, error) {
	c, prefix := rt.target()
	if c == nil {
		return nil, errors.New("OpenSearch is not set up")
	}
	docs, err := c.SearchDocs(ctx, runtimeIndex(prefix), map[string]any{"term": map[string]any{"kind": ApprovalKind}})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return map[string]bool{}, nil
		}
		return nil, err
	}
	out := map[string]bool{}
	for _, d := range docs {
		var a ApprovalDoc
		if json.Unmarshal(d.Source, &a) == nil && a.Kind == ApprovalKind && d.ID == ApprovalID(a.NodeID) {
			out[a.NodeID] = true
		}
	}
	return out, nil
}

// putRuntime writes the runtime document id whatever is there.
func putRuntime(ctx context.Context, c *store.Client, idx, id string, body any) error {
	for range 3 {
		_, ver, found, err := c.Get(ctx, idx, id)
		if err != nil {
			return err
		}
		if found {
			_, err = c.PutIf(ctx, idx, id, body, ver, true)
		} else {
			_, err = c.Create(ctx, idx, id, body, true)
		}
		if !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrExists) {
			return err
		}
	}
	return store.ErrConflict
}

// deleteRuntime deletes the runtime document id when it is there.
func deleteRuntime(ctx context.Context, c *store.Client, idx, id string) {
	_, ver, found, err := c.Get(ctx, idx, id)
	if err != nil || !found {
		return
	}
	_ = c.DeleteIf(ctx, idx, id, ver, true)
}

// Pending lists the servers that wait for approval, oldest first. The
// fingerprint of each is worked out again from its node key, so the page
// always shows the fingerprint of the key an approval would seal to.
func (rt *Runtime) Pending(ctx context.Context) ([]PendingDoc, error) {
	c, prefix := rt.target()
	if c == nil {
		return nil, errors.New("OpenSearch is not set up")
	}
	docs, err := c.SearchDocs(ctx, runtimeIndex(prefix), map[string]any{"term": map[string]any{"kind": PendingKind}})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	var out []PendingDoc
	for _, d := range docs {
		var p PendingDoc
		if json.Unmarshal(d.Source, &p) != nil || p.Kind != PendingKind || d.ID != PendingID(p.NodeID) {
			continue
		}
		pub, err := p.NodePubBytes()
		if err != nil {
			continue
		}
		p.Fingerprint = Fingerprint(pub)
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b PendingDoc) int { return a.RequestedAt.Compare(b.RequestedAt) })
	return out, nil
}

// PendingOf reads the pending document of server nodeID now, with its
// fingerprint worked out from its node key; false when there is none.
func (rt *Runtime) PendingOf(ctx context.Context, nodeID string) (*PendingDoc, bool, error) {
	c, prefix := rt.target()
	if c == nil {
		return nil, false, errors.New("OpenSearch is not set up")
	}
	src, _, found, err := c.Get(ctx, runtimeIndex(prefix), PendingID(nodeID))
	if err != nil || !found {
		return nil, false, err
	}
	var p PendingDoc
	if err := json.Unmarshal(src, &p); err != nil || p.Kind != PendingKind || p.NodeID != nodeID {
		return nil, false, nil
	}
	pub, err := p.NodePubBytes()
	if err != nil {
		return nil, false, err
	}
	p.Fingerprint = Fingerprint(pub)
	return &p, true, nil
}

// WriteApproval writes the approval a, then deletes the server's pending
// document. Only a member writes one (clusterjoin.Approver).
func (rt *Runtime) WriteApproval(ctx context.Context, a ApprovalDoc) error {
	if err := rt.Writable(); err != nil {
		return err
	}
	c, prefix := rt.target()
	idx := runtimeIndex(prefix)
	a.Kind = ApprovalKind
	if err := putRuntime(ctx, c, idx, ApprovalID(a.NodeID), a); err != nil {
		return err
	}
	deleteRuntime(ctx, c, idx, PendingID(a.NodeID))
	return nil
}

// DropStalePending removes the pending documents not written for
// PendingStale at now, and approvals as old (a server that never came
// back for its key); the server that runs the background jobs calls it
// with its housekeeping. It returns how many it removed.
func (rt *Runtime) DropStalePending(ctx context.Context, now time.Time) (int, error) {
	if m, _ := rt.Mode(); m != ModeMember || rt.opts.ReadOnly {
		return 0, nil
	}
	c, prefix := rt.target()
	idx := runtimeIndex(prefix)
	docs, err := c.SearchDocs(ctx, idx, map[string]any{"terms": map[string]any{"kind": []string{PendingKind, ApprovalKind}}})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	var errs []error
	for _, d := range docs {
		var v struct {
			At time.Time `json:"at"`
		}
		if json.Unmarshal(d.Source, &v) == nil && !v.At.IsZero() && now.Sub(v.At) <= PendingStale {
			continue
		}
		if err := c.DeleteIf(ctx, idx, d.ID, d.Version, true); err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, err)
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// keyFileUnsecured is the warning of a server that takes the cluster key
// from SIGNALITH_CLUSTER_KEY_FILE while OpenSearch is not secured as
// several servers need: that way of joining keeps working, and says so.
func (rt *Runtime) keyFileUnsecured() *Warning {
	if rt.opts.KeyFile == "" || rt.opts.Secured == nil {
		return nil
	}
	err := rt.opts.Secured()
	if err == nil {
		return nil
	}
	return &Warning{Level: "red", Text: "This server takes the cluster key from a key file (SIGNALITH_CLUSTER_KEY_FILE) while OpenSearch is not secured: " + err.Error() +
		" Until it is, anyone who reaches OpenSearch can read and change the events and the shared settings of every server."}
}
