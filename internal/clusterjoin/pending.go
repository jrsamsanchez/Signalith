package clusterjoin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// Errors of Approve.
var (
	ErrNoPending   = errors.New("no server with this id waits for approval")
	ErrFingerprint = errors.New("the fingerprint does not match the one the waiting server shows; compare it again on the new server's sign-in page or log")
)

// Approver approves servers that wait to join (shared.PendingDoc): it
// gives each the cluster key sealed to its node key, after an admin
// compared its fingerprint.
type Approver struct {
	RT *shared.Runtime
	// Secured checks the cluster's secured-OpenSearch requirement on this
	// server's settings (RequireSecured); nil skips it.
	Secured func() error
	Log     *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

func (a *Approver) log() *slog.Logger {
	if a.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return a.Log
}

func (a *Approver) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

// Pending lists the servers that wait for approval and are not members
// with the same node key already (one approved that has not taken its
// key yet).
func (a *Approver) Pending(ctx context.Context) ([]shared.PendingDoc, error) {
	list, err := a.RT.Pending(ctx)
	if err != nil {
		return nil, err
	}
	kr, _ := a.RT.Keyring().Get()
	out := list[:0]
	for _, p := range list {
		if kr != nil {
			if m, ok := kr.Members[p.NodeID]; ok && m.NodePub == p.NodePub {
				continue
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// SameFingerprint compares two node key fingerprints, ignoring case,
// spaces and dashes.
func SameFingerprint(a, b string) bool {
	n := func(s string) string {
		return strings.ToUpper(strings.NewReplacer("-", "", " ", "", ":", "").Replace(strings.TrimSpace(s)))
	}
	return n(a) != "" && n(a) == n(b)
}

// Approve makes the waiting server nodeID a member, for the user by:
// fingerprint, which the admin read on the new server, must be the one
// of the node key in its pending document. It adds the server to the
// keyring (added_by "approval"), then writes the approval with the
// active cluster key sealed to that node key, which the server takes
// within seconds. It returns the pending document it approved.
func (a *Approver) Approve(ctx context.Context, nodeID, fingerprint, by string) (*shared.PendingDoc, error) {
	if err := a.RT.Writable(); err != nil {
		return nil, err
	}
	if a.Secured != nil {
		if err := a.Secured(); err != nil {
			return nil, err
		}
	}
	p, ok, err := a.RT.PendingOf(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNoPending
	}
	if !SameFingerprint(p.Fingerprint, fingerprint) {
		a.log().Warn("cluster.approve refused: the fingerprint does not match", "audit", true, "node_id", nodeID, "name", p.Name, "user", by)
		return nil, ErrFingerprint
	}
	if !config.ValidNodeName(p.Name) {
		return nil, fmt.Errorf("the waiting server's name %q is not a server name", p.Name)
	}
	if nodeID == a.RT.Self().NodeID {
		return nil, errors.New("a server cannot approve itself")
	}
	pub, err := p.NodePubBytes()
	if err != nil {
		return nil, err
	}
	k := a.RT.Hub().Keys().Active()
	if k == nil {
		return nil, errors.New("this server has no cluster key")
	}
	sealed, err := shared.SealToNode(pub, nodeID, k.ID(), []byte(k.Text()))
	if err != nil {
		return nil, err
	}
	now := a.now()
	// The keyring first: a server that took its key before it was listed
	// would add itself as imported.
	m := shared.KeyringMember{Name: p.Name, NodePub: p.NodePub, Fingerprint: p.Fingerprint,
		AddedAt: now.Format(time.RFC3339Nano), AddedBy: shared.AddedByApproval}
	if _, err := a.RT.Keyring().Mutate(ctx, by, func(b *shared.KeyringBody) error {
		if old, there := b.Members[nodeID]; there && old.NodePub == m.NodePub {
			return nil
		}
		if b.Members == nil {
			b.Members = map[string]shared.KeyringMember{}
		}
		b.Members[nodeID] = m
		return nil
	}); err != nil {
		return nil, err
	}
	if err := a.RT.WriteApproval(ctx, shared.ApprovalDoc{NodeID: nodeID, KID: k.ID(), Sealed: sealed, By: by, At: now}); err != nil {
		return nil, err
	}
	a.log().Info("cluster.approve: a server was approved to join the cluster", "audit", true,
		"node_id", nodeID, "name", p.Name, "fingerprint", p.Fingerprint, "user", by)
	return p, nil
}
