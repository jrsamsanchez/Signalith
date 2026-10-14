package clusterarchive

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Claimer claims an index before each retention step that changes it, on
// <prefix>_runtime/op:<index>, with the job lease's epoch: a claim made
// with a later epoch refuses every step of an earlier one, so a server
// that lost the background jobs, and does not know yet, stops before it
// changes the index. Its Claim is retention.Manager.Claim.
type Claimer struct {
	Client Client
	Prefix string
	Server string
	NodeID string
	// Epoch is the job lease's epoch, and Frozen reports whether the
	// lease is held frozen while OpenSearch refuses writes: then no claim
	// can be written, and the disk guard's deletions go ahead on the
	// lease alone.
	Epoch  func() int64
	Frozen func() bool
	Now    func() time.Time
}

// ErrSuperseded is a step refused because a server with a later epoch
// claimed the index.
var ErrSuperseded = errors.New("a server that took the background jobs over later claimed this index")

// Claim records step on index with this server's epoch, refused when the
// claim there has a later epoch.
func (c *Claimer) Claim(ctx context.Context, index, step string) error {
	if c.Frozen != nil && c.Frozen() {
		return nil
	}
	epoch := c.Epoch()
	id := OpDocID(index)
	d := doc{Kind: KindOp, Name: index, Node: c.Server, NodeID: c.NodeID, State: step, Epoch: epoch, At: now(c.Now)}
	for try := 0; try < 3; try++ {
		cur, v, found, err := read(ctx, c.Client, c.Prefix, id)
		if err != nil {
			return err
		}
		if found && cur.Epoch > epoch {
			return fmt.Errorf("%w (%s, epoch %d; this server's is %d)", ErrSuperseded, cur.Node, cur.Epoch, epoch)
		}
		if found {
			_, err = c.Client.PutIf(ctx, cluster.RuntimeIndex(c.Prefix), id, d, v, false)
		} else {
			_, err = c.Client.Create(ctx, cluster.RuntimeIndex(c.Prefix), id, d, false)
		}
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrExists) || errors.Is(err, store.ErrNotFound) {
			continue
		}
		return err
	}
	return errors.New("the claim on the index kept changing")
}
