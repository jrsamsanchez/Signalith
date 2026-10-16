package clusterarchive

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jrsamsanchez/signalith/internal/retention"
)

// Jobs shares the progress of restores in <prefix>_runtime/retention:job,
// written by the server that runs them. It implements retention.JobStore.
type Jobs struct {
	Client Client
	Prefix string
	Server string
	NodeID string
	Epoch  func() int64
	Now    func() time.Time
}

type jobBody struct {
	Restores []retention.RestoreStatus `json:"restores"`
}

// Save implements retention.JobStore.
func (j *Jobs) Save(ctx context.Context, restores []retention.RestoreStatus) error {
	body, err := json.Marshal(jobBody{Restores: restores})
	if err != nil {
		return err
	}
	var epoch int64
	if j.Epoch != nil {
		epoch = j.Epoch()
	}
	return put(ctx, j.Client, j.Prefix, JobID, doc{Kind: KindJob, Node: j.Server, NodeID: j.NodeID, Epoch: epoch, At: now(j.Now), Body: body})
}

// Load implements retention.JobStore.
func (j *Jobs) Load(ctx context.Context) ([]retention.RestoreStatus, error) {
	d, _, found, err := read(ctx, j.Client, j.Prefix, JobID)
	if err != nil || !found {
		return nil, err
	}
	var b jobBody
	if err := json.Unmarshal(d.Body, &b); err != nil {
		return nil, err
	}
	return b.Restores, nil
}
