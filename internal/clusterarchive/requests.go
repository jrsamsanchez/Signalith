package clusterarchive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// RequestArchiveRestore restores archived days on the server that runs
// the background jobs (see shared.Requests): any server asks, that one
// restores, and every server follows the progress.
const RequestArchiveRestore = "archive_restore"

// ArchiveRestoreArgs are the arguments of an archive_restore request.
type ArchiveRestoreArgs struct {
	IDs      []string `json:"ids"`
	KeepDays int      `json:"keep_days,omitempty"`
	// Confirm restores even when it makes the disk guard delete live days
	// or fills the disk (see retention.RestoreCheck).
	Confirm bool `json:"confirm,omitempty"`
}

// ArchiveRestoreResult is what an archive_restore request did: each
// archive's restore, or the check that needs a confirmation.
type ArchiveRestoreResult struct {
	Restores []retention.RestoreStatus `json:"restores,omitempty"`
	Check    *retention.RestoreCheck   `json:"check,omitempty"`
}

// Progress records how far a request has come: shared.Requests.SetProgress.
type Progress func(ctx context.Context, req *shared.Request, done, total int64) error

// Handlers returns the handler of archive_restore requests, which runs
// the restore with ret and waits for it, recording its progress.
func Handlers(ret *retention.Manager, progress Progress) map[string]shared.Handler {
	return map[string]shared.Handler{
		RequestArchiveRestore: func(ctx context.Context, req *shared.Request) error {
			var a ArchiveRestoreArgs
			if err := json.Unmarshal(req.Args, &a); err != nil || len(a.IDs) == 0 {
				return errors.New("the request names no archives to restore")
			}
			_, err := ret.Restore(ctx, a.IDs, a.KeepDays, req.RequestedBy, a.Confirm)
			var ce *retention.ConfirmError
			if errors.As(err, &ce) {
				if serr := req.SetResult(ArchiveRestoreResult{Check: ce.Check}); serr != nil {
					return serr
				}
				return err
			}
			if err != nil {
				return err
			}
			var last int64 = -1
			out, err := ret.WaitRestores(ctx, a.IDs, func(done, total int64) {
				if progress != nil && done != last {
					last = done
					_ = progress(ctx, req, done, total)
				}
			})
			if serr := req.SetResult(ArchiveRestoreResult{Restores: out}); serr != nil && err == nil {
				err = serr
			}
			if err != nil {
				return err
			}
			for _, r := range out {
				if r.State == retention.RestoreFailed {
					return fmt.Errorf("%s: %s", r.ID, r.Error)
				}
			}
			return nil
		},
	}
}
