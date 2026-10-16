package store

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"
)

// ModifyTries is how many times a read, change and conditional write is
// tried when other writers keep changing the same document in between.
const ModifyTries = 10

// RetryConflicts runs try until it returns anything but ErrConflict, at
// most ModifyTries times, waiting a short random time between tries (0 to
// 10 ms times the try) so writers that collided do not collide again in
// step. When every try conflicted it returns ErrConflict. try must read
// the document again each time: a conflict means the copy it had is old.
func RetryConflicts(ctx context.Context, try func() error) error {
	var err error
	for n := 1; n <= ModifyTries; n++ {
		if err = try(); !errors.Is(err, ErrConflict) {
			return err
		}
		if n == ModifyTries {
			break
		}
		wait := time.Duration(rand.Int64N(int64(10*time.Millisecond)*int64(n) + 1))
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
	return err
}
