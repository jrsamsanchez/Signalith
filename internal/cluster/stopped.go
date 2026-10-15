package cluster

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ErrRunning is a change to the state folder that needs the server
// stopped, asked while a Signalith process uses the folder.
var ErrRunning = errors.New("a Signalith process uses this state folder")

// WhileStopped runs fn holding the state folder dir's lock, so no server
// can start with the folder meanwhile: ErrRunning when one runs now. On a
// filesystem that does not lock files, fn runs anyway.
func WhileStopped(dir string, fn func() error) error {
	unlock, err := lockFile(filepath.Join(dir, "cluster", lockName))
	switch {
	case errors.Is(err, errLocked):
		return fmt.Errorf("%w (%s): stop the server first", ErrRunning, dir)
	case errors.Is(err, errLockUnsupported), errors.Is(err, os.ErrNotExist):
		unlock = func() {}
	case err != nil:
		return fmt.Errorf("could not lock the state folder %s: %w", dir, err)
	}
	defer unlock()
	return fn()
}

// ReplaceIdentity moves node.id in the state folder dir aside, to
// node.id.replaced-<time>, so the next start makes a new identity, and
// returns the file it moved it to. The caller holds the folder's lock
// (WhileStopped).
func ReplaceIdentity(dir string, now time.Time) (string, error) {
	from := filepath.Join(dir, nodeFile)
	to := from + ".replaced-" + now.UTC().Format("20060102T150405Z")
	if err := os.Rename(from, to); err != nil {
		return "", err
	}
	return to, nil
}
