package clusterauth

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/users"
)

// The directory users of a cluster are checked again by one server, the
// one that runs the background jobs (job "directory"), rather than by
// each server on its own: every RecheckEvery, and at once when the
// directory sign-in settings change. It looks up, with the service
// account, each directory user who has a session that has not ended,
// taken from the signed user documents and the sessions whose MAC
// verifies (never from what a session says about itself). A changed role
// is written to the user; a user the directory no longer lets in is
// refused, which ends their sessions on every server in the same write.

const (
	// RecheckEvery is how often signed-in directory users are looked up.
	RecheckEvery = 5 * time.Minute
	// recheckParallel bounds how many lookups run at once.
	recheckParallel = 32
)

// Recheck checks signed-in directory users with the directory.
type Recheck struct {
	Docs      *Docs
	Store     *users.Store
	Users     *UsersBackend
	Directory *users.Directory
	Sessions  *Sessions
	Log       *slog.Logger

	mu sync.Mutex
	// checked is the revision of the directory settings each user was
	// last checked under.
	checked map[string]uint64
}

func (r *Recheck) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Run checks the directory users with a session once, and returns how
// many it looked up.
func (r *Recheck) Run(ctx context.Context) int {
	if !r.Directory.Enabled() {
		return 0
	}
	live := r.Sessions.Users(ctx)
	var names []string
	for _, it := range r.Docs.Users().List() {
		u := it.Value
		if u == nil || u.Source != users.SourceDirectory || u.Disabled || u.Refused != "" {
			continue
		}
		if _, found := slices.BinarySearch(live, it.Name); found {
			names = append(names, it.Name)
		}
	}
	rev := r.Directory.Revision()
	sem := make(chan struct{}, recheckParallel)
	var wg sync.WaitGroup
	for _, name := range names {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			r.one(ctx, name, rev)
		}()
	}
	wg.Wait()
	return len(names)
}

// one looks up one directory user, as of the settings of revision rev.
func (r *Recheck) one(ctx context.Context, name string, rev uint64) {
	r.mu.Lock()
	if r.checked == nil {
		r.checked = map[string]uint64{}
	}
	last, seen := r.checked[name]
	r.checked[name] = rev
	r.mu.Unlock()
	settingsChanged := seen && last != rev
	lctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	du, err := r.Directory.Lookup(lctx, name)
	var sie *users.SignInError
	switch {
	case err == nil && users.NormalizeUsername(du.Username) != name:
		r.refuse(ctx, name, "renamed in the directory to "+du.Username)
	case err == nil:
		before, _ := r.Store.Get(name)
		u, changed, err := r.Store.RefreshDirectoryUser(ctx, name, *du)
		if err == nil && changed && u.Role != before.Role {
			r.log().Info("directory user's role changed", "audit", true, "user", name, "from", before.Role, "to", u.Role, "by", "directory")
		}
	case errors.As(err, &sie) && sie.Revoke != "":
		r.refuse(ctx, name, sie.Revoke)
	case errors.Is(err, users.ErrDirectoryOff):
		// Directory users cannot use Signalith while it is off.
	default:
		// The directory could not be asked. Access stays as it was, but a
		// role given under settings that changed since is not trusted, so
		// those sessions end.
		if settingsChanged {
			if eerr := r.Users.EndSessions(ctx, "directory", name); eerr == nil {
				r.log().Warn("ended a directory user's sessions: the directory settings changed and the user could not be checked with the directory",
					"audit", true, "user", name, "err", err)
				return
			}
		}
		r.log().Warn("could not check a directory user with the directory", "user", name, "err", err)
	}
}

func (r *Recheck) refuse(ctx context.Context, name, reason string) {
	u, changed, err := r.Store.RefuseDirectoryUser(ctx, name, reason)
	if err == nil && changed {
		r.log().Warn("directory user lost access", "audit", true, "user", u.Username, "reason", reason, "by", "directory")
	}
}

// Loop runs Run every RecheckEvery, and at once after the directory
// sign-in settings change, until ctx ends. The server that runs the
// background jobs runs it.
func (r *Recheck) Loop(ctx context.Context) {
	kick := make(chan struct{}, 1)
	r.Docs.OnDirectory(func() {
		select {
		case kick <- struct{}{}:
		default:
		}
	})
	t := time.NewTicker(RecheckEvery)
	defer t.Stop()
	for {
		r.Run(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-kick:
		}
	}
}
