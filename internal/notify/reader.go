package notify

import (
	"context"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

// How far back the dispatcher and the playbooks runner read findings.
const (
	// Window is how far back each pass reads findings at least, so a
	// finding stored a little after a pass, or seen late by OpenSearch,
	// is read by the next one.
	Window = 30 * time.Minute
	// CatchUp is the furthest back a pass reads: after a restart, a
	// takeover of the background jobs, or passes that could not finish,
	// the findings raised meanwhile are read up to this far back.
	CatchUp = 24 * time.Hour
	// maxFindings is the most findings one pass reads.
	maxFindings = 10000
)

// Reader reads the findings each pass of the dispatcher or the playbooks
// runner looks at: those raised since the last pass that finished, less
// Window, and never more than CatchUp before now. Before any pass has
// finished on this server, that is the last CatchUp. A rule or playbook
// still skips findings raised before it was turned on, and each finding
// goes to a channel, or starts a playbook, at most once, so reading a
// finding again does nothing.
//
// The zero Reader is ready to use.
type Reader struct {
	mu   sync.Mutex
	done time.Time // when the last pass that finished started
}

// Read reads the findings for a pass at now, newest first. truncated is
// true when more were raised than one pass reads; the oldest are then
// left out.
func (rd *Reader) Read(ctx context.Context, fs findings.Store, now time.Time) (list []*findings.Finding, truncated bool, err error) {
	since := now.Add(-CatchUp)
	rd.mu.Lock()
	if d := rd.done.Add(-Window); d.After(since) {
		since = d
	}
	rd.mu.Unlock()
	list, total, err := fs.Search(ctx, findings.Filter{Since: since, Limit: maxFindings})
	if err != nil {
		return nil, false, err
	}
	return list, total > len(list), nil
}

// Done records that the pass that read at now looked at every finding it
// read, so the next one need only read from then, less Window. A pass
// that could not do so does not call it, and the next pass reads its
// findings again.
func (rd *Reader) Done(now time.Time) {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	if now.After(rd.done) {
		rd.done = now
	}
}
