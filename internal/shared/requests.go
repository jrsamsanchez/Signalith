package shared

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Work that must run on the server that holds the job lease (a feed
// refresh, a retention run), on one particular server, or on several (a
// restart of these servers, one at a time) is a request document in the
// runtime index, request:<id>. Any server creates one and bumps
// watch:requests; the server it is for claims it with a compare-and-set
// from queued to running, so exactly one runs it. Pages follow it with
// GET /api/requests/{id}. Requests are outside the config index, so they
// are not part of the configuration token.

// Request states.
const (
	RequestQueued  = "queued"
	RequestRunning = "running"
	RequestDone    = "done"
	RequestFailed  = "failed"
	// RequestSkipped is the state of a server in a sequential request
	// that was offline when its turn came; the next one went on.
	RequestSkipped = "skipped"
)

// TargetLeader is the target of a request for the server that holds the
// job lease.
const TargetLeader = "leader"

// requestsWatch is the watch document bumped when a request is made.
const requestsWatch = "watch:requests"

// FinishedRequestAge is how long a finished request is kept.
const FinishedRequestAge = 7 * 24 * time.Hour

// Progress is how far a request has come.
type Progress struct {
	Done  int64 `json:"done"`
	Total int64 `json:"total"`
}

// Request is a request document.
type Request struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Type string `json:"type"`
	// Target is TargetLeader or a server's node id, for a request that
	// one server runs.
	Target string `json:"target,omitempty"`
	// Targets are the node ids of the servers that each run a request
	// meant for several, in order. With Sequential, each one acts once
	// every earlier one is over or has been offline long enough (see
	// Runner.Offline). Status holds each one's state: queued, running,
	// done, failed or skipped.
	Targets     []string          `json:"targets,omitempty"`
	Sequential  bool              `json:"sequential,omitempty"`
	Status      map[string]string `json:"status,omitempty"`
	Args        json.RawMessage   `json:"args,omitempty"`
	State       string            `json:"state"`
	RequestedBy string            `json:"requested_by"`
	RequestedOn string            `json:"requested_on"`
	Created     time.Time         `json:"created"`
	ClaimedBy   string            `json:"claimed_by"`
	Started     *time.Time        `json:"started,omitempty"`
	Finished    *time.Time        `json:"finished,omitempty"`
	// Epoch is the job lease's epoch of the server that runs a leader
	// request.
	Epoch int64 `json:"epoch"`
	// Interrupted is set on a request put back in the queue because its
	// server lost the job lease while running it.
	Interrupted bool            `json:"interrupted,omitempty"`
	Progress    Progress        `json:"progress"`
	Result      json.RawMessage `json:"result,omitempty"`
	Error       string          `json:"error"`

	ver store.Version
}

// Over reports whether the request is done or failed.
func (r *Request) Over() bool { return r.State == RequestDone || r.State == RequestFailed }

// SetResult records what a request found or did, shown when it is over.
func (r *Request) SetResult(v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	r.Result = raw
	return nil
}

func requestDocID(id string) string { return "request:" + id }

func newRequestID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "rq_" + hex.EncodeToString(b)
}

// Requests makes and reads requests.
type Requests struct {
	h *Hub
	// NodeID is this server's node id.
	NodeID string
}

// NewRequests returns the requests of h's cluster, made by server nodeID.
func NewRequests(h *Hub, nodeID string) *Requests { return &Requests{h: h, NodeID: nodeID} }

func (r *Requests) index() string {
	_, p := r.h.target()
	return runtimeIndex(p)
}

// Submit makes a request of type typ for target (TargetLeader or a node
// id), with args, asked for by the user by.
func (r *Requests) Submit(ctx context.Context, typ, target string, args any, by string) (*Request, error) {
	return r.submit(ctx, &Request{Type: typ, Target: target}, args, by)
}

// SubmitTo makes a request of type typ that each of the servers targets
// runs, one after the other in that order when sequential.
func (r *Requests) SubmitTo(ctx context.Context, typ string, targets []string, sequential bool, args any, by string) (*Request, error) {
	if len(targets) == 0 {
		return nil, errors.New("a request needs at least one server")
	}
	req := &Request{Type: typ, Targets: slices.Clone(targets), Sequential: sequential, Status: map[string]string{}}
	for _, t := range targets {
		req.Status[t] = RequestQueued
	}
	return r.submit(ctx, req, args, by)
}

func (r *Requests) submit(ctx context.Context, req *Request, args any, by string) (*Request, error) {
	raw, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	if args == nil {
		raw = nil
	}
	req.Kind, req.ID, req.Args, req.State = "request", newRequestID(), raw, RequestQueued
	req.RequestedBy, req.RequestedOn, req.Created = by, r.h.opts.NodeName, r.h.clock.Now().UTC()
	c, _ := r.h.target()
	ver, err := c.Create(ctx, r.index(), requestDocID(req.ID), req, true)
	if err != nil {
		return nil, err
	}
	req.ver = ver
	if _, err := r.h.bump(ctx, requestsWatch, nil); err != nil {
		// The runner also looks for requests on its own.
		r.h.log.Warn("made a request, but could not tell the other servers; it starts within a minute", "request", req.ID, "err", err)
	}
	return req, nil
}

// Get reads request id now.
func (r *Requests) Get(ctx context.Context, id string) (*Request, bool, error) {
	c, _ := r.h.target()
	src, ver, found, err := c.Get(ctx, r.index(), requestDocID(id))
	if err != nil || !found {
		return nil, false, err
	}
	var req Request
	if err := json.Unmarshal(src, &req); err != nil {
		return nil, false, fmt.Errorf("request %s is damaged: %w", id, err)
	}
	req.ver = ver
	return &req, true, nil
}

// put writes req over the version it was read at.
func (r *Requests) put(ctx context.Context, req *Request) error {
	c, _ := r.h.target()
	ver, err := c.PutIf(ctx, r.index(), requestDocID(req.ID), req, req.ver, false)
	if err != nil {
		return err
	}
	req.ver = ver
	return nil
}

// SetProgress records how far a running request has come.
func (r *Requests) SetProgress(ctx context.Context, req *Request, done, total int64) error {
	req.Progress = Progress{Done: done, Total: total}
	return r.put(ctx, req)
}

// pending lists the requests queued or running, oldest first.
func (r *Requests) pending(ctx context.Context) ([]*Request, error) {
	c, _ := r.h.target()
	docs, err := c.SearchDocs(ctx, r.index(), map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"term": map[string]any{"kind": "request"}},
		map[string]any{"terms": map[string]any{"state": []string{RequestQueued, RequestRunning}}},
	}}})
	if err != nil {
		return nil, err
	}
	var out []*Request
	for _, d := range docs {
		var req Request
		if json.Unmarshal(d.Source, &req) != nil || !strings.HasPrefix(d.ID, "request:") {
			continue
		}
		req.ver = d.Version
		out = append(out, &req)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

// Housekeep deletes the requests that finished more than
// FinishedRequestAge before now. It returns how many.
func (r *Requests) Housekeep(ctx context.Context, now time.Time) (int, error) {
	c, _ := r.h.target()
	docs, err := c.SearchDocs(ctx, r.index(), map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"term": map[string]any{"kind": "request"}},
		map[string]any{"terms": map[string]any{"state": []string{RequestDone, RequestFailed}}},
	}}})
	if err != nil {
		return 0, err
	}
	n := 0
	var errs []error
	for _, d := range docs {
		var req Request
		if json.Unmarshal(d.Source, &req) != nil || req.Finished == nil || now.Sub(*req.Finished) <= FinishedRequestAge {
			continue
		}
		if err := c.DeleteIf(ctx, r.index(), d.ID, d.Version, false); err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, err)
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// Handler runs one request. An error fails the request, unless the
// server lost the job lease meanwhile: then the request goes back to the
// queue for the next holder.
type Handler func(ctx context.Context, req *Request) error

// Runner runs the requests for this server: those for the leader while
// it holds the job lease, and those that name it.
type Runner struct {
	Requests *Requests
	Handlers map[string]Handler
	// Lease returns the job lease's epoch and whether this server holds
	// it.
	Lease func() (epoch int64, holding bool)
	// Offline reports whether the server nodeID has been offline long
	// enough (2 minutes) for the next server of a sequential request to
	// go on without it. Nil means never.
	Offline func(nodeID string) bool
	Log     *slog.Logger
}

// RunOnce claims and runs the requests waiting for this server, one
// after the other, and returns how many ran. A leader request still
// "running" under an older lease epoch was left by a holder that stopped
// and is taken over.
func (rn *Runner) RunOnce(ctx context.Context) (int, error) {
	list, err := rn.Requests.pending(ctx)
	if err != nil {
		return 0, err
	}
	ran := 0
	for _, req := range list {
		if ctx.Err() != nil {
			return ran, ctx.Err()
		}
		h := rn.Handlers[req.Type]
		if h == nil {
			// A newer version's request: left for a server that knows it.
			continue
		}
		epoch, ok := rn.mayRun(req)
		if !ok {
			continue
		}
		claimed, err := rn.claim(ctx, req, epoch)
		if err != nil || !claimed {
			continue
		}
		ran++
		rn.run(ctx, req, h, epoch)
	}
	return ran, nil
}

// mayRun reports whether this server is to run req now, and the lease
// epoch to record.
func (rn *Runner) mayRun(req *Request) (int64, bool) {
	if len(req.Targets) > 0 {
		return 0, rn.mayRunListed(req)
	}
	if req.Target != TargetLeader {
		return 0, req.Target == rn.Requests.NodeID && req.State == RequestQueued
	}
	epoch, holding := rn.Lease()
	if !holding {
		return 0, false
	}
	return epoch, req.State == RequestQueued || req.State == RequestRunning && req.Epoch < epoch
}

// mayRunListed reports whether this server is to run its part of a
// request for several servers now: it is one of them, its part is
// queued, and in a sequential request every earlier server is over or
// offline.
func (rn *Runner) mayRunListed(req *Request) bool {
	self := rn.Requests.NodeID
	i := slices.Index(req.Targets, self)
	if i < 0 || req.Over() || req.Status[self] != RequestQueued && req.Status[self] != "" {
		return false
	}
	if !req.Sequential {
		return true
	}
	for _, id := range req.Targets[:i] {
		if !partOver(req.Status[id]) && (rn.Offline == nil || !rn.Offline(id)) {
			return false
		}
	}
	return true
}

func partOver(state string) bool {
	return state == RequestDone || state == RequestFailed || state == RequestSkipped
}

// claim reads req again and marks it running on this server. Servers of
// a request for several write the same document, so a conflict is tried
// again on the newer copy.
func (rn *Runner) claim(ctx context.Context, req *Request, epoch int64) (bool, error) {
	for range store.ModifyTries {
		now, found, err := rn.Requests.Get(ctx, req.ID)
		if err != nil || !found {
			return false, err
		}
		if _, ok := rn.mayRun(now); !ok {
			return false, nil
		}
		*req = *now
		t := rn.Requests.h.clock.Now().UTC()
		if len(req.Targets) > 0 {
			self := rn.Requests.NodeID
			if req.Status == nil {
				req.Status = map[string]string{}
			}
			if req.Sequential {
				// The earlier servers not over were offline: skipped.
				for _, id := range req.Targets[:slices.Index(req.Targets, self)] {
					if !partOver(req.Status[id]) {
						req.Status[id] = RequestSkipped
					}
				}
			}
			req.Status[self] = RequestRunning
			req.State, req.ClaimedBy = RequestRunning, self
			if req.Started == nil {
				req.Started = &t
			}
		} else {
			req.State, req.ClaimedBy, req.Epoch, req.Started = RequestRunning, rn.Requests.NodeID, epoch, &t
		}
		err = rn.Requests.put(ctx, req)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, store.ErrConflict) {
			return false, err
		}
		if len(req.Targets) == 0 {
			// Another server claimed it.
			return false, nil
		}
	}
	return false, nil
}

func (rn *Runner) run(ctx context.Context, req *Request, h Handler, epoch int64) {
	err := h(ctx, req)
	// The end is written even when ctx ended, as the lease was lost.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if len(req.Targets) > 0 {
		rn.finishListed(wctx, req, err)
		return
	}
	lost := false
	if err != nil && req.Target == TargetLeader {
		now, holding := rn.Lease()
		lost = ctx.Err() != nil || !holding || now != epoch
	}
	t := rn.Requests.h.clock.Now().UTC()
	switch {
	case err == nil:
		req.State, req.Finished, req.Error = RequestDone, &t, ""
	case lost:
		req.State, req.ClaimedBy, req.Started, req.Interrupted = RequestQueued, "", nil, true
	default:
		req.State, req.Finished, req.Error = RequestFailed, &t, err.Error()
	}
	if werr := rn.Requests.put(wctx, req); werr != nil && rn.Log != nil {
		rn.Log.Warn("could not record the end of a request", "request", req.ID, "type", req.Type, "state", req.State, "err", werr)
	}
}

// finishListed records the end of this server's part of a request for
// several servers, and the request's end once every part is over (or
// one failed, in a sequential request: the servers after it do not act).
func (rn *Runner) finishListed(ctx context.Context, req *Request, runErr error) {
	self := rn.Requests.NodeID
	var err error
	for range store.ModifyTries {
		now, found, gerr := rn.Requests.Get(ctx, req.ID)
		if gerr != nil || !found {
			err = gerr
			break
		}
		// What the handler recorded (progress, result) is kept.
		now.Progress, now.Result = req.Progress, req.Result
		if now.Status == nil {
			now.Status = map[string]string{}
		}
		now.Status[self] = RequestDone
		if runErr != nil {
			now.Status[self] = RequestFailed
			now.Error = strings.TrimPrefix(now.Error+"; "+self+": "+runErr.Error(), "; ")
		}
		over, failed, running := true, false, false
		for _, id := range now.Targets {
			st := now.Status[id]
			over = over && partOver(st)
			failed = failed || st == RequestFailed
			running = running || st == RequestRunning
		}
		t := rn.Requests.h.clock.Now().UTC()
		switch {
		case failed && now.Sequential || over && failed:
			now.State, now.Finished = RequestFailed, &t
		case over:
			now.State, now.Finished = RequestDone, &t
		case running:
			now.State = RequestRunning
		default:
			now.State = RequestQueued
		}
		if err = rn.Requests.put(ctx, now); !errors.Is(err, store.ErrConflict) {
			*req = *now
			break
		}
	}
	if err != nil && rn.Log != nil {
		rn.Log.Warn("could not record the end of a request", "request", req.ID, "type", req.Type, "server", self, "err", err)
	}
}

// Watch calls fn whenever the watch document watch:<name> changes (and
// at every full resync), as the request runner does with
// watch:requests.
func (h *Hub) Watch(name string, fn func(ctx context.Context) error) {
	h.trackCollection(watchFunc{id: "watch:" + name, fn: fn})
}

// watchFunc is a function run when a watch document changes.
type watchFunc struct {
	id string
	fn func(ctx context.Context) error
}

func (w watchFunc) watchID() string                          { return w.id }
func (w watchFunc) reload(ctx context.Context) (bool, error) { return true, w.fn(ctx) }
func (w watchFunc) owns(string) bool                         { return false }
func (w watchFunc) restore(store.Doc, string)                {}
func (w watchFunc) cached() []CacheDoc                       { return nil }

// WatchDoc calls fn, as Watch does, with the watch document watch:<name>
// it read for the call (nil and a zero version when there is none), so a
// subscriber can use what BumpWith wrote and tell one change from several
// by its _version. A full resync calls fn with a version it may have seen
// already.
func (h *Hub) WatchDoc(name string, fn func(ctx context.Context, raw json.RawMessage, v store.Version) error) {
	id := "watch:" + name
	h.trackCollection(watchFunc{id: id, fn: func(ctx context.Context) error {
		c, prefix := h.target()
		raw, v, found, err := c.Get(ctx, ConfigIndex(prefix), id)
		if err != nil {
			return err
		}
		if !found {
			raw, v = nil, store.Version{}
		}
		return fn(ctx, raw, v)
	}})
}

// Bump bumps the watch document watch:<name>, for a write outside the
// config index that other servers follow (a downloaded feed). It returns
// the bump's _seq_no.
func (h *Hub) Bump(ctx context.Context, name string) (int64, error) {
	return h.bump(ctx, "watch:"+name, nil)
}

// BumpWith bumps the watch document watch:<name> as Bump does, adding
// fields to its body (unsigned, as the rest of it), such as the id of the
// session ended for a WatchDoc subscriber. It returns the bump's _seq_no.
func (h *Hub) BumpWith(ctx context.Context, name string, fields map[string]any) (int64, error) {
	return h.bump(ctx, "watch:"+name, fields)
}
