package clusterarchive

import (
	"cmp"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/audit"
	"github.com/jrsamsanchez/signalith/internal/retention"
)

// ActionPrefix starts the action of every retention audit record, such
// as retention.archive.
const ActionPrefix = "retention."

// actField is the audit record field that holds the whole action.
const actField = "act"

// History keeps the retention history as audit records: each action is
// logged as an audit line (Log is the server's logger, whose audit
// handler stores it), and the last run in <prefix>_runtime/
// retention:lastrun. It implements retention.HistorySink.
type History struct {
	Client Client
	Prefix string
	Log    *slog.Logger
	Server string
	NodeID string
	Epoch  func() int64
	Now    func() time.Time
}

// Record implements retention.HistorySink.
func (h *History) Record(ctx context.Context, run *retention.Run, acts ...retention.Action) error {
	for _, a := range acts {
		a.Server = cmp.Or(a.Server, h.Server)
		if len(a.Error) > 1000 {
			a.Error = a.Error[:1000]
		}
		b, _ := json.Marshal(a)
		msg := ActionPrefix + a.Action + ": " + a.Reason
		args := []any{"audit", true, "index", a.Index, "category", a.Category, actField, string(b)}
		if a.By != "" {
			args = append(args, "by", a.By)
		}
		if a.Error != "" {
			h.Log.Warn(msg, append(args, "err", a.Error)...)
		} else {
			h.Log.Info(msg, args...)
		}
	}
	if run == nil {
		return nil
	}
	body, err := json.Marshal(run)
	if err != nil {
		return err
	}
	var epoch int64
	if h.Epoch != nil {
		epoch = h.Epoch()
	}
	return put(ctx, h.Client, h.Prefix, LastRunID, doc{Kind: KindLastRun, Node: h.Server, NodeID: h.NodeID, Epoch: epoch, At: now(h.Now), Body: body})
}

// Recent implements retention.HistorySink: the last run, and the last
// MaxActions retention actions of every server.
func (h *History) Recent(ctx context.Context) (*retention.Run, []retention.Action, error) {
	var run *retention.Run
	if d, _, found, err := read(ctx, h.Client, h.Prefix, LastRunID); err != nil {
		return nil, nil, err
	} else if found {
		var r retention.Run
		if json.Unmarshal(d.Body, &r) == nil {
			run = &r
		}
	}
	page, err := audit.Search(ctx, h.Client, h.Prefix, audit.Query{Action: ActionPrefix, Size: retention.MaxActions})
	if err != nil {
		return run, nil, err
	}
	acts := make([]retention.Action, 0, len(page.Events))
	for _, ev := range page.Events {
		var a retention.Action
		if raw := ev.Fields[actField]; raw == "" || json.Unmarshal([]byte(raw), &a) != nil {
			a = retention.Action{Time: ev.Time, Action: strings.TrimPrefix(ev.Action, ActionPrefix), Index: ev.Target, Reason: ev.Message, By: ev.User}
		}
		a.Server = cmp.Or(a.Server, ev.Server)
		acts = append(acts, a)
	}
	return run, acts, nil
}

// Source implements retention.HistorySink.
func (h *History) Source() string { return retention.HistoryFromAudit }
