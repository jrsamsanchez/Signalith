package search

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/lookuptables"
	"github.com/jrsamsanchez/signalith/internal/query"
)

// LookupWriter lets the searches of one request write lookup tables with
// outputlookup. The API gives one only to an admin's own interactive
// searches; detections, dashboards, API tokens and every other search
// have none, and their outputlookup fails.
type LookupWriter interface {
	// Allowed reports why tables cannot change right now, if they cannot.
	Allowed() error
	// Wrote records a table written, for the audit log.
	Wrote(table string, rows, total int, mode string)
}

type lookupWriterKey struct{}

// WithLookupWriter lets ctx's searches write lookup tables through w.
func WithLookupWriter(ctx context.Context, w LookupWriter) context.Context {
	return context.WithValue(ctx, lookupWriterKey{}, w)
}

// outputLookup writes res's rows to c's table and leaves them as they are.
// Fields starting with _ other than _time are not written, as in Splunk.
func (e *Engine) outputLookup(ctx context.Context, res *Result, c *query.OutputLookup) error {
	w, _ := ctx.Value(lookupWriterKey{}).(LookupWriter)
	if w == nil {
		return &QueryError{Msg: "outputlookup writes lookup tables, so only an admin's own searches on the Search page can use it, not detections, dashboards or API tokens"}
	}
	if e.Lookups == nil {
		return &QueryError{Msg: "lookup tables are not available on this server"}
	}
	if err := w.Allowed(); err != nil {
		return &QueryError{Msg: err.Error()}
	}
	mode, name := lookuptables.OutputCreate, "create"
	if c.Append != nil {
		mode, name = lookuptables.OutputReplace, "replace"
		if *c.Append {
			mode, name = lookuptables.OutputAppend, "append"
		}
	}
	var cols []string
	for _, f := range res.Columns {
		if f == "_time" || !strings.HasPrefix(f, "_") && !strings.HasPrefix(f, "\x00") {
			cols = append(cols, f)
		}
	}
	rows := res.Rows
	if c.Max > 0 && len(rows) > c.Max {
		rows = rows[:c.Max]
	}
	if len(rows) == 0 {
		_, exists := e.Lookups.Get(c.Table)
		if exists && (mode == lookuptables.OutputAppend || mode == lookuptables.OutputReplace && !c.OverrideIfEmpty) || !exists && !c.CreateEmpty {
			return nil
		}
	}
	if len(cols) == 0 {
		return &QueryError{Msg: "outputlookup has no fields to write; a lookup table needs at least one column"}
	}
	ev := evaluatorFor(ctx)
	var out [][]string
	for i, r := range rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		if !ev.stepN(len(cols)) {
			return ev.err
		}
		var row []string
		for _, f := range cols {
			s, _ := evStr(r[f])
			row = append(row, s)
		}
		out = append(out, row)
	}
	t, err := e.Lookups.Output(c.Table, cols, out, mode)
	if errors.Is(err, lookuptables.ErrExists) {
		return &QueryError{Msg: fmt.Sprintf("lookup table %s exists; add append=t to add these rows to it, or append=f to replace it", c.Table)}
	}
	if err != nil {
		return &QueryError{Msg: err.Error()}
	}
	w.Wrote(c.Table, len(out), len(t.Rows), name)
	return nil
}
