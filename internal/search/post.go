package search

import (
	"context"
	"fmt"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// RunCommands runs pipe commands over stored events held in memory, as
// the engine runs the commands after its OpenSearch search: each doc is
// one event as indexed, and becomes the row a search returns for it. The
// commands that read other data (lookup, join, append, inputlookup,
// enrich, intel, threatmatch) are not run here; they are an error.
func RunCommands(ctx context.Context, docs []map[string]any, cmds []query.Command) ([]Row, error) {
	res := &Result{Kind: "events"}
	seen := map[string]bool{}
	for _, d := range docs {
		row := Row{}
		flatten("", d, row)
		if t, ok := row[TimeField]; ok {
			row["_time"] = t
			delete(row, TimeField)
		}
		if m, ok := row[StoredRawField]; ok {
			row[RawField] = m
			delete(row, StoredRawField)
		}
		for k := range row {
			if !seen[k] {
				seen[k] = true
				res.Columns = append(res.Columns, k)
			}
		}
		res.Rows = append(res.Rows, row)
	}
	for _, c := range cmds {
		switch c.(type) {
		case *query.Lookup, *query.Join, *query.Append, *query.Union, *query.MultiSearch, *query.Set, *query.AppendPipe, *query.InputLookup,
			*query.Enrich, *query.Intel, *query.ThreatMatch, *query.MakeResults, *query.EventCount, *query.IPLocation, *query.Map:
			return nil, fmt.Errorf("command %q reads other data", c.Name())
		case *query.AddInfo:
			return nil, fmt.Errorf("command %q needs a search's time range", c.Name())
		}
		if err := applyCommand(ctx, res, c); err != nil {
			return nil, err
		}
	}
	return res.Rows, nil
}
