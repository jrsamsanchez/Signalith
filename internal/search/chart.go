package search

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// chartCommands is what chart stands for: stats by the over and split
// fields, then, with a split field, xyseries to make its values columns.
func chartCommands(c *query.Chart) []query.Command {
	st := &query.Stats{Aggs: c.Aggs, By: []string{c.Over}}
	if c.By == "" {
		return []query.Command{st}
	}
	st.By = append(st.By, c.By)
	return []query.Command{st, &query.XYSeries{X: c.Over, Y: c.By, Values: []string{c.Aggs[0].Column()}, Limit: c.Limit}}
}

// applyXYSeries makes one row per X value with one column per Y value,
// first seen first; with Limit, the Y values whose first value field adds
// up to the most.
func applyXYSeries(ctx context.Context, res *Result, c *query.XYSeries) error {
	ev := evaluatorFor(ctx)
	var order []string // Y values
	totals := map[string]float64{}
	seen := map[string]int{}
	type cell struct {
		x, y string
		r    Row
	}
	var cells []cell
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		x, okx := evStr(r[c.X])
		y, oky := evStr(r[c.Y])
		if !okx || !oky || r[c.X] == nil || r[c.Y] == nil {
			continue
		}
		if _, ok := seen[y]; !ok {
			seen[y] = len(order)
			order = append(order, y)
		}
		if f, ok := asFloat(r[c.Values[0]]); ok {
			totals[y] += f
		}
		cells = append(cells, cell{x, y, r})
	}
	keep := append([]string(nil), order...)
	if c.Limit > 0 && len(keep) > c.Limit {
		sort.SliceStable(keep, func(i, j int) bool { return totals[keep[i]] > totals[keep[j]] })
		keep = keep[:c.Limit]
		sort.Slice(keep, func(i, j int) bool { return seen[keep[i]] < seen[keep[j]] })
	}
	if len(keep) > query.MaxSeriesColumns {
		keep = keep[:query.MaxSeriesColumns]
		res.Truncated = true
	}
	kept := map[string]bool{}
	for _, y := range keep {
		kept[y] = true
	}
	column := func(v, y string) string {
		if len(c.Values) == 1 {
			return y
		}
		return v + ": " + y
	}
	rows := map[string]Row{}
	var out []Row
	for _, cl := range cells {
		if !kept[cl.y] {
			continue
		}
		row := rows[cl.x]
		if row == nil {
			row = Row{c.X: cl.r[c.X]}
			rows[cl.x] = row
			out = append(out, row)
		}
		for _, v := range c.Values {
			if val, ok := cl.r[v]; ok && val != nil {
				col := column(v, cl.y)
				if !ev.charge(valueSize(val) + len(col)) {
					return ev.err
				}
				row[col] = val
			}
		}
	}
	cols := []string{c.X}
	for _, v := range c.Values {
		for _, y := range keep {
			cols = append(cols, column(v, y))
		}
	}
	res.Rows, res.Columns, res.Kind = out, cols, "table"
	return nil
}

// applyUntable makes one row per cell: the X field, the column's name and
// its value.
func applyUntable(ctx context.Context, res *Result, c *query.Untable) error {
	ev := evaluatorFor(ctx)
	var out []Row
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		for _, col := range res.Columns {
			v, ok := r[col]
			if col == c.X || !ok || v == nil {
				continue
			}
			if len(out) >= maxAppendRows {
				res.Truncated = true
				break
			}
			if !ev.charge(valueSize(v) + valueSize(r[c.X]) + len(col)) {
				return ev.err
			}
			out = append(out, Row{c.X: r[c.X], c.Label: col, c.Value: v})
		}
	}
	res.Rows, res.Columns, res.Kind = out, []string{c.X, c.Label, c.Value}, "table"
	return nil
}

// maxSpathFields caps the fields spath without a path extracts from one
// value.
const maxSpathFields = 500

// maxSpathNames caps the field names spath adds across a search, so a
// search whose events each hold other keys cannot make a column for each.
const maxSpathNames = query.MaxSeriesColumns

// applySpath extracts fields from the JSON in c.Input: the value at
// c.Path, or every value named by its path (items{}.id for each id of an
// array of items). Values that are objects or arrays are written as JSON.
func applySpath(ctx context.Context, res *Result, c *query.Spath) error {
	ev := evaluatorFor(ctx)
	out := c.Output
	if out == "" {
		out = c.Path
	}
	var path []string
	if c.Path != "" {
		path = strings.Split(c.Path, ".")
	}
	added := map[string]bool{}
	var order []string
	set := func(r Row, name string, v any) bool {
		if v == nil {
			return true
		}
		if !added[name] && len(order) >= maxSpathNames {
			res.Truncated = true
			return true
		}
		if !ev.step() || !ev.newField(r, name) || !ev.charge(valueSize(v)) {
			return false
		}
		r[name] = v
		if !added[name] {
			added[name] = true
			order = append(order, name)
		}
		return true
	}
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		s, ok := evStr(r[c.Input])
		if !ok || s == "" {
			continue
		}
		if !ev.stepN(len(s)) {
			return ev.err
		}
		dec := json.NewDecoder(strings.NewReader(s))
		dec.UseNumber()
		var doc any
		if dec.Decode(&doc) != nil {
			continue
		}
		if path != nil {
			vals := spathAt(doc, path, nil)
			switch {
			case len(vals) == 0:
				continue
			case len(vals) == 1 && !strings.Contains(c.Path, "{}"):
				if !set(r, out, spathValue(vals[0])) {
					return ev.err
				}
			default:
				if len(vals) > maxMultiValues {
					vals = vals[:maxMultiValues]
				}
				var mv []any
				for _, v := range vals {
					mv = append(mv, spathValue(v))
				}
				if !set(r, out, mvOut(mv)) {
					return ev.err
				}
			}
			continue
		}
		fields := map[string][]any{}
		var names []string
		spathAll(doc, "", fields, &names)
		for _, name := range names {
			vs := fields[name]
			var v any = vs[0]
			if len(vs) > 1 || strings.HasSuffix(name, "{}") {
				v = mvOut(vs)
			}
			if !set(r, name, v) {
				return ev.err
			}
		}
	}
	have := map[string]bool{}
	for _, col := range res.Columns {
		have[col] = true
	}
	for _, name := range order {
		if !have[name] {
			addColumn(res, name)
		}
	}
	return nil
}

// spathAt returns the values at path in v; a part ending in {} goes into
// every item of an array.
func spathAt(v any, path []string, out []any) []any {
	if len(path) == 0 {
		return append(out, v)
	}
	if len(out) >= maxMultiValues {
		return out
	}
	part := path[0]
	each := strings.HasSuffix(part, "{}")
	name := strings.TrimSuffix(part, "{}")
	if name != "" {
		m, ok := v.(map[string]any)
		if !ok {
			return out
		}
		if v, ok = m[name]; !ok {
			return out
		}
	}
	if !each {
		return spathAt(v, path[1:], out)
	}
	items, ok := v.([]any)
	if !ok {
		return out
	}
	for _, it := range items {
		out = spathAt(it, path[1:], out)
	}
	return out
}

// spathAll collects every scalar value in v under its path.
func spathAll(v any, prefix string, fields map[string][]any, names *[]string) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			name := k
			if prefix != "" {
				name = prefix + "." + k
			}
			spathAll(x[k], name, fields, names)
		}
	case []any:
		for _, it := range x {
			spathAll(it, prefix+"{}", fields, names)
		}
	case nil:
	default:
		if prefix == "" {
			return
		}
		if _, ok := fields[prefix]; !ok {
			if len(*names) >= maxSpathFields {
				return
			}
			*names = append(*names, prefix)
		}
		if len(fields[prefix]) < maxMultiValues {
			fields[prefix] = append(fields[prefix], spathValue(x))
		}
	}
}

// spathValue is a JSON value as a field value: numbers as numbers, true
// and false as text, objects and arrays as JSON.
func spathValue(v any) any {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return toNumber(x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	case nil:
		return nil
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// applyFromJSON extracts the top-level keys of the JSON object in
// c.Field: arrays of plain values become multivalue fields, objects and
// other arrays JSON text.
func applyFromJSON(ctx context.Context, res *Result, c *query.FromJSON) error {
	ev := evaluatorFor(ctx)
	added := map[string]bool{}
	var order []string
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		s, ok := evStr(r[c.Field])
		if !ok || s == "" {
			continue
		}
		if !ev.stepN(len(s)) {
			return ev.err
		}
		dec := json.NewDecoder(strings.NewReader(s))
		dec.UseNumber()
		var doc map[string]any
		if dec.Decode(&doc) != nil {
			continue
		}
		keys := make([]string, 0, len(doc))
		for k := range doc {
			if k != "" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		if len(keys) > maxSpathFields {
			keys = keys[:maxSpathFields]
			res.Truncated = true
		}
		for _, k := range keys {
			v := fromJSONValue(doc[k])
			if v == nil {
				continue
			}
			name := c.Prefix + k
			if !added[name] && len(order) >= maxSpathNames {
				res.Truncated = true
				continue
			}
			if !ev.step() || !ev.newField(r, name) || !ev.charge(valueSize(v)) {
				return ev.err
			}
			r[name] = v
			if !added[name] {
				added[name] = true
				order = append(order, name)
			}
		}
	}
	have := map[string]bool{}
	for _, col := range res.Columns {
		have[col] = true
	}
	for _, name := range order {
		if !have[name] {
			addColumn(res, name)
		}
	}
	return nil
}

// fromJSONValue is a top-level JSON value as a field value: an array of
// plain values is a multivalue field, anything else as spath writes it.
func fromJSONValue(v any) any {
	items, ok := v.([]any)
	if !ok {
		return spathValue(v)
	}
	var mv []any
	for _, it := range items {
		switch it.(type) {
		case map[string]any, []any:
			return spathValue(v)
		}
		if x := spathValue(it); x != nil && len(mv) < maxMultiValues {
			mv = append(mv, x)
		}
	}
	if len(mv) == 0 {
		return nil
	}
	return mvOut(mv)
}
