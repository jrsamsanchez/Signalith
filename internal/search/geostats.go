// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"math"
	"strconv"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// applyGeostats sorts the rows with a usable latitude and longitude into
// map squares of c.SpanLat by c.SpanLon degrees and replaces them with
// one row per square: its geobin name, the average latitude and
// longitude of its rows, and the functions' values, which with c.By are
// split into a column per value as chart does.
func applyGeostats(ctx context.Context, res *Result, c *query.Geostats) error {
	ev := evaluatorFor(ctx)
	type centre struct {
		lat, lon float64
		n        int
	}
	centres := map[string]*centre{}
	var rows []Row
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		lat, ok1 := evNum(r[c.LatField])
		lon, ok2 := evNum(r[c.LonField])
		if !ok1 || !ok2 || !finite(lat) || !finite(lon) || lat < -90 || lat > 90 || lon < -180 || lon > 180 {
			continue
		}
		y := int64(math.Floor((lat + 90) / c.SpanLat))
		x := int64(math.Floor((lon + 180) / c.SpanLon))
		bin := "bin_id_zl_0_y_" + strconv.FormatInt(y, 10) + "_x_" + strconv.FormatInt(x, 10)
		cn := centres[bin]
		if cn == nil {
			if !ev.charge(len(bin) + fieldOverhead) {
				return ev.err
			}
			cn = &centre{}
			centres[bin] = cn
		}
		cn.lat += lat
		cn.lon += lon
		cn.n++
		if !ev.newField(r, query.GeoBinField) || !ev.charge(len(bin)) {
			return ev.err
		}
		r[query.GeoBinField] = bin
		rows = append(rows, r)
	}
	res.Rows = rows
	// stats by the square (and the split field), then with a split field
	// a column per split value, as chart does.
	st := &query.Stats{Aggs: c.Aggs, By: []string{query.GeoBinField}}
	if c.By != "" {
		st.By = append(st.By, c.By)
	}
	if err := applyCommand(ctx, res, st); err != nil {
		return err
	}
	if c.By != "" {
		xy := &query.XYSeries{X: query.GeoBinField, Y: c.By, Values: []string{c.Aggs[0].Column()}, Limit: c.Limit}
		if err := applyCommand(ctx, res, xy); err != nil {
			return err
		}
	}
	for _, r := range res.Rows {
		bin, _ := r[query.GeoBinField].(string)
		cn := centres[bin]
		if cn == nil || cn.n == 0 {
			continue
		}
		if !ev.charge(2 * (fieldOverhead + 8)) {
			return ev.err
		}
		r[query.GeoLatField] = numOut(cn.lat / float64(cn.n))
		r[query.GeoLonField] = numOut(cn.lon / float64(cn.n))
	}
	cols := []string{query.GeoBinField, query.GeoLatField, query.GeoLonField}
	for _, col := range res.Columns {
		if col != query.GeoBinField && col != query.GeoLatField && col != query.GeoLonField {
			cols = append(cols, col)
		}
	}
	res.Columns, res.Kind = cols, "table"
	return nil
}
