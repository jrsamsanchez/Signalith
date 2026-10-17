package search

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// kmeansFields are the fields kmeans reads: the named ones, or every
// column but _ fields that holds a number in some row.
func kmeansFields(ctx context.Context, res *Result, named []string) ([]string, error) {
	if len(named) > 0 {
		return named, nil
	}
	var out []string
	for _, f := range res.Columns {
		if f == RawField || strings.HasPrefix(f, "_") || strings.HasPrefix(f, "\x00") {
			continue
		}
		for i, r := range res.Rows {
			if i%checkEvery == 0 && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if _, ok := outlierNum(r[f]); ok {
				out = append(out, f)
				break
			}
		}
	}
	if len(out) > query.MaxKMeansFields {
		return nil, &QueryError{Msg: fmt.Sprintf("kmeans reads at most %d fields, and the results have %d with numbers; name the fields to use", query.MaxKMeansFields, len(out))}
	}
	return out, nil
}

// kmeansDist is how far apart a and b are, by c's distance.
func kmeansDist(kind string, a, b []float64) float64 {
	switch kind {
	case "l1":
		d := 0.0
		for i := range a {
			d += math.Abs(a[i] - b[i])
		}
		return d
	case "cos":
		dot, na, nb := 0.0, 0.0, 0.0
		for i := range a {
			dot += a[i] * b[i]
			na += a[i] * a[i]
			nb += b[i] * b[i]
		}
		if na == 0 || nb == 0 {
			return 1
		}
		return 1 - dot/math.Sqrt(na*nb)
	}
	d := 0.0
	for i := range a {
		d += (a[i] - b[i]) * (a[i] - b[i])
	}
	return d
}

// kmeansRun is one run from a k-means++ start drawn with seed: each row's
// cluster, the centroids and their total distance to their rows.
func kmeansRun(ev *evaluator, c *query.KMeans, pts [][]float64, seed uint64) ([]int, [][]float64, float64, bool) {
	n, d := len(pts), len(pts[0])
	rng := rand.New(rand.NewPCG(seed, 0x6b6d65616e73))
	var cents [][]float64
	cents = append(cents, append([]float64(nil), pts[rng.IntN(n)]...))
	var near []float64
	for range pts {
		near = append(near, math.Inf(1))
	}
	for len(cents) < c.K {
		if !ev.stepN(n * d) {
			return nil, nil, 0, false
		}
		last := cents[len(cents)-1]
		total := 0.0
		for i, p := range pts {
			near[i] = math.Min(near[i], kmeansDist(c.Distance, p, last))
			if finite(near[i]) {
				total += near[i]
			}
		}
		// A point is picked with chance in proportion to its distance from
		// the centroids so far; when every point sits on one, any will do.
		pick := rng.IntN(n)
		if total > 0 && finite(total) {
			r := rng.Float64() * total
			for i, w := range near {
				if r -= w; r <= 0 {
					pick = i
					break
				}
			}
		}
		cents = append(cents, append([]float64(nil), pts[pick]...))
	}
	var assign []int
	for range pts {
		assign = append(assign, -1)
	}
	var sums [][]float64
	var counts []int
	for range cents {
		sums = append(sums, append([]float64(nil), cents[0]...))
		counts = append(counts, 0)
	}
	for iter := 0; iter < c.MaxIters; iter++ {
		changed := false
		for i, p := range pts {
			if !ev.stepN(c.K * d) {
				return nil, nil, 0, false
			}
			best, bestD := 0, math.Inf(1)
			for j, cent := range cents {
				if dist := kmeansDist(c.Distance, p, cent); dist < bestD {
					best, bestD = j, dist
				}
			}
			if assign[i] != best {
				assign[i], changed = best, true
			}
		}
		if !changed {
			break
		}
		if !ev.stepN(n * d) {
			return nil, nil, 0, false
		}
		for j := range sums {
			clear(sums[j])
			counts[j] = 0
		}
		for i, p := range pts {
			counts[assign[i]]++
			for f, x := range p {
				sums[assign[i]][f] += x
			}
		}
		moved := 0.0
		for j := range cents {
			if counts[j] == 0 {
				continue // an empty cluster keeps its centroid
			}
			var next []float64
			for _, s := range sums[j] {
				next = append(next, s/float64(counts[j]))
			}
			moved = math.Max(moved, kmeansDist(c.Distance, cents[j], next))
			cents[j] = next
		}
		if moved <= c.Tol && c.Tol > 0 {
			break
		}
	}
	total := 0.0
	for i, p := range pts {
		total += kmeansDist(c.Distance, p, cents[assign[i]])
	}
	return assign, cents, total, true
}

// applyKMeans puts each row with numbers in all of c's fields into one of
// c.K clusters, the best of c.Reps runs, and numbers the clusters from 1
// in the order their first rows appear. Rows missing a number get none.
func applyKMeans(ctx context.Context, res *Result, c *query.KMeans) error {
	ev := evaluatorFor(ctx)
	fields, err := kmeansFields(ctx, res, c.Fields)
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		return &QueryError{Msg: "kmeans found no fields with numbers; name the fields to cluster by"}
	}
	var pts [][]float64
	var rows []int
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		if !ev.stepN(len(fields)) {
			return ev.err
		}
		var p []float64
		for _, f := range fields {
			x, ok := outlierNum(r[f])
			if !ok {
				p = nil
				break
			}
			p = append(p, x)
		}
		if p == nil {
			continue
		}
		if !ev.charge(8*len(p) + 48) {
			return ev.err
		}
		pts, rows = append(pts, p), append(rows, i)
	}
	if len(pts) < c.K {
		return &QueryError{Msg: fmt.Sprintf("kmeans k=%d needs at least %d rows with numbers in %s, and there are %d", c.K, c.K, strings.Join(fields, ", "), len(pts))}
	}
	var best []int
	var cents [][]float64
	bestTotal := math.Inf(1)
	for rep := range c.Reps {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		a, cs, total, ok := kmeansRun(ev, c, pts, uint64(rep)+1)
		if !ok {
			return ev.err
		}
		if best == nil || total < bestTotal {
			best, cents, bestTotal = a, cs, total
		}
	}
	number := map[int]int64{}
	for i, j := range best {
		if _, ok := number[j]; !ok {
			number[j] = int64(len(number) + 1)
		}
		r := res.Rows[rows[i]]
		if !ev.newField(r, c.ClusterField) {
			return ev.err
		}
		r[c.ClusterField] = number[j]
		if c.ShowCentroid {
			for f, name := range fields {
				col := "centroid_" + name
				if !finite(cents[j][f]) {
					continue
				}
				if !ev.newField(r, col) {
					return ev.err
				}
				r[col] = numOut(cents[j][f])
			}
		}
	}
	addColumn(res, c.ClusterField)
	if c.ShowCentroid {
		for _, name := range fields {
			addColumn(res, "centroid_"+name)
		}
	}
	return nil
}
