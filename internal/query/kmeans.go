// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"math"
	"strconv"
	"strings"
)

// KMeans groups rows by their numbers in Fields into K clusters and
// writes each row's cluster, from 1, to ClusterField.
type KMeans struct {
	Fields       []string // none = every field with numbers, except _ fields
	K            int
	Reps         int // runs from different starts; the tightest wins
	MaxIters     int
	Tol          float64 // a run stops when no centroid moves more than this
	Distance     string  // l2 (squared Euclidean), l1 or cos
	ShowCentroid bool    // add centroid_<field> to each row
	ClusterField string
}

func (*KMeans) Name() string { return "kmeans" }

const (
	// MaxKMeansK bounds kmeans's k=.
	MaxKMeansK = 100
	// MaxKMeansFields bounds the fields kmeans reads.
	MaxKMeansFields = 100

	defaultKMeansK        = 2
	defaultKMeansReps     = 10
	defaultKMeansMaxIters = 10000
	defaultKMeansDistance = "l2"
	defaultKMeansField    = "CLUSTERNUM"

	kmeansUsage = "kmeans [k=2] [reps=10] [maxiters=10000] [t=0] [dt=l2|l1|cos] [showcentroid=true] [cfield=CLUSTERNUM] [field ...]"
)

func (p *parser) parseKMeans(cmd token) (Command, error) {
	c := &KMeans{K: defaultKMeansK, Reps: defaultKMeansReps, MaxIters: defaultKMeansMaxIters, Distance: defaultKMeansDistance, ShowCentroid: true, ClusterField: defaultKMeansField}
	for {
		t := p.peek()
		if t.kind == tokEOF || t.kind == tokPipe {
			break
		}
		if t.kind == tokComma {
			p.next()
			continue
		}
		if t, key, ok := p.option(); ok {
			var err error
			switch key {
			case "k":
				c.K, err = p.optionInt("kmeans", key, 1, MaxKMeansK)
			case "reps":
				c.Reps, err = p.optionInt("kmeans", key, 1, 100)
			case "maxiters":
				c.MaxIters, err = p.optionInt("kmeans", key, 1, 10000)
			case "t":
				vt := p.next()
				f, perr := strconv.ParseFloat(vt.text, 64)
				if vt.kind != tokWord || perr != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
					return nil, errorf(vt.pos, "kmeans t= takes a number of at least 0")
				}
				c.Tol = f
			case "dt":
				vt := p.next()
				switch d := strings.ToLower(vt.text); d {
				case "l2", "sqeuclidean":
					c.Distance = "l2"
				case "l1", "cityblock":
					c.Distance = "l1"
				case "cos", "cosine":
					c.Distance = "cos"
				default:
					return nil, errorf(vt.pos, "kmeans dt= takes l2, l1 or cos")
				}
			case "showcentroid":
				c.ShowCentroid, err = parseBool(p.next())
			case "cfield":
				c.ClusterField, err = p.optionName("kmeans", key)
			default:
				return nil, errorf(t.pos, "unknown kmeans option %q; kmeans expects: %s", t.text, kmeansUsage)
			}
			if err != nil {
				return nil, err
			}
			continue
		}
		if (t.kind == tokWord || t.kind == tokString) && t.text != "" {
			if len(c.Fields) >= MaxKMeansFields {
				return nil, errorf(t.pos, "kmeans takes at most %d fields", MaxKMeansFields)
			}
			p.next()
			c.Fields = append(c.Fields, t.text)
			continue
		}
		return nil, errorf(t.pos, "unexpected %s; kmeans expects: %s", describe(t), kmeansUsage)
	}
	return c, nil
}

func kmeansString(c *KMeans) string {
	s := "kmeans"
	if c.K != defaultKMeansK {
		s += " k=" + strconv.Itoa(c.K)
	}
	if c.Reps != defaultKMeansReps {
		s += " reps=" + strconv.Itoa(c.Reps)
	}
	if c.MaxIters != defaultKMeansMaxIters {
		s += " maxiters=" + strconv.Itoa(c.MaxIters)
	}
	if c.Tol != 0 {
		s += " t=" + formatNum(c.Tol)
	}
	if c.Distance != defaultKMeansDistance {
		s += " dt=" + c.Distance
	}
	if !c.ShowCentroid {
		s += " showcentroid=false"
	}
	if c.ClusterField != defaultKMeansField {
		s += " cfield=" + optionValue(c.ClusterField)
	}
	for _, f := range c.Fields {
		s += " " + outlierField(f)
	}
	return s
}
