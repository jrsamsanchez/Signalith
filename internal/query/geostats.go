package query

import (
	"math"
	"strconv"
	"strings"
)

// Geostats counts rows in a grid of map squares: one row per square
// (geobin) with the average latitude and longitude of its rows and the
// functions' values, split into columns by By.
type Geostats struct {
	LatField, LonField string
	SpanLat, SpanLon   float64
	Aggs               []Agg
	By                 string
	Limit              int // By values kept as columns, the largest first
}

func (*Geostats) Name() string { return "geostats" }

const (
	defaultGeoLat     = "lat"
	defaultGeoLon     = "lon"
	defaultGeoSpanLat = 22.5
	defaultGeoSpanLon = 45.0
	minGeoSpan        = 0.000001
	// GeoBinField, GeoLatField and GeoLonField are the fields geostats
	// writes for each square.
	GeoBinField   = "geobin"
	GeoLatField   = "latitude"
	GeoLonField   = "longitude"
	geostatsUsage = "geostats [latfield=lat] [longfield=lon] [binspanlat=22.5] [binspanlong=45] [globallimit=10] count [by field]"
)

func (p *parser) parseGeostats(cmd token) (Command, error) {
	c := &Geostats{LatField: defaultGeoLat, LonField: defaultGeoLon, SpanLat: defaultGeoSpanLat, SpanLon: defaultGeoSpanLon, Limit: DefaultChartLimit}
	for {
		t, key, ok := p.option()
		if !ok {
			break
		}
		var err error
		switch key {
		case "latfield":
			c.LatField, err = p.optionName("geostats", key)
		case "longfield":
			c.LonField, err = p.optionName("geostats", key)
		case "binspanlat", "binspanlong":
			hi := 180.0
			if key == "binspanlong" {
				hi = 360
			}
			vt := p.next()
			f, perr := strconv.ParseFloat(vt.text, 64)
			if vt.kind != tokWord || perr != nil || math.IsNaN(f) || f < minGeoSpan || f > hi {
				return nil, errorf(vt.pos, "geostats %s= takes a number of degrees from %s to %s", key, formatNum(minGeoSpan), formatNum(hi))
			}
			if key == "binspanlat" {
				c.SpanLat = f
			} else {
				c.SpanLon = f
			}
		case "globallimit":
			c.Limit, err = p.optionInt("geostats", key, 0, MaxSeriesColumns)
		default:
			return nil, errorf(t.pos, "unknown geostats option %q; geostats expects: %s", t.text, geostatsUsage)
		}
		if err != nil {
			return nil, err
		}
	}
	if p.peek().kind == tokEOF || p.peek().kind == tokPipe || p.isKeywordFold("by") {
		c.Aggs = []Agg{{Func: "count"}}
	} else {
		var err error
		if c.Aggs, err = p.parseChartAggs(cmd.pos); err != nil {
			return nil, err
		}
	}
	if p.isKeywordFold("by") {
		byTok := p.next()
		by, err := p.fieldList(true)
		if err != nil {
			return nil, err
		}
		if len(by) != 1 {
			return nil, errorf(byTok.pos, "geostats splits by one field: geostats count by action")
		}
		if len(c.Aggs) > 1 {
			return nil, errorf(cmd.pos, "geostats with a split field takes one function")
		}
		c.By = by[0]
	}
	return c, p.endCommand()
}

func geostatsString(c *Geostats) string {
	parts := []string{"geostats"}
	if c.LatField != defaultGeoLat {
		parts = append(parts, "latfield="+optionValue(c.LatField))
	}
	if c.LonField != defaultGeoLon {
		parts = append(parts, "longfield="+optionValue(c.LonField))
	}
	if c.SpanLat != defaultGeoSpanLat {
		parts = append(parts, "binspanlat="+formatNum(c.SpanLat))
	}
	if c.SpanLon != defaultGeoSpanLon {
		parts = append(parts, "binspanlong="+formatNum(c.SpanLon))
	}
	if c.Limit != DefaultChartLimit {
		parts = append(parts, "globallimit="+strconv.Itoa(c.Limit))
	}
	parts = append(parts, aggList(c.Aggs))
	if c.By != "" {
		parts = append(parts, "by "+chartName(c.By))
	}
	return strings.Join(parts, " ")
}
