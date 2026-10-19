package query

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

// After a summary, a command that writes a column takes it out of the
// columns whose values name events; the others still do.
func TestDrilldownAfterSummary(t *testing.T) {
	base := "x=1 | stats count by a, b, range, City, a_p1, centroid_1, info_min_time"
	for after, want := range map[string]string{
		"fillnull":                              "",
		"fillnull a":                            "City a_p1 b centroid_1 info_min_time range",
		"mvexpand a":                            "City a_p1 b centroid_1 info_min_time range",
		"convert ctime(a)":                      "City a_p1 b centroid_1 info_min_time range",
		"convert ctime(a*)":                     "City b centroid_1 info_min_time range",
		"convert none(a)":                       "City a a_p1 b centroid_1 info_min_time range",
		"convert num(count) as a":               "City a_p1 b centroid_1 info_min_time range",
		"makemv a":                              "City a_p1 b centroid_1 info_min_time range",
		"nomv a":                                "City a_p1 b centroid_1 info_min_time range",
		"mvcombine a":                           "City a_p1 b centroid_1 info_min_time range",
		"strcat b City a":                       "City a_p1 b centroid_1 info_min_time range",
		"rangemap field=count low=0-1":          "City a a_p1 b centroid_1 info_min_time",
		"foreach a* [eval <<FIELD>>=1]":         "City b centroid_1 info_min_time range",
		"addtotals labelfield=a":                "City a_p1 b centroid_1 info_min_time range",
		"accum count as a":                      "City a_p1 b centroid_1 info_min_time range",
		"delta count as a":                      "City a_p1 b centroid_1 info_min_time range",
		"autoregress a p=1":                     "City a b centroid_1 info_min_time range",
		"autoregress count as a":                "City a_p1 b centroid_1 info_min_time range",
		"trendline sma2(count) as a":            "City a_p1 b centroid_1 info_min_time range",
		"filldown":                              "",
		"filldown a*":                           "City b centroid_1 info_min_time range",
		"concurrency duration=count output=a":   "City a_p1 b centroid_1 info_min_time range",
		"outlier":                               "",
		"outlier a*":                            "City b centroid_1 info_min_time range",
		"addinfo":                               "City a a_p1 b centroid_1 range",
		"iplocation b":                          "a a_p1 b centroid_1 info_min_time range",
		"rex field=b \"(?<z>.)\"":               "",
		"spath":                                 "",
		"xpath field=b outfield=a \"//k\"":      "City a_p1 b centroid_1 info_min_time range",
		"kmeans k=2 count":                      "City a a_p1 b info_min_time range",
		"setfields a=1":                         "City a_p1 b centroid_1 info_min_time range",
		"predict count as a":                    "City a_p1 b centroid_1 info_min_time range",
		"anomalydetection count":                "City a a_p1 b centroid_1 info_min_time range",
		"anomalydetection action=summary count": "",
		"abstract":                              "City a a_p1 b centroid_1 info_min_time range",
		"bin a span=1":                          "City a_p1 b centroid_1 info_min_time range",
		"bin count span=1 as a":                 "City a_p1 b centroid_1 info_min_time range",
		"streamstats count as a":                "City a_p1 b centroid_1 info_min_time range",
		"eventstats max(count) as a":            "City a_p1 b centroid_1 info_min_time range",
		"transpose":                             "",
		"stats count":                           "",
		"eval a=1":                              "City a_p1 b centroid_1 info_min_time range",
		"rename a as b":                         "City a_p1 b centroid_1 info_min_time range",
	} {
		q, err := Parse(base + " | " + after)
		if err != nil {
			t.Errorf("%s: %v", after, err)
			continue
		}
		d := q.Drilldown()
		got := strings.Join(slices.Sorted(maps.Keys(d.Fields)), " ")
		if got != want {
			t.Errorf("after %s: fields %q, want %q", after, got, want)
		}
	}
	// A renamed column keeps naming the field it came from.
	d := mustParse(t, base+" | rename a as b").Drilldown()
	if d.Fields["b"] != "a" {
		t.Errorf("renamed column = %v", d.Fields)
	}
}

// Commands before the summary go in the pipe; those that make or change
// fields, or a where of an expression, make the filters a where after it.
func TestDrilldownPipe(t *testing.T) {
	for src, where := range map[string]bool{
		"x=1 | where len(a) > 3 | stats count by a": true,
		"x=1 | where a=1 | stats count by a":        false,
		"x=1 | table a | sort a | stats count by a": false,
		"x=1 | head 5 | stats count by a":           true,
		"x=1 | head 5":                              false,
		"x=1 | eval b=1 | stats count by a":         true,
		"x=1 | outputlookup t | stats count by a":   false,
		"x=1 | chart count over a by b":             false,
	} {
		d := mustParse(t, src).Drilldown()
		if d.Where != where {
			t.Errorf("%s: where = %v", src, d.Where)
		}
		if strings.Contains(src, "outputlookup") && strings.Contains(d.Pipe, "outputlookup") {
			t.Errorf("%s: pipe %q keeps the outputlookup", src, d.Pipe)
		}
	}
	d := mustParse(t, "x=1 | chart count over a by b").Drilldown()
	if d.Fields["a"] != "a" || d.Series != "b" {
		t.Errorf("chart drill = %+v", d)
	}
}
