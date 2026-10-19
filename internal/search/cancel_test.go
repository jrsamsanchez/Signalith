package search

import (
	"context"
	"errors"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// Every row command stops when the search is canceled, rather than
// working through its rows.
func TestRowCommandsStopWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rows := func() *Result {
		return &Result{Columns: []string{"_time", "a", "b", "n", "mv", "x", "y", "xml", "j"}, Rows: []Row{
			{"_time": "2026-10-11T10:00:00Z", "a": "x1 y=2", "b": "b1", "n": int64(1), "mv": []any{"p", "q"}, "x": 1.0, "y": 2.0,
				"xml": "<r><k>v</k></r>", "j": `{"k":"v"}`, "lat": 1.5, "lon": 2.5},
			{"_time": "2026-10-11T09:00:00Z", "a": "x2 y=3", "b": "b2", "n": int64(2), "mv": []any{"r"}, "x": 2.0, "y": 4.0,
				"xml": "<r><k>w</k></r>", "j": `{"k":"w"}`, "lat": 1.6, "lon": 2.6},
		}}
	}
	for _, src := range []string{
		`* | eval c=n+1`,
		`* | anomalydetection n`,
		`* | xyseries a b n`,
		`* | untable a name value`,
		`* | fromjson j`,
		`* | extract`,
		`* | nomv mv`,
		`* | mvcombine b`,
		`* | strcat a b c`,
		`* | rangemap field=n low=0-1 high=2-9`,
		`* | foreach n [eval <<FIELD>>=<<FIELD>>*2]`,
		`* | kmeans k=2 x y`,
		`* | mvexpand mv`,
		`* | makemv delim=" " a`,
		`* | addtotals`,
		`* | uniq`,
		`* | convert num(n)`,
		`* | setfields z=1`,
		`* | xmlkv xml`,
		`* | trendline sma2(n)`,
		`* | accum n`,
		`* | delta n`,
		`* | autoregress n`,
		`* | fieldsummary`,
		`* | contingency a b`,
		`* | streamstats count`,
		`* | bin n span=1`,
		`* | regex a="x"`,
		`* | abstract`,
		`* | cluster field=a`,
		`* | xpath field=xml "//k"`,
		`* | rex field=a mode=sed "s/x/z/"`,
		`* | geostats latfield=lat longfield=lon count`,
		`* | concurrency duration=n`,
		`* | format`,
		`* | correlate`,
		`* | timewrap 1h`,
	} {
		q, err := query.Parse(src)
		if err != nil {
			t.Errorf("%s: %v", src, err)
			continue
		}
		if err := applyCommand(ctx, rows(), q.Commands[0]); !errors.Is(err, context.Canceled) {
			t.Errorf("%s: err = %v, want canceled", src, err)
		}
	}
}
