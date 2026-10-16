package api

import (
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func TestExplainNewCommands(t *testing.T) {
	q, err := query.Parse(`datamodel=Endpoint
| rex field=process max_match=0 "(?<flag>-\w+)"
| eval kb=round(bytes / 1024, 1)
| where len(process) > 100
| dedup 2 host keepempty=true
| fillnull value=none user
| eventstats count by host
| rare limit=5 process_name`)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(Explain(q), "\n")
	for _, want := range []string{
		"Extract flag from process with the regular expression (?<flag>-\\w+), keeping every match.",
		"Set kb to round(bytes / 1024, 1).",
		"Keep only rows where len(process) > 100 holds.",
		"Keep only the first 2 rows for each host; rows missing one of these fields are kept.",
		"Fill missing values in user with none.",
		"Add the number of events for each host to every row, keeping the rows.",
		"List the 5 least common values of process_name",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Explain is missing %q in:\n%s", want, got)
		}
	}
}

func TestExplainStatsFunctions(t *testing.T) {
	q, err := query.Parse(`* | stats median(bytes), p95(duration) as slow, perc1(x), stdev(bytes), values(user), latest(src) by dest`)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(Explain(q), "\n")
	want := "Calculate the median bytes, the 95th percentile of duration (as slow), the 1st percentile of x, the standard deviation of bytes, the distinct values of user, the newest src for each dest."
	if !strings.Contains(got, want) {
		t.Errorf("Explain = %s\nwant %s", got, want)
	}
}
