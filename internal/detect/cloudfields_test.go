package detect

import (
	"slices"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
)

// cloudSourcetypes are the sourcetypes of cloud records, whose field
// names the sender chooses in part.
var cloudSourcetypes = []string{ingest.CloudTrailSourcetype, ingest.AzureADSourcetype, ingest.AzureActivitySourcetype, ingest.O365Sourcetype}

// TestCloudRuleFieldsMapped checks every field a shipped cloud rule reads
// is mapped up front, so names a caller chooses (a call's tags, an
// Exchange cmdlet's parameters) can't use up a day's budget of new names
// and leave the rule's fields out of the index.
func TestCloudRuleFieldsMapped(t *testing.T) {
	_, ds, err := Packs()
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for _, d := range ds {
		if !slices.ContainsFunc(cloudSourcetypes, func(st string) bool { return strings.Contains(d.Query, "sourcetype="+st) }) {
			continue
		}
		q, err := query.Parse(d.Query)
		if err != nil {
			t.Errorf("%s: %v", d.ID, err)
			continue
		}
		for _, f := range queryFields(q) {
			// _time is the event's time, @timestamp.
			if f != "_time" && !ingest.KnownField(f) && !slices.Contains(missing, f) {
				missing = append(missing, f)
			}
		}
	}
	slices.Sort(missing)
	if len(missing) > 0 {
		t.Errorf("%d fields cloud rules read are not mapped in the index template:\n%q", len(missing), missing)
	}
}

// queryFields are the fields a query searches and groups by.
func queryFields(q *query.Query) []string {
	var out []string
	var walk func(e query.Expr)
	walk = func(e query.Expr) {
		switch x := e.(type) {
		case *query.And:
			for _, c := range x.Children {
				walk(c)
			}
		case *query.Or:
			for _, c := range x.Children {
				walk(c)
			}
		case *query.Not:
			walk(x.Child)
		case *query.Compare:
			out = append(out, x.Field)
		case *query.In:
			out = append(out, x.Field)
		}
	}
	if q.Search != nil {
		walk(q.Search)
	}
	for _, c := range q.Commands {
		if s, ok := c.(*query.Stats); ok {
			out = append(out, s.By...)
			for _, a := range s.Aggs {
				if a.Field != "" {
					out = append(out, a.Field)
				}
			}
		}
	}
	return out
}
