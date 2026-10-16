package detect

import (
	"cmp"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
)

// cloudSourcetypes are the sourcetypes of cloud records, whose field
// names the sender chooses in part.
var cloudSourcetypes = []string{ingest.CloudTrailSourcetype, ingest.AzureADSourcetype, ingest.AzureActivitySourcetype, ingest.O365Sourcetype, ingest.GCPSourcetype, ingest.OktaSourcetype,
	ingest.GitHubSourcetype}

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

// queryFields are the fields a query searches and groups by, leaving out
// those its own commands make (eval, rex, rename, spath, earlier stats).
func queryFields(q *query.Query) []string {
	var out []string
	made := map[string]bool{}
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
	read := func(fs ...string) {
		for _, f := range fs {
			if f != "" && !made[f] {
				out = append(out, f)
			}
		}
	}
	aggs := func(as []query.Agg) {
		for _, a := range as {
			made[a.Column()] = true
		}
	}
	for _, c := range q.Commands {
		switch c := c.(type) {
		case *query.Stats:
			read(c.By...)
			for _, a := range c.Aggs {
				read(a.Field)
			}
			aggs(c.Aggs)
		case *query.EventStats:
			aggs(c.Aggs)
		case *query.StreamStats:
			aggs(c.Aggs)
		case *query.Eval:
			for _, a := range c.Assigns {
				made[a.Field] = true
			}
		case *query.Rex:
			if re, err := regexp.Compile(strings.ReplaceAll(c.Pattern, "(?<", "(?P<")); err == nil {
				for _, n := range re.SubexpNames() {
					made[n] = true
				}
			}
		case *query.Rename:
			for _, p := range c.Pairs {
				made[p[1]] = true
			}
		case *query.Spath:
			made[cmp.Or(c.Output, c.Path)] = true
		case *query.FromJSON:
			// Any field after it may be one of the JSON's keys.
			return out
		}
	}
	return out
}
