// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"reflect"
	"strings"
	"testing"
)

// drillQuery builds the events query the way the dashboards page does.
func drillQuery(d *Drill, terms ...string) string {
	search := d.Search
	if len(terms) > 0 && !d.Where {
		search = strings.TrimSpace(search + " " + strings.Join(terms, " "))
	}
	if search == "" {
		search = "*"
	}
	q := search + d.Pipe
	if len(terms) > 0 && d.Where {
		q += "\n| where " + strings.Join(terms, " AND ")
	}
	return q
}

func TestDrilldown(t *testing.T) {
	cases := []struct {
		src    string
		want   Drill
		terms  []string
		events string
	}{
		{
			src:    `datamodel=Malware type=threat category!=test | stats dc(dest) as hosts`,
			want:   Drill{Search: `datamodel=Malware type=threat category!=test`},
			events: `datamodel=Malware type=threat category!=test`,
		},
		{
			src:    `datamodel=Network_Traffic direction=outbound | stats count, sum(bytes_out) as bytes by dest, dest_port | sort -count | head 10`,
			want:   Drill{Search: `datamodel=Network_Traffic direction=outbound`, Fields: map[string]string{"dest": "dest", "dest_port": "dest_port"}},
			terms:  []string{`dest="10.0.0.1"`, `dest_port=443`},
			events: `datamodel=Network_Traffic direction=outbound dest="10.0.0.1" dest_port=443`,
		},
		{
			src: `datamodel=Vulnerabilities | stats dc(cve) as cves by dest, product | rename dest as host, product as software`,
			want: Drill{Search: `datamodel=Vulnerabilities`,
				Fields: map[string]string{"host": "dest", "software": "product"}},
		},
		{
			src:    `datamodel=Intrusion_Detection | timechart count by severity`,
			want:   Drill{Search: `datamodel=Intrusion_Detection`, Series: "severity"},
			terms:  []string{`severity=high`},
			events: `datamodel=Intrusion_Detection severity=high`,
		},
		{
			src:    `* | timechart count by datamodel`,
			want:   Drill{Series: "datamodel"},
			events: `*`,
		},
		{
			src:    `action=failure OR action=blocked | top limit=5 user by src`,
			want:   Drill{Search: `(action=failure OR action=blocked)`, Fields: map[string]string{"user": "user", "src": "src"}},
			terms:  []string{`user=bob`},
			events: `(action=failure OR action=blocked) user=bob`,
		},
		{
			// eval makes the field the stats groups by, so the filter
			// has to come after it.
			src:    `datamodel=Web | eval site=lower(dest) | stats count by site`,
			want:   Drill{Search: `datamodel=Web`, Pipe: "\n| eval site=lower(dest)", Where: true, Fields: map[string]string{"site": "site"}},
			terms:  []string{`site=example.com`},
			events: "datamodel=Web\n| eval site=lower(dest)\n| where site=example.com",
		},
		{
			src:    `sourcetype=syslog earliest=-7d latest=-1d | where host!="a" | stats count by host`,
			want:   Drill{Search: `sourcetype=syslog`, Pipe: "\n| where host!=a", Earliest: "-7d", Latest: "-1d", Fields: map[string]string{"host": "host"}},
			terms:  []string{`host=b`},
			events: "sourcetype=syslog host=b\n| where host!=a",
		},
		{
			// Columns eval or a second stats replace no longer drill.
			src:  `* | stats count by host, user | eval user=upper(user)`,
			want: Drill{Fields: map[string]string{"host": "host"}},
		},
		{
			src:  `* | stats count by host | stats avg(count)`,
			want: Drill{},
		},
		{
			// A plain search's events are its results.
			src:    `datamodel=Malware | table dest, signature | head 50`,
			want:   Drill{Search: `datamodel=Malware`, Pipe: "\n| table dest, signature\n| head 50", Events: true},
			terms:  []string{`dest=pc1`},
			events: "datamodel=Malware dest=pc1\n| table dest, signature\n| head 50",
		},
		{
			// head before stats picks which events are counted.
			src:    `datamodel=Malware | head 100 | stats count by dest`,
			want:   Drill{Search: `datamodel=Malware`, Pipe: "\n| head 100", Where: true, Fields: map[string]string{"dest": "dest"}},
			terms:  []string{`dest=pc1`},
			events: "datamodel=Malware\n| head 100\n| where dest=pc1",
		},
	}
	for _, c := range cases {
		q := mustParse(t, c.src)
		got := q.Drilldown()
		if !reflect.DeepEqual(*got, c.want) {
			t.Errorf("Drilldown(%q)\n got %#v\nwant %#v", c.src, *got, c.want)
			continue
		}
		if c.events == "" {
			continue
		}
		ev := drillQuery(got, c.terms...)
		if ev != c.events {
			t.Errorf("events query for %q = %q, want %q", c.src, ev, c.events)
		}
		if _, err := Parse(ev); err != nil {
			t.Errorf("events query %q does not parse: %v", ev, err)
		}
	}
}

// A value missing from the events reads as NOT field=*, in the search or
// in a where.
func TestDrilldownMissingValueParses(t *testing.T) {
	for _, src := range []string{`* | stats count by host`, `* | eval h=host | stats count by h`} {
		d := mustParse(t, src).Drilldown()
		ev := drillQuery(d, `NOT host=*`)
		if _, err := Parse(ev); err != nil {
			t.Errorf("%q: %v", ev, err)
		}
	}
}

func TestDrilldownAfterRoundThreeCommands(t *testing.T) {
	for src, want := range map[string]map[string]string{
		`* | stats count by user, bytes | bin span=100 bytes`:               {"user": "user"},
		`* | stats count by user, src | streamstats count as src`:           {"user": "user"},
		`* | stats count by user, src | eventstats dc(user) as src`:         {"user": "user"},
		`* | stats count by user | appendpipe [stats sum(count) as count]`:  nil,
		`* | stats count by user | append [search * | stats count by user]`: nil,
	} {
		q, err := Parse(src)
		if err != nil {
			t.Fatal(err)
		}
		if got := q.Drilldown().Fields; !reflect.DeepEqual(got, want) {
			t.Errorf("%s: fields = %v, want %v", src, got, want)
		}
	}
}
