package splcheck

import (
	"context"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

const (
	joinMain    = "| tstats count from datamodel=Endpoint.Processes where Processes.process_name=java.exe by Processes.dest Processes.process_guid Processes.process_id Processes.process_name\n| `drop_dm_object_name(Processes)`\n"
	joinSubName = "| tstats count from datamodel=Endpoint.Filesystem where Filesystem.file_name=*.jsp by Filesystem.dest Filesystem.process_name Filesystem.file_name | `drop_dm_object_name(Filesystem)`"
	joinSub     = "| tstats count from datamodel=Endpoint.Filesystem where Filesystem.file_name=*.jsp by Filesystem.dest Filesystem.process_guid Filesystem.process_id Filesystem.file_name | `drop_dm_object_name(Filesystem)`"
)

// The join stages Signalith cannot run as Splunk does are refused, each
// with its reason.
func TestJoinRefusals(t *testing.T) {
	for stage, want := range map[string]string{
		"join process-guid [" + joinSub + "]":                                                                         "a join on process-guid is not supported",
		"join type=right process_guid [" + joinSub + "]":                                                              "a join of type=right is not supported",
		"join max=x process_guid [" + joinSub + "]":                                                                   "a join with max=x is not supported",
		"join max=-1 process_guid [" + joinSub + "]":                                                                  "a join with max=-1 is not supported",
		"join max=1000 process_guid [" + joinSub + "]":                                                                "a join with max=1000 is not supported",
		"join usetime=t process_guid [" + joinSub + "]":                                                               "a join with the option usetime is not supported",
		"join type=inner [" + joinSub + "]":                                                                           "a join with no fields is not supported",
		"join process_guid [search `sysmon` EventCode=11]":                                                            "a join of a subsearch that is not a tstats search is not supported",
		"join process_guid [| tstats count from nowhere]":                                                             "join's subsearch: search is not a tstats search",
		"join process_guid [" + joinSub + " | join process_guid [" + joinSub + "]]":                                   "in a join's subsearch",
		"join dest [| tstats count from datamodel=Web where Web.status=500 by Web.dest | `drop_dm_object_name(Web)`]": "a join of a subsearch of Web is not supported",
		"join process_name [" + joinSubName + " | eval process_name=lower(process_name)]":                             "a join on Filesystem process_name",
		"join process_name [" + joinSubName + " | rex field=process_name mode=sed \"s/a/b/\"]":                        "a join on Filesystem process_name",
		"join process_guid [" + joinSub + " | stats count by file_name]":                                              "a join on Filesystem process_guid",
		"join process_guid [" + joinSub + " | eventstats count by process_guid]":                                      "",
	} {
		_, err := Parse(rule(joinMain+"| "+stage), nil)
		if err == nil {
			t.Errorf("%s: parsed", stage)
			continue
		}
		if want != "" && !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", stage, err, want)
		}
	}

	// The options Signalith runs are kept in the stage it runs.
	r, err := Parse(rule(joinMain+"| join type=outer max=0 process_guid, process_id ["+joinSub+"]"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Joins) != 1 || !r.Joins[0].Left || r.Joins[0].Max != 0 || strings.Join(r.Joins[0].Fields, ",") != "process_guid,process_id" {
		t.Fatalf("join = %+v", r.Joins)
	}
	if !strings.Contains(r.Post, "join type=left max=0 process_guid, process_id [search * | ") {
		t.Errorf("post = %s", r.Post)
	}
	if up := r.upTo(0); len(up.Joins) != 0 || strings.Contains(up.Post, "join") {
		t.Errorf("before the join: %+v %q", up.Joins, up.Post)
	}
	// A run with a join this rule lacks is an error.
	if _, err := r.runJoin(context.Background(), nil, &query.Join{}, 3, nil); err == nil || !strings.Contains(err.Error(), "join 4 of 1") {
		t.Errorf("runJoin past the joins: %v", err)
	}
}

// Rows share a value as Signalith's join compares them.
func TestJoinValues(t *testing.T) {
	for _, c := range []struct {
		v    any
		want string
		ok   bool
	}{
		{nil, "", false},
		{"", "", false},
		{"a", "a", true},
		{[]any{"a", nil, "b"}, "a\nb", true},
		{[]any{nil}, "", false},
		{int64(42), "42", true},
	} {
		got, ok := joinValue(c.v)
		if got != c.want || ok != c.ok {
			t.Errorf("joinValue(%#v) = %q %v", c.v, got, ok)
		}
	}
	for v, want := range map[string]string{"41": "42", "0x1f": "0x20", "{X}": "{0D9B4E77-1A00-6F02-4C05-00000000CD07}"} {
		if got := otherValue(v); got != want {
			t.Errorf("otherValue(%s) = %s", v, got)
		}
	}
}

// joinSource follows a field back through the stages that make it.
func TestJoinSource(t *testing.T) {
	stages := func(s string) []query.Command {
		q, err := query.Parse("* | " + s)
		if err != nil {
			t.Fatal(err)
		}
		return q.Commands
	}
	for _, c := range []struct {
		stages, field, want string
		ok                  bool
	}{
		{"rename process_guid as guid", "guid", "process_guid", true},
		{"rename process_* as p_*", "p_guid", "process_guid", true},
		{"eval guid=process_guid", "guid", "process_guid", true},
		{"eval guid=lower(process_guid)", "guid", "", false},
		{`rex field=process "(?<exe>\S+)"`, "exe", "process", true},
		{`rex field=process mode=sed "s/a/b/"`, "process", "", false},
		{"stats count by process_guid", "process_guid", "process_guid", true},
		{"stats count by dest", "process_guid", "", false},
		{"fillnull | table process_guid | dedup process_guid | sort process_guid | head 5", "process_guid", "process_guid", true},
		{"eventstats count by process_guid", "process_guid", "", false},
	} {
		got, ok := joinSource(stages(c.stages), c.field)
		if got != c.want || ok != c.ok {
			t.Errorf("joinSource(%s, %s) = %q %v, want %q %v", c.stages, c.field, got, ok, c.want, c.ok)
		}
	}
	// A field renamed from a pattern, or by an uneven pattern, has no one
	// source.
	for _, pairs := range [][3]string{{"*", "x", "x"}, {"a*b*", "c*", "cz"}} {
		if got, ok := joinSource([]query.Command{&query.Rename{Pairs: [][2]string{{pairs[0], pairs[1]}}}}, pairs[2]); ok {
			t.Errorf("rename %v: source %q", pairs, got)
		}
	}
}

// A joined rule's cases need the events with them: without those, or
// with events of another program, Splunk's rule finds nothing.
func TestJoinReads(t *testing.T) {
	r, err := Parse(rule(joinMain+"| join process_guid ["+joinSub+"]"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var joined *sigmacheck.Case
	for _, c := range Cases(r) {
		if c.Expect {
			joined = &c
			break
		}
	}
	if joined == nil {
		t.Fatal("no joined case")
	}
	if !r.joinReads(*joined) {
		t.Fatal("the joined case is not read")
	}
	alone := *joined
	alone.With = nil
	if r.joinReads(alone) {
		t.Error("read without the events with it")
	}
	other := *joined
	other.With = []sigmacheck.Case{joined.With[0]}
	other.With[0].Data = map[string]string{}
	for k, v := range joined.With[0].Data {
		other.With[0].Data[k] = v
	}
	other.With[0].Data["ProcessGuid"] = otherValue(other.With[0].Data["ProcessGuid"])
	if r.joinReads(other) {
		t.Error("read with another program's event")
	}
	notMine := *joined
	notMine.Channel, notMine.EventID = sigmacheck.SysmonChannel, "11"
	if r.joinReads(notMine) {
		t.Error("read an event of another node")
	}
}
