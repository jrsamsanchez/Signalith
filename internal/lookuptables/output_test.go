// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package lookuptables

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestOutput(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Output("users", []string{"user", "n"}, [][]string{{"amy", "1"}, {"=cmd", "2"}}, OutputCreate); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Output("users", []string{"user"}, nil, OutputCreate); !errors.Is(err, ErrExists) {
		t.Errorf("create over a table = %v", err)
	}
	// Appended rows bring their new columns; the table keeps its options.
	if _, err := s.PutWithOptions("users", []byte("user,n\namy,1\n=cmd,2\n"), Options{IgnoreCase: true}); err != nil {
		t.Fatal(err)
	}
	tb, err := s.Output("users", []string{"team", "user"}, [][]string{{"soc", "bob"}}, OutputAppend)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tb.Columns, []string{"user", "n", "team"}) || !reflect.DeepEqual(tb.Rows, [][]string{{"amy", "1", ""}, {"=cmd", "2", ""}, {"bob", "", "soc"}}) || !tb.IgnoreCase {
		t.Errorf("appended = %v %v %+v", tb.Columns, tb.Rows, tb.Options)
	}
	// What a search writes is kept as it is, and survives a restart.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s2.Get("users"); got == nil || got.Rows[1][0] != "=cmd" || !got.IgnoreCase {
		t.Errorf("reopened = %+v", got)
	}
	if tb, err = s.Output("users", []string{"x"}, [][]string{{"1"}}, OutputReplace); err != nil || !reflect.DeepEqual(tb.Columns, []string{"x"}) || len(tb.Rows) != 1 {
		t.Errorf("replaced = %v %v", tb, err)
	}
	// A replacement must still have the columns its options name.
	if _, err := s.PutWithOptions("paths", []byte("path\n*.exe\n"), Options{Wildcard: []string{"path"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Output("paths", []string{"other"}, nil, OutputReplace); err == nil {
		t.Error("replaced a wildcard column away")
	}
	if _, err := s.Output("Bad Name", []string{"a"}, nil, OutputCreate); err == nil {
		t.Error("wrote a bad name")
	}
	big := strings.Repeat("x", 1<<20)
	var rows [][]string
	for range 17 {
		rows = append(rows, []string{big})
	}
	if _, err := s.Output("big", []string{"a"}, rows, OutputCreate); err == nil {
		t.Error("wrote over the size limit")
	}
	var cols []string
	for i := range MaxColumns {
		cols = append(cols, "c"+strings.Repeat("x", i))
	}
	if _, err := s.Output("wide", cols, nil, OutputCreate); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Output("wide", []string{"one more"}, [][]string{{"1"}}, OutputAppend); err == nil {
		t.Error("appended past the column limit")
	}
}

// A search's outputlookup cannot write a content pack's table, or a new
// table under a pack's prefix.
func TestOutputLeavesPackTables(t *testing.T) {
	pt, err := NewPackTable("splunk", "splunk-pipes", []byte("pipe,tool\nx,PsExec\n"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := NewPackStore([]*Table{pt})
	for _, name := range []string{"splunk-pipes", "splunk-other"} {
		for _, mode := range []OutputMode{OutputCreate, OutputAppend, OutputReplace} {
			if _, err := s.Output(name, []string{"pipe"}, [][]string{{"y"}}, mode); err == nil {
				t.Errorf("Output(%s, %v) succeeded", name, mode)
			}
		}
	}
	if tb, _ := s.Get("splunk-pipes"); len(tb.Rows) != 1 {
		t.Errorf("pack table rows = %v", tb.Rows)
	}
}
