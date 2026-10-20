// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ticketing

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func saveProblems(t *testing.T, in ...ConnectionInput) []Problem {
	t.Helper()
	m := &Manager{File: filepath.Join(t.TempDir(), "tickets.yaml")}
	_, err := m.Save(Input{Connections: in})
	var ie *InputError
	if !errors.As(err, &ie) {
		t.Fatalf("not an input error: %v", err)
	}
	if !strings.HasPrefix(ie.Error(), "Please fix these settings: ") {
		t.Errorf("error = %q", ie.Error())
	}
	return ie.Problems
}

func TestConnectionInputProblems(t *testing.T) {
	for _, c := range []struct {
		field, msg string
		in         func() ConnectionInput
	}{
		{"id", "a new connection's ID", func() ConnectionInput { c := jiraInput(); c.ID = "Bad ID"; return c }},
		{"name", "too long", func() ConnectionInput { c := jiraInput(); c.Name = strings.Repeat("n", maxName+1); return c }},
		{"url", "address of the Jira site", func() ConnectionInput { c := jiraInput(); c.URL = ""; return c }},
		{"url", "address of the ServiceNow instance", func() ConnectionInput { c := snInput(); c.URL = ""; return c }},
		{"token", "too long", func() ConnectionInput { c := jiraInput(); c.Token = strings.Repeat("t", maxSecret+1); return c }},
		{"issue_type", "too long", func() ConnectionInput { c := jiraInput(); c.IssueType = strings.Repeat("i", 61); return c }},
		{"statuses", "at most 10 Jira statuses", func() ConnectionInput {
			c := jiraInput()
			var names []string
			for i := range 11 {
				names = append(names, fmt.Sprintf("S%d", i))
			}
			c.Statuses = map[string]string{"new": strings.Join(names, ",")}
			return c
		}},
		{"auth", "Jira Cloud (email and API token)", func() ConnectionInput { c := jiraInput(); c.Auth = "kerberos"; return c }},
		{"username", "enter the user name", func() ConnectionInput {
			c := snInput()
			c.Auth, c.ClientID, c.ClientSecret, c.Password = "", "", "", "pw"
			return c
		}},
		{"auth", "user name and password, or OAuth", func() ConnectionInput { c := snInput(); c.Auth = "saml"; return c }},
	} {
		ps := saveProblems(t, c.in())
		found := false
		for _, p := range ps {
			if p.Field == c.field && strings.Contains(p.Msg, c.msg) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s %q: %v", c.field, c.msg, ps)
		}
	}
	var many []ConnectionInput
	for i := range MaxConnections + 1 {
		c := jiraInput()
		c.ID = fmt.Sprintf("c%d", i)
		many = append(many, c)
	}
	if ps := saveProblems(t, many...); len(ps) != 1 || ps[0].Where != "connections" {
		t.Errorf("too many = %v", ps)
	}
}

func TestConnectionDefaultsAndCheck(t *testing.T) {
	m := &Manager{File: filepath.Join(t.TempDir(), "tickets.yaml")}
	sn := snInput()
	sn.ID, sn.Auth, sn.ClientID, sn.ClientSecret, sn.Username, sn.Password = "desk", "", "", "", "svc", "sn-pass-0001"
	j := jiraInput()
	j.Auth = ""
	s, err := m.Save(Input{Connections: []ConnectionInput{j, sn}})
	if err != nil {
		t.Fatal(err)
	}
	jc, _ := s.Connection("soc")
	dc, _ := s.Connection("desk")
	if jc.Auth != AuthCloud || dc.Auth != AuthBasic || dc.Username != "svc" {
		t.Errorf("defaults: %+v %+v", jc, dc)
	}
	st := dc.statusesOrDefault()
	for _, cs := range CaseStatuses {
		if st[cs] == "" {
			t.Errorf("ServiceNow has no state for %s: %v", cs, st)
		}
	}
	if (Connection{Type: TypeJira}).statusesOrDefault()["new"] != "" {
		t.Error("Jira got a default status")
	}
	if jc.Label() != "Jira SOC" || (Connection{Type: TypeJira, Name: "Jira cloud"}).Label() != "Jira cloud" {
		t.Errorf("labels %q", jc.Label())
	}
	// A saved connection that changes system starts without its secrets.
	in := jiraInput()
	in.ID, in.Type, in.Token = "desk", TypeJira, ""
	if _, err := m.Check(in); err == nil {
		t.Error("a connection that changed system kept its secrets")
	}
	if c, err := m.Check(snInput()); err != nil || c.Type != TypeServiceNow {
		t.Errorf("check = %+v %v", c, err)
	}

	broken := &Manager{File: t.TempDir()}
	if _, err := broken.Check(snInput()); err == nil {
		t.Error("an unreadable file was ignored")
	}
}
