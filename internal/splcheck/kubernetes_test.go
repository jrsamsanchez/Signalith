// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"testing"

	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

func TestKubernetesRule(t *testing.T) {
	macros := map[string]*Macro{
		"kube_audit":               {Name: "kube_audit", Definition: `source="kubernetes"`},
		"kube_allowed_user_groups": {Name: "kube_allowed_user_groups", Definition: "user.groups{} IN (admin)"},
	}
	r, err := Parse(rule("`kube_audit` objectRef.resource=secrets verb=get\n"+
		"| search NOT `kube_allowed_user_groups`\n| fillnull\n"+
		"| stats count by objectRef.name user.username user.groups{} sourceIPs{} userAgent verb\n"+
		"| rename sourceIPs{} as src_ip, user.username as user"), macros)
	if err != nil {
		t.Fatal(err)
	}
	if r.Node != KubernetesNode {
		t.Fatalf("node %s", r.Node)
	}
	ok := map[string]string{"sourcetype": "_json", "source": "kubernetes", "objectRef.resource": "secrets", "verb": "get",
		"kube_user.groups{}": "developers"}
	if !Eval(r.Where, ok) {
		t.Errorf("%v does not match", ok)
	}
	for k, v := range map[string]string{"kube_user.groups{}": "admin", "source": "/var/log/app.json", "verb": "list"} {
		bad := map[string]string{}
		for k, v := range ok {
			bad[k] = v
		}
		bad[k] = v
		if Eval(r.Where, bad) {
			t.Errorf("%s=%s matches", k, v)
		}
	}
	pos := 0
	for _, c := range Cases(r) {
		if c.Channel != sigmacheck.KubernetesChannel {
			t.Errorf("case %s %s", c.Channel, c.EventID)
		}
		if c.Expect {
			pos++
		}
	}
	if pos == 0 {
		t.Error("no positive cases")
	}
}

// A quote escaped in a word is part of it, and starts no quoted text.
func TestEscapedQuoteInWord(t *testing.T) {
	r, err := Parse(rule("`kube_audit` objectRef.resource=pods verb=create OR verb=update "+
		`requestObject.metadata.annotations.kubectl.kubernetes.io/last-applied-configuration=*\"privileged\":true*`+
		"\n| fillnull | stats count by verb | `x_filter`"), map[string]*Macro{"kube_audit": {Name: "kube_audit", Definition: `source="kubernetes"`}})
	if err != nil {
		t.Fatal(err)
	}
	ev := map[string]string{"sourcetype": "_json", "source": "kubernetes", "objectRef.resource": "pods", "verb": "update",
		"requestObject.metadata.annotations.kubectl.kubernetes.io/last-applied-configuration": `{"spec":{"securityContext":{"privileged":true}}}`}
	if !Eval(r.Where, ev) {
		t.Errorf("%v does not match %v", ev, r.Where)
	}
	ev["requestObject.metadata.annotations.kubectl.kubernetes.io/last-applied-configuration"] = `{"privileged":false}`
	if Eval(r.Where, ev) {
		t.Error("an unprivileged pod matches")
	}
	if got := pipes(`a=*\"x\"* c="p|q" | b`); len(got) != 2 || got[0] != `a=*\"x\"* c="p|q"` {
		t.Errorf("pipes: %q", got)
	}
}
