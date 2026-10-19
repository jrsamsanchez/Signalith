package main

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/vulnscan"
)

// A host a vulnerability scan found is an asset under its address, its
// full name and its short name.
func TestScannedAsset(t *testing.T) {
	a := scannedAsset(&vulnscan.Host{Address: "192.0.2.10", Hostname: "db1.example.test"})
	if !slices.Equal(a.IP, []string{"192.0.2.10"}) || !slices.Equal(a.Host, []string{"db1.example.test", "db1"}) || !slices.Equal(a.Category, []string{"scanned"}) {
		t.Errorf("with a name: %+v", a)
	}
	a = scannedAsset(&vulnscan.Host{Address: "192.0.2.11", Hostname: "printer"})
	if !slices.Equal(a.Host, []string{"printer"}) {
		t.Errorf("a short name: %+v", a)
	}
	if a = scannedAsset(&vulnscan.Host{Address: "192.0.2.12"}); a.Host != nil {
		t.Errorf("no name: %+v", a)
	}
}

// join --merge says what it added and what differs.
func TestPrintMerge(t *testing.T) {
	var out bytes.Buffer
	j := &joiner{env: &joinEnv{out: &out}}
	j.printMerge(&clustercfg.MigrationReport{})
	if out.String() != "Merged: the cluster had everything this server's own files hold.\n" {
		t.Errorf("nothing added:\n%s", out.String())
	}
	out.Reset()
	j.printMerge(&clustercfg.MigrationReport{
		Added:  []clustercfg.MergeItem{{Kind: "detection", ID: "ssh-brute"}},
		Differ: []clustercfg.MergeItem{{Kind: "lookup", ID: "admins", Detail: "other rows"}},
		Held:   true,
	})
	for _, want := range []string{"Merged into the cluster, from this server's own files:\n", "  added detection ssh-brute\n",
		"These differ from the cluster's", "  lookup    admins: other rows\n", "Retention waits for an admin to confirm"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("merge lacks %q:\n%s", want, out.String())
		}
	}
}

// The commands main runs with the process's standard streams.
func TestCommandWrappers(t *testing.T) {
	noServiceSettings(t)
	if _, err := capture(t, func() error { return cmdOpenSearchCheck(nil) }); err == nil || !strings.Contains(err.Error(), "give OpenSearch's address") {
		t.Errorf("opensearch-check: %v", err)
	}
	if _, err := capture(t, func() error { return cmdOpenSearchCheck([]string{"https://os.example.test:9200", "--cert", "c.pem"}) }); err == nil || !strings.Contains(err.Error(), "--cert and --key") {
		t.Errorf("opensearch-check --cert alone: %v", err)
	}
	if out, err := capture(t, func() error { return cmdAgentPrograms(nil) }); err == nil || !strings.Contains(out, "agent-programs") {
		t.Errorf("agent-programs: %v\n%s", err, out)
	}
	if _, err := capture(t, func() error { return cmdSecrets([]string{"bogus"}) }); err == nil || !strings.Contains(err.Error(), "unknown secrets command") {
		t.Errorf("secrets: %v", err)
	}
	if _, err := capture(t, func() error { return cmdCluster([]string{"bogus"}) }); err == nil {
		t.Error("cluster bogus")
	}
	var f error = &joinFail{code: joinExitFailed, msg: "No join token was given."}
	var jf *joinFail
	if !errors.As(f, &jf) || f.Error() != "No join token was given." {
		t.Errorf("joinFail: %v", f)
	}
}
