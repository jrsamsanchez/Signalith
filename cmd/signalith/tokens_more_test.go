package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokensCommandRenameAndErrors(t *testing.T) {
	noServiceSettings(t)
	path := tokensConfig(t)
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	run := func(args ...string) (string, string, error) {
		var out, errOut bytes.Buffer
		err := runTokens(append(args, "-c", path), devnull, &out, &errOut)
		return out.String(), errOut.String(), err
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"bogus"}, `unknown tokens command "bogus"`},
		{[]string{"legacy", "bogus"}, `unknown tokens command "legacy bogus"`},
		{[]string{"create"}, "give the token a name"},
		{[]string{"rename", "only-id"}, "usage: signalith tokens rename"},
		{[]string{"revoke"}, "usage: signalith tokens revoke"},
		{[]string{"revoke", "-yes", "No such token"}, `no active agent token has the ID or name "No such token"`},
		{[]string{"legacy", "refuse"}, "usage: signalith tokens legacy refuse <id>"},
		{[]string{"legacy", "accept", "a", "b"}, "usage: signalith tokens legacy accept <id>"},
		{[]string{"legacy", "refuse", "nothing"}, ""},
		{[]string{"legacy", "accept", "nothing"}, ""},
		{[]string{"rename", "nothing", "New name"}, ""},
	} {
		if _, _, err := run(c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v", c.args, err)
		}
	}
	var out, errOut bytes.Buffer
	if err := runTokens(nil, devnull, &out, &errOut); err == nil || !strings.Contains(err.Error(), "signalith tokens list") {
		t.Errorf("no command: %v", err)
	}
	if err := runTokens([]string{"legacy"}, devnull, &out, &errOut); err == nil || !strings.Contains(err.Error(), "signalith tokens list") {
		t.Errorf("legacy alone: %v", err)
	}
	if err := runTokens([]string{"list", "-c", filepath.Join(t.TempDir(), "missing.yaml")}, devnull, &out, &errOut); err == nil {
		t.Error("list with no config file")
	}

	secret, _, err := run("create", "Old", "name")
	if err != nil {
		t.Fatal(err)
	}
	listed, _, _ := run("list", "-json")
	if strings.Contains(listed, strings.TrimSpace(secret)) {
		t.Fatal("the list shows the token")
	}
	id := tokenID(t, listed, "Old name")
	out2, _, err := run("rename", id, "New", "name")
	if err != nil || !strings.Contains(out2, `Renamed "Old name" to "New name".`) {
		t.Fatalf("rename: %v\n%s", err, out2)
	}
	if listed, _, _ := run("list"); !strings.Contains(listed, "New name") || strings.Contains(listed, "Old name") {
		t.Errorf("list after rename:\n%s", listed)
	}
}

// tokenID finds the ID of the token named name in tokens list -json.
func tokenID(t *testing.T, listJSON, name string) string {
	t.Helper()
	i := strings.Index(listJSON, `"name": "`+name+`"`)
	if i < 0 {
		t.Fatalf("no token %q in\n%s", name, listJSON)
	}
	j := strings.LastIndex(listJSON[:i], `"id": "`)
	if j < 0 {
		t.Fatalf("no id before %q in\n%s", name, listJSON)
	}
	rest := listJSON[j+len(`"id": "`):]
	return rest[:strings.Index(rest, `"`)]
}

func TestTokensCommandWithoutOpenSearch(t *testing.T) {
	noServiceSettings(t)
	path := sampleConfig(t, "http://127.0.0.1:1")
	var out, errOut bytes.Buffer
	if err := runTokens([]string{"list", "-c", path}, os.Stdin, &out, &errOut); err == nil || !strings.Contains(err.Error(), "OpenSearch is not reachable") {
		t.Errorf("list without OpenSearch: %v", err)
	}
}
