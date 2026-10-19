package config

import (
	"os"
	"path/filepath"
	"testing"
)

// A change a restart refused is set aside, listed with its value and why,
// and not used; a change Signalith started with is marked checked once.
func TestMarkRefusedAndChecked(t *testing.T) {
	path := writeConfig(t, "")
	page := writePage(t, path, "settings:\n  search.max_events:\n    value: 600\n    changed_by: ann\n  auth.session_timeout:\n    value: 2h\n")
	marked, err := MarkRefused(page, []string{"search.max_events", "no.such.setting"}, "it did not start")
	if err != nil || len(marked) != 1 || marked[0] != "search.max_events" {
		t.Fatalf("marked %v, %v", marked, err)
	}
	if again, err := MarkRefused(page, []string{"search.max_events"}, "again"); err != nil || len(again) != 0 {
		t.Errorf("marked again %v, %v", again, err)
	}
	if err := MarkChecked(page, []string{"auth.session_timeout", "search.max_events"}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(page)
	if err := MarkChecked(page, []string{"auth.session_timeout"}); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.Stat(page); !after.ModTime().Equal(before.ModTime()) {
		t.Error("marking a checked change again rewrote the file")
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Search.MaxEvents == 600 {
		t.Error("the refused change is in use")
	}
	r := c.Refused()
	if len(r) != 1 || r[0].Key != "search.max_events" || r[0].Reason != "it did not start" || r[0].By != "ann" || r[0].Value != 600 {
		t.Errorf("refused %+v", r)
	}
	if !c.PageChecked("auth.session_timeout") || c.PageChecked("search.max_events") {
		t.Error("checked marks")
	}
	if len((&Config{}).Refused()) != 0 || (&Config{}).PageChecked("x") {
		t.Error("a configuration with no layers has refusals")
	}
	missing := filepath.Join(t.TempDir(), "lookups", "settings.yaml")
	if err := MarkChecked(missing, []string{"x"}); err != nil {
		t.Errorf("MarkChecked with no file: %v", err)
	}
	broken := writePage(t, writeConfig(t, ""), "settings: [\n")
	if err := MarkChecked(broken, []string{"x"}); err == nil {
		t.Error("MarkChecked on a file that is not YAML")
	}
	if _, err := MarkRefused(broken, []string{"x"}, "r"); err == nil {
		t.Error("MarkRefused on a file that is not YAML")
	}
}
