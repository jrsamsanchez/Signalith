package respond

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// writeScript writes an executable shell script into dir.
func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func needUnix(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts and file modes are tested on Linux and macOS")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
}

func TestResolveProgramStaysInTheFolder(t *testing.T) {
	needUnix(t)
	root := t.TempDir()
	dir := filepath.Join(root, "scripts")
	writeScript(t, dir, "ok.sh", "exit 0")
	writeScript(t, dir, "sub/deep.sh", "exit 0")
	outside := writeScript(t, root, "outside.sh", "exit 0")
	if err := os.Symlink(outside, filepath.Join(dir, "escape.sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(dir, "up")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "ok.sh"), filepath.Join(dir, "alias.sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plain.sh"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeScript(t, dir, "open.sh", "exit 0")
	if err := os.Chmod(filepath.Join(dir, "open.sh"), 0o777); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"ok.sh", "sub/deep.sh", `sub\deep.sh`, "alias.sh"} {
		got, err := ResolveProgram(dir, p)
		if err != nil || !strings.HasPrefix(got, mustReal(t, dir)) {
			t.Errorf("ResolveProgram(%q) = %q, %v", p, got, err)
		}
	}
	for _, p := range []string{"escape.sh", "up/outside.sh", "../outside.sh", "sub/../../outside.sh", outside, "/bin/sh",
		"missing.sh", "plain.sh", "open.sh", "sub", "", "C:/x.ps1"} {
		if got, err := ResolveProgram(dir, p); err == nil {
			t.Errorf("ResolveProgram(%q) = %q, want an error", p, got)
		}
	}
	// The folder itself may be a link (as /var/lib often is).
	link := filepath.Join(root, "scripts-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveProgram(link, "ok.sh"); err != nil {
		t.Errorf("through a linked folder: %v", err)
	}
	if _, err := ResolveProgram(filepath.Join(root, "nope"), "ok.sh"); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing folder: %v", err)
	}
	if got := ListScripts(dir); strings.Join(got, ",") != "alias.sh,escape.sh,ok.sh,open.sh,plain.sh,sub/deep.sh" {
		t.Errorf("ListScripts = %v", got)
	}
}

func mustReal(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func scriptRunner(t *testing.T, dir string, c Connector) (*Runner, *Memory) {
	t.Helper()
	c.Normalize()
	mem := &Memory{}
	a := &Actions{}
	if err := a.Save([]Connector{c}); err != nil {
		t.Fatal(err)
	}
	return &Runner{Actions: a, ScriptsDir: dir, Store: mem}, mem
}

func TestScriptGetsTargetAndASmallEnvironment(t *testing.T) {
	needUnix(t)
	dir := t.TempDir()
	writeScript(t, dir, "show.sh", `echo "arg=[$1] argc=$#"; echo "env=$SIGNALITH_TARGET $SIGNALITH_TARGET_KIND $SIGNALITH_FINDING_ID $SIGNALITH_CASE_ID $SIGNALITH_ACTOR"; echo "secret=[$SIGNALITH_OPENSEARCH_PASSWORD]"; pwd`)
	t.Setenv("SIGNALITH_OPENSEARCH_PASSWORD", "do-not-pass-me")
	r, mem := scriptRunner(t, dir, Connector{Name: "iso", Kind: KindScript, Target: TargetHost, Program: "show.sh"})
	run, err := r.Run(t.Context(), Request{Action: "iso", Target: "WS-0042", Reason: "contain", FindingID: "F-9", Actor: Actor{Name: "ann"}})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != StatusSucceeded || !strings.Contains(run.Output, "arg=[ws-0042] argc=1") ||
		!strings.Contains(run.Output, "env=ws-0042 host F-9  ann") || !strings.Contains(run.Output, "secret=[]") ||
		!strings.Contains(run.Output, mustReal(t, dir)) {
		t.Errorf("run %+v", run)
	}
	runs, _ := mem.List(t.Context(), Filter{FindingID: "F-9"})
	if len(runs) != 1 || runs[0].Status != StatusSucceeded {
		t.Errorf("audit %+v", runs)
	}
}

func TestScriptTimeoutAndOutputCap(t *testing.T) {
	needUnix(t)
	dir := t.TempDir()
	writeScript(t, dir, "slow.sh", "echo started; sleep 30; echo never")
	r, _ := scriptRunner(t, dir, Connector{Name: "slow", Kind: KindScript, Target: TargetHost, Program: "slow.sh", TimeoutSeconds: 1})
	start := time.Now()
	run, err := r.Run(t.Context(), Request{Action: "slow", Target: "h1", Reason: "x", Actor: Actor{Name: "ann"}})
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("a 1 s timeout took %s", took)
	}
	if run.Status != StatusFailed || !strings.Contains(run.Error, "did not finish within 1s") || !strings.Contains(run.Output, "started") || strings.Contains(run.Output, "never") {
		t.Errorf("run %+v", run)
	}

	writeScript(t, dir, "loud.sh", `i=0; while [ $i -lt 3000 ]; do echo "line $i of output padding padding padding"; i=$((i+1)); done; exit 3`)
	r, _ = scriptRunner(t, dir, Connector{Name: "loud", Kind: KindScript, Target: TargetHost, Program: "loud.sh"})
	run, err = r.Run(t.Context(), Request{Action: "loud", Target: "h1", Reason: "x", Actor: Actor{Name: "ann"}})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != StatusFailed || !strings.Contains(run.Error, "exited with code 3") || len(run.Output) > MaxOutput+100 ||
		!strings.Contains(run.Output, "line 0 of") || !strings.Contains(run.Output, "output cut") && !strings.Contains(run.Output, "not kept") {
		t.Errorf("status %s error %q output %d bytes, ends %q", run.Status, run.Error, len(run.Output), run.Output[max(0, len(run.Output)-80):])
	}
}
