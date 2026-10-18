package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCommands(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"version"}, &out, &errOut); err != nil || out.String() != "dev\n" {
		t.Errorf("version: %v %q", err, out.String())
	}
	out.Reset()
	if err := run([]string{"help"}, &out, &errOut); err != nil || !strings.Contains(out.String(), "signalith-agent run") {
		t.Errorf("help: %v %q", err, out.String())
	}
	for _, args := range [][]string{nil, {"bogus"}, {"run", "extra"}} {
		errOut.Reset()
		if err := run(args, &out, &errOut); err == nil || !strings.Contains(errOut.String(), "usage:") {
			t.Errorf("%v: %v %q", args, err, errOut.String())
		}
	}
}
