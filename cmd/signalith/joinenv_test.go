package main

import (
	"net"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"
)

// defaultJoinEnv is wired to this computer.
func TestDefaultJoinEnv(t *testing.T) {
	e := defaultJoinEnv()
	if e.out != os.Stdout || e.errOut != os.Stderr || e.in != os.Stdin || e.goos != runtime.GOOS {
		t.Errorf("join env %+v", e)
	}
	if e.getenv("PATH") != os.Getenv("PATH") {
		t.Error("getenv is not the environment")
	}
	for _, f := range []any{e.check, e.serviceEnv, e.owner, e.chownFD, e.readSecret, e.systemctl, e.serviceActive, e.startService} {
		if reflect.ValueOf(f).IsNil() {
			t.Fatal("a function of the join env is not set")
		}
	}
	if d := time.Since(e.now()); d < 0 || d > time.Minute {
		t.Errorf("now is %v off", d)
	}
	if tr := e.transport(); tr == nil || http.RoundTripper(tr) == http.DefaultTransport {
		t.Error("transport is not a copy of the default one")
	}
	// listenFree tells a free address from a taken one.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	taken := l.Addr().String()
	if err := e.listenFree(taken); err == nil {
		t.Errorf("%s is taken, but listenFree says it is free", taken)
	}
	l.Close()
	if err := e.listenFree("127.0.0.1:0"); err != nil {
		t.Errorf("listenFree of a free port: %v", err)
	}
	// Standard input is not a terminal in a test, so no secret is read.
	if !e.terminal {
		if _, err := e.readSecret(); err == nil {
			t.Error("a secret was read from a standard input that is not a terminal")
		}
	}
	if runtime.GOOS == "linux" {
		// systemctl runs, or fails with what it said.
		if err := e.systemctl("--no-such-option-for-the-test"); err == nil {
			t.Error("systemctl took an option it does not have")
		}
	}
}
