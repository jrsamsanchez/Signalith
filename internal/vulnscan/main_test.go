package vulnscan

import (
	"fmt"
	"os"
	"slices"
	"testing"
)

// fakeNmapEnv makes the test binary act as Nmap, so the code that starts
// the real program is tested without Nmap installed: "ok" answers like
// Nmap 7.94, "fail" stops with an error, "silent" prints no version.
const fakeNmapEnv = "SIGNALITH_TEST_FAKE_NMAP"

func TestMain(m *testing.M) {
	if mode := os.Getenv(fakeNmapEnv); mode != "" {
		os.Exit(fakeNmapMain(mode, os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakeNmapMain(mode string, args []string) int {
	switch mode {
	case "fail":
		fmt.Fprintln(os.Stderr, "Starting Nmap 7.94")
		fmt.Fprintln(os.Stderr, `Failed to resolve "nope.example".`)
		return 1
	case "silent":
		fmt.Println("hello")
		return 0
	}
	if slices.Contains(args, "--version") {
		fmt.Println("Nmap version 7.94 ( https://nmap.org )")
		return 0
	}
	fmt.Print(nmapXML)
	return 0
}

// fakeNmapPath returns the path of a program that acts as Nmap in mode.
func fakeNmapPath(t *testing.T, mode string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Skip("the test binary cannot be found:", err)
	}
	t.Setenv(fakeNmapEnv, mode)
	return exe
}
