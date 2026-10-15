package deploy

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// install.sh writes the systemd unit as deploy/systemd/signalith.service
// has it, byte for byte.
func TestInstallSHHasTheUnit(t *testing.T) {
	unit := bytes.ReplaceAll(SystemdUnit, []byte("\r\n"), []byte("\n"))
	want := "<<'UNIT'\n" + strings.TrimRight(string(unit), "\n") + "\nUNIT\n"
	if !strings.Contains(string(InstallSH), want) {
		t.Fatal("deploy/linux/install.sh's unit differs from deploy/systemd/signalith.service: copy the unit between <<'UNIT' and UNIT")
	}
}

// install.sh keeps Unix line endings everywhere (.gitattributes), since
// its SHA-256 is checked and sh cannot run it with CRLF.
func TestInstallSHLineEndings(t *testing.T) {
	if bytes.Contains(InstallSH, []byte("\r")) {
		t.Fatal("deploy/linux/install.sh has CRLF line endings")
	}
}

// The script parses in every POSIX shell at hand (Debian's dash among
// them), and refuses to run without root before it changes anything.
func TestInstallSHRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shells only")
	}
	path := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(path, InstallSH, 0o666); err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, sh := range []string{"sh", "dash", "bash", "busybox"} {
		bin, err := exec.LookPath(sh)
		if err != nil {
			continue
		}
		args := []string{"-n", path}
		if sh == "busybox" {
			args = append([]string{"sh"}, args...)
		}
		if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
			t.Errorf("%s -n: %v\n%s", sh, err, out)
		}
		ran++
	}
	if ran == 0 {
		t.Skip("no POSIX shell")
	}
	out, err := exec.Command("sh", path, "--help").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--join") {
		t.Errorf("--help: %v\n%s", err, out)
	}
	out, err = exec.Command("sh", path, "--bogus").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "Unknown option: --bogus") {
		t.Errorf("--bogus: %v\n%s", err, out)
	}
	if os.Geteuid() != 0 {
		out, err = exec.Command("sh", path, "--join", "SJ1.x").CombinedOutput()
		if err == nil || !strings.Contains(string(out), "Run this with sudo") {
			t.Errorf("not root: %v\n%s", err, out)
		}
	}
}
