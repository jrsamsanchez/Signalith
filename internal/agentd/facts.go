package agentd

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// facts are what the agent tells the server about the computer, so the
// configuration fits it.
type facts struct {
	// Source is where Linux keeps its sign-in log: "file" when
	// /var/log/auth.log or /var/log/secure exists, else "journal".
	Source string
	// Sysmon is whether Sysmon is installed.
	Sysmon bool
}

// lookFacts looks at this computer.
func lookFacts() facts {
	var f facts
	switch runtime.GOOS {
	case "linux":
		f.Source = "journal"
		for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
			if exists(p) {
				f.Source = "file"
				break
			}
		}
		f.Sysmon = exists("/opt/sysmon/sysmon") || exists("/usr/bin/sysmon")
	case "windows":
		root := os.Getenv("SystemRoot")
		if root == "" {
			root = `C:\Windows`
		}
		f.Sysmon = exists(filepath.Join(root, "Sysmon64.exe")) || exists(filepath.Join(root, "Sysmon.exe"))
	}
	return f
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// systemName is the operating system's own name for itself, such as
// "Ubuntu 24.04.1 LTS", or the kind of system when it has none.
func systemName() string {
	if runtime.GOOS == "linux" {
		if name := osReleaseName("/etc/os-release"); name != "" {
			return name
		}
	}
	return runtime.GOOS
}

// osReleaseName reads PRETTY_NAME from an os-release file.
func osReleaseName(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
			return oneLine(strings.Trim(strings.TrimSpace(v), `'"`))
		}
	}
	return ""
}
