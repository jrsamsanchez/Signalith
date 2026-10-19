// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// facts are what the agent tells the server about the computer, so the
// configuration fits it.
type facts struct {
	// Source is where Linux keeps its sign-in log: "file" when
	// /var/log/auth.log or /var/log/secure exists, else "journal".
	Source string
	// Sysmon is whether Sysmon is installed.
	Sysmon bool
	// Osquery is whether osquery is installed (Paths.Osqueryd) and set up
	// for the agent (Settings.Osquery).
	Osquery bool
}

// lookFacts looks at this computer, with osquery where p says.
func lookFacts(p Paths) facts {
	f := facts{Osquery: p.Osqueryd != "" && exists(p.Osqueryd)}
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
	switch runtime.GOOS {
	case "linux":
		if name := osReleaseName("/etc/os-release"); name != "" {
			return name
		}
	case "windows":
		if name := windowsName(); name != "" {
			return name
		}
	case "darwin":
		if name := macName(); name != "" {
			return name
		}
	}
	return runtime.GOOS
}

// macName is macOS's version as sw_vers says it, such as "macOS 15.1
// (24B83)".
func macName() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/sw_vers").Output()
	if err != nil {
		return ""
	}
	return swVersName(string(out))
}

// swVersName reads sw_vers' output.
func swVersName(out string) string {
	v := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, val, ok := strings.Cut(line, ":"); ok {
			v[strings.TrimSpace(k)] = strings.TrimSpace(val)
		}
	}
	if v["ProductVersion"] == "" {
		return ""
	}
	name := v["ProductName"]
	if name == "" || name == "Mac OS X" {
		name = "macOS"
	}
	name += " " + v["ProductVersion"]
	if b := v["BuildVersion"]; b != "" {
		name += " (" + b + ")"
	}
	return oneLine(name)
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
