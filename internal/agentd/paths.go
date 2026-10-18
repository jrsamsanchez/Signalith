package agentd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Paths are where the agent keeps its files and finds the collectors. The
// install scripts write the same paths, and the configurations the server
// makes for the agent name the same certificate authority and state
// folders (agents.ManagedLinuxConfDir and the like).
type Paths struct {
	// Conf holds agent.conf and token, written by the install script,
	// and ca.pem and fluent-bit.conf, written by the agent.
	Conf string
	// State holds the configuration in use, the health file and the
	// collectors' buffers.
	State string
	// FluentBit is Fluent Bit's program.
	FluentBit string
}

// DefaultPaths are the paths on this system.
func DefaultPaths() Paths {
	switch runtime.GOOS {
	case "windows":
		data := `C:\ProgramData\Signalith\Agent`
		prog := os.Getenv("ProgramFiles")
		if prog == "" {
			prog = `C:\Program Files`
		}
		return Paths{Conf: data, State: data, FluentBit: filepath.Join(prog, "Signalith Agent", "fluent-bit", "bin", "fluent-bit.exe")}
	default:
		return Paths{Conf: "/etc/signalith-agent", State: "/var/lib/signalith-agent", FluentBit: "/opt/fluent-bit/bin/fluent-bit"}
	}
}

// Files in the folders.
func (p Paths) settingsFile() string  { return filepath.Join(p.Conf, "agent.conf") }
func (p Paths) tokenFile() string     { return filepath.Join(p.Conf, "token") }
func (p Paths) caFile() string        { return filepath.Join(p.Conf, "ca.pem") }
func (p Paths) fluentBitConf() string { return filepath.Join(p.Conf, "fluent-bit.conf") }
func (p Paths) configFile() string    { return filepath.Join(p.State, "config.json") }

// StatusFile is the last status the agent reported, as JSON.
func (p Paths) StatusFile() string { return filepath.Join(p.State, "status.json") }

// HealthFile is the short file the install script reads to tell whether
// the agent works: one item=value line each for config, fluentbit and
// reported.
func (p Paths) HealthFile() string { return filepath.Join(p.State, "health") }

// Settings are what the install script wrote in agent.conf, and the
// agent token.
type Settings struct {
	// Server is Signalith's address, https://host:port.
	Server string
	// Token is the agent token.
	Token string
}

// ReadSettings reads agent.conf and the token.
func ReadSettings(p Paths) (Settings, error) {
	var s Settings
	f, err := os.Open(p.settingsFile())
	if err != nil {
		return s, fmt.Errorf("the agent is not set up (%w); run the line from Add data > Signalith Agent", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `'"`)
		switch strings.TrimSpace(k) {
		case "SERVER":
			s.Server = v
		}
	}
	if err := sc.Err(); err != nil {
		return s, err
	}
	if !strings.HasPrefix(s.Server, "https://") {
		return s, errors.New("agent.conf has no SERVER=https://... line; run the line from Add data > Signalith Agent again")
	}
	tok, err := os.ReadFile(p.tokenFile())
	if err != nil {
		return s, fmt.Errorf("the agent has no token (%w); run the line from Add data > Signalith Agent again", err)
	}
	s.Token = strings.TrimSpace(string(tok))
	if s.Token == "" {
		return s, errors.New("the agent's token file is empty; run the line from Add data > Signalith Agent again")
	}
	return s, nil
}

// writeFile writes b to path with mode perm: to a new file first, which is
// then renamed over the old one, so a reader never sees half a file.
func writeFile(path string, b []byte, perm os.FileMode) error {
	tmp := path + ".new"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
