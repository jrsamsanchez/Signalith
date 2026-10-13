package main

import (
	"bufio"
	"bytes"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// A command run by hand does not see the environment the signalith
// service is given: the Environment= and EnvironmentFile= lines of its
// systemd unit on Linux, or the Environment value of the Signalith service
// in the Windows registry. Those put the server's own files
// (directory.json, intel_feeds.yaml, a master key it made, its HTTPS
// certificate and identity) in its state folder, and may name its master
// key (SIGNALITH_MASTER_KEY_FILE). So when
// the service runs with the same config file, "signalith secrets",
// "signalith validate", "signalith settings", "signalith passwd" and
// "signalith init" use the service's folder, file and master key settings
// too, and find the same files and key.

// serviceVars are the settings taken from the service: its folders (the
// state folder among them, which holds its master key, HTTPS certificate
// and identity), the files it keeps (not files of secrets, such as
// SIGNALITH_ADMIN_PASSWORD_FILE: the server reads those itself, and a
// command run by hand that cannot read one, such as a systemd credential
// that exists only while the service runs, would stop), its master key,
// and its name and address among the servers that share its OpenSearch,
// so "signalith validate" checks those too.
var serviceVars = map[string]bool{
	"SIGNALITH_STATE_DIR": true, "SIGNALITH_LOOKUPS_DIR": true, "SIGNALITH_DETECTIONS_DIR": true,
	"SIGNALITH_DASHBOARDS_DIR": true, "SIGNALITH_ARCHIVE_DIR": true,
	"SIGNALITH_USERS_FILE": true, "SIGNALITH_INTEL_FEEDS_FILE": true, "SIGNALITH_SETTINGS_FILE": true,
	"SIGNALITH_RESPONSE_FILE": true, "SIGNALITH_RESPONSE_SCRIPTS_DIR": true,
	"SIGNALITH_MASTER_KEY_FILE": true, "SIGNALITH_MASTER_KEY": true,
	"SIGNALITH_NODE_NAME": true, "SIGNALITH_NODE_URL": true,
	// systemd sets it from the unit's StateDirectory= (see
	// parseSystemctlShow): the state folder falls back to it.
	"STATE_DIRECTORY": true,
}

// serviceSettings is what the service is given.
type serviceSettings struct {
	// where says where the settings were read, for people.
	where string
	// args is the service's command line, after the program.
	args []string
	// env is its environment, as NAME=value.
	env map[string]string
	// cred is the file of a master key passed to it as a systemd
	// credential (LoadCredential=master.key:<file>).
	cred string
}

// readServiceSettings returns the service's settings, or nil when there
// is no service here. Tests replace it.
var readServiceSettings = platformServiceSettings

// keyIsCredential is set when the service gets its master key as a
// systemd credential, which it reads only when it starts.
var keyIsCredential bool

// applyServiceEnv sets, in this process, the folder, file and master key
// settings the signalith service has, when it runs with the config file
// path and the variable is not set here already. It returns where they
// were read and what it set, as NAME=value (a key itself is not shown).
func applyServiceEnv(path string) (where string, set []string) {
	s := readServiceSettings()
	if s == nil {
		return "", nil
	}
	env := s.envFor(path)
	if env == nil {
		return "", nil
	}
	for k, v := range env {
		if os.Getenv(k) != "" {
			continue
		}
		os.Setenv(k, v)
		if k == "SIGNALITH_MASTER_KEY" {
			v = "(the key itself, not shown)"
		}
		set = append(set, k+"="+v)
	}
	keyIsCredential = s.cred != "" && os.Getenv("SIGNALITH_MASTER_KEY_FILE") == s.cred
	sort.Strings(set)
	return s.where, set
}

// envFor returns the service's folder, file and master key settings when
// it runs with the config file path, or nil. A master key passed with
// LoadCredential=master.key:<file> is returned as
// SIGNALITH_MASTER_KEY_FILE, since the credential folder exists only for
// the service.
func (s *serviceSettings) envFor(path string) map[string]string {
	if !s.serves(path) {
		return nil
	}
	env := map[string]string{}
	for k, v := range s.env {
		if serviceVars[k] && v != "" {
			env[k] = v
		}
	}
	// $CREDENTIALS_DIRECTORY/master.key comes before SIGNALITH_MASTER_KEY_FILE.
	if s.cred != "" {
		env["SIGNALITH_MASTER_KEY_FILE"] = s.cred
		delete(env, "SIGNALITH_MASTER_KEY")
	}
	return env
}

// serviceGives returns the first of names that the signalith service's
// environment sets, when it runs with the config file path, or "". Unlike
// applyServiceEnv it sets nothing here, so it can tell about secrets that
// are not taken (such as SIGNALITH_ADMIN_PASSWORD_FILE).
func serviceGives(path string, names ...string) string {
	s := readServiceSettings()
	if !s.serves(path) {
		return ""
	}
	for _, n := range names {
		if s.env[n] != "" {
			return n
		}
	}
	return ""
}

// serves reports whether the service runs with the config file path.
func (s *serviceSettings) serves(path string) bool {
	if s == nil || s.args == nil {
		return false
	}
	served := s.env["SIGNALITH_CONFIG"]
	if served == "" {
		served = defaultConfigPath()
	}
	for i, a := range s.args {
		switch {
		case (a == "-c" || a == "--c") && i+1 < len(s.args):
			served = s.args[i+1]
		case strings.HasPrefix(a, "-c="):
			served = strings.TrimPrefix(a, "-c=")
		case strings.HasPrefix(a, "--c="):
			served = strings.TrimPrefix(a, "--c=")
		}
	}
	return sameFile(served, path)
}

// parseSystemctlShow reads "systemctl show" output: the service's command
// line, its Environment= settings, the files EnvironmentFile= names (read
// with readFile, later ones winning, as systemd does), a master key
// passed as a credential, and its StateDirectory=, which systemd gives the
// service as $STATE_DIRECTORY (the first one, under /var/lib), where its
// state folder may fall back to (config.Config.StateDir). A command run by
// hand gets the same, so it looks for the state folder where the service
// does.
func parseSystemctlShow(show []byte, readFile func(string) ([]byte, error)) *serviceSettings {
	s := &serviceSettings{where: "systemctl show signalith", env: map[string]string{}}
	var files []string
	var stateDir string
	sc := bufio.NewScanner(bytes.NewReader(show))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "ExecStart":
			// { path=/usr/local/bin/signalith ; argv[]=/usr/local/bin/signalith serve -c /etc/... ; ... }
			if _, rest, ok := strings.Cut(value, "argv[]="); ok {
				argv, _, _ := strings.Cut(rest, " ;")
				if f := strings.Fields(argv); len(f) > 0 {
					s.args = f[1:]
				}
			}
		case "Environment":
			for _, kv := range splitQuoted(value) {
				if k, v, ok := strings.Cut(kv, "="); ok {
					s.env[k] = v
				}
			}
		case "EnvironmentFiles":
			// /etc/signalith/signalith.env (ignore_errors=yes)
			if f, _, _ := strings.Cut(value, " ("); unitPathIsAbs(f) {
				files = append(files, f)
			}
		case "StateDirectory":
			// signalith, or several separated by spaces; a newer systemd
			// may add :link to an entry.
			if f := strings.Fields(value); len(f) > 0 {
				if d, _, _ := strings.Cut(f[0], ":"); d != "" && !path.IsAbs(d) && !strings.Contains(d, "..") {
					stateDir = path.Join("/var/lib", d)
				}
			}
		case "LoadCredential":
			if id, file, ok := strings.Cut(value, ":"); ok && id == "master.key" && unitPathIsAbs(file) {
				s.cred = file
			}
		}
	}
	if s.args == nil {
		return nil
	}
	for _, f := range files {
		data, err := readFile(f)
		if err != nil {
			continue
		}
		for k, v := range parseEnvFile(data) {
			s.env[k] = v
		}
		clear(data)
	}
	// systemd sets STATE_DIRECTORY itself, over any Environment= line.
	if stateDir != "" {
		s.env["STATE_DIRECTORY"] = stateDir
	}
	return s
}

// parseEnvFile reads a systemd EnvironmentFile: NAME=value lines, with #
// and ; comments, and values optionally in quotes.
func parseEnvFile(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(strings.TrimPrefix(k, "export ")), strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out
}

// splitQuoted splits a systemctl Environment= value: space-separated
// NAME=value items, an item with spaces in double quotes.
func splitQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	quoted, started := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && quoted && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case c == '"':
			quoted, started = !quoted, true
		case c == ' ' && !quoted:
			if cur.Len() > 0 || started {
				out = append(out, cur.String())
			}
			cur.Reset()
			started = false
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 || started {
		out = append(out, cur.String())
	}
	return out
}

// sameFile reports whether two paths name the same file.
func sameFile(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return false
	}
	// Windows paths ignore case.
	if ca, cb := filepath.Clean(aa), filepath.Clean(bb); ca == cb || runtime.GOOS == "windows" && strings.EqualFold(ca, cb) {
		return true
	}
	sa, err1 := os.Stat(aa)
	sb, err2 := os.Stat(bb)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}

// unitPathIsAbs reports whether a path in a systemd unit is absolute.
// Units always use /-paths, which filepath.IsAbs does not accept on
// Windows, where the parser still runs in tests.
func unitPathIsAbs(p string) bool { return path.IsAbs(p) || filepath.IsAbs(p) }
