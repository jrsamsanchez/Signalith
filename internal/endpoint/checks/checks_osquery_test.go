package checks

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestChecksWithOsquery runs every check through a real osqueryd when
// SIGNALITH_OSQUERYD names the binary, for example
//
//	SIGNALITH_OSQUERYD=/opt/osquery/bin/osqueryd go test ./internal/endpoint/checks/
//
// Checks for the platform the test runs on must return exactly one row with a
// valid result. Checks for other platforms must at least parse: osquery
// reports "no such table" for the platform's own tables, which is accepted,
// while a syntax error or any other error fails. SIGNALITH_AUGEAS_LENSES may
// point at the augeas lenses directory; by default the test looks next to the
// binary (../share/osquery/lenses).
func TestChecksWithOsquery(t *testing.T) {
	bin := os.Getenv("SIGNALITH_OSQUERYD")
	if bin == "" {
		t.Skip("SIGNALITH_OSQUERYD not set")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("SIGNALITH_OSQUERYD: %v", err)
	}
	args := []string{"-S", "--json"}
	if lenses := augeasLenses(bin); lenses != "" {
		args = append(args, "--augeas_lenses="+lenses)
	} else {
		t.Log("no augeas lenses found; sshd_config and login.defs checks will report n/a")
	}

	host := runtime.GOOS
	for _, c := range All() {
		t.Run(c.ID, func(t *testing.T) {
			t.Parallel()
			stdout, stderr, err := runOsquery(bin, append(args, c.SQL))
			sqlErr := sqlError(stdout + "\n" + stderr)

			if c.Platform != host {
				if err == nil {
					return
				}
				if !strings.Contains(sqlErr, "no such table") {
					t.Fatalf("SQL does not parse: %v\n%s\n%s\nSQL:\n%s", err, sqlErr, stderr, c.SQL)
				}
				return
			}

			if err != nil || sqlErr != "" {
				t.Fatalf("osqueryd failed: %v %s\nstderr: %s\nSQL:\n%s", err, sqlErr, stderr, c.SQL)
			}
			var rows []map[string]string
			if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
				t.Fatalf("bad JSON output: %v\n%s", err, stdout)
			}
			if len(rows) != 1 {
				t.Fatalf("got %d rows, want exactly 1: %v\nSQL:\n%s", len(rows), rows, c.SQL)
			}
			row := rows[0]
			if len(row) != 2 {
				t.Errorf("got columns %v, want only result and detail", row)
			}
			result, detail := row["result"], row["detail"]
			switch result {
			case "pass":
				if detail != "" {
					t.Errorf("passing check has detail %q", detail)
				}
			case "fail", "n/a":
				if detail == "" {
					t.Errorf("%s result has an empty detail", result)
				}
			default:
				t.Fatalf("result %q, want pass, fail or n/a (detail %q)", result, detail)
			}
			t.Logf("%-5s %s", result, detail)
		})
	}
}

// augeasLenses finds the augeas lenses directory for bin.
func augeasLenses(bin string) string {
	candidates := []string{
		os.Getenv("SIGNALITH_AUGEAS_LENSES"),
		filepath.Join(filepath.Dir(bin), "..", "share", "osquery", "lenses"),
		"/opt/osquery/share/osquery/lenses",
	}
	for _, d := range candidates {
		if d == "" {
			continue
		}
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			return d
		}
	}
	return ""
}

func runOsquery(bin string, args []string) (string, string, error) {
	cmd := exec.Command(bin, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	cmd.WaitDelay = 5 * time.Second
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return "", "", err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return out.String(), errb.String(), err
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return out.String(), errb.String(), os.ErrDeadlineExceeded
	}
}

// sqlError returns the SQLite error osqueryd printed, if any. Its glog lines
// (such as a table failing to reach D-Bus) are not SQL errors.
func sqlError(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Error:") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}
