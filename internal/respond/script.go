package respond

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Script actions run a program on this server. The program must sit in
// the scripts folder (response.scripts_dir), which only signalith.yaml or
// SIGNALITH_RESPONSE_SCRIPTS_DIR can name, never a page: whoever can put a
// program there decides what Signalith may run, so that folder is for the
// server's administrators alone. The path is resolved with every link
// followed before it is checked, so a link cannot lead out of the folder.
//
// The program runs without a shell, with the target as its one argument
// and in SIGNALITH_TARGET (with SIGNALITH_TARGET_KIND,
// SIGNALITH_FINDING_ID, SIGNALITH_CASE_ID and SIGNALITH_ACTOR), a small
// environment that holds none of Signalith's own settings or secrets, the
// scripts folder as its working folder, and a time limit after which it
// and the programs it started are stopped. Standard output and error are
// kept together, cut at MaxOutput. Exit code 0 is success.
//
// On Windows, .ps1 scripts run with powershell.exe -NoProfile
// -NonInteractive -ExecutionPolicy Bypass -File, and .exe programs as they
// are. .cmd and .bat files are refused: cmd.exe reads its command line in
// its own way, which no quoting makes safe for every value. On Linux and
// macOS the program must be executable, and a script needs its #! line.

// ScriptError is a program that cannot be used.
type ScriptError struct{ Msg string }

func (e *ScriptError) Error() string { return e.Msg }

func scriptErr(format string, args ...any) error {
	return &ScriptError{Msg: fmt.Sprintf(format, args...)}
}

// ResolveProgram returns the full path of program inside dir, with every
// link followed, or why it cannot run: it is outside dir (by .., an
// absolute path or a link), missing, not a regular file, not executable,
// writable by everyone, or a kind of file this system does not run.
func ResolveProgram(dir, program string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", scriptErr("there is no scripts folder; set response.scripts_dir in signalith.yaml")
	}
	program = strings.ReplaceAll(strings.TrimSpace(program), `\`, "/")
	if program == "" {
		return "", scriptErr("enter the program's file name")
	}
	if filepath.IsAbs(program) || filepath.VolumeName(program) != "" || strings.HasPrefix(program, "/") || strings.Contains(program, ":") {
		return "", scriptErr("give the program's name relative to the scripts folder")
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", scriptErr("the scripts folder %s does not exist; create it and put the program there", dir)
		}
		return "", scriptErr("the scripts folder %s cannot be read: %v", dir, err)
	}
	realDir, err = filepath.Abs(realDir)
	if err != nil {
		return "", err
	}
	joined := filepath.Join(realDir, filepath.FromSlash(program))
	if !inside(realDir, joined) {
		return "", scriptErr("%s is outside the scripts folder", program)
	}
	full, err := filepath.EvalSymlinks(joined)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", scriptErr("%s is not in the scripts folder %s", program, realDir)
		}
		return "", scriptErr("%s cannot be read: %v", program, err)
	}
	full, err = filepath.Abs(full)
	if err != nil {
		return "", err
	}
	if !inside(realDir, full) {
		return "", scriptErr("%s leads outside the scripts folder (it is a link to %s); put the program itself in the folder", program, full)
	}
	st, err := os.Stat(full)
	if err != nil {
		return "", scriptErr("%s cannot be read: %v", program, err)
	}
	if !st.Mode().IsRegular() {
		return "", scriptErr("%s is not a program file", program)
	}
	if err := checkRunnable(full, st); err != nil {
		return "", err
	}
	return full, nil
}

// inside reports whether p is dir or below it; both are clean absolute
// paths.
func inside(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return false
	}
	return rel != "."
}

// checkRunnable checks that this system can run the file as it is.
func checkRunnable(full string, st fs.FileInfo) error {
	ext := strings.ToLower(filepath.Ext(full))
	if runtime.GOOS == "windows" {
		switch ext {
		case ".exe", ".ps1":
			return nil
		case ".cmd", ".bat":
			return scriptErr("%s is a batch file, which Signalith does not run: cmd.exe cannot be given a value safely. Use a PowerShell script (.ps1) or an .exe", filepath.Base(full))
		}
		return scriptErr("%s cannot run on Windows: use a PowerShell script (.ps1) or an .exe", filepath.Base(full))
	}
	if st.Mode().Perm()&0o111 == 0 {
		return scriptErr("%s is not executable; run chmod +x on it", filepath.Base(full))
	}
	if st.Mode().Perm()&0o002 != 0 {
		return scriptErr("%s can be changed by every account on this server, so Signalith does not run it; run chmod o-w on it", filepath.Base(full))
	}
	return nil
}

// ListScripts returns the files in the scripts folder and one level of
// folders below it, as paths relative to it with / separators, for the
// page's program picker.
func ListScripts(dir string) []string {
	out := []string{}
	if dir == "" {
		return out
	}
	walk := func(rel string) []fs.DirEntry {
		entries, _ := os.ReadDir(filepath.Join(dir, filepath.FromSlash(rel)))
		return entries
	}
	for _, e := range walk("") {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if e.IsDir() {
			for _, s := range walk(e.Name()) {
				if !s.IsDir() && !strings.HasPrefix(s.Name(), ".") {
					out = append(out, e.Name()+"/"+s.Name())
				}
			}
			continue
		}
		if st, err := os.Stat(filepath.Join(dir, e.Name())); err != nil || !st.Mode().IsRegular() {
			continue
		}
		out = append(out, e.Name())
		if len(out) >= 500 {
			break
		}
	}
	sort.Strings(out)
	return out
}

// scriptCommand returns how to run a program with one argument.
func scriptCommand(full, arg string) (string, []string) {
	if runtime.GOOS == "windows" && strings.EqualFold(filepath.Ext(full), ".ps1") {
		return powershellPath(), []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", full, arg}
	}
	return full, []string{arg}
}

// powershellPath finds Windows PowerShell in the system folder, so a
// powershell.exe elsewhere on PATH is never used.
func powershellPath() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		p := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
}

// passEnv are the variables a program gets from Signalith's own
// environment: what programs need to find the system, never Signalith's
// settings or secrets.
var passEnv = map[string][]string{
	"windows": {"SystemRoot", "SystemDrive", "windir", "PATH", "PATHEXT", "TEMP", "TMP", "ComSpec", "ProgramData",
		"ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles", "PSModulePath", "USERPROFILE",
		"LOCALAPPDATA", "APPDATA", "COMPUTERNAME", "USERDOMAIN", "USERNAME", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE"},
	"other": {"HOME", "LANG", "LC_ALL", "TZ", "TMPDIR", "USER", "LOGNAME"},
}

// defaultPath is PATH for programs on Linux and macOS.
const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

func scriptEnv(run *Run) []string {
	var env []string
	names := passEnv["other"]
	if runtime.GOOS == "windows" {
		names = passEnv["windows"]
	} else {
		env = append(env, "PATH="+defaultPath)
	}
	for _, n := range names {
		if v, ok := os.LookupEnv(n); ok {
			env = append(env, n+"="+v)
		}
	}
	return append(env,
		"SIGNALITH_TARGET="+run.Target,
		"SIGNALITH_TARGET_KIND="+run.TargetKind,
		"SIGNALITH_FINDING_ID="+run.FindingID,
		"SIGNALITH_CASE_ID="+run.CaseID,
		"SIGNALITH_ACTOR="+run.Actor,
		"SIGNALITH_RUN_ID="+run.ID,
	)
}

// capped keeps the first max bytes written to it and counts the rest.
type capped struct {
	buf     bytes.Buffer
	max     int
	dropped int64
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		n := min(room, len(p))
		c.buf.Write(p[:n])
		c.dropped += int64(len(p) - n)
	} else {
		c.dropped += int64(len(p))
	}
	return len(p), nil
}

// runScript runs a script action's program.
func (r *Runner) runScript(ctx context.Context, c Connector, run *Run) result {
	full, err := ResolveProgram(r.ScriptsDir, c.Program)
	if err != nil {
		return result{summary: "The program did not run.", err: err}
	}
	timeout := time.Duration(c.TimeoutSeconds) * time.Second
	if timeout <= 0 || timeout > MaxScriptTimeout*time.Second {
		timeout = DefaultScriptTimeout * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	name, args := scriptCommand(full, run.Target)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = filepath.Dir(full)
	cmd.Env = scriptEnv(run)
	cmd.Stdin = nil
	out := &capped{max: MaxOutput}
	cmd.Stdout, cmd.Stderr = out, out
	setProcessGroup(cmd)
	// Programs the script started can hold the output open after it is
	// stopped; stop waiting for them soon after.
	cmd.WaitDelay = 2 * time.Second
	started := time.Now()
	err = cmd.Run()
	text := out.buf.String()
	if out.dropped > 0 {
		text += fmt.Sprintf("\n[… %d more bytes of output not kept]", out.dropped)
	}
	took := time.Since(started).Round(100 * time.Millisecond)
	base := filepath.Base(full)
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		return result{summary: fmt.Sprintf("%s was stopped after %s.", base, timeout),
			output: text, err: fmt.Errorf("%s did not finish within %s, so it was stopped; it may have done part of its work. Raise the action's timeout if it needs longer", base, timeout)}
	case err == nil:
		if took < time.Second {
			return result{summary: fmt.Sprintf("%s finished in under a second.", base), output: text}
		}
		return result{summary: fmt.Sprintf("%s finished in %s.", base, took), output: text}
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.Exited() {
		return result{summary: fmt.Sprintf("%s exited with code %d.", base, ee.ExitCode()), output: text,
			err: fmt.Errorf("%s exited with code %d; see its output", base, ee.ExitCode())}
	}
	return result{summary: base + " could not run.", output: text, err: fmt.Errorf("%s could not run: %v", base, err)}
}
