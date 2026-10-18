package clusterinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
	"github.com/jrsamsanchez/signalith/internal/agents"
)

// The Signalith Agent's install (Add data > Signalith Agent): one pasted
// line downloads the agent install script from the server's agent port,
// checks its SHA-256 and runs it with the agent token on its standard
// input. The script checks the server's certificate authority against the
// fingerprint in the line, installs Fluent Bit from its publisher's
// signed packages, downloads the agent program from the server and starts
// it. The server hands out the agent programs it was installed with (the
// packages and the image carry one for each platform).

// AgentLine is what the agent's pasted line is made from.
type AgentLine struct {
	// URL is the address the agent sends to and downloads from
	// (https://siem:7779).
	URL string
	// Version is this server's version.
	Version string
	// CASHA256 is the SHA-256 (hex) of the certificate authority the
	// agent pins, and NextCASHA256 the one prepared to replace it; both
	// empty when the server's certificate is from a public CA.
	CASHA256, NextCASHA256 string
}

// AgentCommands is the agent's pasted line for each system, and a note
// for the page.
type AgentCommands struct {
	Linux        string `json:"linux"`
	Note         string `json:"note"`
	ScriptSHA256 string `json:"script_sha256"`
	// Windows is the line for an elevated PowerShell, and WindowsNote
	// its note.
	Windows       string `json:"windows"`
	WindowsNote   string `json:"windows_note"`
	WindowsSHA256 string `json:"windows_script_sha256"`
}

// AgentSystems are the systems the agent install script supports, as the
// page and the docs say them.
const AgentSystems = "Ubuntu 22.04 or 24.04, Debian 12 or 13, Red Hat Enterprise Linux, Rocky Linux, AlmaLinux or Oracle Linux 8 or 9, and Amazon Linux 2023 (64-bit x86 or ARM)"

// AgentWindowsSystems are the Windows versions the agent install script
// supports.
const AgentWindowsSystems = "Windows 10 or 11 and Windows Server 2016 or later (64-bit x86)"

func (l *AgentLine) check() error {
	if err := checkURL(l.URL); err != nil {
		return &FieldError{Field: "server", Err: err}
	}
	if !versionText.MatchString(l.Version) {
		return errors.New("not a version")
	}
	for _, sum := range []string{l.CASHA256, l.NextCASHA256} {
		if sum != "" && !hexText.MatchString(sum) {
			return errors.New("not a SHA-256")
		}
	}
	if l.NextCASHA256 != "" && l.CASHA256 == "" {
		return errors.New("a next certificate authority without a current one")
	}
	return nil
}

// AgentLines makes the agent's pasted line. As for the sensor's, the
// download does not check the server's certificate, which the computer
// does not trust yet: the SHA-256 checks the script, and the script
// checks the certificate authority against --ca-sha256 before it trusts
// it. The token is agents.TokenPlaceholder until the page puts a new one
// in, and goes to the script on its standard input, never on its command
// line. The line starts with a space, so bash leaves it out of its
// history where it is set to.
func AgentLines(l AgentLine) (AgentCommands, error) {
	if err := l.check(); err != nil {
		return AgentCommands{}, err
	}
	base := strings.TrimSuffix(l.URL, "/")
	sha := scriptSHA.Agent
	line := fmt.Sprintf(" f=$(mktemp) && curl -fsSk --proto '=https' %s%s -o \"$f\" && echo \"%s  $f\" | sha256sum -c --quiet && echo '%s' | sudo sh \"$f\" --from %s",
		base, agentproto.RouteInstallSH, sha, agents.TokenPlaceholder, base)
	if l.CASHA256 != "" {
		line += " --ca-sha256 " + l.CASHA256
	}
	if l.NextCASHA256 != "" {
		line += " --next-ca-sha256 " + l.NextCASHA256
	}
	line += " --version " + l.Version + " --token -"
	note := "Runs on " + AgentSystems + ". The line holds a new token for the computers you install it on: anyone with it can send data as them, so don't share it. " +
		"It starts with a space, which keeps it out of the shell's history on Ubuntu and Debian; elsewhere, clear the history after running it (history -c)."
	c := AgentCommands{Linux: line, Note: note, ScriptSHA256: sha}
	c.Windows, c.WindowsSHA256 = agentWindowsLine(l, base)
	c.WindowsNote = "Runs on " + AgentWindowsSystems + ", in PowerShell opened with Run as administrator (Windows PowerShell 5.1 or PowerShell 7). " +
		"The line holds a new token for the computers you install it on: anyone with it can send data as them, so don't share it. " +
		"The script takes the line out of PowerShell's saved history when it is done."
	return c, nil
}

// agentWindowsLine is the Windows line: as for the server's own join
// line, Windows PowerShell 5.1 needs the certificate check turned off for
// the one download (and back on after it), PowerShell 7 has
// -SkipCertificateCheck. The token goes to the script through the
// pipeline, in the same PowerShell, so it is on no program's command
// line.
func agentWindowsLine(l AgentLine, base string) (string, string) {
	sha := scriptSHA.AgentPS1
	u := base + agentproto.RouteInstallPS1
	line := fmt.Sprintf("$u='%s'; $f=Join-Path $env:TEMP 'signalith-agent-install.ps1'; $ProgressPreference='SilentlyContinue'; "+
		"if ($PSVersionTable.PSVersion.Major -ge 6) { Invoke-WebRequest '%s' -OutFile $f -SkipCertificateCheck -MaximumRedirection 0 } "+
		"else { [Net.ServicePointManager]::SecurityProtocol='Tls12'; [Net.ServicePointManager]::ServerCertificateValidationCallback={$true}; "+
		"try { Invoke-WebRequest '%s' -OutFile $f -UseBasicParsing -MaximumRedirection 0 } finally { [Net.ServicePointManager]::ServerCertificateValidationCallback=$null } }; "+
		"if ((Get-FileHash $f -Algorithm SHA256).Hash -ne '%s') { throw 'The downloaded script is not the one this line names, so it was not run.' }; "+
		"Set-ExecutionPolicy -Scope Process Bypass -Force; '%s' | & $f -From $u",
		base, u, u, strings.ToUpper(sha), agents.TokenPlaceholder)
	if l.CASHA256 != "" {
		line += " -CaSha256 " + l.CASHA256
	}
	if l.NextCASHA256 != "" {
		line += " -NextCaSha256 " + l.NextCASHA256
	}
	line += " -Version " + l.Version + " -Token -"
	return line, sha
}

var programName = regexp.MustCompile(`^signalith-agent-[a-z0-9]+-[a-z0-9]+(\.exe)?$`)

// ErrNoProgram is the answer for a platform this server has no agent
// program for: a development build, or a platform the agent is not built
// for.
var ErrNoProgram = errors.New("this server has no Signalith Agent program for that kind of computer")

// AgentProgramsEnv names the folder of agent programs, when set.
const AgentProgramsEnv = "SIGNALITH_AGENT_PROGRAMS"

// Programs are the agent programs a server hands out, one file per
// platform (agentproto.ProgramName) in one folder.
type Programs struct {
	// Dir is the folder; empty looks in DefaultProgramsDir.
	Dir string

	mu   sync.Mutex
	sums map[string]programSum
}

type programSum struct {
	stamp fileStamp
	sum   string
}

// DefaultProgramsDir is where the agent programs are: the folder in
// SIGNALITH_AGENT_PROGRAMS, else agents next to this program (the .msi
// and a Windows zip put them there), else /usr/share/signalith/agents (the
// .deb and .rpm packages); "" when none of them exists.
func DefaultProgramsDir() string {
	if d := os.Getenv(AgentProgramsEnv); d != "" {
		return d
	}
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "agents"))
	}
	if runtime.GOOS != "windows" {
		dirs = append(dirs, "/usr/share/signalith/agents")
	}
	for _, d := range dirs {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			return d
		}
	}
	return ""
}

func (p *Programs) dir() string {
	if p.Dir != "" {
		return p.Dir
	}
	return DefaultProgramsDir()
}

// Available lists the platforms (os-arch) this server has a program for.
func (p *Programs) Available() []string {
	out := []string{}
	dir := p.dir()
	if dir == "" {
		return out
	}
	for _, pl := range agentproto.Platforms {
		goos, goarch, _ := strings.Cut(pl, "-")
		if st, err := os.Stat(filepath.Join(dir, agentproto.ProgramName(goos, goarch))); err == nil && st.Mode().IsRegular() {
			out = append(out, pl)
		}
	}
	return out
}

// Open opens the program for goos/goarch, with its size and SHA-256 in
// hex. The caller closes the file.
func (p *Programs) Open(goos, goarch string) (*os.File, int64, string, error) {
	if !slices.Contains(agentproto.Platforms, goos+"-"+goarch) {
		return nil, 0, "", ErrNoProgram
	}
	dir := p.dir()
	if dir == "" {
		return nil, 0, "", ErrNoProgram
	}
	name := agentproto.ProgramName(goos, goarch)
	// Checked again here, where the name becomes a path: only a program
	// file name, never a separator or "..".
	if !programName.MatchString(name) {
		return nil, 0, "", ErrNoProgram
	}
	f, err := os.Open(filepath.Join(dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, "", ErrNoProgram
	}
	if err != nil {
		return nil, 0, "", err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		if err == nil {
			err = ErrNoProgram
		}
		return nil, 0, "", err
	}
	stamp := fileStamp{size: st.Size(), mod: st.ModTime()}
	p.mu.Lock()
	cached, ok := p.sums[name]
	p.mu.Unlock()
	if ok && cached.stamp == stamp {
		return f, stamp.size, cached.sum, nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		f.Close()
		return nil, 0, "", err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, 0, "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	p.mu.Lock()
	if p.sums == nil {
		p.sums = map[string]programSum{}
	}
	p.sums[name] = programSum{stamp: stamp, sum: sum}
	p.mu.Unlock()
	return f, stamp.size, sum, nil
}
