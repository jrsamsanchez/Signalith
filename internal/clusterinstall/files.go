// Package clusterinstall hands a new server what it needs to install
// Signalith and join a cluster: the install scripts (deploy/linux/install.sh
// and deploy/windows/install.ps1), this server's own program for a machine
// of the same kind, and the lines the Add a server dialog shows. These are
// only public bits, the open-source program and its scripts: what a server
// needs to join (keys, settings) comes from "signalith join" with a token.
package clusterinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/deploy"
)

// The scripts' names in GET /api/cluster/join/<name>, and the network
// sensor's (GET /api/sensor/install.sh).
const (
	ScriptSH     = "install.sh"
	ScriptPS1    = "install.ps1"
	ScriptSensor = "sensor-install.sh"
)

// ScriptSHA is the SHA-256 of each install script, in hex, which the
// pasted lines check before they run one.
type ScriptSHA struct {
	SH     string `json:"sh"`
	PS1    string `json:"ps1"`
	Sensor string `json:"sensor"`
}

var scriptSHA = ScriptSHA{SH: hexSHA(deploy.InstallSH), PS1: hexSHA(deploy.InstallPS1), Sensor: hexSHA(deploy.SensorInstallSH)}

// ScriptSHA256 returns the scripts' SHA-256.
func ScriptSHA256() ScriptSHA { return scriptSHA }

// Script returns the script called name and its SHA-256, or false for
// any other name.
func Script(name string) ([]byte, string, bool) {
	switch name {
	case ScriptSH:
		return deploy.InstallSH, scriptSHA.SH, true
	case ScriptPS1:
		return deploy.InstallPS1, scriptSHA.PS1, true
	case ScriptSensor:
		return deploy.SensorInstallSH, scriptSHA.Sensor, true
	}
	return nil, "", false
}

func hexSHA(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ErrOtherPlatform is Binary's answer for a machine of another kind than
// this server: it has only its own program.
var ErrOtherPlatform = errors.New("this server has no program for that kind of machine")

// Files is this server's own program, handed to new servers of the same
// kind (operating system and processor).
type Files struct {
	// Exe is the program's path; empty is os.Executable.
	Exe string
	// GOOS and GOARCH are the kind of machine it runs on; empty is this
	// process's.
	GOOS, GOARCH string

	mu     sync.Mutex
	sum    string
	sumFor fileStamp
}

// fileStamp tells whether the program file was replaced (an upgrade)
// since its SHA-256 was worked out.
type fileStamp struct {
	size int64
	mod  time.Time
}

// Platform returns the kind of machine this server's program is for.
func (f *Files) Platform() (goos, goarch string) {
	goos, goarch = f.GOOS, f.GOARCH
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	return goos, goarch
}

func (f *Files) exe() (string, error) {
	if f.Exe != "" {
		return f.Exe, nil
	}
	return os.Executable()
}

// Binary opens this server's program for a machine of kind goos/goarch,
// with its size and SHA-256 in hex. The caller closes the file. A
// machine of another kind gets ErrOtherPlatform.
func (f *Files) Binary(goos, goarch string) (*os.File, int64, string, error) {
	if g, a := f.Platform(); goos != g || goarch != a {
		return nil, 0, "", ErrOtherPlatform
	}
	path, err := f.exe()
	if err != nil {
		return nil, 0, "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, "", err
	}
	sum, size, err := f.checksum(file)
	if err != nil {
		file.Close()
		return nil, 0, "", err
	}
	return file, size, sum, nil
}

// BinarySHA256 returns the SHA-256 of this server's program, for the
// pasted lines, or "" when it cannot be read.
func (f *Files) BinarySHA256() string {
	path, err := f.exe()
	if err != nil {
		return ""
	}
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	sum, _, err := f.checksum(file)
	if err != nil {
		return ""
	}
	return sum
}

// checksum returns file's SHA-256, worked out again only when the file
// changed, and leaves file at its start.
func (f *Files) checksum(file *os.File) (string, int64, error) {
	st, err := file.Stat()
	if err != nil {
		return "", 0, err
	}
	stamp := fileStamp{size: st.Size(), mod: st.ModTime()}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sum != "" && f.sumFor == stamp {
		return f.sum, stamp.size, nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", 0, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	f.sum, f.sumFor = hex.EncodeToString(h.Sum(nil)), stamp
	return f.sum, stamp.size, nil
}
