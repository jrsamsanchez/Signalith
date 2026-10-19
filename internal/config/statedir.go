// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// The state folder holds what Signalith makes for itself and keeps on one
// server: its master key (keys/), its HTTPS certificate and certificate
// authority (tls/), the built-in admin's password set with signalith
// passwd (admin-password-hash), and this server's identity (node.id) with
// its lock (cluster/). StateDir picks it, for the server and for every
// command, so these always sit together.

// stateFiles are the files and folders whose presence shows that a folder
// is already some install's state folder.
var stateFiles = []string{"keys", "tls", "admin-password-hash", "node.id"}

// insteadOfFile, in a fallback state folder, lists the folders it is used
// instead of, one per line, so every later start and every command run by
// hand (which may run as another user, for whom the usual folder can be
// written) finds the same folder.
const insteadOfFile = "used_instead_of"

// HoldsState reports whether dir already holds Signalith's own files: a
// master key, an HTTPS certificate, a password set with signalith passwd,
// or a server identity.
func HoldsState(dir string) bool {
	for _, f := range stateFiles {
		if _, err := os.Lstat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

// StateDir returns the state folder (see StateDirChoice).
func (c *Config) StateDir() string {
	dir, _ := c.StateDirChoice()
	return dir
}

// StateDirChoice returns the state folder and, when it is not the usual
// one or the usual one cannot be used, why, for the log:
//
//  1. SIGNALITH_STATE_DIR when it is set.
//  2. Else a fallback folder used before instead of the folder that holds
//     lookups.dir (its used_instead_of file names that folder). Files
//     that appear in the usual folder later, such as a master key made by
//     a command run without the service's settings, do not move it back:
//     the reason says they are not used.
//  3. Else the folder that holds lookups.dir when it already holds
//     Signalith's own files (HoldsState), so an upgrade never leaves a
//     master key or a certificate behind.
//  4. Else that folder, when it is on a local disk this user can write.
//  5. Else the first fallback that is (systemd's $STATE_DIRECTORY, then
//     /var/lib/signalith on Linux; %ProgramData%\Signalith on Windows)
//     and is not another install's state folder (see takenByOther).
//  6. Else the folder that holds lookups.dir anyway; the reason, and
//     using it, then say what is wrong.
//
// Choosing writes nothing, so commands that only read (validate, secrets
// status and the others) change nothing. The server, and a command about
// to write in the folder, call RecordStateDir first, which notes a
// fallback as used instead of the usual folder.
//
// The answer is kept for the life of the process, so a restart in place
// or a folder that becomes writable later never moves it.
func (c *Config) StateDirChoice() (dir, why string) {
	if d := os.Getenv("SIGNALITH_STATE_DIR"); d != "" {
		return d, ""
	}
	return pickStateDir(filepath.Dir(c.LookupsDir()), fallbackStateDirs())
}

// StateDirFallbacks are the folders a state folder falls back to here.
func StateDirFallbacks() []string { return fallbackStateDirs() }

// stateChoice is a chosen state folder. insteadOf is the usual folder
// when dir is a fallback that does not yet say it is used instead of it.
type stateChoice struct{ dir, why, insteadOf string }

var (
	stateMu    sync.Mutex
	stateCache = map[string]stateChoice{}
)

// forgetStateDirs empties the kept answers, for tests.
func forgetStateDirs() {
	stateMu.Lock()
	clear(stateCache)
	stateMu.Unlock()
}

func pickStateDir(def string, fallbacks []string) (string, string) {
	abs, err := filepath.Abs(def)
	if err != nil {
		return def, ""
	}
	key := abs + "\x00" + strings.Join(fallbacks, "\x00")
	stateMu.Lock()
	defer stateMu.Unlock()
	if ch, ok := stateCache[key]; ok {
		return ch.dir, ch.why
	}
	ch := chooseStateDir(def, abs, fallbacks)
	stateCache[key] = ch
	return ch.dir, ch.why
}

// RecordStateDir is called by a process about to write in the state
// folder dir: the server when it starts, and signalith passwd. When dir
// is a fallback this process chose, it makes the folder if needed (with
// an access list of its own on Windows, not ProgramData's) and notes in
// it which folder it is used instead of, so every later start and every
// command finds the same folder, and no other install takes it. For any
// other folder it does nothing.
func RecordStateDir(dir string) error {
	stateMu.Lock()
	defer stateMu.Unlock()
	for key, ch := range stateCache {
		if ch.insteadOf == "" || !samePath(ch.dir, dir) {
			continue
		}
		if err := noteInsteadOf(ch.dir, ch.insteadOf); err != nil {
			return fmt.Errorf("could not note in %s that Signalith keeps its own files there: %w. Set SIGNALITH_STATE_DIR to a folder on a local disk that this user can write", ch.dir, err)
		}
		ch.insteadOf = ""
		stateCache[key] = ch
	}
	return nil
}

func chooseStateDir(def, abs string, fallbacks []string) stateChoice {
	var others []string
	for _, d := range fallbacks {
		if d != "" && !samePath(d, abs) {
			others = append(others, d)
		}
	}
	for _, d := range others {
		if !usedInsteadOf(d, abs) {
			continue
		}
		why := fmt.Sprintf("Signalith keeps its own files (master key, HTTPS certificate and this server's identity) in %s, "+
			"used instead of %s since that folder could not be used; set SIGNALITH_STATE_DIR to choose the folder", d, abs)
		if stray := stateFilesIn(abs); len(stray) > 0 {
			it, was := "it", "it was"
			if len(stray) > 1 {
				it, was = "them", "they were"
			}
			why += fmt.Sprintf(". %s also holds %s, which Signalith does not use: %s probably made later by a command run without the service's settings. "+
				"Move %s away once you are sure nothing in %s is needed", abs, strings.Join(stray, " and "), was, it, it)
		}
		return stateChoice{dir: d, why: why}
	}
	if HoldsState(abs) {
		return stateChoice{dir: def}
	}
	problem := stateDirProblem(abs)
	if problem == "" {
		return stateChoice{dir: def}
	}
	var taken []string
	for _, d := range others {
		if stateDirProblem(d) != "" {
			continue
		}
		if takenByOther(d) {
			taken = append(taken, d)
			continue
		}
		return stateChoice{dir: d, insteadOf: abs, why: fmt.Sprintf("Signalith keeps its own files (master key, HTTPS certificate and this server's identity) in %s, "+
			"because %s; set SIGNALITH_STATE_DIR to choose the folder", d, problem)}
	}
	why := fmt.Sprintf("Signalith cannot keep its own files (master key, HTTPS certificate and this server's identity) in %s, because %s", abs, problem)
	if len(taken) > 0 {
		why += fmt.Sprintf(", and %s already %s another Signalith install's files", strings.Join(taken, " and "), plural(len(taken), "holds", "hold"))
	}
	return stateChoice{dir: def, why: why + ". Set SIGNALITH_STATE_DIR to a folder on a local disk that this user can write"}
}

// takenByOther reports whether the fallback folder dir is another
// install's state folder: it holds a server identity, an HTTPS
// certificate or an admin password, or it is noted as used instead of
// another folder. (A fallback that is this install's own is found
// before, by its note.) A folder that holds only a master key may still
// be taken: on Linux, signalith init makes the key of a config in /etc in
// /var/lib/signalith before the service first starts (see Keyring).
func takenByOther(dir string) bool {
	for _, f := range stateFilesIn(dir) {
		if f != "keys" {
			return true
		}
	}
	return len(notedFolders(dir)) > 0
}

// stateFilesIn lists the files and folders of stateFiles that dir holds.
func stateFilesIn(dir string) []string {
	var out []string
	for _, f := range stateFiles {
		if _, err := os.Lstat(filepath.Join(dir, f)); err == nil {
			out = append(out, f)
		}
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// stateDirProblem is StateDirProblem; tests replace it.
var stateDirProblem = StateDirProblem

// StateDirProblem says why dir cannot be a state folder (it is on a
// network share, or this user cannot write in it), or "". A folder that
// does not exist yet is checked where it would be made.
func StateDirProblem(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err.Error()
	}
	at := nearestExisting(abs)
	if network, _, err := FolderFilesystem(at); err == nil && network != "" {
		return fmt.Sprintf("the folder that holds lookups.dir, %s, is on a network share (%s)", abs, network)
	}
	if st, err := os.Stat(at); err != nil || !st.IsDir() {
		return fmt.Sprintf("this user cannot write in %s", at)
	}
	f, err := os.CreateTemp(at, ".signalith-write-check-*")
	if err != nil {
		return fmt.Sprintf("this user cannot write in %s", at)
	}
	name := f.Name()
	f.Close()
	_ = os.Remove(name)
	return ""
}

// nearestExisting returns dir, or the nearest folder above it that exists.
func nearestExisting(dir string) string {
	at := dir
	for {
		if _, err := os.Stat(at); err == nil || filepath.Dir(at) == at {
			return at
		}
		at = filepath.Dir(at)
	}
}

// NearestExisting is nearestExisting, for the cluster package.
func NearestExisting(dir string) string { return nearestExisting(dir) }

// notedFolders lists the folders the fallback folder dir is noted as used
// instead of, in its used_instead_of file.
func notedFolders(dir string) []string {
	f, err := os.Open(filepath.Join(dir, insteadOfFile))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// usedInsteadOf reports whether the fallback folder dir was used instead
// of the folder def before.
func usedInsteadOf(dir, def string) bool {
	for _, d := range notedFolders(dir) {
		if samePath(d, def) {
			return true
		}
	}
	return false
}

// noteInsteadOf records in the fallback folder dir that it is used
// instead of def. A folder that does not exist yet is made private (mode
// 0700, or on Windows an access list of its own for SYSTEM,
// Administrators and the service, not the one ProgramData passes down,
// which lets every user read). The note holds only folder names, so
// every account may read it; made by root, it is given to the folder's
// owner, so the server's own account can add to it.
func noteInsteadOf(dir, def string) error {
	if usedInsteadOf(dir, def) {
		return nil
	}
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err := securefile.MkdirPrivate(dir); err != nil {
			return err
		}
	}
	path := filepath.Join(dir, insteadOfFile)
	fi, err := os.Lstat(path)
	isNew := errors.Is(err, os.ErrNotExist)
	if err == nil && !fi.Mode().IsRegular() {
		// Run as root, a link here made by the server's own account must
		// not be followed to some other file.
		return fmt.Errorf("%s is not a plain file; move it away", path)
	}
	f, ferr := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|noFollow, 0o644)
	if ferr != nil {
		return ferr
	}
	if isNew {
		_, ferr = f.WriteString("# Signalith keeps its own files here instead of in these folders, which could not be used.\n")
		if ferr == nil {
			// Readable by every account whatever the umask (the systemd
			// unit's is 0077).
			ferr = f.Chmod(0o644)
		}
		if ferr == nil {
			ferr = giveToFolderOwner(f, dir)
		}
	}
	if ferr == nil {
		_, ferr = f.WriteString(def + "\n")
	}
	if cerr := f.Close(); ferr == nil {
		ferr = cerr
	}
	return ferr
}

// samePath reports whether two folder names are the same, ignoring case
// on Windows.
func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	return a == b || runtime.GOOS == "windows" && strings.EqualFold(a, b)
}
