// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
	"github.com/jrsamsanchez/signalith/internal/keytrust"
)

// Updates: when the server offers a newer version (Config.Update), the
// agent downloads the program and the release's signed manifest into
// its update folder, checks the program is the one the manifest lists
// for this computer, signed by a release key it trusts, and runs it once
// to see it starts. Then the updater (signalith-agent install-update)
// puts it in place: on Linux a service of its own outside the agent's
// sandbox, started by a path unit when the agent writes the ready file
// (the agent's service cannot write the program); on Windows a copy of
// the agent the agent starts. The updater checks everything again
// itself, keeps the version before, restarts the agent and goes back to
// the version before when the new one does not report within a few
// minutes or does not keep running.

func (p Paths) updateDir() string { return filepath.Join(p.State, "update") }

// stagedProgram is the downloaded program, waiting for the updater.
func (p Paths) stagedProgram() string {
	name := "signalith-agent-new"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(p.updateDir(), name)
}
func (p Paths) stagedManifest() string { return filepath.Join(p.updateDir(), agentproto.ManifestFile) }
func (p Paths) stagedSignature() string {
	return filepath.Join(p.updateDir(), agentproto.SignatureFile)
}

// trustDir is where the agent keeps the newest revocation list its
// server handed it; rootTrustDir is the updater's own copy, next to the
// version before, where the agent's sandbox cannot write.
func (p Paths) trustDir() string     { return filepath.Join(p.State, "keytrust") }
func (p Paths) rootTrustDir() string { return filepath.Join(filepath.Dir(p.Prev), "keytrust") }

// nextProgram is where the updater copies a program before it replaces
// Program with it; Windows wants it to end in .exe to run it.
func (p Paths) nextProgram() string {
	if runtime.GOOS == "windows" {
		return strings.TrimSuffix(p.Program, ".exe") + ".new.exe"
	}
	return p.Program + ".new"
}

// readyFile tells the updater an update waits; it holds the version.
func (p Paths) readyFile() string { return filepath.Join(p.updateDir(), "ready") }

// resultFile is the updater's last result (updateResult).
func (p Paths) resultFile() string { return filepath.Join(p.updateDir(), "result.json") }

// updateResult is what the updater did last.
type updateResult struct {
	Version string    `json:"version"`
	OK      bool      `json:"ok"`
	Error   string    `json:"error,omitempty"`
	At      time.Time `json:"at"`
}

// Timings of updates; tests shorten them.
var (
	// updateRetry is how long the agent waits before trying an update to
	// the same version again after it could not get it ready.
	updateRetry = time.Hour
	// updaterWait is how long a waiting update may sit before the agent
	// says the updater did not pick it up.
	updaterWait = 10 * time.Minute
	// healthWait is how long the new version has to report after the
	// updater restarts the agent, and stableWait how long it must then
	// keep running.
	healthWait = 3 * time.Minute
	stableWait = 30 * time.Second
	// pollEvery is how often the updater looks while it waits.
	pollEvery = 2 * time.Second
)

// checkUpdate gets an update the configuration offers ready for the
// updater.
func (a *Agent) checkUpdate(ctx context.Context) {
	a.mu.Lock()
	var u *agentproto.Update
	if a.cfg != nil {
		u = a.cfg.Update
	}
	a.mu.Unlock()
	res := a.readResult()
	if u == nil || !agentproto.Newer(u.Version, a.Version) {
		// A failed update to a version no longer offered is not news.
		a.setUpdate(nil)
		return
	}
	if res != nil && !res.OK && res.Version == u.Version {
		a.setUpdate(&agentproto.Component{Name: "update", Version: u.Version, State: agentproto.StateFailed,
			Since: res.At.UTC().Format(time.RFC3339), Error: "the update to " + u.Version + " was undone: " + res.Error})
		return
	}
	if st, err := os.Stat(a.Paths.readyFile()); err == nil {
		if a.now().Sub(st.ModTime()) > updaterWait {
			a.setUpdate(&agentproto.Component{Name: "update", Version: u.Version, State: agentproto.StateFailed,
				Error: "the update to " + u.Version + " is ready but nothing installed it; run the line from Add data > Signalith Agent again, which sets up the updater"})
		}
		return
	}
	if t, ok := a.updateTried[u.Version]; ok && a.now().Sub(t) < updateRetry {
		return
	}
	if a.updateTried == nil {
		a.updateTried = map[string]time.Time{}
	}
	a.updateTried[u.Version] = a.now()
	a.Log.Info("getting an update ready", "version", u.Version)
	if err := a.stageUpdate(ctx, u); err != nil {
		a.Log.Warn("could not get the update ready", "version", u.Version, "err", err)
		a.setUpdate(&agentproto.Component{Name: "update", Version: u.Version, State: agentproto.StateFailed,
			Since: a.now().UTC().Format(time.RFC3339), Error: "could not update to " + u.Version + ": " + err.Error()})
		return
	}
	a.setUpdate(&agentproto.Component{Name: "update", Version: u.Version, State: agentproto.StateStarting,
		Since: a.now().UTC().Format(time.RFC3339)})
	run := a.runUpdater
	if run == nil {
		run = a.startUpdater
	}
	if err := run(); err != nil {
		a.setUpdate(&agentproto.Component{Name: "update", Version: u.Version, State: agentproto.StateFailed,
			Error: "could not start the updater: " + err.Error()})
	}
}

func (a *Agent) setUpdate(c *agentproto.Component) {
	a.mu.Lock()
	a.update = c
	a.mu.Unlock()
}

// readResult reads the updater's last result; nil when there is none.
func (a *Agent) readResult() *updateResult {
	b, err := os.ReadFile(a.Paths.resultFile())
	if err != nil {
		return nil
	}
	var r updateResult
	if json.Unmarshal(b, &r) != nil {
		return nil
	}
	return &r
}

// get fetches a route from the server into w, at most max bytes.
func (a *Agent) get(ctx context.Context, path string, q url.Values, w io.Writer, max int64) error {
	req, err := a.request(ctx, http.MethodGet, path, q, nil)
	if err != nil {
		return err
	}
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return serverError(resp)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, max+1))
	if err != nil {
		return err
	}
	if n > max {
		return errors.New("the server sent more than any release is")
	}
	return nil
}

// stageUpdate downloads update u into the update folder and checks it:
// signed manifest, the program's SHA-256 and that it runs. Last, it
// writes the ready file.
func (a *Agent) stageUpdate(ctx context.Context, u *agentproto.Update) error {
	if err := os.MkdirAll(a.Paths.updateDir(), 0o700); err != nil {
		return err
	}
	var buf strings.Builder
	if err := a.get(ctx, agentproto.RouteManifest, nil, &buf, 2*agentproto.MaxManifestBytes); err != nil {
		return fmt.Errorf("the manifest: %w", err)
	}
	var ans agentproto.ManifestAnswer
	if err := json.Unmarshal([]byte(buf.String()), &ans); err != nil {
		return errors.New("the manifest the server sent is not valid JSON")
	}
	// A revocation list the server hands over is kept when it is newer;
	// a bad one is ignored, never a reason to trust a revoked key.
	store := &keytrust.Store{Dir: a.Paths.trustDir()}
	if ans.Revocation != "" {
		if _, err := store.Offer([]byte(ans.Revocation), []byte(ans.RevocationSignature)); err != nil && !errors.Is(err, keytrust.ErrNoRoot) {
			a.Log.Warn("ignoring the revocation list the server sent", "err", err)
		}
	}
	list, listData, listSig, err := store.Load()
	if err != nil {
		a.Log.Warn("the kept revocation list cannot be read", "err", err)
	}
	m, err := agentproto.VerifyManifest(agentproto.TrustedKeys(list), []byte(ans.Manifest), []byte(ans.Signature))
	if err != nil {
		return keytrust.Explain(err, []byte(ans.Signature), keytrust.RevokedIDs(list))
	}
	want := m.Programs[runtime.GOOS+"-"+runtime.GOARCH]
	if m.Version != u.Version || want == "" || want != u.SHA256 {
		return fmt.Errorf("the signed manifest (version %s) does not list the update the server offered", m.Version)
	}
	path := a.Paths.stagedProgram()
	_ = os.Remove(path)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return err
	}
	h := sha256.New()
	err = a.get(ctx, agentproto.RouteProgram, url.Values{"os": {runtime.GOOS}, "arch": {runtime.GOARCH}}, io.MultiWriter(f, h), agentproto.MaxProgramBytes)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && hex.EncodeToString(h.Sum(nil)) != want {
		err = errors.New("the program the server sent is not the one the signed manifest lists")
	}
	if err == nil {
		err = selfTest(ctx, path, m.Version)
	}
	if err != nil {
		os.Remove(path)
		return err
	}
	if err := writeFile(a.Paths.stagedManifest(), []byte(ans.Manifest), 0o600); err != nil {
		return err
	}
	if err := writeFile(a.Paths.stagedSignature(), []byte(ans.Signature), 0o600); err != nil {
		return err
	}
	// The list goes to the updater too, which keeps its own copy.
	stagedList := filepath.Join(a.Paths.updateDir(), keytrust.ListFile)
	stagedListSig := filepath.Join(a.Paths.updateDir(), keytrust.SignatureFile)
	_ = os.Remove(stagedList)
	_ = os.Remove(stagedListSig)
	if listData != nil {
		if err := writeFile(stagedListSig, listSig, 0o600); err != nil {
			return err
		}
		if err := writeFile(stagedList, listData, 0o600); err != nil {
			return err
		}
	}
	return writeFile(a.Paths.readyFile(), []byte(m.Version+"\n"), 0o600)
}

// selfTest runs program version and checks it says version: the program
// runs on this computer and is the version the manifest says.
func selfTest(ctx context.Context, program, version string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, "version")
	setProcAttr(cmd)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("the new program does not run on this computer: %w", err)
	}
	if got := strings.TrimSpace(string(out)); got != version {
		return fmt.Errorf("the new program says it is version %q, not %s", got, version)
	}
	return nil
}

// ServiceControl restarts the agent's service and says how it is: the
// updater's view of systemd or the Windows service manager.
type ServiceControl interface {
	// Stop stops the service (Windows, before the program is replaced);
	// a no-op where the program can be replaced while it runs.
	Stop(ctx context.Context) error
	// Restart starts the service, stopping it first if it runs.
	Restart(ctx context.Context) error
	// State says whether it runs, and something that changes when it
	// restarts (systemd's restart count, the Windows process ID).
	State(ctx context.Context) (running bool, run string, err error)
}

// Updater puts a waiting update in place (signalith-agent
// install-update). It runs outside the agent's sandbox, so it trusts
// nothing in the update folder: it checks the signed manifest with its
// own release keys, copies the program where only it can write and
// checks the copy.
type Updater struct {
	Paths Paths
	// Version is the updater's own version, which is the agent's.
	Version string
	Service ServiceControl
	Log     *slog.Logger
	now     func() time.Time
	// dir is the update folder, opened by Install.
	dir *updateFolder
}

// Install installs the waiting update, if there is one. It returns nil
// when there was none.
func (u *Updater) Install(ctx context.Context) error {
	if u.now == nil {
		u.now = time.Now
	}
	p := u.Paths
	// Nothing is read, written or deleted unless the folders are the
	// updater's own and no link leads elsewhere.
	dir, err := openUpdateFolder(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("refusing the update folder: %w", err)
	}
	defer dir.Close()
	u.dir = dir
	// The ready file goes first, whatever happens: the path unit starts
	// the updater again while it exists.
	if !dir.exists(filepath.Base(p.readyFile())) {
		return nil
	}
	if err := dir.remove(filepath.Base(p.readyFile())); err != nil {
		return err
	}
	m, err := u.check()
	if err != nil {
		u.result("", err)
		return err
	}
	if err := u.install(ctx, m); err != nil {
		u.result(m.Version, err)
		return err
	}
	u.result(m.Version, nil)
	_ = dir.remove(filepath.Base(p.stagedProgram()))
	return nil
}

// check reads and checks the signed manifest the agent left: signed by a
// release key, newer than this version, listing this computer.
func (u *Updater) check() (*agentproto.Manifest, error) {
	data, err := u.read(agentproto.ManifestFile, false, agentproto.MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	sig, err := u.read(agentproto.SignatureFile, false, 1024)
	if err != nil {
		return nil, err
	}
	list := u.revocations()
	m, err := agentproto.VerifyManifest(agentproto.TrustedKeys(list), data, sig)
	if err != nil {
		return nil, keytrust.Explain(err, sig, keytrust.RevokedIDs(list))
	}
	if !agentproto.Newer(m.Version, u.Version) {
		return nil, fmt.Errorf("version %s is not newer than %s", m.Version, u.Version)
	}
	if m.Programs[runtime.GOOS+"-"+runtime.GOARCH] == "" {
		return nil, fmt.Errorf("version %s has no program for %s/%s", m.Version, runtime.GOOS, runtime.GOARCH)
	}
	return m, nil
}

// revocations keeps the revocation list the agent staged, when it is
// newer than the updater's own copy, and returns the updater's copy: a
// revocation the updater saw once stays, whatever the agent leaves later.
func (u *Updater) revocations() *keytrust.List {
	store := &keytrust.Store{Dir: u.Paths.rootTrustDir()}
	if data, err := u.read(keytrust.ListFile, false, keytrust.MaxList); err == nil {
		sig, err := u.read(keytrust.SignatureFile, false, 1024)
		if err == nil {
			_, err = store.Offer(data, sig)
		}
		if err != nil && !errors.Is(err, keytrust.ErrNoRoot) {
			u.Log.Warn("ignoring the revocation list the agent left", "err", err)
		}
	}
	list, _, _, err := store.Load()
	if err != nil {
		u.Log.Warn("the kept revocation list cannot be read", "err", err)
	}
	return list
}

// install puts version m in place and restarts the agent, going back to
// the version before when the new one does not work.
func (u *Updater) install(ctx context.Context, m *agentproto.Manifest) error {
	p := u.Paths
	want := m.Programs[runtime.GOOS+"-"+runtime.GOARCH]
	// The copy is made first and then checked, so what is checked is what
	// runs; it stays readable by root alone until it is checked.
	next := p.nextProgram()
	staged, err := u.dir.open(filepath.Base(p.stagedProgram()), false)
	if err != nil {
		return err
	}
	err = copyChecked(staged, next, want)
	staged.Close()
	if err != nil {
		return err
	}
	if err := selfTest(ctx, next, m.Version); err != nil {
		os.Remove(next)
		return err
	}
	if err := copyFile(p.Program, p.Prev); err != nil {
		os.Remove(next)
		return fmt.Errorf("keeping the version before: %w", err)
	}
	u.Log.Info("installing the update", "version", m.Version)
	if err := u.swap(ctx, next); err != nil {
		os.Remove(next)
		return err
	}
	if err := u.waitWorking(ctx, m.Version); err != nil {
		u.Log.Warn("the new version does not work; going back to the version before", "version", m.Version, "err", err)
		back := p.nextProgram()
		if cerr := copyFile(p.Prev, back); cerr != nil {
			return fmt.Errorf("%w; going back failed too: %v", err, cerr)
		}
		if serr := u.swap(ctx, back); serr != nil {
			return fmt.Errorf("%w; going back failed too: %v", err, serr)
		}
		return err
	}
	u.Log.Info("updated", "version", m.Version)
	return nil
}

// swap replaces the program with next (mode 0755) and restarts the agent.
func (u *Updater) swap(ctx context.Context, next string) error {
	if err := os.Chmod(next, 0o755); err != nil {
		return err
	}
	if err := u.Service.Stop(ctx); err != nil {
		return fmt.Errorf("stopping the agent: %w", err)
	}
	var err error
	// Windows may hold the program a moment after the service stopped.
	for try := 0; try < 10; try++ {
		if err = os.Rename(next, u.Paths.Program); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return fmt.Errorf("replacing the program: %w", err)
	}
	if err := u.Service.Restart(ctx); err != nil {
		return fmt.Errorf("restarting the agent: %w", err)
	}
	return nil
}

// waitWorking waits for the restarted agent to report as version, then
// checks it keeps running.
func (u *Updater) waitWorking(ctx context.Context, version string) error {
	since := u.now().Add(-time.Second).Truncate(time.Second)
	deadline := u.now().Add(healthWait)
	_, run, _ := u.Service.State(ctx)
	for {
		if u.reported(version, since) {
			break
		}
		if u.now().After(deadline) {
			return fmt.Errorf("version %s did not report within %s", version, healthWait)
		}
		if err := sleepCtx(ctx, pollEvery); err != nil {
			return err
		}
	}
	if run == "" {
		_, run, _ = u.Service.State(ctx)
	}
	if err := sleepCtx(ctx, stableWait); err != nil {
		return err
	}
	running, now, err := u.Service.State(ctx)
	if err != nil {
		return err
	}
	if !running || now != run {
		return fmt.Errorf("version %s stopped and was restarted", version)
	}
	return nil
}

// reported says whether the agent wrote a status as version, started
// since then.
func (u *Updater) reported(version string, since time.Time) bool {
	b, err := u.read(filepath.Base(u.Paths.StatusFile()), true, agentproto.MaxStatusBytes)
	if err != nil {
		return false
	}
	var st agentproto.Status
	if json.Unmarshal(b, &st) != nil {
		return false
	}
	started, err := time.Parse(time.RFC3339, st.Started)
	return err == nil && st.Version == version && !started.Before(since)
}

// result writes what the updater did for the agent to report.
func (u *Updater) result(version string, err error) {
	r := updateResult{Version: version, OK: err == nil, At: u.now().UTC().Truncate(time.Second)}
	if err != nil {
		r.Error = err.Error()
	}
	b, _ := json.Marshal(r)
	if werr := u.dir.write(filepath.Base(u.Paths.resultFile()), b); werr != nil {
		u.Log.Warn("could not write the update's result", "err", werr)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// read reads at most max bytes of the plain file name in the update
// folder (or, with state, the folder above it), which the agent's sandbox
// can write.
func (u *Updater) read(name string, state bool, max int64) ([]byte, error) {
	f, err := u.dir.open(name, state)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err == nil && int64(len(b)) > max {
		err = fmt.Errorf("%s is larger than any update writes", name)
	}
	return b, err
}

// copyChecked copies the staged program to dst, readable by its owner
// alone, and checks the copy's SHA-256 is want.
func copyChecked(in *os.File, dst, want string) error {
	_ = os.Remove(dst)
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, agentproto.MaxProgramBytes+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > agentproto.MaxProgramBytes {
		err = errors.New("the waiting program is larger than any release")
	}
	if err == nil && hex.EncodeToString(h.Sum(nil)) != want {
		err = errors.New("the waiting program is not the one the signed manifest lists")
	}
	if err != nil {
		os.Remove(dst)
	}
	return err
}

// copyFile copies src to dst (mode 0755), through a new file renamed
// into place. Both are where only the updater writes.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	_ = os.Remove(tmp)
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}
