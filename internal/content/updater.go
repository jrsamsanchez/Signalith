package content

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
)

// Updater keeps a server's content packs up to date: it uses the
// installed update at start, checks for and installs newer ones, and
// takes one uploaded by an admin.
type Updater struct {
	// Dir is where the installed update is kept.
	Dir string
	// Keys are the trusted public keys; nil means TrustedKeys().
	Keys []ed25519.PublicKey
	// Library is reloaded when the packs change; nil changes only Packs.
	Library *detect.Library
	// Client downloads updates; nil uses a client with a timeout.
	Client *http.Client
	Log    *slog.Logger

	mu     sync.Mutex
	status Status
}

// Status is what the Detections page shows about content updates.
type Status struct {
	// Version is the content in use and Updated whether it is an update;
	// Builtin is the version of the packs in this build of Signalith.
	Version string `json:"version"`
	Updated bool   `json:"updated"`
	Builtin string `json:"builtin"`
	// Ready is false when this build trusts no signing key, so it cannot
	// take updates.
	Ready bool `json:"ready"`
	// Packs are the packs of the update in use.
	Packs []PackInfo `json:"packs,omitempty"`
	// Skipped counts rules of the update this build cannot read, with
	// the first few reasons.
	Skipped        int      `json:"skipped,omitempty"`
	SkippedReasons []string `json:"skipped_reasons,omitempty"`
	// LastCheck, LastResult and LastError are about the latest check or
	// upload.
	LastCheck  time.Time `json:"last_check,omitzero"`
	LastResult string    `json:"last_result,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
}

// ErrNotNewer is returned for an update that is not newer than the
// content in use.
var ErrNotNewer = errors.New("the content in use is as new or newer")

func (u *Updater) keys() []ed25519.PublicKey {
	if u.Keys != nil {
		return u.Keys
	}
	return TrustedKeys()
}

func (u *Updater) log() *slog.Logger {
	if u.Log != nil {
		return u.Log
	}
	return slog.Default()
}

// Status returns the current status.
func (u *Updater) Status() Status {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := u.status
	st.Version, st.Updated = detect.ContentVersion()
	st.Builtin = detect.BuiltinContentVersion()
	st.Ready = len(u.keys()) > 0
	return st
}

// Start uses the installed update, if there is one, it checks and it is
// newer than the packs built into Signalith. A problem with it is logged
// and the built-in packs are used.
func (u *Updater) Start() {
	b, err := Installed(u.Dir, u.keys())
	if err != nil {
		u.log().Error("the installed content update cannot be used; using the rules built into Signalith", "dir", u.Dir, "err", err)
		u.mu.Lock()
		u.status.LastError = "The installed content update cannot be used: " + err.Error()
		u.mu.Unlock()
		return
	}
	if b == nil {
		return
	}
	if b.Manifest.Version < detect.BuiltinContentVersion() {
		u.log().Info("the installed content update is older than the rules built into Signalith, which are used", "update", b.Manifest.Version, "builtin", detect.BuiltinContentVersion())
		return
	}
	if err := u.use(b); err != nil {
		u.log().Error("the installed content update cannot be used; using the rules built into Signalith", "err", err)
		u.mu.Lock()
		u.status.LastError = "The installed content update cannot be used: " + err.Error()
		u.mu.Unlock()
		return
	}
	u.log().Info("content update in use", "version", b.Manifest.Version)
}

// use converts a bundle's packs and puts them in use.
func (u *Updater) use(b *Bundle) error {
	ps, ds, skipped, err := detect.LoadPacks(b.FS)
	if err != nil {
		return err
	}
	if len(ds) == 0 {
		return errors.New("this Signalith can read none of the update's rules")
	}
	detect.UsePacks(ps, ds, b.Manifest.Version)
	if u.Library != nil {
		if err := u.Library.ReloadPacks(); err != nil {
			detect.UsePacks(nil, nil, "")
			_ = u.Library.ReloadPacks()
			return err
		}
	}
	reasons := make([]string, 0, min(len(skipped), 5))
	for _, e := range skipped[:min(len(skipped), 5)] {
		reasons = append(reasons, e.Error())
	}
	u.mu.Lock()
	u.status.Packs = b.Manifest.Packs
	u.status.Skipped = len(skipped)
	u.status.SkippedReasons = reasons
	u.status.LastError = ""
	u.mu.Unlock()
	return nil
}

// Install checks a bundle and its signature and, when it is newer than
// the content in use, keeps it and puts it in use.
func (u *Updater) Install(data, sig []byte) (Status, error) {
	err := u.install(data, sig)
	return u.done(err), err
}

func (u *Updater) install(data, sig []byte) error {
	b, err := Read(u.keys(), data, sig)
	if err != nil {
		return err
	}
	if cur, _ := detect.ContentVersion(); b.Manifest.Version <= cur {
		return ErrNotNewer
	}
	// Convert first, so a bundle this build cannot use is never kept.
	if _, ds, _, err := detect.LoadPacks(b.FS); err != nil {
		return err
	} else if len(ds) == 0 {
		return errors.New("this Signalith can read none of the update's rules")
	}
	if err := Save(u.Dir, b); err != nil {
		return fmt.Errorf("keeping the update: %w", err)
	}
	if err := u.use(b); err != nil {
		return err
	}
	u.log().Info("content update installed", "version", b.Manifest.Version)
	return nil
}

// done records the result of a check or an upload.
func (u *Updater) done(err error) Status {
	u.mu.Lock()
	u.status.LastCheck = time.Now().UTC()
	switch {
	case err == nil:
		u.status.LastResult, u.status.LastError = "installed", ""
	case errors.Is(err, ErrNotNewer):
		u.status.LastResult, u.status.LastError = "up to date", ""
	default:
		u.status.LastResult, u.status.LastError = "failed", err.Error()
	}
	u.mu.Unlock()
	return u.Status()
}

// Check downloads the bundle at url and its signature at url+".sig" and
// installs it when it is newer. An update that is not newer is not an
// error.
func (u *Updater) Check(ctx context.Context, url string) (Status, error) {
	err := u.check(ctx, url)
	st := u.done(err)
	if errors.Is(err, ErrNotNewer) {
		err = nil
	}
	return st, err
}

func (u *Updater) check(ctx context.Context, url string) error {
	if len(u.keys()) == 0 {
		return ErrNoKeys
	}
	sig, err := u.get(ctx, url+".sig", 4096)
	if err != nil {
		return err
	}
	data, err := u.get(ctx, url, MaxBundle)
	if err != nil {
		return err
	}
	return u.install(data, sig)
}

func (u *Updater) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	cl := u.Client
	if cl == nil {
		cl = &http.Client{Timeout: 2 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", hostOf(url), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no content update is published at %s yet (404 Not Found)", hostOf(url))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading %s: the server answered %s", hostOf(url), resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", hostOf(url), err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("downloading %s: the file is too large", hostOf(url))
	}
	return data, nil
}

// hostOf names a URL by its host in messages, leaving out any path or
// query that could hold a secret.
func hostOf(url string) string {
	s := url
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// Remove deletes the installed update and goes back to the packs built
// into Signalith.
func (u *Updater) Remove() (Status, error) {
	if err := Remove(u.Dir); err != nil {
		return u.Status(), err
	}
	detect.UsePacks(nil, nil, "")
	if u.Library != nil {
		if err := u.Library.ReloadPacks(); err != nil {
			return u.Status(), err
		}
	}
	u.mu.Lock()
	u.status.Packs, u.status.Skipped, u.status.SkippedReasons = nil, 0, nil
	u.status.LastError = ""
	u.mu.Unlock()
	return u.Status(), nil
}

// Run checks every day while daily() is true, until ctx ends. The first
// check is a few minutes after start, so a restart loop cannot hammer the
// download.
func (u *Updater) Run(ctx context.Context, daily func() bool, url func() string) {
	wait := 5 * time.Minute
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = 24 * time.Hour
		if !daily() {
			wait = time.Hour // look again whether it was turned on
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		st, err := u.Check(cctx, url())
		cancel()
		if err != nil {
			u.log().Warn("content update check failed; trying again tomorrow", "err", err)
			continue
		}
		u.log().Info("content update check", "result", st.LastResult, "version", st.Version)
	}
}
