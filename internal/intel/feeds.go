package intel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/redact"
)

// Feed is one threat intel feed, from signalith.yaml or added on the
// Threat intel page.
type Feed struct {
	Name        string
	Kind        string // KindURL or KindTAXII; "" is KindURL
	URL         string // the file, or the TAXII API root
	Collection  string // TAXII collection ID
	Format      string
	Type        string
	Column      string
	Interval    time.Duration
	MaxAge      time.Duration
	Weight      float64
	Description string
	Tags        []string
	Headers     map[string]string // may hold API keys; never shown
	Username    string
	Password    string // never shown
	Enabled     bool
	// Source is SourceConfig or SourceUI; "" counts as SourceConfig.
	Source  string
	Catalog string
	// Problem says why a feed from the feeds file cannot run, such as a
	// name that signalith.yaml now uses too.
	Problem string
}

// expand fills ${ENV_VAR} references in a secret. Only feeds from
// signalith.yaml may read the environment: a feed added on the Threat
// intel page could otherwise send the server's own secrets to any URL.
func (fd Feed) expand(v string) string {
	if fd.Source == SourceUI {
		return v
	}
	return ExpandEnv(v)
}

// FeedStatus is what the UI shows about a feed's downloads.
type FeedStatus struct {
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	LastSuccess time.Time `json:"last_success,omitzero"`
	NextRun     time.Time `json:"next_run,omitzero"`
	DurationMS  int64     `json:"duration_ms,omitempty"`
	Count       int       `json:"count"`             // indicators from the last download
	Added       int       `json:"added"`             // new in the last download
	Removed     int       `json:"removed"`           // no longer listed, so removed
	Skipped     int       `json:"skipped,omitempty"` // lines that were not valid indicators
	Example     string    `json:"skipped_example,omitempty"`
	Reserved    int       `json:"reserved,omitempty"` // private or reserved networks skipped
	Note        string    `json:"note,omitempty"`     // such as a TAXII collection read only in part
	// Format and Column are what a feed set to auto was read as at its
	// last download.
	Format    string `json:"format,omitempty"`
	Column    string `json:"column,omitempty"`
	LastError string `json:"last_error,omitempty"`
	Running   bool   `json:"running,omitempty"`
}

// HeaderView names a request header without its value.
type HeaderView struct {
	Name string `json:"name"`
	Set  bool   `json:"set"`
}

// SecretView says whether a secret is stored, never what it is.
type SecretView struct {
	Set bool `json:"set"`
}

// FeedView is a feed and its status, for the API. Secret values are
// never included.
type FeedView struct {
	Name        string       `json:"name"`
	Source      string       `json:"source"` // config or ui
	Kind        string       `json:"kind"`
	URL         string       `json:"url"`
	Collection  string       `json:"collection,omitempty"`
	Format      string       `json:"format"`
	Type        string       `json:"type"`
	Column      string       `json:"column,omitempty"`
	Interval    string       `json:"interval"`
	MaxAge      string       `json:"max_age"`
	Weight      float64      `json:"weight"`
	Description string       `json:"description,omitempty"`
	Tags        []string     `json:"tags,omitempty"`
	Enabled     bool         `json:"enabled"`
	Catalog     string       `json:"catalog,omitempty"`
	Headers     []HeaderView `json:"headers"`
	Username    string       `json:"username,omitempty"`
	Password    SecretView   `json:"password"`
	HasHeaders  bool         `json:"has_headers,omitempty"`
	Problem     string       `json:"problem,omitempty"`
	Indicators  int          `json:"indicators"` // stored now
	Status      FeedStatus   `json:"status"`
}

// Feeds downloads the feeds on their schedules, and keeps the feeds added
// on the Threat intel page. It is safe for concurrent use.
type Feeds struct {
	Store *Store
	// List is the feeds from signalith.yaml, which the page shows but
	// cannot change. Set it before use and do not change it afterwards.
	List []Feed
	// File keeps the feeds added on the Threat intel page; "" keeps them
	// in memory only.
	File string
	// HTTP downloads feeds; nil uses a client that honors HTTPS_PROXY,
	// HTTP_PROXY and NO_PROXY and refuses blocked addresses (see CheckAddr).
	HTTP *http.Client
	// AllowLoopback lets feeds download from this machine.
	AllowLoopback bool
	// Protected lists host:port addresses feeds may never reach, such as
	// Signalith's own OpenSearch (see ProtectedAddr).
	Protected []string
	// MaxBytes caps one download; 0 is MaxDownload.
	MaxBytes int64
	// StatusFile keeps feed status across restarts; "" keeps it in memory.
	StatusFile string
	Log        *slog.Logger
	Now        func() time.Time
	// Tick is how often due feeds are checked (default 30s).
	Tick time.Duration
	// Allowed, when set, says whether this server may still run the feed
	// schedule: with several servers, only the one that runs the
	// background jobs may. It is asked before each scheduled download and
	// each clean-up, so a server that lost that role stops at once.
	Allowed func() bool

	mu       sync.Mutex
	status   map[string]*FeedStatus
	loaded   bool
	ui       []FeedSpec // feeds added on the page, in the order added
	kept     []KeptFeed
	fileRead bool
	fileErr  error
	// gen changes whenever a feed's settings do, so a download that was
	// running meanwhile throws its result away.
	gen    map[string]int
	runCtx context.Context // set while Start runs
	// kicked counts downloads started by kick, which Start waits for.
	kicked sync.WaitGroup
	// storeMu orders storing a download against removing a feed's
	// indicators, so a deleted feed's last download cannot bring them back.
	storeMu    sync.Mutex
	clientOnce sync.Once
	httpc      *http.Client
	// tests holds a slot for each running test or collections lookup.
	testsOnce sync.Once
	tests     chan struct{}
}

// MaxDownload caps a feed download.
const MaxDownload = 256 << 20

// TestMaxDownload caps the download of a feed test; a larger feed is
// previewed from its first part. A test only shows counts and a few
// samples, so it stays small.
const TestMaxDownload = 4 << 20

// MaxTests is how many feed tests and TAXII collection lookups may run at
// once; more are refused with ErrBusy.
const MaxTests = 2

// RetryAfterFailure is how soon a failed download is retried, unless the
// feed's interval is shorter.
const RetryAfterFailure = 15 * time.Minute

// Time limits for a scheduled download and for a test. A TAXII pull has
// TAXIIRunTimeout instead of RunTimeout.
const (
	RunTimeout  = 5 * time.Minute
	TestTimeout = time.Minute
)

func (f *Feeds) allowed() bool { return f.Allowed == nil || f.Allowed() }

func (f *Feeds) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Feeds) log() *slog.Logger {
	if f.Log != nil {
		return f.Log
	}
	return slog.Default()
}

func (f *Feeds) client() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	f.clientOnce.Do(func() { f.httpc = newFeedClient(f.AllowLoopback, f.Protected) })
	return f.httpc
}

func (f *Feeds) maxBytes() int64 {
	if f.MaxBytes > 0 {
		return f.MaxBytes
	}
	return MaxDownload
}

// Load reads the feeds file and the status file. It reports a feeds file
// that cannot be read; until that is fixed, feeds cannot be added or
// changed on the page, so a bad file is never overwritten. A file that
// could not be read is read again on each call, so fixing it takes effect
// without a restart. Feeds load themselves on first use, so calling Load
// is optional.
func (f *Feeds) Load() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loadStatus()
	f.retryFile()
	return f.fileErr
}

func (f *Feeds) loadStatus() {
	if f.loaded {
		return
	}
	f.loaded = true
	if f.status == nil {
		f.status = map[string]*FeedStatus{}
	}
	if f.StatusFile == "" {
		return
	}
	data, err := os.ReadFile(f.StatusFile)
	if err != nil {
		return
	}
	var saved map[string]*FeedStatus
	if json.Unmarshal(data, &saved) == nil {
		for name, st := range saved {
			st.Running = false
			f.status[name] = st
		}
	}
}

// saveStatus writes the status file; the caller holds f.mu.
func (f *Feeds) saveStatus() {
	if f.StatusFile == "" {
		return
	}
	data, err := json.MarshalIndent(f.status, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(f.StatusFile), 0o750); err != nil {
		f.log().Warn("could not save threat intel feed status", "file", f.StatusFile, "err", err)
		return
	}
	if err := replaceFile(f.StatusFile, data); err != nil {
		f.log().Warn("could not save threat intel feed status", "file", f.StatusFile, "err", err)
	}
}

// replaceFile writes data to path through a temporary file of its own
// (a unique name, so two servers or two requests writing the same file
// never write into each other's), then renames it over path. The
// temporary file is removed on any failure. os.Rename replaces an
// existing file on Windows too.
func replaceFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		// CreateTemp makes the file readable by its owner only; on Windows
		// Chmod only sets or clears read-only, which is fine.
		err = os.Chmod(name, 0o640)
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		_ = os.Remove(name)
	}
	return err
}

// stateFor returns a feed's status; the caller holds f.mu.
func (f *Feeds) stateFor(name string) *FeedStatus {
	f.loadStatus()
	st, ok := f.status[name]
	if !ok {
		st = &FeedStatus{}
		f.status[name] = st
	}
	return st
}

// all returns every feed: those from signalith.yaml, then those added on
// the page. The caller holds f.mu.
func (f *Feeds) all() []Feed {
	f.loadFile()
	out := make([]Feed, 0, len(f.List)+len(f.ui))
	inConfig := map[string]bool{}
	for _, fd := range f.List {
		if fd.Source == "" {
			fd.Source = SourceConfig
		}
		if fd.Kind == "" {
			fd.Kind = KindURL
		}
		inConfig[fd.Name] = true
		out = append(out, fd)
	}
	seen := map[string]bool{}
	for _, s := range f.ui {
		s.Defaults()
		var probs []string
		switch {
		case inConfig[s.Name]:
			probs = append(probs, "A feed in signalith.yaml has the same name, so this one is not used; delete it and add it again with another name")
		case seen[s.Name]:
			probs = append(probs, "Another feed has the same name")
		}
		seen[s.Name] = true
		for _, p := range s.Problems(false) {
			probs = append(probs, p.Msg)
		}
		if locked := s.undecrypted(); len(locked) > 0 {
			probs = append(probs, fmt.Sprintf("The saved %s cannot be decrypted with this server's master key, so the feed is not downloaded; edit the feed and enter the value again, or restore the master key it was saved with", strings.Join(locked, " and ")))
		}
		fd := s.Feed(SourceUI)
		fd.Problem = strings.Join(probs, "; ")
		out = append(out, fd)
	}
	return out
}

// get finds a feed by name; the caller holds f.mu. A feed from
// signalith.yaml wins over one added on the page with the same name.
func (f *Feeds) get(name string) (Feed, bool) {
	for _, fd := range f.all() {
		if fd.Name == name {
			return fd, true
		}
	}
	return Feed{}, false
}

// Get returns a feed by name.
func (f *Feeds) Get(name string) (Feed, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.get(name)
}

// Len returns how many feeds there are.
func (f *Feeds) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.all())
}

// Status returns every feed with its status.
func (f *Feeds) Status() []FeedView {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := f.all()
	out := make([]FeedView, 0, len(list))
	for _, fd := range list {
		out = append(out, f.view(fd))
	}
	return out
}

// View returns one feed with its status.
func (f *Feeds) View(name string) (FeedView, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fd, ok := f.get(name)
	if !ok {
		return FeedView{}, false
	}
	return f.view(fd), true
}

// view describes a feed without its secrets; the caller holds f.mu.
func (f *Feeds) view(fd Feed) FeedView {
	kind := fd.Kind
	if kind == "" {
		kind = KindURL
	}
	v := FeedView{
		Name: fd.Name, Source: fd.Source, Kind: kind, URL: fd.URL, Collection: fd.Collection,
		Format: fd.Format, Type: fd.Type, Column: fd.Column, Interval: fmtDuration(fd.Interval), MaxAge: fmtDuration(fd.MaxAge),
		Weight: fd.Weight, Description: fd.Description, Tags: fd.Tags, Enabled: fd.Enabled, Catalog: fd.Catalog,
		Headers: []HeaderView{}, Username: fd.Username, Password: SecretView{Set: fd.Password != ""},
		HasHeaders: len(fd.Headers) > 0, Problem: fd.Problem,
	}
	if v.Source == "" {
		v.Source = SourceConfig
	}
	for k, val := range fd.Headers {
		v.Headers = append(v.Headers, HeaderView{Name: k, Set: val != ""})
	}
	sort.Slice(v.Headers, func(i, j int) bool { return v.Headers[i].Name < v.Headers[j].Name })
	if fd.Problem == "" {
		v.Status = *f.stateFor(fd.Name)
		if f.Store != nil {
			v.Indicators = f.Store.CountSource(fd.Name)
		}
	}
	return v
}

func fmtDuration(d time.Duration) string {
	switch {
	case d == 0:
		return ""
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	return fmt.Sprintf("%dm", d/time.Minute)
}

// Start downloads due feeds, removes indicators of feeds that are no
// longer configured, and purges expired indicators, until ctx ends.
// Feeds added or changed on the page meanwhile download at once. Run it
// on one server only: the one that runs the background jobs.
func (f *Feeds) Start(ctx context.Context) {
	// Feeds replace what they stored before, so the current indicators
	// must be known first.
	for !f.Store.Loaded() {
		err := f.Store.Load(ctx)
		if err == nil {
			break
		}
		f.log().Warn("waiting to read threat intel indicators before downloading feeds", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
	f.mu.Lock()
	f.runCtx = ctx
	var keep []string
	for _, fd := range f.all() {
		if fd.Enabled {
			keep = append(keep, fd.Name)
		}
	}
	now := f.now()
	for _, k := range f.kept {
		if k.Until.After(now) {
			keep = append(keep, k.Name)
		}
	}
	// Without the feeds file, its feeds' indicators cannot be told apart
	// from those of deleted feeds, so nothing is removed.
	fileOK := f.fileErr == nil
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.runCtx = nil
		f.mu.Unlock()
		// Downloads of feeds just added or changed end with the run, so a
		// server that stops running the schedule stores nothing after.
		f.kicked.Wait()
	}()
	if fileOK && f.allowed() {
		f.storeMu.Lock()
		n, err := f.Store.RemoveSources(ctx, keep)
		f.storeMu.Unlock()
		if err != nil {
			f.log().Warn("could not remove indicators of removed or disabled feeds", "err", err)
		} else if n > 0 {
			f.log().Info("removed indicators of feeds that are no longer configured or are disabled", "indicators", n)
		}
	}
	tick := f.Tick
	if tick <= 0 {
		tick = 30 * time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	lastPurge := time.Time{}
	for {
		f.RunDue(ctx)
		if f.now().Sub(lastPurge) >= time.Hour && f.allowed() {
			lastPurge = f.now()
			if n, err := f.Store.Purge(ctx); err != nil {
				f.log().Warn("could not purge expired indicators", "err", err)
			} else if n > 0 {
				f.log().Info("expired threat intel indicators removed", "indicators", n)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunDue downloads every enabled feed whose next run has passed.
func (f *Feeds) RunDue(ctx context.Context) {
	now := f.now()
	var due []string
	f.mu.Lock()
	for _, fd := range f.all() {
		if !fd.Enabled || fd.Problem != "" {
			continue
		}
		st := f.stateFor(fd.Name)
		if st.Running {
			continue
		}
		if st.NextRun.IsZero() && !st.LastAttempt.IsZero() {
			st.NextRun = st.LastAttempt.Add(fd.Interval)
		}
		if st.NextRun.IsZero() || !now.Before(st.NextRun) {
			due = append(due, fd.Name)
		}
	}
	f.mu.Unlock()
	sort.Strings(due)
	for _, name := range due {
		if ctx.Err() != nil {
			return
		}
		f.refreshAndLog(ctx, name)
	}
}

// refreshAndLog downloads a feed on the schedule.
func (f *Feeds) refreshAndLog(ctx context.Context, name string) {
	if !f.allowed() {
		return
	}
	_, err := f.Refresh(ctx, name)
	if err != nil && !errors.Is(err, ErrFeedRunning) && !errors.Is(err, ErrFeedChanged) && !errors.Is(err, ErrUnknownFeed) && !errors.Is(err, ErrFeedOff) {
		f.log().Warn("threat intel feed download failed", "feed", name, "err", err)
	}
}

// kick downloads a feed that was just added or changed, when this server
// runs the schedule. The caller holds f.mu.
func (f *Feeds) kick(name string) {
	if f.runCtx == nil {
		return
	}
	ctx := f.runCtx
	f.kicked.Go(func() { f.refreshAndLog(ctx, name) })
}

// Fingerprint is a hash of every feed's settings, without secrets, so
// servers that share one OpenSearch can tell whether their feed lists
// differ. Any change to a feed, adding or removing one, or a feeds file
// that cannot be read changes it.
func (f *Feeds) Fingerprint() string {
	f.mu.Lock()
	list := f.all()
	fileErr := f.fileErr
	f.mu.Unlock()
	type part struct {
		Name, Kind, URL, Collection, Format, Type, Column string
		Interval, MaxAge                                  time.Duration
		Weight                                            float64
		Tags, Headers                                     []string
		Username                                          bool
		Enabled                                           bool
		Source, Problem                                   string
	}
	parts := make([]part, 0, len(list))
	for _, fd := range list {
		var headers []string
		for k := range fd.Headers {
			headers = append(headers, strings.ToLower(k))
		}
		sort.Strings(headers)
		parts = append(parts, part{Name: fd.Name, Kind: fd.Kind, URL: redact.URL(fd.URL), Collection: fd.Collection,
			Format: fd.Format, Type: fd.Type, Column: fd.Column, Interval: fd.Interval, MaxAge: fd.MaxAge, Weight: fd.Weight,
			Tags: fd.Tags, Headers: headers, Username: fd.Username != "", Enabled: fd.Enabled, Source: fd.Source, Problem: fd.Problem})
	}
	sort.SliceStable(parts, func(i, j int) bool { return parts[i].Name < parts[j].Name })
	b, _ := json.Marshal(map[string]any{"feeds": parts, "file_ok": fileErr == nil})
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Running reports whether this server downloads feeds on their schedules.
func (f *Feeds) Running() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runCtx != nil
}

// ErrUnknownFeed is returned for a feed name that is not configured.
var ErrUnknownFeed = errors.New("no feed with that name is configured")

// ErrFeedRunning is returned when a feed is already downloading.
var ErrFeedRunning = errors.New("this feed is already downloading")

// ErrFeedChanged is returned when a feed's settings changed while it
// downloaded; the result is thrown away and the feed downloads again.
var ErrFeedChanged = errors.New("the feed's settings changed while it downloaded, so it will download again shortly")

// ErrFeedOff is returned for a download of a feed that is turned off.
var ErrFeedOff = errors.New("this feed is turned off; turn it on to download it")

// Refresh downloads one feed now and replaces its indicators.
func (f *Feeds) Refresh(ctx context.Context, name string) (FeedStatus, error) {
	f.mu.Lock()
	fd, ok := f.get(name)
	if !ok {
		f.mu.Unlock()
		return FeedStatus{}, ErrUnknownFeed
	}
	if fd.Problem != "" {
		f.mu.Unlock()
		return FeedStatus{}, errors.New(fd.Problem)
	}
	if !fd.Enabled {
		f.mu.Unlock()
		return FeedStatus{}, ErrFeedOff
	}
	st := f.stateFor(name)
	if st.Running {
		// Copy the status while still holding the lock: the download that
		// is running updates it under the lock.
		cur := *st
		f.mu.Unlock()
		return cur, ErrFeedRunning
	}
	st.Running = true
	gen := f.gen[name]
	f.mu.Unlock()

	start := f.now()
	got, added, removed, err := f.download(ctx, fd, start, gen)

	f.mu.Lock()
	defer f.mu.Unlock()
	if _, still := f.get(name); !still {
		delete(f.status, name) // deleted while it downloaded
		return FeedStatus{}, ErrUnknownFeed
	}
	st = f.stateFor(name)
	st.Running = false
	if errors.Is(err, ErrFeedOff) {
		return *st, ErrFeedOff // turned off while it downloaded
	}
	if errors.Is(err, ErrFeedChanged) || f.gen[name] != gen {
		st.NextRun = time.Time{} // download again with the new settings
		return *st, ErrFeedChanged
	}
	st.LastAttempt = start
	st.DurationMS = f.now().Sub(start).Milliseconds()
	if err != nil {
		st.LastError = err.Error()
		st.NextRun = start.Add(min(fd.Interval, RetryAfterFailure))
		f.saveStatus()
		return *st, err
	}
	res := got.Result
	st.LastError = ""
	st.LastSuccess = start
	st.NextRun = start.Add(fd.Interval)
	st.Count, st.Added, st.Removed = len(res.Indicators), added, removed
	st.Skipped, st.Example, st.Reserved, st.Note = res.Skipped, res.Example, res.Reserved, got.Note
	st.Format, st.Column = "", ""
	if fd.Format == FormatAuto {
		st.Format, st.Column = res.Format, res.Column
	}
	f.saveStatus()
	f.log().Info("threat intel feed downloaded", "feed", name, "indicators", st.Count, "added", added, "removed", removed, "skipped", res.Skipped)
	return *st, nil
}

// download fetches a feed and stores its indicators, unless the feed
// changed (gen) or was turned off meanwhile. Errors are in plain words
// without secrets.
func (f *Feeds) download(ctx context.Context, fd Feed, now time.Time, gen int) (*fetched, int, int, error) {
	timeout := RunTimeout
	if fd.Kind == KindTAXII {
		timeout = TAXIIRunTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	got, err := f.fetch(ctx, fd, now, fetchLimits{MaxBytes: f.maxBytes(), Refuse: f.maxBytes(), Timeout: timeout})
	if err != nil {
		if fd.Kind == KindTAXII {
			timeout = taxiiPageTimeout // the first page timed out
		}
		return nil, 0, 0, errors.New(describe(err, fd, timeout))
	}
	res := got.Result
	if len(res.Indicators) == 0 {
		// The indicators from before stay; the page says so.
		return nil, 0, 0, errors.New(emptyMessage(got))
	}
	expires := now.Add(fd.MaxAge)
	for i := range res.Indicators {
		ind := &res.Indicators[i]
		ind.Weight = fd.Weight
		if ind.Description == "" {
			ind.Description = fd.Description
		}
		ind.Tags = mergeTags(fd.Tags, ind.Tags)
		// A feed that stops updating ages out after max_age.
		if ind.Expires.IsZero() || ind.Expires.After(expires) {
			ind.Expires = expires
		}
	}
	f.storeMu.Lock()
	defer f.storeMu.Unlock()
	f.mu.Lock()
	cur, ok := f.get(fd.Name)
	changed := f.gen[fd.Name] != gen
	f.mu.Unlock()
	switch {
	case changed:
		return nil, 0, 0, ErrFeedChanged
	case !ok || !cur.Enabled:
		return nil, 0, 0, ErrFeedOff // turned off (or deleted) meanwhile
	}
	if got.Incomplete {
		added, err := f.Store.MergeSource(ctx, fd.Name, res.Indicators)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("could not store indicators: %w", err)
		}
		return got, added, 0, nil
	}
	added, removed, err := f.Store.ReplaceSource(ctx, fd.Name, res.Indicators)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("could not store indicators: %w", err)
	}
	return got, added, removed, nil
}

func mergeTags(a, b []string) []string {
	var out []string
	for _, t := range append(append([]string{}, a...), b...) {
		dup := false
		for _, o := range out {
			if strings.EqualFold(o, t) {
				dup = true
				break
			}
		}
		if !dup && t != "" {
			out = append(out, t)
		}
	}
	return out
}

// lookupEnv reads an environment variable.
var lookupEnv = os.Getenv

// ExpandEnv replaces ${NAME} with the environment variable NAME, so API
// keys for feeds can stay out of the config file. Other $ signs are kept.
func ExpandEnv(v string) string {
	var b strings.Builder
	for {
		i := strings.Index(v, "${")
		if i < 0 {
			b.WriteString(v)
			return b.String()
		}
		j := strings.Index(v[i:], "}")
		if j < 0 {
			b.WriteString(v)
			return b.String()
		}
		b.WriteString(v[:i])
		b.WriteString(lookupEnv(v[i+2 : i+j]))
		v = v[i+j+1:]
	}
}

// EnvRefs returns the variable names ${NAME} references in v.
func EnvRefs(v string) []string {
	var out []string
	for {
		i := strings.Index(v, "${")
		if i < 0 {
			return out
		}
		j := strings.Index(v[i:], "}")
		if j < 0 {
			return out
		}
		out = append(out, v[i+2:i+j])
		v = v[i+j+1:]
	}
}

// Watch keeps the in-memory indicators in step with the backend, for
// changes made by another server, until ctx ends. Every server runs it.
func (s *Store) Watch(ctx context.Context, every time.Duration, log *slog.Logger) {
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if reloaded, err := s.Sync(ctx); err != nil {
			if log != nil {
				log.Warn("could not read threat intel indicators", "err", err)
			}
		} else if reloaded && log != nil {
			log.Info("threat intel indicators loaded", "indicators", s.Summary().Total)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
