package intel

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// looksEncrypted is the problem with a typed value that starts like an
// encrypted one (enc:v1:...): it would be stored as it is, not encrypted.
const looksEncrypted = "cannot start with enc:v and a number and a colon, which is how encrypted values look"

// FeedInput is a feed as the Threat intel page sends it. Secrets are
// write-only: they are never sent back, and an empty value keeps the
// stored one.
type FeedInput struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"` // url (default) or taxii
	URL         string   `json:"url"`
	Collection  string   `json:"collection"`
	Format      string   `json:"format"` // default auto
	Type        string   `json:"type"`
	Column      string   `json:"column"`
	Interval    string   `json:"interval"`
	MaxAge      string   `json:"max_age"`
	Weight      float64  `json:"weight"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Enabled     *bool    `json:"enabled"`
	// Catalog adds a feed from the built-in catalog: settings left empty
	// come from the entry.
	Catalog string `json:"catalog"`
	// Headers set, keep or clear request headers. One with a value sets
	// it, one without keeps the stored value, and one with clear removes
	// it. Stored headers that are not listed are kept.
	Headers  []HeaderInput `json:"headers"`
	Username string        `json:"username"`
	// Password sets the password; empty keeps the stored one, and
	// ClearPassword removes it.
	Password      string `json:"password"`
	ClearPassword bool   `json:"clear_password"`
}

// HeaderInput sets, keeps or clears one request header.
type HeaderInput struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	Clear bool   `json:"clear,omitempty"`
}

// InputError lists the settings to fix.
type InputError struct{ Problems []FeedProblem }

func (e *InputError) Error() string {
	return "Please fix these settings: " + strings.Join(e.Messages(), "; ")
}

// Messages returns each problem's message.
func (e *InputError) Messages() []string {
	out := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		out[i] = p.Msg
	}
	return out
}

// Fields maps each setting to its first problem, so a form can mark it.
func (e *InputError) Fields() map[string]string {
	out := map[string]string{}
	for _, p := range e.Problems {
		if _, ok := out[p.Field]; !ok && p.Field != "" {
			out[p.Field] = p.Msg
		}
	}
	return out
}

// ErrReadOnly is returned for changes to a feed from signalith.yaml.
var ErrReadOnly = errors.New("this feed is set in signalith.yaml, so it can only be changed there; edit the file and restart Signalith")

// ErrFeedStale is a change of a feed that someone else changed since the
// page read it.
var ErrFeedStale = errors.New("this feed was changed by someone else since the page read it; reload the page and make the change again")

// specETag is the version of a feed's settings, for a page that changes
// it only if nobody else did meanwhile. It covers the feed's secrets, so
// re-entering one changes it, and is therefore keyed (see etagKey): a
// plain hash would let anyone who sees it test guesses of a password or
// API key.
func specETag(key []byte, s FeedSpec) string {
	s.From = ""
	b, _ := json.Marshal(s)
	h := hmac.New(sha256.New, key)
	h.Write([]byte("sgl-feed-etag-v1\x00"))
	h.Write(b)
	return `"f-` + hex.EncodeToString(h.Sum(nil)[:12]) + `"`
}

// ETagKeyer is a FeedList whose feeds' versions are keyed with a key
// every server that shares the list has, so a version read from one
// server holds on another.
type ETagKeyer interface {
	ETagKey() []byte
}

// etagKey is the key of the feeds' versions: the shared list's, or else
// one made for this process, as only this server reads its own file.
func (f *Feeds) etagKey() []byte {
	if k, ok := f.Saved.(ETagKeyer); ok {
		if b := k.ETagKey(); len(b) > 0 {
			return b
		}
	}
	f.etagOnce.Do(func() {
		f.localETag = make([]byte, 32)
		_, _ = rand.Read(f.localETag)
	})
	return f.localETag
}

// ETag returns the version of a feed added on the page or shared (see
// specETag); false for a feed in signalith.yaml or none.
func (f *Feeds) ETag(name string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loadList()
	if i := specIndex(f.ui, name); i >= 0 {
		return specETag(f.etagKey(), f.ui[i]), true
	}
	return "", false
}

// InputFor returns an existing feed's settings, without its secrets, for
// a change or a test to start from.
func (f *Feeds) InputFor(name string) (FeedInput, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fd, ok := f.get(name)
	if !ok {
		return FeedInput{}, false
	}
	on := fd.Enabled
	return FeedInput{
		Name: fd.Name, Kind: fd.Kind, URL: fd.URL, Collection: fd.Collection, Format: fd.Format, Type: fd.Type,
		Column: fd.Column, Interval: fmtDuration(fd.Interval), MaxAge: fmtDuration(fd.MaxAge), Weight: fd.Weight,
		Description: fd.Description, Tags: slices.Clone(fd.Tags), Enabled: &on, Catalog: fd.Catalog, Username: fd.Username,
	}, true
}

// spec turns input into settings, merging secrets with the old feed's.
func (in FeedInput) spec(old *Feed) (FeedSpec, []FeedProblem) {
	var probs []FeedProblem
	low := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	s := FeedSpec{
		Name: strings.TrimSpace(in.Name), Kind: low(in.Kind), URL: strings.TrimSpace(in.URL),
		Collection: strings.TrimSpace(in.Collection), Format: low(in.Format), Type: low(in.Type),
		Column: strings.TrimSpace(in.Column), Interval: low(in.Interval), MaxAge: low(in.MaxAge),
		Weight: in.Weight, Description: strings.TrimSpace(in.Description), Username: strings.TrimSpace(in.Username),
		Catalog: strings.TrimSpace(in.Catalog),
	}
	on := in.Enabled == nil || *in.Enabled
	s.Enabled = &on
	for _, t := range in.Tags {
		if t = strings.TrimSpace(t); t != "" && !slices.ContainsFunc(s.Tags, func(o string) bool { return strings.EqualFold(o, t) }) {
			s.Tags = append(s.Tags, t)
		}
	}
	// Saved secrets are only sent to the server they were entered for: when
	// the URL points elsewhere, each must be entered again or cleared.
	moved := old != nil && !sameServer(old.URL, s.URL)
	headers := map[string]string{}
	if old != nil {
		for k, v := range old.Headers {
			headers[k] = v
		}
	}
	stored := func(name string) string {
		for k := range headers {
			if strings.EqualFold(k, name) {
				return k
			}
		}
		return ""
	}
	entered := map[string]bool{}
	for _, h := range in.Headers {
		name, value := strings.TrimSpace(h.Name), strings.TrimSpace(h.Value)
		have := stored(name)
		switch {
		case name == "":
			if value != "" {
				probs = append(probs, FeedProblem{Field: "headers", Msg: "a header with a value needs a name"})
			}
		case h.Clear:
			delete(headers, have)
		case secrets.IsSealed(value):
			probs = append(probs, FeedProblem{Field: "headers", Msg: fmt.Sprintf("the value of header %s %s", name, looksEncrypted)})
		case value != "":
			delete(headers, have)
			headers[name] = value
			entered[strings.ToLower(name)] = true
		case have == "":
			probs = append(probs, FeedProblem{Field: "headers", Msg: fmt.Sprintf("enter a value for header %s", name)})
		}
	}
	if moved {
		var again []string
		for k := range headers {
			if !entered[strings.ToLower(k)] {
				again = append(again, k)
				delete(headers, k)
			}
		}
		slices.Sort(again)
		for _, k := range again {
			probs = append(probs, FeedProblem{Field: "headers", Msg: fmt.Sprintf("enter the value of header %s again, or remove it: the URL now points to another server, and saved values are only sent to the server they were entered for", k)})
		}
	}
	if len(headers) > 0 {
		s.Headers = headers
	}
	switch {
	case secrets.IsSealed(in.Password):
		probs = append(probs, FeedProblem{Field: "password", Msg: "the password " + looksEncrypted})
	case in.Password != "":
		s.Password = in.Password
	case in.ClearPassword || s.Username == "" || old == nil || old.Password == "":
	case moved:
		probs = append(probs, FeedProblem{Field: "password", Msg: "enter the password again for the new server, or clear it: a saved password is only sent to the server it was entered for"})
	default:
		s.Password = old.Password
	}
	s.Defaults()
	return s, append(probs, s.Problems(false)...)
}

// fillFromCatalog fills empty settings from the catalog entry.
func (in *FeedInput) fillFromCatalog() []FeedProblem {
	e, ok := CatalogByID(strings.TrimSpace(in.Catalog))
	if !ok {
		return []FeedProblem{{Field: "catalog", Msg: fmt.Sprintf("there is no catalog feed %q", in.Catalog)}}
	}
	set := func(dst *string, v string) {
		if strings.TrimSpace(*dst) == "" {
			*dst = v
		}
	}
	set(&in.Name, e.ID)
	set(&in.Kind, KindURL)
	set(&in.URL, e.URL)
	if strings.TrimSpace(in.Format) == "" || in.Format == FormatAuto {
		in.Format = e.Format
	}
	set(&in.Type, e.Type)
	set(&in.Column, e.Column)
	set(&in.Interval, e.Interval)
	set(&in.MaxAge, e.MaxAge)
	set(&in.Description, e.Description)
	if in.Weight == 0 {
		in.Weight = e.Weight
	}
	if in.Tags == nil {
		in.Tags = append([]string{}, e.Tags...)
	}
	if e.NeedsKey && !slices.ContainsFunc(in.Headers, func(h HeaderInput) bool { return strings.EqualFold(h.Name, e.KeyHeader) && h.Value != "" }) {
		return []FeedProblem{{Field: "headers", Msg: fmt.Sprintf("%s needs an API key in the %s header. %s", e.Title, e.KeyHeader, e.KeyHelp)}}
	}
	return nil
}

// freeName returns base, or base-2, base-3 and so on when a feed of all
// (or one of taken) already has that name.
func freeName(all []Feed, base string, taken ...string) string {
	used := map[string]bool{}
	for _, fd := range all {
		used[fd.Name] = true
	}
	for _, n := range taken {
		used[n] = true
	}
	if !used[base] {
		return base
	}
	for i := 2; ; i++ {
		if n := fmt.Sprintf("%s-%d", base, i); !used[n] {
			return n
		}
	}
}

// nameProblems checks that a new feed's name is free among all.
func nameProblems(all []Feed, name string) []FeedProblem {
	for _, fd := range all {
		if fd.Name != name {
			continue
		}
		if fd.Source == SourceUI {
			return []FeedProblem{{Field: "name", Msg: fmt.Sprintf("a feed named %s already exists; choose another name", name)}}
		}
		return []FeedProblem{{Field: "name", Msg: fmt.Sprintf("a feed in signalith.yaml is already named %s; choose another name", name)}}
	}
	return nil
}

func (f *Feeds) inConfig(name string) bool {
	for _, fd := range f.List {
		if fd.Name == name {
			return true
		}
	}
	return false
}

func specIndex(list []FeedSpec, name string) int {
	return slices.IndexFunc(list, func(s FeedSpec) bool { return s.Name == name })
}

func cloneSpecs(list []FeedSpec) []FeedSpec {
	out := make([]FeedSpec, len(list), len(list)+1)
	for i, s := range list {
		out[i] = s.clone()
	}
	return out
}

func withoutKept(list []KeptFeed, name string) []KeptFeed {
	var out []KeptFeed
	for _, k := range list {
		if k.Name != name {
			out = append(out, k)
		}
	}
	return out
}

// changed records a new or changed feed and downloads it when this
// server runs the schedule; the caller holds f.mu.
func (f *Feeds) changed(name string, enabled bool) {
	f.gen[name]++
	st := f.stateFor(name)
	st.NextRun = time.Time{}
	f.saveStatus(name)
	if enabled {
		f.kick(name)
	}
}

// saved returns a feed as it is now, after a change was saved; the
// caller holds f.mu.
func (f *Feeds) saved(spec FeedSpec) FeedView {
	if fd, ok := f.get(spec.Name); ok {
		return f.view(fd)
	}
	return f.view(spec.Feed(SourceUI))
}

// prime reads the feeds before a change, so the change is told apart
// from what was there.
func (f *Feeds) prime() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loadList()
}

// afterSave takes a change just saved into use; the caller holds f.mu.
func (f *Feeds) afterSave() {
	f.listDirty.Store(true)
	f.loadList()
}

// AddFeed saves a new feed and downloads it at once (on the server that
// runs the schedule).
func (f *Feeds) AddFeed(in FeedInput) (FeedView, error) {
	return f.AddFeedAs(context.Background(), "", in)
}

// AddFeedAs is AddFeed by the user by.
func (f *Feeds) AddFeedAs(ctx context.Context, by string, in FeedInput) (FeedView, error) {
	f.prime()
	var first []FeedProblem
	// A catalog feed is named after its entry, or after it with a number
	// when a feed already has that name.
	pickName := strings.TrimSpace(in.Catalog) != "" && strings.TrimSpace(in.Name) == ""
	if strings.TrimSpace(in.Catalog) != "" {
		first = in.fillFromCatalog()
	}
	if low := strings.ToLower(strings.TrimSpace(in.Kind)); low != KindTAXII && strings.TrimSpace(in.Format) == "" {
		in.Format = FormatAuto
	}
	var spec FeedSpec
	_, err := f.list().Mutate(ctx, by, func(set *FeedSet) error {
		all := f.feedsOf(set.UI)
		in := in
		if pickName {
			in.Name = freeName(all, in.Name)
		}
		sp, p := in.spec(nil)
		probs := append(slices.Clone(first), p...)
		if feedNamePattern.MatchString(sp.Name) {
			probs = append(probs, nameProblems(all, sp.Name)...)
		}
		if len(probs) > 0 {
			return &InputError{Problems: probs}
		}
		set.UI = append(set.UI, sp)
		set.Kept = withoutKept(set.Kept, sp.Name)
		spec = sp
		return nil
	})
	if err != nil {
		return FeedView{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.afterSave()
	return f.saved(spec), nil
}

// UpdateFeed changes a feed added on the page. Start from InputFor so
// settings the request leaves out stay as they are. A feed that is turned
// off loses its indicators; any other change downloads it again at once.
func (f *Feeds) UpdateFeed(ctx context.Context, name string, in FeedInput) (FeedView, error) {
	return f.UpdateFeedAs(ctx, "", name, in)
}

// UpdateFeedAs is UpdateFeed by the user by.
func (f *Feeds) UpdateFeedAs(ctx context.Context, by, name string, in FeedInput) (FeedView, error) {
	return f.UpdateFeedIf(ctx, by, name, "", in)
}

// UpdateFeedIf is UpdateFeedAs, refused with ErrFeedStale when etag is
// set and the feed is no longer the version it names (see ETag).
func (f *Feeds) UpdateFeedIf(ctx context.Context, by, name, etag string, in FeedInput) (FeedView, error) {
	f.prime()
	if f.inConfig(name) {
		return FeedView{}, ErrReadOnly
	}
	var old Feed
	var spec FeedSpec
	_, err := f.list().Mutate(ctx, by, func(set *FeedSet) error {
		i := specIndex(set.UI, name)
		if i < 0 {
			return ErrUnknownFeed
		}
		if etag != "" && specETag(f.etagKey(), set.UI[i]) != etag {
			return ErrFeedStale
		}
		old = set.UI[i].Feed(SourceUI)
		var probs []FeedProblem
		if n := strings.TrimSpace(in.Name); n != "" && n != name {
			probs = append(probs, FeedProblem{Field: "name", Msg: "a feed's name cannot be changed; add a new feed with the new name instead"})
		}
		in := in
		in.Name = name
		if low := strings.ToLower(strings.TrimSpace(in.Kind)); low != KindTAXII && strings.TrimSpace(in.Format) == "" {
			in.Format = FormatAuto
		}
		sp, p := in.spec(&old)
		if probs = append(probs, p...); len(probs) > 0 {
			return &InputError{Problems: probs}
		}
		set.UI[i] = sp
		spec = sp
		return nil
	})
	if err != nil {
		return FeedView{}, err
	}
	f.mu.Lock()
	f.afterSave()
	view := f.saved(spec)
	f.mu.Unlock()
	if old.Enabled && !spec.IsEnabled() {
		f.storeMu.Lock()
		_, err := f.Store.DeleteSource(ctx, name)
		f.storeMu.Unlock()
		if err != nil {
			f.log().Warn("could not remove the indicators of a feed that was turned off; they are removed at the next restart", "feed", name, "err", err)
		} else {
			view.Indicators = 0
		}
	}
	return view, nil
}

// RemoveFeed deletes a feed added on the page. With removeIndicators its
// indicators go at once; otherwise they stay until they expire (the
// feed's max_age after its last download).
func (f *Feeds) RemoveFeed(ctx context.Context, name string, removeIndicators bool) (int, error) {
	return f.RemoveFeedAs(ctx, "", name, removeIndicators)
}

// RemoveFeedAs is RemoveFeed by the user by.
func (f *Feeds) RemoveFeedAs(ctx context.Context, by, name string, removeIndicators bool) (int, error) {
	return f.RemoveFeedIf(ctx, by, name, "", removeIndicators)
}

// RemoveFeedIf is RemoveFeedAs, refused with ErrFeedStale when etag is
// set and the feed is no longer the version it names (see ETag).
func (f *Feeds) RemoveFeedIf(ctx context.Context, by, name, etag string, removeIndicators bool) (int, error) {
	f.prime()
	// A feed in signalith.yaml with the same name owns the indicators and
	// the status; deleting the duplicate leaves them alone.
	shadowed := f.inConfig(name)
	_, err := f.list().Mutate(ctx, by, func(set *FeedSet) error {
		i := specIndex(set.UI, name)
		if i < 0 {
			if shadowed {
				return ErrReadOnly
			}
			return ErrUnknownFeed
		}
		if etag != "" && specETag(f.etagKey(), set.UI[i]) != etag {
			return ErrFeedStale
		}
		old := set.UI[i].Feed(SourceUI)
		set.UI = slices.Delete(set.UI, i, i+1)
		set.Kept = withoutKept(set.Kept, name)
		if !removeIndicators && !shadowed {
			set.Kept = append(set.Kept, KeptFeed{Name: name, Until: f.now().Add(old.MaxAge).UTC()})
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	f.mu.Lock()
	f.afterSave()
	f.mu.Unlock()
	if shadowed || !removeIndicators {
		return 0, nil
	}
	f.storeMu.Lock()
	defer f.storeMu.Unlock()
	return f.Store.DeleteSource(ctx, name)
}

// CatalogSkip is a catalog feed that was not added, and why.
type CatalogSkip struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// errNothingAdded ends a catalog change that adds nothing, without a
// write.
var errNothingAdded = errors.New("nothing to add")

// AddCatalog adds catalog feeds with their suggested settings, skipping
// ones already added and ones that need an API key.
func (f *Feeds) AddCatalog(req []string) ([]FeedView, []CatalogSkip, error) {
	return f.AddCatalogAs(context.Background(), "", req)
}

// AddCatalogAs is AddCatalog by the user by.
func (f *Feeds) AddCatalogAs(ctx context.Context, by string, req []string) ([]FeedView, []CatalogSkip, error) {
	f.prime()
	var names []string
	var skipped []CatalogSkip
	_, err := f.list().Mutate(ctx, by, func(set *FeedSet) error {
		views := catalogViews(f.feedsOf(set.UI))
		var ids []string
		names, skipped = nil, []CatalogSkip{}
		for _, id := range req {
			i := slices.IndexFunc(views, func(v CatalogView) bool { return v.ID == id })
			switch {
			case i < 0:
				skipped = append(skipped, CatalogSkip{ID: id, Reason: "There is no catalog feed with this ID."})
				continue
			case views[i].Added || slices.Contains(ids, id):
				skipped = append(skipped, CatalogSkip{ID: id, Reason: "Already added."})
				continue
			case views[i].NeedsKey:
				skipped = append(skipped, CatalogSkip{ID: id, Reason: "Needs an API key; add it on its own."})
				continue
			}
			spec := views[i].Spec()
			all := f.feedsOf(set.UI)
			spec.Name = freeName(all, spec.Name, names...)
			spec.Defaults()
			if p := append(spec.Problems(false), nameProblems(all, spec.Name)...); len(p) > 0 {
				skipped = append(skipped, CatalogSkip{ID: id, Reason: sentence(p[0].Msg)})
				continue
			}
			set.UI = append(set.UI, spec)
			set.Kept = withoutKept(set.Kept, spec.Name)
			ids = append(ids, id)
			names = append(names, spec.Name)
		}
		if len(names) == 0 {
			return errNothingAdded
		}
		return nil
	})
	if errors.Is(err, errNothingAdded) {
		return []FeedView{}, skipped, nil
	}
	if err != nil {
		return nil, nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.afterSave()
	added := make([]FeedView, 0, len(names))
	for _, n := range names {
		if fd, ok := f.get(n); ok {
			added = append(added, f.view(fd))
		}
	}
	return added, skipped, nil
}

// Sample is one indicator a test found.
type Sample struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

// TestResult is what a feed test found, without storing anything.
type TestResult struct {
	OK bool `json:"ok"`
	// Error says in plain words why the test failed.
	Error string `json:"error,omitempty"`
	// HTTPStatus is the server's answer when it was an error.
	HTTPStatus int `json:"http_status,omitempty"`
	// Format, Column and Type are what the feed was read as: detected
	// when the input said auto, so a form can fill them in.
	Format         string         `json:"format,omitempty"`
	Column         string         `json:"column,omitempty"`
	Type           string         `json:"type,omitempty"`
	Total          int            `json:"total"`
	ByType         map[string]int `json:"by_type"`
	Skipped        int            `json:"skipped"`
	SkippedExample string         `json:"skipped_example,omitempty"`
	Reserved       int            `json:"reserved,omitempty"`
	Samples        []Sample       `json:"samples"`
	Bytes          int64          `json:"bytes"`
	Truncated      bool           `json:"truncated,omitempty"`
	Note           string         `json:"note,omitempty"`
	DurationMS     int64          `json:"duration_ms"`
}

// testMaxBytes is TestMaxDownload; tests lower it.
var testMaxBytes int64 = TestMaxDownload

// testFields are the settings a test needs; the rest (name, schedule,
// weight) are checked when the feed is saved.
var testFields = []string{"kind", "url", "collection", "format", "type", "column", "headers", "username", "password", "catalog"}

// ErrBusy is returned when MaxTests tests already run.
var ErrBusy = errors.New("two feed tests are already running on this server; try again in a moment")

// startTest takes a test slot; call the returned func when done.
func (f *Feeds) startTest() (func(), error) {
	f.testsOnce.Do(func() { f.tests = make(chan struct{}, MaxTests) })
	select {
	case f.tests <- struct{}{}:
		return func() { <-f.tests }, nil
	default:
		return nil, ErrBusy
	}
}

// savedForTest returns a saved feed for a test to start from, so its
// stored secrets fill those the request leaves empty. A feed from
// signalith.yaml has its ${ENV_VAR} references filled in here, and the
// test then runs as a feed added on the page: values the request sends
// are used as written and never read the environment, so a test cannot
// send the server's own secrets to an address the request names. Saved
// secrets are only reused on the server they were entered for (see spec).
func (f *Feeds) savedForTest(name string) (*Feed, error) {
	fd, ok := f.Get(name)
	if !ok {
		return nil, ErrUnknownFeed
	}
	if fd.Source != SourceUI {
		if len(fd.Headers) > 0 {
			h := make(map[string]string, len(fd.Headers))
			for k, v := range fd.Headers {
				h[k] = ExpandEnv(v)
			}
			fd.Headers = h
		}
		fd.Password = ExpandEnv(fd.Password)
		fd.Source = SourceUI
	}
	return &fd, nil
}

// TestFeed downloads a feed without saving anything, with a smaller size
// limit and one page of a TAXII collection. existing names a saved feed
// whose stored secrets fill those the input leaves empty. At most
// MaxTests tests run at once.
func (f *Feeds) TestFeed(ctx context.Context, in FeedInput, existing string) (*TestResult, error) {
	var old *Feed
	if existing != "" {
		var err error
		if old, err = f.savedForTest(existing); err != nil {
			return nil, err
		}
	}
	var probs []FeedProblem
	if strings.TrimSpace(in.Catalog) != "" {
		probs = in.fillFromCatalog()
	}
	if low := strings.ToLower(strings.TrimSpace(in.Kind)); low != KindTAXII && strings.TrimSpace(in.Format) == "" {
		in.Format = FormatAuto
	}
	if !feedNamePattern.MatchString(strings.TrimSpace(in.Name)) {
		in.Name = "feed-test"
	}
	spec, p := in.spec(old)
	probs = slices.DeleteFunc(append(probs, p...), func(pr FeedProblem) bool { return !slices.Contains(testFields, pr.Field) })
	if len(probs) > 0 {
		return nil, &InputError{Problems: probs}
	}
	done, err := f.startTest()
	if err != nil {
		return nil, err
	}
	defer done()
	fd := spec.Feed(SourceUI)
	ctx, cancel := context.WithTimeout(ctx, TestTimeout)
	defer cancel()
	start := time.Now()
	lim := fetchLimits{MaxBytes: f.maxBytes(), Refuse: f.maxBytes(), Pages: 1, Timeout: TestTimeout, Keep: 10}
	if lim.MaxBytes > testMaxBytes {
		// Preview a large feed from its first part.
		lim.MaxBytes, lim.Partial = testMaxBytes, true
	}
	got, err := f.fetch(ctx, fd, f.now(), lim)
	res := &TestResult{ByType: map[string]int{}, Samples: []Sample{}, DurationMS: time.Since(start).Milliseconds()}
	if err != nil {
		res.Error = describe(err, fd, TestTimeout)
		var he *HTTPError
		if errors.As(err, &he) {
			res.HTTPStatus = he.Code
		}
		return res, nil
	}
	r := got.Result
	res.Format, res.Column = r.Format, r.Column
	res.Bytes, res.Truncated, res.Note = got.Bytes, got.Truncated, got.Note
	res.Total, res.Skipped, res.SkippedExample, res.Reserved = r.Found, r.Skipped, r.Example, r.Reserved
	for t, n := range r.ByType {
		res.ByType[t] = n
	}
	for _, ind := range r.Indicators {
		if len(res.Samples) < 10 {
			res.Samples = append(res.Samples, Sample{Type: ind.Type, Value: ind.Value, Description: ind.Description})
		}
	}
	res.Type = fd.Type
	if res.Type == "" || res.Type == "auto" {
		res.Type = SuggestType(res.ByType)
	}
	if res.Total == 0 {
		res.Error = emptyMessage(got)
	} else {
		res.OK = true
	}
	return res, nil
}

// TAXIICollections lists the collections of the TAXII server in the
// input's URL, with its credentials (or those stored for existing). It
// shares the test slots with TestFeed.
func (f *Feeds) TAXIICollections(ctx context.Context, in FeedInput, existing string) (*TAXIIServer, error) {
	var old *Feed
	if existing != "" {
		var err error
		if old, err = f.savedForTest(existing); err != nil {
			return nil, err
		}
	}
	in.Kind, in.Format, in.Collection = KindTAXII, FormatSTIX, "x"
	if !feedNamePattern.MatchString(strings.TrimSpace(in.Name)) {
		in.Name = "feed-test"
	}
	spec, probs := in.spec(old)
	probs = slices.DeleteFunc(probs, func(pr FeedProblem) bool {
		return pr.Field != "url" && pr.Field != "headers" && pr.Field != "username" && pr.Field != "password"
	})
	if len(probs) > 0 {
		return nil, &InputError{Problems: probs}
	}
	done, err := f.startTest()
	if err != nil {
		return nil, err
	}
	defer done()
	fd := spec.Feed(SourceUI)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	srv, err := f.Collections(ctx, fd)
	if err != nil {
		return nil, plain("%s", describe(err, fd, 30*time.Second))
	}
	return srv, nil
}
