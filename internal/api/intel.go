// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/intel"
)

// routeIntel registers the threat intel routes. Everyone can see feeds
// and indicators, and analysts add and remove indicators by hand. Feeds
// and bulk uploads are admin work, and so is anything that makes this
// server download from an address the request names (feeds/test and
// taxii/collections), since a test can read services on the local network.
func (s *Server) routeIntel(api *router) {
	api.viewer("GET /api/intel", s.handleIntelOverview)
	api.viewer("GET /api/intel/feeds", s.handleIntelFeeds)
	api.viewer("GET /api/intel/catalog", s.handleIntelCatalog)
	api.viewer("GET /api/intel/indicators", s.handleIntelList)
	api.viewer("GET /api/intel/lookup", s.handleIntelLookup)
	api.analyst("POST /api/intel/indicators", s.handleIntelAdd)
	api.analyst("DELETE /api/intel/indicators/{id}", s.handleIntelDelete)
	api.admin("POST /api/intel/feeds", s.handleIntelFeedAdd)
	api.admin("POST /api/intel/feeds/test", s.handleIntelFeedTest)
	api.admin("PUT /api/intel/feeds/{name}", s.handleIntelFeedUpdate)
	api.admin("DELETE /api/intel/feeds/{name}", s.handleIntelFeedDelete)
	api.admin("POST /api/intel/feeds/{name}/refresh", s.handleIntelRefresh)
	api.admin("POST /api/intel/catalog", s.handleIntelCatalogAdd)
	api.admin("POST /api/intel/taxii/collections", s.handleIntelTAXIICollections)
	api.admin("POST /api/intel/upload", s.handleIntelUpload)
}

// feedsFor lists the feeds as the request's user may see them. A feed's
// address can carry an API key in its query, and a TAXII sign-in names an
// account, so only admins see those in full.
func (s *Server) feedsFor(r *http.Request) []intel.FeedView {
	list := s.Feeds.Status()
	// Feeds are set up by the provider's users: a tenant's admins see
	// them as the others do.
	if principalOf(r).runsServer() {
		return list
	}
	for i := range list {
		list[i].URL = intel.RedactURL(list[i].URL)
		list[i].Username = ""
	}
	return list
}

var errIntelOff = errors.New("threat intel is not available on this server")

func (s *Server) intelOK(w http.ResponseWriter) bool {
	if s.Intel == nil {
		writeError(w, http.StatusServiceUnavailable, errIntelOff)
		return false
	}
	return true
}

// handleIntelOverview returns indicator counts and every feed's status.
func (s *Server) handleIntelOverview(w http.ResponseWriter, r *http.Request) {
	if !s.intelOK(w) {
		return
	}
	feeds := []intel.FeedView{}
	out := map[string]any{
		"summary":   s.Intel.Summary(),
		"loaded":    s.Intel.Loaded(),
		"downloads": s.downloads(),
		"types":     intel.Types,
		// manage says whether feeds can be added and changed on the page:
		// on every member of the cluster, where they are shared, and
		// otherwise only on the server that downloads them.
		"manage": s.Feeds != nil && s.manageFeeds(),
		"shared": s.sharedContent(),
	}
	if s.Feeds != nil {
		feeds = s.feedsFor(r)
		s.addFeedETags(r, feeds, out)
		// A broken feeds file blocks changes on the page until it is fixed.
		if err := s.Feeds.Load(); err != nil {
			out["file_error"] = err.Error()
		}
	}
	if err := s.noDownloads(); err != nil {
		// Why not, naming the server that does when there is one.
		out["downloads_why"] = sentence(err.Error())
		if s.Cluster != nil && !errors.Is(err, errNoSchedule) {
			out["runs_on"] = s.Cluster.JobHolder()
		}
	}
	out["feeds"] = feeds
	writeJSON(w, http.StatusOK, out)
}

// manageFeeds reports whether feeds can be added and changed here.
func (s *Server) manageFeeds() bool {
	if s.sharedContent() {
		return true
	}
	return s.downloads()
}

func (s *Server) handleIntelRefresh(w http.ResponseWriter, r *http.Request) {
	if !s.intelOK(w) {
		return
	}
	if s.Feeds == nil {
		writeError(w, http.StatusNotFound, intel.ErrUnknownFeed)
		return
	}
	name := r.PathValue("name")
	if s.sharedContent() && !s.leads() {
		// The feeds are shared: the server that runs the background jobs
		// downloads it, and the page follows the request.
		if _, ok := s.Feeds.Get(name); !ok {
			writeError(w, http.StatusNotFound, intel.ErrUnknownFeed)
			return
		}
		s.submit(w, r, clustercfg.RequestFeedRefresh, clustercfg.FeedRefreshArgs{Feed: name}, map[string]any{"feed": name})
		return
	}
	// A feed added on the page is only kept by the server that runs the
	// schedule; indicators another server downloads for it would be
	// removed when that server starts.
	if fd, ok := s.Feeds.Get(name); ok && fd.Source == intel.SourceUI && !s.sharedContent() {
		if err := s.noDownloads(); err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	st, err := s.Feeds.Refresh(ctx, name)
	switch {
	case errors.Is(err, intel.ErrUnknownFeed):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, intel.ErrFeedRunning), errors.Is(err, intel.ErrFeedChanged), errors.Is(err, intel.ErrFeedOff):
		writeError(w, http.StatusConflict, err)
	case err != nil:
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "status": st})
	default:
		s.audit(r, "intel.feed_refresh: threat intel feed refreshed by hand", "feed", name, "indicators", st.Count)
		writeJSON(w, http.StatusOK, map[string]any{"status": st})
	}
}

func (s *Server) handleIntelList(w http.ResponseWriter, r *http.Request) {
	if !s.intelOK(w) {
		return
	}
	v := r.URL.Query()
	limit, _ := strconv.Atoi(v.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	offset, _ := strconv.Atoi(v.Get("offset"))
	list, total := s.Intel.List(intel.Filter{Text: v.Get("q"), Type: v.Get("type"), Source: v.Get("source"), Limit: limit, Offset: max(offset, 0)})
	if list == nil {
		list = []intel.Indicator{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"indicators": list, "total": total})
}

// handleIntelAdd adds one manual indicator.
func (s *Server) handleIntelAdd(w http.ResponseWriter, r *http.Request) {
	if !s.intelOK(w) {
		return
	}
	var in intel.Input
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ind, err := in.Build(time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	inds := []intel.Indicator{ind}
	if err := s.Intel.Add(r.Context(), inds); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.audit(r, "intel.indicator_add: threat intel indicator added", indicatorAudit(ind)...)
	got, _ := s.Intel.Get(inds[0].ID)
	writeJSON(w, http.StatusOK, got)
}

// handleIntelDelete removes a manual indicator. Feed indicators come back
// with the next download, so they are removed by disabling the feed.
func (s *Server) handleIntelDelete(w http.ResponseWriter, r *http.Request) {
	if !s.intelOK(w) {
		return
	}
	id := r.PathValue("id")
	ind, ok := s.Intel.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("no indicator with that id"))
		return
	}
	// A feed's indicators return with its next download. Those of a
	// deleted feed whose indicators were kept can go one by one.
	if ind.Source != intel.ManualSource && s.Feeds != nil {
		if _, ok := s.Feeds.Get(ind.Source); ok {
			writeError(w, http.StatusConflict, errors.New("this indicator comes from the feed "+ind.Source+" and would return with its next download; disable the feed instead"))
			return
		}
	}
	if err := s.Intel.Delete(r.Context(), []string{id}); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.audit(r, "intel.indicator_delete: threat intel indicator deleted", indicatorAudit(ind)...)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// handleIntelUpload adds manual indicators from CSV or a plain list.
// Every bad line is reported and nothing is saved unless all are valid.
func (s *Server) handleIntelUpload(w http.ResponseWriter, r *http.Request) {
	if !s.intelOK(w) {
		return
	}
	inds, err := intel.ParseUpload(uploadBody(w, r), time.Now())
	var pe *intel.ParseError
	if errors.As(err, &pe) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "the file has problems; nothing was saved", "lines": pe.Lines})
		return
	}
	if err != nil {
		uploadFailed(w, err)
		return
	}
	if len(inds) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("the file has no indicators"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	if err := s.Intel.Add(ctx, inds); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.audit(r, "intel.indicator_upload: threat intel indicators uploaded", uploadAudit(inds)...)
	writeJSON(w, http.StatusOK, map[string]any{"count": len(inds)})
}

// handleIntelLookup checks one value against every indicator, the way
// the intel search command does.
func (s *Server) handleIntelLookup(w http.ResponseWriter, r *http.Request) {
	if !s.intelOK(w) {
		return
	}
	m := s.Intel.Lookup(r.URL.Query().Get("value"))
	if m == nil {
		m = []intel.Indicator{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"matches": m})
}

// ---- feeds managed on the page ----

var errFeedsOff = errors.New("threat intel feeds are not available on this server")

// errNoSchedule refuses feed changes on a server that does not download
// feeds: its feeds file is not the one the downloading server reads.
var errNoSchedule = errors.New("this server does not download feeds (detections.scheduler is off here), so feeds are added and changed on the Signalith server that runs the background jobs")

// downloads reports whether this server downloads feeds on their
// schedules: it runs the background jobs.
func (s *Server) downloads() bool {
	return s.noDownloads() == nil
}

// noDownloads says why this server does not download feeds now, or nil.
// Of the servers that share one OpenSearch, only the one that runs the
// background jobs does, with its own list of feeds.
func (s *Server) noDownloads() error {
	if s.conf() == nil || !s.conf().Detections.Scheduler {
		return errNoSchedule
	}
	if s.Cluster == nil || s.Cluster.RunsJobs() {
		return nil
	}
	if holder := s.Cluster.JobHolder(); holder != "" {
		return fmt.Errorf("this server does not download feeds right now: %s does, with its own list of feeds; add and change feeds there", holder)
	}
	return errors.New("this server does not download feeds right now, and no server runs the background jobs at the moment; the Servers page says why")
}

func (s *Server) feedsOK(w http.ResponseWriter) bool {
	if !s.intelOK(w) {
		return false
	}
	if s.Feeds == nil {
		writeError(w, http.StatusServiceUnavailable, errFeedsOff)
		return false
	}
	return true
}

// feedsWritable also refuses changes on a server that does not download
// feeds, or, where they are shared, while the shared settings cannot be
// changed here.
func (s *Server) feedsWritable(w http.ResponseWriter) bool {
	if !s.feedsOK(w) {
		return false
	}
	if s.sharedContent() {
		return s.sharedWritable(w)
	}
	if err := s.noDownloads(); err != nil {
		writeError(w, http.StatusConflict, err)
		return false
	}
	return true
}

// writeFeedError answers a failed feed change in plain words.
func writeFeedError(w http.ResponseWriter, err error) {
	var ie *intel.InputError
	var fe *intel.FileError
	if sharedError(w, err) {
		return
	}
	switch {
	case errors.As(err, &ie):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": ie.Error(), "problems": ie.Messages(), "fields": ie.Fields()})
	case errors.Is(err, intel.ErrUnknownFeed):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, intel.ErrReadOnly):
		writeError(w, http.StatusConflict, err)
	case errors.As(err, &fe):
		writeError(w, http.StatusServiceUnavailable, errHidden("The feeds file could not be read. Fix or delete it, then reload this page", err))
	case errors.Is(err, intel.ErrBusy):
		writeError(w, http.StatusTooManyRequests, err)
	default:
		writeError(w, http.StatusInternalServerError, err)
	}
}

// handleIntelFeeds lists every feed with its settings and status. Secret
// values are never included, only whether each is set.
func (s *Server) handleIntelFeeds(w http.ResponseWriter, r *http.Request) {
	if !s.feedsOK(w) {
		return
	}
	feeds := s.feedsFor(r)
	out := map[string]any{
		"feeds":      feeds,
		"downloads":  s.downloads(),
		"manage":     s.manageFeeds(),
		"shared":     s.sharedContent(),
		"feeds_file": s.Feeds.File,
		"formats":    append(append([]string{}, intel.Formats...), intel.FormatAuto),
		"types":      intel.FeedTypes,
	}
	if s.sharedContent() {
		out["feeds_file"] = ""
	}
	s.addFeedETags(r, feeds, out)
	if err := s.Feeds.Load(); err != nil {
		out["file_error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, out)
}

// addFeedETags adds each feed's version to out, for If-Match on a change:
// a hash of its settings, secrets included, so only admins get it.
func (s *Server) addFeedETags(r *http.Request, feeds []intel.FeedView, out map[string]any) {
	if !principalOf(r).runsServer() {
		return
	}
	etags := map[string]string{}
	for _, f := range feeds {
		if tag, ok := s.Feeds.ETag(f.Name); ok {
			etags[f.Name] = tag
		}
	}
	out["etags"] = etags
}

func (s *Server) handleIntelFeedAdd(w http.ResponseWriter, r *http.Request) {
	if !s.feedsWritable(w) {
		return
	}
	var in intel.FeedInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	v, err := s.Feeds.AddFeedAs(r.Context(), userOf(r), in)
	if err != nil {
		writeFeedError(w, err)
		return
	}
	if fd, ok := s.Feeds.Get(v.Name); ok {
		s.audit(r, "intel.feed_add: threat intel feed added", feedAudit(fd)...)
	}
	writeJSON(w, http.StatusOK, v)
}

// handleIntelFeedUpdate changes a feed added on the page. Settings the
// request leaves out stay as they are, and so do secrets sent empty.
func (s *Server) handleIntelFeedUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.feedsWritable(w) {
		return
	}
	name := r.PathValue("name")
	in, ok := s.Feeds.InputFor(name)
	if !ok {
		writeError(w, http.StatusNotFound, intel.ErrUnknownFeed)
		return
	}
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	before, _ := s.Feeds.Get(name)
	v, err := s.Feeds.UpdateFeedIf(r.Context(), userOf(r), name, r.Header.Get("If-Match"), in)
	if err != nil {
		writeFeedError(w, err)
		return
	}
	if tag, ok := s.Feeds.ETag(name); ok {
		w.Header().Set("ETag", tag)
	}
	after, _ := s.Feeds.Get(name)
	s.audit(r, "intel.feed_change: threat intel feed changed", append(feedAudit(after), "changes", feedChanges(before, after))...)
	writeJSON(w, http.StatusOK, v)
}

// handleIntelFeedDelete deletes a feed added on the page. Its indicators
// are removed too, unless ?indicators=keep, which lets them age out.
func (s *Server) handleIntelFeedDelete(w http.ResponseWriter, r *http.Request) {
	if !s.feedsWritable(w) {
		return
	}
	name := r.PathValue("name")
	mode := r.URL.Query().Get("indicators")
	if mode != "" && mode != "remove" && mode != "keep" {
		writeError(w, http.StatusBadRequest, errors.New("indicators must be remove or keep"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	before, _ := s.Feeds.Get(name)
	n, err := s.Feeds.RemoveFeedIf(ctx, userOf(r), name, r.Header.Get("If-Match"), mode != "keep")
	if err != nil {
		writeFeedError(w, err)
		return
	}
	s.audit(r, "intel.feed_delete: threat intel feed deleted", append(feedAudit(before), "indicators_removed", n)...)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": name, "indicators_removed": n, "indicators_kept": mode == "keep"})
}

// feedTestRequest is a feed to test or a server to list collections of.
// Feed names a saved feed whose stored secrets fill those left empty.
type feedTestRequest struct {
	intel.FeedInput
	Feed string `json:"feed"`
}

// readFeedTest reads a test request; with feed, it starts from that
// feed's settings like a change does.
func (s *Server) readFeedTest(w http.ResponseWriter, r *http.Request) (feedTestRequest, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return feedTestRequest{}, false
	}
	var head struct {
		Feed string `json:"feed"`
	}
	if err := decodeJSON(body, &head); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return feedTestRequest{}, false
	}
	var req feedTestRequest
	if head.Feed != "" {
		in, ok := s.Feeds.InputFor(head.Feed)
		if !ok {
			writeError(w, http.StatusNotFound, intel.ErrUnknownFeed)
			return feedTestRequest{}, false
		}
		req.FeedInput = in
	}
	if err := decodeJSON(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return feedTestRequest{}, false
	}
	return req, true
}

// handleIntelFeedTest downloads a feed without saving it, and reports
// what it found: the format and type (detected for auto), the number of
// indicators by type and a few samples, or why it failed.
func (s *Server) handleIntelFeedTest(w http.ResponseWriter, r *http.Request) {
	if !s.feedsOK(w) {
		return
	}
	req, ok := s.readFeedTest(w, r)
	if !ok {
		return
	}
	res, err := s.Feeds.TestFeed(r.Context(), req.FeedInput, req.Feed)
	if err != nil {
		writeFeedError(w, err)
		return
	}
	s.audit(r, "intel.feed_test: threat intel feed tested", "feed", req.Feed, "url", intel.RedactURL(req.URL), "ok", res.OK, "indicators", res.Total)
	writeJSON(w, http.StatusOK, res)
}

// handleIntelTAXIICollections lists a TAXII 2.1 server's collections, so
// the page can offer a choice.
func (s *Server) handleIntelTAXIICollections(w http.ResponseWriter, r *http.Request) {
	if !s.feedsOK(w) {
		return
	}
	req, ok := s.readFeedTest(w, r)
	if !ok {
		return
	}
	srv, err := s.Feeds.TAXIICollections(r.Context(), req.FeedInput, req.Feed)
	var ie *intel.InputError
	switch {
	case errors.As(err, &ie), errors.Is(err, intel.ErrUnknownFeed), errors.Is(err, intel.ErrBusy):
		writeFeedError(w, err)
	case err != nil:
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error(), "collections": []any{}})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "title": srv.Title, "collections": srv.Collections})
	}
}

// handleIntelCatalog lists the built-in catalog of free feeds, marking
// those already added.
func (s *Server) handleIntelCatalog(w http.ResponseWriter, r *http.Request) {
	if !s.feedsOK(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.Feeds.Catalog()})
}

// handleIntelCatalogAdd adds catalog feeds by ID, such as the recommended
// set, with their suggested settings.
func (s *Server) handleIntelCatalogAdd(w http.ResponseWriter, r *http.Request) {
	if !s.feedsWritable(w) {
		return
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.IDs) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("ids lists the catalog feeds to add"))
		return
	}
	added, skipped, err := s.Feeds.AddCatalogAs(r.Context(), userOf(r), req.IDs)
	if err != nil {
		writeFeedError(w, err)
		return
	}
	for _, v := range added {
		if fd, ok := s.Feeds.Get(v.Name); ok {
			s.audit(r, "intel.feed_add: threat intel feed added from the catalog", feedAudit(fd)...)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"added": added, "skipped": skipped})
}

// indicatorAudit describes an indicator for an audit line.
func indicatorAudit(ind intel.Indicator) []any {
	exp := ""
	if !ind.Expires.IsZero() {
		exp = ind.Expires.UTC().Format(time.RFC3339)
	}
	return []any{"target", ind.Value, "type", ind.Type, "source", ind.Source, "weight", ind.Weight, "expires", exp,
		"tags", strings.Join(ind.Tags, ","), "indicator", ind.ID}
}

// uploadAudit describes an upload for an audit line: how many indicators
// of each type, and the first values.
func uploadAudit(inds []intel.Indicator) []any {
	types := map[string]int{}
	var first []string
	for _, ind := range inds {
		types[ind.Type]++
		if len(first) < 20 {
			first = append(first, ind.Value)
		}
	}
	var byType []string
	for _, t := range slices.Sorted(maps.Keys(types)) {
		byType = append(byType, fmt.Sprintf("%s=%d", t, types[t]))
	}
	return []any{"indicators", len(inds), "types", strings.Join(byType, ","), "values", strings.Join(first, ",")}
}

// feedAudit describes a feed for an audit line. The address loses any
// credentials it holds; headers and the password are never named.
func feedAudit(fd intel.Feed) []any {
	return []any{"feed", fd.Name, "kind", fd.Kind, "url", intel.RedactURL(fd.URL), "collection", fd.Collection,
		"format", fd.Format, "type", fd.Type, "interval", fd.Interval.String(), "max_age", fd.MaxAge.String(),
		"weight", fd.Weight, "enabled", fd.Enabled}
}

// feedChanges names what a change to a feed changed, with the old and
// new values of its settings; secrets are only said to have changed.
func feedChanges(a, b intel.Feed) string {
	var out []string
	add := func(name, from, to string) {
		if from != to {
			out = append(out, name+": "+from+" -> "+to)
		}
	}
	add("url", intel.RedactURL(a.URL), intel.RedactURL(b.URL))
	add("kind", a.Kind, b.Kind)
	add("collection", a.Collection, b.Collection)
	add("format", a.Format, b.Format)
	add("type", a.Type, b.Type)
	add("column", a.Column, b.Column)
	add("interval", a.Interval.String(), b.Interval.String())
	add("max_age", a.MaxAge.String(), b.MaxAge.String())
	add("weight", strconv.FormatFloat(a.Weight, 'g', -1, 64), strconv.FormatFloat(b.Weight, 'g', -1, 64))
	add("enabled", strconv.FormatBool(a.Enabled), strconv.FormatBool(b.Enabled))
	add("tags", strings.Join(a.Tags, ","), strings.Join(b.Tags, ","))
	add("username", a.Username, b.Username)
	if a.Password != b.Password {
		out = append(out, "password changed")
	}
	if !maps.Equal(a.Headers, b.Headers) {
		out = append(out, "headers changed")
	}
	return strings.Join(out, ", ")
}
