// Package ostest is an in-memory OpenSearch for tests. It keeps documents
// with real _seq_no, _primary_term and _version behaviour, so writes that
// name a version (if_seq_no and if_primary_term) succeed or conflict as
// they would in OpenSearch, and it can refuse writes with a cluster block,
// as OpenSearch does when its disk is full. It answers:
//
//   - GET /, /_cluster/health and /_nodes/_local/stats/os (with the time of
//     its own clock);
//   - PUT, HEAD and DELETE of an index, and PUT /<index>/_mapping;
//   - PUT /_index_template/<name>;
//   - GET, PUT and DELETE /<index>/_doc/<id>, PUT /<index>/_create/<id>,
//     POST /<index>/_update/<id> (each with if_seq_no and if_primary_term);
//   - POST /_mget;
//   - POST /<pattern>/_search with match_all, term, terms, ids, range,
//     exists and bool queries, size, sort, search_after,
//     seq_no_primary_term, _source and max aggregations;
//   - POST /<pattern>/_delete_by_query and _update_by_query (recorded,
//     only deletes change anything);
//   - POST /_bulk with create and index actions;
//   - GET /<pattern>/_count (every document, whatever the query);
//   - GET /_nodes/_local/settings (path.home and path.data, see Paths);
//   - GET /_plugins/_security/authinfo, once Secure turns sign-in on
//     (before that, as without the security plugin, it is not found).
//
// Anything else is acknowledged, so a server can start against it.
package ostest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Fault is what the fake does with one request instead of answering it
// normally.
type Fault struct {
	// Status, when set, answers with this status and an error of Type,
	// without doing the request; or, when Text is set, with Text as plain
	// text, as OpenSearch's security plugin answers before its settings
	// are loaded (see NotInitialized).
	Status int
	Type   string
	Text   string
	// Drop does the request, then closes the connection without an answer,
	// as when a connection is reset after the request was sent.
	Drop bool
	// Stall takes the request and answers nothing until the client gives
	// up, as an OpenSearch too slow to answer in time.
	Stall bool
}

// Server is the fake OpenSearch.
type Server struct {
	*httptest.Server

	// Clock, when set, is the fake's own clock for _nodes stats, moved by
	// Offset; otherwise the real clock is.
	Clock  *Clock
	Offset time.Duration

	mu          sync.Mutex
	indices     map[string]*index
	templates   map[string]json.RawMessage
	primaryTerm int64
	blocked     bool
	fault       func(method, path string) *Fault
	requests    []string
	autoID      int
	// security, when set, is the account every request must sign in as
	// (see Secure).
	security *Account
	// paths are the node's path.home and path.data (see SetPaths).
	home string
	data []string
}

// Account is the one account the fake lets in once Secure is called, and
// what its security plugin says about it.
type Account struct {
	User, Password string
	Roles          []string
	BackendRoles   []string
}

// Secure makes the fake require sign-in as a: other requests get 401, as
// with OpenSearch's security plugin; authinfo then answers. nil turns
// that off again.
func (s *Server) Secure(a *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.security = a
}

// SetPaths sets the node's path.home and path.data, which
// /_nodes/_local/settings reports; data may be empty.
func (s *Server) SetPaths(home string, data ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.home, s.data = home, data
}

type index struct {
	name    string
	body    json.RawMessage // settings and mappings it was created with
	docs    map[string]*doc
	seq     int64
	created time.Time
}

type doc struct {
	source      map[string]any
	seqNo       int64
	primaryTerm int64
	version     int64
}

// New starts a fake OpenSearch. It stops when the test ends.
func New(t interface{ Cleanup(func()) }) *Server {
	s := &Server{indices: map[string]*index{}, templates: map[string]json.RawMessage{}, primaryTerm: 1}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// NewHandler returns a fake OpenSearch that is not started, for a server
// of one's own (a demo, say). Its Server field is nil.
func NewHandler() (*Server, http.Handler) {
	s := &Server{indices: map[string]*index{}, templates: map[string]json.RawMessage{}, primaryTerm: 1}
	return s, http.HandlerFunc(s.serve)
}

// Plug is a second address of a fake, for one server's requests, that a
// test can pull out as when that server crashes.
type Plug struct {
	*httptest.Server
	mu     sync.RWMutex
	pulled bool
}

// Plug returns a new address of s. It stops when the test ends.
func (s *Server) Plug(t interface{ Cleanup(func()) }) *Plug {
	p := &Plug{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.RLock()
		defer p.mu.RUnlock()
		if p.pulled {
			drop(w)
			return
		}
		s.serve(w, r)
	}))
	t.Cleanup(p.Close)
	return p
}

// Pull cuts the address off. It waits for the requests being answered,
// and drops every later one, so that nothing sent through it before a
// crash lands after Pull returns: a request a server sent just before it
// was stopped can otherwise reach the fake later.
func (p *Plug) Pull() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pulled = true
}

// Block makes every write refused with a cluster_block_exception (HTTP
// 429), as when OpenSearch's disk passes the flood-stage watermark, or
// lifts that. Reads and deleting whole indices still work.
func (s *Server) Block(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocked = on
}

// SetFault sets a function that may answer a request with a Fault; nil
// clears it.
func (s *Server) SetFault(f func(method, path string) *Fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fault = f
}

// NotInitialized is the answer of OpenSearch's security plugin to every
// request before its security settings are loaded, word for word
// (OpenSearch 2.17).
var NotInitialized = Fault{Status: http.StatusServiceUnavailable, Text: "OpenSearch Security not initialized."}

// FailN answers the next n requests that match (method and a path that
// contains part) with status and an error of typ.
func (s *Server) FailN(n int, method, part string, status int, typ string) {
	left := n
	var mu sync.Mutex
	s.SetFault(func(m, p string) *Fault {
		mu.Lock()
		defer mu.Unlock()
		if left <= 0 || m != method || !strings.Contains(p, part) {
			return nil
		}
		left--
		return &Fault{Status: status, Type: typ}
	})
}

// BumpPrimaryTerm raises the primary term later writes get, as when a
// replica becomes the primary.
func (s *Server) BumpPrimaryTerm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.primaryTerm++
}

// Templates lists the names of the index templates put.
func (s *Server) Templates() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.templates {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Requests returns the requests made, as "METHOD /path?query", and
// forgets them.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.requests
	s.requests = nil
	return out
}

// Source returns a document's source, or nil when it does not exist.
func (s *Server) Source(indexName, id string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	ix := s.indices[indexName]
	if ix == nil || ix.docs[id] == nil {
		return nil
	}
	return clone(ix.docs[id].source)
}

// Put writes a document directly, as someone with write access to
// OpenSearch could, ignoring blocks and faults.
func (s *Server) Put(indexName, id string, source map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.put(s.ensure(indexName), id, clone(source))
}

// Delete deletes a document directly.
func (s *Server) Delete(indexName, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ix := s.indices[indexName]; ix != nil {
		delete(ix.docs, id)
	}
}

// Indices lists the indices.
func (s *Server) Indices() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.indices {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IndexBody returns the settings and mappings an index was created with.
func (s *Server) IndexBody(name string) json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ix := s.indices[name]; ix != nil {
		return ix.body
	}
	return nil
}

func (s *Server) now() time.Time {
	if s.Clock != nil {
		return s.Clock.Now().Add(s.Offset)
	}
	return time.Now().Add(s.Offset)
}

// ensure returns an index, creating it as a write does, with the settings
// and mappings of the index template that matches its name best; the
// caller holds s.mu.
func (s *Server) ensure(name string) *index {
	ix := s.indices[name]
	if ix == nil {
		ix = &index{name: name, docs: map[string]*doc{}, seq: -1, created: s.now(), body: s.templateFor(name)}
		s.indices[name] = ix
	}
	return ix
}

// templateFor returns the "template" part of the index template with the
// highest priority whose index_patterns match name, or nil; the caller
// holds s.mu.
func (s *Server) templateFor(name string) json.RawMessage {
	var best json.RawMessage
	bestPriority := -1
	for _, raw := range s.templates {
		var t struct {
			Patterns []string        `json:"index_patterns"`
			Priority int             `json:"priority"`
			Template json.RawMessage `json:"template"`
		}
		if json.Unmarshal(raw, &t) != nil {
			continue
		}
		for _, pat := range t.Patterns {
			if ok, _ := path.Match(pat, name); ok && t.Priority > bestPriority {
				best, bestPriority = t.Template, t.Priority
			}
		}
	}
	return best
}

// put writes a document; the caller holds s.mu.
func (s *Server) put(ix *index, id string, src map[string]any) *doc {
	ix.seq++
	d := ix.docs[id]
	v := int64(1)
	if d != nil {
		v = d.version + 1
	}
	d = &doc{source: src, seqNo: ix.seq, primaryTerm: s.primaryTerm, version: v}
	ix.docs[id] = d
	return d
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	p := r.URL.Path
	s.mu.Lock()
	s.requests = append(s.requests, r.Method+" "+r.URL.RequestURI())
	fault, sec := s.fault, s.security
	s.mu.Unlock()
	if sec != nil {
		if u, pw, ok := r.BasicAuth(); !ok || u != sec.User || pw != sec.Password {
			writeError(w, http.StatusUnauthorized, "security_exception", "missing authentication credentials")
			return
		}
	}
	if fault != nil {
		if f := fault(r.Method, r.URL.RequestURI()); f != nil {
			if f.Stall {
				<-r.Context().Done()
				return
			}
			if f.Drop {
				s.handle(httptest.NewRecorder(), r, p, body)
				drop(w)
				return
			}
			if f.Text != "" {
				w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
				w.WriteHeader(f.Status)
				_, _ = io.WriteString(w, f.Text)
				return
			}
			writeError(w, f.Status, f.Type, "injected by the test")
			return
		}
	}
	s.handle(w, r, p, body)
}

// drop closes the connection without an answer.
func drop(w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("ostest: cannot drop the connection")
	}
	conn, _, err := hj.Hijack()
	if err == nil {
		conn.Close()
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, typ, reason string) {
	writeJSON(w, status, map[string]any{
		"error":  map[string]any{"root_cause": []any{map[string]any{"type": typ, "reason": reason}}, "type": typ, "reason": reason},
		"status": status,
	})
}

func (s *Server) blockedError(w http.ResponseWriter, indexName string) {
	writeError(w, http.StatusTooManyRequests, "cluster_block_exception",
		"index ["+indexName+"] blocked by: [TOO_MANY_REQUESTS/12/disk usage exceeded flood-stage watermark, index has read-only-allow-delete block];")
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request, p string, body []byte) {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for i := range parts {
		if u, err := url.PathUnescape(parts[i]); err == nil {
			parts[i] = u
		}
	}
	q := r.URL.Query()
	switch {
	case p == "/" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"name": "ostest-1", "cluster_name": "ostest",
			"version": map[string]any{"number": "2.17.1", "distribution": "opensearch"}})
	case p == "/_cluster/health":
		writeJSON(w, 200, map[string]any{"cluster_name": "ostest", "status": "green", "number_of_nodes": 1, "number_of_data_nodes": 1})
	case strings.HasPrefix(p, "/_nodes/") && strings.Contains(p, "/stats"):
		writeJSON(w, 200, map[string]any{"nodes": map[string]any{"ostest-node": map[string]any{
			"name": "ostest-1", "roles": []string{"data", "cluster_manager"},
			"os": map[string]any{"timestamp": s.now().UnixMilli()},
			"fs": map[string]any{"total": map[string]any{"total_in_bytes": int64(1) << 40, "available_in_bytes": int64(1) << 39}},
		}}})
	case len(parts) == 2 && parts[0] == "_index_template" && r.Method == http.MethodPut:
		s.mu.Lock()
		s.templates[parts[1]] = body
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	case strings.HasPrefix(p, "/_cat/"):
		writeJSON(w, 200, []any{})
	case p == "/_plugins/_security/authinfo":
		s.mu.Lock()
		sec := s.security
		s.mu.Unlock()
		if sec == nil {
			writeError(w, 400, "illegal_argument_exception", "no handler found for uri [/_plugins/_security/authinfo] and method [GET]")
			return
		}
		writeJSON(w, 200, map[string]any{"user_name": sec.User, "roles": sec.Roles, "backend_roles": sec.BackendRoles})
	case p == "/_nodes/_local/settings":
		s.mu.Lock()
		home, data := s.home, s.data
		s.mu.Unlock()
		if home == "" {
			home = "/usr/share/opensearch"
		}
		paths := map[string]any{"home": home}
		if len(data) > 0 {
			paths["data"] = data
		}
		writeJSON(w, 200, map[string]any{"nodes": map[string]any{"ostest-node": map[string]any{"settings": map[string]any{"path": paths}}}})
	case len(parts) == 2 && parts[1] == "_count":
		s.mu.Lock()
		n := 0
		for _, ix := range s.match(parts[0]) {
			n += len(ix.docs)
		}
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"count": n})
	case p == "/_mget":
		s.mget(w, q, body)
	case p == "/_bulk" || len(parts) == 2 && parts[1] == "_bulk":
		s.bulk(w, body)
	case len(parts) == 1 && !strings.HasPrefix(parts[0], "_"):
		s.indexOp(w, r.Method, parts[0], body)
	case len(parts) == 2 && parts[1] == "_mapping" && r.Method == http.MethodPut:
		s.mu.Lock()
		blocked, exists := s.blocked, s.indices[parts[0]] != nil
		s.mu.Unlock()
		switch {
		case blocked:
			s.blockedError(w, parts[0])
		case !exists:
			writeError(w, 404, "index_not_found_exception", "no such index ["+parts[0]+"]")
		default:
			writeJSON(w, 200, map[string]any{"acknowledged": true})
		}
	case len(parts) == 2 && parts[1] == "_search":
		s.search(w, parts[0], body)
	case len(parts) == 2 && (parts[1] == "_delete_by_query" || parts[1] == "_update_by_query"):
		s.byQuery(w, parts[0], parts[1], body)
	case len(parts) == 3 && (parts[1] == "_doc" || parts[1] == "_create" || parts[1] == "_update"):
		s.docOp(w, r.Method, parts[0], parts[1], parts[2], q, body)
	default:
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	}
}

func (s *Server) indexOp(w http.ResponseWriter, method, name string, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ix := s.indices[name]
	switch method {
	case http.MethodPut:
		if s.blocked {
			s.blockedError(w, name)
			return
		}
		if ix != nil {
			writeError(w, 400, "resource_already_exists_exception", "index ["+name+"] already exists")
			return
		}
		ix = s.ensure(name)
		ix.body = append(json.RawMessage(nil), body...)
		writeJSON(w, 200, map[string]any{"acknowledged": true, "index": name})
	case http.MethodHead, http.MethodGet:
		if ix == nil {
			writeError(w, 404, "index_not_found_exception", "no such index ["+name+"]")
			return
		}
		writeJSON(w, 200, map[string]any{name: map[string]any{}})
	case http.MethodDelete:
		// Deleting a whole index works even under the disk block.
		if ix == nil {
			writeError(w, 404, "index_not_found_exception", "no such index ["+name+"]")
			return
		}
		delete(s.indices, name)
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	default:
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	}
}

func docMeta(ix *index, id string, d *doc) map[string]any {
	return map[string]any{"_index": ix.name, "_id": id, "_version": d.version, "_seq_no": d.seqNo, "_primary_term": d.primaryTerm}
}

// conditional checks if_seq_no and if_primary_term against d, which may
// be nil.
func conditional(q url.Values, d *doc) (bool, bool) {
	sq, pt := q.Get("if_seq_no"), q.Get("if_primary_term")
	if sq == "" && pt == "" {
		return false, true
	}
	if d == nil {
		return true, false
	}
	return true, strconv.FormatInt(d.seqNo, 10) == sq && strconv.FormatInt(d.primaryTerm, 10) == pt
}

func (s *Server) docOp(w http.ResponseWriter, method, indexName, op, id string, q url.Values, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ix := s.indices[indexName]
	var d *doc
	if ix != nil {
		d = ix.docs[id]
	}
	if method == http.MethodGet && op == "_doc" {
		if ix == nil {
			writeError(w, 404, "index_not_found_exception", "no such index ["+indexName+"]")
			return
		}
		if d == nil {
			writeJSON(w, 404, map[string]any{"_index": indexName, "_id": id, "found": false})
			return
		}
		out := docMeta(ix, id, d)
		out["found"] = true
		out["_source"] = d.source
		writeJSON(w, 200, out)
		return
	}
	if s.blocked {
		s.blockedError(w, indexName)
		return
	}
	conflictErr := func(why string) {
		writeError(w, 409, "version_conflict_engine_exception", "["+id+"]: version conflict, "+why)
	}
	switch {
	case op == "_create" && (method == http.MethodPut || method == http.MethodPost):
		if d != nil {
			conflictErr("document already exists")
			return
		}
		src, err := decodeObject(body)
		if err != nil {
			writeError(w, 400, "mapper_parsing_exception", err.Error())
			return
		}
		ix = s.ensure(indexName)
		nd := s.put(ix, id, src)
		out := docMeta(ix, id, nd)
		out["result"] = "created"
		writeJSON(w, 201, out)
	case op == "_doc" && (method == http.MethodPut || method == http.MethodPost):
		if cond, ok := conditional(q, d); cond && !ok {
			conflictErr("required seqNo [" + q.Get("if_seq_no") + "], primary term [" + q.Get("if_primary_term") + "]")
			return
		}
		src, err := decodeObject(body)
		if err != nil {
			writeError(w, 400, "mapper_parsing_exception", err.Error())
			return
		}
		ix = s.ensure(indexName)
		nd := s.put(ix, id, src)
		out := docMeta(ix, id, nd)
		out["result"] = map[bool]string{true: "updated", false: "created"}[d != nil]
		writeJSON(w, map[bool]int{true: 200, false: 201}[d != nil], out)
	case op == "_update" && method == http.MethodPost:
		if d == nil {
			writeError(w, 404, "document_missing_exception", "["+id+"]: document missing")
			return
		}
		if cond, ok := conditional(q, d); cond && !ok {
			conflictErr("required seqNo [" + q.Get("if_seq_no") + "], primary term [" + q.Get("if_primary_term") + "]")
			return
		}
		var req struct {
			Doc map[string]any `json:"doc"`
		}
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		if err := dec.Decode(&req); err != nil {
			writeError(w, 400, "parse_exception", err.Error())
			return
		}
		src := clone(d.source)
		merge(src, req.Doc)
		nd := s.put(ix, id, src)
		out := docMeta(ix, id, nd)
		out["result"] = "updated"
		writeJSON(w, 200, out)
	case op == "_doc" && method == http.MethodDelete:
		if cond, ok := conditional(q, d); cond && !ok {
			conflictErr("required seqNo [" + q.Get("if_seq_no") + "], primary term [" + q.Get("if_primary_term") + "]")
			return
		}
		if d == nil {
			writeJSON(w, 404, map[string]any{"_index": indexName, "_id": id, "result": "not_found"})
			return
		}
		ix.seq++
		delete(ix.docs, id)
		writeJSON(w, 200, map[string]any{"_index": indexName, "_id": id, "_version": d.version + 1,
			"_seq_no": ix.seq, "_primary_term": s.primaryTerm, "result": "deleted"})
	default:
		writeError(w, 405, "illegal_argument_exception", "not supported by the fake")
	}
}

func (s *Server) mget(w http.ResponseWriter, q url.Values, body []byte) {
	var req struct {
		Docs []struct {
			Index string `json:"_index"`
			ID    string `json:"_id"`
		} `json:"docs"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, 400, "parse_exception", err.Error())
		return
	}
	source := q.Get("_source") != "false"
	s.mu.Lock()
	defer s.mu.Unlock()
	var docs []any
	for _, ref := range req.Docs {
		ix := s.indices[ref.Index]
		switch {
		case ix == nil:
			docs = append(docs, map[string]any{"_index": ref.Index, "_id": ref.ID,
				"error": map[string]any{"type": "index_not_found_exception", "reason": "no such index [" + ref.Index + "]"}})
		case ix.docs[ref.ID] == nil:
			docs = append(docs, map[string]any{"_index": ref.Index, "_id": ref.ID, "found": false})
		default:
			out := docMeta(ix, ref.ID, ix.docs[ref.ID])
			out["found"] = true
			if source {
				out["_source"] = ix.docs[ref.ID].source
			}
			docs = append(docs, out)
		}
	}
	writeJSON(w, 200, map[string]any{"docs": docs})
}

// match returns the indices a pattern names: a comma-separated list of
// names, each of which may hold * wildcards.
func (s *Server) match(pattern string) []*index {
	var out []*index
	for _, part := range strings.Split(pattern, ",") {
		for name, ix := range s.indices {
			if ok, _ := path.Match(part, name); ok {
				out = append(out, ix)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

type hit struct {
	ix *index
	id string
	d  *doc
}

func (s *Server) search(w http.ResponseWriter, pattern string, body []byte) {
	var req struct {
		Query           map[string]any            `json:"query"`
		Size            *int                      `json:"size"`
		From            int                       `json:"from"`
		Sort            []any                     `json:"sort"`
		SearchAfter     []any                     `json:"search_after"`
		SeqNoTerm       bool                      `json:"seq_no_primary_term"`
		Source          any                       `json:"_source"`
		Aggs            map[string]map[string]any `json:"aggs"`
		Aggregations    map[string]map[string]any `json:"aggregations"`
		TrackTotalHits  any                       `json:"track_total_hits"`
		IncludeVersions bool                      `json:"version"`
	}
	if len(body) > 0 {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		if err := dec.Decode(&req); err != nil {
			writeError(w, 400, "parse_exception", err.Error())
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var hits []hit
	for _, ix := range s.match(pattern) {
		for id, d := range ix.docs {
			if matches(req.Query, id, d.source) {
				hits = append(hits, hit{ix, id, d})
			}
		}
	}
	keys := sortKeys(req.Sort)
	sort.Slice(hits, func(i, j int) bool {
		return compareHits(keys, hits[i], hits[j]) < 0
	})
	total := len(hits)
	if len(req.SearchAfter) > 0 && len(keys) > 0 {
		var rest []hit
		for _, h := range hits {
			if compareToAfter(keys, h, req.SearchAfter) > 0 {
				rest = append(rest, h)
			}
		}
		hits = rest
	}
	size := 10
	if req.Size != nil {
		size = *req.Size
	}
	if req.From > 0 {
		hits = hits[min(req.From, len(hits)):]
	}
	if len(hits) > size {
		hits = hits[:size]
	}
	source := true
	if b, ok := req.Source.(bool); ok {
		source = b
	}
	out := []any{}
	for _, h := range hits {
		m := map[string]any{"_index": h.ix.name, "_id": h.id, "_score": 1.0}
		if req.SeqNoTerm {
			m["_seq_no"], m["_primary_term"] = h.d.seqNo, h.d.primaryTerm
		}
		m["_version"] = h.d.version
		if source {
			m["_source"] = h.d.source
		}
		if len(keys) > 0 {
			var sv []any
			for _, k := range keys {
				sv = append(sv, sortValue(k.field, h))
			}
			m["sort"] = sv
		}
		out = append(out, m)
	}
	resp := map[string]any{"took": 1, "timed_out": false,
		"hits": map[string]any{"total": map[string]any{"value": total, "relation": "eq"}, "hits": out}}
	aggs := req.Aggs
	if aggs == nil {
		aggs = req.Aggregations
	}
	if len(aggs) > 0 {
		res := map[string]any{}
		var all []hit
		for _, ix := range s.match(pattern) {
			for id, d := range ix.docs {
				if matches(req.Query, id, d.source) {
					all = append(all, hit{ix, id, d})
				}
			}
		}
		for name, a := range aggs {
			if mx, ok := a["max"].(map[string]any); ok {
				field, _ := mx["field"].(string)
				var best *float64
				for _, h := range all {
					if f, ok := toFloat(lookup(h.d.source, field)); ok && (best == nil || f > *best) {
						best = &f
					}
				}
				if best == nil {
					res[name] = map[string]any{"value": nil}
				} else {
					res[name] = map[string]any{"value": *best}
				}
			}
		}
		resp["aggregations"] = res
	}
	writeJSON(w, 200, resp)
}

func (s *Server) byQuery(w http.ResponseWriter, pattern, op string, body []byte) {
	var req struct {
		Query map[string]any `json:"query"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	_ = dec.Decode(&req)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blocked {
		s.blockedError(w, pattern)
		return
	}
	n := 0
	for _, ix := range s.match(pattern) {
		for id, d := range ix.docs {
			if !matches(req.Query, id, d.source) {
				continue
			}
			n++
			if op == "_delete_by_query" {
				ix.seq++
				delete(ix.docs, id)
			}
		}
	}
	key := map[string]string{"_delete_by_query": "deleted", "_update_by_query": "updated"}[op]
	writeJSON(w, 200, map[string]any{"took": 1, "total": n, key: n, "failures": []any{}})
}

func (s *Server) bulk(w http.ResponseWriter, body []byte) {
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	s.mu.Lock()
	defer s.mu.Unlock()
	var items []any
	errs := false
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var action map[string]struct {
			Index string `json:"_index"`
			ID    string `json:"_id"`
		}
		if err := json.Unmarshal(line, &action); err != nil {
			writeError(w, 400, "parse_exception", err.Error())
			return
		}
		if !sc.Scan() {
			break
		}
		src, err := decodeObject(sc.Bytes())
		for op, meta := range action {
			res := map[string]any{"_index": meta.Index, "status": 201}
			switch {
			case err != nil:
				res["status"], res["error"] = 400, map[string]any{"type": "mapper_parsing_exception", "reason": err.Error()}
				errs = true
			case s.blocked:
				res["status"], res["error"] = 429, map[string]any{"type": "cluster_block_exception", "reason": "disk usage exceeded flood-stage watermark"}
				errs = true
			default:
				ix := s.ensure(meta.Index)
				id := meta.ID
				if id == "" {
					s.autoID++
					id = fmt.Sprintf("auto-%d", s.autoID)
				}
				if op == "create" && ix.docs[id] != nil {
					res["status"], res["error"] = 409, map[string]any{"type": "version_conflict_engine_exception", "reason": "document already exists"}
					errs = true
					break
				}
				d := s.put(ix, id, src)
				res["_id"], res["_seq_no"], res["_primary_term"], res["_version"] = id, d.seqNo, d.primaryTerm, d.version
			}
			items = append(items, map[string]any{op: res})
		}
	}
	writeJSON(w, 200, map[string]any{"took": 1, "errors": errs, "items": items})
}

func decodeObject(b []byte) (map[string]any, error) {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("the document is not a JSON object")
	}
	return m, nil
}

// clone copies a document deeply enough that later changes do not reach
// the copy.
func clone(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	b, _ := json.Marshal(m)
	out, _ := decodeObject(b)
	return out
}

// merge merges a partial document into dst, objects field by field, as
// _update does.
func merge(dst, src map[string]any) {
	for k, v := range src {
		if sub, ok := v.(map[string]any); ok {
			if cur, ok := dst[k].(map[string]any); ok {
				merge(cur, sub)
				continue
			}
		}
		dst[k] = v
	}
}

// lookup returns a field of a source by its dotted path.
func lookup(src map[string]any, field string) any {
	if v, ok := src[field]; ok {
		return v
	}
	cur := any(src)
	for _, part := range strings.Split(field, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return cur
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// compareValues orders two field values: numbers as numbers, times as
// times, anything else as text.
func compareValues(a, b any) int {
	fa, oka := toFloat(a)
	fb, okb := toFloat(b)
	if oka && okb {
		switch {
		case fa < fb:
			return -1
		case fa > fb:
			return 1
		}
		return 0
	}
	sa, sb := fmt.Sprint(a), fmt.Sprint(b)
	ta, erra := time.Parse(time.RFC3339Nano, sa)
	tb, errb := time.Parse(time.RFC3339Nano, sb)
	if erra == nil && errb == nil {
		return ta.Compare(tb)
	}
	return strings.Compare(sa, sb)
}

func equalValues(a, b any) bool {
	if list, ok := a.([]any); ok {
		for _, v := range list {
			if equalValues(v, b) {
				return true
			}
		}
		return false
	}
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return compareValues(a, b) == 0
}

// matches reports whether a document matches a query.
func matches(q map[string]any, id string, src map[string]any) bool {
	if len(q) == 0 {
		return true
	}
	for kind, arg := range q {
		m, _ := arg.(map[string]any)
		switch kind {
		case "match_all":
		case "term":
			for field, v := range m {
				if inner, ok := v.(map[string]any); ok {
					v = inner["value"]
				}
				if field == "_id" {
					if fmt.Sprint(v) != id {
						return false
					}
					continue
				}
				if !equalValues(lookup(src, field), v) {
					return false
				}
			}
		case "terms":
			for field, v := range m {
				list, _ := v.([]any)
				ok := false
				for _, want := range list {
					if field == "_id" && fmt.Sprint(want) == id || field != "_id" && equalValues(lookup(src, field), want) {
						ok = true
						break
					}
				}
				if !ok {
					return false
				}
			}
		case "ids":
			list, _ := m["values"].([]any)
			ok := false
			for _, want := range list {
				if fmt.Sprint(want) == id {
					ok = true
				}
			}
			if !ok {
				return false
			}
		case "exists":
			field, _ := m["field"].(string)
			if lookup(src, field) == nil {
				return false
			}
		case "range":
			for field, v := range m {
				bounds, _ := v.(map[string]any)
				got := lookup(src, field)
				if got == nil {
					return false
				}
				for op, b := range bounds {
					c := compareValues(got, b)
					switch op {
					case "gt":
						if c <= 0 {
							return false
						}
					case "gte":
						if c < 0 {
							return false
						}
					case "lt":
						if c >= 0 {
							return false
						}
					case "lte":
						if c > 0 {
							return false
						}
					}
				}
			}
		case "bool":
			list := func(k string) []map[string]any {
				var out []map[string]any
				switch v := m[k].(type) {
				case map[string]any:
					out = append(out, v)
				case []any:
					for _, it := range v {
						if mm, ok := it.(map[string]any); ok {
							out = append(out, mm)
						}
					}
				}
				return out
			}
			for _, sub := range append(list("must"), list("filter")...) {
				if !matches(sub, id, src) {
					return false
				}
			}
			for _, sub := range list("must_not") {
				if matches(sub, id, src) {
					return false
				}
			}
			if should := list("should"); len(should) > 0 {
				ok := false
				for _, sub := range should {
					if matches(sub, id, src) {
						ok = true
						break
					}
				}
				if !ok {
					return false
				}
			}
		default:
			// Unknown queries match nothing, so a test notices.
			return false
		}
	}
	return true
}

type sortKey struct {
	field string
	desc  bool
}

func sortKeys(raw []any) []sortKey {
	var out []sortKey
	for _, r := range raw {
		switch v := r.(type) {
		case string:
			out = append(out, sortKey{field: v})
		case map[string]any:
			for field, o := range v {
				desc := false
				switch ov := o.(type) {
				case string:
					desc = ov == "desc"
				case map[string]any:
					desc = ov["order"] == "desc"
				}
				out = append(out, sortKey{field: field, desc: desc})
			}
		}
	}
	return out
}

func sortValue(field string, h hit) any {
	switch field {
	case "_id":
		return h.id
	case "_seq_no":
		return h.d.seqNo
	case "_doc":
		return h.d.seqNo
	}
	v := lookup(h.d.source, field)
	if s, ok := v.(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UnixMilli()
		}
	}
	if f, ok := toFloat(v); ok {
		if f == math.Trunc(f) {
			return int64(f)
		}
		return f
	}
	return v
}

func compareHits(keys []sortKey, a, b hit) int {
	for _, k := range keys {
		c := compareValues(sortValue(k.field, a), sortValue(k.field, b))
		if k.desc {
			c = -c
		}
		if c != 0 {
			return c
		}
	}
	// Without a sort, keep a stable order: by index, then by id.
	if c := strings.Compare(a.ix.name, b.ix.name); c != 0 {
		return c
	}
	return strings.Compare(a.id, b.id)
}

func compareToAfter(keys []sortKey, h hit, after []any) int {
	for i, k := range keys {
		if i >= len(after) {
			break
		}
		c := compareValues(sortValue(k.field, h), after[i])
		if k.desc {
			c = -c
		}
		if c != 0 {
			return c
		}
	}
	return 0
}
