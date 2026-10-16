package api

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agents"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/onboard"
)

// Custom parsers bring in logs Signalith has no parser for: an admin
// pastes or uploads a sample on the Add data page, Signalith suggests how
// to read it, and the admin saves the parser (see docs/custom-logs.md).
// Every route is admin work: a parser changes how events are stored.

func (s *Server) routeParsers(api *router) {
	api.admin("GET /api/parsers", s.handleListParsers)
	api.admin("POST /api/parsers/analyze", s.handleAnalyzeSample)
	api.admin("POST /api/parsers/refine", s.handleRefineParser)
	api.admin("GET /api/parsers/{name}/input", s.handleParserInput)
	api.admin("PUT /api/parsers/{name}", s.handlePutParser)
	api.admin("DELETE /api/parsers/{name}", s.handleDeleteParser)
}

// localParsers is the registry of a server started without one: the
// parsers file in its state folder.
type localParsers struct {
	once sync.Once
	reg  *onboard.Registry
}

// parsers is where the custom parsers are kept and run.
func (s *Server) parsers() *onboard.Registry {
	if s.Parsers != nil {
		return s.Parsers
	}
	l := &s.localParsers
	l.once.Do(func() {
		path := ""
		if dir := s.conf().StateDir(); dir != "" {
			path = filepath.Join(dir, onboard.File)
		}
		l.reg = onboard.NewRegistry(onboard.NewFileStore(path))
	})
	return l.reg
}

func (s *Server) handleListParsers(w http.ResponseWriter, r *http.Request) {
	st := s.parsers().Store()
	resp := map[string]any{
		"parsers":      st.List(),
		"formats":      onboard.Formats,
		"models":       onboard.Models(),
		"time_formats": onboard.TimeFormats,
		"limits":       map[string]int{"sample_bytes": onboard.MaxSample, "sample_lines": onboard.MaxSampleLines, "ai_lines": onboard.AILines, "parsers": onboard.MaxParsers},
		"syslog":       s.Syslog != nil,
	}
	targets := map[string][]string{}
	for _, m := range onboard.Models() {
		targets[m] = onboard.MappingTargets(m)
	}
	resp["targets"] = targets
	if err := st.Err(); err != nil {
		resp["error"] = "The saved parsers could not be read: " + err.Error()
	}
	if m := s.model(); m != nil {
		resp["ai"] = map[string]any{"model": m.Name(), "sent_to": config.Origin(m.URL), "local": isLocalModel(m.URL)}
	}
	writeJSON(w, http.StatusOK, resp)
}

// sampleRequest is a sample to read, and the parser to read it with:
// none to have Signalith suggest one.
type sampleRequest struct {
	Sample string          `json:"sample"`
	Parser *onboard.Parser `json:"parser,omitempty"`
}

// sampleAnswer is what the page shows of a parser and a sample.
type sampleAnswer struct {
	Parser     onboard.Parser    `json:"parser"`
	Confidence string            `json:"confidence,omitempty"`
	Notes      []string          `json:"notes,omitempty"`
	Preview    *onboard.Preview  `json:"preview"`
	Coverage   *onboard.Coverage `json:"coverage,omitempty"`
	// Explanation is the AI model's, after a refine.
	Explanation string `json:"explanation,omitempty"`
	Tag         string `json:"tag"`
	// Exists says a saved parser already has the name.
	Exists bool `json:"exists"`
}

func (s *Server) readSample(w http.ResponseWriter, r *http.Request) (*sampleRequest, []string, bool) {
	var req sampleRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return nil, nil, false
	}
	if len(req.Sample) > onboard.MaxSample {
		req.Sample = req.Sample[:onboard.MaxSample]
	}
	lines := onboard.SplitSample(req.Sample)
	if len(lines) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("paste or upload a few lines of the log"))
		return nil, nil, false
	}
	return &req, lines, true
}

// handleAnalyzeSample suggests a parser for a sample, or tries the
// parser the admin edited, and previews the events and the detections
// that could use them.
func (s *Server) handleAnalyzeSample(w http.ResponseWriter, r *http.Request) {
	req, lines, ok := s.readSample(w, r)
	if !ok {
		return
	}
	now := time.Now()
	ans := sampleAnswer{}
	if req.Parser == nil {
		sug := onboard.Analyze(lines, now)
		ans.Parser, ans.Confidence, ans.Notes = sug.Parser, sug.Confidence, sug.Notes
		ans.Parser.Name = s.freeParserName(ans.Parser.Name)
	} else {
		ans.Parser = *req.Parser
	}
	s.answerSample(w, r, &ans, lines, now)
}

// freeParserName returns name, or name-2, name-3... when a saved parser
// has it already, so a suggestion does not replace one by accident.
func (s *Server) freeParserName(name string) string {
	st := s.parsers().Store()
	if _, taken := st.Get(name); !taken {
		return name
	}
	for i := 2; i < 100; i++ {
		n := name
		if suffix := "-" + strconv.Itoa(i); len(n)+len(suffix) > 48 {
			n = n[:48-len(suffix)] + suffix
		} else {
			n += suffix
		}
		if _, taken := st.Get(n); !taken && onboard.ValidName(n) {
			return n
		}
	}
	return name
}

// answerSample runs the parser on the sample and writes the answer.
func (s *Server) answerSample(w http.ResponseWriter, r *http.Request, ans *sampleAnswer, lines []string, now time.Time) {
	c, err := onboard.Compile(ans.Parser)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ans.Parser = c.P
	ans.Preview = c.Run(lines, now)
	ans.Tag = ans.Parser.Tag()
	if ans.Parser.Name != "" {
		_, ans.Exists = s.parsers().Store().Get(ans.Parser.Name)
	}
	if s.Detections != nil {
		ans.Coverage = onboard.MatchDetections(s.Detections.List(), c.P.Model, c.P.Sourcetype, ans.Preview.Docs)
	}
	writeJSON(w, http.StatusOK, ans)
}

// refines counts the AI refines running on this server; maxRefines is
// how many may run at once.
var refines atomic.Int32

const maxRefines = 2

// handleRefineParser asks the AI model to improve a parser for the
// sample. It sends the sample's first lines (onboard.AISample) to the
// model the admin set up, as the page says before the admin asks.
func (s *Server) handleRefineParser(w http.ResponseWriter, r *http.Request) {
	m := s.model()
	if m == nil {
		writeError(w, http.StatusConflict, errors.New("no AI model is set up; an admin sets one up in Settings, under AI assistant"))
		return
	}
	req, lines, ok := s.readSample(w, r)
	if !ok {
		return
	}
	if req.Parser == nil {
		writeError(w, http.StatusBadRequest, errors.New("send the parser to improve"))
		return
	}
	if refines.Add(1) > maxRefines {
		refines.Add(-1)
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusServiceUnavailable, errors.New("the AI model is already working on other samples; try again shortly"))
		return
	}
	defer refines.Add(-1)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	sent := len(onboard.AISample(lines))
	s.audit(r, "log sample sent to the AI model", "lines", sent, "model", m.Name(), "sent_to", config.Origin(m.URL))
	p, why, err := onboard.Refine(ctx, m, lines, *req.Parser)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	ans := sampleAnswer{Parser: p, Explanation: why}
	s.answerSample(w, r, &ans, lines, time.Now())
}

// handleParserInput returns the Fluent Bit input that reads log files
// for a parser, to add to an agent's configuration.
func (s *Server) handleParserInput(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !onboard.ValidName(name) {
		writeError(w, http.StatusBadRequest, errors.New("not a parser name"))
		return
	}
	q := r.URL.Query()
	hostOS := q.Get("os")
	if hostOS == "" {
		hostOS = "linux"
	}
	var paths []string
	for _, p := range strings.Split(q.Get("paths"), "\n") {
		if p = strings.TrimSpace(p); p != "" {
			paths = append(paths, p)
		}
	}
	p := onboard.Parser{Name: name}
	conf, err := agents.CustomInput(p.Tag(), name, hostOS, paths)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"input": conf, "tag": p.Tag()})
}

func (s *Server) handlePutParser(w http.ResponseWriter, r *http.Request) {
	var p onboard.Parser
	if err := readJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	p.Name = r.PathValue("name")
	p.Normalize()
	if err := p.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	st := s.parsers().Store()
	_, existed := st.Get(p.Name)
	if err := st.Put(r.Context(), p, userOf(r)); err != nil {
		var in *onboard.InputError
		if errors.As(err, &in) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	verb := "custom parser added"
	if existed {
		verb = "custom parser changed"
	}
	s.audit(r, verb, "parser", p.Name, "sourcetype", p.Sourcetype, "model", p.Model, "format", p.Format)
	saved, _ := st.Get(p.Name)
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleDeleteParser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := s.parsers().Store().Delete(r.Context(), name, userOf(r))
	switch {
	case errors.Is(err, onboard.ErrNotFound):
		writeError(w, http.StatusNotFound, err)
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "custom parser deleted", "parser", name)
	w.WriteHeader(http.StatusNoContent)
}
