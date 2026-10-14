package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/content"
)

// Content updates: newer content pack rules, signed by the Signalith
// project, checked for on the Detections page or uploaded there.
func (s *Server) routeContent(api *router) {
	api.viewer("GET /api/detections/content", s.handleContentStatus)
	api.admin("POST /api/detections/content/check", s.handleContentCheck)
	api.admin("POST /api/detections/content/upload", s.handleContentUpload)
	api.admin("DELETE /api/detections/content", s.handleContentRemove)
}

// RunContentUpdates checks for content updates every day while
// detections.content_updates is daily, until ctx ends.
func (s *Server) RunContentUpdates(ctx context.Context) {
	if s.Content == nil {
		return
	}
	s.Content.Run(ctx,
		func() bool { return s.conf().Detections.ContentUpdates == config.ContentDaily },
		func() string { return s.conf().Detections.ContentUpdateURL() })
}

var errContentOff = errors.New("content updates are not available on this server")

func (s *Server) contentReady(w http.ResponseWriter) bool {
	if s.Content == nil {
		writeError(w, http.StatusServiceUnavailable, errContentOff)
		return false
	}
	return true
}

// contentView is the status with the settings that go with it.
func (s *Server) contentView() map[string]any {
	c := s.conf()
	mode := c.Detections.ContentUpdates
	if mode == "" {
		mode = "manual"
	}
	return map[string]any{"status": s.Content.Status(), "mode": mode, "url": c.Detections.ContentUpdateURL()}
}

func (s *Server) handleContentStatus(w http.ResponseWriter, r *http.Request) {
	if !s.contentReady(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.contentView())
}

func (s *Server) handleContentCheck(w http.ResponseWriter, r *http.Request) {
	if !s.contentReady(w) {
		return
	}
	st, err := s.Content.Check(r.Context(), s.conf().Detections.ContentUpdateURL())
	s.audit(r, "content update check", "result", st.LastResult, "version", st.Version)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, s.contentView())
}

// maxContentUpload is the most an upload of a bundle and its signature
// takes.
const maxContentUpload = content.MaxBundle + 1<<16

func (s *Server) handleContentUpload(w http.ResponseWriter, r *http.Request) {
	if !s.contentReady(w) {
		return
	}
	allowSlowUpload(w)
	r.Body = http.MaxBytesReader(w, r.Body, maxContentUpload)
	if err := r.ParseMultipartForm(maxContentUpload); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("the upload is larger than %d MB", maxContentUpload>>20))
			return
		}
		writeError(w, http.StatusBadRequest, fmt.Errorf("send the bundle and its signature as a form with the files bundle and signature: %w", err))
		return
	}
	defer r.MultipartForm.RemoveAll()
	read := func(field string) ([]byte, error) {
		f, _, err := r.FormFile(field)
		if err != nil {
			return nil, fmt.Errorf("the %s file is missing", field)
		}
		defer f.Close()
		return io.ReadAll(f)
	}
	data, err := read("bundle")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sig, err := read("signature")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	st, err := s.Content.Install(data, sig)
	s.audit(r, "content update uploaded", "result", st.LastResult, "version", st.Version)
	switch {
	case errors.Is(err, content.ErrNotNewer):
		writeError(w, http.StatusConflict, fmt.Errorf("%w: this update is not newer than the rules in use", err))
	case err != nil:
		writeError(w, http.StatusBadRequest, err)
	default:
		writeJSON(w, http.StatusOK, s.contentView())
	}
}

func (s *Server) handleContentRemove(w http.ResponseWriter, r *http.Request) {
	if !s.contentReady(w) {
		return
	}
	_, err := s.Content.Remove()
	s.audit(r, "content update removed")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, s.contentView())
}
