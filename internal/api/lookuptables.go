package api

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/lookuptables"
)

func (s *Server) routeLookupTables(api *router) {
	api.viewer("GET /api/lookuptables", s.handleListLookupTables)
	api.viewer("GET /api/lookuptables/{name}", s.handleGetLookupTable)
	// Adding, replacing and deleting tables is admin work.
	api.admin("PUT /api/lookuptables/{name}", s.handlePutLookupTable)
	api.admin("DELETE /api/lookuptables/{name}", s.handleDeleteLookupTable)
}

var errLookupTablesOff = errors.New("lookup tables are not available on this server")

func (s *Server) lookupTables(w http.ResponseWriter) *lookuptables.Store {
	if s.Engine == nil || s.Engine.Lookups == nil {
		writeError(w, http.StatusServiceUnavailable, errLookupTablesOff)
		return nil
	}
	return s.Engine.Lookups
}

func (s *Server) handleListLookupTables(w http.ResponseWriter, r *http.Request) {
	st := s.lookupTables(w)
	if st == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tables": st.List(), "multi_server": s.severalServers()})
}

// maxLookupPreview is how many rows the page shows of a table.
const maxLookupPreview = 1000

func (s *Server) handleGetLookupTable(w http.ResponseWriter, r *http.Request) {
	st := s.lookupTables(w)
	if st == nil {
		return
	}
	name, csv := strings.CutSuffix(r.PathValue("name"), ".csv")
	t, ok := st.Get(name)
	if !ok {
		writeError(w, http.StatusNotFound, lookuptables.ErrNotFound)
		return
	}
	if csv {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
		_, _ = w.Write(t.CSV())
		return
	}
	resp := map[string]any{"table": t.Info(), "rows": t.Rows[:min(len(t.Rows), maxLookupPreview)]}
	writeJSON(w, http.StatusOK, resp)
}

// severalServers reports whether other servers share this one's OpenSearch.
// Their searches would not see a table kept on this server, so tables
// cannot change while there are several.
func (s *Server) severalServers() bool {
	return s.Cluster != nil && len(s.Cluster.Status().Servers) > 1
}

var errLookupTablesMulti = errors.New("lookup tables are kept on each server and are not yet shared between the servers of a cluster, " +
	"so they cannot be changed while there are several servers")

// handlePutLookupTable adds or replaces a table with uploaded CSV.
func (s *Server) handlePutLookupTable(w http.ResponseWriter, r *http.Request) {
	st := s.lookupTables(w)
	if st == nil {
		return
	}
	if s.severalServers() {
		writeError(w, http.StatusConflict, errLookupTablesMulti)
		return
	}
	name := r.PathValue("name")
	data, err := io.ReadAll(uploadBody(w, r))
	if err != nil {
		uploadFailed(w, err)
		return
	}
	t, err := st.Put(name, data)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.audit(r, "lookup table saved", "table", name, "rows", len(t.Rows), "columns", len(t.Columns))
	writeJSON(w, http.StatusOK, t.Info())
}

func (s *Server) handleDeleteLookupTable(w http.ResponseWriter, r *http.Request) {
	st := s.lookupTables(w)
	if st == nil {
		return
	}
	if s.severalServers() {
		writeError(w, http.StatusConflict, errLookupTablesMulti)
		return
	}
	name := r.PathValue("name")
	if err := st.Delete(name); errors.Is(err, lookuptables.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, "lookup table deleted", "table", name)
	w.WriteHeader(http.StatusNoContent)
}
