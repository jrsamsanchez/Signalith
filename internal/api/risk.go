package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/query"
)

func (s *Server) routeRisk(api *router) {
	api.viewer("GET /api/lookups/context", s.handleLookupContext)
	api.viewer("GET /api/lookups/{kind}", s.handleGetLookup)
	// Replacing the asset or identity list is admin work.
	api.admin("PUT /api/lookups/{kind}", s.handlePutLookup)
	api.viewer("GET /api/risk", s.handleRiskObjects)
	api.viewer("GET /api/risk/object", s.handleRiskObject)
}

var errLookupsOff = errors.New("asset and identity lists are not configured on this server")

// lookupKind maps the URL to a list; "assets.csv" asks for a download.
func lookupKind(v string) (kind string, csv bool, ok bool) {
	kind, csv = strings.CutSuffix(v, ".csv")
	return kind, csv, kind == "assets" || kind == "identities"
}

func (s *Server) handleGetLookup(w http.ResponseWriter, r *http.Request) {
	if s.Assets == nil {
		writeError(w, http.StatusServiceUnavailable, errLookupsOff)
		return
	}
	kind, csv, ok := lookupKind(r.PathValue("kind"))
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("unknown list; use assets or identities"))
		return
	}
	if csv {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+kind+`.csv"`)
		_, _ = w.Write(s.Assets.CSV(kind))
		return
	}
	// The list is the user's own, followed by the rows the sample data
	// adds for its made-up hosts and users while it is loaded ("sample"
	// counts them). Those are not part of the user's list: they never
	// override it, are not in its CSV and go when the sample is removed.
	resp := map[string]any{}
	oa, oi := s.Assets.Overlay()
	if kind == "assets" {
		// Then the osquery hosts on the Endpoints page that the list does
		// not have ("found" counts them), which also come and go on their
		// own.
		found := s.Assets.Found()
		list := append(append(s.Assets.Assets(), oa...), found...)
		resp["count"], resp["columns"] = len(list), assets.AssetColumns
		resp["items"] = list[:min(len(list), 1000)]
		resp["sample"] = len(oa)
		resp["found"] = len(found)
	} else {
		list := append(s.Assets.Identities(), oi...)
		resp["count"], resp["columns"] = len(list), assets.IdentityColumns
		resp["items"] = list[:min(len(list), 1000)]
		resp["sample"] = len(oi)
	}
	writeJSON(w, http.StatusOK, resp)
}

// handlePutLookup replaces a list with uploaded CSV. Every bad line is
// reported and nothing is saved unless the whole file is valid.
func (s *Server) handlePutLookup(w http.ResponseWriter, r *http.Request) {
	if s.Assets == nil {
		writeError(w, http.StatusServiceUnavailable, errLookupsOff)
		return
	}
	kind, _, ok := lookupKind(r.PathValue("kind"))
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("unknown list; use assets or identities"))
		return
	}
	data, err := io.ReadAll(uploadBody(w, r))
	if err != nil {
		uploadFailed(w, err)
		return
	}
	var n int
	if kind == "assets" {
		n, err = s.Assets.SetAssets(data)
	} else {
		n, err = s.Assets.SetIdentities(data)
	}
	var pe *assets.ParseError
	if errors.As(err, &pe) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "the file has problems; nothing was saved", "lines": pe.Lines})
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.Log.Info("lookup list replaced", "list", kind, "entries", n, "by", userOf(r))
	writeJSON(w, http.StatusOK, map[string]any{"count": n})
}

func (s *Server) handleLookupContext(w http.ResponseWriter, r *http.Request) {
	if s.Assets == nil {
		writeError(w, http.StatusServiceUnavailable, errLookupsOff)
		return
	}
	c, ok := s.Assets.Lookup(r.URL.Query().Get("field"), r.URL.Query().Get("value"))
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("not in the asset or identity lists"))
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func sinceParam(r *http.Request, def string) (string, error) {
	v := strings.TrimPrefix(r.URL.Query().Get("since"), "-")
	if v == "" {
		v = def
	}
	if _, err := detect.ParseDuration(v); err != nil {
		return "", errors.New("since: " + err.Error())
	}
	return "-" + v, nil
}

// handleRiskObjects lists the users and systems with the most risk, like
// the ES Risk Analysis dashboard.
func (s *Server) handleRiskObjects(w http.ResponseWriter, r *http.Request) {
	since, err := sinceParam(r, "24h")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	q := &query.Query{Datamodel: datamodel.RiskModel, Earliest: since, Commands: []query.Command{
		&query.Stats{
			Aggs: []query.Agg{
				{Func: "sum", Field: "risk_score", Alias: "risk_score"},
				{Func: "count", Alias: "events"},
				{Func: "dc", Field: "detection_id", Alias: "detections"},
				{Func: "dc", Field: "mitre_tactic", Alias: "tactics"},
				{Func: "max", Field: "_time", Alias: "last_seen"},
			},
			By: []string{"risk_object", "risk_object_type"},
		},
		&query.Sort{Keys: []query.SortKey{{Field: "risk_score", Desc: true}}},
		&query.Head{N: 200},
	}}
	if t := r.URL.Query().Get("type"); t != "" {
		if !slices.Contains(detect.RiskObjectTypes, t) {
			writeError(w, http.StatusBadRequest, errors.New("type must be user, system or other"))
			return
		}
		q.Search = &query.Compare{Field: "risk_object_type", Op: "=", Value: t}
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	res, err := s.Engine.Execute(ctx, q)
	if err != nil {
		writeSearchError(w, err)
		return
	}
	for _, row := range res.Rows {
		if s.Assets == nil {
			break
		}
		obj, _ := row["risk_object"].(string)
		typ, _ := row["risk_object_type"].(string)
		field := "dest"
		if typ == "user" {
			field = "user"
		}
		if c, ok := s.Assets.Lookup(field, obj); ok {
			row["context"] = c
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"objects": res.Rows, "query": q.String()})
}

// handleRiskObject returns the risk events for one object, newest first.
func (s *Server) handleRiskObject(w http.ResponseWriter, r *http.Request) {
	since, err := sinceParam(r, "7d")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	obj, typ := r.URL.Query().Get("object"), r.URL.Query().Get("type")
	if obj == "" || !slices.Contains(detect.RiskObjectTypes, typ) {
		writeError(w, http.StatusBadRequest, errors.New("object and type (user, system or other) are required"))
		return
	}
	q := &query.Query{Datamodel: datamodel.RiskModel, Earliest: since, Search: &query.And{Children: []query.Expr{
		&query.Compare{Field: "risk_object", Op: "=", Value: obj},
		&query.Compare{Field: "risk_object_type", Op: "=", Value: typ},
	}}, Commands: []query.Command{&query.Head{N: 500}}}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	res, err := s.Engine.Execute(ctx, q)
	if err != nil {
		writeSearchError(w, err)
		return
	}
	total := 0.0
	for _, row := range res.Rows {
		if v, ok := toFloat(row["risk_score"]); ok {
			total += v
		}
	}
	resp := map[string]any{"events": res.Rows, "total": total, "query": q.String()}
	if s.Assets != nil {
		field := "dest"
		if typ == "user" {
			field = "user"
		}
		if c, ok := s.Assets.Lookup(field, obj); ok {
			resp["context"] = c
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	}
	return 0, false
}
