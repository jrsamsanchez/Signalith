package api

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/netip"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/agenttokens"
	"github.com/jrsamsanchez/signalith/internal/clientaddr"
	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// otlpLogsRoute is where OpenTelemetry Collectors (the otlphttp exporter)
// and SDKs send logs over OTLP/HTTP. An exporter whose endpoint is
// https://<server>/api/otlp appends /v1/logs itself.
const otlpLogsRoute = "POST /api/otlp/v1/logs"

// handleOTLPLogs takes an OTLP/HTTP logs export (protobuf or JSON,
// optionally gzip-compressed) with the ingest token, as handleIngest takes
// an agent's batch. Answers follow OTLP/HTTP: an ExportLogsServiceResponse
// on success, and a google.rpc.Status otherwise, in the request's format.
// Failures a sender should retry (busy, OpenSearch down) are 503 with
// Retry-After, which the Collector honours; others are not retried.
func (s *Server) handleOTLPLogs(w http.ResponseWriter, r *http.Request) {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	isJSON := ct == "application/json"
	fail := func(status int, retry string, err error) {
		if retry != "" {
			w.Header().Set("Retry-After", retry)
		}
		writeOTLPStatus(w, isJSON, status, err.Error())
	}
	from := clientaddr.Parse(r.RemoteAddr)
	who, checked := s.tokens().Check(bearerToken(r))
	if checked != agenttokens.Valid {
		if status, _, msg, retry, ok := agentRefusal(checked); ok {
			if checked != agenttokens.NotLoaded {
				s.Pipeline.NoteRefused(from, ingest.RefusedRevoked)
			}
			fail(status, retry, errors.New(msg))
			return
		}
		s.Pipeline.NoteRefused(from, ingest.RefusedToken)
		fail(http.StatusUnauthorized, "", errors.New("missing or invalid agent token; send it as Authorization: Bearer <token>"))
		return
	}
	if ct != "application/x-protobuf" && !isJSON {
		fail(http.StatusUnsupportedMediaType, "", fmt.Errorf("content type %q is not OTLP/HTTP; send application/x-protobuf or application/json", ct))
		return
	}
	enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	if enc != "" && enc != "identity" && enc != "gzip" {
		fail(http.StatusUnsupportedMediaType, "", fmt.Errorf("compression %q is not supported; use gzip (compression: gzip in the Collector's otlphttp exporter) or none", enc))
		return
	}
	s.noteName(r)
	s.notePlainAgent(r)
	var res *ingest.Result
	if plaintextIngest(r) {
		defer func() {
			var hosts []string
			if res != nil {
				hosts = res.Hosts
			}
			s.Pipeline.NotePlaintext(from, hosts)
		}()
	}
	body, release, err := s.readBatch(w, r)
	if err != nil {
		fail(s.batchFailure(r, err))
		return
	}
	defer release()
	if enc == "gzip" {
		sender := netip.Addr{}
		if !clientaddr.Shared(from, s.Config.Server.SharedList()) {
			sender = clientaddr.Key(from)
		}
		var releaseRaw func()
		body, releaseRaw, err = gunzip(s.Pipeline, body, sender)
		if err != nil {
			fail(s.batchFailure(r, err))
			return
		}
		defer releaseRaw()
	}
	slot, err := s.Pipeline.Admit(r.Context(), ingestQueueWait)
	if err != nil {
		fail(http.StatusServiceUnavailable, "5", err)
		return
	}
	defer slot()
	res, err = s.Pipeline.IngestOTLP(withOrigin(r, ingest.IntakeOTLP, who), body, isJSON)
	if res != nil {
		s.tokens().Note(who.ID, from.String(), res.Indexed)
	}
	if err != nil {
		var bad *ingest.BodyError
		if errors.As(err, &bad) {
			fail(bad.Status, "", bad)
			return
		}
		s.Log.Error("OTLP ingest failed", "err", err, "bytes", len(body))
		fail(http.StatusServiceUnavailable, "5", errors.New("events could not be stored right now; try again later"))
		return
	}
	msg := ""
	if len(res.Errors) > 0 {
		msg = res.Errors[0].Reason
		s.Log.Warn("some events were rejected", "rejected", res.Rejected, "first", msg)
	}
	writeOTLPSuccess(w, isJSON, int64(res.Rejected), msg)
}

// gunzip decompresses a gzip body, taking the memory for the result from
// the pipeline's receive budget, as for any body (see ingest.ReadBody).
func gunzip(p *ingest.Pipeline, body []byte, sender netip.Addr) ([]byte, func(), error) {
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, nil, &ingest.BodyError{Status: http.StatusBadRequest, Msg: "the body is not valid gzip: " + err.Error()}
	}
	out, release, err := p.ReadBody(zr, sender, -1)
	if err != nil {
		var bad *ingest.BodyError
		switch {
		case errors.As(err, &bad):
			return nil, nil, &ingest.BodyError{Status: bad.Status, Msg: fmt.Sprintf("the request is larger than %d MB uncompressed; "+
				"send smaller batches (send_batch_max_size in the Collector's batch processor)", ingest.MaxBodyBytes>>20)}
		case errors.Is(err, ingest.ErrBusy), errors.Is(err, ingest.ErrSenderBusy):
			return nil, nil, &batchError{err: err}
		}
		return nil, nil, &ingest.BodyError{Status: http.StatusBadRequest, Msg: "the body is not valid gzip: " + err.Error()}
	}
	return out, release, nil
}

// writeOTLPSuccess writes an ExportLogsServiceResponse, with
// partial_success when some records were rejected.
func writeOTLPSuccess(w http.ResponseWriter, isJSON bool, rejected int64, msg string) {
	if isJSON {
		v := map[string]any{}
		if rejected > 0 {
			v["partialSuccess"] = map[string]any{"rejectedLogRecords": fmt.Sprint(rejected), "errorMessage": msg}
		}
		writeJSON(w, http.StatusOK, v)
		return
	}
	var b []byte
	if rejected > 0 {
		var ps []byte
		ps = pbVarintField(ps, 1, uint64(rejected))
		ps = pbBytesField(ps, 2, []byte(msg))
		b = pbBytesField(b, 1, ps)
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// writeOTLPStatus writes a failure as a google.rpc.Status, which the
// Collector logs.
func writeOTLPStatus(w http.ResponseWriter, isJSON bool, status int, msg string) {
	code := grpcCode(status)
	if isJSON {
		writeJSON(w, status, map[string]any{"code": code, "message": msg})
		return
	}
	var b []byte
	b = pbVarintField(b, 1, uint64(code))
	b = pbBytesField(b, 2, []byte(msg))
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// grpcCode is the gRPC status code for an HTTP status.
func grpcCode(status int) int {
	switch status {
	case http.StatusBadRequest, http.StatusUnsupportedMediaType:
		return 3 // INVALID_ARGUMENT
	case http.StatusUnauthorized:
		return 16 // UNAUTHENTICATED
	case http.StatusForbidden:
		return 7 // PERMISSION_DENIED
	case http.StatusRequestTimeout:
		return 4 // DEADLINE_EXCEEDED
	case http.StatusRequestEntityTooLarge:
		return 8 // RESOURCE_EXHAUSTED
	case http.StatusServiceUnavailable:
		return 14 // UNAVAILABLE
	}
	return 2 // UNKNOWN
}

func pbVarintField(b []byte, num int, v uint64) []byte {
	b = binary.AppendUvarint(b, uint64(num)<<3)
	return binary.AppendUvarint(b, v)
}

func pbBytesField(b []byte, num int, data []byte) []byte {
	b = binary.AppendUvarint(b, uint64(num)<<3|2)
	b = binary.AppendUvarint(b, uint64(len(data)))
	return append(b, data...)
}
