package ingest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
)

// OTLP/JSON: the protobuf messages in the protobuf JSON mapping, with
// lowerCamelCase field names, 64-bit integers as strings, and trace and
// span IDs as hex rather than base64.

type otlpJSONRequest struct {
	ResourceLogs []struct {
		Resource struct {
			Attributes []otlpJSONKeyValue `json:"attributes"`
		} `json:"resource"`
		ScopeLogs []struct {
			Scope struct {
				Name string `json:"name"`
			} `json:"scope"`
			// Each record is decoded on its own, so its size and depth can
			// be checked first.
			LogRecords []json.RawMessage `json:"logRecords"`
		} `json:"scopeLogs"`
	} `json:"resourceLogs"`
}

type otlpJSONLogRecord struct {
	TimeUnixNano         json.RawMessage    `json:"timeUnixNano"`
	ObservedTimeUnixNano json.RawMessage    `json:"observedTimeUnixNano"`
	SeverityNumber       json.RawMessage    `json:"severityNumber"`
	SeverityText         string             `json:"severityText"`
	Body                 *otlpJSONAnyValue  `json:"body"`
	Attributes           []otlpJSONKeyValue `json:"attributes"`
	TraceID              string             `json:"traceId"`
	SpanID               string             `json:"spanId"`
	EventName            string             `json:"eventName"`
}

type otlpJSONKeyValue struct {
	Key   string            `json:"key"`
	Value *otlpJSONAnyValue `json:"value"`
}

type otlpJSONAnyValue struct {
	StringValue *string         `json:"stringValue"`
	BoolValue   *bool           `json:"boolValue"`
	IntValue    json.RawMessage `json:"intValue"`
	DoubleValue json.RawMessage `json:"doubleValue"`
	BytesValue  *string         `json:"bytesValue"`
	ArrayValue  *struct {
		Values []*otlpJSONAnyValue `json:"values"`
	} `json:"arrayValue"`
	KvlistValue *struct {
		Values []otlpJSONKeyValue `json:"values"`
	} `json:"kvlistValue"`
}

// maxJSONDepth is how deeply a JSON log record may nest: each level of
// AnyValue takes up to four JSON levels (kvlistValue, values, the entry,
// value).
const maxJSONDepth = 4*MaxDepth + 4

// walkOTLPJSON is walkOTLPProto for an OTLP/JSON request.
func walkOTLPJSON(body []byte, build bool, fn func(l *otlpLog, size int, bad *BodyError) error) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var req otlpJSONRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return badBody("invalid OTLP/JSON logs request: %v", err)
	}
	n := 0
	for _, rl := range req.ResourceLogs {
		var resource map[string]any
		if build {
			resource = map[string]any{}
		}
		if err := jsonKeyValues(rl.Resource.Attributes, resource, 1, build); err != nil {
			return err
		}
		for _, sl := range rl.ScopeLogs {
			for _, raw := range sl.LogRecords {
				n++
				l, bad := jsonLogRecord(raw, n, resource, sl.Scope.Name, build)
				if bad != nil {
					l = nil
				}
				if err := fn(l, len(raw), bad); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// jsonLogRecord decodes record n of the request, or says why it can't.
func jsonLogRecord(raw json.RawMessage, n int, resource map[string]any, scope string, build bool) (*otlpLog, *BodyError) {
	if len(raw) > MaxRecordBytes {
		return nil, tooLarge("log record %d is %d bytes; the limit is %d bytes (1 MB) per record", n, len(raw), MaxRecordBytes)
	}
	if d := depth(raw); d > maxJSONDepth {
		return nil, badBody("log record %d nests values too deeply", n)
	}
	var rec otlpJSONLogRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, badBody("invalid log record %d: %v", n, err)
	}
	var l *otlpLog
	if build {
		l = &otlpLog{resource: resource, scope: scope, sevText: rec.SeverityText, eventName: rec.EventName}
		l.time = jsonUint(rec.TimeUnixNano)
		l.observed = jsonUint(rec.ObservedTimeUnixNano)
		l.sevNum, _ = otlpInt(rec.SeverityNumber)
		l.traceID = jsonHexID(rec.TraceID)
		l.spanID = jsonHexID(rec.SpanID)
	}
	body, err := jsonAnyValue(rec.Body, 1, build)
	if err != nil {
		return nil, recordError(n, err)
	}
	var attrs map[string]any
	if build {
		l.body = body
		attrs = map[string]any{}
		l.attrs = attrs
	}
	if err := jsonKeyValues(rec.Attributes, attrs, 1, build); err != nil {
		return nil, recordError(n, err)
	}
	return l, nil
}

// recordError names record n in a value's error.
func recordError(n int, err error) *BodyError {
	status := http.StatusBadRequest
	if bad, ok := err.(*BodyError); ok {
		status = bad.Status
	}
	return &BodyError{Status: status, Msg: fmt.Sprintf("log record %d: %v", n, err)}
}

func jsonKeyValues(kvs []otlpJSONKeyValue, m map[string]any, depth int, build bool) error {
	for _, kv := range kvs {
		v, err := jsonAnyValue(kv.Value, depth, build)
		if err != nil {
			return err
		}
		if build {
			m[kv.Key] = v
		}
	}
	return nil
}

func jsonAnyValue(a *otlpJSONAnyValue, depth int, build bool) (any, error) {
	if depth > MaxDepth {
		return nil, badBody("a log record nests values more than %d levels deep", MaxDepth)
	}
	if a == nil {
		return nil, nil
	}
	switch {
	case a.StringValue != nil:
		return *a.StringValue, nil
	case a.BoolValue != nil:
		return *a.BoolValue, nil
	case len(a.IntValue) > 0:
		n, ok := otlpInt(a.IntValue)
		if !ok {
			return nil, badBody("invalid intValue %s", a.IntValue)
		}
		return n, nil
	case len(a.DoubleValue) > 0:
		var d float64
		if err := json.Unmarshal(a.DoubleValue, &d); err != nil {
			// "NaN", "Infinity" and "-Infinity": JSON has no such numbers.
			return nil, nil
		}
		if math.IsNaN(d) || math.IsInf(d, 0) {
			return nil, nil
		}
		return d, nil
	case a.BytesValue != nil:
		return *a.BytesValue, nil // base64, as sent
	case a.ArrayValue != nil:
		list := []any{}
		for _, v := range a.ArrayValue.Values {
			x, err := jsonAnyValue(v, depth+1, build)
			if err != nil {
				return nil, err
			}
			if build {
				list = append(list, x)
			}
		}
		return list, nil
	case a.KvlistValue != nil:
		var m map[string]any
		if build {
			m = map[string]any{}
		}
		if err := jsonKeyValues(a.KvlistValue.Values, m, depth+1, build); err != nil {
			return nil, err
		}
		return m, nil
	}
	return nil, nil
}

// jsonUint reads a 64-bit unsigned integer written as a string or a
// number; 0 when it is neither.
func jsonUint(raw json.RawMessage) uint64 {
	n, ok := otlpInt(raw)
	if !ok || n < 0 {
		return 0
	}
	return uint64(n)
}

// jsonHexID is a hex trace or span ID as in hexID, or "" when it is not
// hex.
func jsonHexID(s string) string {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return hexID(b)
}
