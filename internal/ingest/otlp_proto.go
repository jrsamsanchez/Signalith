package ingest

import (
	"encoding/base64"
	"encoding/binary"
	"math"
	"strings"
	"unicode/utf8"
)

// A small reader for the protobuf messages of an OTLP logs request
// (opentelemetry/proto/collector/logs/v1/logs_service.proto and the
// logs, resource and common protos it uses). Only the fields Signalith
// reads are decoded; others are skipped, as protobuf requires.

const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5
)

// pbField is one field of a protobuf message: its number and wire type,
// and its value (val for varint and fixed types, data for bytes).
type pbField struct {
	num  int
	wire int
	val  uint64
	data []byte
}

// pbEach calls fn for each field of the message in b.
func pbEach(b []byte, fn func(f pbField) error) error {
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 || key>>3 == 0 || key>>3 > math.MaxInt32 {
			return badBody("invalid protobuf: bad field key")
		}
		b = b[n:]
		f := pbField{num: int(key >> 3), wire: int(key & 7)}
		switch f.wire {
		case wireVarint:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return badBody("invalid protobuf: bad varint")
			}
			f.val, b = v, b[n:]
		case wireFixed64:
			if len(b) < 8 {
				return badBody("invalid protobuf: truncated fixed64")
			}
			f.val, b = binary.LittleEndian.Uint64(b), b[8:]
		case wireFixed32:
			if len(b) < 4 {
				return badBody("invalid protobuf: truncated fixed32")
			}
			f.val, b = uint64(binary.LittleEndian.Uint32(b)), b[4:]
		case wireBytes:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return badBody("invalid protobuf: truncated field")
			}
			f.data, b = b[n:n+int(l)], b[n+int(l):]
		default:
			return badBody("invalid protobuf: unsupported wire type %d", f.wire)
		}
		if err := fn(f); err != nil {
			return err
		}
	}
	return nil
}

// walkOTLPProto calls fn for each log record of a protobuf
// ExportLogsServiceRequest, with the size of its encoding. Without build,
// it only checks the request (fn gets a nil record). A record that is over
// MaxRecordBytes, nests a value more than MaxDepth levels or doesn't
// decode is passed with a nil record and why (bad), so the caller can
// reject that record alone; an error in the rest of the request is
// returned.
func walkOTLPProto(body []byte, build bool, fn func(l *otlpLog, size int, bad *BodyError) error) error {
	n := 0
	return pbEach(body, func(f pbField) error {
		if f.num != 1 || f.wire != wireBytes { // resource_logs
			return nil
		}
		// resource (1) may come after scope_logs (2), so it is read first.
		var resource map[string]any
		err := pbEach(f.data, func(f pbField) error {
			if f.num == 1 && f.wire == wireBytes {
				return pbEach(f.data, func(f pbField) error {
					if f.num == 1 && f.wire == wireBytes { // Resource.attributes
						if build && resource == nil {
							resource = map[string]any{}
						}
						return pbKeyValue(f.data, resource, 1, build)
					}
					return nil
				})
			}
			return nil
		})
		if err != nil {
			return err
		}
		return pbEach(f.data, func(f pbField) error {
			if f.num != 2 || f.wire != wireBytes { // scope_logs
				return nil
			}
			scope := ""
			err := pbEach(f.data, func(f pbField) error {
				if f.num == 1 && f.wire == wireBytes { // InstrumentationScope
					return pbEach(f.data, func(f pbField) error {
						if f.num == 1 && f.wire == wireBytes {
							scope = pbString(f.data)
						}
						return nil
					})
				}
				return nil
			})
			if err != nil {
				return err
			}
			return pbEach(f.data, func(f pbField) error {
				if f.num != 2 || f.wire != wireBytes { // log_records
					return nil
				}
				n++
				if len(f.data) > MaxRecordBytes {
					return fn(nil, len(f.data), tooLarge("log record %d is %d bytes; the limit is %d bytes (1 MB) per record", n, len(f.data), MaxRecordBytes))
				}
				var l *otlpLog
				if build {
					l = &otlpLog{resource: resource, scope: scope}
				}
				if err := pbLogRecord(f.data, l); err != nil {
					return fn(nil, len(f.data), recordError(n, err))
				}
				return fn(l, len(f.data), nil)
			})
		})
	})
}

// pbLogRecord reads a LogRecord into l, or only checks it when l is nil.
func pbLogRecord(b []byte, l *otlpLog) error {
	build := l != nil
	return pbEach(b, func(f pbField) error {
		switch {
		case f.num == 1 && f.wire == wireFixed64 && build:
			l.time = f.val
		case f.num == 11 && f.wire == wireFixed64 && build:
			l.observed = f.val
		case f.num == 2 && f.wire == wireVarint && build:
			l.sevNum = int64(int32(f.val))
		case f.num == 3 && f.wire == wireBytes && build:
			l.sevText = pbString(f.data)
		case f.num == 5 && f.wire == wireBytes:
			v, err := pbAnyValue(f.data, 1, build)
			if build {
				l.body = v
			}
			return err
		case f.num == 6 && f.wire == wireBytes:
			if build && l.attrs == nil {
				l.attrs = map[string]any{}
			}
			var attrs map[string]any
			if build {
				attrs = l.attrs
			}
			return pbKeyValue(f.data, attrs, 1, build)
		case f.num == 9 && f.wire == wireBytes && build:
			l.traceID = hexID(f.data)
		case f.num == 10 && f.wire == wireBytes && build:
			l.spanID = hexID(f.data)
		case f.num == 12 && f.wire == wireBytes && build:
			l.eventName = pbString(f.data)
		}
		return nil
	})
}

// pbKeyValue reads a KeyValue into m, at nesting level depth.
func pbKeyValue(b []byte, m map[string]any, depth int, build bool) error {
	var key string
	var val any
	err := pbEach(b, func(f pbField) error {
		switch {
		case f.num == 1 && f.wire == wireBytes:
			key = pbString(f.data)
		case f.num == 2 && f.wire == wireBytes:
			v, err := pbAnyValue(f.data, depth, build)
			val = v
			return err
		}
		return nil
	})
	if err == nil && build {
		m[key] = val
	}
	return err
}

// pbAnyValue reads an AnyValue at nesting level depth (from 1).
func pbAnyValue(b []byte, depth int, build bool) (any, error) {
	if depth > MaxDepth {
		return nil, badBody("a log record nests values more than %d levels deep", MaxDepth)
	}
	var out any
	err := pbEach(b, func(f pbField) error {
		switch {
		case f.num == 1 && f.wire == wireBytes:
			out = pbString(f.data)
		case f.num == 2 && f.wire == wireVarint:
			out = f.val != 0
		case f.num == 3 && f.wire == wireVarint:
			out = int64(f.val)
		case f.num == 4 && f.wire == wireFixed64:
			d := math.Float64frombits(f.val)
			if math.IsNaN(d) || math.IsInf(d, 0) {
				out = nil // JSON, and so OpenSearch, has no such numbers
			} else {
				out = d
			}
		case f.num == 5 && f.wire == wireBytes: // ArrayValue
			var list []any
			err := pbEach(f.data, func(f pbField) error {
				if f.num != 1 || f.wire != wireBytes {
					return nil
				}
				v, err := pbAnyValue(f.data, depth+1, build)
				if build {
					list = append(list, v)
				}
				return err
			})
			if build {
				if list == nil {
					list = []any{}
				}
				out = list
			}
			return err
		case f.num == 6 && f.wire == wireBytes: // KeyValueList
			var m map[string]any
			if build {
				m = map[string]any{}
			}
			err := pbEach(f.data, func(f pbField) error {
				if f.num != 1 || f.wire != wireBytes {
					return nil
				}
				return pbKeyValue(f.data, m, depth+1, build)
			})
			out = m
			return err
		case f.num == 7 && f.wire == wireBytes:
			out = base64.StdEncoding.EncodeToString(f.data)
		}
		return nil
	})
	if !build {
		out = nil
	}
	return out, err
}

// pbString is a protobuf string, with invalid UTF-8 replaced so it can be
// stored.
func pbString(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return strings.ToValidUTF8(string(b), "\uFFFD")
}
