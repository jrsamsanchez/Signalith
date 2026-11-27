// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"errors"
	"strings"
	"testing"
)

func nested(n int) string {
	return strings.Repeat("[", n) + strings.Repeat("]", n)
}

// A resource nested too deeply, or that is not an object, refuses the
// whole request.
func TestOTLPJSONResourceRefusals(t *testing.T) {
	for name, body := range map[string]string{
		"too deep":      `{"resourceLogs":[{"resource":{"x":` + nested(maxJSONDepth+2) + `}}]}`,
		"not an object": `{"resourceLogs":[{"resource":5}]}`,
	} {
		err := walkOTLPJSON([]byte(body), true, func(*otlpLog, int, *BodyError) error { return nil })
		var be *BodyError
		if !errors.As(err, &be) || !strings.Contains(be.Error(), "resource") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A record nested too deeply, or with a bad value in its attributes or
// in a map in its body, is refused on its own; a body with no value is
// none.
func TestOTLPJSONRecordRefusals(t *testing.T) {
	bad := `{"key":"a","value":{"intValue":"zz"}}`
	for name, c := range map[string]struct{ rec, want string }{
		"too deep":              {`{"body":{"arrayValue":{"values":` + nested(maxJSONDepth+2) + `}}}`, "nests values too deeply"},
		"bad attribute":         {`{"attributes":[` + bad + `]}`, "invalid intValue"},
		"bad value in a kvlist": {`{"body":{"kvlistValue":{"values":[` + bad + `]}}}`, "invalid intValue"},
	} {
		body := `{"resourceLogs":[{"scopeLogs":[{"logRecords":[` + c.rec + `]}]}]}`
		var got *BodyError
		calls := 0
		err := walkOTLPJSON([]byte(body), true, func(_ *otlpLog, _ int, bad *BodyError) error {
			calls++
			got = bad
			return nil
		})
		if err != nil || calls != 1 || got == nil || !strings.Contains(got.Error(), c.want) {
			t.Errorf("%s: err %v, calls %d, record error %v", name, err, calls, got)
		}
	}
	var l *otlpLog
	err := walkOTLPJSON([]byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{}}]}]}]}`), true,
		func(x *otlpLog, _ int, bad *BodyError) error { l = x; return nil })
	if err != nil || l == nil || l.body != nil {
		t.Errorf("an empty body = %+v %v", l, err)
	}
}
