// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
)

// pbEach refuses each kind of damaged protobuf with a body error.
func TestPBEachRefusals(t *testing.T) {
	for name, b := range map[string][]byte{
		"field zero":        {0x00},
		"bad key":           {0x80},
		"bad varint":        {0x08, 0x80},
		"short fixed64":     {0x09, 1, 2, 3},
		"short fixed32":     {0x0d, 1, 2},
		"short bytes":       {0x0a, 5, 1},
		"unsupported wire3": {0x0b},
	} {
		err := pbEach(b, func(pbField) error { return nil })
		var be *BodyError
		if !errors.As(err, &be) || !strings.Contains(be.Error(), "invalid protobuf") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The callback's error stops the walk.
	boom := errors.New("stop")
	if err := pbEach([]byte{0x08, 1}, func(pbField) error { return boom }); !errors.Is(err, boom) {
		t.Errorf("callback error = %v", err)
	}
}

func fixed64(num int, v uint64) []byte {
	b := binary.AppendUvarint(nil, uint64(num<<3|wireFixed64))
	return binary.LittleEndian.AppendUint64(b, v)
}

func bytesField(num int, data []byte) []byte {
	b := binary.AppendUvarint(nil, uint64(num<<3|wireBytes))
	b = binary.AppendUvarint(b, uint64(len(data)))
	return append(b, data...)
}

func TestPBAnyValueKinds(t *testing.T) {
	if v, err := pbAnyValue(fixed64(4, math.Float64bits(math.NaN())), 1, true); err != nil || v != nil {
		t.Errorf("NaN = %v %v", v, err)
	}
	if v, err := pbAnyValue(fixed64(4, math.Float64bits(2.5)), 1, true); err != nil || v != 2.5 {
		t.Errorf("2.5 = %v %v", v, err)
	}
	// An empty array, and an array with an entry of another field.
	if v, err := pbAnyValue(bytesField(5, nil), 1, true); err != nil || !reflect.DeepEqual(v, []any{}) {
		t.Errorf("empty array = %#v %v", v, err)
	}
	other := []byte{0x10, 1} // field 2, varint
	if v, err := pbAnyValue(bytesField(5, other), 1, true); err != nil || !reflect.DeepEqual(v, []any{}) {
		t.Errorf("array of another field = %#v %v", v, err)
	}
	if v, err := pbAnyValue(bytesField(6, other), 1, true); err != nil || !reflect.DeepEqual(v, map[string]any{}) {
		t.Errorf("kvlist of another field = %#v %v", v, err)
	}
	if v, err := pbAnyValue(bytesField(7, []byte{1, 2}), 1, true); err != nil || v != "AQI=" {
		t.Errorf("bytes = %#v %v", v, err)
	}
	if v, err := pbAnyValue(bytesField(1, []byte("ok")), 1, false); err != nil || v != nil {
		t.Errorf("without build = %#v %v", v, err)
	}
	if v, err := pbAnyValue(nil, MaxDepth+1, true); err == nil {
		t.Errorf("too deep = %#v", v)
	}
	if got := pbString([]byte("a\xffb")); got != "a�b" {
		t.Errorf("pbString = %q", got)
	}
}

func TestOktaRecordForms(t *testing.T) {
	ev := `{"uuid": "u1", "published": "2026-10-11T11:00:00Z", "eventType": "user.session.start", "actor": {"id": "a"}`
	if _, err := OktaRecords([]byte(ev + `, "x": }`)); err == nil {
		t.Error("a broken object")
	}
	if _, err := OktaRecords([]byte(`[` + ev + `}, ]`)); err == nil {
		t.Error("a broken array")
	}
	if got := oktaFromOTLP(decode(t, ev+`}`)); len(got) != 1 {
		t.Errorf("a map = %v", got)
	}
	if got := oktaFromOTLP(map[string]any{"x": 1}); got != nil {
		t.Errorf("another map = %v", got)
	}
	// A challenged sign-in, by an app named among its targets.
	e := Normalize(OktaTag, decode(t, ev+`, "outcome": {"result": "CHALLENGE"},
		"target": [{"type": "User", "displayName": "Bob"}, {"type": "AppInstance", "displayName": "Salesforce"}]}`), now)
	expect(t, e.Fields, map[string]any{"action": "pending", "app": "Salesforce"})
	if !OktaField("eventType") || OktaField("nonsense") {
		t.Error("OktaField")
	}
	if f, ok := OktaSigmaField("target.nothing.here"); ok {
		t.Logf("target.nothing.here kept as %q", f)
	}
}
