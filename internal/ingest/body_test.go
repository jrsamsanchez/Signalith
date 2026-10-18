package ingest

import (
	"strings"
	"testing"
)

func TestRecordIDsOfARequestShareAPrefix(t *testing.T) {
	a, b := bodySeed("t", []byte("one")), bodySeed("t", []byte("two"))
	a0, a1 := recordID(a, 0), recordID(a, 1)
	if a0 == a1 || a0 != recordID(a, 0) {
		t.Fatalf("ids %q %q", a0, a1)
	}
	// 14 seed bytes are 18 full base64 characters.
	if a0[:18] != a1[:18] || strings.HasPrefix(recordID(b, 0), a0[:18]) {
		t.Fatalf("prefixes %q %q %q", a0, a1, recordID(b, 0))
	}
	if len(a0) != 24 {
		t.Fatalf("length %d", len(a0))
	}
}
