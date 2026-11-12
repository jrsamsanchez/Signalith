// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

func hecStatus(t *testing.T, err error) (int, string) {
	t.Helper()
	var he *HECError
	if !errors.As(err, &he) {
		t.Fatalf("not a HEC error: %v", err)
	}
	return he.Status, he.Text
}

// A /raw body with a line too long, or too many lines, is refused whole;
// so is an /event body with too many events, too many indexed fields or
// a field holding a list of objects.
func TestHECLimits(t *testing.T) {
	p := &Pipeline{Store: &fakeBulk{}, Prefix: "sig", Now: func() time.Time { return now }}
	ctx := context.Background()

	long := append([]byte("ok\n"), bytes.Repeat([]byte("x"), MaxRecordBytes+1)...)
	if st, text := hecStatus(t, func() error { _, err := p.IngestHECRaw(ctx, long, HECMeta{}); return err }()); st != http.StatusRequestEntityTooLarge || !strings.Contains(text, "line 1 is") {
		t.Errorf("a long line = %d %q", st, text)
	}
	many := bytes.Repeat([]byte("x\n"), MaxRecords+1)
	if st, text := hecStatus(t, func() error { _, err := p.IngestHECRaw(ctx, many, HECMeta{}); return err }()); st != http.StatusRequestEntityTooLarge || !strings.Contains(text, "lines") {
		t.Errorf("too many lines = %d %q", st, text)
	}
	events := bytes.Repeat([]byte(`{"event":"x"}`), MaxRecords+1)
	if st, text := hecStatus(t, func() error { _, err := p.IngestHEC(ctx, events); return err }()); st != http.StatusRequestEntityTooLarge || !strings.Contains(text, "events") {
		t.Errorf("too many events = %d %q", st, text)
	}

	var fields []string
	for i := range 101 {
		fields = append(fields, fmt.Sprintf(`"f%d":"v"`, i))
	}
	for name, c := range map[string]struct{ body, want string }{
		"too many fields":   {`{"event":"x","fields":{` + strings.Join(fields, ",") + `}}`, "the limit is 100"},
		"a list of objects": {`{"event":"x","fields":{"a":[{"b":1}]}}`, `"a" of event 0`},
	} {
		_, err := p.IngestHEC(ctx, []byte(c.body))
		if st, text := hecStatus(t, err); st != http.StatusBadRequest || !strings.Contains(text, c.want) {
			t.Errorf("%s = %d %q", name, st, text)
		}
	}
	if len(p.Store.(*fakeBulk).docs) != 0 {
		t.Error("a refused request wrote events")
	}
}

// The callback's error stops a /raw walk; a write that fails fails the
// request.
func TestHECRawErrors(t *testing.T) {
	boom := errors.New("stop")
	if err := walkHECRaw([]byte("a\nb\n"), HECMeta{}, func(*hecItem) error { return boom }); !errors.Is(err, boom) {
		t.Errorf("walkHECRaw = %v", err)
	}
	b := &scriptedBulk{answers: []func([]store.IndexedDoc) ([]store.BulkItemError, error){
		func([]store.IndexedDoc) ([]store.BulkItemError, error) {
			return nil, &store.Error{Status: http.StatusServiceUnavailable, Body: "busy"}
		},
	}}
	p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}
	if _, err := p.IngestHECRaw(context.Background(), []byte("one\ntwo\n"), HECMeta{Host: "h"}); err == nil {
		t.Error("no error from a failed write")
	}
	if s := p.Stats(); s.Received != 2 || s.Failed != 2 {
		t.Errorf("stats = %+v", s)
	}
}
