package store

import (
	"context"
	"errors"
	"testing"
)

func TestRetryConflicts(t *testing.T) {
	ctx := context.Background()
	tries := 0
	err := RetryConflicts(ctx, func() error {
		tries++
		if tries < 3 {
			return ErrConflict
		}
		return nil
	})
	if err != nil || tries != 3 {
		t.Errorf("= %v after %d tries", err, tries)
	}
	tries = 0
	if err := RetryConflicts(ctx, func() error { tries++; return ErrConflict }); !errors.Is(err, ErrConflict) || tries != ModifyTries {
		t.Errorf("constant conflicts = %v after %d tries", err, tries)
	}
	other := errors.New("refused")
	tries = 0
	if err := RetryConflicts(ctx, func() error { tries++; return other }); err != other || tries != 1 {
		t.Errorf("other error = %v after %d tries", err, tries)
	}
}

// TestWithoutConflicts: only "already stored" on a document sent with its
// own ID counts as written; every other error stays.
func TestWithoutConflicts(t *testing.T) {
	docs := []IndexedDoc{{Index: "x", ID: "a"}, {Index: "x"}, {Index: "x", ID: "c"}, {Index: "x", ID: "d"}}
	errs := []BulkItemError{
		{Pos: 0, Status: 409, Type: "version_conflict_engine_exception"}, // a retry of a write that went through
		{Pos: 1, Status: 409, Type: "version_conflict_engine_exception"}, // no ID: kept
		{Pos: 2, Status: 400, Type: "mapper_parsing_exception"},          // not a conflict: kept
		{Pos: 3, Type: "version_conflict_engine_exception"},              // conflict without a status
	}
	out, n := WithoutConflicts(errs, docs)
	if n != 2 || len(out) != 2 || out[0].Pos != 1 || out[1].Pos != 2 {
		t.Errorf("kept %+v, dropped %d", out, n)
	}
	if out, n := WithoutConflicts(nil, docs); out != nil || n != 0 {
		t.Errorf("no errors = %v %d", out, n)
	}
}
