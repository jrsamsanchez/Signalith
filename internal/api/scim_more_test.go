// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/scim"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Each store error is answered as a SCIM error with its status.
func TestSCIMUserError(t *testing.T) {
	for _, c := range []struct {
		err  error
		code int
	}{
		{&scim.Error{Status: http.StatusBadRequest, ScimType: "invalidSyntax", Detail: "bad"}, http.StatusBadRequest},
		{users.ErrNotFound, http.StatusNotFound},
		{users.ErrExists, http.StatusConflict},
		{users.ErrNotSSO, http.StatusConflict},
		{users.ErrRename, http.StatusBadRequest},
		{&users.FieldError{Field: "email", Err: errors.New("not an address")}, http.StatusBadRequest},
		{errDown, http.StatusInternalServerError},
	} {
		w := httptest.NewRecorder()
		scimUserError(w, c.err)
		if w.Code != c.code {
			t.Errorf("%v: %d, want %d", c.err, w.Code, c.code)
		}
	}
}

// While the shared users cannot be changed, provisioning waits.
func TestSCIMWritable(t *testing.T) {
	sh := newReqShared()
	s := &Server{SharedUsers: &SharedUsers{}, Shared: sh}
	if w := httptest.NewRecorder(); !s.scimWritable(w) {
		t.Errorf("writable refused: %d", w.Code)
	}
	sh.set(func(f *reqShared) { f.paused = true })
	w := httptest.NewRecorder()
	if s.scimWritable(w) || w.Code != http.StatusServiceUnavailable {
		t.Errorf("paused: %d", w.Code)
	}
	if !(&Server{}).scimWritable(httptest.NewRecorder()) {
		t.Error("a server of its own refused")
	}
}
