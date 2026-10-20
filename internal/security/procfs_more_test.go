// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

import "testing"

func TestProcAccount(t *testing.T) {
	fs := mapFS{files: map[string]string{
		"/proc/42/status": "Name:\tsignalith\nUid:\t1000\t998\t998\t998\nGid:\t1000\t997\t997\t997\nGroups:\nBad:\tx y\nUmask:\t0022\n",
		"/proc/43/status": "Name:\tsignalith\nUid:\t1000\tabc\t998\t998\n",
	}}
	if a, ok := procAccount(fs, "42"); !ok || a.UID != 998 || a.GID != 997 {
		t.Errorf("42 = %+v %v", a, ok)
	}
	if a, ok := procAccount(fs, "43"); ok || a.UID != -1 || a.GID != -1 {
		t.Errorf("43 = %+v %v", a, ok)
	}
	if _, ok := procAccount(fs, "44"); ok {
		t.Error("a process that is gone has an account")
	}
}
