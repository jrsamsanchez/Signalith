// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package agentd

import "testing"

func TestWindowsDisplayName(t *testing.T) {
	for _, c := range []struct{ product, display, build, want string }{
		{"Windows 10 Pro", "24H2", "26100", "Windows 11 Pro 24H2 (build 26100)"},
		{"Windows 10 Enterprise", "22H2", "19045", "Windows 10 Enterprise 22H2 (build 19045)"},
		{"Windows Server 2022 Datacenter", "", "20348", "Windows Server 2022 Datacenter (build 20348)"},
		{"", "24H2", "26100", ""},
	} {
		if got := windowsDisplayName(c.product, c.display, c.build); got != c.want {
			t.Errorf("%q %q %q = %q, want %q", c.product, c.display, c.build, got, c.want)
		}
	}
	if windowsName() == "" {
		t.Error("windowsName is empty on Windows")
	}
}
