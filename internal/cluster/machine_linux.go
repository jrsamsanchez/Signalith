// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cluster

import (
	"os"
	"strings"
)

// machineID is this computer's id (/etc/machine-id), or "".
func machineID() string {
	for _, f := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(f); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return id
			}
		}
	}
	return ""
}
