// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeSystemctl makes systemctl show answer out (or fail with err).
func fakeSystemctl(t *testing.T, out string, err error) *[]string {
	t.Helper()
	var asked []string
	saved := systemctlShow
	systemctlShow = func(props ...string) ([]byte, error) {
		asked = append(asked, props...)
		return []byte(out), err
	}
	t.Cleanup(func() { systemctlShow = saved })
	return &asked
}

// monotonicMicros is the monotonic clock now, in microseconds, as systemd
// gives start times.
func monotonicMicros(t *testing.T) uint64 {
	t.Helper()
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		t.Fatal(err)
	}
	return uint64(now.Nano() / 1000)
}

func TestServiceStartedAfter(t *testing.T) {
	mono := monotonicMicros(t)
	hourAgo := mono - uint64(time.Hour/time.Microsecond)
	for _, c := range []struct {
		name  string
		out   string
		err   error
		since time.Time
		want  bool
		fails bool
	}{
		{"not running", "ActiveState=inactive\nExecMainStartTimestampMonotonic=0\n", nil, time.Now(), true, false},
		{"started after", fmt.Sprintf("ActiveState=active\nExecMainStartTimestampMonotonic=%d\n", hourAgo), nil, time.Now().Add(-2 * time.Hour), true, false},
		{"started before", fmt.Sprintf("ActiveState=activating\nExecMainStartTimestampMonotonic=%d\n", hourAgo), nil, time.Now().Add(-time.Minute), false, false},
		{"no start time", "ActiveState=reloading\n", nil, time.Now(), false, true},
		{"systemctl fails", "", errors.New("no systemd"), time.Now(), false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			asked := fakeSystemctl(t, c.out, c.err)
			got, err := serviceStartedAfter(c.since)
			if got != c.want || (err != nil) != c.fails {
				t.Errorf("got %v, %v", got, err)
			}
			if strings.Join(*asked, ",") != "ActiveState,ExecMainStartTimestampMonotonic" {
				t.Errorf("asked for %v", *asked)
			}
		})
	}
}

func TestServiceProcessAndSettingsFromSystemctl(t *testing.T) {
	fakeSystemctl(t, "MainPID=4242\n", nil)
	if got := serviceProcess(); got != "4242" {
		t.Errorf("pid %q", got)
	}
	fakeSystemctl(t, "MainPID=0\n", nil)
	if got := serviceProcess(); got != "" {
		t.Errorf("stopped: pid %q", got)
	}
	fakeSystemctl(t, "", errors.New("no systemd"))
	if got := serviceProcess(); got != "" {
		t.Errorf("no systemd: pid %q", got)
	}
	if s := platformServiceSettings(); s != nil {
		t.Errorf("settings without systemd: %+v", s)
	}
	fakeSystemctl(t, "ExecStart={ path=/usr/bin/signalith ; argv[]=/usr/bin/signalith serve -c /etc/signalith/signalith.yaml ; }\nEnvironment=SIGNALITH_STATE_DIR=/var/lib/signalith\nStateDirectory=signalith\n", nil)
	if s := platformServiceSettings(); s == nil {
		t.Error("no settings from systemctl")
	}
}
