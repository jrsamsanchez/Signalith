// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package incontainer

import (
	"errors"
	"testing"
)

func TestDetect(t *testing.T) {
	cases := []struct {
		name   string
		goos   string
		env    map[string]string
		files  map[string]string
		expect bool
	}{
		{"bare Linux", "linux", nil, map[string]string{"/proc/1/cgroup": "0::/init.scope\n"}, false},
		{"Docker", "linux", nil, map[string]string{"/.dockerenv": ""}, true},
		{"Podman", "linux", nil, map[string]string{"/run/.containerenv": ""}, true},
		{"Kubernetes", "linux", map[string]string{"KUBERNETES_SERVICE_HOST": "10.96.0.1"}, nil, true},
		{"Helm chart", "linux", map[string]string{EnvVar: "1"}, nil, true},
		{"cgroup v1 containerd", "linux", nil, map[string]string{"/proc/1/cgroup": "12:pids:/kubepods/besteffort/pod1/abc\n"}, true},
		{"cgroup v2 in a container", "linux", nil, map[string]string{"/proc/1/cgroup": "0::/\n"}, false},
		{"forced off", "linux", map[string]string{EnvVar: "0", "KUBERNETES_SERVICE_HOST": "10.96.0.1"}, map[string]string{"/.dockerenv": ""}, false},
		{"other value ignored", "linux", map[string]string{EnvVar: "maybe"}, map[string]string{"/.dockerenv": ""}, true},
		{"Windows", "windows", map[string]string{"KUBERNETES_SERVICE_HOST": "10.96.0.1"}, nil, false},
		{"Windows, told", "windows", map[string]string{EnvVar: "true"}, nil, true},
	}
	for _, c := range cases {
		p := Probe{
			GOOS:   c.goos,
			Getenv: func(k string) string { return c.env[k] },
			Exists: func(path string) bool { _, ok := c.files[path]; return ok },
			ReadFile: func(path string) ([]byte, error) {
				if s, ok := c.files[path]; ok {
					return []byte(s), nil
				}
				return nil, errors.New("not found")
			},
		}
		if got := Detect(p); got != c.expect {
			t.Errorf("%s: %v, want %v", c.name, got, c.expect)
		}
	}
}
