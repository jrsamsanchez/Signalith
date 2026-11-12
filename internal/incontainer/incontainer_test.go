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

// CRYPTO-06: an LXC, LXD or Proxmox system container is a container, but
// not an application one, so the master key check does not relax for it
// on that hint alone; Docker and Kubernetes still do.
func TestDetectApp(t *testing.T) {
	probe := func(env map[string]string, files map[string]string) Probe {
		return Probe{GOOS: "linux", Getenv: func(k string) string { return env[k] },
			Exists: func(path string) bool { _, ok := files[path]; return ok },
			ReadFile: func(path string) ([]byte, error) {
				if s, ok := files[path]; ok {
					return []byte(s), nil
				}
				return nil, errors.New("not found")
			}}
	}
	lxc := map[string]string{"/proc/1/cgroup": "12:pids:/lxc/101/init.scope\n"}
	if !Detect(probe(nil, lxc)) || DetectApp(probe(nil, lxc)) {
		t.Error("an LXC system container")
	}
	lxd := map[string]string{"/proc/1/cgroup": "0::/lxc.payload.web01/init.scope\n"}
	if DetectApp(probe(nil, lxd)) {
		t.Error("an LXD system container counted as an application container")
	}
	if !DetectApp(probe(map[string]string{EnvVar: "1"}, lxc)) {
		t.Error("SIGNALITH_CONTAINER=1 in an LXC container")
	}
	for name, p := range map[string]Probe{
		"Docker":     probe(nil, map[string]string{"/.dockerenv": ""}),
		"Kubernetes": probe(map[string]string{"KUBERNETES_SERVICE_HOST": "10.96.0.1"}, nil),
		"containerd": probe(nil, map[string]string{"/proc/1/cgroup": "12:pids:/kubepods/besteffort/pod1/abc\n"}),
	} {
		if !DetectApp(p) {
			t.Errorf("%s is not an application container", name)
		}
	}
}
