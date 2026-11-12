// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package incontainer tells whether Signalith runs in a container, so the
// server, its Security page and its cluster identity don't take the
// container for the computer it runs on.
package incontainer

import (
	"os"
	"runtime"
	"strings"
	"sync"
)

// EnvVar, set to 1, says Signalith runs in a container, and set to 0 that
// it doesn't, whatever else says so. The Helm chart sets it, since
// Kubernetes' container runtimes (containerd, CRI-O) leave none of the
// files Docker and Podman do.
const EnvVar = "SIGNALITH_CONTAINER"

// Probe is how Detect looks at the system: the process environment, and
// files.
type Probe struct {
	GOOS     string
	Getenv   func(string) string
	Exists   func(string) bool
	ReadFile func(string) ([]byte, error)
}

// cgroupHints are what /proc/1/cgroup names under cgroup v1 when process 1
// runs in an application container (Docker, Podman, Kubernetes). Under
// cgroup v2 a container sees only "0::/".
var cgroupHints = []string{"kubepods", "/docker/", "/docker-", "containerd", "/crio-", "/libpod-"}

// systemHints are cgroup names of system containers (LXC, LXD, Proxmox):
// a whole Linux system with its own accounts, more like a virtual machine
// than an application container.
var systemHints = []string{"/lxc/"}

// Detect reports whether p describes a container: SIGNALITH_CONTAINER
// when it is set to 1 or 0; else on Linux, Docker's and Podman's marker
// files, the variable Kubernetes sets in every pod, or a container's
// control group for process 1 (a system container's too).
func Detect(p Probe) bool { return detect(p, true) }

// DetectApp is Detect for application containers only: an LXC, LXD or
// Proxmox system container, which has accounts of its own like any
// computer, is not one, unless SIGNALITH_CONTAINER says so. What relaxes
// a check because "no other account runs here" uses it.
func DetectApp(p Probe) bool { return detect(p, false) }

func detect(p Probe, system bool) bool {
	switch strings.ToLower(strings.TrimSpace(p.Getenv(EnvVar))) {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	}
	if p.GOOS != "linux" {
		return false
	}
	if p.Exists("/.dockerenv") || p.Exists("/run/.containerenv") {
		return true
	}
	if Kubernetes(p.Getenv) {
		return true
	}
	if b, err := p.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		for _, h := range cgroupHints {
			if strings.Contains(s, h) {
				return true
			}
		}
		for _, h := range systemHints {
			if system && strings.Contains(s, h) {
				return true
			}
		}
	}
	return false
}

// Kubernetes reports whether the environment is a Kubernetes pod's: the
// kubelet sets KUBERNETES_SERVICE_HOST in every container, whatever the
// pod's enableServiceLinks.
func Kubernetes(getenv func(string) string) bool {
	return getenv("KUBERNETES_SERVICE_HOST") != ""
}

// here is this process's Probe.
func here() Probe {
	return Probe{GOOS: runtime.GOOS, Getenv: os.Getenv, ReadFile: os.ReadFile, Exists: func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	}}
}

// Here reports whether this process runs in a container, looked up once.
var Here = sync.OnceValue(func() bool { return Detect(here()) })

// AppHere reports whether this process runs in an application container
// (DetectApp), looked up once.
var AppHere = sync.OnceValue(func() bool { return DetectApp(here()) })
