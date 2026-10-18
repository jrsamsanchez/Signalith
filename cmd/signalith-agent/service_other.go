//go:build !windows

package main

// runService is false: on Linux, systemd runs "signalith-agent run".
func runService() bool { return false }
