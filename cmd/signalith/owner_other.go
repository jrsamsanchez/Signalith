//go:build !unix

package main

import "github.com/jrsamsanchez/signalith/internal/security"

// runningAsAdmin reports whether this process runs as an elevated
// Administrator.
func runningAsAdmin() bool { return security.Elevated() }

// serviceOwner: outside Unix the service's access comes from the folders'
// access lists (securefile and signalith service install).
func serviceOwner() (uid, gid int, ok bool) { return 0, 0, false }

// giveTree changes nothing outside Unix.
func giveTree(string, int, int, func(string, int, int) error) error { return nil }
