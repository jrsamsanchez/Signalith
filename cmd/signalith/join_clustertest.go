//go:build clustertest

package main

// The cluster tests join servers whose folders belong to the user that
// runs them (CI runs as an ordinary user): signalith join runs without
// root there. Release builds never have this tag.
func init() { joinAnyUser = true }
