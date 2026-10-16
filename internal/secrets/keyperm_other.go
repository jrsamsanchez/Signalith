//go:build !unix

package secrets

import "os"

// keyFileWarning has nothing to check here: on Windows the key file's
// access list is set when it is made (see package securefile), and the
// default key is also protected with DPAPI.
func keyFileWarning(string, os.FileInfo) string { return "" }

// fileWarning is keyFileWarning for any key file.
func fileWarning(string, string, os.FileInfo) string { return "" }

// accessHint says how to let Signalith read a key file it may not.
func accessHint(string) string {
	return "Run this in a PowerShell opened as Administrator; the service reads it as NT SERVICE\\Signalith"
}
