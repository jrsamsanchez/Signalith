// Package deploy holds the install scripts a Signalith server hands to a
// new server joining it (Servers > Add a server).
package deploy

import _ "embed"

// InstallSH is deploy/linux/install.sh.
//
//go:embed linux/install.sh
var InstallSH []byte

// InstallPS1 is deploy/windows/install.ps1.
//
//go:embed windows/install.ps1
var InstallPS1 []byte

// SystemdUnit is deploy/systemd/signalith.service, which install.sh
// writes as it is (a test checks they agree).
//
//go:embed systemd/signalith.service
var SystemdUnit []byte
