// Package deploy holds the install scripts a Signalith server hands to a
// new server joining it (Servers > Add a server), to a new network sensor
// (Add data > Network sensor > Set up a new sensor), and to a computer
// that gets the Signalith Agent (Add data > Signalith Agent).
package deploy

import (
	"embed"
	_ "embed"
)

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

// SensorInstallSH is deploy/sensor/install.sh, the network sensor's
// install script.
//
//go:embed sensor/install.sh
var SensorInstallSH []byte

// AgentInstallSH is deploy/agent/install.sh, the Signalith Agent's Linux
// install script.
//
//go:embed agent/install.sh
var AgentInstallSH []byte

// AgentInstallPS1 is deploy/agent/install.ps1, the Signalith Agent's
// Windows install script.
//
//go:embed agent/install.ps1
var AgentInstallPS1 []byte

// AgentInstallMacOS is deploy/agent/install-macos.sh, the Signalith
// Agent's macOS install script.
//
//go:embed agent/install-macos.sh
var AgentInstallMacOS []byte

// SensorUnits are the systemd units deploy/sensor/install.sh writes, and
// SensorCompose the Docker Compose file of its --docker option; the
// script carries copies of them, which a test checks agree.
//
//go:embed sensor/systemd
var SensorUnits embed.FS

//go:embed sensor/docker-compose.yml
var SensorCompose []byte

// SensorHelpers are the helper scripts deploy/sensor/install.sh writes to
// /usr/lib/signalith-sensor (the status line, the rules update, the
// capture port), also carried in the script.
//
//go:embed sensor/lib
var SensorHelpers embed.FS
