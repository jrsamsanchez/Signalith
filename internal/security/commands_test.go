package security

import "testing"

func TestDeployment(t *testing.T) {
	for _, c := range []struct {
		goos                                string
		docker, container, systemd, service bool
		id, label                           string
	}{
		{"linux", true, true, true, false, DeployDocker, "Docker container"},
		{"linux", false, true, false, false, DeployContainer, "Container"},
		{"linux", false, false, true, false, DeployLinuxSystemd, "Linux, systemd service"},
		{"linux", false, false, false, false, DeployLinux, "Linux, started by hand"},
		{"windows", false, false, false, true, DeployWindowsService, "Windows service"},
		{"windows", false, false, false, false, DeployWindows, "Windows, started by hand"},
		{"darwin", false, false, false, false, DeployOther, "macOS"},
		{"freebsd", false, false, false, false, DeployOther, "Freebsd"},
		{"", false, false, false, false, DeployOther, "Other"},
	} {
		id, label := Deployment(c.goos, c.docker, c.container, c.systemd, c.service)
		if id != c.id || label != c.label {
			t.Errorf("%+v: %s %q", c, id, label)
		}
	}
	if configArg(nil, "linux") != "" {
		t.Error("config arg without facts")
	}
}
