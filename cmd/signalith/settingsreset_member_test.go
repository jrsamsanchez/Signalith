package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// signalith settings reset on a member whose settings are shared: the
// cluster's name, a name that is no setting, and a reset of every one of
// this server's own settings at once.
func TestSettingsResetOnMemberMore(t *testing.T) {
	fastSharedCheck(t)
	t.Setenv(clusterKeyFileEnv, "")
	rs := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP})
	rs.settingsShared()
	if code, out := rs.putSettings(`{"values":{"cluster.name":"Lab cluster","server.node_url":"http://siem.example:9000"}}`); code != http.StatusOK {
		t.Fatalf("save: %d %v", code, out)
	}
	path := filepath.Join(rs.dir, "signalith.yaml")
	eventually(t, "the server writes its copy of the shared settings", func() bool {
		_, err := os.Stat(shared.CachePath(config.StateDirFor(path)))
		return err == nil
	})

	if _, err := capture(t, func() error { return cmdSettings([]string{"reset", "-c", path, "no.such.setting"}) }); err == nil || !strings.Contains(err.Error(), "not a setting on the Settings page") {
		t.Errorf("an unknown setting: %v", err)
	}
	out, err := capture(t, func() error { return cmdSettings([]string{"reset", "-c", path, "cluster.name"}) })
	if err != nil || !strings.Contains(out, "Reset cluster.name for every server of the cluster") {
		t.Fatalf("reset of the cluster's name: %v\n%s", err, out)
	}
	eventually(t, "the cluster has no name again", func() bool {
		b, ok := rs.r.shared.Cluster().Get()
		return ok && b.Name == ""
	})
	// Without a name: every one of this server's own settings.
	out, err = capture(t, func() error { return cmdSettings([]string{"reset", "-c", path}) })
	if err != nil || !strings.Contains(out, "server.node_url") || !strings.Contains(out, "of this server's own settings") {
		t.Fatalf("reset of every own setting: %v\n%s", err, out)
	}
	if _, ok := nodeCfgOf(t, rs.os, rs).Values["server.node_url"]; ok {
		t.Error("server.node_url is still in the nodecfg document")
	}
	if _, err := capture(t, func() error { return cmdSettings([]string{"reset", "-c", path}) }); err == nil || !strings.Contains(err.Error(), "nothing was reset") {
		t.Errorf("a second reset of everything: %v", err)
	}
}
