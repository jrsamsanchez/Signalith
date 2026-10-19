package main

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

// Moving the background jobs on the Servers page asks the server that
// runs them to hand them to the one named, which then runs them.
func TestMoveTheBackgroundJobs(t *testing.T) {
	old := releaseDelay
	releaseDelay = 10 * time.Millisecond
	t.Cleanup(func() { releaseDelay = old })
	t.Setenv(clusterKeyFileEnv, "")
	fos := ostest.New(t)
	a := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, name: "siem-a"})
	eventually(t, "A founds the cluster and runs the jobs", func() bool { return a.r.sharedContent.on.Load() && a.r.node.RunsJobs() })
	giveKey(t, a)
	b := startRunnerWith(t, runOptions{scheduler: true, server: plainHTTP, os: fos, name: "siem-b"})
	eventually(t, "B joins", func() bool { return b.r.sharedContent.on.Load() })
	a.usersShared()
	bID := b.r.node.ID()
	eventually(t, "A sees B ready to take the jobs", func() bool {
		sv, ok := serverIn(a.r.node.Status(), bID)
		return ok && sv.State == cluster.StateReady && sv.Jobs == "standby" && sv.CannotTakeOver == ""
	})
	if _, ok := serverIn(a.r.node.Status(), "n_nobody"); ok {
		t.Error("serverIn found a server that is not there")
	}
	var code int
	var body map[string]any
	eventually(t, "the move is accepted", func() bool {
		var err error
		code, body, err = a.call("", "POST", "/api/cluster/jobs/move", `{"to":"`+bID+`"}`)
		return err == nil && code == http.StatusAccepted
	})
	if body["to"] != "siem-b" {
		t.Errorf("move: %v", body)
	}
	eventually(t, "B runs the jobs", func() bool { return b.r.node.RunsJobs() && !a.r.node.RunsJobs() })
	if !strings.Contains(a.logs.String(), "handing the background jobs to another server") {
		t.Errorf("A's log lacks the hand-over:\n%s", a.logs.String())
	}
}
