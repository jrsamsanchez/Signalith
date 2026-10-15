package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/clusterinstall"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// joinTokenEnv is the join token a new Docker server is started with
// (deploy/docker/docker-compose.server.yml).
const joinTokenEnv = "SIGNALITH_JOIN"

// The program and the download limit belong to the process, so a restart
// in place keeps the limit's count.
var (
	installFiles = &clusterinstall.Files{}
	installGate  = &clusterinstall.Gate{}
)

// clusterInstall hands new servers the install scripts and this server's
// program (Servers > Add a server).
func clusterInstall() *api.ClusterInstall {
	return &api.ClusterInstall{Files: installFiles, Gate: installGate, Deployment: deployment()}
}

// joinFromEnv joins this server to a cluster with the token in
// SIGNALITH_JOIN, once: when its state folder has no cluster key yet. It
// runs "signalith join --no-start --yes -c <path>" as a child, which reads
// the token from SIGNALITH_JOIN (never from its command line), the same
// command as install.sh and install.ps1, and returns its failure, so the
// container stops with the reason and Docker starts it again (a token
// used by a join that failed after its checks then fails the same way,
// and the message says to make a new one). Later starts ignore the
// token.
func joinFromEnv(path string, log *slog.Logger) error {
	if os.Getenv(joinTokenEnv) == "" {
		return nil
	}
	// A new server has no config yet: join makes it.
	joined := os.Getenv(clusterKeyFileEnv) != ""
	if _, err := os.Stat(path); err == nil {
		c, err := config.Load(path)
		if err != nil {
			// loadConfig says what is wrong.
			return nil
		}
		joined = joined || len(shared.ClusterKeyFiles(c.StateDir())) > 0
	}
	if joined {
		log.Info(joinTokenEnv + " is ignored: this server has joined its cluster. Remove it from the .env file.")
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	log.Info("joining the cluster with the token in " + joinTokenEnv)
	cmd := exec.Command(exe, "join", "--no-start", "--yes", "-c", path)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return errors.New(joinFailed(exit.ExitCode()))
	}
	return err
}

// joinFailed says what a failed "signalith join" (exit code code) means
// for a server started with SIGNALITH_JOIN.
func joinFailed(code int) string {
	switch code {
	case 2, 3:
		return "the join was refused (see above); nothing was changed. Make a new token on Servers > Add a server, put it in SIGNALITH_JOIN and start again"
	case 4:
		return "this server is not ready to join (see above); nothing was changed. The token is used up: once the problem is fixed, make a new one on Servers > Add a server, put it in SIGNALITH_JOIN and start again"
	case 5:
		return "the join could not save its files, so it undid what it wrote (see above)"
	}
	return fmt.Sprintf("signalith join failed (exit code %d, see above)", code)
}
