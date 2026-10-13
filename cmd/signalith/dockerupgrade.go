package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Whether a Docker quick start was upgraded from one whose agents all send
// the example ingest token change-this-ingest-token over plain HTTP, and
// so may still accept it from them, is decided once and kept in the state
// folder (see config.Config.OldToken).

// Timings of that decision; tests shorten them.
var (
	// dockerUpgradeWait is how long the first start of a version with
	// this decision waits for OpenSearch to answer before the server
	// starts anyway. Docker Compose starts Signalith once OpenSearch is
	// healthy, so it rarely waits at all.
	dockerUpgradeWait = 60 * time.Second
	// dockerUpgradeRetry is how often it asks OpenSearch again until it
	// answers.
	dockerUpgradeRetry = 5 * time.Second
	// dockerUpgradeLater is how often a server that started undecided
	// asks again.
	dockerUpgradeLater = 30 * time.Second
	// dockerUpgradeAsk bounds each question to OpenSearch.
	dockerUpgradeAsk = 15 * time.Second
)

// indexLister is the part of the OpenSearch client the decision uses.
type indexLister interface {
	Do(ctx context.Context, method, path string, body, out any) error
}

// decideDockerUpgrade decides whether the Docker quick start was upgraded
// from a version whose agents send the example ingest token, from
// OpenSearch's own record of when it made each of Signalith's event
// indices (<prefix>-*): one made before setup, the time the quick
// start's setup step first ran, can only come from an older quick start,
// which had no setup step.
//
// Everything that stores events on an install that starts new comes after
// setup, which runs before OpenSearch and Signalith start: the install's
// own agents, syslog, a quick test, and sample data, whose events are
// dated up to a week back but whose indices are made when it loads. None
// of it can make a new install look upgraded, and nobody can reach its
// OpenSearch before then. That is also why the dates in the index names
// are not used.
func decideDockerUpgrade(ctx context.Context, cat indexLister, prefix string, setup, now time.Time) (*config.DockerUpgrade, error) {
	var rows []struct {
		Index   string `json:"index"`
		Created string `json:"creation.date"`
	}
	path := "/_cat/indices/" + url.PathEscape(prefix+"-*") + "?format=json&h=index,creation.date&expand_wildcards=open,closed"
	if err := cat.Do(ctx, http.MethodGet, path, nil, &rows); err != nil {
		var oe *store.Error
		if !errors.As(err, &oe) || oe.Status != http.StatusNotFound {
			return nil, err
		}
		rows = nil
	}
	u := &config.DockerUpgrade{Setup: setup.UTC(), Decided: now.UTC()}
	for _, r := range rows {
		ms, err := strconv.ParseInt(r.Created, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("OpenSearch gave no creation date for the index %s", r.Index)
		}
		made := time.UnixMilli(ms).UTC()
		if made.Before(setup) && (u.Index == "" || made.Before(u.IndexMade)) {
			u.Upgraded, u.Index, u.IndexMade = true, r.Index, made
		}
	}
	return u, nil
}

// bundledOpenSearch reports whether rawURL is the quick start's own
// OpenSearch, the compose service named opensearch, which every quick start
// has used. Only its indices can come from this install's older version:
// an OpenSearch shared with other servers, or one this install was moved
// to, can hold their events from before setup too.
func bundledOpenSearch(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && strings.EqualFold(u.Hostname(), "opensearch")
}

// dockerSetup returns when the Docker quick start's setup step first ran
// (see config.DockerSetupTime); tests replace it.
var dockerSetup = func() (time.Time, error) { return config.DockerSetupTime(os.Getenv) }

// errNoSetupTime means the decision cannot be made: asking again does not
// help.
var errNoSetupTime = errors.New("cannot tell when the Docker quick start's setup step first ran")

// decideDockerUpgradeOnce makes the decision for the Docker quick start
// whose config is c, keeps it in the state folder and logs it. The error
// is errNoSetupTime, or OpenSearch's when it did not answer.
func decideDockerUpgradeOnce(ctx context.Context, c *config.Config, cat indexLister, log *slog.Logger) (*config.DockerUpgrade, error) {
	setup, err := dockerSetup()
	if err != nil {
		log.Error("cannot tell when the Docker quick start's setup step first ran, so the example ingest token change-this-ingest-token stays refused", "err", err)
		return nil, errNoSetupTime
	}
	var u *config.DockerUpgrade
	if bundledOpenSearch(c.OpenSearch.URL) {
		actx, cancel := context.WithTimeout(ctx, dockerUpgradeAsk)
		u, err = decideDockerUpgrade(actx, cat, c.OpenSearch.IndexPrefix, setup, time.Now())
		cancel()
		if err != nil {
			return nil, err
		}
	} else {
		// Another server's events may be there from long before this
		// install, so they prove nothing about its agents.
		log.Info("this Docker quick start uses an OpenSearch other than its own, so it counts as started new", "opensearch", c.OpenSearch.URL)
		u = &config.DockerUpgrade{Setup: setup.UTC(), Decided: time.Now().UTC()}
	}
	dir := c.StateDir()
	if _, err := config.ReadDockerUpgrade(dir); err != nil {
		log.Warn("the decision about the example ingest token is made again", "err", err)
	}
	if err := config.WriteDockerUpgrade(dir, u); err != nil {
		// Used for this run all the same; made again at the next start.
		log.Error("could not keep the decision about the example ingest token in the state folder", "file", config.DockerUpgradeFileIn(dir), "err", err)
	}
	if u.Upgraded {
		log.Warn("this Docker quick start was upgraded from an older version, so its agents may still send the example ingest token change-this-ingest-token "+
			"over plain HTTP: it is accepted that way until agents on plain HTTP are refused (the Health page lists them)",
			"oldest_index", u.Index, "made", u.IndexMade, "setup", u.Setup)
	} else {
		log.Info("this Docker quick start started new, so the example ingest token change-this-ingest-token from older versions is refused", "setup", u.Setup)
	}
	return u, nil
}

// decideDockerUpgradeAtStart makes the decision before the server starts,
// asking OpenSearch for up to dockerUpgradeWait. It reports whether it
// decided.
func decideDockerUpgradeAtStart(ctx context.Context, c *config.Config, cat indexLister, log *slog.Logger) bool {
	until := time.Now().Add(dockerUpgradeWait)
	for tries := 1; ; tries++ {
		_, err := decideDockerUpgradeOnce(ctx, c, cat, log)
		switch {
		case err == nil:
			return true
		case errors.Is(err, errNoSetupTime):
			return false
		case tries == 1:
			log.Info("waiting for OpenSearch, to find out whether this Docker quick start was upgraded from an older version", "err", err)
		}
		if !time.Now().Before(until) {
			log.Warn("OpenSearch did not answer, so Signalith starts before knowing whether this Docker quick start was upgraded from an older version. "+
				"Until it knows, it refuses agents on plain HTTP and the example ingest token change-this-ingest-token with an answer to try again later, "+
				"so they keep their events; it keeps asking", "waited", dockerUpgradeWait, "err", err)
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(dockerUpgradeRetry):
		}
	}
}

// settleDockerUpgrade runs with each start of the server's parts. A server
// that started undecided asks OpenSearch until it answers and puts the
// decision into use at once. Then, on an upgraded quick start started
// with agents on plain HTTP refused, the example token ends for good.
func settleDockerUpgrade(ctx context.Context, c *config.Config, cat indexLister, srv *api.Server, log *slog.Logger) {
	for c.OldToken() == config.OldTokenUndecided {
		u, err := decideDockerUpgradeOnce(ctx, c, cat, log)
		if err == nil {
			srv.UseDockerUpgrade(u)
			return
		}
		if errors.Is(err, errNoSetupTime) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(dockerUpgradeLater):
		}
	}
	srv.EndOldTokenIfRefused()
}
