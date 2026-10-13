package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// The Docker quick start used to give every agent the same example ingest
// token, change-this-ingest-token, over plain HTTP, and anyone can look it
// up. Its docker-compose.yml no longer sets it, so it is not in
// ingest.tokens, but agents set up then still send it. Signalith accepts
// it from them only on a Docker quick start that was upgraded from such a
// version, only over plain HTTP, and only until agents on plain HTTP are
// refused; a quick start installed new refuses it like any wrong token.
//
// Whether this install was upgraded is decided once, on the first start
// of a version that has this file, from what OpenSearch held before the
// quick start's setup step first ran (see DockerUpgrade), and kept in the
// state folder. Nothing that reaches Signalith over the network can
// change the answer: it is never decided again while the file is there.

// dockerUpgradeFile, in the state folder, keeps that decision.
const dockerUpgradeFile = "docker-upgrade.json"

// DockerSecretsDir is where the Docker quick start's setup step puts the
// secrets Signalith reads: SIGNALITH_ADMIN_PASSWORD_FILE and
// SIGNALITH_INGEST_TOKEN_FILE point into it.
const DockerSecretsDir = "/run/signalith-secrets/"

// DockerUpgrade is the decision about the example token, as kept in the
// state folder.
type DockerUpgrade struct {
	// Upgraded is true when OpenSearch held Signalith's events from before
	// Setup: the install was upgraded from a quick start whose agents send
	// the example token.
	Upgraded bool `json:"upgraded"`
	// Setup is when the quick start's setup step first made this
	// install's secrets. Events stored after it are this install's own
	// (its agents, a test, sample data) and never count.
	Setup time.Time `json:"setup"`
	// Index is the oldest event index OpenSearch made before Setup, and
	// IndexMade when it made it; empty for an install that started new.
	Index     string    `json:"index,omitempty"`
	IndexMade time.Time `json:"index_made,omitzero"`
	// Decided is when Signalith decided.
	Decided time.Time `json:"decided"`
	// Ended is when Signalith, after an upgrade, first ran with agents on
	// plain HTTP refused. It refuses the example token from then on, even
	// if they are accepted again.
	Ended time.Time `json:"ended,omitzero"`
}

// accepting reports whether u lets agents from before the upgrade send
// the example token (while agents on plain HTTP are accepted).
func (u *DockerUpgrade) accepting() bool { return u != nil && u.Upgraded && u.Ended.IsZero() }

// DockerUpgradeFileIn is where the decision is kept in the state folder
// dir.
func DockerUpgradeFileIn(dir string) string { return filepath.Join(dir, dockerUpgradeFile) }

// ReadDockerUpgrade reads the decision kept in the state folder dir: nil
// when there is none yet.
func ReadDockerUpgrade(dir string) (*DockerUpgrade, error) {
	path := DockerUpgradeFileIn(dir)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var u DockerUpgrade
	if err := json.Unmarshal(b, &u); err != nil || u.Decided.IsZero() {
		return nil, fmt.Errorf("%s is damaged", path)
	}
	return &u, nil
}

// WriteDockerUpgrade keeps the decision in the state folder dir.
func WriteDockerUpgrade(dir string, u *DockerUpgrade) error {
	b, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	return securefile.Replace(DockerUpgradeFileIn(dir), append(b, '\n'))
}

// DockerQuickStart reports whether the environment is that of the Docker
// quick start's container, which reads its first secrets from
// DockerSecretsDir.
func DockerQuickStart(getenv func(string) string) bool {
	return len(dockerSecretFiles(getenv)) > 0
}

// dockerSecretFiles lists the files in DockerSecretsDir that Signalith
// reads its secrets from.
func dockerSecretFiles(getenv func(string) string) []string {
	var out []string
	for _, k := range []string{"SIGNALITH_ADMIN_PASSWORD_FILE", "SIGNALITH_INGEST_TOKEN_FILE"} {
		if v := getenv(k); strings.HasPrefix(v, DockerSecretsDir) {
			out = append(out, v)
		}
	}
	return out
}

// DockerSetupTime returns when the Docker quick start's setup step first
// ran: the time it wrote the first admin password and the ingest token,
// which it makes once and then keeps (the earlier of the two). It changes
// their owner and permissions on every start, but never their content.
func DockerSetupTime(getenv func(string) string) (time.Time, error) {
	files := dockerSecretFiles(getenv)
	if len(files) == 0 {
		return time.Time{}, errors.New("this is not the Docker quick start: no secret comes from " + DockerSecretsDir)
	}
	return firstWritten(files)
}

// firstWritten returns when the first of files was last written.
func firstWritten(files []string) (time.Time, error) {
	var first time.Time
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			return time.Time{}, err
		}
		if t := fi.ModTime(); first.IsZero() || t.Before(first) {
			first = t
		}
	}
	return first, nil
}

// dockerQuickStartHere reports whether this process is the Docker quick
// start's server; tests replace it.
var dockerQuickStartHere = func() bool { return inContainer() && DockerQuickStart(os.Getenv) }

// readDockerUpgrade reads the decision about the example token from the
// state folder. A damaged file counts as none: the decision is made again
// from the same evidence and replaces it.
func (c *Config) readDockerUpgrade() {
	c.quickStart = dockerQuickStartHere()
	u, _ := ReadDockerUpgrade(c.StateDir())
	c.useDockerUpgrade(u)
}

func (c *Config) useDockerUpgrade(u *DockerUpgrade) {
	c.dockerUpgrade = u
	c.Server.oldAgents = u.accepting()
}

// WithDockerUpgrade returns a copy of c, as the Docker quick start's
// server, that uses the decision u, made or changed after c was loaded
// (nil: not made yet).
func (c *Config) WithDockerUpgrade(u *DockerUpgrade) *Config {
	next := *c
	next.quickStart = true
	next.useDockerUpgrade(u)
	return &next
}

// DockerUpgrade returns the decision about the example token kept in the
// state folder, or nil when there is none.
func (c *Config) DockerUpgrade() *DockerUpgrade { return c.dockerUpgrade }

// OldToken is what Signalith does with the example ingest token
// change-this-ingest-token when it is not in ingest.tokens.
type OldToken int

const (
	// OldTokenRefused: refused like any wrong token. This is not the
	// Docker quick start, or it is one installed new.
	OldTokenRefused OldToken = iota
	// OldTokenUndecided: the Docker quick start, before Signalith could ask
	// OpenSearch whether it was upgraded. Refused, as a batch the agent
	// keeps and sends again.
	OldTokenUndecided
	// OldTokenAccepted: a Docker quick start upgraded from a version whose
	// agents send it. Accepted over plain HTTP while agents on plain HTTP
	// are accepted, which is then also the default.
	OldTokenAccepted
	// OldTokenEnded: as OldTokenAccepted, until agents on plain HTTP were
	// refused; refused for good since, as a batch the agent keeps.
	OldTokenEnded
)

// OldToken returns what this server does with the example ingest token.
func (c *Config) OldToken() OldToken {
	u := c.dockerUpgrade
	switch {
	case u == nil && c.quickStart:
		return OldTokenUndecided
	case u == nil || !u.Upgraded:
		return OldTokenRefused
	case !u.Ended.IsZero():
		return OldTokenEnded
	}
	return OldTokenAccepted
}

// OldTokenAccepted reports whether this server accepts the example ingest
// token now: over plain HTTP, on a Docker quick start upgraded from a
// version whose agents send it, while agents on plain HTTP are accepted.
func (c *Config) OldTokenAccepted() bool {
	return c.OldToken() == OldTokenAccepted && c.Server.HTTPS() && c.Server.PlaintextIngest()
}
