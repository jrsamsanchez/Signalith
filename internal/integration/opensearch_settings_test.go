//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ospki"
)

// TestOpenSearchAcceptsGeneratedSettings starts each OpenSearch version
// Signalith supports with the opensearch.yml each install path writes, and
// fails when OpenSearch refuses a setting. OpenSearch refuses to start on
// one it doesn't know, and setting names differ between 2.x and 3.x, so a
// name that works on the Docker quick start's version can stop a package
// install on 2.x (or the other way round). The other tests run only the
// quick start's version.
//
// It needs Docker; outside CI it is skipped without it.
func TestOpenSearchAcceptsGeneratedSettings(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("docker is needed to start OpenSearch")
		}
		t.Skip("docker is needed to start OpenSearch")
	}
	versions := supportedOpenSearchVersions(t)

	old := ospki.KeyBits
	ospki.KeyBits = 2048
	set, err := ospki.New(ospki.Options{})
	ospki.KeyBits = old
	if err != nil {
		t.Fatal(err)
	}
	certs := t.TempDir()
	for name, b := range set.OpenSearchFiles() {
		if err := os.WriteFile(filepath.Join(certs, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	security := t.TempDir()
	for name, b := range ospki.SecurityFiles() {
		if err := os.WriteFile(filepath.Join(security, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	single := "discovery.type: single-node\nnetwork.host: 0.0.0.0\n"
	configs := []struct {
		name, yml string
		env       []string
	}{
		// signalith opensearch-certs, for package and Windows installs.
		{name: "opensearch-certs", yml: single + ospki.Settings("")},
		{name: "opensearch-certs with peers", yml: single + ospki.SettingsFor("", []string{"opensearch-2"})},
		// The Docker quick start sets discovery.type in its environment.
		{name: "docker", yml: readRepoFile(t, "deploy/docker/opensearch/opensearch.yml"), env: []string{"discovery.type=single-node"}},
		{name: "docker cluster", yml: readRepoFile(t, "deploy/docker/opensearch/opensearch-cluster.yml"), env: []string{"NODE_NAME=opensearch", "NODE_CERT=node"}},
		{name: "helm", yml: helmOpenSearchYML(t)},
	}
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			image := "opensearchproject/opensearch:" + v
			if exec.Command("docker", "image", "inspect", image).Run() != nil {
				if out, err := exec.Command("docker", "pull", "-q", image).CombinedOutput(); err != nil {
					t.Fatalf("docker pull %s: %v\n%s", image, err, out)
				}
			}
			// Side by side: each OpenSearch takes half a gigabyte.
			for _, c := range configs {
				t.Run(c.name, func(t *testing.T) {
					t.Parallel()
					yml := filepath.Join(t.TempDir(), "opensearch.yml")
					if err := os.WriteFile(yml, []byte(c.yml), 0o644); err != nil {
						t.Fatal(err)
					}
					if err := startOpenSearch(t, v, yml, certs, security, c.env); err != nil {
						t.Errorf("OpenSearch %s does not start with the %s settings: %v", v, c.name, err)
					}
				})
			}
		})
	}
}

// supportedOpenSearchVersions returns the Docker quick start's OpenSearch
// version and the 2.x version docs/opensearch-security.md says to stay on.
func supportedOpenSearchVersions(t *testing.T) []string {
	t.Helper()
	image := regexp.MustCompile(`opensearchproject/opensearch:(\d+\.\d+\.\d+)`)
	compose := image.FindStringSubmatch(readRepoFile(t, "deploy/docker/docker-compose.yml"))
	if compose == nil {
		t.Fatal("no OpenSearch image in deploy/docker/docker-compose.yml")
	}
	versions := []string{compose[1]}
	for _, m := range image.FindAllStringSubmatch(readRepoFile(t, "docs/opensearch-security.md"), -1) {
		if strings.HasPrefix(m[1], "2.") && !strings.Contains(strings.Join(versions, " "), m[1]) {
			versions = append(versions, m[1])
		}
	}
	if len(versions) < 2 {
		t.Fatal("docs/opensearch-security.md names no OpenSearch 2.x image")
	}
	return versions
}

// startOpenSearch starts OpenSearch version v with the given opensearch.yml
// and stops it once the node is set up, which is after it has checked its
// settings. It returns OpenSearch's error when it refuses to start.
func startOpenSearch(t *testing.T, v, yml, certs, security string, env []string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	// Stopping docker run leaves the container running: remove it by name.
	name := fmt.Sprintf("signalith-settings-test-%d-%d", os.Getpid(), containerSeq.Add(1))
	defer exec.Command("docker", "rm", "-f", name).Run()
	args := []string{"run", "--rm", "--name", name,
		"-e", "DISABLE_INSTALL_DEMO_CONFIG=true",
		"-e", "DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI=true",
		"-e", "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m",
		"-v", yml + ":/usr/share/opensearch/config/opensearch.yml:ro",
		"-v", certs + ":/usr/share/opensearch/config/certs:ro",
	}
	for _, e := range env {
		args = append(args, "-e", e)
	}
	entries, _ := os.ReadDir(security)
	for _, e := range entries {
		args = append(args, "-v", filepath.Join(security, e.Name())+":/usr/share/opensearch/config/opensearch-security/"+e.Name()+":ro")
	}
	cmd := exec.CommandContext(ctx, "docker", append(args, "opensearchproject/opensearch:"+v)...)
	var out lockedBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	refused := regexp.MustCompile(`(?m)^.*(StartupException|unknown setting).*$`)
	ready := regexp.MustCompile(`\[o\.o\.n\.Node\s*\] \[[^\]]*\] initialized`)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			if m := refused.FindString(out.String()); m != "" {
				return errorString(m)
			}
			if ready.MatchString(out.String()) {
				// It took its settings, then stopped on a check of this
				// computer, such as vm.max_map_count for a cluster node.
				return nil
			}
			return errorString("OpenSearch stopped: " + errText(err) + "\n" + tail(out.String(), 20))
		case <-tick.C:
			s := out.String()
			if m := refused.FindString(s); m != "" {
				cancel()
				<-done
				return errorString(m)
			}
			if ready.MatchString(s) {
				cancel()
				<-done
				return nil
			}
		case <-ctx.Done():
			<-done
			return errorString("not set up within 4 minutes\n" + tail(out.String(), 20))
		}
	}
}

var containerSeq atomic.Int64

// helmOpenSearchYML renders the Helm chart's opensearch.yml for one
// OpenSearch node, as helm template would with the default values.
func helmOpenSearchYML(t *testing.T) string {
	t.Helper()
	tpl := readRepoFile(t, "deploy/helm/signalith/templates/opensearch-configmap.yaml")
	_, after, ok := strings.Cut(tpl, "  opensearch.yml: |\n")
	if !ok {
		t.Fatal("no opensearch.yml in the Helm chart's OpenSearch ConfigMap")
	}
	var b strings.Builder
	keep := []bool{true}
	for _, line := range strings.Split(after, "\n") {
		if line != "" && !strings.HasPrefix(line, "    ") {
			break // the ConfigMap's next file
		}
		switch d := strings.TrimSpace(line); {
		case strings.HasPrefix(d, "{{- if "):
			// The only condition is on the number of replicas: take the one-node branch.
			keep = append(keep, keep[len(keep)-1])
		case strings.HasPrefix(d, "{{- else"):
			keep[len(keep)-1] = false
		case strings.HasPrefix(d, "{{- end"):
			keep = keep[:len(keep)-1]
		case strings.HasPrefix(d, "{{- range"):
			keep = append(keep, false)
		default:
			if keep[len(keep)-1] {
				line = strings.ReplaceAll(line, `{{ include "signalith.fullname" . }}`, "sig-signalith")
				if strings.Contains(line, "{{") {
					t.Fatalf("Helm chart's opensearch.yml: can't render %q", line)
				}
				b.WriteString(strings.TrimPrefix(line, "    ") + "\n")
			}
		}
	}
	return b.String()
}

func readRepoFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return string(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func errText(err error) string {
	if err == nil {
		return "exit 0"
	}
	return err.Error()
}

type errorString string

func (e errorString) Error() string { return string(e) }

// lockedBuffer is a bytes.Buffer that docker's output and the test can
// use at the same time.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
