package deploy

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestHelmChartFilesMatchDocker checks that the Helm chart's copies of
// OpenSearch's security settings and their loader are the Docker quick
// start's: Helm can't read files outside the chart's folder.
func TestHelmChartFilesMatchDocker(t *testing.T) {
	pairs := map[string]string{
		"docker/opensearch/load-security.sh":            "helm/signalith/files/load-security.sh",
		"docker/opensearch/security/config.yml":         "helm/signalith/files/config.yml",
		"docker/opensearch/security/internal_users.yml": "helm/signalith/files/internal_users.yml",
		"docker/opensearch/security/roles.yml":          "helm/signalith/files/roles.yml",
		"docker/opensearch/security/roles_mapping.yml":  "helm/signalith/files/roles_mapping.yml",
	}
	for docker, helm := range pairs {
		a, err := os.ReadFile(filepath.FromSlash(docker))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.FromSlash(helm))
		if err != nil {
			t.Fatal(err)
		}
		// A Windows checkout may give either one CRLF line endings.
		a, b = bytes.ReplaceAll(a, []byte("\r\n"), []byte("\n")), bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs from %s: copy it there (cp deploy/%s deploy/%s)", helm, docker, docker, helm)
		}
	}
}
