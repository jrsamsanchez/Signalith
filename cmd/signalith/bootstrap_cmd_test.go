package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestBootstrapDockerCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bootstrap-docker prepares Linux container volumes")
	}
	for _, k := range []string{"SIGNALITH_SETUP_OPENSEARCH_DIR", "SIGNALITH_SETUP_SIGNALITH_DIR", "SIGNALITH_SETUP_CA_DIR", "SIGNALITH_SETUP_STATE_DIR",
		"SIGNALITH_SETUP_LOADED_DIR", "SIGNALITH_SETUP_CRL_DIR"} {
		t.Setenv(k, "")
	}
	if _, err := capture(t, func() error { return cmdBootstrapDocker(nil) }); err == nil || !strings.Contains(err.Error(), "usage: signalith bootstrap-docker") {
		t.Errorf("no folders: %v", err)
	}
	root := t.TempDir()
	osDir, sigDir := filepath.Join(root, "opensearch"), filepath.Join(root, "signalith")
	if _, err := capture(t, func() error {
		return cmdBootstrapDocker([]string{"-opensearch-dir", osDir, "-signalith-dir", sigDir, "-ca-dir", filepath.Join(root, "ca"), "-export-ca-key"})
	}); err == nil || !strings.Contains(err.Error(), "-export-ca-key needs -state-dir") {
		t.Errorf("-export-ca-key alone: %v", err)
	}
	if _, err := capture(t, func() error {
		return cmdBootstrapDocker([]string{"-opensearch-dir", osDir, "-signalith-dir", sigDir, "-ca-dir", filepath.Join(root, "ca"), "-apply-security"})
	}); err == nil || !strings.Contains(err.Error(), "-apply-security needs -loaded-dir") {
		t.Errorf("-apply-security alone: %v", err)
	}
	// The folders from the environment, as the Docker quick start gives
	// them, and a name from the command line.
	t.Setenv("SIGNALITH_SETUP_OPENSEARCH_DIR", osDir)
	t.Setenv("SIGNALITH_SETUP_SIGNALITH_DIR", sigDir)
	t.Setenv("SIGNALITH_SETUP_CA_DIR", filepath.Join(root, "ca"))
	uid := os.Getuid()
	out, err := capture(t, func() error {
		return cmdBootstrapDocker([]string{"-opensearch-name", "os.example.test", "-opensearch-uid", strconv.Itoa(uid), "-signalith-uid", strconv.Itoa(uid)})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, f := range []string{filepath.Join(osDir, "root-ca.pem"), filepath.Join(sigDir, "opensearch-ca.pem"), filepath.Join(sigDir, "initial-admin-password"), filepath.Join(sigDir, "ingest-token")} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("not written: %v\n%s", err, out)
		}
	}
	// Again: everything is kept.
	out, err = capture(t, func() error {
		return cmdBootstrapDocker([]string{"-opensearch-uid", strconv.Itoa(uid), "-signalith-uid", strconv.Itoa(uid)})
	})
	if err != nil || !strings.Contains(out, "kept") {
		t.Errorf("second run: %v\n%s", err, out)
	}
}

func TestOpenSearchCertsCommand(t *testing.T) {
	if _, err := capture(t, func() error { return cmdOpenSearchCerts(nil) }); err == nil || !strings.Contains(err.Error(), "usage: signalith opensearch-certs") {
		t.Errorf("no -out: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "certs")
	out, err := capture(t, func() error {
		return cmdOpenSearchCerts([]string{"-out", dir, "-node", "os-1", "-san", "os-1.example.test", "-peer", "os-2"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("nothing written: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, caFolder)); err != nil {
		t.Errorf("no CA folder: %v", err)
	}
	// The folder must be new.
	if _, err := capture(t, func() error { return cmdOpenSearchCerts([]string{"-out", dir}) }); err == nil {
		t.Error("wrote into a folder that exists")
	}
}

func TestBootstrapKubernetesCommandOutsideKubernetes(t *testing.T) {
	if _, err := capture(t, func() error { return cmdBootstrapKubernetes(nil) }); err == nil || !strings.Contains(err.Error(), "-prefix") {
		t.Errorf("no -prefix: %v", err)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := capture(t, func() error { return cmdBootstrapKubernetes([]string{"-prefix", "signalith"}) }); err == nil || !strings.Contains(err.Error(), "KUBERNETES_SERVICE_HOST is not set") {
		t.Errorf("outside a pod: %v", err)
	}
	if _, err := os.Stat(filepath.Join(serviceAccountDir, "token")); err == nil {
		t.Skip("this runs in a Kubernetes pod")
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "127.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "1")
	if _, err := capture(t, func() error { return cmdBootstrapKubernetes([]string{"-prefix", "signalith"}) }); err == nil || !strings.Contains(err.Error(), "service account token") {
		t.Errorf("no service account: %v", err)
	}
}
