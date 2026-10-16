package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ospki"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// fakeSecrets keeps secrets in memory, with a resourceVersion each.
type fakeSecrets struct {
	data     map[string]map[string][]byte
	versions map[string]string
	labels   map[string]map[string]string
	n        int
}

func newFakeSecrets() *fakeSecrets {
	return &fakeSecrets{data: map[string]map[string][]byte{}, versions: map[string]string{}, labels: map[string]map[string]string{}}
}

func (f *fakeSecrets) get(_ context.Context, name string) (map[string][]byte, string, error) {
	d, ok := f.data[name]
	if !ok {
		return nil, "", nil
	}
	return maps.Clone(d), f.versions[name], nil
}

func (f *fakeSecrets) put(_ context.Context, name, version string, labels map[string]string, data map[string][]byte) error {
	if f.versions[name] != version {
		return errors.New("conflict")
	}
	f.n++
	f.data[name], f.versions[name], f.labels[name] = maps.Clone(data), strconv.Itoa(f.n), labels
	return nil
}

func runK8sBootstrap(t *testing.T, api k8sSecrets, o k8sOptions) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("bootstrap-kubernetes runs in Linux pods")
	}
	o.WorkDir = t.TempDir()
	if o.Prefix == "" {
		o.Prefix = "sig"
	}
	var out bytes.Buffer
	if err := bootstrapKubernetes(context.Background(), &out, api, o); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestBootstrapKubernetesMakesThenKeeps(t *testing.T) {
	api := newFakeSecrets()
	o := k8sOptions{OpenSearch: true, Instance: "rel", Names: []string{"sig-opensearch", "sig-opensearch.ns.svc"}, Now: time.Now()}
	out := runK8sBootstrap(t, api, o)
	for _, name := range []string{"sig-secrets", "sig-opensearch-certs", "sig-opensearch-ca"} {
		if !strings.Contains(out, "Secret "+name+": made.") {
			t.Errorf("%s not made:\n%s", name, out)
		}
		if api.labels[name]["app.kubernetes.io/instance"] != "rel" {
			t.Errorf("%s labels %v", name, api.labels[name])
		}
	}
	sig := api.data["sig-secrets"]
	for _, k := range []string{ospki.ClientCAFile, ospki.ClientCertFile, ospki.ClientKeyFile, initialPasswordFile, ingestTokenFile, clusterKeyFile} {
		if len(bytes.TrimSpace(sig[k])) == 0 {
			t.Errorf("sig-secrets has no %s", k)
		}
	}
	osc := api.data["sig-opensearch-certs"]
	for _, k := range []string{ospki.RootCAFile, ospki.NodeCertFile, ospki.NodeKeyFile, ospki.AdminCertFile, ospki.AdminKeyFile} {
		if len(osc[k]) == 0 {
			t.Errorf("sig-opensearch-certs has no %s", k)
		}
	}
	if _, ok := osc[ospki.RootCAKeyFile]; ok {
		t.Error("the CA's key is in OpenSearch's secret")
	}
	if len(api.data["sig-opensearch-ca"][ospki.RootCAKeyFile]) == 0 {
		t.Error("the CA's key was not kept")
	}

	// The node certificate covers the service's names.
	dir := t.TempDir()
	writeFiles(dir, map[string][]byte{ospki.NodeCertFile: osc[ospki.NodeCertFile], ospki.NodeKeyFile: osc[ospki.NodeKeyFile]})
	p, err := ospki.ReadPair(dir, ospki.NodeCertFile, ospki.NodeKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if names := strings.Join(p.Cert.DNSNames, ","); !strings.Contains(names, "sig-opensearch.ns.svc") {
		t.Errorf("node certificate names %s", names)
	}

	// The cluster key is one Signalith reads.
	kf := filepath.Join(t.TempDir(), "k")
	os.WriteFile(kf, sig[clusterKeyFile], 0o600)
	if _, err := shared.KeyFromFile(kf); err != nil {
		t.Fatalf("cluster key: %v", err)
	}

	// A second run changes nothing.
	before := api.n
	out = runK8sBootstrap(t, api, o)
	if api.n != before || strings.Count(out, "kept.") != 3 {
		t.Errorf("second run wrote secrets:\n%s", out)
	}

	// A lost client certificate is made again under the same CA, and only
	// that secret is written.
	delete(api.data["sig-secrets"], ospki.ClientCertFile)
	out = runK8sBootstrap(t, api, o)
	if !strings.Contains(out, "Secret sig-secrets: updated opensearch-client-key.pem, opensearch-client.pem.") || api.n != before+1 {
		t.Errorf("after losing the client certificate:\n%s", out)
	}
	if !bytes.Equal(api.data["sig-opensearch-ca"][ospki.RootCAFile], osc[ospki.RootCAFile]) {
		t.Error("the CA changed")
	}
	if !bytes.Equal(api.data["sig-secrets"][initialPasswordFile], sig[initialPasswordFile]) || !bytes.Equal(api.data["sig-secrets"][clusterKeyFile], sig[clusterKeyFile]) {
		t.Error("the password or cluster key changed")
	}
}

func TestBootstrapKubernetesExternalOpenSearch(t *testing.T) {
	api := newFakeSecrets()
	runK8sBootstrap(t, api, k8sOptions{OpenSearch: false, Now: time.Now()})
	if len(api.data) != 1 {
		t.Fatalf("secrets %v", slicesKeys(api.data))
	}
	got := slicesKeys(api.data["sig-secrets"])
	if want := clusterKeyFile + "," + ingestTokenFile + "," + initialPasswordFile; got != want {
		t.Errorf("keys %s, want %s", got, want)
	}
}

func TestBootstrapKubernetesRefusesOddKeys(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bootstrap-kubernetes runs in Linux pods")
	}
	api := newFakeSecrets()
	api.data["sig-secrets"] = map[string][]byte{"../x": []byte("y")}
	err := bootstrapKubernetes(context.Background(), io.Discard, api, k8sOptions{Prefix: "sig", WorkDir: t.TempDir(), Now: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "not a file name") {
		t.Fatalf("err %v", err)
	}
}

func slicesKeys[V any](m map[string]V) string {
	return strings.Join(slices.Sorted(maps.Keys(m)), ",")
}

// TestK8sAPISecrets checks the requests to the API server: the token, a
// 404 read as no secret, a create, and a replace with its version.
func TestK8sAPISecrets(t *testing.T) {
	var mu sync.Mutex
	store := map[string]k8sSecret{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		const base = "/api/v1/namespaces/ns/secrets"
		name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, base), "/")
		switch r.Method {
		case http.MethodGet:
			s, ok := store[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"message":"secrets \"` + name + `\" not found"}`))
				return
			}
			json.NewEncoder(w).Encode(s)
		case http.MethodPost, http.MethodPut:
			var s k8sSecret
			json.NewDecoder(r.Body).Decode(&s)
			if r.Method == http.MethodPost {
				name = s.Metadata.Name
				if _, ok := store[name]; ok {
					w.WriteHeader(http.StatusConflict)
					w.Write([]byte(`{"message":"already exists"}`))
					return
				}
			} else if store[name].Metadata.ResourceVersion != s.Metadata.ResourceVersion {
				w.WriteHeader(http.StatusConflict)
				w.Write([]byte(`{"message":"the object has been modified"}`))
				return
			}
			s.Metadata.ResourceVersion += "1"
			store[name] = s
			w.WriteHeader(http.StatusCreated)
		}
	}))
	defer srv.Close()
	api := &k8sAPI{base: srv.URL, namespace: "ns", token: "tok", client: srv.Client()}
	ctx := context.Background()
	d, v, err := api.get(ctx, "a")
	if err != nil || d != nil || v != "" {
		t.Fatalf("missing secret: %v %v %q", d, err, v)
	}
	if err := api.put(ctx, "a", "", map[string]string{"x": "y"}, map[string][]byte{"k": []byte("v")}); err != nil {
		t.Fatal(err)
	}
	d, v, err = api.get(ctx, "a")
	if err != nil || string(d["k"]) != "v" || v == "" {
		t.Fatalf("read back: %v %v %q", d, err, v)
	}
	if err := api.put(ctx, "a", v, nil, map[string][]byte{"k": []byte("w")}); err != nil {
		t.Fatal(err)
	}
	if err := api.put(ctx, "a", v, nil, map[string][]byte{"k": []byte("z")}); err == nil || !strings.Contains(err.Error(), "modified") {
		t.Fatalf("stale version: %v", err)
	}
	api.token = "bad"
	if _, _, err := api.get(ctx, "a"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad token: %v", err)
	}
}
