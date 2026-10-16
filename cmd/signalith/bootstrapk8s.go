package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// clusterKeyFile is the cluster key's name in the Signalith secret that
// bootstrap-kubernetes keeps, read through SIGNALITH_CLUSTER_KEY_FILE.
const clusterKeyFile = "cluster-key"

// The service account files Kubernetes mounts into every pod.
const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// k8sOptions are bootstrap-kubernetes's flags.
type k8sOptions struct {
	Namespace string
	// Prefix starts the name of each secret: <prefix>-opensearch-ca,
	// <prefix>-opensearch-certs and <prefix>-secrets.
	Prefix   string
	Instance string // the Helm release, for the app.kubernetes.io/instance label
	// OpenSearch is false when Signalith uses an OpenSearch it did not
	// set up: then only the first admin password, the ingest token and
	// the cluster key are made.
	OpenSearch bool
	Names      []string // more names for OpenSearch's node certificate
	WorkDir    string
	Now        time.Time
}

// k8sSecrets is the part of the Kubernetes API bootstrap-kubernetes uses.
type k8sSecrets interface {
	// get returns the secret's data and resourceVersion, or nil data
	// when there is no such secret.
	get(ctx context.Context, name string) (map[string][]byte, string, error)
	// put creates the secret (version "") or replaces that version of it.
	put(ctx context.Context, name, version string, labels map[string]string, data map[string][]byte) error
}

// cmdBootstrapKubernetes makes and keeps the secrets the Helm chart
// (deploy/helm/signalith) runs Signalith and OpenSearch with, as Kubernetes
// Secrets: what bootstrap-docker makes for the Docker quick start, and the
// cluster key every Signalith server of the release shares. The chart runs
// it as a Job before each install and upgrade, with a service account that
// may only read and write Secrets in its namespace. Secrets already there
// are kept; certificates about to expire are renewed under the same CA.
func cmdBootstrapKubernetes(args []string) error {
	fs := flag.NewFlagSet("bootstrap-kubernetes", flag.ExitOnError)
	var o k8sOptions
	fs.StringVar(&o.Namespace, "namespace", "", "the namespace to keep the secrets in (default: this pod's)")
	fs.StringVar(&o.Prefix, "prefix", "", "the start of each secret's name, such as the Helm release's full name")
	fs.StringVar(&o.Instance, "instance", "", "the Helm release, for each secret's app.kubernetes.io/instance label")
	fs.BoolVar(&o.OpenSearch, "opensearch", true, "make OpenSearch's certificates and Signalith's client certificate (false: Signalith uses an OpenSearch set up elsewhere)")
	var names listFlag
	fs.Var(&names, "opensearch-name", "another host name or IP address OpenSearch's node certificate covers (repeat it, or separate names with commas)")
	fs.StringVar(&o.WorkDir, "work-dir", "", "an empty folder to work in (default: a new folder in the temporary folder)")
	fs.Parse(args)
	o.Names = names
	if o.Prefix == "" {
		return errors.New("usage: signalith bootstrap-kubernetes -prefix NAME [-namespace NS] [-instance RELEASE] [-opensearch=false] [-opensearch-name NAME]")
	}
	api, ns, err := inClusterSecrets(o.Namespace)
	if err != nil {
		return err
	}
	o.Namespace = ns
	if o.WorkDir == "" {
		d, err := os.MkdirTemp("", "signalith-bootstrap-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(d)
		o.WorkDir = d
	}
	o.Now = time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return bootstrapKubernetes(ctx, os.Stdout, api, o)
}

// bootstrapKubernetes reads the secrets into folders, lets bootstrap-docker
// make and renew what it would for the Docker quick start, and writes back
// each secret that changed. A secret changed by someone else in the
// meantime fails the write, and the Job runs again from the start.
func bootstrapKubernetes(ctx context.Context, out io.Writer, api k8sSecrets, o k8sOptions) error {
	type secret struct {
		name, dir string
		old       map[string][]byte
		version   string
	}
	secrets := []*secret{{name: o.Prefix + "-secrets", dir: "signalith"}}
	if o.OpenSearch {
		secrets = append(secrets,
			&secret{name: o.Prefix + "-opensearch-certs", dir: "opensearch"},
			&secret{name: o.Prefix + "-opensearch-ca", dir: "ca"})
	}
	dirs := map[string]string{}
	for _, s := range secrets {
		s.dir = filepath.Join(o.WorkDir, s.dir)
		dirs[filepath.Base(s.dir)] = s.dir
		if err := os.MkdirAll(s.dir, 0o700); err != nil {
			return err
		}
		data, version, err := api.get(ctx, s.name)
		if err != nil {
			return err
		}
		s.old, s.version = data, version
		for k, v := range data {
			if !validSecretKey(k) {
				return fmt.Errorf("secret %s has a key %q that is not a file name", s.name, k)
			}
			if err := writeFile(filepath.Join(s.dir, k), v, 0o600); err != nil {
				return err
			}
		}
	}

	sig := dirs["signalith"]
	if o.OpenSearch {
		// Its own messages name Docker Compose commands, which do not
		// apply here; what changed is said below instead.
		err := bootstrapDocker(io.Discard, bootstrapOptions{
			OSDir: dirs["opensearch"], SigDir: sig, CADir: dirs["ca"],
			OSUID: os.Getuid(), SigUID: os.Getuid(), Names: o.Names, Nodes: 1, Now: o.Now,
		})
		if err != nil {
			return err
		}
	} else {
		made := map[string]func() string{
			initialPasswordFile: users.GeneratePassword,
			ingestTokenFile:     func() string { return config.RandomToken(24) },
		}
		for _, name := range []string{initialPasswordFile, ingestTokenFile} {
			if len(bytes.TrimSpace(readOr(filepath.Join(sig, name)))) == 0 {
				if err := writeFile(filepath.Join(sig, name), []byte(made[name]()+"\n"), 0o600); err != nil {
					return err
				}
			}
		}
	}
	// The cluster key every server of the release joins with
	// (docs/servers.md, Shared settings and the cluster key): 32 random
	// bytes as one line of base64, made once.
	if len(bytes.TrimSpace(readOr(filepath.Join(sig, clusterKeyFile)))) == 0 {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		if err := writeFile(filepath.Join(sig, clusterKeyFile), []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600); err != nil {
			return err
		}
	}

	labels := map[string]string{
		"app.kubernetes.io/name":      "signalith",
		"app.kubernetes.io/component": "secrets",
	}
	if o.Instance != "" {
		labels["app.kubernetes.io/instance"] = o.Instance
	}
	for _, s := range secrets {
		data := map[string][]byte{}
		entries, err := os.ReadDir(s.dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !e.Type().IsRegular() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
			if err != nil {
				return err
			}
			data[e.Name()] = b
		}
		if maps.EqualFunc(data, s.old, bytes.Equal) {
			fmt.Fprintf(out, "Secret %s: kept.\n", s.name)
			continue
		}
		if err := api.put(ctx, s.name, s.version, labels, data); err != nil {
			return err
		}
		if s.old == nil {
			fmt.Fprintf(out, "Secret %s: made.\n", s.name)
			continue
		}
		var changed []string
		for k, v := range data {
			if !bytes.Equal(v, s.old[k]) {
				changed = append(changed, k)
			}
		}
		slices.Sort(changed)
		fmt.Fprintf(out, "Secret %s: updated %s. Restart the pods that use it to pick them up.\n", s.name, strings.Join(changed, ", "))
	}
	return nil
}

func readOr(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}

// validSecretKey reports whether k is a key Kubernetes allows in a secret
// and a plain file name.
func validSecretKey(k string) bool {
	if k == "" || k == "." || k == ".." || len(k) > 253 {
		return false
	}
	for _, r := range k {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// k8sAPI talks to the Kubernetes API server with a service account token.
type k8sAPI struct {
	base      string // https://host:port
	namespace string
	token     string
	client    *http.Client
}

// inClusterSecrets connects to the API server of the cluster this pod
// runs in, as its service account.
func inClusterSecrets(namespace string) (*k8sAPI, string, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, "", errors.New("bootstrap-kubernetes runs in a Kubernetes pod (KUBERNETES_SERVICE_HOST is not set)")
	}
	token, err := os.ReadFile(filepath.Join(serviceAccountDir, "token"))
	if err != nil {
		return nil, "", fmt.Errorf("cannot read the pod's service account token: %w", err)
	}
	caPEM, err := os.ReadFile(filepath.Join(serviceAccountDir, "ca.crt"))
	if err != nil {
		return nil, "", fmt.Errorf("cannot read the cluster's CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, "", errors.New("the cluster's CA file has no certificate")
	}
	if namespace == "" {
		b, err := os.ReadFile(filepath.Join(serviceAccountDir, "namespace"))
		if err != nil {
			return nil, "", fmt.Errorf("cannot read the pod's namespace: %w", err)
		}
		namespace = strings.TrimSpace(string(b))
	}
	return &k8sAPI{
		base:      "https://" + net.JoinHostPort(host, port),
		namespace: namespace,
		token:     strings.TrimSpace(string(token)),
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
	}, namespace, nil
}

type k8sSecret struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   k8sMeta           `json:"metadata"`
	Type       string            `json:"type,omitempty"`
	Data       map[string][]byte `json:"data"`
}

type k8sMeta struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace,omitempty"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
}

func (a *k8sAPI) secretsURL(name string) string {
	u := a.base + "/api/v1/namespaces/" + url.PathEscape(a.namespace) + "/secrets"
	if name != "" {
		u += "/" + url.PathEscape(name)
	}
	return u
}

func (a *k8sAPI) do(ctx context.Context, method, u string, body any) (*http.Response, []byte, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp, b, err
}

func (a *k8sAPI) get(ctx context.Context, name string) (map[string][]byte, string, error) {
	resp, b, err := a.do(ctx, http.MethodGet, a.secretsURL(name), nil)
	if err != nil {
		return nil, "", fmt.Errorf("cannot read secret %s: %w", name, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, "", nil
	default:
		return nil, "", fmt.Errorf("cannot read secret %s: %s", name, apiError(resp, b))
	}
	var s k8sSecret
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, "", fmt.Errorf("cannot read secret %s: %w", name, err)
	}
	if s.Data == nil {
		s.Data = map[string][]byte{}
	}
	return s.Data, s.Metadata.ResourceVersion, nil
}

func (a *k8sAPI) put(ctx context.Context, name, version string, labels map[string]string, data map[string][]byte) error {
	s := k8sSecret{
		APIVersion: "v1", Kind: "Secret", Type: "Opaque", Data: data,
		Metadata: k8sMeta{Name: name, Namespace: a.namespace, ResourceVersion: version, Labels: labels},
	}
	method, u := http.MethodPut, a.secretsURL(name)
	if version == "" {
		method, u = http.MethodPost, a.secretsURL("")
	}
	resp, b, err := a.do(ctx, method, u, s)
	if err != nil {
		return fmt.Errorf("cannot write secret %s: %w", name, err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("cannot write secret %s: %s", name, apiError(resp, b))
	}
	return nil
}

// apiError is the message of a Kubernetes API error response.
func apiError(resp *http.Response, b []byte) string {
	var st struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(b, &st) == nil && st.Message != "" {
		return fmt.Sprintf("%s (%s)", st.Message, resp.Status)
	}
	return resp.Status
}
