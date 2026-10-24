// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clusterarchive"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/clusterlib"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// signalith cluster export --to-files writes the shared settings as the
// files a server on its own keeps (the layout of the versions before
// they were shared), so a server can go back to such a version after the
// cluster's level was raised: each exporter is the inverse of the
// importer of the same name. Passwords and keys are sealed again with
// this server's master key, as its own files keep them, so the export is
// for this server: run it on each server you take back.

// sharedExporters lists the exporters of the shared settings, in the
// order of sharedImporters. A new shared feature appends its exporter
// here, from its own package, or names its importer in exportSkipped.
func sharedExporters(d sharedDocs, f clustercfg.Files) []shared.Exporter {
	return slices.Concat(
		// The feeds, their status, the retention policies, the users, the
		// directory sign-in settings and the settings of the Settings page.
		clustercfg.Exporters(d.docs, f),
		// The retention history.
		[]shared.Exporter{clusterarchive.HistoryExporter(func() (clusterarchive.Client, string) {
			cl, prefix := f.Client()
			return cl, prefix
		}, filepath.Join(f.Config().LookupsDir(), "retention_history.json"))},
		// The cluster's certificate authority, as this server's own.
		[]shared.Exporter{tlsExporter(d, f)},
		// The detections, dashboards and the asset and identity lists.
		clusterlib.Exporters(d.lib, libraryFiles(f)),
		// The notes on compliance controls (sharedcompliance.go).
		[]shared.Exporter{complianceExporter(d.comp, f)},
		// The custom parsers (sharedparsers.go).
		[]shared.Exporter{parsersExporter(d.parsers, f)},
		// The case report keys (sharedreportkeys.go).
		[]shared.Exporter{reportKeysExporter(d.reportKeys, f)},
		// Append a new shared feature's exporter here.
	)
}

// exportSkipped names the importers with no exporter, and why.
var exportSkipped = map[string]string{
	shared.ImportArchives: "the archive manifests are files in the archive folder already",
}

// exportNotFiles lists what the shared settings hold that no earlier
// version keeps in a file, for MANIFEST.json and README.txt.
var exportNotFiles = map[string]string{
	"api_tokens":        "API tokens have no file form in any earlier version: make them again",
	"join_tokens":       "join tokens are only for adding a server to a cluster",
	"migration_reports": "the reports of servers that joined with signalith join -merge are only for the cluster",
	"keyring":           "the cluster's keyring: a server on its own has no cluster key",
	"sessions":          "sign-in sessions: everyone signs in again after the downgrade",
	"opensearch_ca":     "OpenSearch's certificate authority stays where it was imported from",
}

// tlsExporter writes the cluster's certificate authority and its key as
// the tls folder of a server on its own keeps them (ca.pem and ca.key in
// the state folder's tls folder), so the agents that trust it keep
// working.
func tlsExporter(d sharedDocs, f clustercfg.Files) shared.Exporter {
	return shared.Exporter{Name: shared.ImportTLS, Run: func(_ context.Context, t shared.ExportTarget) ([]shared.ExportedFile, error) {
		ca, key, err := d.tls.tls.Store().Load()
		if err != nil {
			return nil, err
		}
		if ca == nil {
			return nil, nil
		}
		dir := f.Config().TLSDir()
		certDest, keyDest := filepath.Join(dir, tlsauto.CAFile), filepath.Join(dir, "ca.key")
		certPath, keyPath := t.Under(certDest), t.Under(keyDest)
		if err := os.MkdirAll(filepath.Dir(certPath), 0o750); err != nil {
			return nil, err
		}
		if err := securefile.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})); err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		clear(der)
		defer clear(data)
		p, err := securefile.PreparePrivate(keyPath, data)
		if err != nil {
			return nil, err
		}
		if err := p.Commit(); err != nil {
			return nil, err
		}
		return []shared.ExportedFile{{Path: certPath, Dest: certDest}, {Path: keyPath, Dest: keyDest, Secret: true}}, nil
	}}
}

// exportManifest is MANIFEST.json.
type exportManifest struct {
	Server    string            `json:"server"`
	NodeID    string            `json:"node_id"`
	Version   string            `json:"version"`
	At        string            `json:"at"`
	ClusterID string            `json:"cluster_id,omitempty"`
	Level     int               `json:"level,omitempty"`
	OwnFrom   string            `json:"own_settings_of"`
	Folders   []manifestFolder  `json:"folders"`
	Files     []manifestFile    `json:"files"`
	Skipped   []manifestSkipped `json:"skipped"`
}

// manifestFile is one file written. Path is where it is in the export
// folder, relative, with / between folders; Dest where it goes on this
// server.
type manifestFile struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Dest   string `json:"dest"`
	Secret bool   `json:"secret,omitempty"`
}

type manifestSkipped struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// manifestFolder is a folder of the export (Path, relative) and the
// folder of this server it is copied into.
type manifestFolder struct {
	Path string `json:"path"`
	Dest string `json:"dest"`
}

// exportLayout lays the files out in the export folder as on this
// server: each under the folder it is in here (detections, dashboards,
// state, config), and any other under other/ with its whole path.
type exportLayout struct {
	root  string
	areas []manifestFolder
}

func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return filepath.Clean(p)
}

// relWithin reports whether p is base or under it, and its path from
// base.
func relWithin(base, p string) (string, bool) {
	if base == "" {
		return "", false
	}
	rel, err := filepath.Rel(base, p)
	if err != nil || rel != "." && !filepath.IsLocal(rel) {
		return "", false
	}
	return rel, true
}

func newExportLayout(root string, x *clusterCLI) exportLayout {
	l := exportLayout{root: root}
	add := func(name, dir string) {
		if dir != "" {
			l.areas = append(l.areas, manifestFolder{Path: name, Dest: absPath(dir)})
		}
	}
	add("detections", x.c.DetectionsDir())
	add("dashboards", x.c.DashboardsDir())
	add("state", x.c.StateDir())
	if x.c.Path() != "" {
		add("config", filepath.Dir(x.c.Path()))
	}
	return l
}

// under is shared.ExportTarget.Under.
func (l exportLayout) under(p string) string {
	a := absPath(p)
	for _, ar := range l.areas {
		if rel, ok := relWithin(ar.Dest, a); ok {
			return filepath.Join(l.root, ar.Path, rel)
		}
	}
	vol := filepath.VolumeName(a)
	rest := strings.TrimPrefix(a, vol)
	vol = strings.NewReplacer(":", "", `\`, "_", "/", "_").Replace(vol)
	return filepath.Join(l.root, "other", vol, rest)
}

// used lists the folders of the export that hold files.
func (l exportLayout) used(files []manifestFile) []manifestFolder {
	var out []manifestFolder
	for _, ar := range l.areas {
		for _, f := range files {
			if f.Path == ar.Path || strings.HasPrefix(f.Path, ar.Path+"/") {
				out = append(out, ar)
				break
			}
		}
	}
	return out
}

// checkExportDir refuses an export folder that holds anything, or that
// is in a folder this server uses, and makes it. A new folder directly in
// the state folder is the exception: in Docker the state folder is the
// only one kept (the signalith-data volume), and nothing there is in it.
func (x *clusterCLI) checkExportDir(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", errors.New("name the folder to write the files into: --to-files <dir>")
	}
	root := absPath(dir)
	state := ""
	if x.c.StateDir() != "" {
		state = absPath(x.c.StateDir())
	}
	inState := false
	if rel, ok := relWithin(state, root); ok && rel != "." && !strings.ContainsAny(rel, `/\`) {
		if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
			inState = true
		}
	}
	live := []string{x.c.StateDir(), x.c.LookupsDir(), x.c.DetectionsDir(), x.c.DashboardsDir()}
	if x.c.Path() != "" {
		live = append(live, filepath.Dir(x.c.Path()))
	}
	for _, d := range live {
		if d == "" || inState && absPath(d) == state {
			continue
		}
		if _, ok := relWithin(absPath(d), root); ok {
			return "", fmt.Errorf("%s is in %s, a folder this server uses: write the files somewhere else, or into a new folder directly in %s", root, absPath(d), state)
		}
	}
	entries, err := os.ReadDir(root)
	switch {
	case err == nil && len(entries) > 0:
		return "", fmt.Errorf("%s is not empty: name a new or empty folder", root)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return "", err
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return "", err
	}
	return root, nil
}

// exportServer returns the node id and name of the server whose own
// settings are written: server (a name or node id), or this one.
func (x *clusterCLI) exportServer(ctx context.Context, server string) (string, string, error) {
	if server == "" || server == x.self.NodeID || strings.EqualFold(server, x.self.Name) {
		return x.self.NodeID, x.self.Name, nil
	}
	hbs, err := x.heartbeats(ctx)
	if err != nil {
		return "", "", err
	}
	for _, hb := range hbs {
		if hb.NodeID == server || strings.EqualFold(hb.Name, server) {
			return hb.NodeID, hb.Name, nil
		}
	}
	return "", "", fmt.Errorf("no server %q shares this OpenSearch", server)
}

// exportToFiles is signalith cluster export --to-files and -retire.
func (x *clusterCLI) exportToFiles(ctx context.Context, dir, server string, retire, yes, force bool) error {
	if retire {
		return x.retire(ctx, dir, server, yes, force)
	}
	root, err := x.checkExportDir(dir)
	if err != nil {
		return err
	}
	m, err := x.writeExport(ctx, root, server)
	if err != nil {
		return err
	}
	fmt.Fprintf(x.out, "Wrote %d files into %s, for %s (passwords and keys sealed with its master key).\n"+
		"README.txt there says where each goes; MANIFEST.json lists them.\n", len(m.Files), root, x.self.Name)
	return nil
}

// writeExport runs the exporters into root, an empty folder, and writes
// MANIFEST.json and README.txt there.
func (x *clusterCLI) writeExport(ctx context.Context, root, server string) (*exportManifest, error) {
	rt := x.runtime(true, "")
	if mode, why := rt.Mode(); mode != shared.ModeMember {
		return nil, fmt.Errorf("this server cannot read the shared settings (%s: %s)", mode.Text(), why)
	}
	if rt.Hub().Keys().Active() == nil {
		return nil, errors.New("this server has no cluster key, so the shared passwords and keys cannot be opened")
	}
	nodeID, name, err := x.exportServer(ctx, server)
	if err != nil {
		return nil, err
	}
	files := x.files()
	files.NodeCfg = rt.NodeCfg
	layout := newExportLayout(root, x)
	t := shared.ExportTarget{Under: layout.under, Master: x.c.Keyring(), Server: nodeID, Log: x.log}
	st := rt.Status()
	m := &exportManifest{Server: x.self.Name, NodeID: x.self.NodeID, Version: version, At: time.Now().UTC().Format(time.RFC3339),
		ClusterID: st.ClusterID, Level: st.Level, OwnFrom: name}
	for _, ex := range sharedExporters(x.shared, files) {
		list, err := ex.Run(ctx, t)
		if err != nil {
			return nil, fmt.Errorf("could not export %s: %w", ex.Name, err)
		}
		for _, f := range list {
			rel, err := filepath.Rel(root, f.Path)
			if err != nil {
				return nil, err
			}
			m.Files = append(m.Files, manifestFile{Name: ex.Name, Path: filepath.ToSlash(rel), Dest: f.Dest, Secret: f.Secret})
		}
	}
	for _, k := range slices.Sorted(maps.Keys(exportSkipped)) {
		m.Skipped = append(m.Skipped, manifestSkipped{Name: k, Reason: exportSkipped[k]})
	}
	for _, k := range slices.Sorted(maps.Keys(exportNotFiles)) {
		m.Skipped = append(m.Skipped, manifestSkipped{Name: k, Reason: exportNotFiles[k]})
	}
	m.Folders = layout.used(m.Files)
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := securefile.WriteFile(filepath.Join(root, "MANIFEST.json"), append(data, '\n')); err != nil {
		return nil, err
	}
	if err := securefile.WriteFile(filepath.Join(root, "README.txt"), []byte(exportReadme(m, root, x.readmeEnv()))); err != nil {
		return nil, err
	}
	// The mark that this server exported its files, which a later -retire
	// on it checks for: once the shared settings are put aside, it cannot
	// export them any more.
	mark, err := json.Marshal(exportMark{Dir: root, At: m.At, Version: m.Version, ClusterID: m.ClusterID})
	if err != nil {
		return nil, err
	}
	if err := securefile.WriteFile(exportMarkPath(x.c.StateDir(), m.ClusterID), append(mark, '\n')); err != nil {
		return nil, fmt.Errorf("wrote the files, but could not note that in the state folder: %w", err)
	}
	x.audit("exported the shared settings to files", "dir", root, "files", len(m.Files), "own_settings_of", name)
	return m, nil
}

// exportMark is <state>/exported-<cluster id>.json: this server ran
// signalith cluster export --to-files, into Dir.
type exportMark struct {
	Dir       string `json:"dir"`
	At        string `json:"at"`
	Version   string `json:"version"`
	ClusterID string `json:"cluster_id,omitempty"`
}

// exportMarkPath is where the mark of an export of cluster id goes.
func exportMarkPath(stateDir, id string) string {
	return filepath.Join(stateDir, "exported-"+cmp.Or(id, "cluster")+".json")
}

// exportMarks lists the marks of exports in the state folder.
func exportMarks(stateDir string) []string {
	list, _ := filepath.Glob(filepath.Join(stateDir, "exported-*.json"))
	return list
}

// readmeEnv is what README.txt says the commands for: the platform
// ("linux", "windows" or "docker") and this server's configuration file.
type readmeEnv struct {
	platform string
	config   string
	state    string
}

func (x *clusterCLI) readmeEnv() readmeEnv {
	env := readmeEnv{platform: runtime.GOOS, config: x.c.Path(), state: x.c.StateDir()}
	if deployment() == "docker" {
		env.platform = "docker"
	} else if env.platform != "windows" {
		env.platform = "linux"
	}
	return env
}

// downgradeDocs is the section of docs/servers.md on going back.
const downgradeDocs = "https://github.com/jrsamsanchez/Signalith/blob/main/docs/servers.md#going-back-to-the-previous-version"

// dockerCompose is the start of a Docker Compose command, for README.txt.
const dockerCompose = "docker compose -f deploy/docker/docker-compose.yml"

// exportReadme is README.txt: where each folder of the export goes, with
// the commands that copy it on Linux, Windows and Docker.
func exportReadme(m *exportManifest, root string, env readmeEnv) string {
	var b strings.Builder
	cli, cfg := "signalith", ""
	switch env.platform {
	case "linux":
		cli = "sudo signalith"
	case "windows":
		cli = "& \"$env:ProgramFiles\\Signalith\\signalith.exe\""
	case "docker":
		cli = dockerCompose + " run --rm signalith"
	}
	if env.config != "" {
		cfg = fmt.Sprintf(" -c \"%s\"", env.config)
	}
	fmt.Fprintf(&b, `The shared settings of cluster %s, written by signalith cluster export
--to-files on %s (%s), version %s, at %s.

They are the files a server on its own keeps, for a version that keeps its
settings in files. Passwords and keys in them are sealed with the master key
of %s, so they are for that server only: each server you take back needs its
own export, made on it.

The steps (see "Going back to the previous version",
%s):

  1. Stop every server.
  2. On each server but one: %s cluster export%s --to-files <new folder>
  3. On that one: %s cluster export%s -retire --to-files <new folder>
     On each of the others: %s cluster export%s -retire
  4. On each server, copy the files of its export as below.
  5. Install the previous version and start the servers. The server that runs
     the background jobs makes a new cluster, with a new cluster key, from its
     files.
  6. Give the other servers that key: signalith cluster export-key there, and
     signalith cluster import-key on each of the others. (A server with
     SIGNALITH_CLUSTER_KEY_FILE set uses that key file again instead.)
`, m.ClusterID, m.Server, m.NodeID, m.Version, m.At, m.Server, downgradeDocs, cli, cfg, cli, cfg, cli, cfg)
	if env.platform == "docker" {
		fmt.Fprintf(&b, `
In Docker, the export folder must be a new folder directly in %s (the
signalith-data volume), such as %s/export: anything else is lost with the
container. For a server added with "Add a server", use
  docker compose -f deploy/docker/docker-compose.server.yml --env-file deploy/docker/join.env
in place of %s, and -c /var/lib/signalith/signalith.yaml.
`, cmp.Or(env.state, "/var/lib/signalith"), cmp.Or(env.state, "/var/lib/signalith"), dockerCompose)
	}
	b.WriteString("\nCopying the files:\n\n")
	for _, f := range m.Folders {
		src := filepath.Join(root, filepath.FromSlash(f.Path))
		fmt.Fprintf(&b, "%s -> %s\n", src, f.Dest)
		switch env.platform {
		case "windows":
			fmt.Fprintf(&b, "  Copy-Item -Path \"%s\\*\" -Destination \"%s\" -Recurse -Force\n\n", src, f.Dest)
		case "docker":
			if _, ok := relWithin(env.state, f.Dest); env.state != "" && ok {
				fmt.Fprintf(&b, "  %s run --rm --entrypoint cp signalith -r \"%s/.\" \"%s/\"\n\n", dockerCompose, src, f.Dest)
			} else {
				fmt.Fprintf(&b, "  This folder is not in the signalith-data volume. Copy the folder out with\n"+
					"    %s cp signalith:\"%s\" ./signalith-export-%s\n"+
					"  and its files into what your compose file mounts at %s.\n\n", dockerCompose, src, f.Path, f.Dest)
			}
		default:
			// One file at a time, so only the files copied change owner.
			for _, file := range m.Files {
				if file.Path != f.Path && !strings.HasPrefix(file.Path, f.Path+"/") {
					continue
				}
				fmt.Fprintf(&b, "  sudo install -D -o signalith -g signalith -m 0600 \"%s\" \"%s\"\n",
					filepath.Join(root, filepath.FromSlash(file.Path)), file.Dest)
			}
			b.WriteString("\n")
		}
	}
	var loose []manifestFile
	for _, file := range m.Files {
		if !slices.ContainsFunc(m.Folders, func(f manifestFolder) bool {
			return file.Path == f.Path || strings.HasPrefix(file.Path, f.Path+"/")
		}) {
			loose = append(loose, file)
		}
	}
	if len(loose) > 0 {
		b.WriteString("Files outside those folders, one by one:\n")
		for _, file := range loose {
			src := filepath.Join(root, filepath.FromSlash(file.Path))
			switch env.platform {
			case "windows":
				fmt.Fprintf(&b, "  Copy-Item -Path \"%s\" -Destination \"%s\" -Force\n", src, file.Dest)
			case "docker":
				fmt.Fprintf(&b, "  %s -> what your compose file mounts at %s\n", src, file.Dest)
			default:
				fmt.Fprintf(&b, "  sudo install -D -o signalith -g signalith -m 0600 \"%s\" \"%s\"\n", src, file.Dest)
			}
		}
		b.WriteString("\n")
	}
	if env.platform == "docker" {
		fmt.Fprintf(&b, "Then give the files to the user Signalith runs as:\n  %s run --rm --user 0 --entrypoint chown signalith -R 65532:65532 \"%s\"\n\n",
			dockerCompose, cmp.Or(env.state, "/var/lib/signalith"))
	}
	b.WriteString("The files:\n")
	for _, f := range m.Files {
		mark := ""
		if f.Secret {
			mark = " (passwords or keys: keep it private)"
		}
		fmt.Fprintf(&b, "  %s -> %s%s\n", f.Path, f.Dest, mark)
	}
	b.WriteString(`
Not written:
`)
	for _, s := range m.Skipped {
		fmt.Fprintf(&b, "  %s: %s\n", s.Name, s.Reason)
	}
	fmt.Fprintf(&b, `
Also:
  - The built-in admin stays as signalith.yaml (and signalith passwd) set it on
    each server; the users' file holds every other user.
  - The feeds of signalith.yaml on any server are in intel_feeds.yaml too.
  - The settings file holds every shared setting and the own settings of %s.
  - If the tls folder holds cluster-ca.txt, delete it: the cluster's
    certificate authority is this server's own again (ca.pem and ca.key).
`, m.OwnFrom)
	return b.String()
}

// retire is signalith cluster export -retire: with every server stopped,
// the first server exports its files (dir), copies the config index into
// a retired copy and deletes it; every server moves its copy of the shared
// settings (cache.enc) and its cluster keys into a retired folder of its
// state folder. The previous version then starts with no cluster
// document and no key, and the server that runs the jobs founds a new
// cluster from the files.
func (x *clusterCLI) retire(ctx context.Context, dir, server string, yes, force bool) error {
	peers, err := x.peers(ctx, cliWatch)
	if err != nil {
		return fmt.Errorf("could not read the servers' heartbeats: %w", err)
	}
	for _, p := range peers {
		if p.Live {
			return fmt.Errorf("%s is running: stop every server of the cluster first", p.Name)
		}
	}
	return cluster.WhileStopped(x.c.StateDir(), func() error {
		cfg := shared.ConfigIndex(x.prefix())
		have, err := x.cl.ListIndices(ctx, cfg)
		// OpenSearch answers an exact name that is not there with 404.
		if se := (*store.Error)(nil); errors.As(err, &se) && se.Status == http.StatusNotFound {
			have, err = nil, nil
		}
		if err != nil {
			return err
		}
		retired, err := x.cl.ListIndices(ctx, shared.RetiredConfigPattern(x.prefix()))
		if err != nil {
			return err
		}
		var stamp, index string
		var m *exportManifest
		switch {
		case slices.Contains(have, cfg):
			if dir == "" {
				return errors.New("the shared settings are still in OpenSearch: the first server retired writes its files, so add --to-files <dir>")
			}
			root, err := x.checkExportDir(dir)
			if err != nil {
				return err
			}
			if err := x.confirm(fmt.Sprintf("Put the shared settings (%s) aside for a downgrade, after writing this server's files into %s?", cfg, root), yes); err != nil {
				return err
			}
			if m, err = x.writeExport(ctx, root, server); err != nil {
				return err
			}
			stamp = time.Now().UTC().Format("20060102T150405")
			index = shared.RetiredConfigIndex(x.prefix(), stamp)
			n, err := shared.RetireConfig(ctx, x.cl, x.prefix(), stamp)
			if err != nil {
				return err
			}
			fmt.Fprintf(x.out, "Copied the %d documents of %s into %s and deleted %s.\n", n, cfg, index, cfg)
		case len(retired) > 0:
			if dir != "" {
				return fmt.Errorf("the shared settings were put aside already (%s), so they cannot be exported here: "+
					"run signalith cluster export -retire without --to-files, and use the files this server exported before", slices.Max(retired))
			}
			index = slices.Max(retired)
			stamp = strings.TrimPrefix(index, shared.RetiredConfigIndex(x.prefix(), ""))
			if len(exportMarks(x.c.StateDir())) == 0 && !force {
				return fmt.Errorf("this server never ran signalith cluster export --to-files, and the shared settings were put aside already (%s), "+
					"so its feed passwords, shared secret settings and directory bind password could not be opened by the previous version. "+
					"Copy %s back into %s to export first, or add -force to go on without files", index, index, cfg)
			}
			if err := x.confirm(fmt.Sprintf("Put this server's copy of the shared settings and its cluster keys aside (%s)?", index), yes); err != nil {
				return err
			}
		default:
			return fmt.Errorf("OpenSearch holds no shared settings (%s) and no copy put aside: there is nothing to retire", cfg)
		}
		moved, err := retireLocal(x.c.StateDir(), stamp)
		if err != nil {
			return err
		}
		x.audit("retired the shared settings for a downgrade", "index", index, "dir", dir, "moved", strings.Join(moved, ","))
		if len(moved) > 0 {
			fmt.Fprintf(x.out, "Moved %s into %s.\n", strings.Join(moved, ", "), filepath.Join(x.c.StateDir(), "retired-"+stamp))
		}
		if m != nil {
			fmt.Fprintf(x.out, "Wrote %d files into %s: copy them as its README.txt says, then start the previous version.\n", len(m.Files), absPath(dir))
		} else {
			fmt.Fprintln(x.out, "Copy the files this server exported as their README.txt says, then start the previous version.")
		}
		return nil
	})
}

// retireLocal moves this server's copy of the shared settings and its
// cluster keys into <state>/retired-<stamp>; node.id and node.key stay.
func retireLocal(stateDir, stamp string) ([]string, error) {
	dest := filepath.Join(stateDir, "retired-"+stamp)
	list := shared.ClusterKeyFiles(stateDir)
	if _, err := os.Stat(shared.CachePath(stateDir)); err == nil {
		list = append([]string{shared.CachePath(stateDir)}, list...)
	}
	var moved []string
	for _, p := range list {
		if err := os.MkdirAll(dest, 0o700); err != nil {
			return moved, err
		}
		if err := os.Rename(p, filepath.Join(dest, filepath.Base(p))); err != nil {
			return moved, err
		}
		moved = append(moved, filepath.Base(p))
	}
	return moved, nil
}
