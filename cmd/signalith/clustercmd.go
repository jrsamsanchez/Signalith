package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clusterauth"
	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const clusterUsage = `usage:
  signalith cluster status         [-c file] [-json]          this server's place in the cluster, the keyring and any problem
  signalith cluster found          [-c file] [-force] [-name n]   make the servers sharing this OpenSearch a cluster, from this server's files
  signalith cluster export         [-c file] [-o file]        the shared settings as YAML (stored passwords stay encrypted)
  signalith cluster export -settings [-c file] [-o file] [-server s]   the settings the servers share, as a file cluster apply takes
  signalith cluster apply          [-c file] -f file [-yes]   change the settings the servers share to those of a file
  signalith cluster import         [-c file] -from-cache      write this server's copy of the shared settings back to OpenSearch
  signalith cluster export-key     [-c file] [-o file]        the cluster key, encrypted with a passphrase, for another server
  signalith cluster import-key     [-c file] <file>           give this server the cluster key that export-key wrote
  signalith cluster reset-key      [-c file] [-yes]           make a new cluster key when every copy of it is lost
  signalith cluster accept-restore [-c file] [-yes]           accept the shared settings after an OpenSearch snapshot was restored
  signalith cluster tls            [-c file] [-json]          the cluster's certificate authority and each server's
  signalith cluster tls choose     [-c file] [-yes] <server|fingerprint>   keep that certificate authority for the whole cluster
  signalith cluster upgrade-check  [-c file] [-json]          whether it is safe to upgrade the next server

The servers that share one OpenSearch keep the settings they share in it
(the <prefix>_config index), signed with the cluster key that each of them
keeps in its state folder. The server that runs the background jobs makes
the cluster by itself; these commands are for when something went wrong.
Only found and reset-key change the cluster without a running server's
help; the others may run while the server runs. apply changes the shared
settings as a Settings page does: what applies at once does so on every
server within a few seconds.
`

// cmdCluster runs signalith cluster.
func cmdCluster(args []string) error { return runCluster(args, os.Stdin, os.Stdout, os.Stderr) }

// clusterCLI is what every cluster command works with.
type clusterCLI struct {
	c      *config.Config
	cl     *store.Client
	log    *slog.Logger
	self   cluster.Identity
	in     *os.File
	out    io.Writer
	errOut io.Writer
	by     string
	// auth holds the users' documents of the runtime made last, and docs
	// its documents of the shared content and settings.
	auth *clusterauth.Docs
	docs *clustercfg.Docs
	// tls holds the cluster's certificate authority of the same runtime.
	tls *sharedTLS
}

// runCluster is cmdCluster with its input and output.
func runCluster(args []string, in *os.File, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New(clusterUsage)
	}
	sub, args := args[0], args[1:]
	flags := flag.NewFlagSet("cluster "+sub, flag.ExitOnError)
	flags.Usage = func() { fmt.Fprint(errOut, clusterUsage) }
	path := configFlag(flags)
	asJSON := flags.Bool("json", false, "print as JSON")
	force := flags.Bool("force", false, "found even though a server that may run the background jobs seems up")
	name := flags.String("name", "", "the cluster's name (default Signalith)")
	outFile := flags.String("o", "", "write to this file instead of the standard output")
	fromCache := flags.Bool("from-cache", false, "write this server's copy of the shared settings (cache.enc) back")
	yes := flags.Bool("yes", false, "do it without asking")
	settingsOnly := flags.Bool("settings", false, "export the settings the servers share, as a file signalith cluster apply takes")
	server := flags.String("server", "", "with -settings, only this server's own settings (a name or node id)")
	file := flags.String("f", "", "the file of settings to apply")
	pos := parseInterleaved(flags, args)
	switch sub {
	case "status", "found", "export", "import", "export-key", "import-key", "reset-key", "accept-restore", "apply", "tls", "upgrade-check":
	default:
		return fmt.Errorf("unknown cluster command %q\n\n%s", sub, clusterUsage)
	}
	useServiceEnv(*path, errOut)
	log := newLogger(errOut)
	c, err := loadConfig(*path, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	x := &clusterCLI{c: c, log: log, in: in, out: out, errOut: errOut, by: cliUser()}
	if x.self, err = cluster.ReadIdentity(c.StateDir()); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("this server has no identity yet (no node.id in %s): start it once with signalith serve, or check SIGNALITH_STATE_DIR", c.StateDir())
		}
		return err
	}
	if x.cl, err = cliOpenSearch(ctx, c, "the cluster cannot be read or changed"); err != nil {
		return err
	}
	switch sub {
	case "status":
		return x.status(ctx, *asJSON)
	case "found":
		return x.found(ctx, *force, *name)
	case "export":
		if *settingsOnly {
			return x.exportSettings(ctx, *outFile, *server)
		}
		return x.export(ctx, *outFile)
	case "apply":
		if *file == "" {
			return errors.New("usage: signalith cluster apply [-c file] -f file [-yes]")
		}
		return x.apply(ctx, *file, *yes)
	case "import":
		if !*fromCache {
			return errors.New("signalith cluster import needs -from-cache: it writes this server's copy of the shared settings back to OpenSearch")
		}
		return x.importCache(ctx)
	case "export-key":
		return x.exportKey(ctx, *outFile)
	case "import-key":
		if len(pos) != 1 {
			return errors.New("usage: signalith cluster import-key <file that signalith cluster export-key wrote>")
		}
		return x.importKey(ctx, pos[0])
	case "reset-key":
		return x.resetKey(ctx, *yes)
	case "accept-restore":
		return x.acceptRestore(ctx, *yes)
	case "tls":
		return x.tlsCommand(ctx, pos, *asJSON, *yes)
	case "upgrade-check":
		return upgradeExit(x.upgradeCheck(ctx, *asJSON))
	}
	return nil
}

// cliOpenSearch returns a client of c's OpenSearch once it answers.
func cliOpenSearch(ctx context.Context, c *config.Config, what string) (*store.Client, error) {
	cl := newStore(c)
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, err := cl.Health(hctx)
	cancel()
	if err != nil {
		if store.Problem(err) == "" {
			return nil, fmt.Errorf("OpenSearch is not reachable, so %s: %w", what, err)
		}
		return nil, fmt.Errorf("%s: %s", what, store.Unusable(err))
	}
	return cl, nil
}

func (x *clusterCLI) prefix() string { return x.c.OpenSearch.IndexPrefix }

func (x *clusterCLI) keyStore() shared.KeyStore {
	return shared.KeyStore{Dir: x.c.StateDir(), Master: x.c.Keyring()}
}

// runtime returns a runtime that has looked for the cluster once.
// readOnly writes nothing to OpenSearch or the state folder.
func (x *clusterCLI) runtime(readOnly bool, name string) *shared.Runtime {
	d := newSharedDocs(clusterauth.NewDocs())
	x.docs, x.auth, x.tls = d.docs, d.auth, d.tls
	files := x.files()
	var made atomic.Pointer[shared.Runtime]
	files.NodeCfg = func() *shared.Doc[shared.NodeCfg] {
		if rt := made.Load(); rt != nil {
			return rt.NodeCfg()
		}
		return nil
	}
	rt := shared.NewRuntime(shared.RuntimeOptions{
		StateDir: x.c.StateDir(), Self: shared.Self{NodeID: x.self.NodeID, Name: x.self.Name},
		KeyFile: os.Getenv(clusterKeyFileEnv), ClusterName: name, ReadOnly: readOnly, Log: x.log,
		Peers: func() []shared.Peer {
			peers, _ := x.peers(context.Background(), 0)
			return peers
		},
		// A founding from the command line imports this server's feeds,
		// retention policies and users, as the server's own would.
		Content:   d.track,
		Importers: sharedImporters(d, files),
	})
	made.Store(rt)
	x.auth.Cluster = rt.Cluster
	rt.Use(x.cl, x.prefix(), x.c.Keyring())
	return rt
}

// files is what the importers read, for a founding from the command
// line.
func (x *clusterCLI) files() clustercfg.Files {
	return clustercfg.Files{
		Config: func() *config.Config { return x.c },
		Node:   x.self.Name, NodeID: x.self.NodeID,
		Client: func() (*store.Client, string) { return x.cl, x.prefix() },
		Peers: func() map[string]string {
			return heartbeatRetention(context.Background(), x.cl, x.prefix(), x.self.NodeID)
		},
		Log: x.log,
	}
}

// cliHeartbeatAge is how old a heartbeat may be for its server to count
// as up, when the command does not watch the heartbeats.
const cliHeartbeatAge = 30 * time.Second

// cliWatch is how long found, reset-key and accept-restore watch the
// heartbeats: a server whose heartbeat changes meanwhile is up, whatever
// the clocks say.
var cliWatch = 12 * time.Second

// peers reads the servers' heartbeats. With watch, they are read again
// after watch, and a server is up when its heartbeat changed; without, when
// it is under cliHeartbeatAge old by this computer's clock.
func (x *clusterCLI) peers(ctx context.Context, watch time.Duration) ([]shared.Peer, error) {
	read := func() (map[string]store.Doc, error) {
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		docs, err := x.cl.SearchDocs(rctx, cluster.RuntimeIndex(x.prefix()), map[string]any{"term": map[string]any{"kind": "node"}})
		out := map[string]store.Doc{}
		for _, d := range docs {
			out[d.ID] = d
		}
		return out, err
	}
	first, err := read()
	if err != nil {
		return nil, err
	}
	second := first
	if watch > 0 {
		fmt.Fprintf(x.errOut, "Watching the servers' heartbeats for %s...\n", watch)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(watch):
		}
		if second, err = read(); err != nil {
			return nil, err
		}
	}
	var out []shared.Peer
	for id, d := range second {
		var hb cluster.Heartbeat
		if json.Unmarshal(d.Source, &hb) != nil || hb.NodeID == "" {
			continue
		}
		live := hb.State != cluster.StateStopped
		if watch > 0 {
			live = live && !first[id].Version.Same(d.Version)
		} else {
			live = live && time.Since(hb.HeartbeatAt) < cliHeartbeatAge
		}
		p := shared.Peer{NodeID: hb.NodeID, Name: hb.Name, Live: live, Eligible: hb.LeaderEligible,
			Leader: hb.Leader, MaxRev: hb.MaxRev, LevelMax: hb.LevelMax, Users: hb.FilesFingerprint.Users}
		if !live {
			p.SeenAgo = max(time.Since(hb.HeartbeatAt), 0)
		}
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b shared.Peer) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// audit logs a change made from the command line.
func (x *clusterCLI) audit(msg string, args ...any) {
	x.log.Info(msg, append([]any{"audit", true, "by", x.by}, args...)...)
}

// confirm asks a yes or no question at the terminal.
func (x *clusterCLI) confirm(question string, yes bool) error {
	if yes {
		return nil
	}
	if !term.IsTerminal(int(x.in.Fd())) {
		return errors.New("add -yes to do this when not at a terminal")
	}
	fmt.Fprintf(x.errOut, "%s [y/N] ", question)
	line, _ := bufio.NewReader(x.in).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
		return errors.New("nothing was changed")
	}
	return nil
}

// clusterStatus is what signalith cluster status -json prints.
type clusterStatus struct {
	Server   string                          `json:"server"`
	NodeID   string                          `json:"node_id"`
	Status   shared.Status                   `json:"shared"`
	Keyring  map[string]shared.KeyringMember `json:"keyring,omitempty"`
	Keys     []string                        `json:"keys,omitempty"`
	Problems []shared.Problem                `json:"problems,omitempty"`
	Warnings []string                        `json:"warnings,omitempty"`
}

func (x *clusterCLI) status(ctx context.Context, asJSON bool) error {
	rt := x.runtime(true, "")
	st := rt.Status()
	out := clusterStatus{Server: x.self.Name, NodeID: x.self.NodeID, Status: st, Problems: rt.Hub().Problems()}
	if kr, ok := rt.Keyring().Get(); ok {
		out.Keyring, out.Keys = kr.Members, kr.KIDs()
	}
	for _, w := range rt.Warnings() {
		out.Warnings = append(out.Warnings, w.Text)
	}
	if asJSON {
		enc := json.NewEncoder(x.out)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	w := tabwriter.NewWriter(x.out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "This server:\t%s (%s)\n", x.self.Name, x.self.NodeID)
	fmt.Fprintf(w, "Mode:\t%s: %s\n", st.Mode, st.Mode.Text())
	if st.Why != "" {
		fmt.Fprintf(w, "\t%s\n", st.Why)
	}
	if st.ClusterID != "" {
		fmt.Fprintf(w, "Cluster:\t%s (%s), level %d; this version reads levels %d to %d\n", st.ClusterName, st.ClusterID, st.Level, st.LevelMin, st.LevelMax)
	}
	if st.ClusterKID != "" {
		fmt.Fprintf(w, "Cluster key:\t%s\n", st.ClusterKID)
	}
	if st.Fingerprint != "" {
		fmt.Fprintf(w, "Fingerprint:\t%s\n", st.Fingerprint)
	}
	w.Flush()
	if len(out.Keyring) > 0 {
		fmt.Fprintf(x.out, "\nKeyring (keys %s):\n", strings.Join(out.Keys, ", "))
		w = tabwriter.NewWriter(x.out, 0, 0, 2, ' ', 0)
		ids := make([]string, 0, len(out.Keyring))
		for id := range out.Keyring {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			m := out.Keyring[id]
			fmt.Fprintf(w, "  %s\t%s\t%s\tadded %s (%s)\n", m.Name, id, m.Fingerprint, m.AddedAt, m.AddedBy)
		}
		w.Flush()
	}
	if len(out.Problems) > 0 {
		fmt.Fprintln(x.out, "\nShared settings not in use (the last good copy is):")
		for _, p := range out.Problems {
			fmt.Fprintf(x.out, "  %s (%s): %s\n", p.ID, p.Kind, p.Reason)
		}
	}
	if len(out.Warnings) > 0 {
		fmt.Fprintln(x.out)
		for _, t := range out.Warnings {
			fmt.Fprintln(x.out, t)
		}
	}
	return nil
}

func (x *clusterCLI) found(ctx context.Context, force bool, name string) error {
	rt := x.runtime(false, name)
	switch m, why := rt.Mode(); m {
	case shared.ModeLegacyC:
	case shared.ModeGone:
		if _, _, err := shared.CacheHeader(shared.CachePath(x.c.StateDir())); err == nil {
			return errors.New("this server was a member of a cluster whose shared settings are gone from OpenSearch, and it keeps a copy of them: " +
				"restore them with signalith cluster import -from-cache rather than found a new cluster")
		}
		if !force {
			return errors.New("this server keeps a cluster key but no copy of the shared settings, which are gone from OpenSearch. " +
				"If no server keeps a copy (signalith cluster import -from-cache), found the cluster again from this server's files with -force")
		}
	case shared.ModeLegacyA, shared.ModeStarting:
		return fmt.Errorf("could not look for the cluster: %s", why)
	default:
		return fmt.Errorf("the servers sharing this OpenSearch are a cluster already (this server: %s)", m.Text())
	}
	if !force {
		peers, err := x.peers(ctx, cliWatch)
		if err != nil {
			return fmt.Errorf("could not read the servers' heartbeats: %w", err)
		}
		for _, p := range peers {
			if p.Live && p.Eligible {
				return fmt.Errorf("%s is up and may run the background jobs, so it founds the cluster by itself within seconds of running them. "+
					"Use -force to found it from this server's files anyway", p.Name)
			}
		}
	}
	if err := rt.Found(ctx, x.by); err != nil {
		return err
	}
	st := rt.Status()
	x.audit("founded the cluster from the command line", "cluster_id", st.ClusterID, "cluster_key", st.ClusterKID)
	fmt.Fprintf(x.out, "Founded cluster %q (%s) with cluster key %s, from this server's files.\n"+
		"Give the other servers the key: signalith cluster export-key here, then signalith cluster import-key there.\n",
		st.ClusterName, st.ClusterID, st.ClusterKID)
	return nil
}

// exportedDoc is one shared document as signalith cluster export writes
// it.
type exportedDoc struct {
	ID        string    `yaml:"id"`
	Kind      string    `yaml:"kind"`
	Format    int       `yaml:"format"`
	Rev       int64     `yaml:"rev"`
	Deleted   bool      `yaml:"deleted,omitempty"`
	UpdatedAt string    `yaml:"updated_at"`
	UpdatedBy shared.By `yaml:"updated_by"`
	// Verified says whether its MAC checks out with this server's cluster
	// key: "yes", "no (why)" or "no key".
	Verified string `yaml:"verified"`
	Body     any    `yaml:"body"`
}

func (x *clusterCLI) export(ctx context.Context, outFile string) error {
	rt := x.runtime(true, "")
	keys := rt.Hub().Keys()
	docs, bad, err := shared.ReadAll(ctx, x.cl, x.prefix())
	if err != nil {
		return err
	}
	list := make([]exportedDoc, 0, len(docs))
	for _, d := range docs {
		e := d.Envelope
		ed := exportedDoc{ID: d.ID, Kind: e.Kind, Format: e.Format, Rev: e.Rev, Deleted: e.Deleted, UpdatedAt: e.UpdatedAt,
			UpdatedBy: e.UpdatedBy, Verified: "no key"}
		if keys.Active() != nil {
			ed.Verified = "yes"
			if err := shared.Verify(keys, d.ID, &e); err != nil {
				ed.Verified = "no (" + err.Error() + ")"
			}
		}
		if e.Body != "" {
			var body any
			if err := json.Unmarshal([]byte(e.Body), &body); err != nil {
				body = e.Body
			}
			ed.Body = body
		}
		list = append(list, ed)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# The shared settings in %s, exported by %s on %s.\n# Stored passwords and keys stay encrypted.\n",
		shared.ConfigIndex(x.prefix()), x.self.Name, time.Now().UTC().Format(time.RFC3339))
	for _, id := range bad {
		fmt.Fprintf(&b, "# %s is not a document Signalith wrote; left out.\n", id)
	}
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(map[string]any{"documents": list}); err != nil {
		return err
	}
	return x.write(outFile, []byte(b.String()))
}

// write writes data to file, readable by this user only, or to the
// standard output.
func (x *clusterCLI) write(file string, data []byte) error {
	if file == "" {
		_, err := x.out.Write(data)
		return err
	}
	p, err := securefile.PreparePrivate(file, data)
	if err != nil {
		return err
	}
	if err := p.Commit(); err != nil {
		return err
	}
	fmt.Fprintf(x.errOut, "Wrote %s.\n", file)
	return nil
}

func (x *clusterCLI) importCache(ctx context.Context) error {
	path := shared.CachePath(x.c.StateDir())
	id, prefix, err := shared.CacheHeader(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("this server keeps no copy of the shared settings (%s): restore them on a server that does", path)
		}
		return err
	}
	if prefix != x.prefix() {
		return fmt.Errorf("this server's copy of the shared settings is of the index prefix %q, not %q", prefix, x.prefix())
	}
	cache := shared.Cache{Path: path, Master: x.c.Keyring(), ClusterID: id, Prefix: prefix}
	d, err := cache.Read(time.Now())
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	// Not into another cluster founded meanwhile.
	src, _, found, err := x.cl.Get(ctx, shared.ConfigIndex(prefix), shared.ClusterDocID)
	if err != nil {
		return err
	}
	if found {
		var e shared.Envelope
		var body shared.ClusterBody
		if json.Unmarshal(src, &e) == nil && json.Unmarshal([]byte(e.Body), &body) == nil && body.ClusterID != id {
			return fmt.Errorf("OpenSearch holds another cluster (%s) now; this server's copy is of %s, so nothing was written", body.ClusterID, id)
		}
	}
	written, there, err := shared.RestoreFromCache(ctx, x.cl, prefix, d)
	x.audit("restored the shared settings from this server's copy", "cluster_id", id, "written", len(written), "already_there", len(there))
	fmt.Fprintf(x.out, "Wrote back %d shared documents from this server's copy (written %s); %d were there already.\n"+
		"The servers resume within seconds.\n", len(written), d.WrittenAt.Format(time.RFC3339), len(there))
	return err
}

// clusterKey returns the cluster key this server signs with.
func (x *clusterCLI) clusterKey() (*shared.ClusterKey, error) {
	rt := x.runtime(true, "")
	if k := rt.Hub().Keys().Active(); k != nil {
		return k, nil
	}
	stored, err := x.keyStore().ClusterKeys()
	if err != nil {
		return nil, err
	}
	switch len(stored) {
	case 0:
		return nil, errors.New("this server has no cluster key")
	case 1:
		return stored[0], nil
	}
	return nil, errors.New("this server keeps several cluster keys and none checks out against the cluster in OpenSearch")
}

func (x *clusterCLI) exportKey(ctx context.Context, outFile string) error {
	k, err := x.clusterKey()
	if err != nil {
		return err
	}
	fmt.Fprintln(x.errOut, "The key is encrypted with a passphrase; import-key on the other server asks for it. Use at least 12 characters.")
	pass, err := readSecret(x.in, x.errOut, "Passphrase: ", false)
	if err != nil {
		return err
	}
	if len(pass) < 12 {
		return errors.New("the passphrase is shorter than 12 characters; nothing was written")
	}
	text, err := shared.ExportKey(k, []byte(pass))
	if err != nil {
		return err
	}
	if err := x.write(outFile, []byte(text+"\n")); err != nil {
		return err
	}
	x.audit("exported the cluster key", "cluster_key", k.ID())
	return nil
}

func (x *clusterCLI) importKey(ctx context.Context, file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	pass, err := readPassphrase(x.in, x.errOut, "Passphrase: ")
	if err != nil {
		return err
	}
	k, err := shared.ImportKey(strings.TrimSpace(string(data)), []byte(pass))
	if err != nil {
		return err
	}
	if err := x.keyStore().SaveClusterKey(k); err != nil {
		return err
	}
	x.audit("imported a cluster key", "cluster_key", k.ID())
	rt := x.runtime(true, "")
	m, _ := rt.Mode()
	switch {
	case rt.Status().ClusterKID == k.ID() && (m == shared.ModeMember || m == shared.ModeImporting):
		fmt.Fprintf(x.out, "Kept cluster key %s in this server's state folder. The shared settings check out with it; a running server joins within seconds.\n", k.ID())
	default:
		fmt.Fprintf(x.out, "Kept cluster key %s in this server's state folder, but the shared settings in OpenSearch do not check out with it (%s).\n", k.ID(), m.Text())
	}
	return nil
}

// readPassphrase reads a passphrase once, without showing it.
func readPassphrase(in *os.File, prompt io.Writer, label string) (string, error) {
	fd := int(in.Fd())
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(in).ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if err != nil && !errors.Is(err, io.EOF) {
				return "", err
			}
			return "", errors.New("no passphrase entered; nothing was changed")
		}
		return line, nil
	}
	fmt.Fprint(prompt, label)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(prompt)
	if err == nil && len(b) == 0 {
		err = errors.New("no passphrase entered; nothing was changed")
	}
	return string(b), err
}

func (x *clusterCLI) resetKey(ctx context.Context, yes bool) error {
	// No server may run on this state folder meanwhile.
	local, err := cluster.OpenLocal(x.c.StateDir(), cluster.LocalOptions{Name: x.c.Cluster.NodeName, InContainer: cluster.InContainer()})
	if err != nil {
		return err
	}
	defer local.Close()
	peers, err := x.peers(ctx, cliWatch)
	if err != nil {
		return fmt.Errorf("could not read the servers' heartbeats: %w", err)
	}
	var peerMax int64
	for _, p := range peers {
		if p.Live {
			return fmt.Errorf("%s is up: stop every server before making a new cluster key", p.Name)
		}
		peerMax = max(peerMax, p.MaxRev)
	}
	docs, bad, err := shared.ReadAll(ctx, x.cl, x.prefix())
	if err != nil {
		return err
	}
	if len(docs) == 0 {
		return errors.New("there are no shared settings in OpenSearch to sign: signalith cluster found makes a cluster")
	}
	// What this server's copy says, next to what is stored now.
	copyOf := map[string]shared.Envelope{}
	path := shared.CachePath(x.c.StateDir())
	if id, prefix, err := shared.CacheHeader(path); err == nil && prefix == x.prefix() {
		cache := shared.Cache{Path: path, Master: x.c.Keyring(), ClusterID: id, Prefix: prefix}
		if d, err := cache.Read(time.Now()); err == nil {
			for _, cd := range d.Docs {
				var e shared.Envelope
				if json.Unmarshal(cd.Source, &e) == nil {
					copyOf[cd.ID] = e
				}
			}
			peerMax = max(peerMax, d.MaxRev)
		}
	}
	// The keys this server has: when one still checks out the cluster
	// document, the key is not lost, and other servers get it with
	// export-key instead. A document that fails under a key this server
	// has was changed outside Signalith, and is not signed again.
	held, err := x.keyStore().ClusterKeys()
	if err != nil {
		return err
	}
	if p := os.Getenv(clusterKeyFileEnv); p != "" {
		if k, err := shared.KeyFromFile(p); err == nil {
			held = append(held, k)
		}
	}
	var keys *shared.KeySet
	if len(held) > 0 {
		keys = shared.NewKeySet(held[0], held[1:]...)
	}
	check := func(e *shared.Envelope, id string) (string, bool) {
		if keys == nil {
			return "no key here", true
		}
		err := shared.Verify(keys, id, e)
		var uk *shared.UnknownKeyError
		switch {
		case err == nil:
			return "checks out", true
		case errors.As(err, &uk):
			return "no key here", true
		}
		return "changed outside Signalith", false
	}
	for _, d := range docs {
		if d.ID != shared.ClusterDocID {
			continue
		}
		if note, _ := check(&d.Envelope, d.ID); note == "checks out" {
			return errors.New("this server still has the cluster key: the shared settings check out with it, so it is not lost. " +
				"Give it to the other servers with signalith cluster export-key here and signalith cluster import-key there")
		}
	}
	var sign []shared.StoredDoc
	var refused []string
	fmt.Fprintln(x.out, "This server cannot check the shared settings below with a key it has. Look at them (signalith cluster export shows them in full) before you sign them with a new key:")
	w := tabwriter.NewWriter(x.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  DOCUMENT\tREVISION\tCHANGED\tBY\tSIGNATURE\tTHIS SERVER'S COPY")
	for _, d := range docs {
		e := d.Envelope
		peerMax = max(peerMax, e.Rev)
		sig, ok := check(&e, d.ID)
		if ok {
			sign = append(sign, d)
		} else {
			refused = append(refused, d.ID)
		}
		note := "none"
		if c, ok := copyOf[d.ID]; ok {
			switch {
			case c.Rev == e.Rev && c.Body == e.Body && c.Deleted == e.Deleted:
				note = "the same"
			default:
				note = fmt.Sprintf("differs (revision %d there)", c.Rev)
			}
		}
		fmt.Fprintf(w, "  %s\t%d\t%s\t%s on %s\t%s\t%s\n", d.ID, e.Rev, e.UpdatedAt, e.UpdatedBy.User, e.UpdatedBy.Node, sig, note)
	}
	w.Flush()
	for _, id := range bad {
		fmt.Fprintf(x.out, "  %s is not a document Signalith wrote; it is left as it is.\n", id)
	}
	for _, id := range refused {
		fmt.Fprintf(x.out, "  %s was changed outside Signalith: it is not signed with the new key, so every server ignores it.\n", id)
	}
	if len(sign) == 0 {
		return errors.New("none of the shared settings can be signed again")
	}
	docs = sign
	if err := x.confirm("Sign these with a new cluster key? Every other server then needs the new key (export-key, import-key).", yes); err != nil {
		return err
	}
	k, err := shared.NewClusterKey()
	if err != nil {
		return err
	}
	ks := x.keyStore()
	nk, err := ks.NodeKey()
	if err != nil {
		return err
	}
	if err := ks.SaveClusterKey(k); err != nil {
		return err
	}
	at := time.Now().UTC().Format(time.RFC3339Nano)
	self := shared.KeyringMember{Name: x.self.Name, NodePub: nk.PublicText(), Fingerprint: nk.Fingerprint(), AddedAt: at, AddedBy: shared.AddedByFounder}
	dropped, err := shared.Resign(ctx, x.cl, x.prefix(), docs, k, peerMax+1, x.by, x.self.Name, at, x.self.NodeID, self)
	x.audit("made a new cluster key and signed the shared settings with it", "cluster_key", k.ID(), "documents", len(docs), "values_dropped", len(dropped))
	// The copy is of the old key's documents.
	_ = os.Remove(path)
	fmt.Fprintf(x.out, "Signed %d shared documents with the new cluster key %s.\n", len(docs), k.ID())
	if len(dropped) > 0 {
		fmt.Fprintln(x.out, "These stored passwords and keys were encrypted with the lost key and were emptied; enter them again:")
		for _, d := range dropped {
			fmt.Fprintln(x.out, "  "+d)
		}
	}
	fmt.Fprintln(x.out, "Give the other servers the new key: signalith cluster export-key here, then signalith cluster import-key there.")
	return err
}

func (x *clusterCLI) acceptRestore(ctx context.Context, yes bool) error {
	// Read-only: the server may run meanwhile, and only the documents are
	// signed again here; this server's own files are left to it.
	rt := x.runtime(true, "")
	if m, _ := rt.Mode(); m != shared.ModeMember && m != shared.ModeKeyMissing {
		return fmt.Errorf("this server is not a member of the cluster now (%s)", m.Text())
	}
	if err := x.confirm("Accept the shared settings now in OpenSearch on every server, as restored from a snapshot?", yes); err != nil {
		return err
	}
	peers, err := x.peers(ctx, 0)
	if err != nil {
		return fmt.Errorf("could not read the servers' heartbeats: %w", err)
	}
	var peerMax int64
	for _, p := range peers {
		peerMax = max(peerMax, p.MaxRev)
	}
	if err := rt.AcceptRestore(ctx, x.by, peerMax); err != nil {
		return err
	}
	x.audit("accepted the shared settings restored in OpenSearch")
	fmt.Fprintln(x.out, "Every server accepts the shared settings now in OpenSearch within seconds.")
	return nil
}
