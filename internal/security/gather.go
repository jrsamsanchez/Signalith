package security

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/users"
	"golang.org/x/crypto/bcrypt"
)

// Host says how and where the server runs, for the collectors.
type Host struct {
	Config *config.Config
	GOOS   string
	// InContainer is true in a container, Docker for the quick start's.
	InContainer, Docker bool
	// Getenv reads the server's environment: this process's in the
	// server, the service's in the CLI.
	Getenv func(string) string
	// PID is the server's process: "self" in the server, the running
	// service's in the CLI ("service" on Windows), "" when it isn't
	// running.
	PID string
	// Systemd is true when the server runs as a systemd service, and
	// Service when it runs as a Windows service.
	Systemd, Service bool
	// Account is the account the server runs as.
	Account Account
}

func (h Host) getenv(name string) string {
	if h.Getenv == nil {
		return os.Getenv(name)
	}
	return h.Getenv(name)
}

// NewFacts starts the facts with what the configuration says.
func NewFacts(h Host, now time.Time, server ServerInfo) *Facts {
	f := &Facts{Now: now, Server: server, Config: h.Config, InContainer: h.InContainer, Docker: h.Docker, SettingEnv: map[string]string{}}
	f.PublicTokenAccepted = h.InContainer && h.Config.OldTokenAccepted()
	if f.Server.OS == "" {
		f.Server.OS = h.GOOS
	}
	for _, s := range config.Registry {
		if src := h.Config.Source(s.Key); src.Kind == config.FromEnv {
			f.SettingEnv[s.Key] = src.Env
		}
	}
	return f
}

// isDenied reports whether err means this account may not read a file.
func isDenied(err error) bool { return errors.Is(err, fs.ErrPermission) }

// HostCollectors gather what the server's files, folders, process and
// configuration say. archiving is whether a retention policy archives
// days.
func HostCollectors(h Host, archiving bool) []Collector {
	c := h.Config
	stateDir := c.StateDir()
	return []Collector{
		{Name: "master key", Checks: []string{"rest.master_key"}, Timeout: OSTimeout, Run: func(context.Context) func(*Facts) {
			k := keyFacts(h)
			return func(f *Facts) {
				f.Key = k
				if k.SourceErr != nil && isDenied(k.SourceErr) {
					f.deny("rest.master_key")
				}
			}
		}},
		{Name: "stored secrets", Checks: []string{"rest.stored_secrets"}, Timeout: OSTimeout, Run: func(context.Context) func(*Facts) {
			s, denied := secretFacts(h)
			return func(f *Facts) {
				f.Secrets = s
				if denied {
					f.deny("rest.stored_secrets")
				}
			}
		}},
		{Name: "disks", Checks: []string{"rest.disk"}, Timeout: OSTimeout, Run: func(context.Context) func(*Facts) {
			disks := probeDisks([]string{stateDir, c.LookupsDir(), filepath.Dir(c.Path())}, h.InContainer, stateDir)
			return func(f *Facts) { f.Disks = disks }
		}},
		{Name: "archives", Checks: []string{"rest.archives"}, Timeout: OSTimeout, Run: func(context.Context) func(*Facts) {
			a, denied := archiveFacts(h, archiving)
			return func(f *Facts) {
				f.Archive = a
				if denied {
					f.deny("rest.archives")
				}
			}
		}},
		{Name: "files", Checks: []string{"host.files"}, Timeout: OSTimeout, Run: func(context.Context) func(*Facts) {
			files, denied := fileFacts(h)
			return func(f *Facts) {
				f.Files = files
				if denied {
					f.deny("host.files")
				}
			}
		}},
		{Name: "process", Checks: []string{"use.memory", "use.confidential_vm", "host.account", "host.service"}, Timeout: OSTimeout,
			Run: func(context.Context) func(*Facts) {
				p, m, cvm := probeProcess(h.PID, h.PID == "self", h.Systemd)
				return func(f *Facts) { f.Process, f.Memory, f.ConfidentialVM = p, m, cvm }
			}},
		{Name: "built-in admin", Checks: []string{"accounts.builtin_password"}, Timeout: OSTimeout, Run: func(context.Context) func(*Facts) {
			a := adminFacts(h)
			return func(f *Facts) { f.Admin = a }
		}},
	}
}

// keyFacts reads where the master key comes from, and who may read it.
func keyFacts(h Host) KeyFacts {
	keys := h.Config.Keyring()
	var k KeyFacts
	k.Source, k.SourceErr = keys.Source()
	if k.SourceErr != nil {
		return k
	}
	k.Unused = keys.Unused()
	if k.Source.Path != "" {
		if p, err := probePerm(k.Source.Path, h.Account); err == nil {
			k.Perm = p
		}
	}
	return k
}

// secretFacts lists the stored passwords and keys, and the files with
// plain ones that other accounts can read.
func secretFacts(h Host) (SecretFacts, bool) {
	c := h.Config
	var s SecretFacts
	s.Stored, s.Errors = c.SecretInventory()
	for _, a := range c.AddressSecretsInFile() {
		s.Address = append(s.Address, a.Label)
	}
	denied := len(s.Errors) > 0
	for _, err := range s.Errors {
		denied = denied && isDenied(err)
	}
	plainIn := map[string]bool{}
	for _, v := range s.Stored {
		if v.State == secrets.Plain {
			plainIn[v.File] = true
		}
	}
	for _, f := range c.SecretFiles() {
		if !plainIn[f.Path] {
			continue
		}
		if p, err := probePerm(f.Path, h.Account); err == nil && (p.OtherRead || p.GroupRead || p.SomeRead) {
			s.Exposed = append(s.Exposed, f.Path)
		}
	}
	return s, denied
}

// archiveMaxFiles caps the walk of the archive folder.
const archiveMaxFiles = 100000

// archiveFacts counts the archived days and reads who may read them.
func archiveFacts(h Host, archiving bool) (*ArchiveFacts, bool) {
	dir := h.Config.ArchiveDir()
	a := &ArchiveFacts{Dir: dir, Policies: archiving}
	if inVolume(dir) != "" && h.Docker {
		a.Volume = dockerVolume
	}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == dir {
				return err
			}
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".ndjson.gz") {
			return nil
		}
		if a.Count >= archiveMaxFiles {
			a.More = true
			return filepath.SkipAll
		}
		a.Count++
		if info, err := d.Info(); err == nil {
			a.Bytes += info.Size()
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return a, false
		}
		if isDenied(err) {
			return a, true
		}
	}
	if a.Count == 0 && !archiving {
		return a, false
	}
	if p, err := probePerm(dir, h.Account); err == nil {
		a.Perm = p
	}
	if disks := probeDisks([]string{dir}, h.InContainer, h.Config.StateDir()); len(disks) > 0 {
		a.Disk = disks[0]
	}
	return a, false
}

// secretFileVars name files of secrets the server reads.
var secretFileVars = []string{"SIGNALITH_ADMIN_PASSWORD_FILE", "SIGNALITH_INGEST_TOKEN_FILE", "SIGNALITH_OPENSEARCH_PASSWORD_FILE",
	"SIGNALITH_LDAP_BIND_PASSWORD_FILE", "SIGNALITH_ASSISTANT_API_KEY_FILE"}

// fileFacts reads who may use Signalith's keys, private files, folders
// and configuration. The master key is left to rest.master_key.
func fileFacts(h Host) (FileFacts, bool) {
	c := h.Config
	state := c.StateDir()
	tls := c.TLSDir()
	type item struct{ path, kind string }
	var items []item
	for _, p := range []string{"ca.key", "server.key", "next/ca.key", "previous/ca.key", "previous/server.key"} {
		items = append(items, item{filepath.Join(tls, filepath.FromSlash(p)), "key"})
	}
	items = append(items, item{c.SignInKeyFile(), "key"})
	if c.Server.TLSMode() == config.TLSFiles {
		_, key := c.TLSFiles()
		items = append(items, item{key, "key"})
	}
	if _, _, key := c.OpenSearchTLSFiles(); key != "" {
		items = append(items, item{key, "key"})
	}
	for _, v := range secretFileVars {
		if p := h.getenv(v); p != "" {
			items = append(items, item{p, "key"})
		}
	}
	for _, p := range []string{c.AdminHashFile(), c.UsersFile(), c.DirectoryFile(), c.SettingsFile(), c.IntelFeedsFile(), SavedDisksFile(state)} {
		items = append(items, item{p, "private"})
	}
	for _, p := range []string{state, filepath.Join(state, "keys"), tls, c.LookupsDir()} {
		items = append(items, item{p, "folder"})
	}
	if c.Path() != "" {
		items = append(items, item{c.Path(), "config"}, item{filepath.Dir(c.Path()), "config"})
	}
	ff := FileFacts{Known: true, Admins: h.GOOS == "windows"}
	if h.Docker {
		ff.Volume = dockerVolume
	}
	seen := map[string]bool{}
	denied, checked := 0, 0
	keyFile := ""
	if src, err := c.Keyring().Source(); err == nil {
		keyFile = filepath.Clean(src.Path)
	}
	for _, it := range items {
		if it.path == "" || seen[it.path] || filepath.Clean(it.path) == keyFile {
			continue
		}
		seen[it.path] = true
		p, err := probePerm(it.path, h.Account)
		if err != nil {
			if isDenied(err) {
				denied++
			}
			continue
		}
		checked++
		prob := FileProblem{Path: it.path, Kind: it.kind}
		switch it.kind {
		case "key", "private":
			prob.Read = p.OtherRead || p.GroupRead || p.SomeRead
			prob.Everyone = p.OtherRead
			prob.Write = p.OtherWrite || p.GroupWrite || p.SomeWrite
		case "folder", "config":
			prob.Write = p.OtherWrite || p.GroupWrite || p.SomeWrite
			prob.Everyone = p.OtherWrite
		}
		if !p.OtherRead && !p.OtherWrite {
			prob.Group = p.Group
		}
		if prob.Read || prob.Write {
			ff.Problems = append(ff.Problems, prob)
		}
	}
	slices.SortStableFunc(ff.Problems, func(a, b FileProblem) int {
		if a.Everyone != b.Everyone {
			if a.Everyone {
				return -1
			}
			return 1
		}
		return 0
	})
	if network, _, err := config.FolderFilesystem(state); err == nil && network != "" {
		ff.NetworkState = network
	}
	return ff, checked == 0 && denied > 0
}

// adminFacts reads how the built-in admin's password is kept.
func adminFacts(h Host) AdminFacts {
	c := h.Config
	changed := c.AdminPasswordChanged() != ""
	a := AdminFacts{Public: c.PublicAdminPassword()}
	a.FromEnv = !changed && h.getenv("SIGNALITH_ADMIN_PASSWORD") != ""
	fromFile := !changed && h.getenv("SIGNALITH_ADMIN_PASSWORD_FILE") != "" && h.getenv("SIGNALITH_ADMIN_PASSWORD") == ""
	a.DockerFirst = fromFile && h.Docker
	a.FromFile = fromFile && !h.Docker
	if hash := c.Auth.AdminPasswordHash; hash != "" {
		if cost, err := bcrypt.Cost([]byte(hash)); err == nil && cost < bcrypt.DefaultCost {
			a.WeakHash = true
		}
	}
	if changed {
		if st, err := os.Stat(c.AdminHashFile()); err == nil {
			t := st.ModTime()
			a.SetAt = &t
		}
	}
	return a
}

// UserFactsFrom reads who signs in from the users store.
func UserFactsFrom(st *users.Store, builtin string, now time.Time) UserFacts {
	u := UserFacts{BuiltinName: builtin}
	if st == nil {
		return u
	}
	u.BuiltinLastSignIn = st.BuiltinLastSignIn()
	week := now.Add(-7 * 24 * time.Hour)
	for _, x := range st.List() {
		if x.Source == users.SourceLocal {
			u.Local = true
		}
		if x.Disabled {
			continue
		}
		if x.Role == users.Admin {
			u.OtherAdmins++
		} else {
			u.Others++
		}
		if x.Source == users.SourceLocal && x.MustChangePassword && x.Updated.Before(week) {
			u.StaleTemporary = append(u.StaleTemporary, x.Username)
		}
	}
	return u
}

// FeedsFrom lists the enabled threat intel feeds, as the Threat intel
// page shows them (without their secrets).
func FeedsFrom(views []intel.FeedView) []Feed {
	var out []Feed
	for _, v := range views {
		if v.Enabled {
			out = append(out, Feed{Name: v.Name, URL: v.URL, Credentials: v.Username != "" || v.Password.Set || v.HasHeaders})
		}
	}
	return out
}

// DockerQuickStart reports whether the environment is that of the
// Docker quick start's container, which reads its first secrets from
// /run/signalith-secrets.
func DockerQuickStart(getenv func(string) string) bool { return config.DockerQuickStart(getenv) }

// ServerHost describes this process, for the server's own checks.
func ServerHost(c *config.Config, inContainer bool) Host {
	return Host{Config: c, GOOS: runtime.GOOS, InContainer: inContainer, Docker: inContainer && DockerQuickStart(os.Getenv),
		Getenv: os.Getenv, PID: "self", Systemd: runtime.GOOS == "linux" && os.Getenv("INVOCATION_ID") != "",
		Service: isService(), Account: CurrentAccount()}
}

// ServerInfoFor names the server and how it runs, for a report.
func ServerInfoFor(h Host, name, version string) ServerInfo {
	dep, label := Deployment(h.GOOS, h.Docker, h.InContainer, h.Systemd, h.Service)
	return ServerInfo{Name: name, Version: version, Go: runtime.Version(), OS: h.GOOS, Deployment: dep, DeploymentLabel: label}
}
