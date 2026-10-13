package security

import (
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Facts is everything the checks look at. The server gathers them with
// its runtime facts (Runtime); the CLI without (Runtime is nil), and
// the checks that need them say what they can.
type Facts struct {
	Now    time.Time
	Server ServerInfo
	// Config is the configuration in use.
	Config *config.Config
	// SettingEnv names, for each setting set by an environment variable,
	// that variable.
	SettingEnv map[string]string
	// InContainer is true when Signalith runs in a container, and Docker
	// when that container is the Docker quick start's.
	InContainer, Docker bool
	// PublicTokenAccepted is true when the server accepts the old example
	// ingest token over plain HTTP: a Docker quick start upgraded from a
	// version whose agents send it, with HTTPS on and agents on plain HTTP
	// allowed (see config.Config.OldToken and api.retiredTokenAccepted).
	PublicTokenAccepted bool
	// Uptime is how long the server has run (zero in the CLI).
	Uptime time.Duration

	TLS        *TLSFacts // nil when Signalith serves no TLS itself
	Runtime    *RuntimeFacts
	Key        KeyFacts
	Secrets    SecretFacts
	Disks      []Disk // the filesystems that hold Signalith's own files
	Archive    *ArchiveFacts
	OpenSearch OpenSearchFacts
	Users      UserFacts
	Admin      AdminFacts
	Directory  *users.LDAPSettings // nil when directory sign-in is off
	Process    ProcessFacts
	Memory     MemoryFacts
	Files      FileFacts
	// ConfidentialVM is "AMD SEV-SNP" or "Intel TDX" when found.
	ConfidentialVM string
	// Feeds are the enabled threat intel feeds.
	Feeds []Feed

	// TimedOut lists the checks whose facts did not arrive in time, and
	// Denied those whose facts this account may not read (the CLI run
	// without sudo or Administrator).
	TimedOut map[string]bool
	Denied   map[string]bool
}

func (f *Facts) timedOut(id string) bool { return f.TimedOut[id] }

// Deny marks checks whose facts this account may not read: they are
// "can't tell", with the line that says to run with more rights.
func (f *Facts) Deny(ids ...string) { f.deny(ids...) }

// deny marks checks whose facts this account may not read.
func (f *Facts) deny(ids ...string) {
	if f.Denied == nil {
		f.Denied = map[string]bool{}
	}
	for _, id := range ids {
		f.Denied[id] = true
	}
}

// DeniedLine is the line of a check whose facts this account may not
// read.
func DeniedLine(goos string) string {
	if goos == "windows" {
		return "Run signalith security in a PowerShell opened as Administrator to check this."
	}
	return "Run signalith security with sudo to check this."
}

// NoServiceLine is the line of a check of the server's process when
// signalith security finds no running service that uses its config file.
// It may be stopped, or started another way; the Security page checks it
// either way.
const NoServiceLine = "No running Signalith service uses this config file, so signalith security can't check the server's process."

// noServiceFix says how to check the process anyway.
func noServiceFix() *Fix {
	return &Fix{Steps: []string{"Run signalith security again while the Signalith service runs. A server started another way shows this on its own Security page."}}
}

// HTTPSOn reports whether Signalith serves HTTPS itself.
func (f *Facts) HTTPSOn() bool { return f.Config != nil && f.Config.Server.HTTPS() }

// CLI reports whether the facts come from signalith security, which
// cannot see what the running server saw.
func (f *Facts) CLI() bool { return f.Runtime == nil }

// TLSFacts is about the certificate Signalith serves.
type TLSFacts struct {
	Mode string // auto or files
	Leaf *LeafFacts
	// Outside lists the names the auto certificate leaves out.
	Outside []string
	// Files mode.
	CertFile, KeyFile string
	CoversPublicHost  bool
	PublicHost        string
	CAMissing         bool // the file does not include its CA, and it is not public
	// Auto mode.
	CA         *tlsauto.CAInfo
	Next       *tlsauto.CAInfo
	Previous   *tlsauto.CAInfo
	Refusals   []tlsauto.Refusal // runtime only
	ScopeSetup string            // server.tls.ca_scope
	// WouldCover lists the names a CA made now would cover, by scope.
	WouldCover map[string][]string
	// Seen are the names people used to reach this server in the last
	// day (runtime only).
	Seen []SeenName
}

// SeenName is a name someone used to reach this server, and whether a
// strict certificate authority made now would cover it. Own is whether
// Signalith can tell the name is this server's: it leads to one of this
// computer's addresses, or only means something on a private network.
type SeenName struct {
	Name          string    `json:"name"`
	CoveredStrict bool      `json:"covered_strict"`
	Own           bool      `json:"own"`
	LastSeen      time.Time `json:"last_seen"`
}

// CAReport is the state of Signalith's own certificate authority, for
// the Security page's certificate authority panel. It is in a report only
// with Automatic HTTPS.
type CAReport struct {
	Mode         string              `json:"mode"`
	ScopeSetting string              `json:"scope_setting"`
	Current      *tlsauto.CAInfo     `json:"current"`
	Next         *tlsauto.CAInfo     `json:"next"`
	Previous     *tlsauto.CAInfo     `json:"previous"`
	WouldCover   map[string][]string `json:"would_cover"`
	// SeenNames and Refusals are what the running server saw; the CLI
	// leaves them out.
	SeenNames []SeenName        `json:"seen_names,omitzero"`
	Refusals  []tlsauto.Refusal `json:"refusals,omitzero"`
	Container bool              `json:"container"`
}

// caReport builds the CA panel's facts, or nil without Automatic HTTPS.
func caReport(f *Facts) *CAReport {
	t := f.TLS
	if t == nil || t.Mode != config.TLSAuto || t.CA == nil {
		return nil
	}
	setting := t.ScopeSetup
	if setting == "" {
		setting = tlsauto.ScopeStandard
	}
	r := &CAReport{Mode: t.Mode, ScopeSetting: setting, Current: t.CA, Next: t.Next, Previous: t.Previous,
		WouldCover: t.WouldCover, Container: f.InContainer}
	if r.WouldCover == nil {
		r.WouldCover = map[string][]string{}
	}
	if f.Runtime != nil {
		r.SeenNames = append([]SeenName{}, t.Seen...)
		r.Refusals = append([]tlsauto.Refusal{}, t.Refusals...)
	}
	return r
}

// LeafFacts is the certificate being served.
type LeafFacts struct {
	NotAfter time.Time
	// RSABits is the RSA key size, 0 for other keys.
	RSABits int
	SHA1    bool
	// NoName means it covers IP addresses only, so agents can't check a
	// certificate from a CA that vouches for other computers belongs to
	// this server.
	NoName bool
}

// RuntimeFacts are what only the running server sees.
type RuntimeFacts struct {
	// DirectPlain are the addresses that signed in over plain HTTP, not
	// from this computer or a trusted proxy, in the last day.
	DirectPlain []string
	// PlainSenders are the agents that sent over plain HTTP in the last
	// day, by name (address and host names).
	PlainSenders []string
	// PlainSenderCount counts them as agents. Agents on this computer are
	// left out of both, and counted in LocalPlainSenders: what they send
	// never crosses the network.
	PlainSenderCount  int
	LocalPlainSenders int
	// DirectPlainAgents are the addresses of agents that sent events
	// straight to Signalith over plain HTTP while HTTPS is off, not from
	// this computer or through a trusted proxy, in the last day.
	DirectPlainAgents []string
	// Syslog senders in the last day, by protocol, and whether every
	// plain one came from the container's default gateway.
	SyslogSenders map[string]int
	SyslogNATed   bool
	// LegacyProxies are reverse proxies believed only because the config
	// predates HTTPS by default, in the last day.
	LegacyProxies []string
	// ClusterServer names this server among several, for the CA check.
	ClusterServer string
}

// KeyFacts is about the master key.
type KeyFacts struct {
	Source    secrets.Source
	SourceErr error // secrets.ErrNoKey when there is none yet
	Unused    []string
	Perm      *Perm // the key file's permissions; nil when unknown or none
	// AnyEncrypted is true when some stored value is encrypted.
	AnyEncrypted bool
}

// SecretFacts is about the passwords and keys stored in files.
type SecretFacts struct {
	Stored []config.StoredSecret
	// Address lists the settings with a secret in their address, by
	// label (such as opensearch.url).
	Address []string
	// Exposed are the files with plain values that other accounts can
	// read.
	Exposed []string
	Errors  map[string]error
}

// ArchiveFacts is about archived days.
type ArchiveFacts struct {
	Dir      string
	Count    int
	More     bool // the walk stopped at its cap
	Bytes    int64
	Perm     *Perm
	Disk     Disk
	Policies bool // a retention policy archives
	Volume   string
}

// OpenSearchFacts is about OpenSearch, as the probes found it.
type OpenSearchFacts struct {
	// Anonymous is open, closed or unknown: whether a request without
	// sign-in could read events. AnonymousErr says why unknown.
	Anonymous    string
	AnonymousErr string
	// Listening is true when OpenSearch, at a loopback address, also
	// answers on this computer's network addresses.
	Listening bool
	// DemoCert is true when OpenSearch presented its demo certificate.
	DemoCert bool
	// SameNetwork is true when, in a container, OpenSearch's host is on
	// the container's own network.
	SameNetwork bool
	// AuthInfo is what OpenSearch says Signalith's account may do.
	AuthUser     string
	AuthRoles    []string
	AuthBackend  []string
	AuthErr      string
	AuthNoPlugin bool // the security plugin is not installed
	AuthProbed   bool
	// DataPaths are where OpenSearch keeps events, with their disks,
	// when it runs on this computer; DataErr says why they are unknown.
	DataPaths []Disk
	DataErr   string
	// DataMissing lists the folders OpenSearch named that don't exist on
	// this computer, as when it runs in a container; DataPaths leaves
	// them out.
	DataMissing []string
	// DemoAdmin is true when Signalith signs in as admin with the
	// password admin. The password is compared in memory, never shown.
	DemoAdmin bool
}

// UserFacts is about the people who sign in.
type UserFacts struct {
	BuiltinName       string
	BuiltinLastSignIn *time.Time
	// OtherAdmins counts enabled admins other than the built-in admin,
	// and Others every other enabled account.
	OtherAdmins, Others int
	// Local is true when there are local users at all.
	Local bool
	// StaleTemporary lists those who haven't changed a temporary
	// password given more than a week ago.
	StaleTemporary []string
}

// AdminFacts is about the built-in admin's password.
type AdminFacts struct {
	Public      bool // change-me-please
	FromEnv     bool // SIGNALITH_ADMIN_PASSWORD, with no hash file
	DockerFirst bool // SIGNALITH_ADMIN_PASSWORD_FILE in the Docker quick start, not changed since
	FromFile    bool // SIGNALITH_ADMIN_PASSWORD_FILE elsewhere, not changed since
	WeakHash    bool // bcrypt cost below the default
	SetAt       *time.Time
}

// ProcessFacts is about the running process.
type ProcessFacts struct {
	Known bool // false when the service's process could not be read
	// Why says why not, such as "Signalith isn't running".
	Why string
	// Unix.
	UID      int
	UserName string
	Root     bool
	// Systemd is true under systemd.
	Systemd bool
	// The protections found, under their plain names.
	NoNewPrivs, Seccomp, NoCaps, NoCapsAtAll, ReadOnlyRoot, HiddenProc, PrivateDev, Umask077 bool
	// NoHiddenProc is true when this Linux is too old to hide other
	// processes from one service (before 5.8), so the unit can't.
	NoHiddenProc bool
	// Windows. Elevated is true when the account is an administrator;
	// AdminUnknown when that couldn't be found out.
	SID          string
	Elevated     bool
	AdminUnknown bool
	Service      bool
}

// MemoryFacts is about whether Signalith's memory can be saved.
type MemoryFacts struct {
	Known bool
	// CoreOff is true when the core file limit is 0, and NotDumpable when
	// the process is not dumpable (or that cannot be read, in the CLI).
	CoreOff, NotDumpable bool
	// Swap: off, encrypted, or plain; SwapOffForUs when the cgroup's
	// memory.swap.max is 0.
	SwapOn, SwapEncrypted, SwapOffForUs bool
	// Windows: full local dumps, and where.
	FullDumps     bool
	DumpFolder    string
	DumpsRegistry string
}

// FileFacts is about the permissions of Signalith's files.
type FileFacts struct {
	Known bool
	// Problems found, worst first.
	Problems []FileProblem
	// NetworkState is the network filesystem the state folder is on, and
	// its source.
	NetworkState string
	// Admins is true when administrators can read them too (Windows).
	Admins bool
	Volume string // the Docker volume, when known
}

// FileProblem is a file or folder others may read or change.
type FileProblem struct {
	Path  string
	Kind  string // key, private, folder, config
	Read  bool   // read by others
	Write bool   // changed by others
	// Everyone is true for every account, false for a group or some.
	Everyone bool
	Group    string
}

// Perm is who other than Signalith's own account may use a file.
type Perm struct {
	OtherRead, OtherWrite bool
	GroupRead, GroupWrite bool
	Group                 string
	Owner                 string
	WrongOwner            bool
	// Some is set on Windows when accounts other than the trusted ones
	// may read it.
	SomeRead, SomeWrite bool
}

// Feed is an enabled threat intel feed, as far as the checks need it.
type Feed struct {
	Name        string
	URL         string
	Credentials bool
}

// Disk is what Signalith could find out about the filesystem a path is
// on.
type Disk struct {
	Path       string `json:"path"`
	MountPoint string `json:"mount_point,omitempty"`
	FSType     string `json:"fs_type,omitempty"`
	Source     string `json:"source,omitempty"`
	Device     string `json:"device,omitempty"`
	// Kind is encrypted, plain, network, memory, unreadable, virtual,
	// container, windows (no saved answer), denied (this account may not
	// look) or unknown.
	Kind string `json:"kind"`
	// Hidden is a folder above Path that Signalith may not look into:
	// the disk is that folder's, as no other is mounted inside it.
	Hidden string `json:"hidden,omitempty"`
	// Method names the encryption, such as LUKS2 or BitLocker.
	Method string `json:"method,omitempty"`
	// Provider names the virtual machine's host, when known.
	Provider string `json:"provider,omitempty"`
	// Windows: the drive, whether BitLocker protects it, whether it is
	// suspended, and when that was checked.
	Drive     string    `json:"drive,omitempty"`
	Suspended bool      `json:"suspended,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitzero"`
}

// Disk kinds.
const (
	DiskEncrypted  = "encrypted"
	DiskPlain      = "plain"
	DiskNetwork    = "network"
	DiskMemory     = "memory"
	DiskUnreadable = "unreadable"
	DiskVirtual    = "virtual"
	DiskContainer  = "container"
	DiskWindows    = "windows"
	DiskDenied     = "denied"
	DiskUnknown    = "unknown"
)

// ---- helpers the checks share ----

// isLoopback reports whether host is this computer.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && a.Unmap().IsLoopback()
}

// listenHost splits a listen address.
func listenHost(addr string) (host, port string) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", ""
	}
	return h, p
}

// urlParts returns the scheme and host of an address.
func urlParts(raw string) (scheme, host, hostport string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", ""
	}
	return strings.ToLower(u.Scheme), u.Hostname(), u.Host
}

// joinAnd joins items as "a, b and c".
func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// orList lists up to n items joined with "or", then "or k more".
func orList(items []string, n int) string {
	switch {
	case len(items) > n:
		return strings.Join(items[:n], ", ") + " or " + itoa(len(items)-n) + " more"
	case len(items) > 1:
		return strings.Join(items[:len(items)-1], ", ") + " or " + items[len(items)-1]
	case len(items) == 1:
		return items[0]
	}
	return ""
}

// shorten lists up to n items, then "and k more".
func shorten(items []string, n int) string {
	if len(items) <= n {
		return joinAnd(items)
	}
	return strings.Join(items[:n], ", ") + " and " + itoa(len(items)-n) + " more"
}

func itoa(n int) string { return strconv.Itoa(n) }

// plural picks one or many by n.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// ago says how long ago t was, in plain words.
func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < 2*time.Minute:
		return "just now"
	case d < time.Hour:
		return itoa(int(d/time.Minute)) + " minutes ago"
	case d < 2*time.Hour:
		return "an hour ago"
	case d < 48*time.Hour:
		return itoa(int(d/time.Hour)) + " hours ago"
	}
	return itoa(int(d/(24*time.Hour))) + " days ago"
}

// day formats a date as the report shows it.
func day(t time.Time) string { return t.UTC().Format("2 Jan 2006") }

// span says a duration in plain words, such as 12 hours or 3 days.
func span(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		n := int(d / (24 * time.Hour))
		return itoa(n) + plural(n, " day", " days")
	case d%time.Hour == 0:
		n := int(d / time.Hour)
		return itoa(n) + plural(n, " hour", " hours")
	}
	n := int(d / time.Minute)
	return itoa(n) + plural(n, " minute", " minutes")
}

// sizeOf says a number of bytes in plain words.
func sizeOf(b int64) string {
	const unit = 1024
	switch {
	case b < unit*unit:
		return itoa(int((b+unit-1)/unit)) + " KB"
	case b < unit*unit*unit:
		return itoa(int(b/(unit*unit))) + " MB"
	}
	gb := float64(b) / (unit * unit * unit)
	whole := int(gb)
	tenth := int((gb - float64(whole)) * 10)
	if tenth == 0 || whole >= 10 {
		return itoa(whole) + " GB"
	}
	return itoa(whole) + "." + itoa(tenth) + " GB"
}
