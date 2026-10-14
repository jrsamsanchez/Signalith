package cluster

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// errLockUnsupported is a filesystem that does not lock files, as some
// 9p and FUSE mounts.
var errLockUnsupported = errors.New("this filesystem does not support file locks")

// errLocked is a lock file another process (or another open file in this
// one) holds.
var errLocked = errors.New("the lock is held")

// Identity is who a server is, kept in node.id in its state folder. The
// id never changes; the name is what people see.
type Identity struct {
	NodeID    string    `json:"node_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	// MachineID is the computer's id when node.id was made (none in a
	// container), to notice a folder that moved to another computer.
	MachineID string `json:"machine_id,omitempty"`
}

// Local is this server's state folder, locked while the server runs, so
// no second process on this computer can use the same identity.
type Local struct {
	Dir      string
	Identity Identity
	// BootID is new for each process; LastBoot is the BootID of the
	// previous process that used this folder, "" when there was none.
	BootID   string
	LastBoot string
	// Moved is true when node.id was made on another computer: the folder
	// was copied or restored there, or the computer was cloned.
	Moved bool
	// Warnings are about the folder, for the log and the Servers page.
	Warnings []string

	unlock    func()
	closeOnce sync.Once
}

// LocalOptions are what OpenLocal needs besides the folder.
type LocalOptions struct {
	// Name is cluster.node_name (or SIGNALITH_NODE_NAME); "" keeps the
	// name in node.id, or uses this computer's name for a new one.
	Name string
	// InContainer is true in Docker and similar, where the computer's name
	// is a random container id and there is no machine id.
	InContainer bool
	// Hostname and MachineID replace the computer's for tests.
	Hostname  func() (string, error)
	MachineID func() string
}

const (
	nodeFile     = "node.id"
	lockName     = "lock"
	lastBootName = "last_boot"
)

// OpenLocal opens the state folder dir (config.Config.StateDir): it
// refuses a folder on a network filesystem (see CheckFolder), takes
// cluster/lock, and reads node.id, making it on the
// first start. Close releases the lock.
func OpenLocal(dir string, o LocalOptions) (*Local, error) {
	if o.Hostname == nil {
		o.Hostname = os.Hostname
	}
	if o.MachineID == nil {
		o.MachineID = machineID
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(abs, "cluster"), 0o750); err != nil {
		return nil, fmt.Errorf("could not make the state folder %s: %w. Set SIGNALITH_STATE_DIR to a folder on a local disk that this user can write", abs, err)
	}
	l := &Local{Dir: abs}
	var shared string
	if l.Warnings, shared, err = checkFolder(abs); err != nil {
		return nil, err
	}
	unlock, err := lockFile(filepath.Join(abs, "cluster", lockName))
	if errors.Is(err, errLockUnsupported) && shared != "" {
		// Docker Desktop and WSL bind mounts, and some network shares, may
		// not lock files: the heartbeat check still catches a second
		// process that runs.
		l.Warnings = append(l.Warnings, fmt.Sprintf("The %s mount of the state folder %s cannot lock files, so nothing stops a second Signalith process from using the folder. Run only one, or use a Docker volume or a folder on a local disk.", shared, abs))
		unlock, err = func() {}, nil
	}
	if errors.Is(err, errLocked) {
		return nil, fmt.Errorf("another Signalith process uses the state folder %s. Stop it first, or give this one its own folder with SIGNALITH_STATE_DIR", abs)
	}
	if err != nil {
		return nil, fmt.Errorf("could not lock the state folder %s: %w", abs, err)
	}
	l.unlock = unlock
	if err := l.load(o); err != nil {
		unlock()
		return nil, err
	}
	if b, err := os.ReadFile(filepath.Join(abs, "cluster", lastBootName)); err == nil {
		l.LastBoot = strings.TrimSpace(string(b))
	}
	l.BootID = "b_" + randomHex(10)
	return l, nil
}

// CheckFolder checks the filesystem the state folder dir is on, changing
// nothing: a network share is an error, unless the folder already holds
// Signalith's own files (config.HoldsState), and a mount on which locks
// may not stop a second process is a warning. A folder that does not
// exist yet is checked where it would be made.
func CheckFolder(dir string) (warnings []string, err error) {
	warnings, _, err = checkFolder(dir)
	return warnings, err
}

// checkFolder is CheckFolder, and names the kind of a mount whose locks
// may not work (FUSE, 9p, virtiofs, or a network share kept because it
// already holds Signalith's files).
func checkFolder(dir string) (warnings []string, shared string, err error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, "", err
	}
	network, shared, err := config.FolderFilesystem(config.NearestExisting(abs))
	switch {
	case err != nil:
		return []string{fmt.Sprintf("Could not check which filesystem the state folder %s is on: %v.", abs, err)}, "", nil
	case network != "" && config.HoldsState(abs):
		// An install from before servers had an identity may keep its
		// master key and HTTPS certificate there: the folder stays in use
		// rather than leave them behind. Two servers that share it share
		// one identity, which the lock or the heartbeats find out.
		return []string{fmt.Sprintf("The state folder %s is on a network share (%s). Signalith still uses it, since it already holds its master key, HTTPS certificate or identity, but a folder on a local disk is safer: "+
			"two servers that share one folder share one identity, and only one of them can run. Move what is in it to a folder on a local disk and set SIGNALITH_STATE_DIR to that folder.", abs, network)}, network, nil
	case network != "":
		return nil, "", fmt.Errorf("the state folder %s is on a network share (%s). Keep it on a local disk: Signalith locks a file in it, and two servers that share one folder would share one identity. Set SIGNALITH_STATE_DIR to a local folder", abs, network)
	case shared != "":
		return []string{fmt.Sprintf("The state folder %s is on a %s mount, as Docker Desktop and WSL bind mounts are. That works, but a Docker volume or a folder on a local disk is safer, since locks on such mounts may not stop a second process.", abs, shared)}, shared, nil
	}
	return nil, "", nil
}

// InUse reports whether a Signalith process uses the state folder dir
// now: whether another open file holds its cluster/lock. It changes
// nothing, and is false where files cannot be locked.
func InUse(dir string) (bool, error) {
	path := filepath.Join(dir, "cluster", lockName)
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	unlock, err := lockFile(path)
	switch {
	case errors.Is(err, errLocked):
		return true, nil
	case errors.Is(err, errLockUnsupported):
		return false, nil
	case err != nil:
		return false, err
	}
	unlock()
	return false, nil
}

// ReadIdentity reads node.id in the state folder dir without locking the
// folder or changing anything, for a command run while the server runs.
// An error wrapping fs.ErrNotExist means the server has not started yet.
func ReadIdentity(dir string) (Identity, error) {
	var id Identity
	path := filepath.Join(dir, nodeFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return id, err
	}
	if err := json.Unmarshal(b, &id); err != nil || !strings.HasPrefix(id.NodeID, "n_") {
		return Identity{}, fmt.Errorf("this server's identity file %s is damaged", path)
	}
	return id, nil
}

// load reads node.id, or makes it, and settles the name.
func (l *Local) load(o LocalOptions) error {
	path := filepath.Join(l.Dir, nodeFile)
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		l.Identity = Identity{NodeID: "n_" + randomHex(10), CreatedAt: time.Now().UTC()}
		if !o.InContainer {
			l.Identity.MachineID = o.MachineID()
		}
	case err != nil:
		return fmt.Errorf("could not read this server's identity from %s: %w", path, err)
	default:
		if err := json.Unmarshal(b, &l.Identity); err != nil || !strings.HasPrefix(l.Identity.NodeID, "n_") {
			return fmt.Errorf("this server's identity file %s is damaged. Restore it from a backup, or, if this server should start as a new one, stop it, delete the file and start it again", path)
		}
		if now := o.MachineID(); !o.InContainer && l.Identity.MachineID != "" && now != "" && now != l.Identity.MachineID {
			l.Moved = true
			l.Warnings = append(l.Warnings, "This server's state folder was made on another computer: it was copied, restored or the computer was cloned. "+
				"If another server still runs with a copy of it, the two share one identity; give this one a new identity by stopping it, deleting "+path+" and starting it again.")
		}
	}
	name := o.Name
	if name == "" {
		name = l.Identity.Name
	}
	if name == "" {
		name = hostName(o)
	}
	if name != l.Identity.Name || err != nil {
		l.Identity.Name = name
		if err := writeFileAtomic(path, mustJSON(l.Identity)); err != nil {
			return fmt.Errorf("could not save this server's identity in %s: %w", path, err)
		}
	}
	return nil
}

// randomContainerName is the random id Docker gives a container as its
// host name.
var randomContainerName = regexp.MustCompile(`^[0-9a-f]{12}([0-9a-f]{52})?$`)

// hostName is this computer's name as a server name. In a container a
// random container id is never used.
func hostName(o LocalOptions) string {
	h, err := o.Hostname()
	h = strings.TrimSpace(h)
	if err != nil || h == "" || o.InContainer && randomContainerName.MatchString(h) {
		return "signalith-1"
	}
	if config.ValidNodeName(h) {
		return h
	}
	var b strings.Builder
	for _, r := range h {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	name := strings.TrimLeft(b.String(), ".-_")
	if len(name) > 63 {
		name = name[:63]
	}
	if !config.ValidNodeName(name) {
		return "signalith-1"
	}
	return name
}

// WriteLastBoot records this process's BootID, so the next process that
// uses this folder knows the heartbeat it finds was this one's. It is
// written just before the first heartbeat.
func (l *Local) WriteLastBoot() error {
	return writeFileAtomic(filepath.Join(l.Dir, "cluster", lastBootName), []byte(l.BootID+"\n"))
}

// Close releases the lock on the folder.
func (l *Local) Close() {
	l.closeOnce.Do(func() {
		if l.unlock != nil {
			l.unlock()
		}
	})
}

// InContainer reports whether Signalith runs in Docker or Podman.
func InContainer() bool {
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

// writeFileAtomic replaces a file through a temporary file and a rename,
// so it is never seen half written.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(name, path)
	}
	if werr != nil {
		os.Remove(name)
	}
	return werr
}

func mustJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
