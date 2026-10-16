// Package tenants keeps the tenants of a multi-tenant install: the separate
// customers one Signalith serves (see docs/multi-tenant.md).
//
// A tenant's data is kept apart by construction. Its OpenSearch indices
// have a prefix of their own, Prefix, that no index name or pattern of the
// default tenant or of any other tenant can match, and its files live in a
// folder of its own, Dir. An install with no tenants has only the default
// tenant, whose prefix and folders are the configured ones, as before.
package tenants

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// Default is the default tenant's ID: the data an install had before it
// had tenants, kept under the configured index prefix and folders.
const Default = "default"

// Infix sits between the configured index prefix and a tenant's ID in the
// tenant's index prefix: tenant acme of prefix signalith is signalith.t.acme.
// The configured prefix must not contain it (see ValidConfiguredPrefix).
const Infix = ".t."

// MaxTenants bounds how many tenants an install may have: each runs its
// own detections and background jobs.
const MaxTenants = 200

// Tenant is one customer.
type Tenant struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Disabled bool      `json:"disabled,omitempty"`
	Created  time.Time `json:"created"`
	// CreatedBy is who added it: a user name, or "command line".
	CreatedBy string `json:"created_by,omitempty"`
}

var (
	// ErrExists is returned when adding a tenant whose ID is taken.
	ErrExists = errors.New("a tenant with that ID already exists")
	// ErrNotFound is returned for a tenant that does not exist.
	ErrNotFound = errors.New("no tenant has that ID")
	// ErrTooMany is returned when adding a tenant would go past MaxTenants.
	ErrTooMany = fmt.Errorf("an install can have at most %d tenants", MaxTenants)
)

// ValidID reports why id cannot be a tenant's ID, or nil. An ID is 2 to 24
// lower-case letters and digits, starting with a letter, and not
// "default". Only letters and digits, so that the character after an ID
// in an index name is always "-" or "_", and no tenant's index names or
// patterns can match another tenant's whose ID starts with the same
// letters (acme and acmex).
func ValidID(id string) error {
	if id == Default {
		return fmt.Errorf("%q is the default tenant's ID", id)
	}
	if len(id) < 2 || len(id) > 24 {
		return fmt.Errorf("tenant ID %q must be 2 to 24 characters", id)
	}
	if id[0] < 'a' || id[0] > 'z' {
		return fmt.Errorf("tenant ID %q must start with a lower-case letter", id)
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return fmt.Errorf("tenant ID %q may only have lower-case letters and digits", id)
		}
	}
	return nil
}

// validName reports why name cannot be a tenant's display name, or nil.
func validName(name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("the tenant needs a name")
	}
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > 100 {
		return errors.New("the tenant's name must be at most 100 characters")
	}
	for _, r := range name {
		// Bidirectional overrides and isolates could make one tenant's
		// name read as another's.
		if unicode.IsControl(r) || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 {
			return errors.New("the tenant's name cannot have control or text-direction characters")
		}
	}
	return nil
}

// ValidConfiguredPrefix reports why opensearch.index_prefix cannot be used
// on an install that may have tenants, or nil: it must not contain Infix,
// so it can never equal or start a tenant's prefix.
func ValidConfiguredPrefix(prefix string) error {
	if strings.Contains(prefix, Infix) {
		return fmt.Errorf("opensearch.index_prefix must not contain %q, which tenants' index names use", Infix)
	}
	return nil
}

// Prefix returns the index prefix of tenant id on an install whose
// configured prefix is base: base itself for the default tenant, else
// base + Infix + id. The default tenant's indices are base-... and base_...,
// a tenant's base.t.<id>-... and base.t.<id>_..., so no pattern of one,
// base-*, base_* or base.t.<id>-*, can match another's.
func Prefix(base, id string) string {
	if id == "" || id == Default {
		return base
	}
	return base + Infix + id
}

// Dir returns the folder that keeps tenant id's files, under the state
// folder: <state>/tenants/<id>. The default tenant has none: its files are
// where the configuration says.
func Dir(stateDir, id string) string {
	return filepath.Join(stateDir, "tenants", id)
}

// File returns the registry's file in the state folder.
func File(stateDir string) string {
	return filepath.Join(stateDir, "tenants.json")
}

// Registry is the list of tenants, kept in a file in the state folder.
// The default tenant is not in it: it always exists.
type Registry struct {
	Path string

	mu      sync.Mutex
	loaded  bool
	tenants []Tenant
	modTime time.Time
	size    int64
}

type fileFormat struct {
	Version int      `json:"version"`
	Tenants []Tenant `json:"tenants"`
}

// Open returns the registry kept at path, read now: a damaged file is an
// error, so tenants are never silently lost. A missing file is an empty
// list.
func Open(path string) (*Registry, error) {
	r := &Registry{Path: path}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

// load reads the file when it changed since it was last read.
func (r *Registry) load() error {
	fi, err := os.Stat(r.Path)
	if errors.Is(err, os.ErrNotExist) {
		r.tenants, r.loaded, r.modTime, r.size = nil, true, time.Time{}, 0
		return nil
	}
	if err != nil {
		return err
	}
	if r.loaded && fi.ModTime().Equal(r.modTime) && fi.Size() == r.size {
		return nil
	}
	b, err := os.ReadFile(r.Path)
	if err != nil {
		return err
	}
	var f fileFormat
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("%s: %w", r.Path, err)
	}
	seen := map[string]bool{}
	for _, t := range f.Tenants {
		if err := ValidID(t.ID); err != nil {
			return fmt.Errorf("%s: %w", r.Path, err)
		}
		if seen[t.ID] {
			return fmt.Errorf("%s: tenant %q is listed twice", r.Path, t.ID)
		}
		seen[t.ID] = true
	}
	r.tenants, r.loaded, r.modTime, r.size = f.Tenants, true, fi.ModTime(), fi.Size()
	return nil
}

func (r *Registry) save(list []Tenant) error {
	b, err := json.MarshalIndent(fileFormat{Version: 1, Tenants: list}, "", "  ")
	if err != nil {
		return err
	}
	if err := securefile.MkdirPrivate(filepath.Dir(r.Path)); err != nil {
		return err
	}
	if err := securefile.Replace(r.Path, append(b, '\n')); err != nil {
		return err
	}
	r.tenants, r.loaded = list, false
	return r.load()
}

// List returns the tenants, by ID, without the default tenant.
func (r *Registry) List() ([]Tenant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.load(); err != nil {
		return nil, err
	}
	out := slices.Clone(r.tenants)
	slices.SortFunc(out, func(a, b Tenant) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// Get returns tenant id. The default tenant is not in the registry.
func (r *Registry) Get(id string) (Tenant, error) {
	list, err := r.List()
	if err != nil {
		return Tenant{}, err
	}
	for _, t := range list {
		if t.ID == id {
			return t, nil
		}
	}
	return Tenant{}, ErrNotFound
}

// Add adds a tenant.
func (r *Registry) Add(id, name, by string, now time.Time) (Tenant, error) {
	if err := ValidID(id); err != nil {
		return Tenant{}, err
	}
	name = strings.TrimSpace(name)
	if err := validName(name); err != nil {
		return Tenant{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.load(); err != nil {
		return Tenant{}, err
	}
	if slices.ContainsFunc(r.tenants, func(t Tenant) bool { return t.ID == id }) {
		return Tenant{}, ErrExists
	}
	if len(r.tenants) >= MaxTenants {
		return Tenant{}, ErrTooMany
	}
	t := Tenant{ID: id, Name: name, Created: now.UTC(), CreatedBy: by}
	if err := r.save(append(slices.Clone(r.tenants), t)); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// Change renames tenant id, or turns it off or on again; nil leaves a
// field as it is. A disabled tenant's users cannot sign in and its agents
// are refused, but its data stays.
func (r *Registry) Change(id string, name *string, disabled *bool) (Tenant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.load(); err != nil {
		return Tenant{}, err
	}
	i := slices.IndexFunc(r.tenants, func(t Tenant) bool { return t.ID == id })
	if i < 0 {
		return Tenant{}, ErrNotFound
	}
	list := slices.Clone(r.tenants)
	if name != nil {
		n := strings.TrimSpace(*name)
		if err := validName(n); err != nil {
			return Tenant{}, err
		}
		list[i].Name = n
	}
	if disabled != nil {
		list[i].Disabled = *disabled
	}
	if err := r.save(list); err != nil {
		return Tenant{}, err
	}
	return list[i], nil
}
