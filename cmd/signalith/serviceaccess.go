package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// serviceFiles are the folders the Windows service writes to and the
// files it reads, outside the config folder. "signalith service install"
// gives its account, NT SERVICE\Signalith, access to them.
type serviceFiles struct {
	// write are the folders to give the service Modify on: the config
	// file's folder and every data folder that exists (lookups,
	// detections, dashboards, archive, state with its keys and HTTPS
	// certificate, and the Settings page's file's), each one itself, since
	// a folder an older version made may have an access list of its own
	// that the config folder's does not reach. shown lists the top ones,
	// for people.
	write, shown []string
	// read are files the service reads outside those folders, such as a
	// TLS certificate and key kept in an administrators' folder.
	read []string
}

// serviceAccess works out what the service needs, from the config file
// and the settings saved on the Settings page. Both count: the service
// uses the page's settings, and falls back to signalith.yaml's alone when
// it cannot start with them, so a certificate either names must be
// readable. Older versions ran as LocalSystem, which could read any file.
func serviceAccess(configPath string) serviceFiles {
	top := filepath.Dir(configPath)
	out := serviceFiles{write: []string{top}, shown: []string{top}}
	c, err := config.LoadUnchecked(configPath)
	if err != nil {
		return out
	}
	configs := []*config.Config{c}
	if s, err := config.LoadSaved(configPath); err == nil {
		configs = append(configs, s.Config)
	}
	inside := func(p string, dirs []string) bool {
		for _, have := range dirs {
			if rel, err := filepath.Rel(have, p); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}
	folders := []string{c.StateDir(), filepath.Join(c.StateDir(), "keys"), c.TLSDir(), c.LookupsDir(), c.DetectionsDir(), c.DashboardsDir(), c.ArchiveDir(),
		filepath.Dir(c.UsersFile()), filepath.Dir(c.IntelFeedsFile()), filepath.Dir(c.NotifyFile()), filepath.Dir(c.ResponseFile()), filepath.Dir(c.PlaybooksFile()), filepath.Dir(c.SettingsFile())}
	for _, d := range folders {
		if d == "" || slices.ContainsFunc(out.write, func(have string) bool { return strings.EqualFold(have, d) }) {
			continue
		}
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			continue
		}
		if !inside(d, out.shown) {
			out.shown = append(out.shown, d)
		}
		out.write = append(out.write, d)
	}
	var files []string
	for _, c := range configs {
		ca, cert, key := c.OpenSearchTLSFiles()
		files = append(files, c.Server.TLSCert, c.Server.TLSKey, ca, cert, key)
		if c.Auth.LDAP != nil && c.Auth.LDAP.CACertFile != "" {
			files = append(files, c.Auth.LDAP.CACertFile)
		}
	}
	for _, f := range files {
		if f == "" {
			continue
		}
		if !filepath.IsAbs(f) {
			f = filepath.Join(top, f)
		}
		if _, err := os.Stat(f); err != nil || inside(f, out.write) || slices.Contains(out.read, f) {
			continue
		}
		out.read = append(out.read, f)
	}
	return out
}
