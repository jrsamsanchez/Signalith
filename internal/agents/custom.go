package agents

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// MaxCustomPaths is how many files or patterns one custom input tails.
const MaxCustomPaths = 8

// CustomInput returns the Fluent Bit input that tails log files for a
// custom parser, sending each line under tag (custom.<parser name>), to
// add to an agent's fluent-bit.conf next to its other inputs. hostOS is
// linux or windows; paths are the files, with * for any part of a name.
func CustomInput(tag, name, hostOS string, paths []string) (string, error) {
	if len(paths) == 0 {
		return "", errors.New("name the log files to read")
	}
	if len(paths) > MaxCustomPaths {
		return "", fmt.Errorf("one input reads at most %d files or patterns", MaxCustomPaths)
	}
	for _, p := range paths {
		if err := customPath(p, hostOS); err != nil {
			return "", err
		}
	}
	db := "/var/lib/fluent-bit/signalith-" + name + ".db"
	if hostOS == "windows" {
		db = `C:\ProgramData\fluent-bit\signalith-` + name + `.sqlite`
	}
	return strings.TrimPrefix(section("INPUT", [][2]string{
		{"Name", "tail"}, {"Tag", tag},
		{"Path", strings.Join(paths, ",")},
		{"Path_Key", "file"},
		{"DB", db},
		{"Read_from_Head", "Off"},
		{"Skip_Long_Lines", "On"},
		{"storage.type", "filesystem"},
	}), "\n"), nil
}

// customPath checks a path written into the config: absolute, one line,
// no comma (Fluent Bit's list separator), no "..", at most 260 bytes.
func customPath(p, hostOS string) error {
	switch {
	case p == "":
		return errors.New("a path is empty")
	case len(p) > 260:
		return fmt.Errorf("the path %.40s... is longer than 260 characters", p)
	case strings.ContainsAny(p, ",\r\n\t\x00\"'`$;|&<>"):
		return fmt.Errorf("the path %q holds a character a log path cannot", p)
	case strings.Contains(p, ".."):
		return fmt.Errorf("the path %q must not use ..", p)
	}
	var deny []string
	norm := p
	switch hostOS {
	case "linux":
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("the path %q must start with /", p)
		}
		deny = linuxDenied
	case "windows":
		if len(p) < 3 || p[1] != ':' || p[2] != '\\' {
			return fmt.Errorf(`the path %q must start with a drive, such as C:\`, p)
		}
		// Windows paths do not care about case, the kind of slash or, here,
		// the drive.
		norm = "?" + strings.ToLower(strings.ReplaceAll(p[1:], `\`, "/"))
		deny = windowsDenied
	default:
		return fmt.Errorf("unknown os %q; use linux or windows", hostOS)
	}
	if secretPath(norm, deny) {
		return fmt.Errorf("the path %q may hold secrets (passwords, keys or the agent's own token), which would become searchable; name the log files themselves", p)
	}
	return nil
}

// Files and folders that hold secrets: the agent's own configuration and
// token, Signalith's, password and key stores. A path naming one, or a
// pattern that can match one, is refused. Folders end in /.
var (
	linuxDenied = []string{"/etc/fluent-bit/", "/var/lib/fluent-bit/", "/etc/td-agent-bit/", "/etc/signalith/", "/var/lib/signalith/",
		"/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-", "/etc/sudoers", "/etc/sudoers.d/", "/etc/ssh/", "/root/",
		"/proc/", "/sys/", "/dev/", "/etc/ssl/private/", "/etc/pki/"}
	windowsDenied = []string{"?:/program files/fluent-bit/", "?:/programdata/fluent-bit/", "?:/programdata/signalith/", "?:/program files/signalith/",
		"?:/windows/system32/config/", "?:/windows/ntds/", "?:/users/*/.ssh/", "?:/programdata/ssh/"}
)

// secretPath reports whether p names, or as a pattern can match, a denied
// file or something in a denied folder, or a key file.
func secretPath(p string, deny []string) bool {
	if ext := strings.ToLower(path.Ext(p)); ext == ".key" || ext == ".pfx" || ext == ".p12" || ext == ".kdbx" {
		return true
	}
	for _, d := range deny {
		if strings.HasSuffix(d, "/") {
			// In the folder: the path, or the part of a pattern before its
			// first wildcard, is under it, or the pattern's folder matches it.
			lit := p
			if i := strings.IndexAny(p, "*?["); i >= 0 {
				lit = p[:i]
			}
			if m, _ := path.Match(d+"*", lit); m || strings.HasPrefix(lit, d) || strings.HasPrefix(lit+"/", d) {
				return true
			}
			for dir := path.Dir(p); dir != "/" && dir != "."; dir = path.Dir(dir) {
				dd := strings.TrimSuffix(d, "/")
				if m, _ := path.Match(dd, dir); m {
					return true
				}
				if m, _ := path.Match(dir, dd); m {
					return true
				}
			}
			continue
		}
		if m, _ := path.Match(p, d); m || p == d {
			return true
		}
	}
	return false
}
