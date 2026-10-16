package agents

import (
	"errors"
	"fmt"
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
	switch hostOS {
	case "linux":
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("the path %q must start with /", p)
		}
	case "windows":
		if len(p) < 3 || p[1] != ':' || p[2] != '\\' {
			return fmt.Errorf(`the path %q must start with a drive, such as C:\`, p)
		}
	default:
		return fmt.Errorf("unknown os %q; use linux or windows", hostOS)
	}
	return nil
}
