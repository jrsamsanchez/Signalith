package dashboards

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strings"
)

// MalwareID is the ID of the built-in Malware dashboard.
const MalwareID = "malware"

//go:embed builtin/*.yaml
var builtinFS embed.FS

// builtins holds the parsed built-in panel dashboards, in file name
// order. They are checked by the tests, so a load error here is a build
// mistake and panics at start.
var builtins = loadBuiltins()

func loadBuiltins() []Dashboard {
	files, err := fs.Glob(builtinFS, "builtin/*.yaml")
	if err != nil {
		panic(err)
	}
	sort.Strings(files)
	out := make([]Dashboard, 0, len(files))
	for _, f := range files {
		data, err := builtinFS.ReadFile(f)
		if err != nil {
			panic(err)
		}
		d, err := Decode(data)
		if err != nil {
			panic(fmt.Sprintf("built-in dashboard %s: %v", f, err))
		}
		if d.ID+".yaml" != path.Base(f) {
			panic(fmt.Sprintf("built-in dashboard %s: id %q does not match the file name", f, d.ID))
		}
		if err := d.check(); err != nil {
			panic(fmt.Sprintf("built-in dashboard %s: %v", f, err))
		}
		out = append(out, *d)
	}
	return out
}

// Builtin returns copies of the built-in panel dashboards, such as
// Malware. They are read-only: they can be viewed, run and copied, but not
// changed or deleted. The posture dashboard is computed and not listed
// here.
func Builtin() []Dashboard {
	out := make([]Dashboard, len(builtins))
	for i, d := range builtins {
		d.Panels = slices.Clone(d.Panels)
		out[i] = d
	}
	return out
}

// GetBuiltin returns a copy of one built-in panel dashboard.
func GetBuiltin(id string) (*Dashboard, bool) {
	for _, d := range builtins {
		if d.ID == id {
			d.Panels = slices.Clone(d.Panels)
			return &d, true
		}
	}
	return nil, false
}

// IsBuiltin reports whether id belongs to a built-in panel dashboard.
func IsBuiltin(id string) bool {
	_, ok := GetBuiltin(id)
	return ok
}

// builtinTitle names the built-in dashboard that owns id, for messages.
func builtinTitle(id string) string {
	if d, ok := GetBuiltin(id); ok {
		return d.Title
	}
	return strings.ToUpper(id[:1]) + id[1:]
}
