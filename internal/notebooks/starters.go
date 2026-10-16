package notebooks

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// StarterPrefix starts the ID of every starter hunt; other notebooks
// cannot use it.
const StarterPrefix = "starter-"

//go:embed starters/*.yaml
var starterFS embed.FS

// starterFile is a starter hunt as its YAML file holds it.
type starterFile struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Techniques  []string `yaml:"techniques"`
	TimeRange   string   `yaml:"time_range"`
	Cells       []struct {
		Kind  string `yaml:"kind"`
		Title string `yaml:"title"`
		Text  string `yaml:"text"`
		Query string `yaml:"query"`
	} `yaml:"cells"`
}

// starters holds the parsed starter hunts, sorted by title. They are
// checked by the tests, so a load error here is a build mistake and
// panics at start.
var starters = loadStarters()

func loadStarters() []Notebook {
	files, err := fs.Glob(starterFS, "starters/*.yaml")
	if err != nil {
		panic(err)
	}
	out := make([]Notebook, 0, len(files))
	for _, f := range files {
		data, err := starterFS.ReadFile(f)
		if err != nil {
			panic(err)
		}
		n, err := decodeStarter(data)
		if err != nil {
			panic(fmt.Sprintf("starter hunt %s: %v", f, err))
		}
		if n.ID != StarterPrefix+strings.TrimSuffix(path.Base(f), ".yaml") {
			panic(fmt.Sprintf("starter hunt %s: id %q must be %q", f, n.ID, StarterPrefix+strings.TrimSuffix(path.Base(f), ".yaml")))
		}
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Title < out[j].Title })
	return out
}

func decodeStarter(data []byte) (*Notebook, error) {
	var sf starterFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&sf); err != nil {
		return nil, err
	}
	n := &Notebook{ID: sf.ID, Title: sf.Title, Description: sf.Description, Techniques: sf.Techniques,
		TimeRange: sf.TimeRange, Sharing: Read, Owner: "Signalith", Starter: true}
	for i, c := range sf.Cells {
		n.Cells = append(n.Cells, Cell{ID: fmt.Sprintf("c%d", i+1), Kind: c.Kind, Title: c.Title, Text: c.Text, Query: c.Query})
	}
	n.Normalize()
	if err := n.Validate(); err != nil {
		return nil, err
	}
	return n, nil
}

// Starters returns copies of the built-in starter hunts.
func Starters() []*Notebook {
	out := make([]*Notebook, len(starters))
	for i := range starters {
		out[i] = clone(&starters[i])
	}
	return out
}

// Starter returns a copy of one starter hunt.
func Starter(id string) (*Notebook, bool) {
	for i := range starters {
		if starters[i].ID == id {
			return clone(&starters[i]), true
		}
	}
	return nil, false
}
