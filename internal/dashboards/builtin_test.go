package dashboards

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

func TestBuiltinMalware(t *testing.T) {
	bs := Builtin()
	if len(bs) != 1 || bs[0].ID != MalwareID || bs[0].Title != "Malware" {
		t.Fatalf("built-ins = %+v", bs)
	}
	d, ok := GetBuiltin(MalwareID)
	if !ok || !IsBuiltin("malware") || IsBuiltin(PostureID) || IsBuiltin("nope") {
		t.Fatal("built-in lookup")
	}
	if d.TimeRange != "7d" || d.Description == "" || len(d.Panels) != 11 {
		t.Errorf("malware = %+v", d)
	}
	if err := d.check(); err != nil {
		t.Errorf("check: %v", err)
	}
	// Copies are independent of the embedded definition.
	d.Panels[0].Title = "changed"
	if again, _ := GetBuiltin(MalwareID); again.Panels[0].Title == "changed" {
		t.Error("GetBuiltin returned shared panels")
	}

	eng := &search.Engine{Intel: intel.NewStore(intel.NewMemory())}
	known := map[string]bool{}
	for _, f := range datamodel.FieldsFor("Malware") {
		known[f.Name] = true
	}
	if _, ok := datamodel.Get("Malware"); !ok {
		t.Fatal("data model Malware is missing")
	}
	for _, p := range d.Panels {
		q, err := query.Parse(p.Query)
		if err != nil {
			t.Errorf("%s: %v", p.Title, err)
			continue
		}
		if _, err := eng.Compile(q); err != nil {
			t.Errorf("%s: compile: %v", p.Title, err)
		}
		if q.Datamodel != "Malware" {
			t.Errorf("%s: datamodel = %q", p.Title, q.Datamodel)
		}
		for _, f := range panelFields(q) {
			if !known[f] {
				t.Errorf("%s: field %s is not in the Malware data model", p.Title, f)
			}
		}
	}
}

// panelFields returns the event fields a query filters on, aggregates,
// groups by or lists in table.
func panelFields(q *query.Query) []string {
	var out []string
	var walk func(e query.Expr)
	walk = func(e query.Expr) {
		switch x := e.(type) {
		case *query.And:
			for _, c := range x.Children {
				walk(c)
			}
		case *query.Or:
			for _, c := range x.Children {
				walk(c)
			}
		case *query.Not:
			walk(x.Child)
		case *query.Compare:
			out = append(out, x.Field)
		case *query.In:
			out = append(out, x.Field)
		}
	}
	if q.Search != nil {
		walk(q.Search)
	}
	if len(q.Commands) > 0 {
		switch c := q.Commands[0].(type) {
		case *query.Stats:
			for _, a := range c.Aggs {
				if a.Field != "" {
					out = append(out, a.Field)
				}
			}
			out = append(out, c.By...)
		case *query.Timechart:
			if c.By != "" {
				out = append(out, c.By)
			}
		case *query.Table:
			out = append(out, c.Fields...)
		}
	}
	return out
}

func TestValidateRefusesBuiltinIDs(t *testing.T) {
	d := &Dashboard{ID: "malware", Title: "Mine"}
	d.Defaults()
	err := d.Validate()
	if err == nil || !strings.Contains(err.Error(), `id "malware" is a built-in dashboard; choose another`) {
		t.Errorf("err = %v", err)
	}
	d.ID = "posture"
	if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "built-in") {
		t.Errorf("posture err = %v", err)
	}
	// Other problems are still listed after the reserved id.
	d = &Dashboard{ID: "malware"}
	d.Defaults()
	ve, ok := d.Validate().(*ValidationError)
	if !ok || len(ve.Problems) != 2 {
		t.Errorf("problems = %v", d.Validate())
	}
}

func TestStoreBuiltinIDs(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if id := s.NewID("Malware"); id != "malware-2" {
		t.Errorf("NewID(Malware) = %q", id)
	}
	if err := s.Put(&Dashboard{ID: "malware", Title: "Mine"}); err == nil {
		t.Error("Put with a built-in id succeeded")
	}
	// A file written by hand with the built-in id is reported, not loaded.
	data := "id: malware\ntitle: Old malware board\npanels: []\n"
	if err := os.WriteFile(filepath.Join(dir, "malware.yaml"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(&Dashboard{ID: "ops", Title: "Ops"}); err != nil {
		t.Fatal(err)
	}
	ds, problems, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 1 || ds[0].ID != "ops" {
		t.Errorf("list = %+v", ds)
	}
	want := "malware.yaml uses the id of the built-in Malware dashboard and is ignored. Rename the file and change its id to keep it."
	if len(problems) != 1 || problems[0].File != "malware.yaml" || problems[0].Error != want {
		t.Errorf("problems = %+v", problems)
	}
	if _, err := s.Get("malware"); err == nil {
		t.Error("Get(malware) loaded the custom file")
	}
}
