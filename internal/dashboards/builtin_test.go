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
	if len(bs) != 3 || bs[0].ID != MalwareID || bs[0].Title != "Malware" || bs[1].ID != NetworkID || bs[2].ID != VulnerabilitiesID {
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

	checkPanels(t, d, "Malware")
}

func TestBuiltinVulnerabilities(t *testing.T) {
	d, ok := GetBuiltin(VulnerabilitiesID)
	if !ok || d.Title != "Vulnerabilities" || d.TimeRange != "7d" || len(d.Panels) != 11 {
		t.Fatalf("vulnerabilities = %+v", d)
	}
	if err := d.check(); err != nil {
		t.Errorf("check: %v", err)
	}
	checkPanels(t, d, "Vulnerabilities")
}

func TestBuiltinNetwork(t *testing.T) {
	d, ok := GetBuiltin(NetworkID)
	if !ok || d.Title != "Network" || d.TimeRange != "24h" || d.Description == "" || len(d.Panels) != 16 {
		t.Fatalf("network = %+v", d)
	}
	if err := d.check(); err != nil {
		t.Errorf("check: %v", err)
	}
	// The panels read several network data models (and the sensor health
	// events, which have none), so each panel is checked against the model
	// it names.
	eng := &search.Engine{Intel: intel.NewStore(intel.NewMemory())}
	models := map[string]bool{}
	titles := map[string]bool{}
	for _, p := range d.Panels {
		if titles[p.Title] {
			t.Errorf("title %q twice", p.Title)
		}
		titles[p.Title] = true
		q, err := query.Parse(p.Query)
		if err != nil {
			t.Errorf("%s: %v", p.Title, err)
			continue
		}
		if _, err := eng.Compile(q); err != nil {
			t.Errorf("%s: compile: %v", p.Title, err)
		}
		if q.Datamodel == "" {
			// Sensor health: fields the ingest registry knows.
			for _, f := range panelFields(q) {
				if f != "sourcetype" && f != "capture_loss_percent" && f != "drop_percent" {
					t.Errorf("%s: field %s", p.Title, f)
				}
			}
			continue
		}
		models[q.Datamodel] = true
		known := map[string]bool{}
		for _, f := range datamodel.FieldsFor(q.Datamodel) {
			known[f.Name] = true
		}
		for _, f := range panelFields(q) {
			if !known[f] {
				t.Errorf("%s: field %s is not in the %s data model", p.Title, f, q.Datamodel)
			}
		}
	}
	for _, m := range []string{"Intrusion_Detection", "Network_Traffic", "Network_Resolution", "Web", "File_Transfers", "Certificates"} {
		if !models[m] {
			t.Errorf("no panel reads %s", m)
		}
	}
	last := d.Panels[len(d.Panels)-1]
	if q, _ := query.Parse(last.Query); q == nil || len(q.Commands) != 1 || len(q.Commands[0].(*query.Timechart).Aggs) != 2 {
		t.Errorf("packet loss panel = %q", last.Query)
	}
}

// checkPanels checks that every panel of d compiles, reads data model
// model, and uses only that model's fields.
func checkPanels(t *testing.T, d *Dashboard, model string) {
	t.Helper()
	eng := &search.Engine{Intel: intel.NewStore(intel.NewMemory())}
	known := map[string]bool{}
	for _, f := range datamodel.FieldsFor(model) {
		known[f.Name] = true
	}
	if _, ok := datamodel.Get(model); !ok {
		t.Fatalf("data model %s is missing", model)
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
		if q.Datamodel != model {
			t.Errorf("%s: datamodel = %q", p.Title, q.Datamodel)
		}
		for _, f := range panelFields(q) {
			if !known[f] {
				t.Errorf("%s: field %s is not in the %s data model", p.Title, f, model)
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
