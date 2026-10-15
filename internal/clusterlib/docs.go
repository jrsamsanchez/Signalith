// Package clusterlib keeps the detection library and the custom
// dashboards of a cluster in the shared settings (internal/shared), so
// every server reads and changes the same ones: the custom detections
// and the choices made for shipped ones (detection:<id>), and the custom
// dashboards (dashboard:<id>). It has the backends the detect and
// dashboards packages use, the importers that move the founder's folders
// into the cluster, and the inbox that keeps each server's folders and
// the shared library in step (a file changed in a folder is pushed, a
// shared change is written back).
package clusterlib

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// Kinds and watch documents of the shared library.
const (
	DetectionKind  = "detection"
	DashboardKind  = "dashboard"
	DetectionWatch = "detections"
	DashboardWatch = "dashboards"
)

// Sources of a shared item, in From.
const (
	FromPage   = "page"
	FromImport = "import"
	// FromFile is a file changed in a server's folder and pushed by its
	// inbox.
	FromFile = "file"
)

// From says where a shared item's latest change came from.
type From struct {
	Source string `json:"source"`
	Node   string `json:"node,omitempty"`
	At     string `json:"at,omitempty"`
}

// DetectionBody is the body of detection:<id>: a custom detection or an
// override of a shipped one, as detect.Encode writes it, and the state
// chosen for a shipped one (on or off, exceptions). At least one is set.
type DetectionBody struct {
	YAML         string        `json:"yaml,omitempty"`
	State        *detect.State `json:"state,omitempty"`
	From         *From         `json:"from,omitempty"`
	shared.Extra `json:"-"`
}

// DashboardBody is the body of dashboard:<id>: a custom dashboard as
// dashboards.Encode writes it.
type DashboardBody struct {
	YAML         string `json:"yaml"`
	From         *From  `json:"from,omitempty"`
	shared.Extra `json:"-"`
}

// idPattern is what a detection or dashboard ID looks like, as the
// detect and dashboards packages check it. An item name is also a file
// name in the folders, so it is checked even when the item holds no YAML.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,63}$`)

// checkName checks that an item name is a valid ID.
func checkName(name string) error {
	if !idPattern.MatchString(name) {
		return fmt.Errorf("its name %q is not a valid id", name)
	}
	return nil
}

// decode returns the custom detection and the state of a body.
func (b *DetectionBody) decode(id string) (*detect.Detection, *detect.State, error) {
	if err := checkName(id); err != nil {
		return nil, nil, err
	}
	var d *detect.Detection
	if b.YAML != "" {
		var err error
		if d, err = detect.Decode([]byte(b.YAML)); err != nil {
			return nil, nil, err
		}
		if err := d.Validate(); err != nil {
			return nil, nil, err
		}
		if d.ID != id {
			return nil, nil, fmt.Errorf("it holds the detection %q", d.ID)
		}
	}
	if b.State != nil {
		if p := detect.ExceptionProblems(b.State.Exceptions); len(p) > 0 {
			return nil, nil, &detect.ValidationError{ID: id, Problems: p}
		}
	}
	if d == nil && b.State == nil {
		return nil, nil, errors.New("it holds neither a detection nor a state")
	}
	return d, b.State, nil
}

// decode returns the dashboard of a body.
func (b *DashboardBody) decode(id string) (*dashboards.Dashboard, error) {
	return dashboards.DecodeFile(id+".yaml", []byte(b.YAML))
}

// namesID checks that the YAML text, when there is one, holds the item
// name.
func namesID(name, text string) error {
	if text == "" {
		return nil
	}
	var head struct {
		ID string `yaml:"id"`
	}
	if err := yaml.Unmarshal([]byte(text), &head); err != nil {
		return err
	}
	if head.ID != name {
		return fmt.Errorf("it holds %q", head.ID)
	}
	return nil
}

// Docs holds the shared collections of the library, made again on each
// hub the runtime builds (Track is part of its RuntimeOptions.Content),
// and passes their changes to whoever uses them now. Each start of the
// server's components subscribes again after Reset.
type Docs struct {
	mu         sync.Mutex
	hub        *shared.Hub
	detections *shared.Collection[DetectionBody]
	dashboards *shared.Collection[DashboardBody]
	lookups    *shared.Collection[LookupHead]
	subs       map[string][]func()
}

// Kinds of change subscribers hear of.
const (
	changeDetections = "detections"
	changeDashboards = "dashboards"
	changeLookups    = "lookups"
)

// NewDocs returns the holder; the runtime makes the collections.
func NewDocs() *Docs { return &Docs{subs: map[string][]func(){}} }

// Track makes the collections on h.
func (d *Docs) Track(h *shared.Hub) {
	// An item must name its own id. What else it holds is checked where
	// it is used: a detection written by a newer version, with a field or
	// query command this one does not know, is left out here rather than
	// reported as a problem with the shared settings.
	dets := shared.NewCollection[DetectionBody](h, DetectionKind, DetectionWatch, 1)
	dets.ValidateItem = func(name string, b *DetectionBody) error {
		if err := checkName(name); err != nil {
			return err
		}
		if b.YAML == "" && b.State == nil {
			return errors.New("it holds neither a detection nor a state")
		}
		return namesID(name, b.YAML)
	}
	boards := shared.NewCollection[DashboardBody](h, DashboardKind, DashboardWatch, 1)
	boards.ValidateItem = func(name string, b *DashboardBody) error {
		if err := checkName(name); err != nil {
			return err
		}
		return namesID(name, b.YAML)
	}
	heads := shared.NewCollection[LookupHead](h, LookupKind, LookupWatch, 1)
	heads.ValidateItem = func(name string, b *LookupHead) error { return b.check(name) }
	dets.OnChange(func() { d.fire(changeDetections) })
	boards.OnChange(func() { d.fire(changeDashboards) })
	heads.OnChange(func() { d.fire(changeLookups) })
	d.mu.Lock()
	d.hub, d.detections, d.dashboards, d.lookups = h, dets, boards, heads
	d.mu.Unlock()
}

// Reset forgets every subscriber, at each start of the components.
func (d *Docs) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.subs = map[string][]func(){}
}

func (d *Docs) on(kind string, fn func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.subs[kind] = append(d.subs[kind], fn)
}

func (d *Docs) fire(kind string) {
	d.mu.Lock()
	subs := slices.Clone(d.subs[kind])
	d.mu.Unlock()
	for _, fn := range subs {
		fn()
	}
}

// OnDetections adds a function called after the shared detections
// changed, here or on another server.
func (d *Docs) OnDetections(fn func()) { d.on(changeDetections, fn) }

// OnDashboards adds a function called after the shared dashboards
// changed, here or on another server.
func (d *Docs) OnDashboards(fn func()) { d.on(changeDashboards, fn) }

// OnLookups adds a function called after the shared asset or identity
// list changed, here or on another server.
func (d *Docs) OnLookups(fn func()) { d.on(changeLookups, fn) }

// Hub returns the hub the collections are on.
func (d *Docs) Hub() *shared.Hub {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hub
}

// Detections returns the collection of the shared detections.
func (d *Docs) Detections() *shared.Collection[DetectionBody] {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.detections
}

// Dashboards returns the collection of the shared dashboards.
func (d *Docs) Dashboards() *shared.Collection[DashboardBody] {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dashboards
}

// Lookups returns the collection of the shared lists' heads.
func (d *Docs) Lookups() *shared.Collection[LookupHead] {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lookups
}

// stamp is a From of source now, on node.
func stamp(source, node string, now time.Time) *From {
	return &From{Source: source, Node: node, At: now.UTC().Format(time.RFC3339Nano)}
}
