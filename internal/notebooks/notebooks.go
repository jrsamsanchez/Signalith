// Package notebooks stores hunting notebooks: saved, shareable threat
// hunts made of notes and searches in order, each search with a snapshot
// of what it found when it last ran, tagged with the ATT&CK techniques
// the hunt looks for.
//
// A notebook is private to the analyst who made it until they share it,
// for reading or for editing by every analyst. A few starter hunts are
// built in; they can be run and copied, not changed.
package notebooks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Sharing says who can see and change a notebook besides its owner and
// admins.
const (
	// Private notebooks are seen only by their owner and admins.
	Private = "private"
	// Read notebooks are seen and run by everyone who can sign in; only
	// the owner and admins change them.
	Read = "read"
	// Edit notebooks are also changed by every analyst. Only the owner
	// and admins change the sharing or delete one.
	Edit = "edit"
)

// Sharings lists the valid sharing values.
var Sharings = []string{Private, Read, Edit}

// Cell kinds.
const (
	KindMarkdown = "markdown"
	KindSearch   = "search"
)

// Limits keep one notebook a reasonable size and a run of it bounded.
const (
	MaxCells       = 60
	MaxSearchCells = 25
	MaxTextLen     = 20000 // one markdown cell or the description
	MaxTitleLen    = 200
	MaxQueryLen    = 10000
	MaxTechniques  = 30
	MaxCases       = 50
	// MaxRows is how many rows of a search's result are kept with it.
	MaxRows = 100
	// MaxValueLen bounds one kept value; longer ones are cut.
	MaxValueLen = 2000
	// MaxResultBytes bounds one kept result; rows past it are dropped.
	MaxResultBytes = 256 << 10
)

// Notebook is one hunt.
type Notebook struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	// Owner made the notebook; with admins, they decide its sharing.
	Owner   string `json:"owner"`
	Sharing string `json:"sharing"`
	// Techniques are the ATT&CK technique IDs the hunt looks for.
	Techniques []string `json:"techniques,omitempty"`
	// TimeRange is how far back searches look unless their own
	// earliest= says otherwise: 24h, 7d, 30d.
	TimeRange string `json:"time_range"`
	// Cases are the investigations the hunt is linked to.
	Cases []string `json:"cases,omitempty"`
	Cells []Cell   `json:"cells"`
	// From names the starter hunt or notebook this one was copied from.
	From      string    `json:"from,omitempty"`
	Created   time.Time `json:"created"`
	Updated   time.Time `json:"updated"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	// Starter marks a built-in hunt.
	Starter bool `json:"starter,omitempty"`
}

// Cell is a note (markdown) or a search with its last result.
type Cell struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// Title names a search cell; Text is a markdown cell's text.
	Title string `json:"title,omitempty"`
	Text  string `json:"text,omitempty"`
	Query string `json:"query,omitempty"`
	// Result is what the search found when it last ran.
	Result *Result `json:"result,omitempty"`
}

// Result is a snapshot of a search's result.
type Result struct {
	RanAt     time.Time        `json:"ran_at"`
	RanBy     string           `json:"ran_by,omitempty"`
	Earliest  string           `json:"earliest,omitempty"`
	Kind      string           `json:"kind,omitempty"` // events, table, timechart
	Columns   []string         `json:"columns,omitempty"`
	Rows      []map[string]any `json:"rows,omitempty"`
	Matched   int64            `json:"matched"`
	Truncated bool             `json:"truncated,omitempty"` // more rows than were kept
	Error     string           `json:"error,omitempty"`
}

// Errors returned by stores and notebook methods.
var (
	ErrNotFound = errors.New("notebook not found")
	ErrExists   = errors.New("a notebook with this ID exists")
	// ErrBusy is a Modify that lost to other changes of the same notebook
	// on every try.
	ErrBusy = errors.New("someone else changed this notebook at the same moment; try again")
)

// ValidationError lists every problem in a notebook.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid notebook: " + strings.Join(e.Problems, "; ")
}

var (
	techPattern  = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	rangePattern = regexp.MustCompile(`^\d+[mhd]$`)
	cellPattern  = regexp.MustCompile(`^[a-z0-9]{1,32}$`)
)

// Normalize trims text, fills defaults and gives new cells an ID.
func (n *Notebook) Normalize() {
	n.Title = cleanLine(n.Title)
	n.Description = cleanText(n.Description)
	n.TimeRange = strings.TrimPrefix(strings.TrimSpace(n.TimeRange), "-")
	if n.TimeRange == "" {
		n.TimeRange = "7d"
	}
	if n.Sharing == "" {
		n.Sharing = Private
	}
	techs := make([]string, 0, len(n.Techniques))
	for _, t := range n.Techniques {
		if t = strings.ToUpper(strings.TrimSpace(t)); t != "" && !slices.Contains(techs, t) {
			techs = append(techs, t)
		}
	}
	n.Techniques = techs
	if n.Cells == nil {
		n.Cells = []Cell{}
	}
	seen := map[string]bool{}
	for i := range n.Cells {
		c := &n.Cells[i]
		c.Kind = strings.ToLower(strings.TrimSpace(c.Kind))
		c.Title = cleanLine(c.Title)
		c.Text = cleanText(c.Text)
		c.Query = strings.TrimSpace(c.Query)
		if c.ID == "" || seen[c.ID] {
			c.ID = NewCellID()
		}
		seen[c.ID] = true
		if c.Kind == KindMarkdown {
			c.Query, c.Title, c.Result = "", "", nil
		}
	}
}

// Validate checks every field and returns all problems at once.
func (n *Notebook) Validate() error {
	var p []string
	switch {
	case n.Title == "":
		p = append(p, "title is required")
	case utf8.RuneCountInString(n.Title) > MaxTitleLen:
		p = append(p, fmt.Sprintf("title must be %d characters or fewer", MaxTitleLen))
	}
	if len(n.Description) > MaxTextLen {
		p = append(p, "description is too long")
	}
	if !slices.Contains(Sharings, n.Sharing) {
		p = append(p, "sharing must be private, read or edit")
	}
	if !rangePattern.MatchString(n.TimeRange) {
		p = append(p, "time range must be like 24h, 7d or 30d")
	} else if d, err := detect.ParseDuration(n.TimeRange); err != nil || d < time.Minute || d > 366*24*time.Hour {
		p = append(p, "time range must be between 1m and 366d")
	}
	if len(n.Techniques) > MaxTechniques {
		p = append(p, fmt.Sprintf("a notebook can have at most %d techniques", MaxTechniques))
	}
	for _, t := range n.Techniques {
		if !techPattern.MatchString(t) {
			p = append(p, fmt.Sprintf("%q is not an ATT&CK technique ID such as T1059 or T1059.001", t))
		} else if _, ok := detect.ATTACK().Technique(t); !ok {
			p = append(p, fmt.Sprintf("%s is not in the ATT&CK matrix", t))
		}
	}
	if len(n.Cases) > MaxCases {
		p = append(p, fmt.Sprintf("a notebook can be linked to at most %d cases", MaxCases))
	}
	if len(n.Cells) > MaxCells {
		p = append(p, fmt.Sprintf("a notebook can have at most %d cells", MaxCells))
	}
	searches := 0
	for i, c := range n.Cells {
		name := fmt.Sprintf("cell %d", i+1)
		if !cellPattern.MatchString(c.ID) {
			p = append(p, name+": bad id")
		}
		switch c.Kind {
		case KindMarkdown:
			if len(c.Text) > MaxTextLen {
				p = append(p, name+": the note is too long")
			}
		case KindSearch:
			searches++
			if utf8.RuneCountInString(c.Title) > MaxTitleLen {
				p = append(p, fmt.Sprintf("%s: title must be %d characters or fewer", name, MaxTitleLen))
			}
			if len(c.Text) > MaxTextLen {
				p = append(p, name+": the note is too long")
			}
			switch {
			case c.Query == "":
				p = append(p, name+": query is required")
			case len(c.Query) > MaxQueryLen:
				p = append(p, name+": query is too long")
			default:
				if _, err := query.Parse(c.Query); err != nil {
					p = append(p, name+": query: "+queryErr(err))
				}
			}
		default:
			p = append(p, fmt.Sprintf("%s: kind must be markdown or search", name))
		}
	}
	if searches > MaxSearchCells {
		p = append(p, fmt.Sprintf("a notebook can have at most %d searches", MaxSearchCells))
	}
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

func queryErr(err error) string {
	var qe *query.Error
	if errors.As(err, &qe) {
		return fmt.Sprintf("%s (at character %d)", qe.Msg, qe.Pos+1)
	}
	return err.Error()
}

// cleanLine trims a one-line value and drops control characters.
func cleanLine(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s))
}

// cleanText trims multi-line text and drops control characters other
// than newlines and tabs.
func cleanText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s))
}

// CanSee reports whether user (with the admin role or not) may read n.
func (n *Notebook) CanSee(user string, admin bool) bool {
	return n.Starter || admin || n.Sharing != Private || n.IsOwner(user)
}

// CanEdit reports whether user may change n's cells and text: analysts
// may only on their own notebooks and ones shared for editing.
func (n *Notebook) CanEdit(user string, analyst, admin bool) bool {
	if n.Starter || !analyst {
		return false
	}
	return admin || n.IsOwner(user) || n.Sharing == Edit
}

// CanManage reports whether user may change n's sharing or delete it.
func (n *Notebook) CanManage(user string, admin bool) bool {
	return !n.Starter && (admin || n.IsOwner(user))
}

// IsOwner reports whether user made n. User names compare without case,
// as sign-in does.
func (n *Notebook) IsOwner(user string) bool {
	return user != "" && strings.EqualFold(n.Owner, user)
}

// SearchCount counts the search cells.
func (n *Notebook) SearchCount() int {
	k := 0
	for _, c := range n.Cells {
		if c.Kind == KindSearch {
			k++
		}
	}
	return k
}

// Cell returns the cell with the ID id.
func (n *Notebook) Cell(id string) (*Cell, bool) {
	for i := range n.Cells {
		if n.Cells[i].ID == id {
			return &n.Cells[i], true
		}
	}
	return nil, false
}

// KeepResults gives each search cell of n the result it had in old when
// its query is unchanged, since a client sends cells without results.
func (n *Notebook) KeepResults(old *Notebook) {
	for i := range n.Cells {
		c := &n.Cells[i]
		c.Result = nil
		if c.Kind != KindSearch {
			continue
		}
		if o, ok := old.Cell(c.ID); ok && o.Kind == KindSearch && o.Query == c.Query {
			c.Result = o.Result
		}
	}
}

// Snapshot makes the result kept with a search cell: at most MaxRows
// rows, values cut to MaxValueLen, and rows dropped past MaxResultBytes.
func Snapshot(kind string, columns []string, rows []map[string]any, matched int64, truncated bool) *Result {
	r := &Result{Kind: kind, Columns: columns, Matched: matched, Truncated: truncated || len(rows) > MaxRows, Rows: []map[string]any{}}
	size := 0
	for _, row := range rows[:min(len(rows), MaxRows)] {
		out := make(map[string]any, len(row))
		for k, v := range row {
			out[k] = cutValue(v)
		}
		b, _ := json.Marshal(out)
		if size+len(b) > MaxResultBytes {
			r.Truncated = true
			break
		}
		size += len(b)
		r.Rows = append(r.Rows, out)
	}
	return r
}

func cutValue(v any) any {
	switch x := v.(type) {
	case string:
		if len(x) > MaxValueLen {
			return cutUTF8(x, MaxValueLen) + "…"
		}
		return x
	case []any:
		if len(x) > 100 {
			x = x[:100]
		}
		out := make([]any, len(x))
		for i, y := range x {
			out[i] = cutValue(y)
		}
		return out
	case map[string]any:
		b, _ := json.Marshal(x)
		if len(b) > MaxValueLen {
			return cutUTF8(string(b), MaxValueLen) + "…"
		}
		return x
	}
	return v
}

// NewID returns a notebook ID such as "NB-20261016-3fa9c1d27b40e865".
func NewID(now time.Time) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "NB-" + now.UTC().Format("20060102") + "-" + hex.EncodeToString(b)
}

// NewCellID returns a random cell ID.
func NewCellID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Filter selects notebooks.
type Filter struct {
	// User and Admin decide what is visible: admins see every notebook,
	// others their own and shared ones.
	User  string
	Admin bool
	// Text matches the title, description or ID.
	Text string
	// Technique keeps notebooks tagged with it or one of its
	// sub-techniques.
	Technique string
	// Case keeps notebooks linked to it.
	Case string
	// Owner keeps notebooks owned by this user name (without case).
	Owner string
	Limit int
}

// Visible reports whether n passes f's visibility rule.
func (f Filter) Visible(n *Notebook) bool { return n.CanSee(f.User, f.Admin) }

// Matches reports whether n passes every part of f.
func (f Filter) Matches(n *Notebook) bool {
	if !f.Visible(n) {
		return false
	}
	if f.Case != "" && !slices.Contains(n.Cases, f.Case) {
		return false
	}
	if f.Owner != "" && !n.IsOwner(f.Owner) {
		return false
	}
	if t := strings.ToUpper(strings.TrimSpace(f.Technique)); t != "" &&
		!slices.ContainsFunc(n.Techniques, func(x string) bool { return x == t || strings.HasPrefix(x, t+".") }) {
		return false
	}
	if t := strings.ToLower(strings.TrimSpace(f.Text)); t != "" &&
		!strings.Contains(strings.ToLower(n.ID+"\n"+n.Title+"\n"+n.Description), t) {
		return false
	}
	return true
}

// Store persists notebooks.
type Store interface {
	// Create adds a new notebook; ErrExists when its ID is taken.
	Create(ctx context.Context, n *Notebook) error
	Get(ctx context.Context, id string) (*Notebook, error)
	// Modify reads a notebook, lets change edit a fresh copy and writes
	// it back if change reports a change, but only if nobody else changed
	// it in between; if someone did, it reads again and reruns change.
	// It returns ErrNotFound, ErrBusy, or change's own error as it is.
	Modify(ctx context.Context, id string, change func(n *Notebook) (bool, error)) (*Notebook, error)
	// Delete removes one notebook; a missing one is not an error.
	Delete(ctx context.Context, id string) error
	// Search returns the matching notebooks without their cells, most
	// recently updated first, and how many match.
	Search(ctx context.Context, f Filter) ([]*Summary, int, error)
}

// Summary is a notebook as a list shows it.
type Summary struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Owner       string    `json:"owner,omitempty"`
	Sharing     string    `json:"sharing,omitempty"`
	Techniques  []string  `json:"techniques,omitempty"`
	Cases       []string  `json:"cases,omitempty"`
	Cells       int       `json:"cells"`
	Searches    int       `json:"searches"`
	LastRun     time.Time `json:"last_run,omitzero"`
	Created     time.Time `json:"created,omitzero"`
	Updated     time.Time `json:"updated,omitzero"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
	Starter     bool      `json:"starter,omitempty"`
}

// Summarize returns n as a list shows it.
func Summarize(n *Notebook) *Summary {
	s := &Summary{ID: n.ID, Title: n.Title, Description: n.Description, Owner: n.Owner, Sharing: n.Sharing,
		Techniques: n.Techniques, Cases: n.Cases, Cells: len(n.Cells), Searches: n.SearchCount(),
		Created: n.Created, Updated: n.Updated, UpdatedBy: n.UpdatedBy, Starter: n.Starter}
	for _, c := range n.Cells {
		if c.Result != nil && c.Result.RanAt.After(s.LastRun) {
			s.LastRun = c.Result.RanAt
		}
	}
	return s
}

// changeError carries the error of a Modify's change function through
// the retry loop, so it is returned as it is and never retried.
type changeError struct{ err error }

func (e changeError) Error() string { return e.err.Error() }

func modifyResult(err error) error {
	var ce changeError
	switch {
	case errors.As(err, &ce):
		return ce.err
	case errors.Is(err, store.ErrConflict):
		return ErrBusy
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	}
	return err
}

func clone(n *Notebook) *Notebook {
	b, _ := json.Marshal(n)
	var out Notebook
	_ = json.Unmarshal(b, &out)
	return &out
}
