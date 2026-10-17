package retention

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// Actions the planner picks for an index.
const (
	ActionKeep    = "keep"
	ActionCompact = "compact"
	// ActionArchive archives the index, then deletes it.
	ActionArchive = "archive"
	ActionDelete  = "delete"
	// ActionSkip marks an index that is not a Signalith daily index; it is
	// never touched.
	ActionSkip = "skip"
	// ActionCold moves a day to cold storage: snapshot, delete from the
	// nodes' disks, mount back from the snapshot.
	ActionCold = "cold"
	// ActionMount mounts a day whose move to cold storage stopped after
	// its snapshot was made and its index deleted.
	ActionMount = "mount"
)

// Rules that lead to an action.
const (
	RuleKeepDays = "keep_days"
	RuleSizeCap  = "size_cap"
	RuleGuard    = "guard"
	RuleCompact  = "compact_after_days"
	RuleRecords  = "closed_records"
	RuleCold     = "cold_after_days"
	// RuleColdRecover finishes a move to cold storage that stopped
	// between deleting the index and mounting its snapshot.
	RuleColdRecover = "cold_recover"
)

// Decision is what the planner chose for one index, and why.
type Decision struct {
	Index    string `json:"index"`
	Category string `json:"category,omitempty"`
	Day      string `json:"day,omitempty"` // YYYY-MM-DD
	Action   string `json:"action"`
	Rule     string `json:"rule,omitempty"`
	Reason   string `json:"reason"`
	// Source is where the policy behind the decision comes from: default,
	// days, ui or config (for the guard: builtin, ui or config).
	Source string `json:"source,omitempty"`
	Bytes  int64  `json:"bytes"`
	Docs   int64  `json:"docs"`
	// Snapshot is the cold storage snapshot the step mounts or deletes
	// (after the index, when the index is mounted from it).
	Snapshot string `json:"snapshot,omitempty"`

	age int
	// cold means the index is mounted from cold storage; snapshotOnly
	// that only its snapshot is left (a delete removes just that).
	cold, snapshotOnly bool
	// stale is a snapshot of this very index left by a move to cold
	// storage that stopped before the index was deleted; the next move
	// deletes it and snapshots again.
	stale     string
	restored  bool
	compacted bool
	// writesBlocked means writes to the index are already blocked, by an
	// earlier compaction or by OpenSearch's flood-stage block.
	writesBlocked bool
	// diskBlocked means OpenSearch's flood-stage block is on the index:
	// it can still be read and deleted, but not changed or merged.
	diskBlocked bool
	// verify is set on a delete in a category that archives, when the
	// archive already holds the index (or it is empty): before deleting,
	// the run blocks writes, refreshes and counts, and archives the index
	// after all if it holds more than archived documents.
	verify   bool
	archived int64
	// hold keeps an index out of reach of size caps and the guard.
	hold bool
	// uuid and primary (the primary shards' size) are for the archive.
	uuid    string
	primary int64
}

// Changes reports whether the decision does something to the index.
func (d Decision) Changes() bool {
	switch d.Action {
	case ActionCompact, ActionArchive, ActionDelete, ActionCold, ActionMount:
		return true
	}
	return false
}

// Removes reports whether the decision deletes the index.
func (d Decision) Removes() bool { return d.Action == ActionArchive || d.Action == ActionDelete }

// RecordStep deletes resolved and closed findings or cases.
type RecordStep struct {
	Category string    `json:"category"`
	Index    string    `json:"index"`
	Count    int64     `json:"count"`
	KeepDays int       `json:"keep_days"`
	Before   time.Time `json:"before"`
	Reason   string    `json:"reason"`
	Source   string    `json:"source"`
	// keepCases lists open cases whose findings are kept.
	keepCases []string
}

// Guard states.
const (
	GuardOff     = "off"
	GuardOK      = "ok"
	GuardOver    = "over"    // above the limit; the plan deletes the oldest days
	GuardShort   = "short"   // above the limit, and the days the guard may delete cannot get it under
	GuardUnknown = "unknown" // disk use could not be read
	GuardPaused  = "paused"  // the settings file has errors, so nothing runs
)

// GuardStatus says what the disk guard sees and plans.
type GuardStatus struct {
	State     string  `json:"state"`
	Percent   float64 `json:"percent"`
	Threshold int     `json:"max_disk_percent"`
	MinDays   int     `json:"min_days"`
	// NeedBytes is how much must go to get under the limit after the
	// policies' own deletions; CanFreeBytes is what every day the guard
	// may delete holds on that disk; PlannedBytes is what it deletes.
	NeedBytes    int64  `json:"need_bytes,omitempty"`
	CanFreeBytes int64  `json:"can_free_bytes,omitempty"`
	PlannedBytes int64  `json:"planned_bytes,omitempty"`
	PlannedDays  int    `json:"planned_days,omitempty"`
	Message      string `json:"message"`
}

// FloodPercent is the disk use at which OpenSearch makes indices
// read-only (its default flood-stage watermark). When the guard cannot get
// the disk under its own limit, it only deletes days if that keeps the
// disk at or below FloodPercent minus one.
const FloodPercent = 95

// Plan is everything a run would do.
type Plan struct {
	Time  time.Time `json:"time"`
	Today string    `json:"today"`
	// Decisions has one entry per index under the prefix, oldest day first.
	Decisions []Decision   `json:"-"`
	Records   []RecordStep `json:"records"`
	Guard     GuardStatus  `json:"guard"`
	Notes     []string     `json:"notes"`
}

// Steps returns the decisions that change something: deletions first,
// oldest day first, then mounts, moves to cold storage and compactions.
func (p *Plan) Steps() []Decision {
	var del, mount, cold, comp []Decision
	for _, d := range p.Decisions {
		switch {
		case d.Removes():
			del = append(del, d)
		case d.Action == ActionMount:
			mount = append(mount, d)
		case d.Action == ActionCold:
			cold = append(cold, d)
		case d.Action == ActionCompact:
			comp = append(comp, d)
		}
	}
	return slices.Concat(del, mount, cold, comp)
}

// Summary counts what a plan, or part of it, does.
type Summary struct {
	DeleteDays   int   `json:"delete_days"` // archived days included
	DeleteBytes  int64 `json:"delete_bytes"`
	ArchiveDays  int   `json:"archive_days"`
	CompactDays  int   `json:"compact_days"`
	CompactBytes int64 `json:"compact_bytes"`
	// ColdDays move to cold storage, freeing ColdBytes of disk; MountDays
	// finish a move that stopped.
	ColdDays      int      `json:"cold_days"`
	ColdBytes     int64    `json:"cold_bytes"`
	MountDays     int      `json:"mount_days"`
	DeleteRecords int64    `json:"delete_records"`
	Categories    []string `json:"categories"`
}

// DeletesData reports whether the summary deletes anything.
func (s Summary) DeletesData() bool { return s.DeleteDays > 0 || s.DeleteRecords > 0 }

// Summarize counts steps and record steps.
func Summarize(steps []Decision, records []RecordStep) Summary {
	s := Summary{Categories: []string{}}
	touch := func(c string) {
		if !slices.Contains(s.Categories, c) {
			s.Categories = append(s.Categories, c)
		}
	}
	for _, d := range steps {
		switch {
		case d.Removes():
			s.DeleteDays++
			s.DeleteBytes += d.Bytes
			if d.Action == ActionArchive {
				s.ArchiveDays++
			}
		case d.Action == ActionCompact:
			s.CompactDays++
			s.CompactBytes += d.Bytes
		case d.Action == ActionCold:
			s.ColdDays++
			s.ColdBytes += d.Bytes
		case d.Action == ActionMount:
			s.MountDays++
		default:
			continue
		}
		touch(d.Category)
	}
	for _, r := range records {
		if r.Count > 0 {
			s.DeleteRecords += r.Count
			touch(r.Category)
		}
	}
	return s
}

// Snapshot is the state the planner works from.
type Snapshot struct {
	Now    time.Time
	Prefix string
	// Indices lists the indices under <prefix>-*.
	Indices []IndexInfo
	// Disk is nil when disk use could not be read.
	Disk *Disk
	// NodeBytes maps each index to the bytes it holds on Disk's node, so
	// the guard knows what deleting it frees there. When nil, every
	// index's whole size counts (a single node).
	NodeBytes map[string]int64
	// Archives lists the archive files of each index name.
	Archives map[string][]Manifest
	// Skip lists indices to leave alone, with the reason, such as days
	// whose archive failed earlier in the same run.
	Skip map[string]string
	// Cold is what OpenSearch says about cold storage; nil when it could
	// not be read, and then nothing moves to or from cold storage.
	Cold *ColdState
}

// archivedCopy returns how many documents of this very index the archive
// holds, or -1 when no archive is known to cover it. An archive covers an
// index it was made from (same UUID, written after writes were blocked),
// or a restored index whose documents all came from its archives. An index
// of the same name created again by late events is not covered, however
// many documents older archives of that day hold.
func archivedCopy(ix IndexInfo, mans []Manifest) int64 {
	for _, m := range mans {
		if ix.UUID != "" && m.IndexUUID == ix.UUID && m.Docs >= ix.Docs {
			return m.Docs
		}
	}
	if len(ix.RestoredFrom) == 0 {
		return -1
	}
	var n int64
	for _, id := range ix.RestoredFrom {
		i := slices.IndexFunc(mans, func(m Manifest) bool { return m.ID == id })
		if i < 0 {
			return -1 // that file was moved or removed: archive again
		}
		n += mans[i].Docs
	}
	if ix.Docs > n {
		return -1 // events were added after the restore
	}
	return n
}

// isMonthly reports whether a category keeps monthly indices.
func isMonthly(id string) bool {
	c, ok := CategoryByID(id)
	return ok && c.Kind == KindMonthly
}

func startOfDay(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// PlanIndices decides what happens to every daily index. It is a pure
// function of the snapshot and settings, so previews and runs agree.
//
// The rules, in order:
//   - Names that are not <prefix>-<category>-YYYY.MM.DD are skipped.
//   - Today's and future-dated indices are always kept, as are restored
//     indices until their keep-until day.
//   - keep_days: days more than keep_days before today are deleted.
//   - max_size_gb: while a category is over its cap, its oldest days are
//     deleted.
//   - Disk guard: while the disk is over the limit, the oldest days of any
//     category are deleted, sparing the last min_days days.
//   - compact_after_days: kept days older than that are compacted once.
//
// A deleted day is archived first when its category's policy says so and
// the archive does not already hold all of its documents.
func PlanIndices(snap Snapshot, s Settings) *Plan {
	today := startOfDay(snap.Now)
	plan := &Plan{Time: snap.Now.UTC(), Today: today.Format(time.DateOnly), Notes: []string{}, Records: []RecordStep{}}
	todayKey := today.Format(time.DateOnly)

	order := map[string]int{}
	for i, c := range Categories() {
		order[c.ID] = i
	}
	type entry struct {
		Decision
		dayT time.Time
		info IndexInfo
	}
	var ents []*entry
	var unavailable []string
	for _, ix := range snap.Indices {
		cat, day, ok := ParseIndex(snap.Prefix, ix.Name)
		e := &entry{Decision: Decision{Index: ix.Name, Bytes: ix.Bytes, Docs: ix.Docs, uuid: ix.UUID, primary: ix.PrimaryBytes}, dayT: day, info: ix}
		if !ok {
			e.Action, e.Reason = ActionSkip, "Not a Signalith daily index; left alone"
			ents = append(ents, e)
			continue
		}
		pol, src := s.For(cat)
		e.Category, e.Day, e.Source = cat, day.Format(time.DateOnly), src
		e.age = int(today.Sub(day).Hours() / 24)
		e.compacted = ix.Compacted()
		e.writesBlocked, e.diskBlocked = ix.WriteBlocked || ix.DiskBlocked, ix.DiskBlocked
		if ix.Cold != nil {
			// Its data is in the snapshot repository: deleting it frees no
			// disk, so size caps and the disk guard leave it alone.
			e.cold, e.hold, e.Snapshot = true, true, ix.Cold.Snapshot
		}
		e.Action = ActionKeep
		monthly := isMonthly(cat)
		if monthly {
			// A month counts from its last day, and only keep_days removes
			// it: size caps and the disk guard never touch it.
			e.age = int(today.Sub(monthEnd(day)).Hours() / 24)
			e.hold = true
		}
		switch {
		case monthly && !ix.Unavailable && e.age <= 0 && !(ix.RestoredUntil != "" && ix.RestoredUntil >= todayKey):
			e.age = 0
			e.Reason = "This month's records"
		case ix.Unavailable:
			// Its size and events are unknown, and deleting it now would
			// lose what is on the missing shard.
			e.hold = true
			e.Reason = "Unavailable in OpenSearch (a primary shard is missing); left alone until it recovers"
			unavailable = append(unavailable, ix.Name)
		case snap.Skip[ix.Name] != "":
			e.hold = true
			e.Reason = "Left alone in this run: " + snap.Skip[ix.Name]
		case day.After(today):
			e.Reason = "Dated in the future; kept"
		case e.age == 0:
			e.Reason = "Today's data"
		case ix.RestoredUntil != "" && ix.RestoredUntil >= todayKey:
			e.restored = true
			e.Reason = "Restored from the archive; kept until " + ix.RestoredUntil
		case pol.KeepDays > 0 && e.age > pol.KeepDays:
			e.Action, e.Rule = ActionDelete, RuleKeepDays
			e.Reason = fmt.Sprintf("Older than %s", days(pol.KeepDays))
		case pol.KeepDays > 0:
			e.Reason = fmt.Sprintf("Within %s", days(pol.KeepDays))
		default:
			e.Reason = "Kept forever"
		}
		if e.cold && e.Action == ActionKeep {
			e.Reason = "In cold storage; " + strings.ToLower(e.Reason[:1]) + e.Reason[1:]
		}
		ents = append(ents, e)
	}
	// Snapshots in cold storage that no index is mounted from: a move
	// that stopped after the index was deleted gets mounted, and one whose
	// day is past keep_days gets deleted.
	if snap.Cold != nil {
		mounted, names := map[string]bool{}, map[string]bool{}
		for _, e := range ents {
			names[e.Index] = true
			if e.cold {
				mounted[e.Snapshot] = true
			}
		}
		var waiting []string
		for _, sn := range snap.Cold.Snapshots {
			if mounted[sn.Name] {
				continue
			}
			cat, day, ok := ParseIndex(snap.Prefix, sn.Index)
			if !ok || isMonthly(cat) {
				continue
			}
			if i := slices.IndexFunc(ents, func(e *entry) bool { return e.Index == sn.Index && !e.cold }); i >= 0 &&
				ColdSnapshotName(ents[i].Index, ents[i].uuid) == sn.Name {
				// Left by a move that stopped before the index was deleted.
				ents[i].stale = sn.Name
				continue
			}
			pol, src := s.For(cat)
			e := &entry{Decision: Decision{Index: sn.Index, Category: cat, Day: day.Format(time.DateOnly), Source: src,
				Snapshot: sn.Name, snapshotOnly: true, cold: true, hold: true}, dayT: day}
			e.age = int(today.Sub(day).Hours() / 24)
			switch {
			case pol.KeepDays > 0 && e.age > pol.KeepDays:
				e.Action, e.Rule = ActionDelete, RuleKeepDays
				e.Reason = fmt.Sprintf("Older than %s; only its cold storage snapshot is left", days(pol.KeepDays))
			case names[sn.Index]:
				// Another index of that name holds events that arrived
				// later; mounting would need its name, so both are kept.
				e.Action = ActionKeep
				e.Reason = "In cold storage, not mounted: an index of the same name holds events that arrived later"
				waiting = append(waiting, sn.Index)
			case snap.Cold.Mountable:
				e.Action, e.Rule = ActionMount, RuleColdRecover
				e.Reason = "Moved to cold storage, but not mounted yet"
			default:
				e.Action = ActionKeep
				e.Reason = "In cold storage, not mounted: no OpenSearch node can mount searchable snapshots"
				waiting = append(waiting, sn.Index)
			}
			ents = append(ents, e)
		}
		if len(waiting) > 0 {
			slices.Sort(waiting)
			plan.Notes = append(plan.Notes, fmt.Sprintf("Cold storage holds %s that can't be mounted now, so %s searchable only once %s mounted: %s.",
				plural(len(waiting), "day", "days"), map[bool]string{true: "it isn't", false: "they aren't"}[len(waiting) == 1],
				map[bool]string{true: "it is", false: "they are"}[len(waiting) == 1], strings.Join(waiting, ", ")))
		}
	}
	sort.SliceStable(ents, func(i, j int) bool {
		a, b := ents[i], ents[j]
		if (a.Category == "") != (b.Category == "") {
			return a.Category != ""
		}
		if !a.dayT.Equal(b.dayT) {
			return a.dayT.Before(b.dayT)
		}
		if order[a.Category] != order[b.Category] {
			return order[a.Category] < order[b.Category]
		}
		return a.Index < b.Index
	})
	// deletable reports whether a kept index may be deleted by the size
	// cap or the guard.
	deletable := func(e *entry) bool {
		return e.Category != "" && e.Action == ActionKeep && e.age >= 1 && !e.dayT.After(today) && !e.restored && !e.hold
	}
	if len(unavailable) > 0 {
		slices.Sort(unavailable)
		plan.Notes = append(plan.Notes, fmt.Sprintf("OpenSearch can't read %s (a primary shard is missing), so retention leaves %s alone until OpenSearch recovers: %s.",
			plural(len(unavailable), "index", "indices"), map[bool]string{true: "it", false: "them"}[len(unavailable) == 1], strings.Join(unavailable, ", ")))
	}

	// Size caps, oldest days first. Restored days count neither toward a
	// cap nor as something it may delete: restoring days for an
	// investigation must not push live days out.
	for _, c := range Categories() {
		pol, _ := s.For(c.ID)
		capBytes := pol.CapBytes()
		if c.Kind != KindEvents || capBytes <= 0 {
			continue
		}
		var size int64
		for _, e := range ents {
			if e.Category == c.ID && !e.Removes() && !e.restored && !e.cold {
				size += e.Bytes
			}
		}
		if size <= capBytes {
			continue
		}
		for _, e := range ents {
			if size <= capBytes {
				break
			}
			if e.Category == c.ID && deletable(e) {
				e.Action, e.Rule = ActionDelete, RuleSizeCap
				e.Reason = fmt.Sprintf("%s is over its %s size cap", c.Name, gbString(pol.MaxSizeGB))
				size -= e.Bytes
			}
		}
		if size > capBytes {
			plan.Notes = append(plan.Notes, fmt.Sprintf("%s is over its %s size cap, but only today's or restored data is left to delete.",
				c.Name, gbString(pol.MaxSizeGB)))
		}
	}

	// Disk guard, oldest days of any category first.
	g := s.Guard
	plan.Guard = GuardStatus{Threshold: g.MaxDiskPercent, MinDays: g.MinDays}
	switch {
	case !g.IsEnabled():
		plan.Guard.State, plan.Guard.Message = GuardOff, "The disk guard is off."
		if snap.Disk != nil {
			plan.Guard.Percent = roundPercent(snap.Disk.Percent())
		}
	case snap.Disk == nil || snap.Disk.Total <= 0:
		plan.Guard.State, plan.Guard.Message = GuardUnknown, "Disk use could not be read from OpenSearch."
	default:
		d := snap.Disk
		plan.Guard.Percent = roundPercent(d.Percent())
		if d.Percent() <= float64(g.MaxDiskPercent) {
			plan.Guard.State = GuardOK
			plan.Guard.Message = fmt.Sprintf("Disk %.0f%% used; the guard acts above %d%%.", d.Percent(), g.MaxDiskPercent)
			break
		}
		// What deleting an index frees on the full disk: on a cluster of
		// several nodes, only its shards on that node count.
		freed := func(e *entry) int64 {
			if e.cold {
				return 0
			}
			if snap.NodeBytes != nil {
				return snap.NodeBytes[e.Index]
			}
			return e.Bytes
		}
		used := d.Used()
		for _, e := range ents {
			if e.Removes() {
				used -= freed(e)
			}
		}
		need := used - d.Total*int64(g.MaxDiskPercent)/100
		plan.Guard.State = GuardOver
		if need <= 0 {
			plan.Guard.Message = fmt.Sprintf("Disk %.0f%% used, above the %d%% disk guard; the policies' own deletions get it under.",
				d.Percent(), g.MaxDiskPercent)
			break
		}
		plan.Guard.NeedBytes = need
		var cands []*entry
		var can int64
		for _, e := range ents {
			if deletable(e) && e.age > g.MinDays && freed(e) > 0 {
				cands = append(cands, e)
				can += freed(e)
			}
		}
		plan.Guard.CanFreeBytes = can
		// When even every day it may delete cannot get the disk under the
		// limit, for example because other files fill it, deleting them all
		// would lose history for nothing. The guard then only deletes to
		// keep OpenSearch below its flood stage, if that is in reach.
		target, fallback := need, false
		if can < need {
			target = used - d.Total*(FloodPercent-1)/100
			fallback = true
			if target <= 0 || can < target {
				target = 0
			}
		}
		// Oldest day first; on the same day, the biggest first.
		sort.SliceStable(cands, func(i, j int) bool {
			if !cands[i].dayT.Equal(cands[j].dayT) {
				return cands[i].dayT.Before(cands[j].dayT)
			}
			return cands[i].Bytes > cands[j].Bytes
		})
		for _, e := range cands {
			if target <= 0 {
				break
			}
			e.Action, e.Rule, e.Source = ActionDelete, RuleGuard, s.GuardSource
			e.Reason = fmt.Sprintf("Disk %.0f%% used, above the %d%% disk guard", d.Percent(), g.MaxDiskPercent)
			target -= freed(e)
			plan.Guard.PlannedBytes += freed(e)
			plan.Guard.PlannedDays++
		}
		head := fmt.Sprintf("Disk %.0f%% used, above the %d%% disk guard.", d.Percent(), g.MaxDiskPercent)
		switch {
		case !fallback:
			verb := "are"
			if plan.Guard.PlannedDays == 1 {
				verb = "is"
			}
			plan.Guard.Message = fmt.Sprintf("Disk %.0f%% used, above the %d%% disk guard; %s %s deleted to get under it.",
				d.Percent(), g.MaxDiskPercent, oldestDays(plan.Guard.PlannedDays), verb)
		case len(cands) == 0:
			plan.Guard.State = GuardShort
			plan.Guard.Message = fmt.Sprintf("%s Only the last %s are left, which the guard never deletes. Add disk space or keep less.",
				head, days(g.MinDays))
		case plan.Guard.PlannedDays > 0:
			plan.Guard.State = GuardShort
			plan.Guard.Message = fmt.Sprintf("%s Every day the guard may delete holds only %s of the %s it needs, so it deletes only %s, enough to keep the disk below %d%%, where OpenSearch stops taking events. Add disk space or keep less.",
				head, sizeString(can), sizeString(need), oldestDays(plan.Guard.PlannedDays), FloodPercent)
		default:
			plan.Guard.State = GuardShort
			plan.Guard.Message = fmt.Sprintf("%s Every day the guard may delete holds only %s of the %s it needs, so it deletes nothing. Add disk space, keep less, or look for other files on that disk.",
				head, sizeString(can), sizeString(need))
		}
		if plan.Guard.State == GuardShort {
			plan.Notes = append(plan.Notes, plan.Guard.Message)
		}
	}

	// Archive before deleting, and moves to cold storage and compaction
	// of what is kept.
	var coldWaits []string
	for _, e := range ents {
		if e.Category == "" {
			continue
		}
		pol, _ := s.For(e.Category)
		wantsCold := e.Action == ActionKeep && !e.restored && !e.hold && !e.cold && pol.ColdAfterDays > 0 &&
			e.age > pol.ColdAfterDays && !e.dayT.After(today)
		if wantsCold && !snap.Cold.Ready() && !slices.Contains(coldWaits, e.Category) {
			coldWaits = append(coldWaits, e.Category)
		}
		switch {
		case e.snapshotOnly:
			// Nothing to archive from; a day due to be archived is
			// mounted first (above) only while it is within keep_days.
		case e.Removes() && pol.Archive:
			switch n := archivedCopy(e.info, snap.Archives[e.Index]); {
			case n >= 0:
				e.Reason += " (already archived)"
				e.verify, e.archived = true, n
			case e.Docs == 0:
				// Nothing to archive, as far as OpenSearch has refreshed;
				// the run checks again before deleting.
				e.verify = true
			default:
				e.Action = ActionArchive
			}
		case wantsCold && snap.Cold.Ready():
			e.Action, e.Rule = ActionCold, RuleCold
			e.Reason = fmt.Sprintf("Older than %s", days(pol.ColdAfterDays))
		case e.Action == ActionKeep && !e.restored && !e.hold && !e.compacted && !e.diskBlocked && pol.CompactAfterDays > 0 &&
			e.age > pol.CompactAfterDays && !e.dayT.After(today):
			e.Action, e.Rule = ActionCompact, RuleCompact
			e.Reason = fmt.Sprintf("Older than %s", days(pol.CompactAfterDays))
		}
	}
	if len(coldWaits) > 0 {
		names := make([]string, len(coldWaits))
		for i, id := range coldWaits {
			c, _ := CategoryByID(id)
			names[i] = c.Name
		}
		plan.Notes = append(plan.Notes, fmt.Sprintf("Days of %s are due to move to cold storage, but %s, so they stay on the nodes' disks.",
			strings.Join(names, ", "), snap.Cold.Missing(snap.Prefix)))
	}
	plan.Decisions = make([]Decision, len(ents))
	for i, e := range ents {
		plan.Decisions[i] = e.Decision
	}
	return plan
}

// oldestDays says "the oldest day" or "the oldest 3 days".
func oldestDays(n int) string {
	if n == 1 {
		return "the oldest day"
	}
	return fmt.Sprintf("the oldest %d days", n)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func days(n int) string {
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

func gbString(gb float64) string {
	if gb == float64(int64(gb)) {
		return fmt.Sprintf("%d GB", int64(gb))
	}
	return fmt.Sprintf("%g GB", gb)
}
