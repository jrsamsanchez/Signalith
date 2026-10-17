package retention

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
)

// Memory is an in-memory Cluster for tests and evaluation. Disk use is
// DiskBase plus the size of every index, so deleting indices frees disk.
type Memory struct {
	mu      sync.Mutex
	indices map[string]*memIndex
	records map[string][]Record
	uuids   int

	DiskTotal int64
	DiskBase  int64
	// Fail makes an operation fail: keys are "op index", for example
	// "export signalith-endpoint-2026.07.01" or "disk".
	Fail map[string]error
	// Calls records state-changing calls, such as "delete <index>".
	Calls []string
	// OnExport, when set, runs before each exported document.
	OnExport func(index string, n int)
	// ColdRepo names the registered cold storage repository (empty: none
	// is registered), and ColdMountable says whether a node can mount
	// searchable snapshots.
	ColdRepo      string
	ColdMountable bool
	snapshots     map[string]memSnapshot
}

// memSnapshot is a snapshot of one index.
type memSnapshot struct {
	info IndexInfo
	docs []Doc
}

type memIndex struct {
	info IndexInfo
	docs []Doc
	// unrefreshed documents are written but not searchable yet: counts
	// and exports miss them until a refresh, as in OpenSearch.
	unrefreshed []Doc
}

// Record is a finding or case as Memory stores it.
type Record struct {
	ID      string
	Status  string
	Updated time.Time
	Created time.Time
	CaseID  string
}

// NewMemory returns an empty cluster with a 1 TB disk.
func NewMemory() *Memory {
	return &Memory{indices: map[string]*memIndex{}, records: map[string][]Record{}, DiskTotal: 1 << 40, Fail: map[string]error{},
		snapshots: map[string]memSnapshot{}}
}

// AddIndex adds an index of a given size with docs documents, replacing
// any index of the same name.
func (m *Memory) AddIndex(name string, bytes int64, docs ...Doc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.indices[name] = &memIndex{info: IndexInfo{Name: name, UUID: m.uuid(), Health: "green", Bytes: bytes, PrimaryBytes: bytes,
		Docs: int64(len(docs)), Segments: 5, Copies: 1}, docs: slices.Clone(docs)}
}

// uuid returns a new index UUID; the caller holds m.mu.
func (m *Memory) uuid() string {
	m.uuids++
	return fmt.Sprintf("mem-%06d", m.uuids)
}

// AddUnrefreshed writes documents that searches, counts and exports
// only see after the next refresh.
func (m *Memory) AddUnrefreshed(name string, docs ...Doc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ix, ok := m.indices[name]; ok {
		ix.unrefreshed = append(ix.unrefreshed, docs...)
	}
}

// AddDocs adds documents to an index, as late events would.
func (m *Memory) AddDocs(name string, docs ...Doc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ix, ok := m.indices[name]; ok {
		ix.docs = append(ix.docs, docs...)
		ix.info.Docs = int64(len(ix.docs))
	}
}

// SetIndex changes an index's info; the name and documents stay.
func (m *Memory) SetIndex(name string, change func(*IndexInfo)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ix, ok := m.indices[name]; ok {
		change(&ix.info)
		ix.info.Name = name
		if ix.info.UUID == "" {
			ix.info.UUID = m.uuid()
		}
	}
}

// Index returns an index's info and documents.
func (m *Memory) Index(name string) (IndexInfo, []Doc, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ix, ok := m.indices[name]
	if !ok {
		return IndexInfo{}, nil, false
	}
	return ix.info, slices.Clone(ix.docs), true
}

// AddRecords adds findings or cases to a records index.
func (m *Memory) AddRecords(index string, recs ...Record) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[index] = append(m.records[index], recs...)
}

// Records returns the records of an index.
func (m *Memory) Records(index string) []Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.records[index])
}

func (m *Memory) fail(op, index string) error {
	if err := m.Fail[strings.TrimSpace(op+" "+index)]; err != nil {
		return err
	}
	return nil
}

func (m *Memory) call(op, index string) { m.Calls = append(m.Calls, op+" "+index) }

func (m *Memory) Indices(_ context.Context, pattern string) ([]IndexInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("indices", ""); err != nil {
		return nil, err
	}
	var out []IndexInfo
	for name, ix := range m.indices {
		for _, p := range strings.Split(pattern, ",") {
			if ok, _ := path.Match(p, name); ok {
				out = append(out, ix.info)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) Disk(context.Context) (*Disk, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("disk", ""); err != nil {
		return nil, err
	}
	used := m.DiskBase
	for _, ix := range m.indices {
		if ix.info.Cold == nil {
			used += ix.info.Bytes
		}
	}
	return &Disk{Node: "memory", Total: m.DiskTotal, Available: max(m.DiskTotal-used, 0)}, nil
}

// NodeBytes treats the cluster as one node that holds every index.
func (m *Memory) NodeBytes(_ context.Context, pattern, node string) (map[string]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("nodebytes", ""); err != nil {
		return nil, err
	}
	out := map[string]int64{}
	if node != "memory" {
		return out, nil
	}
	for name, ix := range m.indices {
		for _, p := range strings.Split(pattern, ",") {
			if ok, _ := path.Match(p, name); ok && ix.info.Cold == nil {
				out[name] = ix.info.Bytes
				break
			}
		}
	}
	return out, nil
}

func (m *Memory) get(index string) (*memIndex, error) {
	ix, ok := m.indices[index]
	if !ok {
		return nil, fmt.Errorf("no such index [%s]", index)
	}
	return ix, nil
}

func (m *Memory) BlockWrites(_ context.Context, index string, block bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("block", index); err != nil {
		return err
	}
	ix, err := m.get(index)
	if err != nil {
		return err
	}
	if ix.info.DiskBlocked {
		return errFloodStage(index)
	}
	ix.info.WriteBlocked = block
	m.call(fmt.Sprintf("block=%v", block), index)
	return nil
}

// errFloodStage is what OpenSearch answers when a setting change or merge
// meets its flood-stage block.
func errFloodStage(index string) error {
	return fmt.Errorf("cluster_block_exception: index [%s] blocked by: [TOO_MANY_REQUESTS/12/disk usage exceeded flood-stage watermark, index has read-only-allow-delete block]", index)
}

func (m *Memory) ForceMerge(_ context.Context, index string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("forcemerge", index); err != nil {
		return err
	}
	ix, err := m.get(index)
	if err != nil {
		return err
	}
	if ix.info.DiskBlocked {
		return errFloodStage(index)
	}
	ix.info.Segments = max(ix.info.Copies, 1)
	// Merging saves some space.
	ix.info.Bytes -= ix.info.Bytes / 10
	ix.info.PrimaryBytes = ix.info.Bytes
	m.call("forcemerge", index)
	return nil
}

func (m *Memory) DeleteIndex(_ context.Context, index string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("delete", index); err != nil {
		return err
	}
	delete(m.indices, index)
	m.call("delete", index)
	return nil
}

func (m *Memory) Count(_ context.Context, index string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ix, err := m.get(index)
	if err != nil {
		return 0, err
	}
	return int64(len(ix.docs)), nil
}

func (m *Memory) Export(ctx context.Context, index string, fn func(Doc) error) error {
	m.mu.Lock()
	if err := m.fail("export", index); err != nil {
		m.mu.Unlock()
		return err
	}
	ix, err := m.get(index)
	var docs []Doc
	if err == nil {
		docs = slices.Clone(ix.docs)
	}
	hook := m.OnExport
	m.mu.Unlock()
	if err != nil {
		return err
	}
	for i, d := range docs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if hook != nil {
			hook(index, i)
		}
		if err := fn(d); err != nil {
			return err
		}
	}
	return nil
}

func (m *Memory) CreateIndex(_ context.Context, index string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.indices[index]; !ok {
		m.indices[index] = &memIndex{info: IndexInfo{Name: index, UUID: m.uuid(), Health: "green", Segments: 1, Copies: 1}}
		m.call("create", index)
	}
	return nil
}

func (m *Memory) MarkRestored(_ context.Context, index, until string, from []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ix, err := m.get(index)
	if err != nil {
		return err
	}
	ix.info.RestoredUntil, ix.info.RestoredFrom = until, slices.Clone(from)
	return nil
}

func (m *Memory) Import(_ context.Context, index string, docs []Doc) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("import", index); err != nil {
		return err
	}
	ix, err := m.get(index)
	if err != nil {
		return err
	}
	if ix.info.WriteBlocked || ix.info.DiskBlocked {
		return errors.New("index is read-only")
	}
	for _, d := range docs {
		i := slices.IndexFunc(ix.docs, func(x Doc) bool { return x.ID == d.ID })
		if i >= 0 {
			ix.docs[i] = d
		} else {
			ix.docs = append(ix.docs, d)
			ix.info.Bytes += int64(len(d.Source))
		}
	}
	ix.info.Docs = int64(len(ix.docs))
	ix.info.PrimaryBytes = ix.info.Bytes
	return nil
}

func (m *Memory) Refresh(_ context.Context, index string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("refresh", index); err != nil {
		return err
	}
	if ix, ok := m.indices[index]; ok && len(ix.unrefreshed) > 0 {
		ix.docs = append(ix.docs, ix.unrefreshed...)
		ix.unrefreshed = nil
		ix.info.Docs = int64(len(ix.docs))
	}
	m.call("refresh", index)
	return nil
}

func closed(r Record, before time.Time, keep []string) bool {
	return (r.Status == findings.StatusResolved || r.Status == findings.StatusClosed) &&
		r.Updated.Before(before) && (r.CaseID == "" || !slices.Contains(keep, r.CaseID))
}

func (m *Memory) CountClosed(_ context.Context, index string, before time.Time, keep []string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for _, r := range m.records[index] {
		if closed(r, before, keep) {
			n++
		}
	}
	return n, nil
}

func (m *Memory) DeleteClosed(_ context.Context, index string, before time.Time, keep []string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("delete_closed", index); err != nil {
		return 0, err
	}
	n := len(m.records[index])
	m.records[index] = slices.DeleteFunc(m.records[index], func(r Record) bool { return closed(r, before, keep) })
	m.call("delete_closed", index)
	return int64(n - len(m.records[index])), nil
}

func (m *Memory) CaseIDs(_ context.Context, index string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("caseids", index); err != nil {
		return nil, err
	}
	var ids []string
	for _, r := range m.records[index] {
		ids = append(ids, r.ID)
	}
	return ids, nil
}

func (m *Memory) RecordRange(_ context.Context, index string) (time.Time, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var lo, hi time.Time
	for _, r := range m.records[index] {
		if lo.IsZero() || r.Created.Before(lo) {
			lo = r.Created
		}
		if r.Created.After(hi) {
			hi = r.Created
		}
	}
	return lo, hi, nil
}

// Snapshots lists the snapshot names in the cold storage repository.
func (m *Memory) Snapshots() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := slices.Collect(maps.Keys(m.snapshots))
	slices.Sort(out)
	return out
}

func (m *Memory) ColdState(_ context.Context, repo, prefix string) (*ColdState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("coldstate", ""); err != nil {
		return nil, err
	}
	st := &ColdState{Repository: repo, Registered: m.ColdRepo == repo && repo != "", Mountable: m.ColdMountable}
	if !st.Registered {
		return st, nil
	}
	st.Type = "fs"
	for name, sn := range m.snapshots {
		if strings.HasPrefix(name, prefix+"-") {
			st.Snapshots = append(st.Snapshots, ColdSnapshot{Name: name, Index: sn.info.Name})
		}
	}
	sort.Slice(st.Snapshots, func(i, j int) bool { return st.Snapshots[i].Name < st.Snapshots[j].Name })
	return st, nil
}

func (m *Memory) SnapshotIndex(_ context.Context, repo, name, index string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("snapshot", index); err != nil {
		return err
	}
	if repo != m.ColdRepo || repo == "" {
		return fmt.Errorf("[%s] missing", repo)
	}
	if _, ok := m.snapshots[name]; ok {
		return fmt.Errorf("[%s:%s] a snapshot with the same name already exists", repo, name)
	}
	ix, err := m.get(index)
	if err != nil {
		return err
	}
	m.snapshots[name] = memSnapshot{info: ix.info, docs: slices.Clone(ix.docs)}
	m.call("snapshot", index)
	return nil
}

func (m *Memory) MountSnapshot(_ context.Context, repo, name, index string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("mount", index); err != nil {
		return err
	}
	sn, ok := m.snapshots[name]
	if !ok || repo != m.ColdRepo {
		return fmt.Errorf("[%s:%s] is missing", repo, name)
	}
	if _, ok := m.indices[index]; ok {
		return fmt.Errorf("cannot restore index [%s] because an open index with same name already exists in the cluster", index)
	}
	info := sn.info
	info.UUID, info.WriteBlocked, info.Copies = m.uuid(), true, 1
	info.Cold = &ColdRef{Repository: repo, Snapshot: name}
	m.indices[index] = &memIndex{info: info, docs: slices.Clone(sn.docs)}
	m.call("mount", index)
	return nil
}

func (m *Memory) DeleteSnapshot(_ context.Context, repo, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("deletesnapshot", name); err != nil {
		return err
	}
	for _, ix := range m.indices {
		if ix.info.Cold != nil && ix.info.Cold.Snapshot == name {
			return fmt.Errorf("[%s:[%s]] These remote snapshots are backing some indices and hence can't be deleted!", repo, name)
		}
	}
	delete(m.snapshots, name)
	m.call("deletesnapshot", name)
	return nil
}
