package retention

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// Cluster is what retention needs from OpenSearch. OpenSearch implements
// it over the REST API and Memory implements it for tests and demos.
type Cluster interface {
	// Indices lists the open indices matching a pattern with their size
	// and state. A pattern that matches nothing returns no indices.
	Indices(ctx context.Context, pattern string) ([]IndexInfo, error)
	// Disk returns the use of the fullest data disk in the cluster.
	Disk(ctx context.Context) (*Disk, error)

	// BlockWrites makes an index read-only (block) or writable again.
	BlockWrites(ctx context.Context, index string, block bool) error
	// ForceMerge merges an index into one segment and waits until it is done.
	ForceMerge(ctx context.Context, index string) error
	// DeleteIndex deletes an index; one that is already gone is not an error.
	DeleteIndex(ctx context.Context, index string) error
	// Count returns how many documents an index holds.
	Count(ctx context.Context, index string) (int64, error)
	// Export calls fn with every document of an index, a page at a time,
	// so memory use does not grow with the index.
	Export(ctx context.Context, index string, fn func(Doc) error) error

	// NodeBytes returns how many bytes each index matching a pattern
	// holds on one node, counting every shard copy there. The disk guard
	// uses it to know what deleting an index frees on the fullest disk.
	NodeBytes(ctx context.Context, pattern, node string) (map[string]int64, error)

	// CreateIndex creates an index unless it exists; the index template
	// supplies its settings and mappings.
	CreateIndex(ctx context.Context, index string) error
	// MarkRestored records on the index that it was restored from the
	// archive and is kept until the day given (YYYY-MM-DD), and which
	// archives it was restored from.
	MarkRestored(ctx context.Context, index, until string, from []string) error
	// Import writes documents to an index, keeping their IDs, so importing
	// the same documents twice does not duplicate them.
	Import(ctx context.Context, index string, docs []Doc) error
	// Refresh makes imported documents searchable.
	Refresh(ctx context.Context, index string) error

	// CountClosed counts resolved and closed records (findings or cases)
	// last changed before a time, leaving out findings in the given cases.
	CountClosed(ctx context.Context, index string, before time.Time, keepCases []string) (int64, error)
	// DeleteClosed deletes what CountClosed counts and returns how many.
	DeleteClosed(ctx context.Context, index string, before time.Time, keepCases []string) (int64, error)
	// CaseIDs lists the IDs of every case, open or closed. A missing index
	// has none.
	CaseIDs(ctx context.Context, index string) ([]string, error)
	// RecordRange returns when the oldest and newest records were created;
	// both are zero for an empty or missing index.
	RecordRange(ctx context.Context, index string) (oldest, newest time.Time, err error)
}

// IndexInfo describes one index.
type IndexInfo struct {
	Name string `json:"index"`
	// UUID tells apart indices of the same name, such as a day deleted
	// and then created again by events that arrived late.
	UUID string `json:"uuid,omitempty"`
	// Health is green, yellow or red. A red index has a primary shard
	// that is not available, so its size and document count are unknown.
	Health string `json:"health,omitempty"`
	// Unavailable is true when OpenSearch cannot report the index's
	// documents (a red index); retention then leaves it alone.
	Unavailable bool `json:"unavailable,omitempty"`
	// Bytes is the size on disk of every copy; PrimaryBytes of the
	// primary shards only.
	Bytes        int64 `json:"bytes"`
	PrimaryBytes int64 `json:"primary_bytes"`
	Docs         int64 `json:"docs"`
	// Segments counts the segments of every copy and Copies the shard
	// copies (primaries times one plus replicas).
	Segments int `json:"segments"`
	Copies   int `json:"copies"`
	// WriteBlocked is true when the index is read-only.
	WriteBlocked bool `json:"write_blocked"`
	// DiskBlocked is true when OpenSearch made the index read-only because
	// its disk passed the flood-stage watermark, which stops ingest.
	DiskBlocked bool `json:"disk_blocked"`
	// RestoredUntil is the day (YYYY-MM-DD) a restored index is kept
	// until; empty for indices that were not restored.
	RestoredUntil string `json:"restored_until,omitempty"`
	// RestoredFrom lists the archives (IDs) restored into the index.
	RestoredFrom []string `json:"restored_from,omitempty"`
}

// Compacted reports whether an index is read-only and merged into one
// segment per shard copy.
func (ix IndexInfo) Compacted() bool {
	return ix.WriteBlocked && ix.Segments > 0 && ix.Segments <= max(ix.Copies, 1)
}

// Disk is the use of one data disk.
type Disk struct {
	Node      string `json:"node"`
	Path      string `json:"path,omitempty"`
	Total     int64  `json:"total_bytes"`
	Available int64  `json:"available_bytes"`
}

// Used returns the bytes in use, as OpenSearch counts them: everything
// that is not available to it.
func (d Disk) Used() int64 { return d.Total - d.Available }

// Percent returns the disk use in percent, the number OpenSearch compares
// with its disk watermarks.
func (d Disk) Percent() float64 {
	if d.Total <= 0 {
		return 0
	}
	return float64(d.Used()) * 100 / float64(d.Total)
}

// MarshalJSON adds the used bytes and percent.
func (d Disk) MarshalJSON() ([]byte, error) {
	type plain Disk
	return json.Marshal(struct {
		plain
		Used    int64   `json:"used_bytes"`
		Percent float64 `json:"percent"`
	}{plain(d), d.Used(), roundPercent(d.Percent())})
}

func roundPercent(p float64) float64 { return float64(int(p*10+0.5)) / 10 }

// Doc is one document as it is archived: its ID and source.
type Doc struct {
	ID     string          `json:"_id"`
	Source json.RawMessage `json:"_source"`
}

// dayLayout is the date suffix of daily index names.
const dayLayout = "2006.01.02"

// ParseIndex splits a daily event index name, <prefix>-<category>-
// YYYY.MM.DD, into its category and day. It reports false for every other
// name, including indices of other prefixes and unknown categories, which
// retention never touches.
//
// It also accepts the monthly indices of KindMonthly categories,
// <prefix>_<category>-YYYY.MM, whose day is the first of the month.
func ParseIndex(prefix, name string) (category string, day time.Time, ok bool) {
	if rest, ok := strings.CutPrefix(name, prefix+"_"); ok {
		return parseMonthly(rest)
	}
	rest, ok := strings.CutPrefix(name, prefix+"-")
	if !ok || len(rest) < len(dayLayout)+2 || rest[len(rest)-len(dayLayout)-1] != '-' {
		return "", time.Time{}, false
	}
	ds := rest[len(rest)-len(dayLayout):]
	category = rest[:len(rest)-len(dayLayout)-1]
	if c, found := CategoryByID(category); !found || c.Kind != KindEvents {
		return "", time.Time{}, false
	}
	day, err := time.Parse(dayLayout, ds)
	if err != nil || day.Format(dayLayout) != ds {
		return "", time.Time{}, false
	}
	return category, day, true
}

// monthLayout is the date suffix of monthly index names.
const monthLayout = "2006.01"

// parseMonthly splits <category>-YYYY.MM of a KindMonthly category.
func parseMonthly(rest string) (string, time.Time, bool) {
	if len(rest) < len(monthLayout)+2 || rest[len(rest)-len(monthLayout)-1] != '-' {
		return "", time.Time{}, false
	}
	ms := rest[len(rest)-len(monthLayout):]
	category := rest[:len(rest)-len(monthLayout)-1]
	if c, found := CategoryByID(category); !found || c.Kind != KindMonthly {
		return "", time.Time{}, false
	}
	day, err := time.Parse(monthLayout, ms)
	if err != nil || day.Format(monthLayout) != ms {
		return "", time.Time{}, false
	}
	return category, day, true
}

// MonthlyIndexName returns the monthly index of a KindMonthly category
// that holds t: <prefix>_<category>-YYYY.MM.
func MonthlyIndexName(prefix, category string, t time.Time) string {
	return prefix + "_" + category + "-" + t.UTC().Format(monthLayout)
}

// monthEnd is the last day of the month that starts on day.
func monthEnd(day time.Time) time.Time { return day.AddDate(0, 1, -1) }

// IndexName returns the daily index of a category, as ingest names it.
func IndexName(prefix, category string, day time.Time) string {
	return prefix + "-" + category + "-" + day.UTC().Format(dayLayout)
}

// RecordIndex returns the single index of findings, cases or threat intel.
func RecordIndex(prefix, category string) string {
	return prefix + "_" + category
}
