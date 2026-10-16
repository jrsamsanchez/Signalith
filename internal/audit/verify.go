package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultVerifyLimit is the most records Verify reads when the query sets
// no limit.
const DefaultVerifyLimit = 2_000_000

// maxProblems is the most problems a Report lists; its counts count them
// all.
const maxProblems = 100

// verifyMargin is how far past the range's ends Verify reads. A server
// may log two records at once, the later one first, so the record before
// one in its chain can be a little later; the records in the margin are
// used for the links of those in the range, and not counted themselves.
const verifyMargin = time.Minute

// VerifyQuery selects the records Verify checks.
type VerifyQuery struct {
	// From and To bound the records' time (From included, To not).
	From, To time.Time
	// Server, when set, checks that server's records only.
	Server string
	// Limit is the most records read (DefaultVerifyLimit when 0).
	Limit int
}

// Report is what Verify found. A record is OK when its MAC checks out
// with the key it names and it links to the record before it. The other
// counts say what is wrong, or only worth knowing: Edited, Stripped,
// Broken, Missing and Truncated mean records were changed, put in or
// removed; Unsigned, UnknownKey, Dropped, Unverifiable, Restarts and
// Continued do not.
type Report struct {
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Server string `json:"server,omitempty"`
	// Records counts the records read.
	Records int64 `json:"records"`
	OK      int64 `json:"ok"`
	// Unsigned counts records without a MAC: written before the records
	// were chained, imported, or written while the server had no cluster
	// key. Those in a chain are still linked, so removing one shows.
	Unsigned int64 `json:"unsigned"`
	// UnknownKey counts records signed with a key this server does not
	// hold, such as one retired before it joined; their links are still
	// checked.
	UnknownKey int64 `json:"unknown_key"`
	// Edited counts records whose MAC does not check out, or that differ
	// from what a checkpoint saw: changed after they were written.
	Edited int64 `json:"edited"`
	// Stripped counts records with no MAC, or one made with a key this
	// server does not hold, written after their server signed its records
	// with a key it holds (by time, or by place in their chain): a server
	// that signs keeps signing, so their MAC was removed or replaced, or
	// they were put in. Neither the chain's links nor a key-less MAC can
	// vouch for them, as anyone can make those.
	Stripped int64 `json:"stripped"`
	// Broken counts records that do not link to the record before them:
	// that one was changed, or one was put in between.
	Broken int64 `json:"broken"`
	// Missing counts records absent from a chain that no audit.lost
	// record names: removed. Dropped counts those an audit.lost record
	// names (the spool was full, or OpenSearch refused them).
	Missing int64 `json:"missing"`
	Dropped int64 `json:"dropped"`
	// Unverifiable counts records absent from a chain that only an
	// unsigned audit.lost record names, in a part of the chain that is
	// not signed either (written before the server had a cluster key, or
	// checked without the key): a drop cannot be told from a removal
	// there. Only a signed audit.lost record counts a gap between signed
	// records as dropped.
	Unverifiable int64 `json:"unverifiable"`
	// Truncated counts chains whose latest records an audit.checkpoint
	// record saw are gone: the end of a server's records was removed.
	Truncated int64 `json:"truncated"`
	// Restarts counts chains started: a server's first record, or the
	// first after it lost its spool folder. Continued counts chains whose
	// first record is before the records read (the range starts later, or
	// retention deleted it).
	Restarts  int64 `json:"restarts"`
	Continued int64 `json:"continued"`
	// Checkpoints counts the audit.checkpoint records read.
	Checkpoints int64 `json:"checkpoints"`
	// Limited is set when there were more records than the limit; the
	// newest were not read.
	Limited  bool           `json:"limited,omitempty"`
	Servers  []ServerReport `json:"servers"`
	Problems []Problem      `json:"problems"`
}

// Tampered reports whether records were changed or removed.
func (r *Report) Tampered() bool { return r.Edited+r.Stripped+r.Broken+r.Missing+r.Truncated > 0 }

// ServerReport is one server's part of a Report.
type ServerReport struct {
	Server   string    `json:"server"`
	NodeID   string    `json:"node_id"`
	Records  int64     `json:"records"`
	OK       int64     `json:"ok"`
	Problems int64     `json:"problems"`
	Chains   int       `json:"chains"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
}

// Problem is one record found changed, or one place where records are
// missing.
type Problem struct {
	Kind   string    `json:"kind"`
	Time   time.Time `json:"time"`
	Server string    `json:"server,omitempty"`
	NodeID string    `json:"node_id"`
	Chain  string    `json:"chain,omitempty"`
	Seq    int64     `json:"seq"`
	ID     string    `json:"id,omitempty"`
	Index  string    `json:"index,omitempty"`
	Detail string    `json:"detail"`
}

// Kinds of Problem.
const (
	ProblemEdited    = "edited"
	ProblemStripped  = "stripped"
	ProblemBroken    = "broken"
	ProblemMissing   = "missing"
	ProblemTruncated = "truncated"
)

// Verify reads the audit records q selects and checks their chains: the
// MAC of each record with the key it names (keys, nil when this server
// holds none), its link to the record before it, the gaps between them
// against the audit.lost records, and the latest records the
// audit.checkpoint records saw. With no audit index yet, the report is
// empty.
func Verify(ctx context.Context, c Searcher, prefix string, q VerifyQuery, keys KeyFunc) (*Report, error) {
	read := q
	if !read.From.IsZero() {
		read.From = read.From.Add(-verifyMargin)
	}
	if !read.To.IsZero() {
		read.To = read.To.Add(verifyMargin)
	}
	hits, limited, err := readAll(ctx, c, prefix, read)
	if err != nil {
		return nil, err
	}
	if limited && len(hits) > 0 {
		// The range ends where the records read do, less the margin.
		q.To = hits[len(hits)-1].Time.Add(-verifyMargin)
	}
	r := Check(hits, q, keys)
	r.Limited = limited
	return r, nil
}

// readAll reads the records q selects, oldest first. With q.Server set it
// also reads every server's audit.checkpoint records, which say what that
// server's records were.
func readAll(ctx context.Context, c Searcher, prefix string, q VerifyQuery) ([]Hit, bool, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultVerifyLimit
	}
	f := filters(Query{From: q.From, To: q.To})
	if q.Server != "" {
		f = append(f, map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": []any{
			map[string]any{"term": map[string]any{"server": q.Server}},
			map[string]any{"term": map[string]any{"action": ActionCheckpoint}},
		}}})
	}
	var out []Hit
	var after []any
	for {
		size := min(1000, limit-len(out)+1)
		body := map[string]any{
			"query": map[string]any{"bool": map[string]any{"filter": f}},
			"size":  size,
			"sort":  []any{map[string]any{"@timestamp": "asc"}, map[string]any{"node_id": "asc"}, map[string]any{"seq": "asc"}},
		}
		if after != nil {
			body["search_after"] = after
		}
		res, err := c.Search(ctx, Pattern(prefix), body)
		if missing(err) {
			return out, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		var page struct {
			Hits struct {
				Hits []struct {
					Index  string          `json:"_index"`
					ID     string          `json:"_id"`
					Source json.RawMessage `json:"_source"`
					Sort   []any           `json:"sort"`
				} `json:"hits"`
			} `json:"hits"`
		}
		if err := remarshal(res, &page); err != nil {
			return nil, false, fmt.Errorf("audit verify: %w", err)
		}
		for _, h := range page.Hits.Hits {
			var ev Event
			if err := json.Unmarshal(h.Source, &ev); err != nil {
				return nil, false, fmt.Errorf("audit verify: record %s: %w", h.ID, err)
			}
			if len(out) == limit {
				return out, true, nil
			}
			out = append(out, Hit{Event: ev, ID: h.ID, Index: h.Index})
		}
		if len(page.Hits.Hits) < size {
			return out, false, nil
		}
		after = page.Hits.Hits[len(page.Hits.Hits)-1].Sort
	}
}

// chainKey names one chain of one server.
type chainKey struct{ node, chain string }

// checked is one record as Check sees it.
type checked struct {
	hit    *Hit
	hash   string
	macOK  bool
	edited bool
	// unsigned and unknown say the record has no MAC, or one made with a
	// key this server does not hold.
	unsigned, unknown bool
	// broken is set when the record does not follow the one before it.
	broken bool
}

// headRef is what an audit.checkpoint record says of a server's latest
// record.
type headRef struct {
	chainKey
	seq    int64
	hash   string
	at     time.Time
	server string
}

// Check checks records read from OpenSearch, as Verify does. Records
// outside q's range are used for the links of those inside it, and
// neither counted nor reported.
func Check(hits []Hit, q VerifyQuery, keys KeyFunc) *Report {
	r := &Report{Server: q.Server, Servers: []ServerReport{}, Problems: []Problem{}}
	if !q.From.IsZero() {
		r.From = q.From.UTC().Format(time.RFC3339)
	}
	if !q.To.IsZero() {
		r.To = q.To.UTC().Format(time.RFC3339)
	}
	servers := map[string]*ServerReport{}
	server := func(h *Hit) *ServerReport {
		s := servers[h.NodeID]
		if s == nil {
			s = &ServerReport{NodeID: h.NodeID, First: h.Time}
			servers[h.NodeID] = s
		}
		if h.Server != "" {
			s.Server = h.Server
		}
		s.Records++
		if h.Time.Before(s.First) {
			s.First = h.Time
		}
		if h.Time.After(s.Last) {
			s.Last = h.Time
		}
		return s
	}
	in := func(t time.Time) bool {
		return (q.From.IsZero() || !t.Before(q.From)) && (q.To.IsZero() || t.Before(q.To))
	}
	problem := func(kind string, c *checked, detail string) {
		if !in(c.hit.Time) {
			return
		}
		if s := servers[c.hit.NodeID]; s != nil {
			s.Problems++
		}
		if len(r.Problems) < maxProblems {
			r.Problems = append(r.Problems, Problem{Kind: kind, Time: c.hit.Time, Server: c.hit.Server, NodeID: c.hit.NodeID,
				Chain: c.hit.Chain, Seq: c.hit.Seq, ID: c.hit.ID, Index: c.hit.Index, Detail: detail})
		}
	}

	// Each record's MAC first, for when each server started signing its
	// records with a key this server holds.
	all := make([]*checked, len(hits))
	signedFrom := map[string]time.Time{}
	for i := range hits {
		h := &hits[i]
		c := &checked{hit: h}
		var key []byte
		if keys != nil && h.MAC != "" {
			key = keys(h.KID)
		}
		switch {
		case h.MAC == "":
			c.unsigned = true
		case key == nil:
			c.unknown = true
		case h.checkMAC(key):
			c.macOK = true
			if t, ok := signedFrom[h.NodeID]; !ok || h.Time.Before(t) {
				signedFrom[h.NodeID] = h.Time
			}
		default:
			c.edited = true
		}
		all[i] = c
	}
	// stripped counts c, which has no MAC this server can check although
	// its server signed records before it, as a record whose MAC was
	// removed or replaced, or that was put in.
	stripped := func(c *checked, why string) {
		c.edited = true
		if !in(c.hit.Time) {
			return
		}
		if c.unsigned {
			r.Unsigned--
		} else {
			r.UnknownKey--
		}
		r.Stripped++
		problem(ProblemStripped, c, why)
	}

	chains := map[chainKey][]*checked{}
	counted := map[chainKey]bool{}
	// lost holds the runs signed audit.lost records name; unsure those
	// of unsigned ones, which anyone could have written.
	lost := map[chainKey][]lostRange{}
	unsure := map[chainKey][]lostRange{}
	var heads []headRef
	for i := range hits {
		h := &hits[i]
		c := all[i]
		inside := in(h.Time)
		if h.Action == ActionCheckpoint {
			if inside {
				r.Checkpoints++
			}
			// Only a signed checkpoint says what a server's records were:
			// anyone could write an unsigned one.
			if c.macOK {
				heads = append(heads, parseHeads(h)...)
			}
		}
		if q.Server != "" && h.Server != q.Server {
			// Another server's checkpoint, read for what it saw.
			continue
		}
		var s *ServerReport
		if inside {
			r.Records++
			s = server(h)
		}
		switch {
		case c.edited:
			if inside {
				r.Edited++
			}
			problem(ProblemEdited, c, "the record was changed: its MAC does not match its contents")
		case c.unsigned || c.unknown:
			if inside {
				if c.unsigned {
					r.Unsigned++
				} else {
					r.UnknownKey++
				}
			}
			// A record logged as its server got its key may be dated a
			// little after its first signed one (see verifyMargin): its
			// place in its chain says more, checked below.
			if t, ok := signedFrom[h.NodeID]; ok && h.Time.After(t.Add(verifyMargin)) {
				stripped(c, "the record is not signed with a key this server holds, though its server signed its records from "+
					t.UTC().Format(time.RFC3339)+": its MAC was removed or replaced, or the record was put in")
			}
		}
		if h.Chain == "" {
			continue
		}
		c.hash = h.Hash()
		k := chainKey{h.NodeID, h.Chain}
		if s != nil && !counted[k] {
			counted[k] = true
			s.Chains++
		}
		chains[k] = append(chains[k], c)
		if h.Action == ActionLost && !c.edited {
			if lr, ok := parseLost(h); ok {
				lk := chainKey{h.NodeID, lr.chain}
				if c.macOK {
					lost[lk] = append(lost[lk], lr)
				} else {
					unsure[lk] = append(unsure[lk], lr)
				}
			}
		}
	}

	for k, list := range chains {
		sort.SliceStable(list, func(i, j int) bool { return list[i].hit.Seq < list[j].hit.Seq })
		// gap returns how many of the records from to to before c audit.lost
		// records name: signed ones (dropped), and, where c is not signed
		// either, unsigned ones (unverifiable); and the run that ends at
		// to. Between signed records only a signed audit.lost record
		// counts, as anyone could write an unsigned one.
		gap := func(c *checked, from, to int64) (dropped, unverifiable int64, last *lostRange) {
			dropped, last = covers(lost[k], from, to)
			if c.macOK || len(unsure[k]) == 0 {
				return dropped, 0, last
			}
			n, lastAll := covers(append(append([]lostRange{}, lost[k]...), unsure[k]...), from, to)
			if last == nil {
				last = lastAll
			}
			return dropped, n - dropped, last
		}
		var p *checked
		signed := false
		for _, c := range list {
			h := c.hit
			inside := in(h.Time)
			count := func(n *int64, by int64) {
				if inside {
					*n += by
				}
			}
			// A server that signs keeps signing: a record after a signed
			// one in its chain has a MAC this server can check.
			if signed && (c.unsigned || c.unknown) && !c.edited {
				stripped(c, "the record is not signed with a key this server holds, though the record before it in its chain is: "+
					"its MAC was removed or replaced, or the record was put in")
			}
			signed = signed || c.macOK
			linked := true
			switch {
			case p == nil:
				// A chain whose first records the spool dropped started
				// all the same.
				dropped, unverifiable, _ := gap(c, 1, h.Seq-1)
				covered := dropped + unverifiable
				count(&r.Dropped, dropped)
				count(&r.Unverifiable, unverifiable)
				if h.ChainStart && h.Seq == 1 && h.Prev == "" || h.Seq > 1 && covered == h.Seq-1 {
					count(&r.Restarts, 1)
				} else {
					count(&r.Continued, 1)
				}
			case h.Seq == p.hit.Seq:
				if c.hash == p.hash {
					// The same record twice, such as in two indices.
					continue
				}
				linked = false
				count(&r.Broken, 1)
				problem(ProblemBroken, c, "two different records have this sequence number: one was put in")
			case h.Seq > p.hit.Seq+1:
				from, to := p.hit.Seq+1, h.Seq-1
				dropped, unverifiable, last := gap(c, from, to)
				covered := dropped + unverifiable
				count(&r.Dropped, dropped)
				count(&r.Unverifiable, unverifiable)
				if n := to - from + 1 - covered; n > 0 {
					count(&r.Missing, n)
					linked = false
					problem(ProblemMissing, c, fmt.Sprintf("%d %s before this one %s missing (sequence numbers %d to %d): removed",
						n, plural(n, "record", "records"), plural(n, "is", "are"), from, to))
				} else if last != nil && h.Prev != last.hash {
					linked = false
					count(&r.Broken, 1)
					problem(ProblemBroken, c, "the record does not follow the records the audit.lost record names")
				}
			default:
				// After a record found changed, the next one does not
				// follow it either: that is the same change.
				if (h.Prev != p.hash || h.ChainStart) && !p.edited {
					linked = false
					if !p.broken {
						count(&r.Broken, 1)
						problem(ProblemBroken, c, fmt.Sprintf("the record does not follow record %d: that one was changed, or one was put in between", p.hit.Seq))
					}
				}
			}
			c.broken = !linked
			if c.macOK && linked && inside {
				r.OK++
				servers[h.NodeID].OK++
			}
			p = c
		}
	}

	// The latest record of each chain each checkpoint saw must still be
	// there, unchanged.
	latest := map[chainKey]headRef{}
	for _, hr := range heads {
		if !q.From.IsZero() && hr.at.Before(q.From) || !q.To.IsZero() && !hr.at.Before(q.To) {
			continue
		}
		if q.Server != "" && hr.server != q.Server {
			continue
		}
		list := chains[hr.chainKey]
		i, found := slices.BinarySearchFunc(list, hr.seq, func(c *checked, seq int64) int { return compareInt(c.hit.Seq, seq) })
		if found {
			if c := list[i]; c.hash != hr.hash && !c.edited {
				c.edited = true
				if in(c.hit.Time) {
					r.Edited++
				}
				problem(ProblemEdited, c, "the record differs from what an audit checkpoint saw")
			}
			continue
		}
		if cur, ok := latest[hr.chainKey]; !ok || hr.seq > cur.seq {
			latest[hr.chainKey] = hr
		}
	}
	for k, hr := range latest {
		list := chains[k]
		var top int64
		if len(list) > 0 {
			top = list[len(list)-1].hit.Seq
		}
		if hr.seq < top {
			// Inside the chain: counted as missing above.
			continue
		}
		r.Truncated++
		c := &checked{hit: &Hit{Event: Event{Time: hr.at, Server: hr.server, NodeID: k.node, Chain: k.chain, Seq: hr.seq}}}
		if servers[k.node] == nil {
			servers[k.node] = &ServerReport{Server: hr.server, NodeID: k.node, First: hr.at, Last: hr.at}
		}
		problem(ProblemTruncated, c, fmt.Sprintf("an audit checkpoint saw this server's records up to sequence number %d, and those after %d are gone: removed", hr.seq, top))
	}

	for _, s := range servers {
		r.Servers = append(r.Servers, *s)
	}
	sort.Slice(r.Servers, func(i, j int) bool {
		if r.Servers[i].Server != r.Servers[j].Server {
			return r.Servers[i].Server < r.Servers[j].Server
		}
		return r.Servers[i].NodeID < r.Servers[j].NodeID
	})
	sort.SliceStable(r.Problems, func(i, j int) bool { return r.Problems[i].Time.Before(r.Problems[j].Time) })
	return r
}

func compareInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// covers returns how many of the sequence numbers from to to the lost
// runs name, and the run that ends at to, if one does.
func covers(runs []lostRange, from, to int64) (int64, *lostRange) {
	var last *lostRange
	var spans [][2]int64
	for i := range runs {
		lr := &runs[i]
		if a, b := max(from, lr.from), min(to, lr.to); a <= b {
			spans = append(spans, [2]int64{a, b})
		}
		if lr.to == to {
			last = lr
		}
	}
	// Runs may overlap: count each number once.
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
	var n int64
	end := from - 1
	for _, sp := range spans {
		if sp[1] <= end {
			continue
		}
		n += sp[1] - max(sp[0], end+1) + 1
		end = sp[1]
	}
	return n, last
}

// parseLost reads the run of records an audit.lost record names.
func parseLost(h *Hit) (lostRange, bool) {
	f := h.Fields
	from, err1 := strconv.ParseInt(f[fieldLostFrom], 10, 64)
	to, err2 := strconv.ParseInt(f[fieldLostTo], 10, 64)
	if f[fieldLostChain] == "" || err1 != nil || err2 != nil || from < 1 || to < from {
		return lostRange{}, false
	}
	return lostRange{chain: f[fieldLostChain], from: from, to: to, hash: f[fieldLostHash]}, true
}

// parseHeads reads what an audit.checkpoint record saw.
func parseHeads(h *Hit) []headRef {
	var out []headRef
	for k, v := range h.Fields {
		node, ok := strings.CutPrefix(k, headPrefix)
		if !ok {
			continue
		}
		parts := strings.SplitN(v, ":", 5)
		if len(parts) != 5 {
			continue
		}
		seq, err1 := strconv.ParseInt(parts[1], 10, 64)
		ms, err2 := strconv.ParseInt(parts[3], 10, 64)
		if err1 != nil || err2 != nil || parts[0] == "" {
			continue
		}
		out = append(out, headRef{chainKey: chainKey{node, parts[0]}, seq: seq, hash: parts[2], at: time.UnixMilli(ms).UTC(), server: parts[4]})
	}
	return out
}

// headValue is how an audit.checkpoint record names a server's latest
// record.
func headValue(ev Event) string {
	return ev.Chain + ":" + strconv.FormatInt(ev.Seq, 10) + ":" + ev.Hash() + ":" + strconv.FormatInt(ev.Time.UnixMilli(), 10) + ":" + ev.Server
}

// headsLook is how many of each server's latest records Heads reads to
// find the latest one that checks out.
const headsLook = 25

// Heads returns the latest chained record of each server with audit
// records (at most MaxFields-1 of them), for an audit.checkpoint record:
// the latest whose MAC checks out with keys, when keys is set, of those
// not dated in the future. A record someone put in, unsigned or dated
// ahead, is never what a checkpoint vouches for (Verify reports it).
func Heads(ctx context.Context, c Searcher, prefix string, keys KeyFunc) ([]Event, error) {
	res, err := c.Search(ctx, Pattern(prefix), map[string]any{
		"size":  0,
		"query": map[string]any{"bool": map[string]any{"filter": []any{map[string]any{"range": map[string]any{"@timestamp": map[string]any{"lte": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}}}}}},
		"aggs": map[string]any{"nodes": map[string]any{
			"terms": map[string]any{"field": "node_id", "size": 200},
			"aggs": map[string]any{"latest": map[string]any{"top_hits": map[string]any{
				"size": headsLook, "sort": []any{map[string]any{"@timestamp": "desc"}, map[string]any{"seq": "desc"}}}}},
		}},
	})
	if missing(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out struct {
		Aggregations struct {
			Nodes struct {
				Buckets []struct {
					Latest struct {
						Hits struct {
							Hits []struct {
								Source json.RawMessage `json:"_source"`
							} `json:"hits"`
						} `json:"hits"`
					} `json:"latest"`
				} `json:"buckets"`
			} `json:"nodes"`
		} `json:"aggregations"`
	}
	if err := remarshal(res, &out); err != nil {
		return nil, fmt.Errorf("audit heads: %w", err)
	}
	var evs []Event
	for _, b := range out.Aggregations.Nodes.Buckets {
		for _, h := range b.Latest.Hits.Hits {
			var ev Event
			if json.Unmarshal(h.Source, &ev) != nil || ev.Chain == "" || ev.NodeID == "" {
				continue
			}
			if keys != nil {
				key := keys(ev.KID)
				if ev.MAC == "" || key == nil || !ev.checkMAC(key) {
					continue
				}
			}
			if len(evs) < MaxFields-1 {
				evs = append(evs, ev)
			}
			break
		}
	}
	return evs, nil
}

// CheckpointEvent returns the audit.checkpoint record naming heads, the
// latest record of each server: once it is written, removing those
// records, or any before them, shows in Verify, even at the end of a
// server's records where no later record would miss them.
func CheckpointEvent(heads []Event) Event {
	f := map[string]string{"servers": strconv.Itoa(len(heads))}
	for _, h := range heads {
		f[headPrefix+h.NodeID] = headValue(h)
	}
	return Event{Action: ActionCheckpoint, Level: "INFO", Fields: f,
		Message: fmt.Sprintf("audit.checkpoint: the latest audit record of %d %s", len(heads), plural(int64(len(heads)), "server", "servers"))}
}

func plural(n int64, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
