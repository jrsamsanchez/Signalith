package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// osReader reads OpenSearch directly: the run's stored events, for
// verify, and the operation counters, for the request rates. It never
// writes.
type osReader struct {
	url    string
	prefix string
	client *http.Client
	user   string
	pass   string
}

func newOSReader(o OpenSearch) (*osReader, error) {
	if o.URL == "" {
		return nil, errors.New("no OpenSearch address in the scenario")
	}
	var cas []string
	if o.CA != "" {
		cas = append(cas, o.CA)
	}
	tc, err := tlsConfig(cas)
	if err != nil {
		return nil, err
	}
	if o.Cert != "" || o.Key != "" {
		pair, err := tls.LoadX509KeyPair(o.Cert, o.Key)
		if err != nil {
			return nil, fmt.Errorf("OpenSearch client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{pair}
	}
	r := &osReader{url: strings.TrimRight(o.URL, "/"), prefix: o.Prefix,
		client: &http.Client{Timeout: time.Minute, Transport: newTransport(tc, nil)}}
	if r.prefix == "" {
		r.prefix = "signalith"
	}
	if o.UserFile != "" {
		if r.user, r.pass, err = readLogin(o.UserFile); err != nil {
			return nil, fmt.Errorf("OpenSearch user file: %w", err)
		}
	}
	return r, nil
}

func (r *osReader) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.url+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.user != "" {
		req.SetBasicAuth(r.user, r.pass)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if resp.StatusCode/100 != 2 {
		return &apiError{Status: resp.StatusCode, Body: truncate(string(b), 300)}
	}
	if out != nil {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		return dec.Decode(out)
	}
	return nil
}

// verifyPage is how many events one search reads (a variable for tests).
var verifyPage = 5000

// storedCounts counts the run's stored events by agent and sequence
// number. It pages with search_after on _id, so every stored copy is
// read once, duplicates included.
func (r *osReader) storedCounts(ctx context.Context, run string) (map[int]map[int64]int, int64, error) {
	out := map[int]map[int64]int{}
	var total int64
	var after []any
	for {
		req := map[string]any{
			"size":    verifyPage,
			"query":   map[string]any{"bool": map[string]any{"filter": []any{map[string]any{"term": map[string]any{"loadgen_run": run}}}}},
			"_source": []string{"loadgen_agent", "loadgen_seq"},
			"sort":    []any{map[string]any{"_id": "asc"}},
		}
		if after != nil {
			req["search_after"] = after
		}
		var resp struct {
			Hits struct {
				Hits []struct {
					Source map[string]any `json:"_source"`
					Sort   []any          `json:"sort"`
				} `json:"hits"`
			} `json:"hits"`
		}
		path := "/" + r.prefix + "-*/_search?ignore_unavailable=true&allow_no_indices=true"
		if err := r.do(ctx, http.MethodPost, path, req, &resp); err != nil {
			return nil, 0, err
		}
		hits := resp.Hits.Hits
		for _, h := range hits {
			agent, ok1 := number(h.Source["loadgen_agent"])
			seq, ok2 := number(h.Source["loadgen_seq"])
			if !ok1 || !ok2 {
				continue
			}
			if out[int(agent)] == nil {
				out[int(agent)] = map[int64]int{}
			}
			out[int(agent)][seq]++
			total++
		}
		if len(hits) < verifyPage {
			return out, total, nil
		}
		after = hits[len(hits)-1].Sort
	}
}

// number reads a stored number, which ingest may keep as a string.
func number(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	case float64:
		return int64(x), true
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		return n, err == nil
	}
	return 0, false
}

// opsTotal is the operations every OpenSearch node has done so far:
// documents indexed and deleted, searches, and gets.
func (r *osReader) opsTotal(ctx context.Context) (int64, error) {
	var resp struct {
		Nodes map[string]struct {
			Indices struct {
				Indexing struct {
					IndexTotal  int64 `json:"index_total"`
					DeleteTotal int64 `json:"delete_total"`
				} `json:"indexing"`
				Search struct {
					QueryTotal int64 `json:"query_total"`
				} `json:"search"`
				Get struct {
					Total int64 `json:"total"`
				} `json:"get"`
			} `json:"indices"`
		} `json:"nodes"`
	}
	if err := r.do(ctx, http.MethodGet, "/_nodes/stats/indices/indexing,search,get", nil, &resp); err != nil {
		return 0, err
	}
	if len(resp.Nodes) == 0 {
		return 0, errors.New("OpenSearch listed no node statistics")
	}
	var n int64
	for _, nd := range resp.Nodes {
		i := nd.Indices
		n += i.Indexing.IndexTotal + i.Indexing.DeleteTotal + i.Search.QueryTotal + i.Get.Total
	}
	return n, nil
}

// Verdict is what verify found.
type Verdict struct {
	// Acked is how many events the agents were told were stored.
	Acked int64 `json:"acked"`
	// Stored is how many copies of the run's events OpenSearch holds.
	Stored int64 `json:"stored"`
	// Lost were acked but are not stored.
	Lost int64 `json:"lost"`
	// Duplicated are extra copies of an event.
	Duplicated int64 `json:"duplicated"`
	// Unacked are stored although the agent never heard so (the answer
	// was lost), which is not a loss.
	Unacked int64 `json:"stored_without_answer"`
	// Examples name a few lost or duplicated events.
	Examples []string `json:"examples,omitempty"`
}

// compare checks the stored counts against what the agents were told.
func compare(acked map[int][]seqRange, stored map[int]map[int64]int) Verdict {
	var v Verdict
	agents := make([]int, 0, len(acked))
	for a := range acked {
		agents = append(agents, a)
	}
	sort.Ints(agents)
	example := func(f string, a ...any) {
		if len(v.Examples) < 10 {
			v.Examples = append(v.Examples, fmt.Sprintf(f, a...))
		}
	}
	for _, a := range agents {
		got := stored[a]
		for _, r := range acked[a] {
			for seq := r.First; seq <= r.Last; seq++ {
				v.Acked++
				if got[seq] == 0 {
					v.Lost++
					example("agent %d event %d lost", a, seq)
				}
			}
		}
	}
	isAcked := func(a int, seq int64) bool {
		for _, r := range acked[a] {
			if seq >= r.First && seq <= r.Last {
				return true
			}
		}
		return false
	}
	for a, seqs := range stored {
		for seq, n := range seqs {
			v.Stored += int64(n)
			if n > 1 {
				v.Duplicated += int64(n - 1)
				example("agent %d event %d stored %d times", a, seq, n)
			}
			if !isAcked(a, seq) {
				v.Unacked++
			}
		}
	}
	return v
}

// verify compares the run's stored events with what the agents were
// told, reading again until nothing is missing or settle is over:
// OpenSearch shows new events only after its refresh interval.
func verify(ctx context.Context, r *osReader, run string, acked map[int][]seqRange, settle time.Duration) (Verdict, error) {
	deadline := time.Now().Add(settle)
	for {
		stored, _, err := r.storedCounts(ctx, run)
		if err != nil {
			return Verdict{}, err
		}
		v := compare(acked, stored)
		if v.Lost == 0 || time.Now().After(deadline) {
			return v, nil
		}
		select {
		case <-ctx.Done():
			return v, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}
