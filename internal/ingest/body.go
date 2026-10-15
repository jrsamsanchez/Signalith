package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Limits on one ingest request. Fluent Bit sends one buffer chunk per
// request: about 2 MB of records, a few MB of JSON even when much of the
// text needs escaping, and at most about 110,000 records (empty log
// lines). These leave room for that while keeping what one request can
// make the server hold small.
const (
	// MaxBodyBytes is the largest request body accepted.
	MaxBodyBytes = 16 << 20
	// MaxRecords is the most records one request may carry.
	MaxRecords = 200_000
	// MaxRecordBytes is the largest single record, as JSON.
	MaxRecordBytes = 1 << 20
	// MaxDepth is how deeply objects and arrays may nest in a record,
	// counting the record itself.
	MaxDepth = 32

	// A request is written in bulk requests of at most batchEvents events
	// or about batchBytes of JSON, so its decoded form never sits in
	// memory all at once.
	batchEvents = 2000
	batchBytes  = 4 << 20
)

// BodyError is an ingest request refused as a whole, before anything was
// written. Status is the HTTP status to answer with.
type BodyError struct {
	Status int
	Msg    string
}

func (e *BodyError) Error() string { return e.Msg }

func tooLarge(format string, args ...any) *BodyError {
	return &BodyError{Status: http.StatusRequestEntityTooLarge, Msg: fmt.Sprintf(format, args...)}
}

func badBody(format string, args ...any) *BodyError {
	return &BodyError{Status: http.StatusBadRequest, Msg: fmt.Sprintf(format, args...)}
}

// IngestBody writes the records of a request body sent with a Fluent Bit
// tag: a JSON array of objects, JSON lines (one object per line), or a
// single object. The whole body is checked against the limits above first,
// so a refused request (a *BodyError) writes nothing. Records are then
// decoded and written in batches; if OpenSearch fails part way, the
// batches already written stay. Each record's document ID comes from the
// tag, the whole body and the record's place in it, so when the sender
// sends the same request again (Fluent Bit does on the 503 this leads
// to), records already stored count as duplicates instead of being
// stored twice.
func (p *Pipeline) IngestBody(ctx context.Context, tag string, body []byte) (*Result, error) {
	n, err := checkBody(body)
	if err != nil {
		return nil, err
	}
	p.stats.Received.Add(int64(n))
	p.stats.LastSeen.Store(p.now().Unix())
	total := &Result{Received: n}
	if n == 0 {
		return total, nil
	}
	rd, err := newRecordReader(body)
	if err != nil {
		return nil, err
	}
	batch := make([]Event, 0, min(n, batchEvents))
	ids := make([]string, 0, cap(batch))
	seed := bodySeed(tag, body)
	size, done := 0, 0
	flush := func() error {
		for i := range batch {
			ids = append(ids, recordID(seed, done+i))
		}
		res, err := p.write(ctx, batch, ids)
		done += len(batch)
		clear(batch)
		batch, ids, size = batch[:0], ids[:0], 0
		if err != nil {
			p.stats.Failed.Add(int64(n - done))
			return err
		}
		total.add(res)
		return nil
	}
	for {
		var rec map[string]any
		raw, err := rd.next(&rec)
		if err == io.EOF {
			break
		}
		if err != nil {
			// checkBody read the same body without error.
			p.stats.Failed.Add(int64(n - done))
			return nil, err
		}
		batch = append(batch, Normalize(tag, rec, p.now()))
		total.noteHost(&batch[len(batch)-1])
		size += len(raw)
		if len(batch) >= batchEvents || size >= batchBytes {
			if err := flush(); err != nil {
				return nil, err
			}
		}
	}
	if len(batch) > 0 {
		if err := flush(); err != nil {
			return nil, err
		}
	}
	return total, nil
}

// bodySeed identifies a request by its tag and body.
func bodySeed(tag string, body []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte(tag))
	h.Write([]byte{0})
	h.Write(body)
	return [sha256.Size]byte(h.Sum(nil))
}

// recordID is the document ID of the record at pos in the request seed
// identifies: the same in every send of that request, and different for
// identical records within it.
func recordID(seed [sha256.Size]byte, pos int) string {
	var b [sha256.Size + 8]byte
	copy(b[:], seed[:])
	binary.BigEndian.PutUint64(b[sha256.Size:], uint64(pos))
	sum := sha256.Sum256(b[:])
	return base64.RawURLEncoding.EncodeToString(sum[:18])
}

// checkBody reads a body without keeping what it decodes and returns how
// many records it has, or a *BodyError saying which limit it breaks.
func checkBody(body []byte) (int, error) {
	rd, err := newRecordReader(body)
	if err != nil {
		return 0, err
	}
	for {
		var skip struct{}
		raw, err := rd.next(&skip)
		if err == io.EOF {
			return rd.n, nil
		}
		if err != nil {
			return 0, err
		}
		switch {
		case rd.n > MaxRecords:
			return 0, tooLarge("the request has more than %d records; send smaller batches", MaxRecords)
		case len(raw) == 0 || raw[0] != '{':
			return 0, badBody("record %d is not a JSON object; send an array of objects or one object per line", rd.n)
		case len(raw) > MaxRecordBytes:
			return 0, tooLarge("record %d is %d bytes; the limit is %d bytes (1 MB) per record", rd.n, len(raw), MaxRecordBytes)
		}
		if d := depth(raw); d > MaxDepth {
			return 0, badBody("record %d nests objects or arrays %d levels deep; the limit is %d", rd.n, d, MaxDepth)
		}
	}
}

// recordReader reads the records of a body one at a time.
type recordReader struct {
	body  []byte
	dec   *json.Decoder
	array bool
	empty bool
	n     int   // records read so far
	end   int64 // offset just after the last record
}

func newRecordReader(body []byte) (*recordReader, error) {
	rd := &recordReader{body: body}
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		rd.empty = true
		return rd, nil
	}
	rd.dec = json.NewDecoder(bytes.NewReader(body))
	rd.dec.UseNumber()
	switch trimmed[0] {
	case '[':
		rd.array = true
		if _, err := rd.dec.Token(); err != nil {
			return nil, badBody("invalid JSON: %v", err)
		}
	case '{':
	default:
		return nil, badBody("the body must be a JSON array of records or JSON lines (one object per line)")
	}
	rd.end = rd.dec.InputOffset()
	return rd, nil
}

// next decodes the next record into v and returns its JSON, or io.EOF
// after the last one.
func (rd *recordReader) next(v any) ([]byte, error) {
	if rd.empty {
		return nil, io.EOF
	}
	if rd.array && !rd.dec.More() {
		if _, err := rd.dec.Token(); err != nil {
			return nil, badBody("invalid JSON array: %v", err)
		}
		if _, err := rd.dec.Token(); err != io.EOF {
			return nil, badBody("unexpected data after the JSON array")
		}
		rd.empty = true
		return nil, io.EOF
	}
	err := rd.dec.Decode(v)
	if err == io.EOF && !rd.array {
		rd.empty = true
		return nil, io.EOF
	}
	rd.n++
	if err != nil {
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) {
			return nil, badBody("record %d is not a JSON object; send an array of objects or one object per line", rd.n)
		}
		return nil, badBody("invalid JSON in record %d: %v", rd.n, err)
	}
	end := rd.dec.InputOffset()
	raw := bytes.TrimLeft(rd.body[rd.end:end], " \t\r\n,")
	rd.end = end
	return raw, nil
}

// depth returns how deeply objects and arrays nest in a JSON value.
func depth(raw []byte) int {
	d, deepest := 0, 0
	inString, escaped := false, false
	for _, c := range raw {
		switch {
		case inString:
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			d++
			deepest = max(deepest, d)
		case c == '}' || c == ']':
			d--
		}
	}
	return deepest
}
