package shared

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Chunks keep a value too big for one shared document (an asset list of
// a million rows) in the config index, outside the watcher: the value is
// cut into signed documents <kind>:<name>:<gen>:<n>, written once and
// never changed, and a watched document (a Collection item) names the
// generation in use. A reader reads the chunks of the generation the
// watched document names, so it sees the old value or the new one, never
// a mix; the chunks of a generation no longer in use are deleted later,
// once no reader can still be reading them.

// ChunkSize is how many bytes of the value each chunk holds.
var ChunkSize = 2 << 20

// ChunkRef names one generation of a chunked value.
type ChunkRef struct {
	Kind string
	Name string
	Gen  int64
	// N is how many chunks the generation has.
	N int
}

func (r ChunkRef) id(i int) string {
	return r.Kind + ":" + r.Name + ":" + strconv.FormatInt(r.Gen, 10) + ":" + strconv.Itoa(i)
}

// chunkBody is the body of one chunk: its bytes, base64, so a value that
// is not valid UTF-8 comes back as it was written.
type chunkBody struct {
	Data string `json:"data"`
}

// ErrChunkMissing is a chunk that is not there, or does not verify: the
// generation was retired and deleted while it was being read, or changed
// outside Signalith.
var ErrChunkMissing = errors.New("a part of the list is missing")

// PutChunks writes data as the generation ref.Gen of ref.Kind:ref.Name
// and returns the ref with its N, and the SHA-256 of data in hex. The
// chunks are written with create, so a generation is never written
// twice; written chunks are removed again when a later one fails.
func (h *Hub) PutChunks(ctx context.Context, by string, ref ChunkRef, data []byte) (ChunkRef, string, error) {
	c, _ := h.target()
	k := h.Keys().Active()
	if c == nil || k == nil {
		return ref, "", errors.New("this server cannot sign the shared settings now")
	}
	ref.N = max(1, (len(data)+ChunkSize-1)/ChunkSize)
	index := h.index()
	for i := range ref.N {
		part := data[min(i*ChunkSize, len(data)):min((i+1)*ChunkSize, len(data))]
		body, err := json.Marshal(chunkBody{Data: base64.StdEncoding.EncodeToString(part)})
		if err != nil {
			return ref, "", err
		}
		id := ref.id(i)
		e := &Envelope{Kind: ref.Kind, ID: id, Format: 1, Rev: 1, UpdatedAt: h.now(),
			UpdatedBy: By{User: by, Node: h.opts.NodeName}, Body: string(body)}
		if err := Sign(k, id, e); err != nil {
			return ref, "", err
		}
		if _, err := c.Create(ctx, index, id, e, false); err != nil {
			h.DeleteChunks(context.WithoutCancel(ctx), ChunkRef{Kind: ref.Kind, Name: ref.Name, Gen: ref.Gen, N: i})
			return ref, "", fmt.Errorf("could not write part %d of %d: %w", i+1, ref.N, err)
		}
	}
	if err := c.Do(ctx, http.MethodPost, "/"+url.PathEscape(index)+"/_refresh", nil, nil); err != nil {
		h.log.Debug("could not refresh the shared settings after writing a list", "err", err)
	}
	sum := sha256.Sum256(data)
	return ref, hex.EncodeToString(sum[:]), nil
}

// ReadChunks reads the generation ref and checks it against sum, the
// SHA-256 PutChunks returned. A chunk missing or failing its MAC gives
// ErrChunkMissing.
func (h *Hub) ReadChunks(ctx context.Context, ref ChunkRef, sum string) ([]byte, error) {
	c, _ := h.target()
	if c == nil {
		return nil, errors.New("OpenSearch is not reachable")
	}
	keys := h.Keys()
	index := h.index()
	var out []byte
	// A few chunks per request: each is up to ChunkSize, base64.
	const per = 4
	for from := 0; from < ref.N; from += per {
		var refs []store.Ref
		for i := from; i < min(from+per, ref.N); i++ {
			refs = append(refs, store.Ref{Index: index, ID: ref.id(i)})
		}
		docs, err := c.MGet(ctx, refs)
		if err != nil {
			return nil, err
		}
		if len(docs) != len(refs) {
			return nil, ErrChunkMissing
		}
		for i, d := range docs {
			if !d.Found || d.ID != refs[i].ID {
				return nil, ErrChunkMissing
			}
			var e Envelope
			if err := json.Unmarshal(d.Source, &e); err != nil || e.ID != d.ID || e.Kind != ref.Kind {
				return nil, ErrChunkMissing
			}
			if err := Verify(keys, d.ID, &e); err != nil {
				return nil, fmt.Errorf("%w: %s %v", ErrChunkMissing, d.ID, err)
			}
			var b chunkBody
			if err := json.Unmarshal([]byte(e.Body), &b); err != nil {
				return nil, ErrChunkMissing
			}
			part, err := base64.StdEncoding.DecodeString(b.Data)
			if err != nil {
				return nil, ErrChunkMissing
			}
			out = append(out, part...)
		}
	}
	got := sha256.Sum256(out)
	if hex.EncodeToString(got[:]) != sum {
		return nil, fmt.Errorf("%w: its checksum does not match", ErrChunkMissing)
	}
	return out, nil
}

// DeleteChunks deletes the chunks of the generation ref. Chunks already
// gone are no error.
func (h *Hub) DeleteChunks(ctx context.Context, ref ChunkRef) error {
	c, _ := h.target()
	if c == nil {
		return errors.New("OpenSearch is not reachable")
	}
	index := h.index()
	var errs []error
	for i := range ref.N {
		err := c.Do(ctx, http.MethodDelete, "/"+url.PathEscape(index)+"/_doc/"+url.PathEscape(ref.id(i)), nil, nil)
		var se *store.Error
		if err != nil && !(errors.As(err, &se) && se.Status == http.StatusNotFound) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
