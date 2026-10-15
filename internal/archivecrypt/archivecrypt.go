// Package archivecrypt encrypts archive files as they are written and
// decrypts them as they are read, as retention.Archive's Seal and Unseal.
//
// Each file gets its own random data key. The file starts with a header
// that holds that key encrypted ("wrapped") with each key given to Seal:
// this server's master key and, on servers that share their settings,
// the cluster key, so any server of the cluster can read any archive, and
// a file copied elsewhere carries what it needs except the keys. After
// the header, the gzip stream is cut into chunks, each encrypted with
// AES-256-GCM under a nonce that counts the chunks; the last chunk is
// marked, so a file cut short or with chunks moved is refused.
//
// Layout:
//
//	"SGLARC1\n"
//	uint32 big-endian header length, header JSON
//	chunks: uint32 big-endian ciphertext length, ciphertext
//
// The SHA-256 of the header without its wrapped keys is part of every
// chunk's associated data, with the chunk's number and whether it is the
// last one. The wrapped keys are left out so that they can be wrapped
// again with other keys without encrypting the file again; each is
// authenticated on its own.
package archivecrypt

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// Scheme names the encryption in archive manifests.
const Scheme = "aes-256-gcm/sglarc1"

// Field is the setting name the data keys are wrapped for: a wrapped key
// copied into another setting does not open.
const Field = "retention.archive_data_key"

const (
	magic     = "SGLARC1\n"
	chunkSize = 64 << 10
	// maxHeader and maxChunk bound what a damaged file can make Unseal
	// allocate.
	maxHeader = 64 << 10
	maxChunk  = chunkSize + 64
)

// Wrapper encrypts a data key: *secrets.Keyring (the master key) and
// *secrets.Key (the cluster key) are Wrappers.
type Wrapper interface {
	Seal(field, plain string) (string, error)
}

// header is the file's header.
type header struct {
	Alg   string `json:"alg"`
	Chunk int    `json:"chunk"`
	// Nonce is the 8 random bytes every chunk's nonce starts with.
	Nonce string `json:"nonce"`
	// Keys are the data key, wrapped by each key Seal was given.
	Keys []string `json:"keys"`
}

// KeyIDs returns the ids of the keys that wrap a data key, as stored by
// Seal, for the manifest.
func KeyIDs(wrapped []string) []string {
	var out []string
	for _, w := range wrapped {
		// enc:v1:<key id>:...
		if p := strings.SplitN(w, ":", 4); len(p) == 4 {
			out = append(out, p[2])
		}
	}
	return out
}

// Seal returns a writer that encrypts what is written to it into w, with
// a new data key wrapped by each of wrappers (nil ones are skipped), and
// the ids of the wrapping keys. Close writes the last chunk; it does not
// close w.
func Seal(w io.Writer, wrappers ...Wrapper) (io.WriteCloser, []string, error) {
	dk := make([]byte, 32)
	nonce := make([]byte, 8)
	if _, err := rand.Read(dk); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	h := header{Alg: "AES-256-GCM", Chunk: chunkSize, Nonce: base64.StdEncoding.EncodeToString(nonce)}
	text := base64.StdEncoding.EncodeToString(dk)
	for _, wr := range wrappers {
		if wr == nil {
			continue
		}
		s, err := wr.Seal(Field, text)
		if err != nil {
			return nil, nil, fmt.Errorf("could not encrypt the archive's key: %w", err)
		}
		h.Keys = append(h.Keys, s)
	}
	if len(h.Keys) == 0 {
		return nil, nil, errors.New("no key to encrypt the archive with")
	}
	hb, err := json.Marshal(h)
	if err != nil {
		return nil, nil, err
	}
	aead, err := newAEAD(dk)
	if err != nil {
		return nil, nil, err
	}
	var pre bytes.Buffer
	pre.WriteString(magic)
	_ = binary.Write(&pre, binary.BigEndian, uint32(len(hb)))
	pre.Write(hb)
	if _, err := w.Write(pre.Bytes()); err != nil {
		return nil, nil, err
	}
	sum, err := h.sum()
	if err != nil {
		return nil, nil, err
	}
	return &sealer{w: w, aead: aead, nonce: nonce, hsum: sum[:], buf: make([]byte, 0, chunkSize)}, KeyIDs(h.Keys), nil
}

// sum is the SHA-256 of the header without its wrapped keys.
func (h header) sum() ([32]byte, error) {
	h.Keys = nil
	b, err := json.Marshal(h)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// chunkNonce is the nonce of chunk n: the file's 8 random bytes and n.
func chunkNonce(prefix []byte, n uint32) []byte {
	out := make([]byte, 12)
	copy(out, prefix)
	binary.BigEndian.PutUint32(out[8:], n)
	return out
}

// chunkAD is the associated data of chunk n.
func chunkAD(hsum []byte, n uint32, last bool) []byte {
	ad := make([]byte, 0, len(hsum)+5)
	ad = append(ad, hsum...)
	ad = binary.BigEndian.AppendUint32(ad, n)
	if last {
		return append(ad, 1)
	}
	return append(ad, 0)
}

type sealer struct {
	w      io.Writer
	aead   cipher.AEAD
	nonce  []byte
	hsum   []byte
	buf    []byte
	n      uint32
	closed bool
}

func (s *sealer) Write(p []byte) (int, error) {
	if s.closed {
		return 0, errors.New("archivecrypt: write after close")
	}
	total := len(p)
	for len(p) > 0 {
		// A full chunk is written once more data follows, so that the
		// last chunk, written by Close, is never empty unless the whole
		// stream is.
		if len(s.buf) == chunkSize {
			if err := s.flush(false); err != nil {
				return total - len(p), err
			}
		}
		k := min(chunkSize-len(s.buf), len(p))
		s.buf = append(s.buf, p[:k]...)
		p = p[k:]
	}
	return total, nil
}

func (s *sealer) flush(last bool) error {
	if s.n == ^uint32(0) {
		return errors.New("archivecrypt: archive too large")
	}
	ct := s.aead.Seal(nil, chunkNonce(s.nonce, s.n), s.buf, chunkAD(s.hsum, s.n, last))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(ct)))
	if _, err := s.w.Write(l[:]); err != nil {
		return err
	}
	if _, err := s.w.Write(ct); err != nil {
		return err
	}
	s.n++
	s.buf = s.buf[:0]
	return nil
}

// Close writes the last chunk.
func (s *sealer) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return s.flush(true)
}

// Encrypted reports whether r starts like an encrypted archive, without
// consuming it.
func Encrypted(r *bufio.Reader) bool {
	b, err := r.Peek(len(magic))
	return err == nil && string(b) == magic
}

// Unseal returns a reader of what was sealed into r, opening the data key
// with opener (secrets.Chain of the keys this server has). It fails at
// once when no key of opener opens it, and while reading when the file was
// changed, cut short or has more after its last chunk.
func Unseal(r io.Reader, opener secrets.Opener) (io.Reader, error) {
	br := bufio.NewReader(r)
	m := make([]byte, len(magic))
	if _, err := io.ReadFull(br, m); err != nil || string(m) != magic {
		return nil, errors.New("not an encrypted Signalith archive")
	}
	var hl uint32
	if err := binary.Read(br, binary.BigEndian, &hl); err != nil {
		return nil, fmt.Errorf("the archive's header is cut short: %w", err)
	}
	if hl == 0 || hl > maxHeader {
		return nil, errors.New("the archive's header is damaged")
	}
	hb := make([]byte, hl)
	if _, err := io.ReadFull(br, hb); err != nil {
		return nil, fmt.Errorf("the archive's header is cut short: %w", err)
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, fmt.Errorf("the archive's header is damaged: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(h.Nonce)
	if err != nil || len(nonce) != 8 || h.Alg != "AES-256-GCM" {
		return nil, errors.New("the archive's header is damaged or of an unknown kind")
	}
	if opener == nil {
		return nil, fmt.Errorf("the archive is encrypted with key %s and this server has no key to open it", strings.Join(KeyIDs(h.Keys), ", "))
	}
	var dk []byte
	var errs []string
	for _, w := range h.Keys {
		text, err := opener.Open(Field, w)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if b, err := base64.StdEncoding.DecodeString(text); err == nil && len(b) == 32 {
			dk = b
			break
		}
	}
	if dk == nil {
		return nil, fmt.Errorf("no key of this server opens the archive (it was encrypted with key %s): %s",
			strings.Join(KeyIDs(h.Keys), ", "), strings.Join(errs, "; "))
	}
	aead, err := newAEAD(dk)
	if err != nil {
		return nil, err
	}
	sum, err := h.sum()
	if err != nil {
		return nil, err
	}
	return &unsealer{r: br, aead: aead, nonce: nonce, hsum: sum[:]}, nil
}

type unsealer struct {
	r    *bufio.Reader
	aead cipher.AEAD
	// nonce is the file's nonce prefix and hsum its header's SHA-256.
	nonce []byte
	hsum  []byte
	n     uint32
	plain []byte
	done  bool
	err   error
}

func (u *unsealer) Read(p []byte) (int, error) {
	for len(u.plain) == 0 {
		if u.err != nil {
			return 0, u.err
		}
		if u.done {
			return 0, io.EOF
		}
		u.err = u.next()
	}
	n := copy(p, u.plain)
	u.plain = u.plain[n:]
	return n, nil
}

// next reads and decrypts the next chunk.
func (u *unsealer) next() error {
	var l uint32
	if err := binary.Read(u.r, binary.BigEndian, &l); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("the archive is cut short: its last part is missing")
		}
		return err
	}
	if l > maxChunk {
		return errors.New("the archive is damaged")
	}
	ct := make([]byte, l)
	if _, err := io.ReadFull(u.r, ct); err != nil {
		return errors.New("the archive is cut short")
	}
	nonce := chunkNonce(u.nonce, u.n)
	plain, err := u.aead.Open(nil, nonce, ct, chunkAD(u.hsum, u.n, false))
	if err != nil {
		if plain, err = u.aead.Open(nil, nonce, ct, chunkAD(u.hsum, u.n, true)); err != nil {
			return fmt.Errorf("the archive was changed or damaged (part %d)", u.n)
		}
		u.done = true
		if _, err := u.r.Peek(1); err == nil {
			return errors.New("the archive has data after its last part")
		}
	}
	u.n++
	u.plain = plain
	return nil
}
