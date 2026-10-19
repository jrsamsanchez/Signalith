package archivecrypt

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

type badWrapper struct{}

func (badWrapper) Seal(string, string) (string, error) { return "", errors.New("key store locked") }

// limitWriter fails once it has taken n bytes.
type limitWriter struct {
	n   int
	buf bytes.Buffer
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.buf.Len()+len(p) > l.n {
		return 0, errors.New("disk full")
	}
	return l.buf.Write(p)
}

func TestSealFailures(t *testing.T) {
	k := newKey(t, "master key")
	if _, _, err := Seal(&bytes.Buffer{}, badWrapper{}); err == nil || !strings.Contains(err.Error(), "key store locked") {
		t.Errorf("wrapper = %v", err)
	}
	if _, _, err := Seal(&limitWriter{n: 3}, k); err == nil || err.Error() != "disk full" {
		t.Errorf("header write = %v", err)
	}

	// Room for the header only: the first chunk's length fails.
	var head bytes.Buffer
	if _, _, err := Seal(&head, k); err != nil {
		t.Fatal(err)
	}
	lw := &limitWriter{n: head.Len() + 2}
	w, _, err := Seal(lw, k)
	if err != nil {
		t.Fatal(err)
	}
	big := make([]byte, chunkSize+1)
	if n, err := w.Write(big); err == nil || n != chunkSize {
		t.Errorf("chunk length write = %d %v", n, err)
	}
	// Room for the length but not the chunk.
	lw = &limitWriter{n: head.Len() + 4 + 10}
	w, _, _ = Seal(lw, k)
	w.Write([]byte("hello"))
	if err := w.Close(); err == nil {
		t.Error("closing with no room worked")
	}

	w, _, _ = Seal(&bytes.Buffer{}, k)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second close = %v", err)
	}
	if _, err := w.Write([]byte("x")); err == nil || !strings.Contains(err.Error(), "after close") {
		t.Errorf("write after close = %v", err)
	}
	s := w.(*sealer)
	s.closed, s.n = false, ^uint32(0)
	if err := s.Close(); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("too many chunks = %v", err)
	}
}

func TestEncryptedAndKeyIDs(t *testing.T) {
	k := newKey(t, "master key")
	file, ids := seal(t, []byte("data"), k)
	if !Encrypted(bufio.NewReader(bytes.NewReader(file))) {
		t.Error("an encrypted file was not seen")
	}
	if Encrypted(bufio.NewReader(strings.NewReader("SGL"))) || Encrypted(bufio.NewReader(strings.NewReader("plain text file"))) {
		t.Error("a plain file was seen as encrypted")
	}
	if got := KeyIDs([]string{"no-colons", "a:b:" + ids[0] + ":rest"}); len(got) != 1 || got[0] != ids[0] {
		t.Errorf("KeyIDs = %v", got)
	}
}

func TestDamagedHeaders(t *testing.T) {
	k := newKey(t, "master key")
	file, _ := seal(t, []byte("data"), k)
	withHeader := func(h string) []byte {
		var b bytes.Buffer
		b.WriteString(magic)
		binary.Write(&b, binary.BigEndian, uint32(len(h)))
		b.WriteString(h)
		return b.Bytes()
	}
	hl := binary.BigEndian.Uint32(file[len(magic):])
	bigChunk := append([]byte{}, file[:len(magic)+4+int(hl)]...)
	bigChunk = binary.BigEndian.AppendUint32(bigChunk, maxChunk+1)
	for name, c := range map[string]struct {
		file []byte
		want string
	}{
		"no length":   {[]byte(magic + "\x00"), "cut short"},
		"zero length": {[]byte(magic + "\x00\x00\x00\x00"), "header is damaged"},
		"huge length": {[]byte(magic + "\x00\x10\x00\x01"), "header is damaged"},
		"header cut":  {[]byte(magic + "\x00\x00\x00\x10{}"), "cut short"},
		"not JSON":    {withHeader("not json"), "header is damaged"},
		"other alg":   {withHeader(`{"alg":"ROT13","nonce":"AAAAAAAAAAA="}`), "unknown kind"},
		"bad nonce":   {withHeader(`{"alg":"AES-256-GCM","nonce":"AA=="}`), "unknown kind"},
		"big chunk":   {bigChunk, "the archive is damaged"},
	} {
		if _, err := unseal(c.file, k); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
