package archivecrypt

import (
	"bytes"
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

func newKey(t *testing.T, name string) *secrets.Key {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	k, err := secrets.NewKey(raw, name)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func seal(t *testing.T, plain []byte, keys ...Wrapper) ([]byte, []string) {
	t.Helper()
	var out bytes.Buffer
	w, ids, err := Seal(&out, keys...)
	if err != nil {
		t.Fatal(err)
	}
	// Odd write sizes cross chunk boundaries.
	for p := plain; len(p) > 0; {
		n := min(len(p), 7777)
		if _, err := w.Write(p[:n]); err != nil {
			t.Fatal(err)
		}
		p = p[n:]
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), ids
}

func unseal(file []byte, opener secrets.Opener) ([]byte, error) {
	r, err := Unseal(bytes.NewReader(file), opener)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestRoundTrip(t *testing.T) {
	master, cluster := newKey(t, "master key"), newKey(t, "cluster key")
	for _, size := range []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 3*chunkSize + 17} {
		plain := make([]byte, size)
		_, _ = rand.Read(plain)
		file, ids := seal(t, plain, master, nil, cluster)
		if len(ids) != 2 || ids[0] != master.ID() || ids[1] != cluster.ID() {
			t.Fatalf("key ids = %v", ids)
		}
		if bytes.Contains(file, plain[:min(size, 64)]) && size >= 16 {
			t.Fatalf("size %d: plain text in the file", size)
		}
		// Either key alone opens it.
		for _, k := range []secrets.Opener{master, cluster, secrets.Chain(newKey(t, "other"), cluster)} {
			got, err := unseal(file, k)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("size %d: %v (%d bytes)", size, err, len(got))
			}
		}
	}
}

func TestRefusesWrongKeyAndDamage(t *testing.T) {
	k := newKey(t, "master key")
	plain := bytes.Repeat([]byte("event line\n"), 20000)
	file, _ := seal(t, plain, k)

	if _, err := unseal(file, newKey(t, "master key")); err == nil || !strings.Contains(err.Error(), "no key of this server opens") {
		t.Errorf("wrong key: %v", err)
	}
	if _, err := unseal(file, nil); err == nil {
		t.Error("no key opened it")
	}
	cases := map[string][]byte{
		"cut short": file[:len(file)-100],
		// 220000 bytes are 3 full chunks and a last one of 23392.
		"last chunk gone":    file[:len(file)-(4+23392+16)],
		"flipped byte":       flip(file, len(file)/2),
		"data after the end": append(append([]byte{}, file...), 0, 0, 0, 1, 9),
	}
	for name, f := range cases {
		if got, err := unseal(f, k); err == nil {
			t.Errorf("%s: read %d bytes without an error", name, len(got))
		}
	}
	if _, err := unseal([]byte("\x1f\x8b plain gzip"), k); err == nil {
		t.Error("a plain file was taken as encrypted")
	}
}

func TestNoKey(t *testing.T) {
	if _, _, err := Seal(io.Discard); err == nil {
		t.Error("sealed without a key")
	}
}

func flip(b []byte, i int) []byte {
	out := append([]byte{}, b...)
	out[i] ^= 1
	return out
}
