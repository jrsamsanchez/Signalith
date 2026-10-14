package retention

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testDocs(n int) []Doc {
	out := make([]Doc, n)
	for i := range out {
		// Pretty-printed sources are compacted onto one line.
		out[i] = Doc{ID: fmt.Sprintf("id-%d", i), Source: json.RawMessage(fmt.Sprintf("{\n  \"n\": %d, \"user\": \"bob\", \"message\": \"line\\nbreak\"\n}", i))}
	}
	return out
}

func TestArchiveWriteReadRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "archive")
	a := &Archive{Dir: dir}
	mem := NewMemory()
	name := "signalith-endpoint-2026.07.01"
	mem.AddIndex(name, 12345, testDocs(1203)...)
	ctx := context.Background()
	m, err := a.Write(ctx, mem, Source{Index: name, Category: "endpoint", Day: "2026-07-01", Bytes: 12345}, 1203)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != name || m.File != name+".ndjson.gz" || m.Docs != 1203 || m.Index != name || m.Category != "endpoint" ||
		m.Day != "2026-07-01" || m.IndexBytes != 12345 || len(m.SHA256) != 64 || m.Format != ArchiveFormat || m.Encryption != "" {
		t.Errorf("manifest = %+v", m)
	}
	st, err := os.Stat(filepath.Join(dir, m.File))
	if err != nil || st.Size() != m.Bytes {
		t.Fatalf("file: %v %v", st, err)
	}
	if runtime.GOOS != "windows" {
		if st.Mode().Perm() != 0o600 {
			t.Errorf("file mode = %v", st.Mode().Perm())
		}
		if mst, _ := os.Stat(filepath.Join(dir, name+".json")); mst.Mode().Perm() != 0o600 {
			t.Errorf("manifest mode = %v", mst.Mode().Perm())
		}
		if dst, _ := os.Stat(dir); dst.Mode().Perm() != 0o700 {
			t.Errorf("folder mode = %v", dst.Mode().Perm())
		}
	}
	// The file is plain gzip'd NDJSON, one document per line.
	f, _ := os.Open(filepath.Join(dir, m.File))
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(zr)
	f.Close()
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 1203 || lines[0] != `{"_id":"id-0","_source":{"n":0,"user":"bob","message":"line\nbreak"}}` {
		t.Errorf("first line %q of %d", lines[0], len(lines))
	}
	var got []Doc
	if err := a.Read(*m, func(d Doc) error { got = append(got, d); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1203 || got[7].ID != "id-7" || string(got[7].Source) != `{"n":7,"user":"bob","message":"line\nbreak"}` {
		t.Errorf("read back %d docs, #7 = %s %s", len(got), got[7].ID, got[7].Source)
	}

	list, problems, err := a.List()
	if err != nil || len(problems) != 0 || len(list) != 1 || list[0].SHA256 != m.SHA256 {
		t.Errorf("list = %+v %v %v", list, problems, err)
	}
	if g, err := a.Get(name); err != nil || g.Docs != 1203 {
		t.Errorf("get = %+v %v", g, err)
	}
	for _, bad := range []string{"../etc/passwd", "nope", "", "Signalith-x"} {
		if _, err := a.Get(bad); !errors.Is(err, ErrArchiveNotFound) {
			t.Errorf("get %q = %v", bad, err)
		}
	}

	// Archiving the same index again (late events recreated it) writes a
	// second file instead of replacing the first.
	m2, err := a.Write(ctx, mem, Source{Index: name, Category: "endpoint", Day: "2026-07-01", Bytes: 1}, 1203)
	if err != nil || m2.ID != name+".2" || m2.File != name+".2.ndjson.gz" {
		t.Fatalf("second archive = %+v %v", m2, err)
	}
	if list, _, _ := a.List(); len(list) != 2 || len(archivesByIndex(list)[name]) != 2 {
		t.Errorf("list = %+v", list)
	}
}

func TestArchiveDetectsDamage(t *testing.T) {
	dir := t.TempDir()
	a := &Archive{Dir: dir}
	mem := NewMemory()
	mem.AddIndex("signalith-change-2026.07.01", 1, testDocs(50)...)
	m, err := a.Write(context.Background(), mem, Source{Index: "signalith-change-2026.07.01", Category: "change", Day: "2026-07-01", Bytes: 1}, 50)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, m.File)
	data, _ := os.ReadFile(p)
	data[len(data)/2] ^= 0xff
	os.WriteFile(p, data, 0o600)
	if err := a.Verify(*m); err == nil {
		t.Error("a damaged file passed verification")
	}
	// A manifest whose count is wrong fails too.
	data[len(data)/2] ^= 0xff
	os.WriteFile(p, data, 0o600)
	bad := *m
	bad.Docs = 49
	if err := a.Verify(bad); err == nil || !strings.Contains(err.Error(), "holds 50 events, not 49") {
		t.Errorf("count check: %v", err)
	}
	if err := a.Verify(*m); err != nil {
		t.Errorf("restored file: %v", err)
	}
	// A truncated file is reported by List.
	os.WriteFile(p, data[:len(data)-10], 0o600)
	if list, problems, _ := a.List(); len(list) != 0 || len(problems) != 1 {
		t.Errorf("list = %v, problems = %v", list, problems)
	}
}

func TestArchiveFailuresLeaveNoFiles(t *testing.T) {
	dir := t.TempDir()
	a := &Archive{Dir: dir}
	mem := NewMemory()
	name := "signalith-risk-2026.07.01"
	mem.AddIndex(name, 1, testDocs(20)...)
	ctx := context.Background()
	// The index holds more events than were exported.
	if _, err := a.Write(ctx, mem, Source{Index: name, Category: "risk", Day: "2026-07-01", Bytes: 1}, 21); err == nil || !strings.Contains(err.Error(), "has 20 events but the index has 21") {
		t.Errorf("count mismatch: %v", err)
	}
	mem.Fail["export "+name] = errors.New("scroll expired")
	if _, err := a.Write(ctx, mem, Source{Index: name, Category: "risk", Day: "2026-07-01", Bytes: 1}, 20); err == nil || !strings.Contains(err.Error(), "scroll expired") {
		t.Errorf("export error: %v", err)
	}
	delete(mem.Fail, "export "+name)
	mem.AddIndex(name, 1, Doc{ID: "x", Source: json.RawMessage(`{not json`)})
	if _, err := a.Write(ctx, mem, Source{Index: name, Category: "risk", Day: "2026-07-01", Bytes: 1}, 1); err == nil {
		t.Error("bad JSON was archived")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("left behind: %v", entries)
	}
	// A folder that cannot be created is an error, not a panic.
	file := filepath.Join(dir, "file")
	os.WriteFile(file, nil, 0o600)
	if _, err := (&Archive{Dir: filepath.Join(file, "sub")}).Write(ctx, mem, Source{Index: name, Category: "risk", Day: "2026-07-01", Bytes: 1}, 1); err == nil {
		t.Error("archive under a file worked")
	}
	if _, err := (&Archive{}).Write(ctx, mem, Source{Index: name, Category: "risk", Day: "2026-07-01", Bytes: 1}, 1); err == nil {
		t.Error("archive without a folder worked")
	}
}

// xorWriter stands in for an encrypting writer.
type xorWriter struct{ w io.Writer }

func (x xorWriter) Write(p []byte) (int, error) {
	q := bytes.Clone(p)
	for i := range q {
		q[i] ^= 0x5a
	}
	return x.w.Write(q)
}
func (x xorWriter) Close() error { return nil }

type xorReader struct{ r io.Reader }

func (x xorReader) Read(p []byte) (int, error) {
	n, err := x.r.Read(p)
	for i := range p[:n] {
		p[i] ^= 0x5a
	}
	return n, err
}

func TestArchiveSealHook(t *testing.T) {
	dir := t.TempDir()
	sealed := &Archive{Dir: dir, Encryption: "xor-test",
		Seal:   func(w io.Writer) (io.WriteCloser, []string, error) { return xorWriter{w}, []string{"k1"}, nil },
		Unseal: func(r io.Reader) (io.Reader, error) { return xorReader{r}, nil }}
	mem := NewMemory()
	name := "signalith-endpoint-2026.07.02"
	mem.AddIndex(name, 1, testDocs(30)...)
	m, err := sealed.Write(context.Background(), mem, Source{Index: name, Category: "endpoint", Day: "2026-07-02", Bytes: 1}, 30)
	if err != nil {
		t.Fatal(err)
	}
	if m.Encryption != "xor-test" {
		t.Errorf("encryption = %q", m.Encryption)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, m.File))
	if _, err := gzip.NewReader(bytes.NewReader(raw)); err == nil {
		t.Error("a sealed file is plain gzip")
	}
	n := 0
	if err := sealed.Read(*m, func(Doc) error { n++; return nil }); err != nil || n != 30 {
		t.Errorf("read sealed: %d %v", n, err)
	}
	if err := (&Archive{Dir: dir}).Verify(*m); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("reading without the key: %v", err)
	}
}
