package intel

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// racingBackend lets another server add an indicator right after each of
// our writes, before anyone reads the version again.
type racingBackend struct {
	*Memory
	mu    sync.Mutex
	other []Indicator
}

func (b *racingBackend) Put(ctx context.Context, inds []Indicator) error {
	if err := b.Memory.Put(ctx, inds); err != nil {
		return err
	}
	b.mu.Lock()
	other := b.other
	b.other = nil
	b.mu.Unlock()
	if len(other) > 0 {
		return b.Memory.Put(ctx, other)
	}
	return nil
}

// TestAnotherServersChangeAroundOurWriteIsLoaded: a change another server
// makes between our write and the next version read must still reach this
// server at its next Sync (the missed-update race).
func TestAnotherServersChangeAroundOurWriteIsLoaded(t *testing.T) {
	ctx := context.Background()
	b := &racingBackend{Memory: NewMemory()}
	s := NewStore(b)
	if err := s.Load(ctx); err != nil {
		t.Fatal(err)
	}
	theirs := Indicator{Type: TypeIP, Value: "198.51.100.7", Source: ManualSource, Weight: 1}
	theirs.ID = MakeID(theirs.Source, theirs.Type, theirs.Value)
	b.other = []Indicator{theirs}

	if err := s.Add(ctx, []Indicator{{Type: TypeIP, Value: "192.0.2.1", Source: ManualSource}}); err != nil {
		t.Fatal(err)
	}
	if len(s.Lookup("192.0.2.1")) != 1 {
		t.Error("our own indicator is not seen at once")
	}
	reloaded, err := s.Sync(ctx)
	if err != nil || !reloaded {
		t.Fatalf("sync = %v %v, want a reload", reloaded, err)
	}
	if _, ok := s.Get(theirs.ID); !ok {
		t.Error("the other server's indicator was missed")
	}
	if reloaded, _ := s.Sync(ctx); reloaded {
		t.Error("a second sync reloaded without a change")
	}
}

// TestConcurrentStatusWritesDoNotMix: two writers saving the feed status
// file at once leave one complete version and no temporary file behind.
func TestConcurrentStatusWritesDoNotMix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intel_feeds.json")
	a, b := strings.Repeat("a", 300000), strings.Repeat("b", 200000)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		data := a
		if i%2 == 1 {
			data = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Windows may refuse to rename over a file another rename is
			// replacing at that instant; the writer then reports an error.
			if err := replaceFile(path, []byte(data)); err != nil && runtime.GOOS != "windows" {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != a && string(got) != b {
		t.Errorf("the file mixes the two writes (%d bytes)", len(got))
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*.tmp")); len(left) > 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}
