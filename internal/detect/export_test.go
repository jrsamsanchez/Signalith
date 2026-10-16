package detect

import "testing"

// OnlyRules returns a library holding just ds, without the built-in and
// content pack detections, so a test sees only its own rules run.
func OnlyRules(t testing.TB, ds ...*Detection) *Library {
	t.Helper()
	lib, problems, err := NewLibrary(t.TempDir())
	if err != nil || len(problems) > 0 {
		t.Fatal(err, problems)
	}
	lib.mu.Lock()
	lib.builtin, lib.pack = map[string]*Detection{}, map[string]*Detection{}
	lib.mu.Unlock()
	for _, d := range ds {
		if err := lib.Put(d); err != nil {
			t.Fatal(err)
		}
	}
	return lib
}

// LeaderState returns the run state this server keeps for a rule.
func (s *Scheduler) LeaderState(id string) (DetState, bool) {
	e, ok := s.entry(id)
	return e.doc, ok
}

// AsNew makes the scheduler treat every rule it sees first as a new one,
// starting at its next slot, even on a first start with no run state.
func (s *Scheduler) AsNew() *Scheduler {
	s.noFirstStart = true
	return s
}
